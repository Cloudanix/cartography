import json

from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '555555555555'
OTHER_ACCOUNT_ID = '666666666666'


def _seed_public_instance(neo4j_session, account_id, instance_id):
    # Publicly accessible, open to the internet by security group, in a subnet routed to an internet gateway:
    # public under every instance statement of the job, so this test does not depend on their details.
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(rds:RDSInstance{id: $instance_id})
        SET rds.arn = $instance_id, rds.publicly_accessible = true, rds.endpoint_port = 5432
        MERGE (rds)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup{id: $instance_id + '-sg'})
        MERGE (sg)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:IpPermissionInbound:IpRule{ruleid: $instance_id + '-rule'})
        SET rule.fromport = 0, rule.toport = 65535, rule.protocol = '-1'
        MERGE (rule)<-[:MEMBER_OF_IP_RULE]-(:IpRange{id: $instance_id + '-range', range: '0.0.0.0/0'})
        MERGE (rds)-[:MEMBER_OF_DB_SUBNET_GROUP]->(:DBSubnetGroup{id: $instance_id + '-dbsg'})
            -[:CONNECTED_TO]->(subnet:EC2Subnet{subnetid: $instance_id + '-subnet'})
        MERGE (a)-[:RESOURCE]->(subnet)
        MERGE (subnet)-[:HAS_EXPLICIT_ASSOCIATION]->(:EC2RouteTableAssociation{id: $instance_id + '-rta'})
            <-[:HAS_ASSOCIATION]-(:EC2RouteTable{id: $instance_id + '-rt'})
            <-[:MEMBER_OF_ROUTE_TABLE]-(:EC2Route{
                id: $instance_id + '-route', destination_cidr_block: '0.0.0.0/0', gateway_id: 'igw-1'
            })
        """,
        account_id=account_id, instance_id=instance_id,
    )


def _seed_private_instance(neo4j_session, account_id, instance_id):
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(rds:RDSInstance{id: $instance_id})
        SET rds.arn = $instance_id, rds.publicly_accessible = false
        """,
        account_id=account_id, instance_id=instance_id,
    )


def _seed_cluster(neo4j_session, account_id, cluster_id, member_ids, stale_exposure=False):
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(c:RDSCluster{id: $cluster_id})
        SET c.arn = $cluster_id, c.db_cluster_identifier = $cluster_id, c.port = 5432
        FOREACH (_ IN CASE WHEN $stale THEN [1] ELSE [] END | SET c.exposed_internet = true)
        WITH c
        UNWIND $member_ids AS member_id
        MATCH (rds:RDSInstance{id: member_id})
        MERGE (rds)-[:IS_CLUSTER_MEMBER_OF]->(c)
        """,
        account_id=account_id, cluster_id=cluster_id, member_ids=member_ids, stale=stale_exposure,
    )


def test_rds_cluster_is_exposed_when_a_member_instance_is(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-rdsc', 'o-rdsc', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-rdsc-other', 'o-rdsc-other', OTHER_ACCOUNT_ID)
    _seed_public_instance(neo4j_session, ACCOUNT_ID, 'rdsc-inst-public')
    _seed_private_instance(neo4j_session, ACCOUNT_ID, 'rdsc-inst-private')
    _seed_private_instance(neo4j_session, ACCOUNT_ID, 'rdsc-inst-private-2')
    _seed_cluster(neo4j_session, ACCOUNT_ID, 'rdsc-mixed', ['rdsc-inst-public', 'rdsc-inst-private'])
    _seed_cluster(neo4j_session, ACCOUNT_ID, 'rdsc-private', ['rdsc-inst-private-2'])
    _seed_cluster(neo4j_session, ACCOUNT_ID, 'rdsc-stale', [], stale_exposure=True)
    # Ingest links members to clusters by db_cluster_identifier alone, so a same-named cluster in another
    # tenant's account can pick up a foreign member; that member must not expose this account's cluster.
    _seed_public_instance(neo4j_session, OTHER_ACCOUNT_ID, 'rdsc-foreign-public')
    _seed_cluster(neo4j_session, ACCOUNT_ID, 'rdsc-foreign-member', ['rdsc-foreign-public'])
    other_params = exposure_job_parameters('ws-rdsc-other', 'o-rdsc-other', OTHER_ACCOUNT_ID, TEST_UPDATE_TAG + 1)
    run_analysis_job('aws_rds_asset_exposure.json', neo4j_session, other_params)

    run_analysis_job(
        'aws_rds_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-rdsc', 'o-rdsc', ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(c:RDSCluster{exposed_internet: true})
        RETURN c.id AS id, c.exposed_internet_type AS types, c.publicContext AS context
        """,
        account_id=ACCOUNT_ID,
    )
    exposed = {n['id']: (n['types'], n['context']) for n in nodes}
    assert list(exposed) == ['rdsc-mixed']
    types, context = exposed['rdsc-mixed']
    assert types == ['public_member_instance']
    members = json.loads(context)[0]['context'][0]['exposedMembers']
    assert [member['instanceId'] for member in members] == ['rdsc-inst-public']
