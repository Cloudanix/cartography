import json

import cartography.intel.aws.neptune
import cartography.intel.aws.rds
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777776'
OTHER_ACCOUNT_ID = '888888888886'
REGION = 'us-east-1'


def _load(neo4j_session, account_id, clusters):
    # name -> {member instance name: PubliclyAccessible}
    cartography.intel.aws.neptune.load_neptune_clusters(
        neo4j_session,
        [
            {
                'DBClusterArn': f'arn:aws:rds:{REGION}:{account_id}:cluster:{name}', 'DBClusterIdentifier': name,
                'Engine': 'neptune', 'Port': 8182, 'region': REGION, 'name': name,
            }
            for name in clusters
        ],
        account_id, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session,
        [
            {
                'DBInstanceArn': f'arn:aws:rds:{REGION}:{account_id}:db:{instance}', 'DBInstanceIdentifier': instance,
                'Engine': 'neptune', 'DBClusterIdentifier': name, 'PubliclyAccessible': public, 'region': REGION,
            }
            for name, members in clusters.items() for instance, public in members.items()
        ],
        account_id, TEST_UPDATE_TAG,
    )


def test_neptune_cluster_is_exposed_when_a_member_instance_is(neo4j_session, mocker):
    mocker.patch.object(cartography.intel.aws.rds, 'dns_lookup_with_ip_type', return_value=[])
    create_test_org_account(neo4j_session, 'ws-nptx', 'o-nptx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-nptx-other', 'o-nptx-other', OTHER_ACCOUNT_ID)
    _load(
        neo4j_session, ACCOUNT_ID, {
            'nptx-public': {'nptx-public-1': True},
            'nptx-mixed': {'nptx-mixed-writer': False, 'nptx-mixed-reader': True},
            'nptx-private': {'nptx-private-1': False},
            'nptx-foreign-member': {},
            'nptx-stale': {},
        },
    )
    _load(neo4j_session, OTHER_ACCOUNT_ID, {'nptx-other': {'nptx-other-1': True}})
    # A public instance of another tenant linked to this account's cluster must not expose it.
    neo4j_session.run(
        """
        MATCH (c:NeptuneCluster{db_cluster_identifier: 'nptx-foreign-member'}),
            (i:RDSInstance{db_instance_identifier: 'nptx-other-1'})
        MERGE (i)-[:IS_CLUSTER_MEMBER_OF]->(c)
        WITH c
        MATCH (s:NeptuneCluster{db_cluster_identifier: 'nptx-stale'})
        SET s.exposed_internet = true, s.exposed_internet_type = ['public_member_instance']
        """,
    )
    other_params = exposure_job_parameters('ws-nptx-other', 'o-nptx-other', OTHER_ACCOUNT_ID, TEST_UPDATE_TAG)
    run_analysis_job('aws_rds_asset_exposure.json', neo4j_session, other_params)
    params = exposure_job_parameters('ws-nptx', 'o-nptx', ACCOUNT_ID, TEST_UPDATE_TAG)

    run_analysis_job('aws_rds_asset_exposure.json', neo4j_session, params)
    run_analysis_job('aws_neptune_cluster_asset_exposure.json', neo4j_session, params)

    rows = neo4j_session.run(
        "MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(c:NeptuneCluster) RETURN c.db_cluster_identifier AS name, "
        "c.exposed_internet AS exposed, c.exposed_internet_type AS types, c.publicContext AS context",
        account_id=ACCOUNT_ID,
    )
    clusters = {r['name']: r for r in rows}
    assert {n: r['types'] for n, r in clusters.items() if r['exposed']} == {
        'nptx-public': ['public_member_instance'],
        'nptx-mixed': ['public_member_instance'],
    }
    context = json.loads(clusters['nptx-mixed']['context'])[0]
    assert (context['resource'], context['resourceType']) == (
        f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:cluster:nptx-mixed', 'aws-database-neptune-dbcluster',
    )
    assert [m['instanceId'] for m in context['context'][0]['exposedMembers']] == [
        f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:db:nptx-mixed-reader',
    ]
    assert clusters['nptx-stale']['context'] is None
