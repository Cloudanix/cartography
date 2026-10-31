from importlib.resources import read_text

from cartography.graph.job import GraphJob

TEST_UPDATE_TAG = 123456789


def _vpc_ids(neo4j_session):
    return {
        r['id'] for r in neo4j_session.run("MATCH (v:AWSVpc) WHERE v.id STARTS WITH 'vc-' RETURN v.id AS id")
    }


def test_vpc_cleanup_spares_vpcs_of_other_accounts(neo4j_session):
    # Before the peering loader fix, a synced account took a RESOURCE edge to the peer side of
    # each peering. Those legacy edges are stale now. When the peer VPC is another account's real
    # VPC (its arn names that account), this account's cleanup must drop only its own stale edge,
    # not the VPC. Its own stale VPC, a stale peer stub (no arn) and a stale VPC whose arn cannot
    # be parsed are still deleted, as before.
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: 'vc-w1'})-[:OWNER]->(o:AWSOrganization{id: 'vc-w1/o-1'})
        MERGE (o)-[:OWNER]->(a:AWSAccount{id: 'vc-a1'})
        MERGE (o)-[:OWNER]->(b:AWSAccount{id: 'vc-b1'})
        MERGE (a)-[:RESOURCE{lastupdated: $tag}]->(:AWSVpc{
            id: 'vc-own', arn: 'arn:aws:ec2:r:vc-a1:vpc/vc-own', lastupdated: $tag
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(:AWSVpc{
            id: 'vc-own-gone', arn: 'arn:aws:ec2:r:vc-a1:vpc/vc-own-gone', lastupdated: 1
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(:AWSVpc{id: 'vc-stub', lastupdated: 1})
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(:AWSVpc{id: 'vc-odd-arn', arn: 'vpc/vc-odd-arn', lastupdated: 1})
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(:AWSVpc{id: 'vc-empty-arn', arn: '', lastupdated: 1})
        MERGE (b)-[:RESOURCE{lastupdated: 5}]->(vb:AWSVpc{
            id: 'vc-vpc-b', arn: 'arn:aws:ec2:r:vc-b1:vpc/vc-vpc-b', lastupdated: 5
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(vb)
        MERGE (:EC2Subnet{id: 'vc-subnet-b'})-[:MEMBER_OF_AWS_VPC]->(vb)
        """,
        tag=TEST_UPDATE_TAG,
    )

    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', 'aws_import_vpc_cleanup.json'),
        {
            'WORKSPACE_ID': 'vc-w1', 'ORGANIZATION_ID': 'vc-w1/o-1', 'AWS_ID': 'vc-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )

    assert _vpc_ids(neo4j_session) == {'vc-own', 'vc-vpc-b'}
    owners = {
        (r['a'], r['v']) for r in neo4j_session.run(
            "MATCH (a:AWSAccount)-[:RESOURCE]->(v:AWSVpc) WHERE v.id STARTS WITH 'vc-' RETURN a.id AS a, v.id AS v",
        )
    }
    assert owners == {('vc-a1', 'vc-own'), ('vc-b1', 'vc-vpc-b')}
    subnet_links = neo4j_session.run(
        "MATCH (:EC2Subnet{id: 'vc-subnet-b'})-[r:MEMBER_OF_AWS_VPC]->(:AWSVpc{id: 'vc-vpc-b'}) RETURN count(r) AS c",
    ).single()['c']
    assert subnet_links == 1
