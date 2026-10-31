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


def _cidr_ids(neo4j_session):
    return {
        r['id'] for r in neo4j_session.run("MATCH (c:AWSCidrBlock) WHERE c.id STARTS WITH 'cc-' RETURN c.id AS id")
    }


def test_vpc_cleanup_deletes_stale_cidr_blocks_of_own_vpcs(neo4j_session):
    # vpc.py labels CIDR blocks AWSCidrBlock:AWSIpv4CidrBlock / AWSIpv6CidrBlock. Statements 1-2 matched
    # :CidrBlock, which nothing creates, so a stale block of this account's own VPC was never deleted, and
    # a VPC deleted by statement 3 left its blocks behind as orphans. Blocks of another account's VPC
    # (reached through a legacy RESOURCE edge), of a peer stub (reached only through a peering; the
    # peering cleanup owns those) and of another tenant stay.
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: 'cc-w1'})-[:OWNER]->(o:AWSOrganization{id: 'cc-w1/o-1'})
        MERGE (o)-[:OWNER]->(a:AWSAccount{id: 'cc-a1'})
        MERGE (o)-[:OWNER]->(b:AWSAccount{id: 'cc-b1'})
        MERGE (a)-[:RESOURCE{lastupdated: $tag}]->(own:AWSVpc{
            id: 'cc-own', arn: 'arn:aws:ec2:r:cc-a1:vpc/cc-own', lastupdated: $tag
        })
        MERGE (own)-[:BLOCK_ASSOCIATION{lastupdated: $tag}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-own|fresh', lastupdated: $tag
        })
        MERGE (own)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-own|gone-v4', lastupdated: 1
        })
        MERGE (own)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv6CidrBlock{
            id: 'cc-own|gone-v6', lastupdated: 1
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(gone:AWSVpc{
            id: 'cc-own-gone', arn: 'arn:aws:ec2:r:cc-a1:vpc/cc-own-gone', lastupdated: 1
        })
        MERGE (gone)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-own-gone|1', lastupdated: 1
        })
        MERGE (b)-[:RESOURCE{lastupdated: 5}]->(vb:AWSVpc{
            id: 'cc-vpc-b', arn: 'arn:aws:ec2:r:cc-b1:vpc/cc-vpc-b', lastupdated: 5
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(vb)
        MERGE (vb)-[:BLOCK_ASSOCIATION{lastupdated: 5}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-vpc-b|1', lastupdated: 5
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(noarn:AWSVpc{id: 'cc-noarn-gone', lastupdated: 1})
        MERGE (noarn)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-noarn-gone|1', lastupdated: 1
        })
        MERGE (pcx:AWSPeeringConnection{id: 'cc-pcx', lastupdated: $tag})-[:REQUESTER_VPC]->(own)
        MERGE (pcx)-[:ACCEPTER_VPC]->(stub:AWSVpc{id: 'cc-stub', lastupdated: $tag})
        MERGE (stub)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(sc:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-stub|1', lastupdated: 1
        })
        MERGE (pcx)-[:ACCEPTER_CIDR{lastupdated: 1}]->(sc)
        MERGE (w2:CloudanixWorkspace{id: 'cc-w2'})-[:OWNER]->(o2:AWSOrganization{id: 'cc-w2/o-1'})
        MERGE (o2)-[:OWNER]->(a2:AWSAccount{id: 'cc-a2'})
        MERGE (a2)-[:RESOURCE{lastupdated: 1}]->(v2:AWSVpc{
            id: 'cc-vpc-t2', arn: 'arn:aws:ec2:r:cc-a2:vpc/cc-vpc-t2', lastupdated: 1
        })
        MERGE (v2)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'cc-vpc-t2|1', lastupdated: 1
        })
        """,
        tag=TEST_UPDATE_TAG,
    )

    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', 'aws_import_vpc_cleanup.json'),
        {
            'WORKSPACE_ID': 'cc-w1', 'ORGANIZATION_ID': 'cc-w1/o-1', 'AWS_ID': 'cc-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )

    assert _cidr_ids(neo4j_session) == {'cc-own|fresh', 'cc-vpc-b|1', 'cc-stub|1', 'cc-vpc-t2|1'}
    links = {
        (r['v'], r['c']) for r in neo4j_session.run(
            "MATCH (v:AWSVpc)-[:BLOCK_ASSOCIATION]->(c:AWSCidrBlock) WHERE c.id STARTS WITH 'cc-' "
            "RETURN v.id AS v, c.id AS c",
        )
    }
    assert links == {
        ('cc-own', 'cc-own|fresh'), ('cc-vpc-b', 'cc-vpc-b|1'), ('cc-stub', 'cc-stub|1'),
        ('cc-vpc-t2', 'cc-vpc-t2|1'),
    }


def test_vpc_cleanup_deletes_stale_block_association_of_own_vpc_only(neo4j_session):
    # A stale association edge whose block is still fresh (e.g. re-stamped by a peering) is dropped
    # for this account's own VPC, but not for another account's VPC reached through a legacy edge.
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: 'ce-w1'})-[:OWNER]->(o:AWSOrganization{id: 'ce-w1/o-1'})
        MERGE (o)-[:OWNER]->(a:AWSAccount{id: 'ce-a1'})
        MERGE (o)-[:OWNER]->(b:AWSAccount{id: 'ce-b1'})
        MERGE (a)-[:RESOURCE{lastupdated: $tag}]->(own:AWSVpc{
            id: 'ce-own', arn: 'arn:aws:ec2:r:ce-a1:vpc/ce-own', lastupdated: $tag
        })
        MERGE (own)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'ce-own|1', lastupdated: $tag
        })
        MERGE (b)-[:RESOURCE{lastupdated: 5}]->(vb:AWSVpc{
            id: 'ce-vpc-b', arn: 'arn:aws:ec2:r:ce-b1:vpc/ce-vpc-b', lastupdated: 5
        })
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(vb)
        MERGE (vb)-[:BLOCK_ASSOCIATION{lastupdated: 1}]->(:AWSCidrBlock:AWSIpv4CidrBlock{
            id: 'ce-vpc-b|1', lastupdated: $tag
        })
        """,
        tag=TEST_UPDATE_TAG,
    )

    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', 'aws_import_vpc_cleanup.json'),
        {
            'WORKSPACE_ID': 'ce-w1', 'ORGANIZATION_ID': 'ce-w1/o-1', 'AWS_ID': 'ce-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )

    links = {
        r['v'] for r in neo4j_session.run(
            "MATCH (v:AWSVpc)-[:BLOCK_ASSOCIATION]->(c:AWSCidrBlock) WHERE c.id STARTS WITH 'ce-' RETURN v.id AS v",
        )
    }
    assert links == {'ce-vpc-b'}
