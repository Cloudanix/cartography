import cartography.intel.aws.ec2
import tests.data.aws.ec2.vpc_peerings


TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'eu-north-1'
TEST_UPDATE_TAG = 123456789


def test_load_vpc_peerings(neo4j_session):
    data = tests.data.aws.ec2.vpc_peerings.DESCRIBE_VPC_PEERINGS
    cartography.intel.aws.ec2.vpc_peerings.load_vpc_peerings(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "pcx-09969456d9ec69ab6",
    }

    nodes = neo4j_session.run(
        """
        MATCH (pcx:AWSPeeringConnection) RETURN pcx.id;
        """,
    )
    actual_nodes = {n['pcx.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_vpc_peering_relationships_vpc(neo4j_session):
    data = tests.data.aws.ec2.vpc_peerings.DESCRIBE_VPC_PEERINGS
    cartography.intel.aws.ec2.vpc_peerings.load_vpc_peerings(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            'vpc-055d355d6d2e498fa',
            'pcx-09969456d9ec69ab6',
            'vpc-0015dc961e537676a',
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH
        (rvpc:AWSVpc)-[:REQUESTER_VPC]-(pcx:AWSPeeringConnection)-[:ACCEPTER_VPC]-(avpc:AWSVpc)
        RETURN rvpc.id, pcx.id, avpc.id;
        """,
    )
    actual = {
        (r['rvpc.id'], r['pcx.id'], r['avpc.id']) for r in result
    }

    assert actual == expected_nodes


def test_vpc_peering_relationships_cidr(neo4j_session):
    data = tests.data.aws.ec2.vpc_peerings.DESCRIBE_VPC_PEERINGS
    cartography.intel.aws.ec2.vpc_peerings.load_vpc_peerings(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    cartography.intel.aws.ec2.vpc_peerings.load_accepter_cidrs(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    cartography.intel.aws.ec2.vpc_peerings.load_requester_cidrs(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            'vpc-055d355d6d2e498fa|10.1.0.0/16',
            'pcx-09969456d9ec69ab6',
            'vpc-0015dc961e537676a|10.0.0.0/16',
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH
        (r:AWSIpv4CidrBlock)-[:REQUESTER_CIDR]-(p:AWSPeeringConnection)-[]-(a:AWSIpv4CidrBlock)
        RETURN r.id, p.id, a.id;
        """,
    )
    actual = {
        (r['r.id'], r['p.id'], r['a.id']) for r in result
    }

    assert actual == expected_nodes


def _side(owner_id, vpc_id, cidrs):
    return {
        'OwnerId': owner_id,
        'VpcId': vpc_id,
        'Region': TEST_REGION,
        'CidrBlockSet': [{'CidrBlock': c} for c in cidrs],
        'PeeringOptions': {},
    }


def _peering(pcx_id, accepter, requester):
    return {
        'VpcPeeringConnectionId': pcx_id,
        'AccepterVpcInfo': _side(*accepter),
        'RequesterVpcInfo': _side(*requester),
        'Status': {'Code': 'active', 'Message': 'Active'},
    }


def _load_peerings(neo4j_session, rows, account_id, update_tag):
    peerings = cartography.intel.aws.ec2.vpc_peerings
    peerings.load_vpc_peerings(neo4j_session, rows, TEST_REGION, account_id, update_tag)
    peerings.load_accepter_cidrs(neo4j_session, rows, TEST_REGION, account_id, update_tag)
    peerings.load_requester_cidrs(neo4j_session, rows, TEST_REGION, account_id, update_tag)


def test_load_vpc_peerings_claims_only_the_synced_accounts_side(neo4j_session):
    # The peer side of a peering belongs to another account: an unonboarded one (pl-ext) or an
    # onboarded one (pl-b1, here with its real VPC already loaded). The synced account must not
    # take ownership of it nor overwrite it, and the loader must never create account nodes.
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: 'pl-w1'})-[:OWNER]->(o:AWSOrganization{id: 'pl-w1/o-1'})
        MERGE (o)-[:OWNER]->(a:AWSAccount{id: 'pl-a1'})
        MERGE (o)-[:OWNER]->(b:AWSAccount{id: 'pl-b1'})
        MERGE (a)-[:RESOURCE{lastupdated: 1}]->(:AWSVpc{
            id: 'pl-vpc-own', arn: 'arn:aws:ec2:eu-north-1:pl-a1:vpc/pl-vpc-own', lastupdated: 1
        })
        MERGE (b)-[:RESOURCE{lastupdated: 1}]->(:AWSVpc{
            id: 'pl-vpc-b', arn: 'arn:aws:ec2:eu-north-1:pl-b1:vpc/pl-vpc-b', name: 'b-vpc', lastupdated: 1
        })
        """,
    )
    rows = [
        _peering('pl-pcx-1', ('pl-a1', 'pl-vpc-own', ['10.0.0.0/16']), ('pl-ext', 'pl-vpc-ext', ['10.9.0.0/16'])),
        _peering('pl-pcx-2', ('pl-b1', 'pl-vpc-b', ['10.2.0.0/16']), ('pl-a1', 'pl-vpc-own', ['10.0.0.0/16'])),
    ]

    _load_peerings(neo4j_session, rows, 'pl-a1', TEST_UPDATE_TAG)
    _load_peerings(neo4j_session, rows[:1], 'pl-missing', TEST_UPDATE_TAG)

    owners = {
        (r['a'], r['v'], r['t']) for r in neo4j_session.run(
            """
            MATCH (a:AWSAccount)-[r:RESOURCE]->(v:AWSVpc) WHERE v.id STARTS WITH 'pl-'
            RETURN a.id AS a, v.id AS v, r.lastupdated AS t
            """,
        )
    }
    assert owners == {('pl-a1', 'pl-vpc-own', TEST_UPDATE_TAG), ('pl-b1', 'pl-vpc-b', 1)}

    # VPCs the VPC sync loaded (they carry an arn) keep its stamp; only peer stubs get ours.
    vpcs = {
        r['id']: (r['lastupdated'], r['name']) for r in neo4j_session.run(
            """
            MATCH (v:AWSVpc) WHERE v.id STARTS WITH 'pl-'
            RETURN v.id AS id, v.lastupdated AS lastupdated, v.name AS name
            """,
        )
    }
    assert vpcs == {
        'pl-vpc-own': (1, None),
        'pl-vpc-b': (1, 'b-vpc'),
        'pl-vpc-ext': (TEST_UPDATE_TAG, None),
    }

    sides = {
        (r['p'], r['t'], r['v']) for r in neo4j_session.run(
            """
            MATCH (p:AWSPeeringConnection)-[r:ACCEPTER_VPC|REQUESTER_VPC]->(v:AWSVpc) WHERE p.id STARTS WITH 'pl-'
            RETURN p.id AS p, type(r) AS t, v.id AS v
            """,
        )
    }
    assert sides == {
        ('pl-pcx-1', 'ACCEPTER_VPC', 'pl-vpc-own'), ('pl-pcx-1', 'REQUESTER_VPC', 'pl-vpc-ext'),
        ('pl-pcx-2', 'ACCEPTER_VPC', 'pl-vpc-b'), ('pl-pcx-2', 'REQUESTER_VPC', 'pl-vpc-own'),
    }

    accounts = {
        r['id'] for r in neo4j_session.run("MATCH (a:AWSAccount) WHERE a.id STARTS WITH 'pl-' RETURN a.id AS id")
    }
    assert accounts == {'pl-a1', 'pl-b1'}
