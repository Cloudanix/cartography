from importlib.resources import read_text

import cartography.intel.aws.ec2
import tests.data.aws.ec2.vpc_peerings
from cartography.graph.job import GraphJob


TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'eu-north-1'
TEST_UPDATE_TAG = 123456789


def _seed_account(neo4j_session):
    # organizations.sync creates the account before any service sync; the loader requires it.
    neo4j_session.run('MERGE (:AWSAccount{id: $id})', id=TEST_ACCOUNT_ID)


def test_load_vpc_peerings(neo4j_session):
    _seed_account(neo4j_session)
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
    _seed_account(neo4j_session)
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
    _seed_account(neo4j_session)
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


def _run_peering_cleanup(neo4j_session, workspace_id, organization_id, account_id):
    # GraphJob directly: run_cleanup_job logs and swallows query errors.
    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', 'aws_import_vpc_peering_cleanup.json'),
        {
            'WORKSPACE_ID': workspace_id, 'ORGANIZATION_ID': organization_id, 'AWS_ID': account_id,
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )


def _ids(neo4j_session, label):
    return {
        r['id'] for r in neo4j_session.run(
            f"MATCH (n:{label}) WHERE n.id STARTS WITH 'pc-' RETURN n.id AS id",
        )
    }


def test_vpc_peering_cleanup_removes_only_this_accounts_stale_peer_stubs(neo4j_session):
    # pc-a1 is the synced account. It carries a leftover foreign flag, which must not matter.
    # Its peerings are fresh (pc-x-fresh) or stale. A stale peering's peer side is removed only
    # when it is a pure stub: no arn, no account owns it, nothing else hangs off it, and no other
    # account's peering still references it (pc-stub-shared is also peered by tenant 2).
    # Tenant 2's own stale peering is not this run's business.
    stale, fresh = 1, TEST_UPDATE_TAG
    neo4j_session.run(
        """
        MERGE (w1:CloudanixWorkspace{id: 'pc-w1'})-[:OWNER]->(o1:AWSOrganization{id: 'pc-w1/o-1'})
        MERGE (o1)-[:OWNER]->(a1:AWSAccount{id: 'pc-a1', foreign: true})
        MERGE (o1)-[:OWNER]->(b1:AWSAccount{id: 'pc-b1'})
        MERGE (w2:CloudanixWorkspace{id: 'pc-w2'})-[:OWNER]->(o2:AWSOrganization{id: 'pc-w2/o-2'})
        MERGE (o2)-[:OWNER]->(c1:AWSAccount{id: 'pc-c1'})
        MERGE (a1)-[:RESOURCE]->(:AWSVpc{id: 'pc-own', arn: 'arn:aws:ec2:r:pc-a1:vpc/pc-own'})
        MERGE (a1)-[:RESOURCE]->(:AWSVpc{id: 'pc-own2'})
        MERGE (b1)-[:RESOURCE]->(:AWSVpc{id: 'pc-vpc-b', arn: 'arn:aws:ec2:r:pc-b1:vpc/pc-vpc-b'})
        MERGE (c1)-[:RESOURCE]->(:AWSVpc{id: 'pc-t2', arn: 'arn:aws:ec2:r:pc-c1:vpc/pc-t2'})
        MERGE (:EC2Subnet{id: 'pc-subnet'})-[:MEMBER_OF_AWS_VPC]->(:AWSVpc{id: 'pc-stub-subnet'})
        WITH 1 AS _
        UNWIND $peerings AS p
        MERGE (pcx:AWSPeeringConnection{id: p.id}) SET pcx.lastupdated = p.t
        MERGE (av:AWSVpc{id: p.a}) MERGE (rv:AWSVpc{id: p.r})
        MERGE (pcx)-[:ACCEPTER_VPC{lastupdated: p.t}]->(av)
        MERGE (pcx)-[:REQUESTER_VPC{lastupdated: p.t}]->(rv)
        WITH DISTINCT 1 AS _
        UNWIND $cidrs AS c
        MATCH (v:AWSVpc{id: c.vpc}), (pcx:AWSPeeringConnection{id: c.pcx})
        MERGE (cb:AWSCidrBlock:AWSIpv4CidrBlock{id: c.vpc + '|' + c.block}) SET cb.lastupdated = c.t
        MERGE (v)-[:BLOCK_ASSOCIATION{lastupdated: c.t}]->(cb)
        MERGE (pcx)-[:ACCEPTER_CIDR{lastupdated: c.t}]->(cb)
        """,
        peerings=[
            {'id': 'pc-x-stale', 't': stale, 'a': 'pc-own', 'r': 'pc-stub-stale'},
            {'id': 'pc-x-fresh', 't': fresh, 'a': 'pc-stub-fresh', 'r': 'pc-own'},
            {'id': 'pc-x-shared', 't': stale, 'a': 'pc-stub-shared', 'r': 'pc-own'},
            {'id': 'pc-y-shared', 't': 5, 'a': 'pc-stub-shared', 'r': 'pc-t2'},
            {'id': 'pc-x-b', 't': stale, 'a': 'pc-vpc-b', 'r': 'pc-own'},
            {'id': 'pc-x-own2', 't': stale, 'a': 'pc-own2', 'r': 'pc-own'},
            {'id': 'pc-x-subnet', 't': stale, 'a': 'pc-stub-subnet', 'r': 'pc-own'},
            {'id': 'pc-y-stale', 't': stale, 'a': 'pc-t2-stub', 'r': 'pc-t2'},
        ],
        cidrs=[
            {'vpc': 'pc-own', 'block': '10.0.0.0/16', 'pcx': 'pc-x-stale', 't': stale},
            {'vpc': 'pc-stub-stale', 'block': '10.1.0.0/16', 'pcx': 'pc-x-stale', 't': stale},
            {'vpc': 'pc-stub-fresh', 'block': '10.2.0.0/16', 'pcx': 'pc-x-fresh', 't': fresh},
            {'vpc': 'pc-stub-fresh', 'block': '10.8.0.0/16', 'pcx': 'pc-x-fresh', 't': stale},
            {'vpc': 'pc-stub-shared', 'block': '10.3.0.0/16', 'pcx': 'pc-x-shared', 't': stale},
            {'vpc': 'pc-vpc-b', 'block': '10.4.0.0/16', 'pcx': 'pc-x-b', 't': stale},
            {'vpc': 'pc-own2', 'block': '10.5.0.0/16', 'pcx': 'pc-x-own2', 't': stale},
            {'vpc': 'pc-stub-subnet', 'block': '10.6.0.0/16', 'pcx': 'pc-x-subnet', 't': stale},
            {'vpc': 'pc-t2-stub', 'block': '10.7.0.0/16', 'pcx': 'pc-y-stale', 't': stale},
        ],
    )

    _run_peering_cleanup(neo4j_session, 'pc-w1', 'pc-w1/o-1', 'pc-a1')

    assert _ids(neo4j_session, 'AWSVpc') == {
        'pc-own', 'pc-own2', 'pc-vpc-b', 'pc-t2', 'pc-stub-fresh', 'pc-stub-shared', 'pc-stub-subnet',
        'pc-t2-stub',
    }
    assert _ids(neo4j_session, 'AWSCidrBlock') == {
        'pc-own|10.0.0.0/16', 'pc-stub-fresh|10.2.0.0/16', 'pc-stub-shared|10.3.0.0/16',
        'pc-vpc-b|10.4.0.0/16', 'pc-own2|10.5.0.0/16', 'pc-stub-subnet|10.6.0.0/16', 'pc-t2-stub|10.7.0.0/16',
    }
    assert _ids(neo4j_session, 'AWSPeeringConnection') == {'pc-x-fresh', 'pc-y-shared', 'pc-y-stale'}
    assert _ids(neo4j_session, 'AWSAccount') == {'pc-a1', 'pc-b1', 'pc-c1'}

    # Tenant 2 drops its side of the shared peering later: its own run removes the stub then.
    neo4j_session.run("MATCH (p:AWSPeeringConnection{id: 'pc-y-shared'}) SET p.lastupdated = 1")
    _run_peering_cleanup(neo4j_session, 'pc-w2', 'pc-w2/o-2', 'pc-c1')

    assert 'pc-stub-shared' not in _ids(neo4j_session, 'AWSVpc')
    assert 'pc-stub-shared|10.3.0.0/16' not in _ids(neo4j_session, 'AWSCidrBlock')
    assert 'pc-t2-stub' not in _ids(neo4j_session, 'AWSVpc')


def test_load_vpc_peerings_without_the_account_writes_nothing(neo4j_session):
    # organizations.sync creates the account before any service sync. If it is missing anyway,
    # the peering load must neither fail nor leave unowned peering, VPC or CIDR nodes behind.
    rows = [_peering('pm-pcx-1', ('pm-a1', 'pm-vpc-own', ['10.0.0.0/16']), ('pm-ext', 'pm-vpc-ext', ['10.9.0.0/16']))]

    _load_peerings(neo4j_session, rows, 'pm-a1', TEST_UPDATE_TAG)

    left = neo4j_session.run(
        "MATCH (n) WHERE n.id STARTS WITH 'pm-' RETURN count(n) AS c",
    ).single()['c']
    assert left == 0
