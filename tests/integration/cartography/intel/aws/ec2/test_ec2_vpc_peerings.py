from importlib.resources import read_text

import cartography.intel.aws.ec2
import tests.data.aws.ec2.vpc_peerings
from cartography.graph.job import GraphJob
from cartography.intel.aws.exposure_layers import blast_radius
from tests.integration.cartography.intel.aws.common import create_test_org_account


TEST_ACCOUNT_ID = '000000000000'
TEST_WORKSPACE_ID = 'ws-peering'
TEST_REGION = 'eu-north-1'
TEST_UPDATE_TAG = 123456789


def _seed_account(neo4j_session):
    # organizations.sync creates the account before any service sync, and the VPC sync loads its VPCs.
    create_test_org_account(neo4j_session, TEST_WORKSPACE_ID, f'{TEST_WORKSPACE_ID}/o-1', TEST_ACCOUNT_ID)
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $id})
        UNWIND ['vpc-0015dc961e537676a', 'vpc-055d355d6d2e498fa'] AS vpc_id
        MERGE (a)-[:RESOURCE]->(:AWSVpc{id: vpc_id})
        """,
        id=TEST_ACCOUNT_ID,
    )


def test_load_vpc_peerings(neo4j_session):
    _seed_account(neo4j_session)
    data = tests.data.aws.ec2.vpc_peerings.DESCRIBE_VPC_PEERINGS
    cartography.intel.aws.ec2.vpc_peerings.load_vpc_peerings(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
        TEST_WORKSPACE_ID,
    )

    expected_nodes = {
        "pcx-09969456d9ec69ab6",
    }

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $id})-[:RESOURCE]->(pcx:AWSPeeringConnection) RETURN pcx.id;
        """,
        id=TEST_ACCOUNT_ID,
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
        TEST_WORKSPACE_ID,
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
        TEST_WORKSPACE_ID,
    )
    cartography.intel.aws.ec2.vpc_peerings.load_accepter_cidrs(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
        TEST_WORKSPACE_ID,
    )
    cartography.intel.aws.ec2.vpc_peerings.load_requester_cidrs(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
        TEST_WORKSPACE_ID,
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


def _load_peerings(neo4j_session, rows, account_id, update_tag, workspace_id):
    peerings = cartography.intel.aws.ec2.vpc_peerings
    peerings.load_vpc_peerings(neo4j_session, rows, TEST_REGION, account_id, update_tag, workspace_id)
    peerings.load_accepter_cidrs(neo4j_session, rows, TEST_REGION, account_id, update_tag, workspace_id)
    peerings.load_requester_cidrs(neo4j_session, rows, TEST_REGION, account_id, update_tag, workspace_id)


def _rows(neo4j_session, query, **kw):
    return {tuple(r.values()) for r in neo4j_session.run(query, **kw)}


def test_vpc_peerings_link_only_vpcs_of_the_workspace(neo4j_session):
    # Workspace 1 holds pt-a1 (synced; VPCs pt-vpc-a and pt-vpc-a2) and pt-b1 (pt-vpc-b). Workspace 2 is
    # another customer: pt-c1 owns pt-vpc-c (with its CIDR block) and synced its side of pt-pcx-ext first.
    # pt-pcx-same peers two of pt-a1's VPCs, pt-pcx-ws peers with pt-b1, pt-pcx-ext with pt-c1.
    old, tag = 1, TEST_UPDATE_TAG
    create_test_org_account(neo4j_session, 'pt-w1', 'pt-w1/o-1', 'pt-a1')
    create_test_org_account(neo4j_session, 'pt-w1', 'pt-w1/o-1', 'pt-b1')
    create_test_org_account(neo4j_session, 'pt-w2', 'pt-w2/o-2', 'pt-c1')
    neo4j_session.run(
        """
        UNWIND [['pt-a1', 'pt-vpc-a'], ['pt-a1', 'pt-vpc-a2'], ['pt-b1', 'pt-vpc-b'], ['pt-c1', 'pt-vpc-c']] AS v
        MATCH (a:AWSAccount{id: v[0]})
        MERGE (a)-[:RESOURCE]->(vpc:AWSVpc{id: v[1], lastupdated: 1})
        SET vpc.arn = 'arn:aws:ec2:eu-north-1:' + v[0] + ':vpc/' + v[1]
        WITH 1 AS _
        MATCH (vpc:AWSVpc{id: 'pt-vpc-c'})
        MERGE (vpc)-[:BLOCK_ASSOCIATION]->(:AWSCidrBlock:AWSIpv4CidrBlock{id: 'pt-vpc-c|10.9.0.0/16', lastupdated: 1})
        """,
    )
    ext = _peering('pt-pcx-ext', ('pt-a1', 'pt-vpc-a', ['10.0.0.0/16']), ('pt-c1', 'pt-vpc-c', ['10.9.0.0/16']))
    rows = [
        _peering('pt-pcx-same', ('pt-a1', 'pt-vpc-a', ['10.0.0.0/16']), ('pt-a1', 'pt-vpc-a2', ['10.1.0.0/16'])),
        _peering('pt-pcx-ws', ('pt-b1', 'pt-vpc-b', ['10.2.0.0/16']), ('pt-a1', 'pt-vpc-a', ['10.0.0.0/16'])),
        ext,
    ]
    _load_peerings(neo4j_session, [ext], 'pt-c1', old, 'pt-w2')
    _load_peerings(neo4j_session, rows, 'pt-a1', tag, 'pt-w1')

    claims = _rows(
        neo4j_session,
        "MATCH (a:AWSAccount)-[:RESOURCE]->(p:AWSPeeringConnection) WHERE a.id STARTS WITH 'pt-' "
        "RETURN a.id, p.id, p.lastupdated",
    )
    assert claims == {
        ('pt-a1', 'pt-pcx-same', tag), ('pt-a1', 'pt-pcx-ws', tag), ('pt-a1', 'pt-pcx-ext', tag),
        ('pt-c1', 'pt-pcx-ext', old),
    }

    sides = _rows(
        neo4j_session,
        "MATCH (a:AWSAccount)-[:RESOURCE]->(p:AWSPeeringConnection)-[r:ACCEPTER_VPC|REQUESTER_VPC]->(v:AWSVpc) "
        "WHERE a.id STARTS WITH 'pt-' RETURN a.id, p.id, type(r), v.id",
    )
    assert sides == {
        ('pt-a1', 'pt-pcx-same', 'ACCEPTER_VPC', 'pt-vpc-a'), ('pt-a1', 'pt-pcx-same', 'REQUESTER_VPC', 'pt-vpc-a2'),
        ('pt-a1', 'pt-pcx-ws', 'ACCEPTER_VPC', 'pt-vpc-b'), ('pt-a1', 'pt-pcx-ws', 'REQUESTER_VPC', 'pt-vpc-a'),
        ('pt-a1', 'pt-pcx-ext', 'ACCEPTER_VPC', 'pt-vpc-a'),
        ('pt-c1', 'pt-pcx-ext', 'REQUESTER_VPC', 'pt-vpc-c'),
    }

    cidrs = _rows(
        neo4j_session,
        "MATCH (a:AWSAccount)-[:RESOURCE]->(p:AWSPeeringConnection)-[r:ACCEPTER_CIDR|REQUESTER_CIDR]->(b) "
        "WHERE a.id STARTS WITH 'pt-' RETURN a.id, p.id, type(r), b.id",
    )
    assert cidrs == {
        ('pt-a1', 'pt-pcx-same', 'ACCEPTER_CIDR', 'pt-vpc-a|10.0.0.0/16'),
        ('pt-a1', 'pt-pcx-same', 'REQUESTER_CIDR', 'pt-vpc-a2|10.1.0.0/16'),
        ('pt-a1', 'pt-pcx-ws', 'ACCEPTER_CIDR', 'pt-vpc-b|10.2.0.0/16'),
        ('pt-a1', 'pt-pcx-ws', 'REQUESTER_CIDR', 'pt-vpc-a|10.0.0.0/16'),
        ('pt-a1', 'pt-pcx-ext', 'ACCEPTER_CIDR', 'pt-vpc-a|10.0.0.0/16'),
        ('pt-c1', 'pt-pcx-ext', 'REQUESTER_CIDR', 'pt-vpc-c|10.9.0.0/16'),
    }

    # The other customer's side is kept as facts on this tenant's peering only.
    facts = neo4j_session.run(
        "MATCH (:AWSAccount{id: 'pt-a1'})-[:RESOURCE]->(p:AWSPeeringConnection{id: 'pt-pcx-ext'}) "
        "RETURN p.requester_vpc_id AS vpc, p.requester_owner_id AS owner, p.requester_cidr_blocks AS cidrs",
    ).single()
    assert (facts['vpc'], facts['owner'], facts['cidrs']) == ('pt-vpc-c', 'pt-c1', ['10.9.0.0/16'])

    # Nothing of workspace 2 was written or reached by pt-a1's load.
    tenant2 = _rows(
        neo4j_session,
        "MATCH (n) WHERE n.id IN ['pt-vpc-c', 'pt-vpc-c|10.9.0.0/16'] RETURN n.id, n.lastupdated, "
        "COUNT { (n)--(:AWSPeeringConnection) } AS peerings",
    )
    assert tenant2 == {('pt-vpc-c', 1, 1), ('pt-vpc-c|10.9.0.0/16', 1, 1)}
    assert _rows(
        neo4j_session, "MATCH (v:AWSVpc) WHERE v.id STARTS WITH 'pt-' AND v.arn IS NULL RETURN v.id",
    ) == set()

    # The blast-radius read sees the same-workspace peering with both VPCs.
    params = {'WORKSPACE_ID': 'pt-w1', 'ORGANIZATION_ID': 'pt-w1/o-1', 'AWS_ID': 'pt-a1'}
    gateways = blast_radius.read_routes(neo4j_session, params).gateways
    assert gateways['peering:pt-pcx-ws'].vpcs == frozenset({'pt-vpc-a', 'pt-vpc-b'})
    assert gateways['peering:pt-pcx-same'].vpcs == frozenset({'pt-vpc-a', 'pt-vpc-a2'})

    # pt-b1 (same workspace) synced pt-pcx-ws earlier into its own node; pt-a1 then drops pt-pcx-same
    # and pt-pcx-ext. pt-a1's cleanup removes only its own stale peerings.
    _load_peerings(neo4j_session, [rows[1]], 'pt-b1', old, 'pt-w1')
    _load_peerings(neo4j_session, [rows[1]], 'pt-a1', tag + 1, 'pt-w1')
    _run_peering_cleanup(neo4j_session, 'pt-w1', 'pt-w1/o-1', 'pt-a1', tag + 1)

    claims = _rows(
        neo4j_session,
        "MATCH (a:AWSAccount)-[:RESOURCE]->(p:AWSPeeringConnection) WHERE a.id STARTS WITH 'pt-' RETURN a.id, p.id",
    )
    assert claims == {('pt-a1', 'pt-pcx-ws'), ('pt-b1', 'pt-pcx-ws'), ('pt-c1', 'pt-pcx-ext')}
    assert _rows(
        neo4j_session,
        "MATCH (p:AWSPeeringConnection) WHERE p.id STARTS WITH 'pt-' AND NOT (p)<-[:RESOURCE]-() RETURN p.id",
    ) == set()
    assert _rows(
        neo4j_session,
        "MATCH (:AWSAccount{id: 'pt-c1'})-[:RESOURCE]->(p:AWSPeeringConnection)-[r]->(n) RETURN type(r), n.id",
    ) == {('REQUESTER_VPC', 'pt-vpc-c'), ('REQUESTER_CIDR', 'pt-vpc-c|10.9.0.0/16')}


def _run_peering_cleanup(neo4j_session, workspace_id, organization_id, account_id, update_tag=TEST_UPDATE_TAG):
    # GraphJob directly: run_cleanup_job logs and swallows query errors.
    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', 'aws_import_vpc_peering_cleanup.json'),
        {
            'WORKSPACE_ID': workspace_id, 'ORGANIZATION_ID': organization_id, 'AWS_ID': account_id,
            'UPDATE_TAG': update_tag, 'LIMIT_SIZE': 100,
        },
    )


def _ids(neo4j_session, label):
    return {
        r['id'] for r in neo4j_session.run(
            f"MATCH (n:{label}) WHERE n.id STARTS WITH 'pc-' RETURN n.id AS id",
        )
    }


def test_vpc_peering_cleanup_removes_only_this_accounts_stale_peer_stubs(neo4j_session):
    # Legacy graph shape: unclaimed peering nodes and peer VPC stubs, from before peerings were claimed.
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

    _load_peerings(neo4j_session, rows, 'pm-a1', TEST_UPDATE_TAG, 'pm-w1')

    left = neo4j_session.run(
        "MATCH (n) WHERE n.id STARTS WITH 'pm-' RETURN count(n) AS c",
    ).single()['c']
    assert left == 0
