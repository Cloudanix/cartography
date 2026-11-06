from cartography.intel.aws import route53
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
WORKSPACE, ORG = 'r53-ws1', 'r53-o1'
OTHER_WORKSPACE, OTHER_ORG = 'r53-ws2', 'r53-o2'
ACCOUNT, SIBLING_ACCOUNT, OTHER_ACCOUNT = 'r53-a1', 'r53-a2', 'r53-b1'
NAME_SERVER = 'ns-1.awsdns-01.com'
PRIVATE_NAME_SERVER = 'ns-0.awsdns-00.com'
OWN_LB = 'own-lb-1.us-east-1.elb.amazonaws.com'
FOREIGN_LB = 'other-lb-1.us-east-1.elb.amazonaws.com'
FOREIGN_EC2 = 'ec2-1-2-3-4.compute-1.amazonaws.com'


def _zone(zone_id, name, private=False):
    return {
        'Id': f'/hostedzone/{zone_id}', 'Name': f'{name}.', 'Config': {'PrivateZone': private},
        'ResourceRecordSetCount': 1, 'arn': f'arn:aws:route53:::hostedzone/{zone_id}', 'consolelink': '',
    }


def _ns(name, server):
    return {'Name': f'{name}.', 'Type': 'NS', 'ResourceRecords': [{'Value': f'{server}.'}]}


def _cname(name, value):
    return {'Name': f'{name}.', 'Type': 'CNAME', 'ResourceRecords': [{'Value': value}]}


def _a(name, ip):
    return {'Name': f'{name}.', 'Type': 'A', 'ResourceRecords': [{'Value': ip}]}


def _alias(name, target):
    return {'Name': f'{name}.', 'Type': 'A', 'AliasTarget': {'DNSName': f'{target}.'}}


def _load(neo4j_session, account_id, zones):
    route53.load_dns_details(neo4j_session, zones, account_id, TEST_UPDATE_TAG)


def _seed(neo4j_session):
    # The other tenant reuses the same names: a dev.example.com zone on the same AWS name servers, a
    # private corp.local zone (every private zone uses the same AWS name servers), app.internal, and
    # nodes whose DNS names this tenant's records point to.
    create_test_org_account(neo4j_session, WORKSPACE, ORG, ACCOUNT)
    create_test_org_account(neo4j_session, WORKSPACE, ORG, SIBLING_ACCOUNT)
    create_test_org_account(neo4j_session, OTHER_WORKSPACE, OTHER_ORG, OTHER_ACCOUNT)
    _load(
        neo4j_session, ACCOUNT, [
            (
                _zone('Z-R53-A1', 'example.com'), [
                    _ns('dev.example.com', NAME_SERVER),
                    _cname('www.example.com', 'app.internal'),
                    _alias('lb.example.com', OWN_LB),
                    _alias('other.example.com', FOREIGN_LB),
                    _cname('host.example.com', FOREIGN_EC2),
                ],
            ),
            (_zone('Z-R53-A1P', 'corp.local', private=True), [_ns('corp.local', PRIVATE_NAME_SERVER)]),
        ],
    )
    _load(
        neo4j_session, SIBLING_ACCOUNT, [
            (_zone('Z-R53-A2', 'dev.example.com'), [_ns('dev.example.com', NAME_SERVER)]),
            (_zone('Z-R53-A2I', 'internal', private=True), [_a('app.internal', '10.0.0.1')]),
        ],
    )
    _load(
        neo4j_session, OTHER_ACCOUNT, [
            (_zone('Z-R53-B', 'dev.example.com'), [_ns('dev.example.com', NAME_SERVER)]),
            (_zone('Z-R53-BI', 'internal', private=True), [_a('app.internal', '10.0.0.1')]),
            (_zone('Z-R53-BP', 'corp.local', private=True), [_ns('corp.local', PRIVATE_NAME_SERVER)]),
        ],
    )
    neo4j_session.run(
        """
        MATCH (a2:AWSAccount{id: $sibling}), (b:AWSAccount{id: $other})
        MERGE (a2)-[:RESOURCE]->(:LoadBalancerV2{id: $own_lb, dnsname: $own_lb})
        MERGE (b)-[:RESOURCE]->(:LoadBalancerV2{id: $foreign_lb, dnsname: $foreign_lb})
        MERGE (b)-[:RESOURCE]->(:EC2Instance{id: 'i-r53-b', publicdnsname: $foreign_ec2})
        """,
        sibling=SIBLING_ACCOUNT, other=OTHER_ACCOUNT, own_lb=OWN_LB, foreign_lb=FOREIGN_LB, foreign_ec2=FOREIGN_EC2,
    )


def _pairs(neo4j_session, query):
    return {(r['a'], r['b']) for r in neo4j_session.run(query)}


def test_route53_links_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session)

    route53.link_aws_resources(neo4j_session, ACCOUNT, WORKSPACE, TEST_UPDATE_TAG)
    route53.link_sub_zones(neo4j_session, ACCOUNT, WORKSPACE, TEST_UPDATE_TAG)

    # The delegation reaches the sibling account's child zone only; corp.local is nobody's child.
    assert _pairs(
        neo4j_session,
        "MATCH (z:AWSDNSZone)-[:SUBZONE]->(c:AWSDNSZone) WHERE z.zoneid CONTAINS 'R53' "
        "RETURN z.zoneid AS a, c.zoneid AS b",
    ) == {('/hostedzone/Z-R53-A1', '/hostedzone/Z-R53-A2')}
    assert _pairs(
        neo4j_session,
        "MATCH (r:AWSDNSRecord)-[:DNS_POINTS_TO]->(t) WHERE r.id CONTAINS 'R53' AND NOT t:NameServer "
        "RETURN r.name AS a, t.id AS b",
    ) == {
        # an NS record's value is its own name: it points at the child zone's apex NS record
        ('dev.example.com', '/hostedzone/Z-R53-A2/dev.example.com/NS'),
        ('www.example.com', '/hostedzone/Z-R53-A2I/app.internal/A'),
        ('lb.example.com', OWN_LB),
    }
    # The shared name server carries no tenant's zone console link.
    assert neo4j_session.run(
        "MATCH (ns:NameServer{id: $id}) RETURN ns.consolelink AS link", id=NAME_SERVER,
    ).single()['link'] is None


def test_route53_cleanup_deletes_own_stale_records_only(neo4j_session):
    create_test_org_account(neo4j_session, 'r53r-ws1', 'r53r-o1', 'r53r-a1')
    create_test_org_account(neo4j_session, 'r53r-ws2', 'r53r-o2', 'r53r-b1')
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: 'r53r-a1'}), (b:AWSAccount{id: 'r53r-b1'})
        MERGE (a)-[:RESOURCE]->(za:AWSDNSZone:DNSZone{zoneid: 'r53r-za'}) SET za.lastupdated = $tag
        MERGE (a)-[:RESOURCE]->(gone:AWSDNSZone:DNSZone{zoneid: 'r53r-za-gone'}) SET gone.lastupdated = 1
        MERGE (b)-[:RESOURCE]->(zb:AWSDNSZone:DNSZone{zoneid: 'r53r-zb'}) SET zb.lastupdated = 5
        MERGE (:AWSDNSRecord:DNSRecord{id: 'r53r-a-fresh', lastupdated: $tag})-[:MEMBER_OF_DNS_ZONE]->(za)
        MERGE (:AWSDNSRecord:DNSRecord{id: 'r53r-a-stale', lastupdated: 1})-[:MEMBER_OF_DNS_ZONE]->(za)
        MERGE (:AWSDNSRecord:DNSRecord{id: 'r53r-a-in-gone-zone', lastupdated: 1})-[:MEMBER_OF_DNS_ZONE]->(gone)
        MERGE (:AWSDNSRecord:DNSRecord{id: 'r53r-b-other-tag', lastupdated: 5})-[:MEMBER_OF_DNS_ZONE]->(zb)
        """,
        tag=TEST_UPDATE_TAG,
    )

    route53.cleanup_route53(
        neo4j_session, {
            'WORKSPACE_ID': 'r53r-ws1', 'ORGANIZATION_ID': 'r53r-o1', 'AWS_ID': 'r53r-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )

    assert {
        r['id'] for r in neo4j_session.run(
            "MATCH (n:AWSDNSRecord) WHERE n.id STARTS WITH 'r53r-' RETURN n.id AS id",
        )
    } == {'r53r-a-fresh', 'r53r-b-other-tag'}


def test_route53_cleanup_drops_own_name_server_links_not_shared_name_servers(neo4j_session):
    create_test_org_account(neo4j_session, 'r53c-ws1', 'r53c-o1', 'r53c-a1')
    create_test_org_account(neo4j_session, 'r53c-ws2', 'r53c-o2', 'r53c-b1')
    neo4j_session.run(
        """
        MERGE (shared:NameServer{id: 'r53c-shared'})
        MERGE (own:NameServer{id: 'r53c-own'})
        WITH shared, own
        MATCH (a:AWSAccount{id: 'r53c-a1'}), (b:AWSAccount{id: 'r53c-b1'})
        MERGE (a)-[:RESOURCE]->(za:AWSDNSZone:DNSZone{zoneid: 'r53c-za'}) SET za.lastupdated = $tag
        MERGE (b)-[:RESOURCE]->(zb:AWSDNSZone:DNSZone{zoneid: 'r53c-zb'}) SET zb.lastupdated = 5
        MERGE (za)-[:NAMESERVER{lastupdated: 1}]->(shared)
        MERGE (za)-[:NAMESERVER{lastupdated: 1}]->(own)
        MERGE (zb)-[:NAMESERVER{lastupdated: 5}]->(shared)
        """,
        tag=TEST_UPDATE_TAG,
    )

    route53.cleanup_route53(
        neo4j_session, {
            'WORKSPACE_ID': 'r53c-ws1', 'ORGANIZATION_ID': 'r53c-o1', 'AWS_ID': 'r53c-a1',
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )

    # This account's stale links go; the name server another tenant still uses stays, the orphan goes.
    assert _pairs(
        neo4j_session,
        "MATCH (z:AWSDNSZone)-[:NAMESERVER]->(ns:NameServer) WHERE ns.id STARTS WITH 'r53c-' "
        "RETURN z.zoneid AS a, ns.id AS b",
    ) == {('r53c-zb', 'r53c-shared')}
    assert {
        r['id'] for r in neo4j_session.run("MATCH (ns:NameServer) WHERE ns.id STARTS WITH 'r53c-' RETURN ns.id AS id")
    } == {'r53c-shared'}


def _record(kind, zone):
    return {'id': f'{zone}-{kind}', 'name': f'{kind}.example.com', 'zoneid': zone, 'type': kind, 'value': 'v'}


def test_route53_records_join_only_the_accounts_zones(neo4j_session):
    create_test_org_account(neo4j_session, 'r53z-ws-own', 'r53z-org-own', 'r53z-own')
    create_test_org_account(neo4j_session, 'r53z-ws-other', 'r53z-org-other', 'r53z-other')
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: 'r53z-own'}), (other:AWSAccount{id: 'r53z-other'})
        MERGE (own)-[:RESOURCE]->(:AWSDNSZone{zoneid: 'Z-OWN'})
        MERGE (other)-[:RESOURCE]->(:AWSDNSZone{zoneid: 'Z-OTHER'})
        """,
    )

    for zone in ('Z-OWN', 'Z-OTHER'):
        route53.load_a_records(neo4j_session, [_record('A', zone)], TEST_UPDATE_TAG, 'r53z-own')
        route53.load_alias_records(neo4j_session, [_record('ALIAS', zone)], TEST_UPDATE_TAG, 'r53z-own')
        route53.load_cname_records(neo4j_session, [_record('CNAME', zone)], TEST_UPDATE_TAG, 'r53z-own')
        route53.load_ns_records(
            neo4j_session, [{**_record('NS', zone), 'name': 'example.com', 'servers': ['ns-1.example.net']}],
            'example.com', TEST_UPDATE_TAG, '', 'r53z-own',
        )

    linked = neo4j_session.run(
        "MATCH (z:AWSDNSZone)-[r:NAMESERVER|MEMBER_OF_DNS_ZONE]-() WHERE z.zoneid STARTS WITH 'Z-' "
        "RETURN z.zoneid AS z, type(r) AS r",
    )
    assert sorted((r['z'], r['r']) for r in linked) == [
        ('Z-OWN', 'MEMBER_OF_DNS_ZONE'), ('Z-OWN', 'MEMBER_OF_DNS_ZONE'), ('Z-OWN', 'MEMBER_OF_DNS_ZONE'),
        ('Z-OWN', 'MEMBER_OF_DNS_ZONE'), ('Z-OWN', 'NAMESERVER'),
    ]
