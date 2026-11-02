"""
End-to-end check of the AWS exposure layers on a graph shaped like the loaders write it.
Scenarios follow docs/exposure-layers/plan.md section 8.
"""
import json

from cartography.intel.aws import exposure_layers
from cartography.intel.aws.ec2.load_balancer_v2s import load_load_balancer_v2_listeners
from cartography.intel.aws.ec2.load_balancer_v2s import transform_listeners
from cartography.intel.aws.ec2.network_acls import load_network_acls
from cartography.intel.aws.ec2.network_acls import transform_network_acls
from cartography.intel.aws.ec2.route_tables import load_route_tables
from cartography.intel.aws.ec2.tgw import load_tgw_attachments
from cartography.intel.aws.ec2.tgw import load_transit_gateways
from cartography.intel.aws.ec2.vpc_peerings import load_accepter_cidrs
from cartography.intel.aws.ec2.vpc_peerings import load_requester_cidrs
from cartography.intel.aws.ec2.vpc_peerings import load_vpc_peerings
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TAG = 1700000000
WS, ORG, ACCOUNT = 'ws-xl', 'o-xl', '111122223333'
OTHER_WS, OTHER_ORG, OTHER_ACCOUNT = 'ws-xl-other', 'o-xl-other', '444455556666'
VPC = 'vpc-xl'

ALL = {'Protocol': '-1', 'RuleAction': 'allow', 'CidrBlock': '0.0.0.0/0'}


def _run(session, query, **kw):
    session.run(query, **kw).consume()


def _subnet(session, subnet_id, igw_v4=False, igw_v6=False, account=ACCOUNT):
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account})
        MERGE (vpc:AWSVpc{id: $vpc})
        MERGE (a)-[:RESOURCE]->(s:EC2Subnet{subnetid: $subnet_id}) SET s.id = $subnet_id
        MERGE (s)-[:MEMBER_OF_AWS_VPC]->(vpc)
        MERGE (rt:EC2RouteTable{id: 'rtb-' + $subnet_id})
        MERGE (rt)-[:HAS_ASSOCIATION]->(asc:EC2RouteTableAssociation{id: 'rtbassoc-' + $subnet_id})
        MERGE (s)-[:HAS_EXPLICIT_ASSOCIATION]->(asc)
        WITH rt
        UNWIND $routes AS route
            MERGE (r:EC2Route{id: rt.id + route.dst})
            SET r.gateway_id = 'igw-xl', r.destination_cidr_block = route.v4, r.destination_ipv6_cidr_block = route.v6
            MERGE (rt)-[:MEMBER_OF_ROUTE_TABLE]->(r)
        """,
        account=account, vpc=VPC, subnet_id=subnet_id,
        routes=([{'dst': 'v4', 'v4': '0.0.0.0/0', 'v6': None}] if igw_v4 else []) +
        ([{'dst': 'v6', 'v4': None, 'v6': '::/0'}] if igw_v6 else []),
    )


def _nacl(session, acl_id, subnet_id, entries):
    acls = [{
        'NetworkAclId': acl_id, 'VpcId': VPC, 'IsDefault': False, 'OwnerId': ACCOUNT,
        'Entries': entries, 'Associations': [{'SubnetId': subnet_id}],
    }]
    rows = transform_network_acls(acls, 'us-east-1', ACCOUNT)
    load_network_acls(session, *rows, ACCOUNT, TAG)


def _sg(session, sg_id, rules, account=ACCOUNT, vpc=VPC):
    """rules: (protocol, from, to, cidrs, source_sg_ids), stored like security_groups.py."""
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account})
        MERGE (vpc:AWSVpc{id: $vpc})
        MERGE (a)-[:RESOURCE]->(sg:EC2SecurityGroup{id: $sg_id})
        MERGE (vpc)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        WITH sg
        UNWIND $rules AS r
            MERGE (rule:IpPermissionInbound:IpRule{ruleid: $sg_id + '/IpPermissions/' + r.key})
            SET rule.protocol = r.protocol, rule.fromport = r.from, rule.toport = r.to
            MERGE (rule)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
            FOREACH (cidr IN r.cidrs |
                MERGE (rng:IpRange{id: rule.ruleid + '/' + cidr}) SET rng.range = cidr
                FOREACH (_ IN CASE WHEN cidr CONTAINS ':' THEN [1] ELSE [] END |
                    REMOVE rng:IpRange SET rng:Ipv6Range)
                MERGE (rng)-[:MEMBER_OF_IP_RULE]->(rule))
            FOREACH (src IN r.sources |
                MERGE (s:EC2SecurityGroup{id: src})
                MERGE (rule)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(s))
        """,
        account=account, vpc=vpc, sg_id=sg_id,
        rules=[
            {'key': f'{p}{f}{t}{i}', 'protocol': p, 'from': f, 'to': t, 'cidrs': c, 'sources': s}
            for i, (p, f, t, c, s) in enumerate(rules)
        ],
    )


def _instance(session, iid, subnet, sgs, public_ip=None, ipv6=None, private_ip='10.0.9.9', image=None):
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account})
        MERGE (a)-[:RESOURCE]->(i:EC2Instance{id: $iid})
        SET i.publicipaddress = $public_ip, i.privateipaddress = $private_ip
        MERGE (a)-[:RESOURCE]->(eni:NetworkInterface{id: 'eni-' + $iid})
        SET eni.public_ip = $public_ip, eni.ipv6_addresses = $ipv6, eni.private_ip_address = $private_ip
        MERGE (i)-[:NETWORK_INTERFACE]->(eni)
        WITH i, eni
        MATCH (s:EC2Subnet{subnetid: $subnet}) MERGE (eni)-[:PART_OF_SUBNET]->(s)
        WITH i, eni
        UNWIND $sgs AS sg_id
            MATCH (sg:EC2SecurityGroup{id: sg_id}) MERGE (eni)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account=ACCOUNT, iid=iid, subnet=subnet, sgs=sgs, public_ip=public_ip, ipv6=ipv6 or [],
        private_ip=private_ip,
    )
    if image:
        _run(
            session,
            "MATCH (i:EC2Instance{id: $iid}) MERGE (img:EC2Image{id: $img}) SET img.name = $img "
            "MERGE (i)-[:CHILDREN]->(img)",
            iid=iid, img=image,
        )


def _lb(session, lb_id, subnet, sgs, listeners, targets):
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account}), (s:EC2Subnet{subnetid: $subnet})
        MERGE (a)-[:RESOURCE]->(lb:LoadBalancerV2{id: $lb_id})
        SET lb.scheme = 'internet-facing', lb.type = 'application', lb.target_group_arns = ['tg-xl'],
            lb.arn = 'arn:' + $lb_id
        MERGE (lb)-[:SUBNET]->(s)
        WITH lb
        UNWIND $sgs AS sg_id MATCH (sg:EC2SecurityGroup{id: sg_id}) MERGE (lb)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        WITH DISTINCT lb
        UNWIND $listeners AS port
            MERGE (l:Endpoint:ELBV2Listener{id: $lb_id + '/' + toString(port)}) SET l.port = port, l.protocol = 'HTTPS'
            MERGE (lb)-[:ELBV2_LISTENER]->(l)
        WITH DISTINCT lb
        UNWIND $targets AS t
            MATCH (i:EC2Instance{id: t.instance})
            MERGE (lb)-[e:EXPOSE]->(i) SET e.port = t.port, e.protocol = 'HTTP', e.target_group_arn = 'tg-xl'
        """,
        account=ACCOUNT, lb_id=lb_id, subnet=subnet, sgs=sgs, listeners=listeners, targets=targets,
    )


def _rds(session, rid, public, subnet, sgs, port=5432):
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account}), (s:EC2Subnet{subnetid: $subnet})
        MERGE (a)-[:RESOURCE]->(r:RDSInstance{id: $rid})
        SET r.publicly_accessible = $public, r.endpoint_port = $port, r.engine = 'postgres',
            r.engine_version = '15.4', r.iam_database_authentication_enabled = false
        MERGE (r)-[:MEMBER_OF_DB_SUBNET_GROUP]->(g:DBSubnetGroup{name: 'dbsg-' + $rid})
        MERGE (g)-[:CONNECTED_TO]->(s)
        WITH r
        UNWIND $sgs AS sg_id MATCH (sg:EC2SecurityGroup{id: sg_id}) MERGE (r)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account=ACCOUNT, rid=rid, public=public, subnet=subnet, sgs=sgs, port=port,
    )


def _managed(session):
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account})
        MERGE (a)-[:RESOURCE]->(lf:AWSLambda{id: 'fn-url'})
        SET lf.functionurl = 'https://x.lambda-url.us-east-1.on.aws/', lf.functionurl_auth_type = 'NONE',
            lf.runtime = 'python3.12'
        MERGE (a)-[:RESOURCE]->(api:APIGatewayRestAPI{id: 'api-open'})
        SET api.endpoint_conf_types = ['REGIONAL'], api.disableexecuteapiendpoint = false
        MERGE (api)-[:RESOURCE]->(:APIGatewayResource{id: 'res-1', unauthenticated_methods: ['GET']})
        // get_resources failed: no resources, or methods stored null next to an empty list.
        MERGE (a)-[:RESOURCE]->(:APIGatewayRestAPI{id: 'api-no-resources'})
        MERGE (a)-[:RESOURCE]->(api_null:APIGatewayRestAPI{id: 'api-null-methods'})
        MERGE (api_null)-[:RESOURCE]->(:APIGatewayResource{id: 'res-empty', unauthenticated_methods: []})
        MERGE (api_null)-[:RESOURCE]->(:APIGatewayResource{id: 'res-unread'})
        MERGE (a)-[:RESOURCE]->(c:ElasticacheCluster{id: 'cache-1'})
        SET c.engine = 'redis', c.engine_version = '7.1.0', c.auth_token_enabled = true, c.port = 6379
        MERGE (a)-[:RESOURCE]->(b:S3Bucket{id: 'bucket-public'}) SET b.anonymous_access = true
        MERGE (a)-[:RESOURCE]->(:S3Bucket{id: 'bucket-private'})
        """,
        account=ACCOUNT,
    )


def _alb_listener(lb_id, port, protocol, default, rules):
    """API shape of describe_listeners + describe_rules; rules None = describe_rules denied."""
    def actions(*types):
        return [{'Type': t, 'Order': i + 1} for i, t in enumerate(types)]
    return {
        'ListenerArn': f'{lb_id}/{port}', 'Port': port, 'Protocol': protocol, 'DefaultActions': actions(*default),
        'Rules': None if rules is None else [{'IsDefault': True, 'Actions': actions(*default)}] + [
            {'IsDefault': False, 'Actions': actions(*r)} for r in rules
        ],
    }


def _build_alb_auth(session):
    """lb-auth: every path authenticates; lb-mixed: one rule forwards directly; lb-denied: rules unread."""
    oidc = ('authenticate-oidc', 'forward')
    cases = {
        'lb-auth': [
            _alb_listener('lb-auth', 443, 'HTTPS', oidc, [oidc, ('fixed-response',)]),
            _alb_listener('lb-auth', 80, 'HTTP', ('redirect',), []),
        ],
        'lb-mixed': [_alb_listener('lb-mixed', 443, 'HTTPS', ('authenticate-cognito', 'forward'), [('forward',)])],
        'lb-denied': [_alb_listener('lb-denied', 443, 'HTTPS', oidc, None)],
    }
    for n, (lb_id, listeners) in enumerate(cases.items()):
        instance = f'i-behind-{lb_id}'
        _instance(session, instance, 'subnet-private', ['sg-app'], private_ip=f'10.0.2.{n}')
        _lb(session, lb_id, 'subnet-public', ['sg-lb'], [443], [{'instance': instance, 'port': 8080}])
        load_load_balancer_v2_listeners(session, lb_id, transform_listeners(listeners), TAG)


def _vpc(session, vpc_id, cidr):
    """An account-owned VPC with one subnet holding the first /24 of `cidr`."""
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account})
        MERGE (a)-[:RESOURCE]->(v:AWSVpc{id: $vpc})
        MERGE (v)-[:BLOCK_ASSOCIATION]->(:AWSCidrBlock:AWSIpv4CidrBlock{id: $vpc + '|' + $cidr, cidr_block: $cidr})
        MERGE (a)-[:RESOURCE]->(s:EC2Subnet{subnetid: 'subnet-' + $vpc})
        SET s.id = s.subnetid, s.cidr_block = $subnet_cidr
        MERGE (s)-[:MEMBER_OF_AWS_VPC]->(v)
        """,
        account=ACCOUNT, vpc=vpc_id, cidr=cidr, subnet_cidr=cidr.replace('.0.0/16', '.1.0/24'),
    )


def _route_table(vpc_id, routes):
    """describe_route_tables shape; routes: (destination, pcx-* or tgw-*)."""
    key = {'pcx': 'VpcPeeringConnectionId', 'tgw': 'TransitGatewayId'}
    return {
        'RouteTableId': f'rtb-{vpc_id}', 'VpcId': vpc_id, 'OwnerId': ACCOUNT, 'region': 'us-east-1',
        'Associations': [{
            'RouteTableAssociationId': f'rtbassoc-{vpc_id}', 'RouteTableId': f'rtb-{vpc_id}',
            'SubnetId': f'subnet-{vpc_id}', 'Main': False,
        }],
        'Routes': [
            {'DestinationCidrBlock': dst, key[target.split('-')[0]]: target, 'State': 'active'}
            for dst, target in routes
        ],
    }


def _peering(pcx_id, requester, accepter):
    def side(vpc_id):
        return {'VpcId': vpc_id, 'OwnerId': ACCOUNT, 'Region': 'us-east-1', 'PeeringOptions': {}, 'CidrBlockSet': []}
    return {
        'VpcPeeringConnectionId': pcx_id, 'RequesterVpcInfo': side(requester), 'AccepterVpcInfo': side(accepter),
        'Status': {'Code': 'active', 'Message': 'Active'},
    }


def _build_cross_vpc(session):
    """
    vpc-src (10.1/16, i-src) peers with vpc-peer and vpc-noroute, and shares tgw-xl with vpc-tgw.
    vpc-noroute routes back but vpc-src has no route to it.
    """
    for vpc_id, cidr in [
        ('vpc-src', '10.1.0.0/16'), ('vpc-peer', '10.2.0.0/16'), ('vpc-tgw', '10.3.0.0/16'),
        ('vpc-noroute', '10.4.0.0/16'),
    ]:
        _vpc(session, vpc_id, cidr)
    peerings = [_peering('pcx-ok', 'vpc-src', 'vpc-peer'), _peering('pcx-noroute', 'vpc-src', 'vpc-noroute')]
    for loader in (load_vpc_peerings, load_accepter_cidrs, load_requester_cidrs):
        loader(session, peerings, 'us-east-1', ACCOUNT, TAG)
    tgw = {
        'TransitGatewayId': 'tgw-xl', 'TransitGatewayArn': 'arn:aws:ec2:us-east-1:1:transit-gateway/tgw-xl',
        'OwnerId': ACCOUNT, 'State': 'available', 'Description': '',
    }
    load_transit_gateways(session, [tgw], 'us-east-1', ACCOUNT, TAG)
    load_tgw_attachments(
        session, [
            {
                'TransitGatewayAttachmentId': f'tgw-attach-{v}', 'TransitGatewayId': 'tgw-xl', 'ResourceType': 'vpc',
                'State': 'available', 'VpcId': v, 'SubnetIds': [f'subnet-{v}'],
            } for v in ('vpc-src', 'vpc-tgw')
        ], 'us-east-1', ACCOUNT, TAG,
    )
    load_route_tables(
        session, [
            _route_table('vpc-src', [('10.2.0.0/16', 'pcx-ok'), ('10.3.0.0/16', 'tgw-xl')]),
            _route_table('vpc-peer', [('10.1.0.0/16', 'pcx-ok')]),
            _route_table('vpc-tgw', [('10.0.0.0/8', 'tgw-xl')]),
            _route_table('vpc-noroute', [('10.1.0.0/16', 'pcx-noroute')]),
        ], ACCOUNT, TAG,
    )

    pg = ('tcp', 5432, 5432)
    _sg(session, 'sg-src', [], vpc='vpc-src')
    _sg(session, 'sg-db-peer', [(*pg, [], ['sg-src'])], vpc='vpc-peer')
    _sg(session, 'sg-cache-peer', [('tcp', 6379, 6379, ['10.1.0.0/16'], [])], vpc='vpc-peer')
    _sg(session, 'sg-db-tgw', [(*pg, ['10.1.1.0/24'], [])], vpc='vpc-tgw')
    _sg(session, 'sg-db-tgw-ref', [(*pg, [], ['sg-src'])], vpc='vpc-tgw')
    _sg(session, 'sg-db-noroute', [(*pg, ['10.0.0.0/8'], [])], vpc='vpc-noroute')
    _instance(session, 'i-src', 'subnet-vpc-src', ['sg-src'], private_ip='10.1.1.10')
    _rds(session, 'db-peer', False, 'subnet-vpc-peer', ['sg-db-peer'])
    _rds(session, 'db-tgw', False, 'subnet-vpc-tgw', ['sg-db-tgw'])
    _rds(session, 'db-tgw-ref', False, 'subnet-vpc-tgw', ['sg-db-tgw-ref'])
    _rds(session, 'db-noroute', False, 'subnet-vpc-noroute', ['sg-db-noroute'])
    # ElastiCache has no subnets in the graph: the whole VPC's routes and CIDRs stand in.
    _run(
        session,
        """
        MATCH (a:AWSAccount{id: $account}), (sg:EC2SecurityGroup{id: 'sg-cache-peer'})
        MERGE (a)-[:RESOURCE]->(c:ElasticacheCluster{id: 'cache-peer'}) SET c.port = 6379
        MERGE (c)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account=ACCOUNT,
    )


def _build(session):
    create_test_org_account(session, WS, ORG, ACCOUNT)
    create_test_org_account(session, OTHER_WS, OTHER_ORG, OTHER_ACCOUNT)
    _subnet(session, 'subnet-public', igw_v4=True, igw_v6=True)
    _subnet(session, 'subnet-private')
    _subnet(session, 'subnet-nacl-deny22', igw_v4=True)
    _subnet(session, 'subnet-nacl-noreturn', igw_v4=True)
    _nacl(
        session, 'acl-deny22', 'subnet-nacl-deny22', [
            {
                'RuleNumber': 100, 'Egress': False, 'Protocol': '6', 'RuleAction': 'deny', 'CidrBlock': '0.0.0.0/0',
                'PortRange': {'From': 22, 'To': 22},
            },
            {'RuleNumber': 200, 'Egress': False, **ALL},
            {'RuleNumber': 100, 'Egress': True, **ALL},
            {'RuleNumber': 32767, 'Egress': False, 'Protocol': '-1', 'RuleAction': 'deny', 'CidrBlock': '0.0.0.0/0'},
        ],
    )
    _nacl(
        session, 'acl-noreturn', 'subnet-nacl-noreturn', [
            {'RuleNumber': 100, 'Egress': False, **ALL},
            {
                'RuleNumber': 100, 'Egress': True, 'Protocol': '6', 'RuleAction': 'allow', 'CidrBlock': '0.0.0.0/0',
                'PortRange': {'From': 443, 'To': 443},
            },
        ],
    )
    _sg(session, 'sg-open', [('tcp', 22, 22, ['0.0.0.0/0'], []), ('tcp', 443, 443, ['0.0.0.0/0'], [])])
    _sg(session, 'sg-open6', [('tcp', 80, 80, ['::/0'], [])])
    _sg(session, 'sg-office', [('tcp', 22, 22, ['203.0.113.0/24'], [])])
    _sg(session, 'sg-ssh', [('tcp', 22, 22, ['0.0.0.0/0'], [])])
    _sg(session, 'sg-lb', [('tcp', 443, 443, ['0.0.0.0/0'], [])])
    _sg(session, 'sg-app', [('tcp', 8080, 8080, [], ['sg-lb'])])
    _sg(session, 'sg-db', [('tcp', 5432, 5432, [], ['sg-app'])])
    _sg(session, 'sg-db-cidr', [('tcp', 5432, 5432, ['10.0.0.0/16'], [])])
    _sg(session, 'sg-db-open', [('tcp', 5432, 5432, ['0.0.0.0/0'], [])])
    _sg(session, 'sg-other-open', [('-1', None, None, ['0.0.0.0/0'], [])], account=OTHER_ACCOUNT)

    _instance(
        session, 'i-open', 'subnet-public', ['sg-open'], public_ip='54.0.0.1',
        image='ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20240207',
    )
    _instance(session, 'i-office', 'subnet-public', ['sg-office'], public_ip='54.0.0.2')
    _instance(session, 'i-noroute', 'subnet-private', ['sg-open'], public_ip='54.0.0.3')
    _instance(session, 'i-nacl', 'subnet-nacl-deny22', ['sg-open'], public_ip='54.0.0.4')
    _instance(session, 'i-noreturn', 'subnet-nacl-noreturn', ['sg-open'], public_ip='54.0.0.5')
    # Only port 22 is open, and acl-deny22 denies it: no port left.
    _instance(session, 'i-nacl-ssh', 'subnet-nacl-deny22', ['sg-ssh'], public_ip='54.0.0.6')
    _instance(session, 'i-ipv6', 'subnet-public', ['sg-open6'], ipv6=['2600:1f18::1'])
    _instance(session, 'i-app', 'subnet-private', ['sg-app'], private_ip='10.0.1.5')
    _instance(session, 'i-elsewhere', 'subnet-private', ['sg-office'], private_ip='192.168.1.1')
    _lb(session, 'lb-1', 'subnet-public', ['sg-lb'], [443], [{'instance': 'i-app', 'port': 8080}])
    _rds(session, 'db-private-subnet', True, 'subnet-private', ['sg-db-open'])
    _rds(session, 'db-public', True, 'subnet-public', ['sg-db-open'])
    _rds(session, 'db-app', False, 'subnet-private', ['sg-db', 'sg-db-cidr'])
    _managed(session)
    _build_alb_auth(session)
    _build_cross_vpc(session)
    # Stale edge from a previous run must disappear.
    _run(
        session,
        "MATCH (i:EC2Instance{id: 'i-elsewhere'}), (r:RDSInstance{id: 'db-app'}) "
        "MERGE (i)-[e:CAN_NETWORK_REACH]->(r) SET e.lastupdated = 1",
    )
    # A node in another workspace must stay untouched.
    _run(
        session,
        "MATCH (a:AWSAccount{id: $other}) "
        "MERGE (a)-[:RESOURCE]->(:EC2Instance{id: 'i-other', publicipaddress: '1.1.1.1'})",
        other=OTHER_ACCOUNT,
    )


def _props(session, label, node_id):
    return session.run(f"MATCH (n:{label}{{id: $id}}) RETURN properties(n) AS p", id=node_id).single()["p"]


def test_aws_exposure_layers_end_to_end(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, exposure_job_parameters(WS, ORG, ACCOUNT, TAG))

    def reach(label, node_id):
        p = _props(neo4j_session, label, node_id)
        return p['internet_reachable'], p['internet_reachable_ports'], p['internet_reachable_via'], p['public_reasons']

    # L1 + L2
    assert reach('EC2Instance', 'i-open') == (True, ['tcp:22-22', 'tcp:443-443'], ['direct_ipv4'], ['public_ip'])
    assert reach('EC2Instance', 'i-office') == (False, [], [], ['public_ip'])  # scenario 1
    assert reach('EC2Instance', 'i-noroute')[0] is False  # scenario 2
    assert reach('EC2Instance', 'i-nacl')[:2] == (True, ['tcp:443-443'])  # scenario 5
    assert reach('EC2Instance', 'i-noreturn')[0] is False  # scenario 6
    assert reach('EC2Instance', 'i-ipv6') == (True, ['tcp:80-80'], ['direct_ipv6'], ['ipv6_address'])
    assert reach('EC2Instance', 'i-app') == (True, ['tcp:8080-8080'], ['elbv2:lb-1'], [])  # scenario 4
    assert reach('LoadBalancerV2', 'lb-1') == (True, ['tcp:443-443'], ['direct_ipv4'], ['internet_facing_scheme'])
    assert reach('NetworkInterface', 'eni-i-open')[:2] == (True, ['tcp:22-22', 'tcp:443-443'])
    assert reach('RDSInstance', 'db-private-subnet') == (False, [], [], ['publicly_accessible'])  # scenario 3
    assert reach('RDSInstance', 'db-public')[:2] == (True, ['tcp:5432-5432'])
    assert reach('AWSLambda', 'fn-url') == (True, ['tcp:443-443'], ['function_url'], ['function_url'])
    assert reach('APIGatewayRestAPI', 'api-open')[0] is True
    assert reach('ElasticacheCluster', 'cache-1')[0] is False
    assert reach('S3Bucket', 'bucket-public')[3] == ['public_resource_policy']

    # L1 + L2 context: per-entry paths with their hops, blockers of public unreachable nodes.
    def context(label, node_id):
        p = _props(neo4j_session, label, node_id)
        assert p['exposure_evaluated_at'] == TAG
        return json.loads(p['exposure_paths']), json.loads(p['exposure_blocked_by'])

    route_public = {'hop': 'route', 'id': 'rtb-subnet-public', 'rule': '0.0.0.0/0 -> igw-xl'}
    assert context('EC2Instance', 'i-open') == (
        [{
            'via': 'direct_ipv4', 'entry': {'type': 'public_ip', 'id': '54.0.0.1'},
            'ports': ['tcp:22-22', 'tcp:443-443'], 'hops': [route_public, {'hop': 'security_group', 'id': 'sg-open'}],
        }], [],
    )
    assert context('EC2Instance', 'i-app') == (
        [{
            'via': 'elbv2:lb-1', 'entry': {'type': 'elbv2', 'id': 'arn:lb-1', 'listener_ports': ['tcp:443-443']},
            'ports': ['tcp:8080-8080'], 'hops': [
                route_public, {'hop': 'security_group', 'id': 'sg-lb'},
                {'hop': 'listener', 'id': 'lb-1/443', 'rule': 'HTTPS 443'},
                {'hop': 'target_group', 'id': 'tg-xl', 'rule': 'HTTP 8080'},
                {'hop': 'security_group', 'id': 'sg-app'},
            ],
        }], [],
    )
    nacl_hops = context('EC2Instance', 'i-nacl')[0][0]['hops']
    assert {'hop': 'nacl', 'id': 'acl-deny22'} in nacl_hops
    no_route = {
        'hop': 'route', 'id': 'rtb-subnet-private', 'reason': 'no_internet_route',
        'detail': 'no 0.0.0.0/0 route to an internet gateway',
    }
    assert context('RDSInstance', 'db-private-subnet') == ([], [no_route])  # scenario 3
    assert context('EC2Instance', 'i-noroute') == ([], [no_route])  # scenario 2
    assert context('EC2Instance', 'i-office')[1] == [
        {'hop': 'security_group', 'id': 'sg-office', 'reason': 'not_allowed'},
    ]  # scenario 1
    assert context('EC2Instance', 'i-nacl-ssh')[1] == [
        {'hop': 'nacl', 'id': 'acl-deny22', 'reason': 'denied', 'ports': ['tcp:22-22']},
    ]  # scenario 5
    assert context('EC2Instance', 'i-noreturn')[1] == [{
        'hop': 'nacl', 'id': 'acl-noreturn', 'reason': 'return_path_denied', 'ports': ['tcp:22-22', 'tcp:443-443'],
    }]  # scenario 6
    # Not public: nothing to explain.
    assert context('ElasticacheCluster', 'cache-1') == ([], [])

    # L3
    def auth(label, node_id):
        p = _props(neo4j_session, label, node_id)
        return p['access_auth'], p['access_auth_reasons']

    assert auth('AWSLambda', 'fn-url') == ('none', ['function_url_auth_none'])
    assert auth('APIGatewayRestAPI', 'api-open') == ('none', ['method_authorization_none'])
    assert auth('APIGatewayRestAPI', 'api-no-resources') == ('unknown', ['methods_not_ingested'])
    assert auth('APIGatewayRestAPI', 'api-null-methods') == ('unknown', ['methods_not_ingested'])
    assert auth('RDSInstance', 'db-public') == ('required', ['database_credentials'])
    assert auth('ElasticacheCluster', 'cache-1') == ('required', ['auth_token'])
    assert auth('S3Bucket', 'bucket-public')[0] == 'none'
    assert auth('S3Bucket', 'bucket-private')[0] == 'required'
    assert auth('EC2Instance', 'i-open')[0] == 'unknown'
    # ALB authenticate actions: every listener path authenticates (redirect / fixed-response answer
    # at the LB), so the LB and the instance reached only through it require credentials.
    assert auth('LoadBalancerV2', 'lb-auth') == ('required', ['alb_authenticate_oidc'])
    assert auth('EC2Instance', 'i-behind-lb-auth') == ('required', ['alb_authenticate_oidc'])
    assert auth('LoadBalancerV2', 'lb-mixed') == ('unknown', ['backend_decides'])
    assert auth('EC2Instance', 'i-behind-lb-mixed') == ('unknown', ['self_managed_service'])
    assert auth('LoadBalancerV2', 'lb-denied') == ('unknown', ['backend_decides'])
    assert auth('LoadBalancerV2', 'lb-1') == ('unknown', ['backend_decides'])
    assert auth('EC2Instance', 'i-app') == ('unknown', ['self_managed_service'])
    listener = _props(neo4j_session, 'ELBV2Listener', 'lb-auth/443')
    assert (listener['all_paths_authenticated'], listener['auth_action_types']) == (True, ['authenticate-oidc'])
    assert 'all_paths_authenticated' not in _props(neo4j_session, 'ELBV2Listener', 'lb-denied/443')

    # L4
    def software(label, node_id):
        p = _props(neo4j_session, label, node_id)
        # A null source removes the property, so read it with get().
        return p['software_identity'], p.get('software_identity_source')

    assert software('RDSInstance', 'db-public') == (['postgres@15.4'], 'managed_config')
    assert software('ElasticacheCluster', 'cache-1') == (['redis@7.1.0'], 'managed_config')
    assert software('AWSLambda', 'fn-url') == (['python@3.12'], 'managed_config')
    assert software('EC2Instance', 'i-open') == (['ubuntu@22.04'], 'image_name')
    assert software('EC2Instance', 'i-office') == ([], None)

    # L5
    edges = {
        (r['src'], r['dst']): (r['via'], r['ports']) for r in neo4j_session.run(
            "MATCH (i:EC2Instance)-[e:CAN_NETWORK_REACH]->(d) "
            "RETURN i.id AS src, d.id AS dst, e.via AS via, e.ports AS ports",
        )
    }
    assert edges[('i-app', 'db-app')] == ('security_group', ['tcp:5432-5432'])
    # 10.0.9.9 sits in sg-db-cidr's 10.0.0.0/16.
    assert edges[('i-office', 'db-app')] == ('cidr', ['tcp:5432-5432'])
    # Outside every allowed CIDR and SG: the stale edge from a previous run is removed.
    assert ('i-elsewhere', 'db-app') not in edges
    # sg-db-open admits 0.0.0.0/0, which holds every private IP in the VPC.
    assert edges[('i-office', 'db-public')] == ('cidr', ['tcp:5432-5432'])
    # Cross-VPC: same-region peering honours SG references; TGW admits by CIDR only.
    assert edges[('i-src', 'db-peer')] == ('peering:pcx-ok', ['tcp:5432-5432'])
    assert edges[('i-src', 'cache-peer')] == ('peering:pcx-ok', ['tcp:6379-6379'])
    assert edges[('i-src', 'db-tgw')] == ('tgw:tgw-xl', ['tcp:5432-5432'])
    assert ('i-src', 'db-tgw-ref') not in edges
    # Peered and admitted by CIDR, but vpc-src has no route to vpc-noroute.
    assert ('i-src', 'db-noroute') not in edges
    # sg-db-open admits 0.0.0.0/0, but no gateway joins vpc-src and vpc-xl.
    assert ('i-src', 'db-public') not in edges

    # L5 summaries: the console cannot read edge properties.
    def stores(node_id):
        p = _props(neo4j_session, 'EC2Instance', node_id)
        assert p['exposure_evaluated_at'] == TAG
        out = json.loads(p['network_reachable_data_stores'])
        assert p['network_reachable_data_store_count'] == len(out)
        return out

    assert stores('i-src') == [
        {
            'id': 'cache-peer', 'type': 'ElasticacheCluster', 'ports': ['tcp:6379-6379'], 'via': 'peering:pcx-ok',
            'admitted_by': 'sg-cache-peer',
        },
        {
            'id': 'db-peer', 'type': 'RDSInstance', 'ports': ['tcp:5432-5432'], 'via': 'peering:pcx-ok',
            'admitted_by': 'sg-db-peer',
        },
        {
            'id': 'db-tgw', 'type': 'RDSInstance', 'ports': ['tcp:5432-5432'], 'via': 'tgw:tgw-xl',
            'admitted_by': 'sg-db-tgw',
        },
    ]
    assert {
        'id': 'db-app', 'type': 'RDSInstance', 'ports': ['tcp:5432-5432'], 'via': 'security_group',
        'admitted_by': 'sg-db',
    } in stores('i-app')

    def reached_from(label, node_id):
        p = _props(neo4j_session, label, node_id)
        return p['network_reachable_from_count'], p['network_reachable_from_internet_exposed_count']

    assert reached_from('RDSInstance', 'db-peer') == (1, 0)
    # Reached by every 10.0/16 instance (sg-db-cidr) plus i-app (sg-db): 11, of which i-open, i-nacl,
    # i-ipv6, i-app and the three i-behind-* instances are internet reachable.
    assert reached_from('RDSInstance', 'db-app') == (11, 7)
    assert reached_from('ElasticacheCluster', 'cache-1') == (0, 0)

    # Other workspace untouched.
    assert 'internet_reachable' not in _props(neo4j_session, 'EC2Instance', 'i-other')


def test_nacl_loader_shape(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-nacl', 'o-nacl', '999988887777')
    _run(neo4j_session, "MERGE (:AWSVpc{id: $vpc})", vpc=VPC)
    acls = [{
        'NetworkAclId': 'acl-shape', 'VpcId': VPC, 'IsDefault': True, 'OwnerId': '999988887777',
        'Entries': [{'RuleNumber': 100, 'Egress': False, **ALL}],
        'Associations': [{'SubnetId': 'subnet-shape'}],
    }]
    load_network_acls(neo4j_session, *transform_network_acls(acls, 'us-east-1', '999988887777'), '999988887777', TAG)
    row = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: '999988887777'})-[:RESOURCE]->(acl:EC2NetworkAcl{id: 'acl-shape'})
              -[:PART_OF_SUBNET]->(:EC2Subnet{subnetid: 'subnet-shape'})
        MATCH (acl)-[:MEMBER_OF_AWS_VPC]->(:AWSVpc{id: $vpc})
        MATCH (r:EC2NetworkAclRule)-[:MEMBER_OF_NACL]->(acl)
        RETURN acl.is_default AS d, r.id AS rid, r.rule_action AS action, r.cidr_block AS cidr, r.egress AS egress
        """,
        vpc=VPC,
    ).single()
    assert (row['d'], row['rid'], row['action'], row['cidr'], row['egress']) == (
        True, 'acl-shape/inbound/100', 'allow', '0.0.0.0/0', False,
    )
