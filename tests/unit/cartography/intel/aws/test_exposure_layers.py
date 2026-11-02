import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cartography.intel.aws.apigateway import transform_resource_methods
from cartography.intel.aws.ec2.load_balancer_v2s import _add_listener_rules
from cartography.intel.aws.ec2.load_balancer_v2s import get_listener_rules
from cartography.intel.aws.ec2.load_balancer_v2s import listener_auth_facts
from cartography.intel.aws.elasticache import _cluster_port
from cartography.intel.aws.exposure_layers.access import apigateway_auth
from cartography.intel.aws.exposure_layers.access import elasticache_auth
from cartography.intel.aws.exposure_layers.access import instance_auth
from cartography.intel.aws.exposure_layers.access import lambda_auth
from cartography.intel.aws.exposure_layers.access import load_balancer_v2_auth
from cartography.intel.aws.exposure_layers.blast_radius import Gateway
from cartography.intel.aws.exposure_layers.blast_radius import match_via
from cartography.intel.aws.exposure_layers.blast_radius import reach_rows
from cartography.intel.aws.exposure_layers.blast_radius import RouteFacts
from cartography.intel.aws.exposure_layers.blast_radius import sg_admits
from cartography.intel.aws.exposure_layers.network import add_direct_path
from cartography.intel.aws.exposure_layers.network import listener_ports
from cartography.intel.aws.exposure_layers.network import nacl_ports
from cartography.intel.aws.exposure_layers.network import sg_facts
from cartography.intel.aws.exposure_layers.network import SgFacts
from cartography.intel.aws.exposure_layers.network import subnet_facts
from cartography.intel.aws.exposure_layers.network import V4
from cartography.intel.aws.exposure_layers.network import V6
from cartography.intel.aws.exposure_layers.reach import load_balancers
from cartography.intel.aws.exposure_layers.software import lambda_runtime
from cartography.intel.aws.exposure_layers.software import search_engine
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet


def _rule(n, action, egress=False, protocol="-1", cidr="0.0.0.0/0", ipv6=None, ports=(None, None)):
    return {
        "rule_number": n, "rule_action": action, "egress": egress, "protocol": protocol,
        "cidr_block": cidr, "ipv6_cidr_block": ipv6, "fromport": ports[0], "toport": ports[1],
    }


def test_nacl_default_when_not_ingested():
    assert nacl_ports([], V4).to_strings() == ["tcp:0-65535", "udp:0-65535"]


def test_nacl_ipv6_rules_do_not_open_ipv4():
    rules = [_rule(100, "allow", cidr=None, ipv6="::/0"), _rule(100, "allow", egress=True, cidr=None, ipv6="::/0")]
    assert nacl_ports(rules, V4).is_empty()
    assert not nacl_ports(rules, V6).is_empty()


def test_nacl_tcp_only_return_path_drops_udp():
    rules = [
        _rule(100, "allow"),
        _rule(100, "allow", egress=True, protocol="6", ports=(1024, 65535)),
    ]
    assert nacl_ports(rules, V4).to_strings() == ["tcp:0-65535"]


def test_listener_ports():
    assert listener_ports([
        {"port": 443, "protocol": "HTTPS"}, {"port": 53, "protocol": "TCP_UDP"}, {"port": 6081, "protocol": "GENEVE"},
    ]).to_strings() == ["tcp:53-53", "tcp:443-443", "udp:53-53"]


def test_transform_resource_methods():
    out = transform_resource_methods({
        "GET": {"authorizationType": "NONE"},
        "POST": {"authorizationType": "NONE", "apiKeyRequired": True},
        "PUT": {"authorizationType": "AWS_IAM"},
        "OPTIONS": {"authorizationType": "NONE"},
    })
    assert out == {"method_authorization_types": ["AWS_IAM", "NONE"], "unauthenticated_methods": ["GET"]}
    assert transform_resource_methods({}) == {"method_authorization_types": [], "unauthenticated_methods": []}


def test_cluster_port():
    assert _cluster_port({"ConfigurationEndpoint": {"Port": 11211}}) == 11211
    assert _cluster_port({"CacheNodes": [{"Endpoint": {"Port": 6379}}]}) == 6379
    assert _cluster_port({}) is None


def test_apigateway_auth():
    assert apigateway_auth({"policy_open": False, "unauthenticated": [["GET"]]})[0] == "required"
    assert apigateway_auth({"policy_open": True, "unauthenticated": [[], ["GET"]]})[0] == "none"
    assert apigateway_auth({"policy_open": True, "unauthenticated": [[], []]})[0] == "required"
    assert apigateway_auth({"policy_open": True, "unauthenticated": [None]})[0] == "unknown"
    assert apigateway_auth({"policy_open": True, "unauthenticated": []})[0] == "unknown"


def test_lambda_auth():
    assert lambda_auth({"url": True, "url_auth": "NONE", "anonymous": False})[0] == "none"
    assert lambda_auth({"url": True, "url_auth": "AWS_IAM", "anonymous": False}) == ("required", ["function_url_iam"])
    assert lambda_auth({"url": False, "url_auth": None, "anonymous": True})[0] == "none"


def test_elasticache_auth():
    assert elasticache_auth({"auth_token": False, "engine": "memcached"})[0] == "none"
    assert elasticache_auth({"auth_token": False, "engine": "redis"})[0] == "unknown"


def test_lambda_runtime():
    assert lambda_runtime("python3.12") == "python@3.12"
    assert lambda_runtime("nodejs20.x") == "nodejs@20"
    assert lambda_runtime("java8.al2") == "java@8"
    assert lambda_runtime("go1.x") == "go@1"
    assert lambda_runtime("provided") == "amazon-linux@1"
    assert lambda_runtime("provided.al2023") == "amazon-linux@2023"
    assert lambda_runtime(None) is None


def test_search_engine():
    assert search_engine("OpenSearch_2.11") == "opensearch@2.11"
    assert search_engine("7.10") == "elasticsearch@7.10"


# ---------------------------------------------------------------- L3: ALB authenticate actions

def _actions(*types):
    return [{"Type": t, "Order": i + 1} for i, t in enumerate(types)]


def _listener(rules, default=("authenticate-oidc", "forward")):
    return {"ListenerArn": "arn:l", "Protocol": "HTTPS", "DefaultActions": _actions(*default), "Rules": rules}


def test_listener_auth_facts_all_paths_authenticated():
    rules = [
        {"IsDefault": True, "Actions": _actions("authenticate-oidc", "forward")},
        {"IsDefault": False, "Actions": _actions("authenticate-cognito", "forward")},
        {"IsDefault": False, "Actions": _actions("redirect")},
        # Order, not list position, decides which action runs first.
        {"IsDefault": False, "Actions": [{"Type": "forward", "Order": 2}, {"Type": "authenticate-oidc", "Order": 1}]},
    ]
    assert listener_auth_facts(_listener(rules)) == {
        "all_paths_authenticated": True, "auth_action_types": ["authenticate-cognito", "authenticate-oidc"],
    }


def test_listener_auth_facts_one_open_rule():
    rules = [
        {"IsDefault": True, "Actions": _actions("authenticate-oidc", "forward")},
        {"IsDefault": False, "Actions": _actions("forward")},
    ]
    assert listener_auth_facts(_listener(rules))["all_paths_authenticated"] is False


def test_listener_auth_facts_rules_unread():
    assert listener_auth_facts(_listener(None)) == {"all_paths_authenticated": None, "auth_action_types": None}
    assert listener_auth_facts({"Protocol": "TCP", "DefaultActions": _actions("forward")})["auth_action_types"] is None


def _client(pages=None, error=None):
    client = MagicMock()
    paginate = client.get_paginator.return_value.paginate
    if error:
        paginate.side_effect = ClientError({"Error": {"Code": error, "Message": "x"}}, "DescribeRules")
    else:
        paginate.return_value = pages
    return client


def test_get_listener_rules_denied_is_unknown():
    assert get_listener_rules(_client(error="AccessDenied"), "arn:l") is None
    assert get_listener_rules(_client(pages=[{"Rules": [{"IsDefault": True}]}]), "arn:l") == [{"IsDefault": True}]


def test_add_listener_rules_only_alb_http_listeners():
    client = _client(pages=[{"Rules": []}])
    alb = {"Type": "application", "Listeners": [{"ListenerArn": "a", "Protocol": "HTTPS"}, {"ListenerArn": "b"}]}
    nlb = {"Type": "network", "Listeners": [{"ListenerArn": "c", "Protocol": "TCP"}]}
    _add_listener_rules(client, alb)
    _add_listener_rules(client, nlb)
    assert alb["Listeners"] == [{"ListenerArn": "a", "Protocol": "HTTPS", "Rules": []}, {"ListenerArn": "b"}]
    assert "Rules" not in nlb["Listeners"][0]
    client.get_paginator.return_value.paginate.assert_called_once_with(ListenerArn="a")


def test_load_balancer_v2_auth():
    oidc = {"authenticated": True, "types": ["authenticate-oidc"]}
    redirect_only = {"authenticated": True, "types": []}
    assert load_balancer_v2_auth({"listeners": [oidc, redirect_only]}) == ("required", ["alb_authenticate_oidc"])
    assert load_balancer_v2_auth({"listeners": [oidc, {"authenticated": False, "types": None}]})[0] == "unknown"
    assert load_balancer_v2_auth({"listeners": [redirect_only]})[0] == "unknown"
    assert load_balancer_v2_auth({"listeners": []})[0] == "unknown"


def test_instance_auth_only_behind_authenticating_albs():
    lbs = [
        {"id": "lb-auth", "listeners": [{"authenticated": True, "types": ["authenticate-cognito"]}]},
        {"id": "lb-open", "listeners": [{"authenticated": False, "types": []}]},
    ]
    assert instance_auth({"via": ["elbv2:lb-auth"], "lbs": lbs}) == ("required", ["alb_authenticate_cognito"])
    assert instance_auth({"via": ["elbv2:lb-auth", "direct_ipv4"], "lbs": lbs})[0] == "unknown"
    assert instance_auth({"via": ["elbv2:lb-auth", "elbv2:lb-open"], "lbs": lbs})[0] == "unknown"
    assert instance_auth({"via": None, "lbs": lbs}) == ("unknown", ["self_managed_service"])


# ---------------------------------------------------------------- L5: cross-VPC reach

def _sg_facts(vpc, rules):
    return SgFacts(world={}, any_source=PortSet.empty(), vpc_id=vpc, rules=rules)


PG = PortSet.of("tcp", 5432, 5432)
SGS = {
    "sg-src": _sg_facts("vpc-a", []),
    "sg-db-ref": _sg_facts("vpc-b", [(PG, {"sg-src"}, [])]),
    "sg-db-cidr": _sg_facts("vpc-b", [(PG, set(), ["10.1.0.0/16"])]),
}
COMPUTE = {"id": "i-1", "sgs": ["sg-src"], "subnets": ["subnet-a"], "ips": ["10.1.1.10"]}
PEERING = {"peering:pcx-1": Gateway("pcx-1", frozenset({"vpc-a", "vpc-b"}), True)}
TGW = {"tgw:tgw-1": Gateway("tgw-1", frozenset({"vpc-a", "vpc-b", "vpc-c"}), False)}


def _store(sg, subnets=("subnet-b",)):
    return {"id": "db", "port": 5432, "sgs": [sg], "subnets": list(subnets)}


def _routes(gateways, a_routes, b_routes):
    return RouteFacts(
        subnets={"subnet-a": (["10.1.1.0/24"], a_routes), "subnet-b": (["10.2.1.0/24"], b_routes)},
        vpcs={"vpc-b": (["10.2.0.0/16"], b_routes)},
        gateways=gateways,
    )


def test_cross_vpc_peering_with_sg_reference():
    routes = _routes(PEERING, [("10.2.0.0/16", "pcx-1")], [("10.1.0.0/16", "pcx-1")])
    assert match_via(COMPUTE, _store("sg-db-ref"), SGS, routes) == ("peering:pcx-1", "sg-db-ref")
    # Without route facts other VPCs stay unreachable, as before.
    assert match_via(COMPUTE, _store("sg-db-ref"), SGS) is None


def test_cross_vpc_needs_routes_both_ways():
    no_back = _routes(PEERING, [("10.2.0.0/16", "pcx-1")], [("10.9.0.0/16", "pcx-1")])
    assert match_via(COMPUTE, _store("sg-db-cidr"), SGS, no_back) is None
    other_gateway = _routes(PEERING, [("10.2.0.0/16", "pcx-other")], [("10.1.0.0/16", "pcx-1")])
    assert match_via(COMPUTE, _store("sg-db-cidr"), SGS, other_gateway) is None


def test_cross_vpc_tgw_admits_by_cidr_only():
    routes = _routes(TGW, [("10.0.0.0/8", "tgw-1")], [("10.1.0.0/16", "tgw-1")])
    assert match_via(COMPUTE, _store("sg-db-cidr"), SGS, routes) == ("tgw:tgw-1", "sg-db-cidr")
    assert match_via(COMPUTE, _store("sg-db-ref"), SGS, routes) is None


def test_cross_vpc_store_without_subnets_uses_vpc_routes():
    routes = _routes(PEERING, [("10.2.0.0/16", "pcx-1")], [("10.1.0.0/16", "pcx-1")])
    assert match_via(COMPUTE, _store("sg-db-cidr", subnets=()), SGS, routes) == ("peering:pcx-1", "sg-db-cidr")


def test_cross_region_peering_drops_sg_references():
    cross_region = {"peering:pcx-1": Gateway("pcx-1", frozenset({"vpc-a", "vpc-b"}), False)}
    routes = _routes(cross_region, [("10.2.0.0/16", "pcx-1")], [("10.1.0.0/16", "pcx-1")])
    assert match_via(COMPUTE, _store("sg-db-ref"), SGS, routes) is None
    assert match_via(COMPUTE, _store("sg-db-cidr"), SGS, routes) == ("peering:pcx-1", "sg-db-cidr")


def test_same_vpc_unchanged():
    same = {**SGS, "sg-db-ref": _sg_facts("vpc-a", [(PG, {"sg-src"}, [])])}
    assert sg_admits(COMPUTE, _store("sg-db-ref"), same) == ("security_group", "sg-db-ref")
    assert match_via(COMPUTE, _store("sg-db-ref"), same) == ("security_group", "sg-db-ref")
    assert reach_rows([COMPUTE], [_store("sg-db-ref")], same) == [{
        "src": "i-1", "dst": "db", "ports": ["tcp:5432-5432"], "via": "security_group", "admitted_by": "sg-db-ref",
    }]


# ---------------------------------------------------------------- L1/L2 context: paths and blockers

WALK_SGS = {
    "sg-web": sg_facts([{"protocol": "tcp", "fromport": 443, "toport": 443, "cidrs": ["0.0.0.0/0"]}]),
    "sg-office": sg_facts([{"protocol": "tcp", "fromport": 22, "toport": 22, "cidrs": ["203.0.113.0/24"]}]),
}
ENTRY = {"type": "public_ip", "id": "54.1.2.3"}


def _subnet(igw="igw-1", nacl=()):
    return subnet_facts({
        "igw_v4": igw, "igw_v6": None, "route_table": "rtb-1", "nacl_id": "acl-1" if nacl else None, "nacl": list(nacl),
    })


def _walk(subnet, sgs=("sg-web", "sg-office"), service=None):
    reach = Reach(public_reasons={"public_ip"})
    row = {"subnets": ["subnet-1"], "sgs": list(sgs)}
    add_direct_path(reach, V4, ENTRY, row, {"subnet-1": subnet}, WALK_SGS, service=service)
    props = reach.props()
    return json.loads(props["exposure_paths"]), json.loads(props["exposure_blocked_by"])


def test_direct_path_hops_and_entry():
    nacl = [_rule(100, "allow"), _rule(100, "allow", egress=True)]
    paths, blocked = _walk(_subnet(nacl=nacl))
    assert paths == [{
        "via": "direct_ipv4", "entry": ENTRY, "ports": ["tcp:443-443"], "hops": [
            {"hop": "route", "id": "rtb-1", "rule": "0.0.0.0/0 -> igw-1"},
            {"hop": "nacl", "id": "acl-1"},
            # sg-office admits only the office CIDR: not a hop of the internet path.
            {"hop": "security_group", "id": "sg-web"},
        ],
    }]
    assert blocked == []


def test_direct_path_blockers():
    _, blocked = _walk(_subnet(igw=None))
    assert blocked == [{
        "hop": "route", "id": "rtb-1", "reason": "no_internet_route",
        "detail": "no 0.0.0.0/0 route to an internet gateway",
    }]
    _, blocked = _walk(_subnet(), sgs=["sg-office"])
    assert blocked == [{"hop": "security_group", "id": "sg-office", "reason": "not_allowed"}]
    _, blocked = _walk(_subnet(), service=PortSet.of("tcp", 5432, 5432))
    assert [(b["id"], b["ports"]) for b in blocked] == [("sg-web", ["tcp:5432-5432"]), ("sg-office", ["tcp:5432-5432"])]

    _, blocked = _walk(_subnet(nacl=[_rule(100, "deny"), _rule(100, "allow", egress=True)]))
    assert blocked == [{"hop": "nacl", "id": "acl-1", "reason": "denied", "ports": ["tcp:443-443"]}]
    replies_dropped = [_rule(100, "allow"), _rule(100, "allow", egress=True, protocol="6", ports=(443, 443))]
    _, blocked = _walk(_subnet(nacl=replies_dropped))
    assert blocked == [{"hop": "nacl", "id": "acl-1", "reason": "return_path_denied", "ports": ["tcp:443-443"]}]


def test_load_balancer_listener_hops_and_no_listener():
    row = {
        "id": "lb", "dns": "lb.example", "scheme": "internet-facing", "type": "application", "subnets": [],
        "sgs": ["sg-web"], "listeners": [
            {"id": "l-443", "port": 443, "protocol": "HTTPS"}, {"id": "l-80", "port": 80, "protocol": "HTTP"},
        ],
    }
    path = load_balancers([row], {}, WALK_SGS)["lb"].paths["direct_ipv4"]
    assert path["entry"] == {"type": "dns_name", "id": "lb.example"}
    # Port 80 has a listener but no SG rule: only the 443 listener is on the path.
    assert path["hops"] == [
        {"hop": "security_group", "id": "sg-web"}, {"hop": "listener", "id": "l-443", "rule": "HTTPS 443"},
    ]
    silent = load_balancers([{**row, "listeners": []}], {}, WALK_SGS)["lb"]
    assert json.loads(silent.props()["exposure_blocked_by"]) == [
        {"hop": "listener", "id": None, "reason": "no_listener"},
    ]
