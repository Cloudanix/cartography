from cartography.intel.aws.apigateway import transform_resource_methods
from cartography.intel.aws.elasticache import _cluster_port
from cartography.intel.aws.exposure_layers.access import apigateway_auth
from cartography.intel.aws.exposure_layers.access import elasticache_auth
from cartography.intel.aws.exposure_layers.access import lambda_auth
from cartography.intel.aws.exposure_layers.network import listener_ports
from cartography.intel.aws.exposure_layers.network import nacl_ports
from cartography.intel.aws.exposure_layers.network import V4
from cartography.intel.aws.exposure_layers.network import V6
from cartography.intel.aws.exposure_layers.software import lambda_runtime
from cartography.intel.aws.exposure_layers.software import search_engine


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
