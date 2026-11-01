import json
from unittest.mock import MagicMock

from googleapiclient.errors import HttpError

from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN
from cartography.intel.exposure.ports import PortSet
from cartography.intel.gcp.compute import firewall_entry_strings
from cartography.intel.gcp.compute import get_gcp_effective_firewalls
from cartography.intel.gcp.compute import transform_gcp_firewall_policy_rules
from cartography.intel.gcp.compute import transform_gcp_routes
from cartography.intel.gcp.exposure_layers import access
from cartography.intel.gcp.exposure_layers import network
from cartography.intel.gcp.exposure_layers import reach
from cartography.intel.gcp.exposure_layers import software
from cartography.intel.gcp.exposure_layers.blast_radius import instance_rows
from cartography.intel.gcp.exposure_layers.network import Firewall
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import VpcFacts

WORLD = network.from_cidr("0.0.0.0/0")
NO_TAGS: frozenset = frozenset()
API = "https://www.googleapis.com/compute/v1"


def _fw(allow, entries, priority=1000, **kw):
    return Firewall(allow=allow, ports=PortSet.parse(entries), priority=priority, **kw)


def _open(firewalls, tags=NO_TAGS, sas=NO_TAGS, source=WORLD):
    return network.open_ports(firewalls, frozenset(tags), frozenset(sas), source).to_strings()


def test_firewall_entry_strings_and_parsing():
    entries = firewall_entry_strings([
        {"IPProtocol": "tcp", "ports": ["22", "8000-9000"]}, {"IPProtocol": "all"}, {"IPProtocol": "icmp"},
    ])
    assert entries == ["tcp:22", "tcp:8000-9000", "all", "icmp"]
    assert network.entry_ports("tcp:22").to_strings() == ["tcp:22-22"]
    assert network.entry_ports("udp").to_strings() == ["udp:0-65535"]
    assert network.entry_ports("icmp").is_empty()


def test_firewall_from_row_skips_disabled_and_egress():
    row = {"allowed_entries": ["tcp:443"], "denied_entries": [], "priority": 10, "source_ranges": ["0.0.0.0/0"]}
    fw = network.firewall_from_row(row)
    assert fw.allow and fw.priority == 10 and fw.ports.to_strings() == ["tcp:443-443"]
    assert network.firewall_from_row({**row, "disabled": True}) is None
    assert network.firewall_from_row({**row, "direction": "EGRESS"}) is None
    deny = network.firewall_from_row({"allowed_entries": [], "denied_entries": ["all"]})
    assert not deny.allow and deny.priority == network.DEFAULT_PRIORITY


def test_implied_deny_and_world_only():
    assert _open([]) == []
    assert _open([_fw(True, ["tcp:22-22"], source_ranges=("10.0.0.0/8",))]) == []
    assert _open([_fw(True, ["tcp:22-22"], source_ranges=("0.0.0.0/0",))]) == ["tcp:22-22"]


def test_rule_without_source_defaults_to_world_v4():
    assert _open([_fw(True, ["tcp:80-80"])]) == ["tcp:80-80"]
    assert _open([_fw(True, ["tcp:80-80"])], source=network.from_cidr("::/0")) == []


def test_lower_priority_number_wins_and_deny_wins_ties():
    allow = _fw(True, ["tcp:0-65535"], priority=1000, source_ranges=("0.0.0.0/0",))
    deny_22 = _fw(False, ["tcp:22-22"], priority=100, source_ranges=("0.0.0.0/0",))
    assert _open([allow, deny_22]) == ["tcp:0-21", "tcp:23-65535"]
    tie = _fw(False, ["tcp:0-65535"], priority=1000, source_ranges=("0.0.0.0/0",))
    assert _open([allow, tie]) == []
    later_deny = _fw(False, ["tcp:0-65535"], priority=2000, source_ranges=("0.0.0.0/0",))
    assert _open([allow, later_deny]) == ["tcp:0-65535"]


def test_targets_by_tag_and_service_account():
    by_tag = _fw(True, ["tcp:443-443"], source_ranges=("0.0.0.0/0",), target_tags=frozenset({"web"}))
    by_sa = _fw(True, ["tcp:8080-8080"], source_ranges=("0.0.0.0/0",), target_sas=frozenset({"app@p.iam"}))
    assert _open([by_tag, by_sa]) == []
    assert _open([by_tag, by_sa], tags={"web"}) == ["tcp:443-443"]
    assert _open([by_tag, by_sa], sas={"app@p.iam"}) == ["tcp:8080-8080"]


def test_gfe_sources_match_contained_ranges():
    gfe = network.from_cidr("35.191.0.0/16")
    assert gfe(_fw(True, ["tcp:80-80"], source_ranges=("35.191.0.0/16",)))
    assert gfe(_fw(True, ["tcp:80-80"], source_ranges=("0.0.0.0/0",)))
    assert not gfe(_fw(True, ["tcp:80-80"], source_ranges=("10.0.0.0/8",)))
    assert not gfe(_fw(True, ["tcp:80-80"]))


def test_internet_route():
    igw = {
        "dest_range": "0.0.0.0/0", "priority": 1000, "tags": [],
        "next_hop_gateway": "p/global/gateways/default-internet-gateway",
    }
    nva = {"dest_range": "0.0.0.0/0", "priority": 900, "tags": ["egress-nva"], "next_hop_gateway": None}
    local = {"dest_range": "10.0.0.0/24", "priority": 0, "tags": [], "next_hop_gateway": None}
    assert network.internet_route([], NO_TAGS, network.V4) is None
    assert network.internet_route([local], NO_TAGS, network.V4) is False
    assert network.internet_route([local, igw], NO_TAGS, network.V4) is True
    assert network.internet_route([igw, nva], frozenset({"egress-nva"}), network.V4) is False
    assert network.internet_route([igw, nva], NO_TAGS, network.V4) is True
    assert network.internet_route([igw], NO_TAGS, network.V6) is False


def test_forwarding_ports_and_proxy():
    assert network.forwarding_ports("TCP", "443-443", None).to_strings() == ["tcp:443-443"]
    assert network.forwarding_ports("TCP", None, ["80", "8080"]).to_strings() == ["tcp:80-80", "tcp:8080-8080"]
    assert network.forwarding_ports("UDP", None, None).to_strings() == ["udp:0-65535"]
    assert network.forwarding_ports("L3_DEFAULT", None, None) == PortSet.everything()
    assert network.is_proxy("projects/p/global/targetHttpsProxies/web")
    assert not network.is_proxy("projects/p/regions/r/targetPools/pool")


def test_instance_open_unresolved_vpc_is_fail_safe():
    inst = Instance(id="i", running=True, public_v4=True, vpcs=("vpc",))
    ports, unresolved = network.instance_open(inst, {"vpc": VpcFacts(visible=False)}, ["0.0.0.0/0"], network.V4)
    assert unresolved and ports == PortSet.everything()


def test_named_port():
    assert reach.named_port(["http:80", "admin:9000"], "admin").to_strings() == ["tcp:9000-9000"]
    assert reach.named_port(["http:80"], "grpc") is None
    assert reach.named_port([], None) is None


def test_managed_service_reach():
    rows = [
        {"id": "all", "url": "https://a.run.app", "ingress": "all", "region": "us-east1"},
        {"id": "internal", "url": "https://b.run.app", "ingress": "internal", "region": "us-east1"},
        {"id": "lb", "url": "https://c.run.app", "ingress": "internal-and-cloud-load-balancing", "region": "us-east1"},
    ]
    # Serverless NEGs ingested in its region, none names "lb": no load balancer fronts it.
    run = reach.cloud_run_services(rows, reach.ServerlessLb(regions={"us-east1"}, paths={}))
    assert run["all"].props()["internet_reachable"] is True
    assert run["internal"].props()["internet_reachable"] is False
    assert run["lb"].props()["internet_reachable"] is False
    # No serverless NEG ingested in its region: a load balancer may front it, so it stays reachable (unresolved).
    unresolved = reach.cloud_run_services(rows, reach.ServerlessLb(regions={"us-west1"}, paths={}))
    assert unresolved["lb"].props()["internet_reachable_via"] == ["load_balancer_unresolved"]
    assert unresolved["internal"].props()["internet_reachable"] is False
    sql = reach.sql_instances([
        {"id": "open", "ipv4": True, "public_ip": "1.2.3.4", "networks": ["0.0.0.0/0"], "port": 5432},
        {"id": "narrow", "ipv4": True, "public_ip": "1.2.3.4", "networks": ["203.0.113.0/24"], "port": 5432},
    ])
    assert sql["open"].props()["internet_reachable_ports"] == ["tcp:5432-5432"]
    assert sql["narrow"].props()["public_reasons"] == ["public_ip"]
    assert sql["narrow"].props()["internet_reachable"] is False
    gke = reach.gke_clusters([
        {"id": "off", "endpoint": "1.1.1.1", "private_endpoint": False, "authorized_networks": False, "cidrs": []},
        {
            "id": "narrow", "endpoint": "1.1.1.1", "private_endpoint": False, "authorized_networks": True,
            "cidrs": ["203.0.113.0/24"],
        },
        {"id": "private", "endpoint": "10.0.0.2", "private_endpoint": True, "authorized_networks": False},
    ])
    assert gke["off"].props()["internet_reachable"] and not gke["narrow"].props()["internet_reachable"]
    assert gke["private"].props()["public_reasons"] == []


def test_function_reach_by_ingress():
    rows = [
        {"id": "all", "url": "https://f", "ingress": "ALLOW_ALL"},
        {"id": "internal", "url": "https://f", "ingress": "ALLOW_INTERNAL_ONLY"},
        {"id": "event", "url": None, "event_trigger": "google.pubsub.topic.publish", "ingress": "ALLOW_ALL"},
        {"id": "gclb", "url": "https://f", "ingress": "ALLOW_INTERNAL_AND_GCLB", "region": "us-east1"},
    ]
    lb = reach.LbFacts(url_maps={}, backends={}, named_ports={}, members={})
    serverless = {"id": "neg-s", "type": "SERVERLESS", "region": "us-east1", "function": None, "run": "other"}
    out = reach.functions(rows, reach.serverless_lb_paths([serverless], lb, {}))
    assert out["all"].props()["internet_reachable_ports"] == ["tcp:443-443"]
    assert not out["internal"].props()["internet_reachable"]
    assert out["event"].props() == reach.Reach().props()
    assert not out["gclb"].props()["internet_reachable"]
    # A zonal NEG survives a failed regional list (aggregatedList): it does not show the region was read.
    zonal = {"id": "neg-z", "type": "GCE_VM_IP_PORT", "region": "us-east1", "function": None, "run": None}
    for negs in ([], [zonal], [{**serverless, "region": "us-west1"}]):
        unresolved = reach.functions(rows, reach.serverless_lb_paths(negs, lb, {}))
        assert unresolved["gclb"].props()["internet_reachable_via"] == ["load_balancer_unresolved"]


def test_serverless_neg_behind_reachable_backend():
    listener = {"hop": "listener", "id": "fr", "rule": "443-443"}
    lb_entry = {"type": "forwarding_rule", "id": "fr", "listener_ports": ["tcp:443-443"]}
    lb = reach.LbFacts(
        url_maps={}, backends={
            "bs": {"groups": ["neg-fn", "neg-run", "neg-mask"], "port_name": None},
            "bs-internal": {"groups": ["neg-fn-internal"], "port_name": None},
        }, named_ports={}, members={},
    )
    backends = {"bs": reach.Reach(), "bs-internal": reach.Reach()}
    backends["bs"].add_path(PortSet.of("tcp", 443, 443), "forwarding_rule:fr", hops=[listener], entry=lb_entry)
    negs = [
        {"id": n, "type": "SERVERLESS", "region": "us-east1", "function": fn, "run": run}
        for n, fn, run in [
            ("neg-fn", "fn", None), ("neg-run", None, "run"), ("neg-mask", None, None),
            ("neg-fn-internal", "fn-internal", None),
        ]
    ]
    paths = reach.serverless_lb_paths(negs, lb, backends)
    assert paths.regions == {"us-east1"}
    fns = reach.functions(
        [
            {"id": "fn", "url": "https://f", "ingress": "ALLOW_INTERNAL_AND_GCLB", "region": "us-east1"},
            {"id": "fn-internal", "url": "https://g", "ingress": "ALLOW_INTERNAL_AND_GCLB", "region": "us-east1"},
        ], paths,
    )
    assert json.loads(fns["fn"].props()["exposure_paths"]) == [{
        "via": "forwarding_rule:fr", "ports": ["tcp:443-443"], "entry": lb_entry,
        "hops": [
            listener, {"hop": "backend", "id": "bs"}, {"hop": "target_group", "id": "neg-fn"},
            {"hop": "service", "id": "fn", "rule": "ingress ALLOW_INTERNAL_AND_GCLB"},
        ],
    }]
    # Its backend service is not reached by any external forwarding rule.
    assert not fns["fn-internal"].props()["internet_reachable"]
    run = reach.cloud_run_services(
        [
            {
                "id": "run", "url": "https://r.run.app", "ingress": "internal-and-cloud-load-balancing",
                "region": "us-east1",
            },
        ], paths,
    )
    assert run["run"].props()["internet_reachable_via"] == ["forwarding_rule:fr"]
    internal = reach.cloud_run_services([{"id": "run", "url": "https://r.run.app", "ingress": "internal"}], paths)
    assert not internal["run"].props()["internet_reachable"]


def test_auth_verdicts():
    read = {"status": "resolved"}
    assert access.bucket_auth({**read, "members": ["allUsers"], "acl": [], "ubla": True}) == (
        AUTH_NONE, ["gcs_allusers"],
    )
    assert access.bucket_auth({**read, "members": ["allUsers"], "pap": "enforced"})[0] == AUTH_REQUIRED
    assert access.bucket_auth({**read, "members": [], "acl": ["allAuthenticatedUsers"], "ubla": True})[0] == (
        AUTH_REQUIRED
    )
    assert access.bucket_auth({**read, "members": [], "acl": ["allAuthenticatedUsers"], "ubla": False}) == (
        AUTH_NONE, ["gcs_allauthenticatedusers"],
    )
    # Unread IAM policy: kept bindings may be stale; the ACL (read with the bucket) and PAP still decide.
    for status in ("unresolved", None):
        unread = {"status": status, "members": ["allUsers"], "acl": ["allUsers"]}
        assert access.bucket_auth({**unread, "ubla": True}) == (AUTH_UNKNOWN, ["bucket_policy_not_read"])
        assert access.bucket_auth({**unread, "ubla": False}) == (AUTH_NONE, ["gcs_allusers"])
        assert access.bucket_auth({**unread, "pap": "enforced"})[0] == AUTH_REQUIRED
    assert access.data_verdict("bigquery", [None, "user:a@b.c"]) == (AUTH_REQUIRED, ["iam"])
    assert access.dataset_auth({"status": "resolved", "members": ["allUsers"]}) == (AUTH_NONE, ["bigquery_allusers"])
    # Unread dataset: kept access entries may be stale.
    for status in ("unresolved", None):
        assert access.dataset_auth({"status": status, "members": ["allUsers"]}) == (
            AUTH_UNKNOWN, ["dataset_access_not_read"],
        )
    invoker = {"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}
    viewer = {"role": "roles/viewer", "members": ["allUsers"]}
    assert access.function_auth({"status": "resolved", "bindings": [invoker]}) == (AUTH_NONE, ["invoker_allusers"])
    assert access.function_auth({"status": "resolved", "bindings": [viewer]}) == (AUTH_REQUIRED, ["iam_invoker"])
    # Unread policy (or a sync before the status was stored): kept bindings may be stale.
    for status in ("unresolved", None):
        assert access.function_auth({"status": status, "bindings": []}) == (AUTH_UNKNOWN, ["invoker_policy_not_read"])
    # Properties written by cloudrun.py (PR #507); absent before it merges.
    assert access.cloud_run_auth({})[0] == AUTH_UNKNOWN
    assert access.cloud_run_auth({"status": "not_needed"})[0] == AUTH_UNKNOWN
    assert access.cloud_run_auth({"status": "unresolved"})[0] == AUTH_UNKNOWN
    assert access.cloud_run_auth({"iam_disabled": True}) == (AUTH_NONE, ["invoker_iam_disabled"])
    assert access.cloud_run_auth({"status": "resolved", "public_invokers": ["allAuthenticatedUsers"]}) == (
        AUTH_NONE, ["invoker_allauthenticatedusers"],
    )
    assert access.cloud_run_auth({"status": "resolved", "public_invokers": []}) == (AUTH_REQUIRED, ["iam_invoker"])
    assert access.backend_service_auth({"iap": True}) == (AUTH_REQUIRED, ["iap"])


def test_software_versions():
    assert software.sql_version("POSTGRES_15") == "postgres@15"
    assert software.sql_version("MYSQL_8_0") == "mysql@8.0"
    assert software.sql_version("MYSQL_8_0_31") == "mysql@8.0.31"
    assert software.sql_version("SQLSERVER_2019_STANDARD") == "sqlserver@2019"
    assert software.sql_version(None) is None
    assert software.function_runtime("python312") == "python@3.12"
    assert software.function_runtime("nodejs20") == "nodejs@20"
    assert software.function_runtime("go121") == "go@1.21"
    assert software.function_runtime("java17") == "java@17"
    assert software.function_runtime("php82") == "php@8.2"
    assert software.function_runtime("custom") is None


def test_instance_os_uses_names_not_project_paths():
    row = {"source_image": "https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-109-17800"}
    assert software.instance_os(row) == "cos@109"
    row = {"source_image": "projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20240101"}
    assert software.instance_os(row) == "ubuntu@22.04"
    licenses = ["projects/debian-cloud/global/licenses/debian-12-bookworm"]
    assert software.instance_os({"licenses": licenses}) == "debian@12"


def test_identity_sourced_instance_edges():
    db = Instance(id="db", running=True, vpcs=("vpc",), tags=frozenset({"db"}))
    app = Instance(id="app", running=True, vpcs=("vpc",), sas=frozenset({"app@p.iam"}))
    other = Instance(id="other", running=True, vpcs=("vpc",))
    fw = _fw(
        True, ["tcp:5432-5432"], source_sas=frozenset({"app@p.iam"}), target_tags=frozenset({"db"}),
        name="db-from-app",
    )
    rows = instance_rows([db, app, other], {"vpc": VpcFacts(visible=True, firewalls=[fw])})
    assert rows == [{
        "src": "app", "dst": "db", "ports": ["tcp:5432-5432"], "via": "firewall_source_tag_or_sa",
        "admitted_by": "db-from-app",
    }]


VPC_URI = "projects/p/global/networks/main"


def _policy_rule(priority, action, l4, ranges=("0.0.0.0/0",), **kw):
    match = {"srcIpRanges": list(ranges), "layer4Configs": l4}
    match.update(kw.pop("match", {}))
    return {"priority": priority, "action": action, "direction": "INGRESS", "match": match, **kw}


def test_transform_firewall_policy_rules_keeps_applicable_ingress_rules():
    tcp22 = [{"ipProtocol": "tcp", "ports": ["22"]}]
    ineffective = [{"name": "tagValues/1", "state": "INEFFECTIVE"}]
    response = {
        "firewallPolicys": [
            {
                "name": "111", "shortName": "org-baseline", "type": "HIERARCHY", "rules": [
                    _policy_rule(10, "deny", tcp22, targetServiceAccounts=["a@p.iam"]),
                    _policy_rule(20, "allow", tcp22, direction="EGRESS"),
                    _policy_rule(30, "allow", tcp22, disabled=True),
                    _policy_rule(40, "allow", tcp22, targetResources=[f"{API}/projects/p/global/networks/other"]),
                    _policy_rule(50, "allow", tcp22, targetType="INTERNAL_MANAGED_LB"),
                    _policy_rule(60, "allow", tcp22, targetSecureTags=ineffective),
                ],
            },
            {
                "name": "netpol", "type": "NETWORK", "priority": 1000, "rules": [
                    _policy_rule(
                        5, "goto_next", [{"ipProtocol": "all"}], ranges=(), targetResources=[f"{API}/{VPC_URI}"],
                        match={"srcNetworkContext": "INTERNET", "srcRegionCodes": ["US"]},
                        targetSecureTags=[{"name": "tagValues/2", "state": "EFFECTIVE"}],
                    ),
                ],
            },
        ],
    }
    rows = transform_gcp_firewall_policy_rules(response, VPC_URI)
    assert [r["priority"] for r in rows] == [10, 5]
    org, net = rows
    assert org["id"] == f"{VPC_URI}/firewallPolicies/111/rules/10"
    assert (org["policy_type"], org["policy_order"], org["policy_short_name"]) == ("HIERARCHY", 0, "org-baseline")
    assert org["entries"] == ["tcp:22"] and org["target_service_accounts"] == ["a@p.iam"]
    assert org["other_sources"] is False and org["network_context"] is None
    assert (net["policy_order"], net["policy_priority"], net["entries"]) == (1, 1000, ["all"])
    assert net["network_context"] == "INTERNET" and net["other_sources"] is True
    assert net["target_secure_tags"] == ["tagValues/2"]


def test_effective_firewalls_api_error_falls_back():
    compute = MagicMock()
    compute.networks.return_value.getEffectiveFirewalls.return_value.execute.side_effect = HttpError(
        MagicMock(status=403), b'{"error": {"status": "PERMISSION_DENIED"}}',
    )
    assert get_gcp_effective_firewalls("p", "main", compute) is None
    assert transform_gcp_firewall_policy_rules({}, VPC_URI) == []


def _row(policy_type, order, priority, action, entries, **kw):
    return {
        "policy_type": policy_type, "policy_order": order, "priority": priority, "action": action,
        "entries": entries, "source_ranges": ["0.0.0.0/0"], **kw,
    }


def _vpc(policy_rows, vpc_rules, order=None):
    before, after = network.policy_levels(policy_rows, order)
    return VpcFacts(visible=True, firewalls=vpc_rules, policies_before=before, policies_after=after)


def _inst_open(vpc, sas=(), source="0.0.0.0/0"):
    inst = Instance(id="i", running=True, vpcs=("vpc",), sas=frozenset(sas))
    return network.instance_open(inst, {"vpc": vpc}, [source])[0].to_strings()


VPC_ALLOW_ALL = [_fw(True, ["tcp:0-65535"], source_ranges=("0.0.0.0/0",))]


def test_policy_deny_overrides_vpc_allow():
    # Scenario 8: hierarchical deny beats the VPC allow.
    org = _row("HIERARCHY", 0, 100, "deny", ["tcp:22"])
    assert _inst_open(_vpc([org], VPC_ALLOW_ALL)) == ["tcp:0-21", "tcp:23-65535"]
    # A folder allow below the org deny cannot reopen it; the org's goto_next hands it down.
    folder = _row("HIERARCHY", 1, 1, "allow", ["tcp:22"])
    assert _inst_open(_vpc([org, folder], [])) == []
    handoff = _row("HIERARCHY", 0, 100, "goto_next", ["tcp:22"])
    assert _inst_open(_vpc([handoff, folder], [])) == ["tcp:22-22"]
    assert _inst_open(_vpc([handoff], VPC_ALLOW_ALL)) == ["tcp:0-65535"]


def test_policy_allow_overrides_vpc_deny_and_no_data_falls_back():
    org = _row("HIERARCHY", 0, 100, "allow", ["tcp:8443"])
    assert _inst_open(_vpc([org], [])) == ["tcp:8443-8443"]
    assert _inst_open(_vpc([], VPC_ALLOW_ALL)) == ["tcp:0-65535"]
    unknown_action = _row("HIERARCHY", 0, 1, "mirror", ["all"])
    assert _inst_open(_vpc([unknown_action], VPC_ALLOW_ALL)) == ["tcp:0-65535"]


def test_network_policy_before_or_after_classic():
    net_deny = _row("NETWORK", 1, 10, "deny", ["tcp:443"])
    vpc_443 = [_fw(True, ["tcp:443-443"], source_ranges=("0.0.0.0/0",))]
    assert _inst_open(_vpc([net_deny], vpc_443)) == ["tcp:443-443"]
    assert _inst_open(_vpc([net_deny], vpc_443, "AFTER_CLASSIC_FIREWALL")) == ["tcp:443-443"]
    assert _inst_open(_vpc([net_deny], vpc_443, "BEFORE_CLASSIC_FIREWALL")) == []
    # Hierarchical policies run first whatever the order and whatever the response order.
    org_allow = _row("HIERARCHY", 2, 1, "allow", ["tcp:443"])
    assert _inst_open(_vpc([net_deny, org_allow], [], "BEFORE_CLASSIC_FIREWALL")) == ["tcp:443-443"]


def test_policy_targets_and_contexts():
    by_sa = _row("HIERARCHY", 0, 1, "deny", ["all"], target_service_accounts=["a@p.iam"])
    assert _inst_open(_vpc([by_sa], VPC_ALLOW_ALL)) == ["tcp:0-65535"]
    assert _inst_open(_vpc([by_sa], VPC_ALLOW_ALL), sas={"a@p.iam"}) == []
    # Secure tag bindings are unknown: a tagged deny is not applied, a tagged allow is.
    tagged_deny = _row("HIERARCHY", 0, 1, "deny", ["all"], target_secure_tags=["tagValues/1"])
    tagged_allow = _row("HIERARCHY", 0, 1, "allow", ["tcp:22"], target_secure_tags=["tagValues/1"])
    assert _inst_open(_vpc([tagged_deny], VPC_ALLOW_ALL)) == ["tcp:0-65535"]
    assert _inst_open(_vpc([tagged_allow], [])) == ["tcp:22-22"]
    # GFE traffic is non-internet: an INTERNET-context deny does not touch it, a plain /0 deny does.
    internet_deny = _row("HIERARCHY", 0, 1, "deny", ["all"], source_ranges=[], network_context="INTERNET")
    gfe = "35.191.0.0/16"
    gfe_rule = [_fw(True, ["tcp:8080-8080"], source_ranges=(gfe,))]
    assert _inst_open(_vpc([internet_deny], VPC_ALLOW_ALL)) == []
    assert _inst_open(_vpc([internet_deny], gfe_rule), source=gfe) == ["tcp:8080-8080"]
    assert _inst_open(_vpc([_row("HIERARCHY", 0, 1, "deny", ["all"])], gfe_rule), source=gfe) == []
    # Region-code-only sources are not "everyone": they neither open nor close for the whole internet.
    geo = _row("HIERARCHY", 0, 1, "deny", ["all"], source_ranges=[], other_sources=True)
    assert _inst_open(_vpc([geo], VPC_ALLOW_ALL)) == ["tcp:0-65535"]


def test_policy_world_deny_cuts_identity_edges_but_allow_adds_none():
    db = Instance(id="db", running=True, vpcs=("vpc",), tags=frozenset({"db"}))
    app = Instance(id="app", running=True, vpcs=("vpc",), sas=frozenset({"app@p.iam"}))
    fw = _fw(True, ["tcp:5432-5432"], source_sas=frozenset({"app@p.iam"}), target_tags=frozenset({"db"}))
    deny_all = _row("HIERARCHY", 0, 1, "deny", ["all"])
    internet_only = _row("HIERARCHY", 0, 1, "deny", ["all"], network_context="INTERNET")
    allow_ssh = _row("HIERARCHY", 0, 1, "allow", ["tcp:22"])
    assert instance_rows([db, app], {"vpc": _vpc([deny_all], [fw])}) == []
    assert [r["ports"] for r in instance_rows([db, app], {"vpc": _vpc([internet_only], [fw])})] == [["tcp:5432-5432"]]
    assert [r["ports"] for r in instance_rows([db, app], {"vpc": _vpc([allow_ssh], [fw])})] == [["tcp:5432-5432"]]


def test_transform_routes():
    routes = transform_gcp_routes(
        [{
            "name": "default-route-1", "destRange": "0.0.0.0/0", "priority": 1000,
            "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
            "nextHopGateway": "https://www.googleapis.com/compute/v1/projects/p/global/gateways/"
                              "default-internet-gateway",
        }], "p",
    )
    assert routes[0]["vpc_partial_uri"] == "projects/p/global/networks/default"
    assert routes[0]["next_hop_gateway"] == "projects/p/global/gateways/default-internet-gateway"


# ---------------------------------------------------------------- exposure_paths / exposure_blocked_by

IGW_ROUTE = {
    "name": "default-igw", "dest_range": "0.0.0.0/0", "priority": 1000, "tags": [],
    "next_hop_gateway": "projects/p/global/gateways/default-internet-gateway",
}
SUBNET_ROUTE = {"name": "subnet", "dest_range": "10.0.0.0/24", "priority": 0, "tags": [], "next_hop_gateway": None}
WEB_443 = _fw(True, ["tcp:443-443"], source_ranges=("0.0.0.0/0",), name="web-443")


def _direct(vpc):
    inst = Instance(id="i", running=True, public_v4=True, vpcs=("vpc",), external_ipv4="34.1.2.3")
    props = reach.instance_direct(inst, {"vpc": vpc}).props()
    return json.loads(props["exposure_paths"]), json.loads(props["exposure_blocked_by"])


def test_direct_path_names_route_and_admitting_rule():
    paths, blocked = _direct(VpcFacts(visible=True, firewalls=[WEB_443], routes=[SUBNET_ROUTE, IGW_ROUTE]))
    assert blocked == []
    assert paths == [{
        "via": "direct_ipv4", "entry": {"type": "external_ip", "id": "34.1.2.3"}, "ports": ["tcp:443-443"],
        "hops": [
            {"hop": "network", "id": "vpc"},
            {"hop": "route", "id": "default-igw", "rule": "0.0.0.0/0 -> default-internet-gateway"},
            {"hop": "firewall", "id": "web-443"},
        ],
    }]
    # Firewalls not visible: every port, and only the network is known.
    paths, _ = _direct(VpcFacts(visible=False))
    assert paths[0]["via"] == "direct_ipv4_unresolved_firewall"
    assert paths[0]["hops"] == [{"hop": "network", "id": "vpc"}]


def test_blockers_route_vpc_rules_and_policy():
    no_route = VpcFacts(visible=True, firewalls=[WEB_443], routes=[SUBNET_ROUTE])
    assert _direct(no_route) == (
        [], [{
            "hop": "route", "id": None, "reason": "no_internet_route",
            "detail": "no 0.0.0.0/0 route to default-internet-gateway in vpc",
        }],
    )
    nva = {"name": "to-nva", "dest_range": "0.0.0.0/0", "priority": 900, "tags": [], "next_hop_gateway": None}
    assert _direct(VpcFacts(visible=True, firewalls=[WEB_443], routes=[IGW_ROUTE, nva]))[1][0]["id"] == "to-nva"
    # Implied deny: no rule admits the world.
    internal = _fw(True, ["tcp:22-22"], source_ranges=("10.0.0.0/8",), name="ssh")
    assert _direct(VpcFacts(visible=True, firewalls=[internal]))[1] == [
        {"hop": "firewall", "id": "vpc", "reason": "not_allowed"},
    ]
    deny_all = _fw(False, ["tcp:0-65535"], priority=900, source_ranges=("0.0.0.0/0",), name="deny-all")
    assert _direct(VpcFacts(visible=True, firewalls=[WEB_443, deny_all]))[1] == [
        {"hop": "firewall", "id": "deny-all", "reason": "denied"},
    ]
    # Scenario 8: the org policy's deny decides before the VPC allow.
    org = _row("HIERARCHY", 0, 100, "deny", ["tcp:443"], policy_name="9001")
    assert _direct(_vpc([org], [WEB_443])) == (
        [], [
            {"hop": "firewall_policy", "id": "9001", "reason": "denied", "detail": "HIERARCHY"},
        ],
    )


def test_lb_path_lists_listener_backend_group_and_firewall():
    backend = Instance(id="be", running=True, vpcs=("vpc",), tags=frozenset({"lb"}))
    gfe = _fw(True, ["tcp:8080-8080"], source_ranges=network.GFE_RANGES, target_tags=frozenset({"lb"}), name="gfe")
    row = {
        "id": "fr", "scheme": "EXTERNAL_MANAGED", "protocol": "TCP", "port_range": "443-443", "url_map": "um",
        "target": "projects/p/global/targetHttpsProxies/web", "ip_address": "34.9.9.9",
    }
    lb = reach.LbFacts(
        url_maps={"um": ["bs"]}, backends={"bs": {"groups": ["ig"], "port_name": "http"}},
        named_ports={"ig": ["http:8080"]}, members={"ig": ["be"]},
    )
    rules, backends, inst = reach.forwarding_rules([row]), {"bs": reach.Reach()}, {"be": reach.Reach()}
    vpcs = {"vpc": VpcFacts(visible=True, firewalls=[gfe])}
    reach.add_lb_paths([row], rules, lb, {"be": backend}, vpcs, backends, inst)
    listener = {"hop": "listener", "id": "fr", "rule": "443-443"}
    assert json.loads(inst["be"].props()["exposure_paths"]) == [{
        "via": "forwarding_rule:fr", "ports": ["tcp:8080-8080"],
        "entry": {"type": "forwarding_rule", "id": "fr", "listener_ports": ["tcp:443-443"]},
        "hops": [
            listener, {"hop": "backend", "id": "bs"}, {"hop": "target_group", "id": "ig"},
            {"hop": "network", "id": "vpc"}, {"hop": "firewall", "id": "gfe"},
        ],
    }]
    fr_path = json.loads(rules["fr"].props()["exposure_paths"])[0]
    assert fr_path["entry"] == {"type": "external_ip", "id": "34.9.9.9"} and fr_path["hops"] == [listener]
    assert json.loads(backends["bs"].props()["exposure_paths"])[0]["hops"] == [listener]


def test_managed_service_path_and_blocker():
    sql = reach.sql_instances([
        {"id": "open", "ipv4": True, "public_ip": "1.2.3.4", "networks": ["0.0.0.0/0"], "port": 5432},
        {"id": "narrow", "ipv4": True, "public_ip": "1.2.3.4", "networks": ["203.0.113.0/24"], "port": 5432},
    ])
    path = json.loads(sql["open"].props()["exposure_paths"])[0]
    assert path["entry"] == {"type": "external_ip", "id": "1.2.3.4"}
    assert path["hops"] == [{"hop": "service", "id": "open", "rule": "authorized_networks 0.0.0.0/0"}]
    assert json.loads(sql["narrow"].props()["exposure_blocked_by"]) == [
        {"hop": "service", "id": "narrow", "reason": "not_allowed", "detail": "authorized_networks"},
    ]
