from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN
from cartography.intel.exposure.ports import PortSet
from cartography.intel.gcp.compute import firewall_entry_strings
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
    run = reach.cloud_run_services([
        {"id": "all", "url": "https://a.run.app", "ingress": "all"},
        {"id": "internal", "url": "https://b.run.app", "ingress": "internal"},
        {"id": "lb", "url": "https://c.run.app", "ingress": "internal-and-cloud-load-balancing"},
    ])
    assert run["all"].props()["internet_reachable"] is True
    assert run["internal"].props()["internet_reachable"] is False
    assert run["lb"].props()["internet_reachable"] is False
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
    ]
    out = reach.functions(rows)
    assert out["all"].props()["internet_reachable_ports"] == ["tcp:443-443"]
    assert not out["internal"].props()["internet_reachable"]
    assert out["event"].props() == reach.Reach().props()


def test_auth_verdicts():
    assert access.bucket_auth({"members": ["allUsers"], "acl": [], "ubla": True}) == (AUTH_NONE, ["gcs_allusers"])
    assert access.bucket_auth({"members": ["allUsers"], "pap": "enforced"})[0] == AUTH_REQUIRED
    assert access.bucket_auth({"members": [], "acl": ["allAuthenticatedUsers"], "ubla": True})[0] == AUTH_REQUIRED
    assert access.bucket_auth({"members": [], "acl": ["allAuthenticatedUsers"], "ubla": False}) == (
        AUTH_NONE, ["gcs_allauthenticatedusers"],
    )
    assert access.data_verdict("bigquery", [None, "user:a@b.c"]) == (AUTH_REQUIRED, ["iam"])
    invoker = {"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}
    viewer = {"role": "roles/viewer", "members": ["allUsers"]}
    assert access.function_auth({"bindings": [invoker]}) == (AUTH_NONE, ["invoker_allusers"])
    assert access.function_auth({"bindings": [viewer]}) == (AUTH_REQUIRED, ["iam_invoker"])
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
    )
    rows = instance_rows([db, app, other], {"vpc": VpcFacts(visible=True, firewalls=[fw])})
    assert rows == [{"src": "app", "dst": "db", "ports": ["tcp:5432-5432"], "via": "firewall_source_tag_or_sa"}]


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
