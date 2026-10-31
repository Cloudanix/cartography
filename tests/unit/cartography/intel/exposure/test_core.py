import json

from cartography.intel.exposure.layers import hop
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.layers import reach_summaries
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import protocols_for
from cartography.intel.exposure.rules import allow_only_open
from cartography.intel.exposure.rules import FirewallRule
from cartography.intel.exposure.rules import first_match_open
from cartography.intel.exposure.rules import is_world
from cartography.intel.exposure.rules import tiered_open
from cartography.intel.exposure.rules import with_stateless_return
from cartography.intel.exposure.software import os_from_image_name
from cartography.intel.exposure.step import is_requested
from cartography.intel.exposure.step import run_if_requested
from cartography.util import collect_failed_analysis_jobs


def ps(*values):
    return PortSet.parse(values)


def test_portset_merge_and_format():
    s = PortSet.of("tcp", 80, 80) | PortSet.of("tcp", 81, 90) | PortSet.of("udp", 53, 53)
    assert s.to_strings() == ["tcp:80-90", "udp:53-53"]


def test_portset_all_protocol_and_missing_bounds():
    assert PortSet.of("-1").to_strings() == ["tcp:0-65535", "udp:0-65535"]
    assert PortSet.of("tcp", -1, -1).to_strings() == ["tcp:0-65535"]


def test_portset_icmp_is_empty():
    assert PortSet.of("icmp", 8, 0).is_empty()
    assert protocols_for("1") == ()


def test_portset_intersect_subtract():
    a = ps("tcp:0-1000")
    assert (a & ps("tcp:443-443", "udp:1-5")).to_strings() == ["tcp:443-443"]
    assert (a - ps("tcp:22-22")).to_strings() == ["tcp:0-21", "tcp:23-1000"]
    assert (a - ps("tcp:0-1000")).is_empty()


def test_portset_parse_roundtrip():
    s = ps("tcp:22-22", "tcp:443-443", "udp:500-501")
    assert PortSet.parse(s.to_strings()) == s


def test_is_world():
    assert is_world("0.0.0.0/0") and is_world("::/0") and is_world("Internet") and is_world("*")
    assert not is_world("10.0.0.0/8") and not is_world(None)


def test_allow_only_ignores_narrow_sources():
    rules = [
        FirewallRule(ps("tcp:22-22"), world=False),
        FirewallRule(ps("tcp:443-443"), world=True),
    ]
    assert allow_only_open(rules).to_strings() == ["tcp:443-443"]


def test_first_match_deny_before_allow():
    # NACL: rule 100 denies 22 from anywhere, rule 200 allows all.
    rules = [
        FirewallRule(ps("tcp:0-65535", "udp:0-65535"), world=True, allow=True, priority=200),
        FirewallRule(ps("tcp:22-22"), world=True, allow=False, priority=100),
    ]
    assert first_match_open(rules).to_strings() == ["tcp:0-21", "tcp:23-65535", "udp:0-65535"]


def test_first_match_narrow_deny_does_not_close_for_everyone():
    rules = [
        FirewallRule(ps("tcp:22-22"), world=False, allow=False, priority=1),
        FirewallRule(ps("tcp:22-22"), world=True, allow=True, priority=2),
    ]
    assert first_match_open(rules).to_strings() == ["tcp:22-22"]


def test_first_match_tie_deny_wins_and_default():
    rules = [
        FirewallRule(ps("tcp:80-80"), world=True, allow=True, priority=1000),
        FirewallRule(ps("tcp:80-80"), world=True, allow=False, priority=1000),
    ]
    assert first_match_open(rules).is_empty()
    assert first_match_open([], default_allow=True) == PortSet.everything()


def _rule(entries, allow=True, priority=1, goto_next=False, world=True):
    return FirewallRule(ps(*entries), world=world, allow=allow, priority=priority, goto_next=goto_next)


def test_tiered_upper_level_decides_first():
    org_deny = [_rule(["tcp:22-22"], allow=False)]
    org_allow = [_rule(["tcp:8443-8443"])]
    vpc = [_rule(["tcp:0-65535"]), _rule(["tcp:8443-8443"], allow=False, priority=0)]
    # Org deny beats a VPC allow; org allow beats a VPC deny; ports the org skips stay with the VPC.
    assert tiered_open([org_deny, vpc]).to_strings() == ["tcp:0-21", "tcp:23-8442", "tcp:8444-65535"]
    assert tiered_open([org_allow, vpc]).to_strings() == ["tcp:0-65535"]


def test_tiered_goto_next_and_no_match_fall_through():
    # goto_next on 22 skips the org's later deny-all; ports no org rule covers go on too.
    org = [_rule(["tcp:22-22"], allow=False, goto_next=True), _rule(["tcp:0-1000"], allow=False, priority=2)]
    vpc = [_rule(["tcp:22-22", "tcp:5000-5000"])]
    assert tiered_open([org, vpc]).to_strings() == ["tcp:22-22", "tcp:5000-5000"]
    assert tiered_open([org, vpc], default_allow=True).to_strings() == ["tcp:22-22", "tcp:1001-65535", "udp:0-65535"]


def test_tiered_ignores_narrow_sources_and_matches_first_match():
    narrow_deny = [_rule(["tcp:443-443"], allow=False, world=False)]
    assert tiered_open([narrow_deny, [_rule(["tcp:443-443"])]]).to_strings() == ["tcp:443-443"]
    rules = [_rule(["tcp:80-80"], priority=5), _rule(["tcp:0-100"], allow=False, priority=1)]
    assert tiered_open([rules]) == first_match_open(rules)


def test_stateless_return_requires_ephemeral_outbound():
    inbound = ps("tcp:443-443", "udp:53-53")
    assert with_stateless_return(inbound, ps("tcp:1024-65535")).to_strings() == ["tcp:443-443"]
    assert with_stateless_return(inbound, ps("tcp:443-443")).is_empty()


def test_reach_accumulates_paths():
    r = Reach(public_reasons={"public_ip"})
    r.add_path(ps("tcp:22-22"), "direct")
    r.add_path(PortSet.empty(), "ignored")
    r.add_path(ps("tcp:443-443"), "elbv2:arn")
    props = r.props()
    assert props["internet_reachable"] is True
    assert props["internet_reachable_ports"] == ["tcp:22-22", "tcp:443-443"]
    assert props["internet_reachable_via"] == ["direct", "elbv2:arn"]
    assert Reach().props()["internet_reachable"] is False


def test_reach_keeps_ports_and_hops_per_path():
    r = Reach(public_reasons={"public_ip"})
    r.add_path(ps("tcp:22-22"), "direct_ipv4", [hop("security_group", "sg-1")], {"type": "public_ip", "id": "1.2.3.4"})
    r.add_path(ps("tcp:8080-8080"), "elbv2:arn", [hop("listener", "l-1", "HTTPS 443")])
    r.add_path(ps("tcp:23-23"), "direct_ipv4", [hop("security_group", "sg-1"), hop("nacl", "acl-1")])
    r.block("route", "rtb-9", "no_internet_route")
    props = r.props()
    paths = json.loads(props["exposure_paths"])
    assert [p["via"] for p in paths] == ["direct_ipv4", "elbv2:arn"]
    assert paths[0]["ports"] == ["tcp:22-23"]
    assert paths[0]["hops"] == [{"hop": "security_group", "id": "sg-1"}, {"hop": "nacl", "id": "acl-1"}]
    assert paths[0]["entry"] == {"type": "public_ip", "id": "1.2.3.4"}
    assert paths[1]["hops"] == [{"hop": "listener", "id": "l-1", "rule": "HTTPS 443"}]
    # Reachable: blockers seen on other subnets are not reported.
    assert json.loads(props["exposure_blocked_by"]) == []


def test_reach_blocked_by_only_for_public_unreachable():
    r = Reach(public_reasons={"publicly_accessible"})
    r.block("route", "rtb-9", "no_internet_route", detail="no 0.0.0.0/0 route")
    r.block("route", "rtb-9", "no_internet_route", detail="no 0.0.0.0/0 route")
    r.block("nacl", "acl-1", "denied", ports=ps("tcp:0-65535"))
    assert json.loads(r.props()["exposure_blocked_by"]) == [
        {"hop": "route", "id": "rtb-9", "reason": "no_internet_route", "detail": "no 0.0.0.0/0 route"},
        {"hop": "nacl", "id": "acl-1", "reason": "denied", "ports": ["tcp:0-65535"]},
    ]
    private = Reach()
    private.block("route", "rtb-9", "no_internet_route")
    assert json.loads(private.props()["exposure_blocked_by"]) == []
    assert json.loads(Reach().props()["exposure_paths"]) == []


def test_reach_summaries_rewrite_every_source():
    edges = [
        {"src": "i-1", "dst": "db-2", "dst_type": "RDSInstance", "ports": ["tcp:5432-5432"], "via": "cidr"},
        {
            "src": "i-1", "dst": "c-1", "dst_type": "ElasticacheCluster", "ports": ["tcp:6379-6379"],
            "via": "tgw:tgw-1", "admitted_by": "sg-9",
        },
    ]
    rows = {r["id"]: r["props"] for r in reach_summaries(["i-1", "i-2"], edges)}
    assert rows["i-2"] == {"network_reachable_data_stores": "[]", "network_reachable_data_store_count": 0}
    stores = json.loads(rows["i-1"]["network_reachable_data_stores"])
    assert [s["type"] for s in stores] == ["ElasticacheCluster", "RDSInstance"]
    assert stores[0]["admitted_by"] == "sg-9" and "admitted_by" not in stores[1]
    assert rows["i-1"]["network_reachable_data_store_count"] == 2


def test_exposure_step_runs_only_when_requested():
    all_syncs = ["ec2:instance", "rds"]
    assert is_requested(None, all_syncs) and is_requested([], all_syncs)
    assert is_requested(["exposure_layers"], all_syncs)
    assert is_requested(["rds", "ec2:instance"], all_syncs)
    assert not is_requested(["rds"], all_syncs)


def test_exposure_step_failure_is_reported_not_raised():
    def boom(_session, _params):
        raise RuntimeError("bug")

    with collect_failed_analysis_jobs() as failed:
        run_if_requested(boom, None, {"AWS_ID": "123", "UPDATE_TAG": 1}, ["exposure_layers"], ["rds"])
        run_if_requested(boom, None, {"AWS_ID": "123"}, ["rds"], ["rds", "s3"])  # not requested: not run
    assert failed == [{"job": "exposure_layers", "scope": {"AWS_ID": "123"}}]


def test_os_from_image_name():
    assert os_from_image_name("ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20240207") == "ubuntu@22.04"
    assert os_from_image_name("ubuntu-2204-jammy-v20240207") == "ubuntu@22.04"
    assert os_from_image_name("0001-com-ubuntu-server-jammy", "22_04-lts-gen2") == "ubuntu@22.04"
    assert os_from_image_name("al2023-ami-2023.3.20240219.0-kernel-6.1-x86_64") == "amazon-linux@2023"
    assert os_from_image_name("amzn2-ami-kernel-5.10-hvm-2.0.20240131.0-x86_64-gp2") == "amazon-linux@2"
    assert os_from_image_name("Windows_Server-2019-English-Full-Base-2024.02.14") == "windows-server@2019"
    assert os_from_image_name("RHEL-9.2.0_HVM-20230503-x86_64-41-Hourly2-GP2") == "rhel@9.2"
    assert os_from_image_name("debian-12-bookworm-v20240213") == "debian@12"
    assert os_from_image_name("Oracle-Linux-8.9-2024.01.26-0") == "oracle-linux@8.9"
    assert os_from_image_name("my-golden-image") is None
    assert os_from_image_name(None, "") is None
