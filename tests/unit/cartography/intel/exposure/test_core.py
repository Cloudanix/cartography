from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import protocols_for
from cartography.intel.exposure.rules import allow_only_open
from cartography.intel.exposure.rules import FirewallRule
from cartography.intel.exposure.rules import first_match_open
from cartography.intel.exposure.rules import is_world
from cartography.intel.exposure.rules import with_stateless_return
from cartography.intel.exposure.software import os_from_image_name


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
