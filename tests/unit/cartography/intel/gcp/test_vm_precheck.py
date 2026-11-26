from unittest.mock import MagicMock

from googleapiclient.discovery import HttpError

from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.gcp import vm_precheck
from cartography.intel.gcp.compute import os_login_enabled
from cartography.intel.gcp.compute import transform_gcp_instances
from cartography.intel.gcp.exposure_layers.network import Firewall
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import VpcFacts

VPC = "projects/p1/global/networks/default"
INSTANCE_ID = "projects/p1/zones/us-central1-a/instances/vm1"


def _http_error(status: int = 403) -> HttpError:
    resp = MagicMock(status=status, reason="denied")
    return HttpError(resp, b'{"error": {"code": 403, "message": "denied", "status": "PERMISSION_DENIED"}}')


def _instance(**kwargs) -> Instance:
    return Instance(id=INSTANCE_ID, running=True, vpcs=(VPC,), **kwargs)


def _rule(ports="tcp:22", allow=True, **kwargs) -> Firewall:
    protocol, _, rng = ports.partition(":")
    lo, _, hi = rng.partition("-")
    port_set = PortSet.of(protocol, int(lo), int(hi or lo)) if rng else PortSet.of(protocol)
    return Firewall(allow=allow, ports=port_set, **kwargs)


def _vpcs(*rules, before=(), visible=True):
    return {VPC: VpcFacts(visible=visible, firewalls=list(rules), policies_before=[list(before)] if before else [])}


# ---------------------------------------------------------------- os_login_enabled / transform

def test_os_login_instance_setting_overrides_project():
    assert os_login_enabled({"enable-oslogin": "FALSE"}, {"enable-oslogin": "TRUE"}) is False
    assert os_login_enabled({"enable-oslogin": "true"}, {}) is True


def test_os_login_falls_back_to_project_then_off():
    assert os_login_enabled({}, {"enable-oslogin": "TRUE"}) is True
    assert os_login_enabled({}, {}) is False


def test_os_login_unknown_when_project_metadata_unreadable():
    assert os_login_enabled({}, None) is None
    # The instance's own setting still decides.
    assert os_login_enabled({"enable-oslogin": "TRUE"}, None) is True


def _raw_instance(**kwargs):
    instance = {
        "id": "123",
        "name": "vm1",
        "zone": "https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a",
        "disks": [{"boot": True, "architecture": "ARM64", "initializeParams": {"diskName": "vm1"}}],
        "networkInterfaces": [],
    }
    instance.update(kwargs)
    return instance


def test_transform_sets_architecture_and_os_login():
    raw = _raw_instance(metadata={"items": [{"key": "enable-oslogin", "value": "TRUE"}]})
    result = transform_gcp_instances([raw], MagicMock(), {})[0]
    assert result["architecture"] == "arm64"
    assert result["os_login_enabled"] is True


def test_transform_without_boot_disk_architecture_or_project_metadata():
    raw = _raw_instance(disks=[{"boot": True, "initializeParams": {"diskName": "vm1"}}])
    result = transform_gcp_instances([raw], MagicMock())[0]
    assert result["architecture"] is None
    assert result["os_login_enabled"] is None


# ---------------------------------------------------------------- OS inventory

def test_inventory_instance_segment():
    assert vm_precheck._inventory_instance("projects/1/locations/us-central1-a/instances/456/inventory") == "456"
    assert vm_precheck._inventory_instance("bogus") is None


def test_os_fields_matched_by_instance_id_then_name():
    inventories = {"123": {"shortName": "ubuntu", "longName": "Ubuntu 22.04 LTS", "version": "22.04"}}
    assert vm_precheck.os_fields({"instance_id": "123", "name": "vm1"}, inventories) == {
        "os_short_name": "ubuntu", "os_long_name": "Ubuntu 22.04 LTS", "os_version": "22.04",
        "vm_os": "ubuntu", "vm_os_version": "22.04",
    }
    assert vm_precheck.os_fields({"instance_id": "999", "name": "vm9"}, inventories) == {
        "os_short_name": None, "os_long_name": None, "os_version": None,
    }


def test_os_fields_vm_os_from_inventory():
    """Inventory fills vm_os when the boot-disk license did not. An unknown short name must not wipe it."""
    cos = vm_precheck.os_fields({"instance_id": "1"}, {"1": {
        "shortName": "cos", "longName": "Container-Optimized OS from Google", "version": "125",
    }})
    assert cos["vm_os"] == "cos"
    assert cos["vm_os_version"] == "125"

    windows = vm_precheck.os_fields({"instance_id": "2"}, {"2": {
        "shortName": "windows", "longName": "Windows Server 2022 Datacenter", "version": "10.0.20348",
    }})
    assert windows["vm_os"] == "windows"
    assert windows["vm_os_version"] == "10.0.20348"

    custom = vm_precheck.os_fields({"instance_id": "3"}, {"3": {
        "shortName": "customos", "longName": "My Image", "version": "1",
    }})
    assert "vm_os" not in custom
    assert "vm_os_version" not in custom


def test_get_os_inventories_skips_failing_zone():
    osconfig = MagicMock()
    inventories = osconfig.projects.return_value.locations.return_value.instances.return_value.inventories.return_value
    ok = MagicMock()
    ok.execute.return_value = {"inventories": [{
        "name": "projects/1/locations/us-central1-a/instances/123/inventory", "osInfo": {"shortName": "debian"},
    }]}
    failing = MagicMock()
    failing.execute.side_effect = _http_error()
    inventories.list.side_effect = [ok, failing]
    inventories.list_next.return_value = None
    assert vm_precheck.get_os_inventories(osconfig, "p1", {"us-central1-a", "us-central1-b"}) == {
        "123": {"shortName": "debian"},
    }


# ---------------------------------------------------------------- iap_ssh_ingress_allowed

def test_iap_range_rule_allows_ssh():
    vpcs = _vpcs(_rule(source_ranges=("35.235.240.0/20",)))
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), vpcs) is True


def test_world_rule_and_sourceless_rule_cover_iap():
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), _vpcs(_rule(source_ranges=("0.0.0.0/0",)))) is True
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), _vpcs(_rule())) is True


def test_wrong_port_or_no_rule_is_not_allowed():
    assert vm_precheck.iap_ssh_ingress_allowed(
        _instance(), _vpcs(_rule("tcp:80", source_ranges=("35.235.240.0/20",))),
    ) is False
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), _vpcs()) is False


def test_rule_for_other_tag_does_not_apply():
    vpcs = _vpcs(_rule(source_ranges=("35.235.240.0/20",), target_tags=frozenset({"bastion"})))
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(tags=frozenset({"web"})), vpcs) is False
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(tags=frozenset({"bastion"})), vpcs) is True


def test_higher_priority_deny_wins():
    vpcs = _vpcs(
        _rule(source_ranges=("35.235.240.0/20",), priority=1000),
        _rule(allow=False, source_ranges=("0.0.0.0/0",), priority=100),
    )
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), vpcs) is False


def test_policy_rules_use_non_internet_context():
    allow_non_internet = _rule(
        source_ranges=("35.235.240.0/20",), in_policy=True, network_context="NON_INTERNET", priority=10,
    )
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), _vpcs(before=[allow_non_internet])) is True
    deny_internet = _rule(
        allow=False, source_ranges=("0.0.0.0/0",), in_policy=True, network_context="INTERNET", priority=10,
    )
    # An internet-only deny does not match IAP traffic; the VPC rule then admits it.
    vpcs = _vpcs(_rule(source_ranges=("35.235.240.0/20",)), before=[deny_internet])
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), vpcs) is True


def test_unknown_when_not_visible_or_no_network():
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), _vpcs(visible=False)) is None
    assert vm_precheck.iap_ssh_ingress_allowed(_instance(), {}) is None
    assert vm_precheck.iap_ssh_ingress_allowed(None, _vpcs()) is None


# ---------------------------------------------------------------- permissions

def _resources(project_permissions, instance_permissions=(), iap_permissions=(), sa_permissions=None):
    """Mocked clients; each returns the permissions it is told to grant."""
    resources = MagicMock()

    def crm_test(resource, body):
        request = MagicMock()
        wanted = body["permissions"][0]
        if project_permissions is None:
            request.execute.side_effect = _http_error()
        else:
            request.execute.return_value = {"permissions": [wanted] if wanted in project_permissions else []}
        return request

    resources.crm_v1.projects.return_value.testIamPermissions.side_effect = crm_test
    resources.compute.instances.return_value.testIamPermissions.return_value.execute.return_value = {
        "permissions": list(instance_permissions),
    }
    resources.iap.v1.return_value.testIamPermissions.return_value.execute.return_value = {
        "permissions": list(iap_permissions),
    }
    sa_request = resources.iam.projects.return_value.serviceAccounts.return_value.testIamPermissions.return_value
    sa_request.execute.return_value = {"permissions": list(sa_permissions or [])}
    return resources


ROW = {
    "id": INSTANCE_ID, "name": "vm1", "zone": "us-central1-a", "project_number": 111,
    "service_accounts": ["sa@p1.iam.gserviceaccount.com"],
}


def test_project_grant_skips_per_vm_calls():
    resources = _resources([vm_precheck.PERM_IAP_TUNNEL, vm_precheck.PERM_OS_ADMIN_LOGIN, vm_precheck.PERM_ACT_AS])
    checker = vm_precheck.PermissionChecker(resources, "p1")
    assert checker.iap_tunnel(ROW) is True
    assert checker.os_admin_login(ROW) is True
    assert checker.service_account_user(ROW) is True
    resources.compute.instances.return_value.testIamPermissions.assert_not_called()
    resources.iap.v1.return_value.testIamPermissions.assert_not_called()


def test_vm_level_grants_when_project_does_not_grant():
    resources = _resources(
        [], instance_permissions=[vm_precheck.PERM_OS_ADMIN_LOGIN], iap_permissions=[vm_precheck.PERM_IAP_TUNNEL],
    )
    checker = vm_precheck.PermissionChecker(resources, "p1")
    assert checker.os_admin_login(ROW) is True
    assert checker.iap_tunnel(ROW) is True
    resources.iap.v1.return_value.testIamPermissions.assert_called_with(
        resource="projects/111/iap_tunnel/zones/us-central1-a/instances/vm1",
        body={"permissions": [vm_precheck.PERM_IAP_TUNNEL]},
    )
    assert checker.service_account_user(ROW) is False


def test_unknown_when_project_check_fails_and_vm_denies():
    checker = vm_precheck.PermissionChecker(_resources(None), "p1")
    assert checker.os_admin_login(ROW) is None
    assert checker.iap_tunnel(ROW) is None


def test_service_account_user_without_accounts_and_cache():
    resources = _resources([], sa_permissions=[vm_precheck.PERM_ACT_AS])
    checker = vm_precheck.PermissionChecker(resources, "p1")
    assert checker.service_account_user({**ROW, "service_accounts": []}) is True
    assert checker.service_account_user(ROW) is True
    assert checker.service_account_user(ROW) is True
    sa_test = resources.iam.projects.return_value.serviceAccounts.return_value.testIamPermissions
    assert sa_test.call_count == 1


# ---------------------------------------------------------------- sync

def test_sync_writes_anchored_props(mocker):
    session = MagicMock()
    mocker.patch.object(vm_precheck, "read_precheck_instances", return_value=[{**ROW, "instance_id": "123"}])
    mocker.patch.object(vm_precheck, "get_os_inventories", return_value={"123": {"shortName": "ubuntu"}})
    mocker.patch.object(vm_precheck, "_exposure_view", return_value=({INSTANCE_ID: _instance()}, _vpcs(_rule())))
    resources = _resources([vm_precheck.PERM_IAP_TUNNEL, vm_precheck.PERM_OS_ADMIN_LOGIN, vm_precheck.PERM_ACT_AS])

    vm_precheck.sync(session, resources, "p1", {"UPDATE_TAG": 1})

    query = session.run.call_args.args[0]
    assert "MATCH (:GCPProject{id: $GCP_PROJECT_ID})-[:RESOURCE]->(i:GCPInstance{id: row.id})" in query
    assert session.run.call_args.kwargs["GCP_PROJECT_ID"] == "p1"
    assert session.run.call_args.kwargs["rows"] == [{
        "id": INSTANCE_ID,
        "props": {
            "os_short_name": "ubuntu", "os_long_name": None, "os_version": None,
            "vm_os": "ubuntu",
            "iap_ssh_ingress_allowed": True,
            "iap_tunnel_access_granted": True,
            "os_login_admin_granted": True,
            "service_account_user_granted": True,
        },
    }]


def test_sync_without_instances_calls_no_api(mocker):
    mocker.patch.object(vm_precheck, "read_precheck_instances", return_value=[])
    resources = MagicMock()
    vm_precheck.sync(MagicMock(), resources, "p1", {"UPDATE_TAG": 1})
    resources.crm_v1.projects.assert_not_called()
    resources.osconfig.projects.assert_not_called()
