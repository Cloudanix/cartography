import asyncio
import pathlib
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from azure.mgmt.network import models as network_models

import cartography.intel.azure
from cartography.intel.azure import compute
from cartography.intel.azure import iam
from cartography.intel.azure import key_vaults
from cartography.intel.azure import network
from cartography.intel.azure import tenant
from cartography.intel.azure.util import console_link

AZURE_DIR = pathlib.Path(cartography.intel.azure.__file__).parent
VNET = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1"


def _fake_link(resource_id, common_job_parameters):
    return f"link:{resource_id}"


def test_safe_console_link_returns_none_instead_of_raising_without_tenant_domain(caplog):
    if isinstance(console_link.azure_console_link, MagicMock):
        pytest.skip("cloudconsolelink not installed")
    console_link._warn_missing_tenant_domain.cache_clear()

    with caplog.at_level("WARNING", logger=console_link.__name__):
        assert console_link.safe_console_link(VNET, {"UPDATE_TAG": 1}) is None
        assert console_link.safe_console_link(f"{VNET}/subnets/a", {"UPDATE_TAG": 1}) is None
    assert len(caplog.records) == 1  # once per sync, not once per resource

    assert console_link.safe_console_link(None, {"Azure_Primary_AD_Domain_Name": "x.onmicrosoft.com"}) is None
    assert console_link.safe_console_link(VNET, {"Azure_Primary_AD_Domain_Name": "x.onmicrosoft.com"}).startswith(
        "https://portal.azure.com/#@x.onmicrosoft.com/resource/subscriptions/sub-1/",
    )


def test_a_failed_link_never_overwrites_the_stored_one():
    # safe_console_link returns None on failure; a plain `SET n.consolelink = item.consolelink` would erase the
    # link a previous sync stored, so every Azure loader must write it through coalesce().
    plain_write = re.compile(r"\.(consolelink|console_link) = (?!coalesce\()\w+\.")
    offenders = [
        f"{path.relative_to(AZURE_DIR)}:{lineno}"
        for path in AZURE_DIR.rglob("*.py")
        for lineno, line in enumerate(path.read_text().splitlines(), 1)
        if plain_write.search(line)
    ]
    assert offenders == []


def test_vm_extensions_link_to_their_own_id_not_the_last_vm():
    vm_ids = [f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-{i}" for i in (1, 2)]
    client = MagicMock()
    client.virtual_machine_extensions.list.side_effect = [
        MagicMock(value=[SimpleNamespace(id=f"{vm_id}/extensions/ext", type="t", name="ext", location="l")])
        for vm_id in vm_ids
    ]
    vms = [{"id": vm_id, "name": vm_id.split("/")[-1], "resource_group": "rg"} for vm_id in vm_ids]

    with patch.object(compute, "safe_console_link", side_effect=_fake_link):
        exts = compute.get_vm_extensions_list(vms, client, {})

    assert [e["consolelink"] for e in exts] == [f"link:{vm_id}/extensions/ext" for vm_id in vm_ids]


def test_load_balancer_and_nic_children_get_consolelinks():
    lb_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb"
    nic_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
    lb = network_models.LoadBalancer({
        "id": lb_id,
        "properties": {
            "frontendIPConfigurations": [{"id": f"{lb_id}/frontendIPConfigurations/fe"}],
            "backendAddressPools": [{"id": f"{lb_id}/backendAddressPools/be"}],
        },
    })
    nic = network_models.NetworkInterface({
        "id": nic_id, "properties": {"ipConfigurations": [{"id": f"{nic_id}/ipConfigurations/ip"}]},
    })
    client = MagicMock()
    client.load_balancers.list_all.return_value = [lb]
    client.network_interfaces.list_all.return_value = [nic]

    with patch.object(network, "safe_console_link", side_effect=_fake_link):
        [loaded_lb] = network.get_load_balancers_list(client, None, {})
        [loaded_nic] = network.get_network_interfaces_list(client, None, {})

    assert loaded_lb["frontend_ip_configurations"][0]["consolelink"] == f"link:{lb_id}/frontendIPConfigurations/fe"
    assert loaded_lb["backend_address_pools"][0]["consolelink"] == f"link:{lb_id}/backendAddressPools/be"
    assert loaded_nic["ip_configurations"][0]["consolelink"] == f"link:{nic_id}/ipConfigurations/ip"


def test_service_principal_and_domain_links_use_graph_ids_not_custom_ids():
    client = MagicMock()
    client.service_principals.get = AsyncMock(
        return_value=MagicMock(value=[SimpleNamespace(id="sp-oid", app_id="app-1")], odata_next_link=None),
    )
    client.domains.get = AsyncMock(return_value=MagicMock(value=[SimpleNamespace(id="acme.com")]))

    with patch.object(console_link.azure_console_link, "get_console_link", return_value="link") as link:
        [sp] = asyncio.run(iam.get_tenant_service_accounts_list(client, "tenant-1"))
        [domain] = asyncio.run(iam.get_tenant_domains_list(client, "tenant-1"))

    assert link.call_args_list[0].kwargs["id"] == "sp-oid"
    assert link.call_args_list[1].kwargs["id"] == "acme.com"
    assert sp["id"] == "tenants/tenant-1/ServiceAccounts/sp-oid"
    assert domain["id"] == "tenants/tenant-1/domains/acme.com"


def test_tenant_and_graph_entities_without_an_id_load_without_a_link():
    if isinstance(console_link.azure_console_link, MagicMock):
        pytest.skip("cloudconsolelink not installed")
    tenant_obj = dict.fromkeys(
        ["id", "tenantId", "tenantCategory", "tenantType", "displayName", "country", "countryCode", "defaultDomain"],
        "",
    )

    with patch.object(tenant, "run_write_query") as write:
        tenant.load_azure_tenant(MagicMock(), tenant_obj, {"id": "u"}, 1, {"WORKSPACE_ID": "w"})
    assert write.call_args.kwargs["consolelink"] is None

    client = MagicMock()
    client.domains.get = AsyncMock(return_value=MagicMock(value=[SimpleNamespace(id=None)]))
    [domain] = asyncio.run(iam.get_tenant_domains_list(client, "tenant-1"))
    assert domain["consolelink"] is None


def test_key_vault_children_without_tenant_domain_keep_their_stored_link():
    if isinstance(console_link.azure_console_link, MagicMock):
        pytest.skip("cloudconsolelink not installed")

    [key] = key_vaults.transform_key_vaults_keys([{"key_uri": "https://kv.vault.azure.net/keys/k"}], "v", {})
    # None (not '') so the loader's coalesce() keeps the link a previous sync stored.
    assert key["consolelink"] is None
