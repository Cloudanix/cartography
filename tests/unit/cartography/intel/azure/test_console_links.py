import asyncio
import pathlib
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

import cartography.intel.azure
from cartography.intel.azure import compute
from cartography.intel.azure import iam
from cartography.intel.azure import network
from cartography.intel.azure.util import console_link

AZURE_DIR = pathlib.Path(cartography.intel.azure.__file__).parent
VNET = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1"


def _fake_link(resource_id, common_job_parameters):
    return f"link:{resource_id}"


def test_no_consolelink_is_written_only_on_create():
    # ON CREATE SET never runs again for an existing node, so link fixes would never reach it.
    on_create_blocks = re.compile(r"ON CREATE SET(.*?)(?=^\s*(?:SET|ON MATCH SET|WITH|MERGE|MATCH)\b)", re.S | re.M)
    offenders = [
        path.name
        for path in AZURE_DIR.glob("*.py")
        for block in on_create_blocks.findall(path.read_text())
        if "consolelink" in block
    ]
    assert offenders == []


def test_safe_console_link_returns_empty_instead_of_raising_without_tenant_domain():
    if isinstance(console_link.azure_console_link, MagicMock):
        pytest.skip("cloudconsolelink not installed")

    assert console_link.safe_console_link(VNET, {}) == ""
    assert console_link.safe_console_link(None, {"Azure_Primary_AD_Domain_Name": "x.onmicrosoft.com"}) == ""
    assert console_link.safe_console_link(VNET, {"Azure_Primary_AD_Domain_Name": "x.onmicrosoft.com"}).startswith(
        "https://portal.azure.com/#@x.onmicrosoft.com/resource/subscriptions/sub-1/",
    )


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
    lb = {
        "id": lb_id,
        "frontend_ip_configurations": [{"id": f"{lb_id}/frontendIPConfigurations/fe"}],
        "backend_address_pools": [{"id": f"{lb_id}/backendAddressPools/be"}],
    }
    nic = {"id": nic_id, "ip_configurations": [{"id": f"{nic_id}/ipConfigurations/ip"}]}
    client = MagicMock()
    client.load_balancers.list_all.return_value = [MagicMock(as_dict=lambda: lb)]
    client.network_interfaces.list_all.return_value = [MagicMock(as_dict=lambda: nic)]

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

    with patch.object(iam.azure_console_link, "get_console_link", return_value="link") as link:
        [sp] = asyncio.run(iam.get_tenant_service_accounts_list(client, "tenant-1"))
        [domain] = asyncio.run(iam.get_tenant_domains_list(client, "tenant-1"))

    assert link.call_args_list[0].kwargs["id"] == "sp-oid"
    assert link.call_args_list[1].kwargs["id"] == "acme.com"
    assert sp["id"] == "tenants/tenant-1/ServiceAccounts/sp-oid"
    assert domain["id"] == "tenants/tenant-1/domains/acme.com"
