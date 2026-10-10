import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.intel.azure import iam


def test_azure_role_managed_type():
    # Azure built-in roles surface either a roleDefinitions type or an explicit BuiltInRole role_type.
    assert iam._azure_role_managed_type({"type": "Microsoft.Authorization/roleDefinitions"}) == "predefined"
    assert iam._azure_role_managed_type({"role_type": "BuiltInRole"}) == "predefined"
    # Customer-authored roles report CustomRole / roleAssignments.
    assert iam._azure_role_managed_type(
        {"type": "Microsoft.Authorization/roleAssignments", "role_type": "CustomRole"},
    ) == "custom"
    assert iam._azure_role_managed_type({}) == "custom"


def test_azure_service_principal_managed_type():
    # Service principals owned by Microsoft's first-party tenant are provider-managed.
    assert iam._azure_service_principal_managed_type(iam.AZURE_MICROSOFT_TENANT_ID) == "predefined"
    assert iam._azure_service_principal_managed_type(iam.AZURE_MICROSOFT_TENANT_ID.upper()) == "predefined"
    # Customer-owned service principals belong to the customer's own tenant.
    assert iam._azure_service_principal_managed_type("00000000-1111-2222-3333-444444444444") == "custom"
    assert iam._azure_service_principal_managed_type(None) == "custom"


CUSTOMER_TENANT = "00000000-1111-2222-3333-444444444444"
FOREIGN_TENANT = "99999999-8888-7777-6666-555555555555"


def test_azure_external_access_type_service_principals():
    # Same-tenant SP is internal.
    assert iam.azure_external_access_type(CUSTOMER_TENANT, None, CUSTOMER_TENANT) is None
    # Microsoft first-party tenant is a provider service -> CrossAccount.
    assert iam.azure_external_access_type(iam.AZURE_MICROSOFT_TENANT_ID, None, CUSTOMER_TENANT) == "CrossAccount"
    # Any other foreign tenant -> ThirdParty (case-insensitive).
    assert iam.azure_external_access_type(FOREIGN_TENANT.upper(), None, CUSTOMER_TENANT) == "ThirdParty"


def test_azure_external_access_type_guest_users():
    # Guest user with no home-tenant signal is still external.
    assert iam.azure_external_access_type(None, "Guest", CUSTOMER_TENANT) == "ThirdParty"
    # Member user in-tenant is internal.
    assert iam.azure_external_access_type(None, "Member", CUSTOMER_TENANT) is None
    assert iam.azure_external_access_type("", "", CUSTOMER_TENANT) is None


def test_is_graph_auth_expired_error_detects_invalid_authentication_token():
    err = Exception(
        "APIError Code: 401 error: MainError(code='InvalidAuthenticationToken', "
        "message='Access token validation failed, the token is expired.')",
    )
    assert iam._is_graph_auth_expired_error(err) is True


def test_is_graph_auth_expired_error_ignores_throttle_and_other_failures():
    assert iam._is_graph_auth_expired_error(Exception("429 Too Many Requests")) is False
    assert iam._is_graph_auth_expired_error(Exception("Connection reset")) is False


def test_get_group_members_raises_on_expired_graph_token():
    client = MagicMock()
    members = MagicMock()
    members.get = AsyncMock(
        side_effect=Exception(
            "APIError Code: 401 code='InvalidAuthenticationToken' "
            "message='Access token validation failed, the token is expired.'",
        ),
    )
    client.groups.by_group_id.return_value.members = members

    with pytest.raises(iam.GraphAuthenticationExpiredError):
        asyncio.run(iam.get_group_members(MagicMock(), "tenants/t/Groups/g1", client=client))


def test_gather_group_members_fail_fast_skips_remaining_groups_after_auth_expiry():
    call_count = {"n": 0}

    async def fake_get_group_members(credentials, group_id, client=None):
        call_count["n"] += 1
        # First in-flight call expires; later callers should observe the circuit and skip.
        if group_id == "g-expire":
            await asyncio.sleep(0.01)
            raise iam.GraphAuthenticationExpiredError("expired")
        await asyncio.sleep(0.05)
        return [{"id": "u1", "group_id": group_id}]

    async def _run():
        with patch.object(iam, "get_group_members", side_effect=fake_get_group_members):
            results, expired = await iam._gather_group_members_fail_fast(
                MagicMock(),
                ["g-expire"] + [f"g-{i}" for i in range(20)],
                MagicMock(),
                "tenant-1",
            )
        return results, expired

    results, expired = asyncio.run(_run())
    assert expired is True
    assert any(isinstance(r, iam.GraphAuthenticationExpiredError) for r in results)
    # Circuit breaker must prevent calling Graph for every remaining group.
    assert call_count["n"] < 21


def test_get_tenant_service_accounts_list_stringifies_graph_uuid_fields():
    # https://cloudanix.sentry.io/issues/7784616181/
    # msgraph-sdk types appOwnerOrganizationId / tokenEncryptionKeyId as uuid.UUID; they must
    # leave as strings so managed_type can compare them and neo4j can store them.
    # conftest stubs msgraph, so stand in for the SDK model (plain attributes, no as_dict).
    from neo4j._codec.hydration.v1 import HydrationHandler
    from neo4j._codec.packstream.v1 import Packer

    first_party = SimpleNamespace(
        id="sp-1",
        app_owner_organization_id=uuid.UUID(iam.AZURE_MICROSOFT_TENANT_ID),
        token_encryption_key_id=uuid.UUID(FOREIGN_TENANT),
    )
    customer_owned = SimpleNamespace(id="sp-2", app_owner_organization_id=uuid.UUID(CUSTOMER_TENANT))
    unowned = SimpleNamespace(id="sp-3", app_owner_organization_id=None, token_encryption_key_id=None)
    client = MagicMock()
    client.service_principals.get = AsyncMock(
        return_value=MagicMock(value=[first_party, customer_owned, unowned], odata_next_link=None),
    )

    with patch.object(iam.azure_console_link, "get_console_link", return_value="link"):
        sps = asyncio.run(iam.get_tenant_service_accounts_list(client, CUSTOMER_TENANT))

    assert [sp["managed_type"] for sp in sps] == ["predefined", "custom", "custom"]
    assert sps[0]["app_owner_organization_id"] == iam.AZURE_MICROSOFT_TENANT_ID
    assert sps[0]["token_encryption_key_id"] == FOREIGN_TENANT
    assert sps[2]["app_owner_organization_id"] is None
    # Same packer the neo4j driver uses for query parameters; raises on uuid.UUID.
    Packer(MagicMock()).pack(sps, dehydration_hooks=HydrationHandler().new_hydration_scope().dehydration_hooks)


def test_load_roles_tx_retains_principal_type_and_emits_external_merge():
    tx = MagicMock()
    role_assignments = [
        {
            "role_definition_id": "role-1",
            "principal_id": "oid-1",
            "principal_type": "ServicePrincipal",
        },
    ]

    iam._load_roles_tx(tx, CUSTOMER_TENANT, [], role_assignments, 123, "sub-1")

    run_calls = [c for c in tx.run.call_args_list if c.kwargs.get("role_assignments") is not None]
    # The attach_role + attach_external_principals passes carry principal_type now.
    prepared = run_calls[0].kwargs["role_assignments"][0]
    assert prepared["principal_type"] == "ServicePrincipal"
    assert prepared["role_id"] == "role-1"
    # An external-principal MERGE pass runs with the customer + Microsoft tenant ids.
    external_calls = [c for c in tx.run.call_args_list if "AzureExternalPrincipal" in c.args[0]]
    assert len(external_calls) == 1
    assert external_calls[0].kwargs["tenant_id"] == CUSTOMER_TENANT.lower()
    assert external_calls[0].kwargs["ms_tenant_id"] == iam.AZURE_MICROSOFT_TENANT_ID
