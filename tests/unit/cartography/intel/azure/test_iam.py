import asyncio
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
