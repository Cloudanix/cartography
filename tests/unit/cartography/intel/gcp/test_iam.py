from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.gcp import iam


@patch.object(iam, 'run_write_query')
def test_load_bindings_deleted_members_have_consolelink(mock_run_write_query):
    # Deleted members (deleted:group:..., deleted:user:..., deleted:domain:...) used to omit
    # "consolelink", making the attach_* helpers raise KeyError.
    # The attach_* writes go through run_write_query (managed tx + retry), so the query
    # parameters are asserted there rather than on a raw session.run.
    neo4j_session = MagicMock()
    bindings = [{
        'role': 'projects/p1/roles/custom1',
        'parent': 'project',
        'parent_id': 'p1',
        'members': [
            'deleted:group:grp@example.org?uid=123',
            'deleted:user:usr@example.org?uid=456',
            'deleted:domain:example.org?uid=789',
        ],
    }]

    iam.load_bindings(neo4j_session, bindings, 'p1', 'organizations/1', 12345, {})

    consolelinks = [call.kwargs['ConsoleLink'] for call in mock_run_write_query.call_args_list]
    assert len(consolelinks) == 3
    assert all(link for link in consolelinks)


def test_gcp_service_account_managed_type():
    # Google default service accounts and service agents are provider-managed.
    assert iam._gcp_service_account_managed_type("project@appspot.gserviceaccount.com") == "predefined"
    assert iam._gcp_service_account_managed_type("123-compute@developer.gserviceaccount.com") == "predefined"
    assert iam._gcp_service_account_managed_type("123@cloudservices.gserviceaccount.com") == "predefined"
    assert iam._gcp_service_account_managed_type(
        "service-123@gcp-sa-pubsub.iam.gserviceaccount.com",
    ) == "predefined"
    # Customer-created service accounts live under "<project>.iam.gserviceaccount.com".
    assert iam._gcp_service_account_managed_type("my-sa@my-project.iam.gserviceaccount.com") == "custom"
    assert iam._gcp_service_account_managed_type("") == "custom"
    assert iam._gcp_service_account_managed_type(None) == "custom"


def test_gcp_key_managed_type():
    assert iam._gcp_key_managed_type("SYSTEM_MANAGED") == "predefined"
    assert iam._gcp_key_managed_type("USER_MANAGED") == "custom"
    assert iam._gcp_key_managed_type(None) == "custom"


def test_transform_roles_sets_managed_type():
    common_job_parameters = {"GCP_ORGANIZATION_ID": "organizations/123"}
    predefined = iam.transform_roles(
        [{"name": "roles/viewer", "title": "Viewer"}], "project123", "predefined", common_job_parameters,
    )
    assert predefined[0]["managed_type"] == "predefined"
    assert predefined[0]["type"] == "predefined"

    custom = iam.transform_roles(
        [{"name": "projects/project123/roles/myrole", "title": "My Role"}], "project123", "custom", common_job_parameters,
    )
    assert custom[0]["managed_type"] == "custom"


def test_transform_service_accounts_sets_managed_type():
    accounts = [
        {
            "name": "projects/p/serviceAccounts/p@appspot.gserviceaccount.com",
            "email": "p@appspot.gserviceaccount.com",
            "uniqueId": "1",
        },
        {
            "name": "projects/p/serviceAccounts/my-sa@p.iam.gserviceaccount.com",
            "email": "my-sa@p.iam.gserviceaccount.com",
            "uniqueId": "2",
        },
    ]
    result = iam.transform_service_accounts(accounts, "p")
    assert result[0]["managed_type"] == "predefined"
    assert result[1]["managed_type"] == "custom"


def test_transform_api_keys_sets_custom():
    keys = [{"uid": "abc", "name": "projects/p/locations/global/keys/abc"}]
    result = iam.transform_api_keys(keys, "p")
    assert result[0]["managed_type"] == "custom"
