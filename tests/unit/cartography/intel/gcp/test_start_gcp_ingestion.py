from collections import Counter
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import cartography.intel.gcp

PROJECT_ID = 'proj-1'
GCP = 'cartography.intel.gcp'


def test_each_analysis_job_runs_once_per_sync():
    config = SimpleNamespace(
        update_tag=1, refresh_entitlements=False, gcp_requested_syncs=None,
        params={'workspace': {'id_string': 'ws-1', 'account_id': PROJECT_ID}},
        credentials={'token_uri': 'uri', 'account_email': 'sa@example.com'},
    )
    with patch(f'{GCP}.AuthHelper'), patch(f'{GCP}._initialize_resources'), \
            patch(f'{GCP}.crm.sync_gcp_organizations'), patch(f'{GCP}.crm.sync_gcp_folders'), \
            patch(f'{GCP}.crm.sync_gcp_projects'), \
            patch(f'{GCP}.crm.get_gcp_projects', return_value=[{'projectId': PROJECT_ID}]), \
            patch(f'{GCP}._sync_single_project'), patch(f'{GCP}.exposure_layers.run'), \
            patch('cartography.intel.post_sync.run_analysis_job') as run_analysis_job:
        cartography.intel.gcp.start_gcp_ingestion(None, config)

    runs = Counter(call.args[0] for call in run_analysis_job.call_args_list)
    assert {job: n for job, n in runs.items() if n > 1} == {}
    assert 'gcp_compute_instance_analysis.json' in runs
    assert 'gcp_gke_asset_exposure.json' in runs
    assert 'gcp_load_balancer_exposure.json' in runs


def _analysis_only(organization_id):
    """Run start_gcp_ingestion for services ["analysis"]; return (analysis job calls, API/sync mocks)."""
    config = SimpleNamespace(
        update_tag=2, refresh_entitlements=False, gcp_requested_syncs=[{'name': 'analysis'}],
        params={'workspace': {'id_string': 'ws-1', 'account_id': PROJECT_ID}},
        credentials={'token_uri': 'uri', 'account_email': 'sa@example.com'},
    )
    names = (
        '_initialize_resources', 'crm.sync_gcp_organizations', 'crm.sync_gcp_folders', 'crm.sync_gcp_projects',
        'crm.get_gcp_projects', '_sync_single_project', 'get_all_regions',
    )
    with ExitStack() as stack:
        stack.enter_context(patch(f'{GCP}.AuthHelper'))
        stack.enter_context(patch(f'{GCP}.exposure_layers.run'))
        stack.enter_context(patch(f'{GCP}.crm.read_project_organization_id', return_value=organization_id))
        api = {name: stack.enter_context(patch(f'{GCP}.{name}')) for name in names}
        run_analysis_job = stack.enter_context(patch('cartography.intel.post_sync.run_analysis_job'))
        cartography.intel.gcp.start_gcp_ingestion(None, config)
    return run_analysis_job.call_args_list, api


def test_analysis_only_calls_no_api_sync_or_cleanup():
    # A CRM or project sync here would clean up with this subrun's newer tag: a failed (empty) project list would
    # delete the project the resource subruns wrote before the exposure jobs run.
    calls, api = _analysis_only('organizations/1')

    assert {name for name, mock in api.items() if mock.called} == set()
    assert 'gcp_load_balancer_exposure.json' in {call.args[0] for call in calls}
    assert {call.args[2]['GCP_ORGANIZATION_ID'] for call in calls} == {'organizations/1'}


def test_analysis_only_skips_when_the_project_is_not_in_the_graph():
    calls, _ = _analysis_only(None)

    assert calls == []
