from collections import Counter
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
            patch(f'{GCP}._sync_single_project'), patch(f'{GCP}.run_analysis_job') as run_analysis_job:
        cartography.intel.gcp.start_gcp_ingestion(None, config)

    runs = Counter(call.args[0] for call in run_analysis_job.call_args_list)
    assert {job: n for job, n in runs.items() if n > 1} == {}
    assert 'gcp_compute_instance_analysis.json' in runs
    assert 'gcp_gke_asset_exposure.json' in runs
