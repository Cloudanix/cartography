from unittest.mock import MagicMock
from unittest.mock import patch

from googleapiclient.errors import HttpError

import cartography.intel.gcp
from cartography.intel.gcp import loadbalancer

API = 'https://www.googleapis.com/compute/v1'
PARAMS = {'UPDATE_TAG': 42, 'GCP_PROJECT_ID': 'p1', 'WORKSPACE_ID': 'ws', 'GCP_ORGANIZATION_ID': 'org'}


def _sync_members(groups, client):
    """Run the post-sync step with the given external backend groups; return what it loaded."""
    with patch.object(loadbalancer, 'get_external_backend_groups', return_value=groups), \
            patch.object(loadbalancer, 'load_instance_group_members') as load, \
            patch.object(loadbalancer, 'run_cleanup_job') as cleanup:
        loadbalancer.sync_external_backend_members(MagicMock(), client, 'p1', PARAMS)
    cleanup.assert_called_once()
    return load.call_args.args[1]


def test_members_are_listed_only_for_zonal_instance_groups_of_this_project():
    client = MagicMock()
    igs = client.instanceGroups.return_value
    page_1 = {'items': [{'instance': f'{API}/projects/p1/zones/us-east1-b/instances/node-1'}]}
    page_2 = {'items': [{'instance': f'{API}/projects/p1/zones/us-east1-b/instances/node-2'}, {'status': 'RUNNING'}]}
    igs.listInstances.return_value.execute.side_effect = [page_1, page_2]
    igs.listInstances_next.side_effect = [igs.listInstances.return_value, None]

    members = _sync_members(
        [
            'projects/p1/zones/us-east1-b/instanceGroups/k8s-ig--abc',
            # Regional groups are always managed (PART_OF); NEGs and other projects' groups are not listed here.
            'projects/p1/regions/us-east1/instanceGroups/regional-mig',
            'projects/p1/zones/us-east1-b/networkEndpointGroups/neg',
            'projects/other/zones/us-east1-b/instanceGroups/foreign',
        ],
        client,
    )

    igs.listInstances.assert_called_once_with(
        project='p1', zone='us-east1-b', instanceGroup='k8s-ig--abc', body={'instanceState': 'ALL'},
    )
    group = 'projects/p1/zones/us-east1-b/instanceGroups/k8s-ig--abc'
    assert members == [
        {'group': group, 'instance': 'projects/p1/zones/us-east1-b/instances/node-1'},
        {'group': group, 'instance': 'projects/p1/zones/us-east1-b/instances/node-2'},
    ]


def test_unreadable_instance_group_leaves_its_members_unresolved():
    client = MagicMock()
    client.instanceGroups.return_value.listInstances.return_value.execute.side_effect = HttpError(
        MagicMock(status=403), b'{"error": {"code": 403}}',
    )

    members = _sync_members(['projects/p1/zones/us-east1-b/instanceGroups/denied'], client)

    assert members == []


def test_no_external_backend_groups_means_no_api_calls():
    client = MagicMock()

    assert _sync_members([], client) == []
    client.instanceGroups.assert_not_called()


def _sync_project(requested):
    """Run _sync_single_project sequentially with stub services; return the call order."""
    order = []
    services = {
        name: (lambda name: lambda *_: order.append(name))(name) for name in ('compute', 'cloudcdn', 'loadbalancer')
    }
    with patch.dict('os.environ', {'LOCAL_RUN': '1'}), \
            patch.object(cartography.intel.gcp, 'RESOURCE_FUNCTIONS', services), \
            patch.object(cartography.intel.gcp, 'get_all_regions', return_value=['us-central1']), \
            patch.object(cartography.intel.gcp.compute, 'sync_gke_node_links'), \
            patch.object(
                cartography.intel.gcp.loadbalancer, 'sync_external_backend_members',
                side_effect=lambda *_: order.append('members'),
            ):
        config = MagicMock()
        config.params = {}
        cartography.intel.gcp._sync_single_project(
            neo4j_session=MagicMock(),
            resources=MagicMock(),
            requested_syncs=requested,
            project_id='p1',
            gcp_update_tag=42,
            common_job_parameters={**PARAMS, 'service_labels': []},
            config=config,
        )
    return order


def test_project_sync_resolves_backend_members_after_the_parallel_syncs():
    order = _sync_project(['loadbalancer', 'cloudcdn', 'compute'])

    assert order[-1] == 'members'


def test_project_sync_skips_backend_members_without_load_balancer_syncs():
    assert 'members' not in _sync_project(['compute'])
