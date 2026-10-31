"""
AKS cluster fetcher fed a real SDK model: publicNetworkAccess and the node
resource group (used to link node VMs to the cluster) must arrive.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from azure.mgmt.containerservice import models

from cartography.intel.azure import aks

PARAMS = {'UPDATE_TAG': 1}
CLUSTER_ID = '/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1'


def test_managed_cluster_fields_arrive():
    client = MagicMock()
    client.managed_clusters.list.return_value = [
        models.ManagedCluster({
            'id': CLUSTER_ID, 'name': 'c1', 'location': 'eastus',
            'properties': {'publicNetworkAccess': 'Enabled', 'nodeResourceGroup': 'MC_rg_c1_eastus'},
        }),
    ]

    with patch.object(aks, 'get_client', return_value=client):
        [cluster] = aks.get_aks_managed_clusters_list(MagicMock(), '00-00', None, PARAMS)

    assert cluster['publicNetworkAccess'] == 'Enabled'
    assert cluster['node_resource_group'] == 'MC_rg_c1_eastus'
    assert cluster['resource_group'] == 'rg'
