"""
Web app fetchers fed real SDK models: hostNamesDisabled and the config's
publicNetworkAccess must reflect the site, not the hard-coded defaults.
"""
from unittest.mock import MagicMock

from azure.mgmt.web import models

from cartography.intel.azure import function_app

PARAMS = {'UPDATE_TAG': 1}
SITE_ID = '/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.Web/sites/app'


def test_site_and_config_network_fields_arrive():
    client = MagicMock()
    client.web_apps.list.return_value = [
        models.Site({
            'id': SITE_ID, 'name': 'app', 'location': 'East US', 'kind': 'functionapp',
            'properties': {'hostNamesDisabled': False, 'defaultHostName': 'app.azurewebsites.net'},
        }),
    ]
    client.web_apps.list_configurations.return_value = [
        models.SiteConfigResource({'id': f'{SITE_ID}/config/web', 'properties': {'publicNetworkAccess': 'Enabled'}}),
    ]

    [site] = function_app.get_function_apps_list(client, None, PARAMS)
    [conf] = function_app.get_function_apps_configuration_list([site], client, PARAMS)

    assert site['hostNamesDisabled'] is False
    assert site['default_host_name'] == 'app.azurewebsites.net'
    assert conf['publicNetworkAccess'] == 'Enabled'
    assert conf['function_app_id'] == SITE_ID
