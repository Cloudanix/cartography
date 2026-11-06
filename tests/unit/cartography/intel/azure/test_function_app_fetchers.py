"""
Web app fetchers fed real SDK models: hostNamesDisabled and the config's
publicNetworkAccess must reflect the site, not the hard-coded defaults.
"""
from unittest.mock import MagicMock

from azure.core.exceptions import HttpResponseError
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
    client.web_apps.get_configuration.return_value = models.SiteConfigResource({'properties': {}})
    client.web_apps.get_auth_settings_v2_without_secrets.return_value = models.SiteAuthSettingsV2({'properties': {}})

    [site] = function_app.get_function_apps_list(client, None, PARAMS)
    [conf] = function_app.get_function_apps_configuration_list([site], client, PARAMS)

    assert site['hostNamesDisabled'] is False
    assert site['default_host_name'] == 'app.azurewebsites.net'
    assert conf['publicNetworkAccess'] == 'Enabled'
    assert conf['function_app_id'] == SITE_ID


def _site(name, **properties):
    return models.Site({
        'id': f'/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.Web/sites/{name}', 'name': name,
        'location': 'East US', 'properties': properties,
    })


def _config(default_action=None, *rules):
    properties = {'ipSecurityRestrictions': list(rules)}
    if default_action:
        properties['ipSecurityRestrictionsDefaultAction'] = default_action
    return models.SiteConfigResource({'properties': properties})


def _rule(ip, action='Allow', tag='Default'):
    return {'ipAddress': ip, 'action': action, 'tag': tag, 'priority': 100, 'name': ip}


def test_site_access_restrictions_arrive():
    client = MagicMock()
    client.web_apps.list.return_value = [
        _site('locked', publicNetworkAccess='Enabled'),
        _site('allow-any'),
        _site('internet-tag'),
        _site('front-door'),
        _site('deny-any'),
        _site('no-config'),
    ]
    configs = {
        'locked': _config('Deny', _rule('52.1.2.3/32')),
        'allow-any': _config('Deny', _rule('Any')),
        'internet-tag': _config('Deny', _rule('Internet', tag='ServiceTag')),
        'front-door': _config('Deny', _rule('AzureFrontDoor.Backend', tag='ServiceTag')),
        'deny-any': _config('Allow', _rule('0.0.0.0/0', action='Deny')),
    }

    def get_configuration(resource_group, name):
        if name not in configs:
            raise HttpResponseError('forbidden')
        return configs[name]

    client.web_apps.get_configuration.side_effect = get_configuration
    client.web_apps.get_auth_settings_v2_without_secrets.return_value = models.SiteAuthSettingsV2({'properties': {}})

    sites = {s['name']: s for s in function_app.get_function_apps_list(client, None, PARAMS)}

    assert {
        name: (s['publicNetworkAccess'], s['ipSecurityRestrictionsDefaultAction'], s['openAccessRestriction'])
        for name, s in sites.items()
    } == {
        'locked': ('Enabled', 'Deny', False),
        'allow-any': (None, 'Deny', True),
        'internet-tag': (None, 'Deny', True),
        # Front Door is internet-facing, so a site that admits it is reachable from the internet.
        'front-door': (None, 'Deny', True),
        'deny-any': (None, 'Allow', False),
        # A failed config read leaves the restriction unknown, which the exposure job treats as open.
        'no-config': (None, None, None),
    }
    # Unknown, not assumed disabled.
    assert sites['no-config']['hostNamesDisabled'] is None


def _auth(enabled, action=None, require=True, excluded=None):
    validation = {'requireAuthentication': require, 'unauthenticatedClientAction': action}
    if excluded:
        validation['excludedPaths'] = excluded
    return models.SiteAuthSettingsV2({'properties': {'platform': {'enabled': enabled}, 'globalValidation': validation}})


def test_easy_auth_settings_arrive():
    client = MagicMock()
    client.web_apps.list.return_value = [
        _site(name) for name in ('on', 'anonymous', 'not-required', 'excluded', 'off', 'unreadable')
    ]
    client.web_apps.get_configuration.return_value = _config()
    settings = {
        'on': _auth(True, 'Return401'),
        'anonymous': _auth(True, 'AllowAnonymous'),
        'not-required': _auth(True, 'Return401', require=False),
        'excluded': _auth(True, 'RedirectToLoginPage', excluded=['/health']),
        'off': _auth(False, 'Return401'),
    }

    def get_auth(resource_group, name):
        if name not in settings:
            raise HttpResponseError('forbidden')
        return settings[name]

    client.web_apps.get_auth_settings_v2_without_secrets.side_effect = get_auth

    sites = {s['name']: s for s in function_app.get_function_apps_list(client, None, PARAMS)}

    assert {name: (s['auth_enabled'], s['unauthenticated_client_action']) for name, s in sites.items()} == {
        'on': (True, 'Return401'),
        'anonymous': (True, 'AllowAnonymous'),
        'not-required': (True, 'AllowAnonymous'),
        'excluded': (True, 'AllowAnonymous'),
        'off': (False, 'Return401'),
        'unreadable': (None, None),
    }
    # The secrets-returning /list variant needs list/Action, which Reader lacks.
    client.web_apps.get_auth_settings_v2.assert_not_called()
