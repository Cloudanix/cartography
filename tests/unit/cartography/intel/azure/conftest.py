"""
Mock unavailable third-party dependencies so azure unit tests can run
without the full production install (cloudconsolelink, adal, msrestazure,
azure-mgmt-*, msgraph, etc.).
"""
import importlib.util
import sys
from unittest.mock import MagicMock

# Pure-python with no deps: use the real linker when installed so tests see actual link output.
_OPTIONAL_REAL_DEPS = [
    "cloudconsolelink",
    "cloudconsolelink.clouds",
    "cloudconsolelink.clouds.azure",
]

_MISSING_DEPS = [
    *(m for m in _OPTIONAL_REAL_DEPS if importlib.util.find_spec("cloudconsolelink") is None),
    "adal",
    "msrestazure",
    "msrestazure.azure_active_directory",
    "azure.common",
    "azure.common.credentials",
    "azure.containerregistry",
    "azure.mgmt.containerinstance",
    "azure.mgmt.containerregistry",
    "azure.mgmt.network",
    "azure.mgmt.storage",
    "azure.mgmt.sql",
    "azure.mgmt.cosmosdb",
    "azure.mgmt.keyvault",
    "azure.mgmt.monitor",
    "azure.mgmt.authorization",
    "azure.mgmt.subscription",
    "azure.mgmt.web",
    "azure.mgmt.containerservice",
    "azure.mgmt.compute",
    "azure.mgmt.security",
    "azure.mgmt.msi",
    "azure.graphrbac",
    "azure.keyvault",
    "azure.keyvault.certificates",
    "azure.mgmt.rdbms",
    "azure.mgmt.rdbms.mysql",
    "azure.mgmt.rdbms.mysql_flexibleservers",
    "azure.mgmt.rdbms.postgresql",
    "azure.mgmt.rdbms.postgresql_flexibleservers",
    "azure.mgmt.redis",
    "azure.mgmt.sql.models",
    "msrestazure.azure_exceptions",
    "netaddr",
    "msgraph",
    "msgraph.generated",
    "msgraph.generated.users",
    "msgraph.generated.users.users_request_builder",
    "msgraph.generated.groups",
    "msgraph.generated.groups.groups_request_builder",
]


def _installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# Real SDKs when installed, so tests can build actual SDK models (their as_dict
# shape changed in the TypeSpec-generated releases and the fetchers depend on it).
for _mod in _MISSING_DEPS:
    if _mod not in sys.modules and not _installed(_mod):
        sys.modules[_mod] = MagicMock()
