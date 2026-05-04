from typing import Dict

from . import (
    aks,
    compute,
    containerregistry,
    cosmosdb,
    function_app,
    iam,
    key_vaults,
    monitor,
    network,
    securitycenter,
    sql,
    storage,
)

RESOURCE_FUNCTIONS: Dict = {
    "iam": iam.sync,
    "network": network.sync,
    "aks": aks.sync,
    "images": containerregistry.sync,
    "cosmosdb": cosmosdb.sync,
    "function_app": function_app.sync,
    "key_vaults": key_vaults.sync,
    "compute": compute.sync,
    "sql": sql.sync,
    "storage": storage.sync,
    "monitor": monitor.sync,
    "securitycenter": securitycenter.sync,
}
