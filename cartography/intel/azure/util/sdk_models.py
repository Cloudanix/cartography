from typing import Any
from typing import Dict

from azure.core.serialization import as_attribute_dict


def as_legacy_dict(model: Any) -> Dict[str, Any]:
    """
    Convert an Azure SDK model to the dict shape the Azure ingestion code reads.

    The ingestion code was written against msrest models, whose as_dict() returns
    snake_case attribute names with ARM's `properties` envelope flattened
    (rule['protocol'], account['network_rule_set']['default_action']). The
    TypeSpec-generated SDK releases (network, storage, keyvault, compute, web,
    cosmosdb, containerservice, ...) return the raw REST payload from as_dict()
    instead ({'properties': {'networkAcls': {'defaultAction': ...}}}), so every
    flattened read silently came back None. azure-core's as_attribute_dict gives
    the legacy shape for both model generations.

    :param model: an Azure SDK model instance (msrest or TypeSpec generated).
    :return: dict keyed by the model's Python attribute names.
    :raises TypeError: if model is not a generated SDK model.
    """
    return as_attribute_dict(model)
