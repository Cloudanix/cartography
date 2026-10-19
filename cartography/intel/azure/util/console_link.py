import logging
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import Optional

from cloudconsolelink.clouds.azure import AzureLinker

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


def safe_console_link(resource_id: Optional[str], common_job_parameters: Dict, **link_params: str) -> Optional[str]:
    """
    Build the Azure portal link for an ARM resource id (or Key Vault data-plane URI), or for an Entra ID
    entity when link_params carries iam_entity_type.

    :param resource_id: ARM id, e.g. /subscriptions/<sub>/resourceGroups/<rg>/providers/<ns>/<type>/<name>,
        or the Graph object id / tenant id / domain name of an Entra ID entity
    :param common_job_parameters: must carry Azure_Primary_AD_Domain_Name (not needed for Entra ID entities)
    :param link_params: extra AzureLinker arguments, e.g. iam_entity_type="user", app_id="..."
    :return: the portal link, or None when the id or tenant domain is missing. AzureLinker raises
        ValueError in that case; one unlinkable resource must not abort the whole module sync.
        Loaders write it as coalesce(item.consolelink, n.consolelink), so None keeps the link a
        previous sync stored instead of blanking it.
    """
    domain = common_job_parameters.get('Azure_Primary_AD_Domain_Name', '')
    try:
        return azure_console_link.get_console_link(id=resource_id, primary_ad_domain_name=domain, **link_params)
    except ValueError as e:
        if not domain and not link_params.get('iam_entity_type'):
            _warn_missing_tenant_domain(common_job_parameters.get('UPDATE_TAG'))
        logger.debug("Could not generate console link for %s: %s", resource_id, e)
        return None


@lru_cache(maxsize=1)
def _warn_missing_tenant_domain(update_tag: Any) -> None:
    # Cached on the update tag: one warning per sync instead of one per ARM id.
    logger.warning("Azure_Primary_AD_Domain_Name is missing; Azure console links keep their previous value this sync")
