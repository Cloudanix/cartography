import logging
from typing import Dict
from typing import Optional

from cloudconsolelink.clouds.azure import AzureLinker

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


def safe_console_link(resource_id: Optional[str], common_job_parameters: Dict) -> str:
    """
    Build the Azure portal link for an ARM resource id (or Key Vault data-plane URI).

    :param resource_id: ARM id, e.g. /subscriptions/<sub>/resourceGroups/<rg>/providers/<ns>/<type>/<name>
    :param common_job_parameters: must carry Azure_Primary_AD_Domain_Name
    :return: the portal link, or '' when the id or tenant domain is missing. AzureLinker raises
        ValueError in that case; one unlinkable resource must not abort the whole module sync.
    """
    try:
        return azure_console_link.get_console_link(
            id=resource_id,
            primary_ad_domain_name=common_job_parameters.get('Azure_Primary_AD_Domain_Name', ''),
        )
    except ValueError as e:
        logger.warning("Could not generate console link for %s: %s", resource_id, e)
        return ''
