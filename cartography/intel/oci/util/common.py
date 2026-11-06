import logging
from typing import List

from cartography.intel.exposure.step import EXPOSURE_LAYERS_SYNC
from cartography.intel.oci.resources import RESOURCE_FUNCTIONS

logger = logging.getLogger(__name__)


def parse_and_validate_oci_requested_syncs(oci_requested_syncs: str) -> List[str]:
    """
    Keep the requested OCI sync names this build knows, in request order.

    cloudanix-web sends its configured service list, which can name a sync cartography does not have (a typo, or
    a web config shipped before the cartography deploy). Such a name is skipped rather than failing the whole OCI
    sync, but with a warning: a silently dropped name means that data never syncs.
    """
    requested = [resource.strip() for resource in oci_requested_syncs.split(',')]
    known = [resource for resource in requested if resource in RESOURCE_FUNCTIONS or resource == EXPOSURE_LAYERS_SYNC]
    unknown = [resource for resource in requested if resource and resource not in known]
    if unknown:
        logger.warning(f"Skipping OCI syncs this cartography build does not have: {unknown}")
    return known
