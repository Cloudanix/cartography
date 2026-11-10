import logging
from typing import List

from cartography.intel.oci.resources import RESOURCE_FUNCTIONS
from cartography.intel.post_sync import ANALYSIS_SYNC


def parse_and_validate_oci_requested_syncs(oci_requested_syncs: str) -> List[str]:
    """
    Keep the requested OCI sync names this build knows, in request order.

    cloudanix-web sends its configured service list, which can name a sync cartography does not have (a typo, or
    a web config shipped before the cartography deploy). Such a name is skipped rather than failing the whole OCI
    sync, but with a warning: a silently dropped name means that data never syncs.
    """
    validated_resources: List[str] = []
    unknown: List[str] = []
    for resource in oci_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS or resource == ANALYSIS_SYNC:
            validated_resources.append(resource)
        elif resource:
            unknown.append(resource)
    if unknown:
        logging.getLogger(__name__).warning(f"Skipping OCI syncs this cartography build does not have: {unknown}")
    return validated_resources
