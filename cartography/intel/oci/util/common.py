from typing import List

from cartography.intel.oci.resources import RESOURCE_FUNCTIONS
from cartography.intel.post_sync import ANALYSIS_SYNC


def parse_and_validate_oci_requested_syncs(oci_requested_syncs: str) -> List[str]:
    validated_resources: List[str] = []
    for resource in oci_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS or resource == ANALYSIS_SYNC:
            validated_resources.append(resource)
    return validated_resources
