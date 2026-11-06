from typing import List

from cartography.intel.oci.resources import RESOURCE_FUNCTIONS
from cartography.intel.post_sync import POST_SYNC_SYNCS


def parse_and_validate_oci_requested_syncs(oci_requested_syncs: str) -> List[str]:
    validated_resources: List[str] = []
    for resource in oci_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS or resource in POST_SYNC_SYNCS:
            validated_resources.append(resource)
    return validated_resources
