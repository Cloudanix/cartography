import logging
from typing import Dict
from typing import Optional

import boto3
from botocore.exceptions import UnknownRegionError

logger = logging.getLogger(__name__)

DEFAULT_PARTITION = 'aws'
# common_job_parameters key holding the partition of the account being synced.
PARTITION_PARAM = 'AWS_PARTITION'


def get_partition(boto3_session: boto3.session.Session, region: Optional[str]) -> str:
    """
    Return the AWS partition ('aws', 'aws-cn', 'aws-us-gov', ...) that `region` belongs to,
    from botocore's bundled endpoint data (no API call). An account lives in exactly one
    partition, so any of its regions identifies it. Falls back to 'aws' when the region is
    missing or unknown to botocore.
    """
    if not region:
        return DEFAULT_PARTITION
    try:
        return boto3_session.get_partition_for_region(region)
    except UnknownRegionError:
        logger.warning(f"Unknown region {region}; defaulting ARN partition to {DEFAULT_PARTITION}")
        return DEFAULT_PARTITION


def get_partition_from_params(common_job_parameters: Dict) -> str:
    """Partition set for this sync by start_aws_ingestion; 'aws' when absent (e.g. tests)."""
    return common_job_parameters.get(PARTITION_PARAM) or DEFAULT_PARTITION


def build_arn(
        resource: str,
        account: str,
        typename: str,
        name: str,
        region: Optional[str] = None,
        partition: Optional[str] = None,
) -> str:
    if not partition:
        partition = DEFAULT_PARTITION
    if not region:
        # Some resources are present in all regions, e.g. IAM policies
        region = ""
    return f"arn:{partition}:{resource}:{region}:{account}:{typename}/{name}"
