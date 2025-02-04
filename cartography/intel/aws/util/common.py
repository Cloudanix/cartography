import logging
from typing import List

from cartography.intel.aws.resources import RESOURCE_FUNCTIONS

logger = logging.getLogger(__name__)


def parse_and_validate_aws_requested_syncs(aws_requested_syncs: str) -> List[str]:
    validated_resources: List[str] = []
    for resource in aws_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS:
            validated_resources.append(resource)
        else:
            valid_syncs: str = ', '.join(RESOURCE_FUNCTIONS.keys())
            raise ValueError(
                f'Error parsing `aws-requested-syncs`. You specified "{aws_requested_syncs}". '
                f'Please check that your string is formatted properly. '
                f'Example valid input looks like "s3,iam,rds" or "s3, ec2:instance, dynamodb". '
                f'Our full list of valid values is: {valid_syncs}.',
            )
    return validated_resources


# def get_default_vpc(ec2_client):
#     try:
#         response = ec2_client.describe_vpcs(
#             Filters=[{'Name': 'isDefault', 'Values': ['true']}],
#         )
#         vpcs = response.get('Vpcs', [])

#         if not vpcs:
#             logger.info("No default VPC found.")
#             return {}

#         return vpcs[0]

#     except Exception as e:
#         logger.error(f"Error fetching default VPC: {e}")
#         return {}
