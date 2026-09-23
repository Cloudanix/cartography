import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from cartography.util import is_aws_access_denied
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_ec2_regions(boto3_session: boto3.session.Session, account_id: str) -> List[str]:
    try:
        client = boto3_session.client('ec2')
        result = client.describe_regions()
        return [r['RegionName'] for r in result['Regions']]

    except ClientError as e:
        if is_aws_access_denied(e):
            # Customer IAM/SCP blocks DescribeRegions; expected, so keep it out of Sentry.
            logger.info('DescribeRegions denied for account %s: %s', account_id, e)

        else:
            logger.error(
                ("Failed to retrieve AWS region list, an error occurred: %s. Could not get regions for account %s."),
                e,
                account_id,
            )

    return []
