import logging
from typing import List

import boto3
from botocore.exceptions import ClientError

from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_ec2_regions(boto3_session: boto3.session.Session, account_id: str) -> List[str]:
    try:
        client = boto3_session.client('ec2')
        result = client.describe_regions()
        return [r['RegionName'] for r in result['Regions']]

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_message = e.response.get('Error', {}).get('Message', '')

        if error_code == "UnauthorizedOperation" or 'with an explicit deny in a service control policy' in error_message:
            # INFO: This means, permission is restricted at SCP level. We can't fetch the regions.
            logger.debug('UnauthorizedOperation - Failed to fetch ec2 regions', extra={"error": str(e)})

        else:
            logger.error(
                ("Failed to retrieve AWS region list, an error occurred: %s. Could not get regions for account %s."),
                e,
                account_id,
            )

    return []
