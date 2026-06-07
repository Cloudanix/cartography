import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_acm_certificates(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    certs: List[Dict] = []
    try:
        client = boto3_session.client('acm', region_name=region, config=get_botocore_config())
        paginator = client.get_paginator('list_certificates')
        summaries = []
        for page in paginator.paginate():
            summaries.extend(page.get('CertificateSummaryList', []))
        for summary in summaries:
            try:
                detail = client.describe_certificate(
                    CertificateArn=summary['CertificateArn'],
                )['Certificate']
                certs.append(detail)
            except ClientError as e:
                logger.warning(f"Failed to describe ACM cert {summary.get('CertificateArn')} - {e}")
    except ClientError as e:
        logger.warning(f"Failed to call ACM list_certificates: {region} - {e}")
    return certs


@timeit
def transform_acm_certificates(certs: List[Dict], region: str) -> List[Dict]:
    transformed = []
    for cert in certs:
        transformed.append({
            'arn': cert.get('CertificateArn'),
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=cert.get('CertificateArn', '')),
            'domain_name': cert.get('DomainName'),
            'status': cert.get('Status'),
            'type': cert.get('Type'),
            'renewal_eligibility': cert.get('RenewalEligibility'),
            'key_algorithm': cert.get('KeyAlgorithm'),
            'not_after': str(cert.get('NotAfter')) if cert.get('NotAfter') else None,
            'not_before': str(cert.get('NotBefore')) if cert.get('NotBefore') else None,
            'in_use_by': cert.get('InUseBy', []),
        })
    return transformed


@timeit
def load_acm_certificates(
    neo4j_session: neo4j.Session, certs: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Certs as cert
    MERGE (n:ACMCertificate{id: cert.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = cert.arn
    SET n.lastupdated = $aws_update_tag,
        n.region = cert.region,
        n.consolelink = cert.consolelink,
        n.domain_name = cert.domain_name,
        n.status = cert.status,
        n.type = cert.type,
        n.renewal_eligibility = cert.renewal_eligibility,
        n.key_algorithm = cert.key_algorithm,
        n.not_after = cert.not_after,
        n.not_before = cert.not_before,
        n.in_use_by = cert.in_use_by
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    neo4j_session.run(
        query, Certs=certs, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing ACM for account '%s'.", current_aws_account_id)
    certs: List[Dict] = []
    for region in regions:
        certs.extend(transform_acm_certificates(get_acm_certificates(boto3_session, region), region))
    load_acm_certificates(neo4j_session, certs, current_aws_account_id, update_tag)
    toc = time.perf_counter()
    logger.info(f"Time to process ACM: {toc - tic:0.4f} seconds")
