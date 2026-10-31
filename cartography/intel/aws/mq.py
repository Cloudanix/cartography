import logging
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from urllib.parse import urlsplit

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.util import aws_handle_regions
from cartography.util import log_aws_error
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()

# A broker console URL without an explicit port (RabbitMQ) is served on the HTTPS default.
HTTPS_PORT = 443


def _describe_broker(client: Any, broker_id: str) -> Optional[Dict]:
    """
    list_brokers has no PubliclyAccessible, security groups or endpoints; only describe_broker does.
    None when the describe call fails: the broker is still ingested from its summary.
    """
    try:
        return client.describe_broker(BrokerId=broker_id)
    except ClientError as e:
        log_aws_error(logger, f"Could not describe Amazon MQ broker {broker_id}", e)
        return None


@timeit
@aws_handle_regions
def get_mq_brokers(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    """
    One paginated list_brokers call, then one describe_broker per broker (no batch describe exists).
    Amazon MQ allows 50 brokers per region by default, so the per-broker call stays small.
    """
    client = boto3_session.client('mq', region_name=region, config=get_botocore_config())
    brokers: List[Dict] = []
    for page in client.get_paginator('list_brokers').paginate():
        for summary in page.get('BrokerSummaries', []):
            detail = _describe_broker(client, summary['BrokerId'])
            # The summary keys are a subset of describe_broker's, so the detail wins when present.
            brokers.append({**summary, **(detail or {}), 'described': detail is not None})
    return brokers


def _endpoint_ports(urls: List[str]) -> List[int]:
    ports = set()
    for url in urls:
        parts = urlsplit(url)
        if parts.port:
            ports.add(parts.port)
        elif parts.scheme == 'https':
            ports.add(HTTPS_PORT)
    return sorted(ports)


@timeit
def transform_mq_brokers(brokers: List[Dict], region: str) -> List[Dict]:
    transformed: List[Dict] = []
    for broker in brokers:
        instances = broker.get('BrokerInstances') or []
        endpoints = [endpoint for instance in instances for endpoint in instance.get('Endpoints') or []]
        console_urls = [instance['ConsoleURL'] for instance in instances if instance.get('ConsoleURL')]
        logs = broker.get('Logs') or {}
        encryption = broker.get('EncryptionOptions') or {}
        transformed.append({
            'BrokerArn': broker['BrokerArn'],
            'BrokerId': broker.get('BrokerId'),
            'BrokerName': broker.get('BrokerName'),
            'BrokerState': broker.get('BrokerState'),
            'EngineType': broker.get('EngineType'),
            'EngineVersion': broker.get('EngineVersion'),
            'DeploymentMode': broker.get('DeploymentMode'),
            'HostInstanceType': broker.get('HostInstanceType'),
            # None when describe_broker failed: unknown, not private.
            'PubliclyAccessible': broker.get('PubliclyAccessible') if broker['described'] else None,
            'AutoMinorVersionUpgrade': broker.get('AutoMinorVersionUpgrade'),
            'AuthenticationStrategy': broker.get('AuthenticationStrategy'),
            'StorageType': broker.get('StorageType'),
            'SecurityGroups': broker.get('SecurityGroups') or [],
            'SubnetIds': broker.get('SubnetIds') or [],
            'Endpoints': endpoints,
            'ConsoleUrls': console_urls,
            'IpAddresses': [instance['IpAddress'] for instance in instances if instance.get('IpAddress')],
            'Ports': _endpoint_ports(endpoints + console_urls),
            'AuditLog': logs.get('Audit'),
            'GeneralLog': logs.get('General'),
            'UseAwsOwnedKey': encryption.get('UseAwsOwnedKey'),
            'KmsKeyId': encryption.get('KmsKeyId'),
            'Created': str(broker['Created']) if broker.get('Created') else None,
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=broker['BrokerArn']),
        })
    return transformed


@timeit
def load_mq_brokers(
    neo4j_session: neo4j.Session, brokers: List[Dict], current_aws_account_id: str, update_tag: int,
) -> None:
    query = """
    UNWIND $DictList AS item
        MERGE (broker:AWSMQBroker{id: item.BrokerArn})
        ON CREATE SET broker.firstseen = timestamp(),
            broker.arn = item.BrokerArn
        SET broker.lastupdated = $aws_update_tag,
            broker.broker_id = item.BrokerId,
            broker.name = item.BrokerName,
            broker.state = item.BrokerState,
            broker.engine_type = item.EngineType,
            broker.engine_version = item.EngineVersion,
            broker.deployment_mode = item.DeploymentMode,
            broker.host_instance_type = item.HostInstanceType,
            broker.publicly_accessible = item.PubliclyAccessible,
            broker.auto_minor_version_upgrade = item.AutoMinorVersionUpgrade,
            broker.authentication_strategy = item.AuthenticationStrategy,
            broker.storage_type = item.StorageType,
            broker.security_groups = item.SecurityGroups,
            broker.subnet_ids = item.SubnetIds,
            broker.endpoints = item.Endpoints,
            broker.console_urls = item.ConsoleUrls,
            broker.ip_addresses = item.IpAddresses,
            broker.ports = item.Ports,
            broker.audit_log_enabled = item.AuditLog,
            broker.general_log_enabled = item.GeneralLog,
            broker.use_aws_owned_key = item.UseAwsOwnedKey,
            broker.kms_key_id = item.KmsKeyId,
            broker.created = item.Created,
            broker.region = item.region,
            broker.consolelink = item.consolelink
        WITH broker
        MATCH (owner:AWSAccount{id: $aws_account_id})
        MERGE (owner)-[r:RESOURCE]->(broker)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    logger.info(f"Loading {len(brokers)} Amazon MQ brokers into graph.")
    load_graph_data(
        neo4j_session, query, brokers, aws_update_tag=update_tag, aws_account_id=current_aws_account_id,
    )
    _attach_security_groups(neo4j_session, brokers, update_tag)
    _attach_subnets(neo4j_session, brokers, update_tag)


@timeit
def _attach_security_groups(neo4j_session: neo4j.Session, brokers: List[Dict], update_tag: int) -> None:
    # The group node may not be synced yet (services run in parallel); MERGE it like RDS and ElastiCache do.
    query = """
    UNWIND $DictList AS item
        MATCH (broker:AWSMQBroker{id: item.arn})
        MERGE (sg:EC2SecurityGroup{id: item.group_id})
        ON CREATE SET sg.firstseen = timestamp()
        MERGE (broker)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = [{'arn': b['BrokerArn'], 'group_id': group_id} for b in brokers for group_id in b['SecurityGroups']]
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag)


@timeit
def _attach_subnets(neo4j_session: neo4j.Session, brokers: List[Dict], update_tag: int) -> None:
    query = """
    UNWIND $DictList AS item
        MATCH (broker:AWSMQBroker{id: item.arn}), (subnet:EC2Subnet{subnetid: item.subnet_id})
        MERGE (broker)-[r:PART_OF_SUBNET]->(subnet)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = [{'arn': b['BrokerArn'], 'subnet_id': subnet_id} for b in brokers for subnet_id in b['SubnetIds']]
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag)


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_mq_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Amazon MQ for account '%s', at %s.", current_aws_account_id, tic)

    partition = get_partition_from_params(common_job_parameters)
    # botocore's bundled endpoint data lists the regions Amazon MQ runs in, without an API call.
    mq_regions = set(boto3_session.get_available_regions('mq', partition_name=partition))
    brokers: List[Dict] = []
    for region in regions:
        if region not in mq_regions:
            continue
        logger.info("Syncing Amazon MQ brokers for region '%s' in account '%s'.", region, current_aws_account_id)
        brokers.extend(transform_mq_brokers(get_mq_brokers(boto3_session, region), region))

    load_mq_brokers(neo4j_session, brokers, current_aws_account_id, update_tag)
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Amazon MQ: {toc - tic:0.4f} seconds")
