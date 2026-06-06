import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.models.aws.elasticbeanstalk.environments import ElasticBeanstalkEnvironmentSchema
from cartography.stats import get_stats_client
from cartography.util import aws_handle_regions
from cartography.util import merge_module_sync_metadata
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()
stat_handler = get_stats_client(__name__)

# Listener config the HTTPS compliance check cares about. We store the protocols as facts;
# the consumer decides compliance (keeps rule logic out of the sync).
_LISTENER_NAMESPACE_PREFIXES = ("aws:elbv2:listener", "aws:elb:listener")
_PROTOCOL_OPTION_NAMES = ("Protocol", "ListenerProtocol")


@timeit
@aws_handle_regions
def get_beanstalk_environments(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('elasticbeanstalk', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_environments')
    environments: List[Dict] = []
    for page in paginator.paginate():
        for environment in page.get('Environments', []):
            environment['ConfigurationSettings'] = _get_configuration_settings(client, environment)
            environments.append(environment)
    return environments


def _get_configuration_settings(client: Any, environment: Dict) -> List[Dict]:
    application_name = environment.get('ApplicationName')
    environment_name = environment.get('EnvironmentName')
    if not application_name or not environment_name:
        return []
    try:
        response = client.describe_configuration_settings(
            ApplicationName=application_name,
            EnvironmentName=environment_name,
        )
        return response.get('ConfigurationSettings', [])
    except client.exceptions.ClientError as e:
        logger.warning(
            "Unable to fetch configuration settings for beanstalk environment %s: %s",
            environment_name,
            e,
        )
        return []


def _listener_protocols(configuration_settings: List[Dict]) -> List[str]:
    protocols: List[str] = []
    for setting in configuration_settings:
        for option in setting.get('OptionSettings', []):
            namespace = option.get('Namespace', '')
            option_name = option.get('OptionName', '')
            value = option.get('Value')
            is_listener = namespace.startswith(_LISTENER_NAMESPACE_PREFIXES)
            if is_listener and option_name in _PROTOCOL_OPTION_NAMES and value:
                protocols.append(value)
    # de-dup while preserving order
    return list(dict.fromkeys(protocols))


@timeit
def transform_beanstalk_environments(environments: List[Dict], region: str) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for environment in environments:
        arn = environment.get('EnvironmentArn')
        if not arn:
            continue
        transformed.append({
            'Arn': arn,
            'EnvironmentName': environment.get('EnvironmentName'),
            'EnvironmentId': environment.get('EnvironmentId'),
            'ApplicationName': environment.get('ApplicationName'),
            'Status': environment.get('Status'),
            'Region': region,
            'consolelink': aws_console_link.get_console_link(arn=arn),
            'ListenerProtocols': _listener_protocols(environment.get('ConfigurationSettings', [])),
        })
    return transformed


@timeit
def load_beanstalk_environments(
    neo4j_session: neo4j.Session, data: List[Dict[str, Any]], region: str, current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    logger.info(f"Loading Elastic Beanstalk environments {len(data)} for region '{region}' into graph.")
    load(
        neo4j_session,
        ElasticBeanstalkEnvironmentSchema(),
        data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def cleanup_beanstalk_environments(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    GraphJob.from_node_schema(ElasticBeanstalkEnvironmentSchema(), common_job_parameters).run(neo4j_session)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Elastic Beanstalk for account '%s', at %s.", current_aws_account_id, tic)

    for region in regions:
        logger.info("Syncing Elastic Beanstalk for region '%s' in account '%s'.", region, current_aws_account_id)
        environments = get_beanstalk_environments(boto3_session, region)
        data = transform_beanstalk_environments(environments, region)
        load_beanstalk_environments(neo4j_session, data, region, current_aws_account_id, update_tag)

    cleanup_beanstalk_environments(neo4j_session, common_job_parameters)
    merge_module_sync_metadata(
        neo4j_session,
        group_type='AWSAccount',
        group_id=current_aws_account_id,
        synced_type='ElasticBeanstalkEnvironment',
        update_tag=update_tag,
        stat_handler=stat_handler,
    )

    toc = time.perf_counter()
    logger.info(f"Time to process Elastic Beanstalk: {toc - tic:0.4f} seconds")
