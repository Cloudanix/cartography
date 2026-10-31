import logging
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import boto3
import neo4j
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.client.core.tx import run_write_query
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import log_aws_error
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()

# Listener protocols are stored as facts for the HTTPS check (beanstalk_https_enabled); the consumer decides.
_LISTENER_NAMESPACE_PREFIXES = ('aws:elbv2:listener', 'aws:elb:listener')
_PROTOCOL_OPTION_NAMES = ('Protocol', 'ListenerProtocol')
_ENVIRONMENT_NAMESPACE = 'aws:elasticbeanstalk:environment'
_SKIPPED_STATUSES = ('Terminated',)


@timeit
@aws_handle_regions
def get_environments(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    """
    Live environments of a region with their resources and configuration settings attached.

    API calls: describe_environments (paginated, one call per 100 environments) plus two per environment,
    describe_environment_resources (its load balancers and instances) and describe_configuration_settings
    (listener protocols). No sleeps. Regions without Elastic Beanstalk (EndpointConnectionError) are skipped;
    denials by aws_handle_regions; any other list error fails the module before cleanup.
    """
    client = boto3_session.client('elasticbeanstalk', region_name=region, config=get_botocore_config())
    environments: List[Dict] = []
    try:
        for page in client.get_paginator('describe_environments').paginate(IncludeDeleted=False):
            environments.extend(e for e in page.get('Environments', []) if e.get('Status') not in _SKIPPED_STATUSES)
    except EndpointConnectionError:
        logger.warning(f"Elastic Beanstalk is not available in region {region}. Skipping.")
        return []
    for environment in environments:
        environment['EnvironmentResources'] = _get_environment_resources(client, environment)
        environment['ConfigurationSettings'] = _get_configuration_settings(client, environment)
    return environments


def _get_environment_resources(client: Any, environment: Dict) -> Optional[Dict]:
    """None when the call fails: the exposure job then treats the environment as unresolved (public)."""
    try:
        response = client.describe_environment_resources(EnvironmentId=environment['EnvironmentId'])
        return response.get('EnvironmentResources', {})
    except ClientError as e:
        log_aws_error(
            logger, f"Could not describe resources of beanstalk environment {environment.get('EnvironmentId')}: {e}", e,
        )
        return None


def _get_configuration_settings(client: Any, environment: Dict) -> List[Dict]:
    try:
        response = client.describe_configuration_settings(
            ApplicationName=environment['ApplicationName'],
            EnvironmentName=environment['EnvironmentName'],
        )
        return response.get('ConfigurationSettings', [])
    except ClientError as e:
        log_aws_error(
            logger,
            f"Could not read configuration settings of beanstalk environment {environment.get('EnvironmentId')}: {e}",
            e,
        )
        return []


def _option_settings(configuration_settings: List[Dict]) -> List[Dict]:
    return [option for setting in configuration_settings for option in setting.get('OptionSettings', [])]


def _listener_protocols(options: List[Dict]) -> List[str]:
    protocols = [
        option['Value'] for option in options
        if option.get('Namespace', '').startswith(_LISTENER_NAMESPACE_PREFIXES) and
        option.get('OptionName') in _PROTOCOL_OPTION_NAMES and option.get('Value')
    ]
    return list(dict.fromkeys(protocols))


def _environment_type(options: List[Dict]) -> Optional[str]:
    # LoadBalanced or SingleInstance.
    for option in options:
        if option.get('Namespace') == _ENVIRONMENT_NAMESPACE and option.get('OptionName') == 'EnvironmentType':
            return option.get('Value')
    return None


@timeit
def transform_environments(environments: List[Dict], region: str) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for environment in environments:
        arn = environment.get('EnvironmentArn')
        if not arn:
            continue
        resources = environment.get('EnvironmentResources')
        options = _option_settings(environment.get('ConfigurationSettings', []))
        tier = environment.get('Tier', {})
        transformed.append({
            'arn': arn,
            'name': environment.get('EnvironmentName'),
            'environmentId': environment.get('EnvironmentId'),
            'applicationName': environment.get('ApplicationName'),
            'status': environment.get('Status'),
            'health': environment.get('Health'),
            'healthStatus': environment.get('HealthStatus'),
            'tierName': tier.get('Name'),
            'tierType': tier.get('Type'),
            'cname': environment.get('CNAME'),
            'endpointUrl': environment.get('EndpointURL'),
            'platformArn': environment.get('PlatformArn'),
            'solutionStackName': environment.get('SolutionStackName'),
            'versionLabel': environment.get('VersionLabel'),
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=arn),
            'listenerProtocols': _listener_protocols(options),
            'environmentType': _environment_type(options),
            'resourcesResolved': resources is not None,
            # Classic ELBs are listed by name, application / network load balancers by ARN.
            'loadBalancerNames': [lb['Name'] for lb in (resources or {}).get('LoadBalancers', []) if lb.get('Name')],
            'instanceIds': [i['Id'] for i in (resources or {}).get('Instances', []) if i.get('Id')],
        })
    return transformed


@timeit
def load_environments(
    neo4j_session: neo4j.Session, environments: List[Dict[str, Any]], current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    # Label and arn/name/environment_id/application_name/status/listener_protocols/consolelink are read by the
    # inventory-sync-aws ElasticBeanstalkEnvironment entry and the aws-compliance-analyst-python graph source.
    query = """
    UNWIND $DictList AS env
    MERGE (n:ElasticBeanstalkEnvironment{id: env.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = env.arn
    SET n.lastupdated = $aws_update_tag,
        n.name = env.name,
        n.environment_id = env.environmentId,
        n.application_name = env.applicationName,
        n.status = env.status,
        n.health = env.health,
        n.health_status = env.healthStatus,
        n.tier_name = env.tierName,
        n.tier_type = env.tierType,
        n.cname = env.cname,
        n.endpoint_url = env.endpointUrl,
        n.platform_arn = env.platformArn,
        n.solution_stack_name = env.solutionStackName,
        n.version_label = env.versionLabel,
        n.region = env.region,
        n.consolelink = env.consolelink,
        n.listener_protocols = env.listenerProtocols,
        n.environment_type = env.environmentType,
        n.resources_resolved = env.resourcesResolved,
        n.load_balancer_names = env.loadBalancerNames,
        n.instance_ids = env.instanceIds
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    load_graph_data(
        neo4j_session, query, environments, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_environments(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_elasticbeanstalk_cleanup.json', neo4j_session, common_job_parameters)


_ACCOUNT_ENVIRONMENTS = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization{id: $ORGANIZATION_ID})
        -[:OWNER]->(a:AWSAccount{id: $AWS_ID})-[:RESOURCE]->(env:ElasticBeanstalkEnvironment)
"""
_LINK_QUERIES = (
    _ACCOUNT_ENVIRONMENTS + """
    MATCH (a)-[:RESOURCE]->(lb:LoadBalancerV2)
    WHERE lb.arn IN coalesce(env.load_balancer_names, [])
        OR (lb.name IN coalesce(env.load_balancer_names, []) AND lb.region = env.region)
    MERGE (env)-[r:USES_LOAD_BALANCER]->(lb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UPDATE_TAG
    """,
    _ACCOUNT_ENVIRONMENTS + """
    MATCH (a)-[:RESOURCE]->(lb:LoadBalancer)
    WHERE lb.name IN coalesce(env.load_balancer_names, []) AND lb.region = env.region
    MERGE (env)-[r:USES_LOAD_BALANCER]->(lb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UPDATE_TAG
    """,
    _ACCOUNT_ENVIRONMENTS + """
    MATCH (a)-[:RESOURCE]->(i:EC2Instance)
    WHERE i.id IN coalesce(env.instance_ids, [])
    MERGE (env)-[r:HAS_INSTANCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UPDATE_TAG
    """,
    _ACCOUNT_ENVIRONMENTS + """
    MATCH (env)-[r:USES_LOAD_BALANCER|HAS_INSTANCE]->()
    WHERE r.lastupdated <> $UPDATE_TAG
    DELETE r
    """,
)


@timeit
def link_environment_resources(neo4j_session: neo4j.Session, common_job_parameters: Dict[str, Any]) -> None:
    """
    Post-sync step: `elasticbeanstalk` runs in parallel with `ec2:load_balancer(_v2)` / `ec2:instance`, so the
    environment links to the load balancers and instances stored on it only after all loaded (see
    sync_eks_node_links). Matches stay inside the workspace's account; a name or id that is not in the graph
    gets no edge, and the exposure job reads that as unresolved.
    """
    for query in _LINK_QUERIES:
        run_write_query(
            neo4j_session,
            query,
            WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
            ORGANIZATION_ID=common_job_parameters['ORGANIZATION_ID'],
            AWS_ID=common_job_parameters['AWS_ID'],
            UPDATE_TAG=common_job_parameters['UPDATE_TAG'],
        )


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Elastic Beanstalk for account '%s', at %s.", current_aws_account_id, tic)

    environments: List[Dict[str, Any]] = []
    for region in regions:
        logger.info("Syncing Elastic Beanstalk for region '%s' in account '%s'.", region, current_aws_account_id)
        environments.extend(transform_environments(get_environments(boto3_session, region), region))

    logger.info(f"Total Elastic Beanstalk environments: {len(environments)}")
    load_environments(neo4j_session, environments, current_aws_account_id, update_tag)
    cleanup_environments(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Elastic Beanstalk: {toc - tic:0.4f} seconds")
