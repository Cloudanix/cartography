import logging
import os
import time
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from string import Template
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from neo4j import GraphDatabase

from cartography.config import Config
from cartography.graph.session import Session
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.intel.aws.iam import get_role_tags
from cartography.util import aws_handle_regions
from cartography.util import batch
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


def get_short_id_from_ec2_arn(arn: str) -> str:
    """
    Return the short-form resource ID from an EC2 ARN.
    For example, for "arn:aws:ec2:us-east-1:test_account:instance/i-1337", return 'i-1337'.
    :param arn: The ARN
    :return: The resource ID
    """
    return arn.split('/')[-1]


def get_bucket_name_from_arn(bucket_arn: str) -> str:
    """
    Return the bucket name from an S3 bucket ARN.
    For example, for "arn:aws:s3:::bucket_name", return 'bucket_name'.
    :param arn: The S3 bucket's full ARN
    :return: The S3 bucket's name
    """
    return bucket_arn.split(':')[-1]


def get_short_id_from_elb_arn(alb_arn: str) -> str:
    """
    Return the ELB name from the ARN
    For example, for arn:aws:elasticloadbalancing:::loadbalancer/foo", return 'foo'.
    :param arn: The ELB's full ARN
    :return: The ELB's name
    """
    return alb_arn.split('/')[-1]


def get_short_id_from_lb2_arn(alb_arn: str) -> str:
    """
    Return the (A|N)LB name from the ARN
    For example, for arn:aws:elasticloadbalancing:::loadbalancer/app/foo/ab123", return 'foo'.
    For example, for arn:aws:elasticloadbalancing:::loadbalancer/net/foo/ab123", return 'foo'.
    :param arn: The (N|A)LB's full ARN
    :return: The (N|A)LB's name
    """
    return alb_arn.split('/')[-2]


def get_hosted_zone_id_from_arn(zone_arn: str) -> str:
    """
    AWSDNSZone.zoneid holds the raw Route53 API Id ("/hostedzone/Z123"), so map
    "arn:aws:route53:::hostedzone/Z123" back to that form.
    """
    return '/hostedzone/' + zone_arn.split('/')[-1]


def get_log_group_arn_with_wildcard(arn: str) -> str:
    """
    AWSCloudWatchLogGroup.id comes from describe-log-groups, whose ARNs end in
    ':*'; the tagging API returns the same ARN without the suffix.
    """
    return arn if arn.endswith(':*') else arn + ':*'


# We maintain a mapping from AWS resource types to their associated labels and unique identifiers.
# label: the node label used in cartography for this resource type
# property: the field of this node that uniquely identified this resource type
# id_func: [optional] - EC2 instances and S3 buckets in cartography currently use non-ARNs as their primary identifiers
# so we need to supply a function pointer to translate the ARN returned by the resourcegroupstaggingapi to the form that
# cartography uses.
# reference: https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html
# TODO - we should make EC2 and S3 assets query-able by their full ARN so that we don't need this workaround.
TAG_RESOURCE_TYPE_MAPPINGS: Dict = {
    'apigateway:clientcertificates': {'label': 'APIGatewayClientCertificate', 'property': 'id'},
    'apigateway:resources': {'label': 'APIGatewayResource', 'property': 'id'},
    'apigateway:restapis': {'label': 'APIGatewayRestAPI', 'property': 'id'},
    'autoscaling:autoScalingGroup': {'label': 'AutoScalingGroup', 'property': 'arn'},
    'dynamodb:table': {'label': 'DynamoDBTable', 'property': 'id'},
    'ec2:instance': {'label': 'EC2Instance', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:internet-gateway': {'label': 'AWSInternetGateway', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:key-pair': {'label': 'EC2KeyPair', 'property': 'id'},
    'ec2:network-interface': {'label': 'NetworkInterface', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:security-group': {'label': 'EC2SecurityGroup', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:subnet': {'label': 'EC2Subnet', 'property': 'subnetid', 'id_func': get_short_id_from_ec2_arn},
    'ec2:transit-gateway': {'label': 'AWSTransitGateway', 'property': 'id'},
    'ec2:transit-gateway-attachment': {'label': 'AWSTransitGatewayAttachment', 'property': 'id'},
    'ec2:vpc': {'label': 'AWSVpc', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ecr:repository': {'label': 'ECRRepository', 'property': 'id'},
    'ec2:volume': {'label': 'EBSVolume', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:elastic-ip-address': {'label': 'ElasticIPAddress', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ecs:cluster': {'label': 'ECSCluster', 'property': 'id'},
    'ecs:container-instance': {
        'label': 'ECSContainerInstance', 'property': 'id',
        'path': '-[:RESOURCE]->(:ECSCluster)-[:HAS_CONTAINER_INSTANCE]->',
    },
    'ecs:task': {
        'label': 'ECSTask', 'property': 'id',
        'path': '-[:RESOURCE]->(:ECSCluster)-[:HAS_TASK]->',
    },
    'ecs:task-definition': {'label': 'ECSTaskDefinition', 'property': 'id'},
    'eks:cluster': {'label': 'EKSCluster', 'property': 'id'},
    'elasticache:cluster': {'label': 'ElasticacheCluster', 'property': 'arn'},
    'elasticloadbalancing:loadbalancer': {
        'label': 'LoadBalancer', 'property':
        'name', 'id_func': get_short_id_from_elb_arn,
    },
    'elasticloadbalancing:loadbalancer/app': {
        'label': 'LoadBalancerV2',
        'property': 'name', 'id_func': get_short_id_from_lb2_arn,
    },
    'elasticloadbalancing:loadbalancer/net': {
        'label': 'LoadBalancerV2',
        'property': 'name', 'id_func': get_short_id_from_lb2_arn,
    },
    'elasticloadbalancing:listener/app': {
        'label': 'ELBV2Listener', 'property': 'id',
        'path': '-[:RESOURCE]->(:LoadBalancerV2)-[:ELBV2_LISTENER]->',
    },
    'elasticloadbalancing:listener/net': {
        'label': 'ELBV2Listener', 'property': 'id',
        'path': '-[:RESOURCE]->(:LoadBalancerV2)-[:ELBV2_LISTENER]->',
    },
    'elasticmapreduce:cluster': {'label': 'EMRCluster', 'property': 'arn'},
    'es:domain': {'label': 'ESDomain', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'iam:group': {'label': 'AWSGroup', 'property': 'arn'},
    'iam:policy': {'label': 'AWSPolicy', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'iam:role': {'label': 'AWSRole', 'property': 'arn'},
    'iam:user': {'label': 'AWSUser', 'property': 'arn'},
    'kms:key': {'label': 'KMSKey', 'property': 'arn'},
    'lambda:function': {'label': 'AWSLambda', 'property': 'id'},
    'lambda:layer': {'label': 'AWSLambdaLayer', 'property': 'id'},
    'lambda:event-source-mapping': {'label': 'AWSLambdaEventSourceMapping', 'property': 'id'},
    'redshift:cluster': {'label': 'RedshiftCluster', 'property': 'id'},
    'rds:cluster': {'label': 'RDSCluster', 'property': 'id'},
    'rds:db': {'label': 'RDSInstance', 'property': 'id'},
    'rds:subgrp': {'label': 'DBSubnetGroup', 'property': 'id'},
    'rds:snapshot': {'label': 'RDSSnapshot', 'property': 'id'},
    # Buckets are the only objects in the S3 service: https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html
    's3': {'label': 'S3Bucket', 'property': 'id', 'id_func': get_bucket_name_from_arn},
    'secretsmanager:secret': {'label': 'SecretsManagerSecret', 'property': 'id'},
    'sqs': {'label': 'SQSQueue', 'property': 'id'},
    'bedrock:agent': {'label': 'AWSBedrockAgent', 'property': 'arn'},
    'bedrock:custom-model': {'label': 'AWSBedrockCustomModel', 'property': 'arn'},
    'bedrock:guardrail': {'label': 'AWSBedrockGuardRail', 'property': 'arn'},
    'bedrock:model-customization-job': {'label': 'AWSBedrockCustomisationJob', 'property': 'arn'},
    'cloudformation:stack': {'label': 'AWSCloudformationStack', 'property': 'id'},
    'cloudfront:distribution': {'label': 'AWSCloudfrontDistribution', 'property': 'id'},
    'cloudtrail:trail': {'label': 'AWSCloudTrailTrail', 'property': 'id'},
    'cloudwatch:alarm': {'label': 'AWSCloudWatchAlarm', 'property': 'id'},
    'config:config-rule': {'label': 'AWSConfigRule', 'property': 'id'},
    'ec2:image': {'label': 'EC2Image', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:launch-template': {'label': 'LaunchTemplate', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:reserved-instances': {
        'label': 'EC2ReservedInstance', 'property': 'id',
        'id_func': get_short_id_from_ec2_arn,
    },
    'ec2:route-table': {'label': 'EC2RouteTable', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'ec2:snapshot': {'label': 'EBSSnapshot', 'property': 'id', 'id_func': get_short_id_from_ec2_arn},
    'events:event-bus': {'label': 'AWSEventBridgeEventBus', 'property': 'id'},
    'events:rule': {'label': 'AWSEventBridgeRule', 'property': 'id'},
    'ecs:service': {
        'label': 'ECSService', 'property': 'id',
        'path': '-[:RESOURCE]->(:ECSCluster)-[:HAS_SERVICE]->',
    },
    'eks:nodegroup': {
        'label': 'EKSClusterNodeGroup', 'property': 'id',
        'path': '-[:RESOURCE]->(:EKSCluster)<-[:ASSOCIATED_WITH]-',
    },
    'kinesis:stream': {'label': 'KinesisStream', 'property': 'id'},
    'rds:ri': {'label': 'RDSReservedDBInstance', 'property': 'id'},
    'logs:log-group': {'label': 'AWSCloudWatchLogGroup', 'property': 'id', 'id_func': get_log_group_arn_with_wildcard},
    'route53:hostedzone': {'label': 'AWSDNSZone', 'property': 'zoneid', 'id_func': get_hosted_zone_id_from_arn},
    'sagemaker:cluster': {'label': 'AWSSagemakerCluster', 'property': 'arn'},
    'sagemaker:domain': {'label': 'AWSSagemakerDomain', 'property': 'arn'},
    'sagemaker:endpoint': {'label': 'AWSSagemakerEndpoint', 'property': 'arn'},
    'sagemaker:model': {'label': 'AWSSagemakerModel', 'property': 'arn'},
    'sagemaker:notebook-instance': {'label': 'AWSSagemakerNotebookInstance', 'property': 'arn'},
    'sagemaker:training-job': {'label': 'AWSSagemakerTrainingJob', 'property': 'arn'},
    'securityhub:hub': {'label': 'SecurityHub', 'property': 'id'},
    'ses:identity': {'label': 'AWSSESIdentity', 'property': 'id'},
    'sns': {'label': 'AWSSNSTopic', 'property': 'id'},
    'waf-regional:webacl': {'label': 'AWSWAFClassicWebACL', 'property': 'id'},
    'wafv2': {'label': 'AWSWAFv2WebACL', 'property': 'id'},
}

# Global services are only reported by the tagging API in us-east-1; querying
# them in every region wastes an API call sequence + a Neo4j session per region.
# 'iam:role' is served by get_role_tags() (IAM is global), so it belongs here too.
GLOBAL_RESOURCE_TYPES = frozenset({
    'cloudfront:distribution',
    'iam:role',
    'route53:hostedzone',
})


@timeit
@aws_handle_regions
def get_tags(boto3_session: boto3.session.Session, resource_type: str, region: str) -> List[Dict]:
    """
    Create boto3 client and retrieve tag data.
    """
    # this is a temporary workaround to populate AWS tags for IAM roles.
    # resourcegroupstaggingapi does not support IAM roles and no ETA is provided
    # TODO: when resourcegroupstaggingapi supports iam:role, remove this condition block
    resources: List[Dict] = []
    try:
        if resource_type == 'iam:role':
            return get_role_tags(boto3_session)

        client = boto3_session.client('resourcegroupstaggingapi', region_name=region, config=get_botocore_config())
        paginator = client.get_paginator('get_resources')

        for page in paginator.paginate(
            # Only ingest tags for resources that Cartography supports.
            # This is just a starting list; there may be others supported by this API.
            ResourceTypeFilters=[resource_type],
        ):
            resources.extend(page['ResourceTagMappingList'])
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to get tags for resource type {resource_type}. {e}")
    return resources


def _load_tags_tx(
    tx: neo4j.Transaction,
    tag_data: List[Dict],
    resource_type: str,
    region: str,
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    INGEST_TAG_TEMPLATE = Template("""
    UNWIND $TagData as tag_mapping
        UNWIND tag_mapping.Tags as input_tag
            MATCH
            (a:AWSAccount{id:$Account})$path(resource:$resource_label{$property:tag_mapping.resource_id})
            MERGE
            (aws_tag:AWSTag:Tag{id:input_tag.Key + ":" + input_tag.Value})
            ON CREATE SET aws_tag.firstseen = timestamp()

            SET aws_tag.lastupdated = $UpdateTag,
            aws_tag.key = input_tag.Key,
            aws_tag.value =  input_tag.Value,
            aws_tag.region = $Region

            MERGE (resource)-[r:TAGGED]->(aws_tag)
            SET r.lastupdated = $UpdateTag,
            r.firstseen = timestamp()
    """)
    query = INGEST_TAG_TEMPLATE.safe_substitute(
        resource_label=TAG_RESOURCE_TYPE_MAPPINGS[resource_type]['label'],
        property=TAG_RESOURCE_TYPE_MAPPINGS[resource_type]['property'],
        path=TAG_RESOURCE_TYPE_MAPPINGS[resource_type].get('path', '-[res:RESOURCE]->'),
    )
    tx.run(
        query,
        TagData=tag_data,
        UpdateTag=aws_update_tag,
        Region=region,
        Account=current_aws_account_id,
    )


@timeit
def load_tags(
    neo4j_session: neo4j.Session,
    tag_data: List[Dict],
    resource_type: str,
    region: str,
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    for tag_data_batch in batch(tag_data, size=500):
        neo4j_session.execute_write(
            _load_tags_tx,
            tag_data=tag_data_batch,
            resource_type=resource_type,
            region=region,
            current_aws_account_id=current_aws_account_id,
            aws_update_tag=aws_update_tag,
        )


@timeit
def transform_tags(tag_data: List[Dict], resource_type: str) -> None:
    for tag_mapping in tag_data:
        tag_mapping['resource_id'] = compute_resource_id(tag_mapping, resource_type)


def compute_resource_id(tag_mapping: Dict, resource_type: str) -> str:
    resource_id = tag_mapping['ResourceARN']
    if 'id_func' in TAG_RESOURCE_TYPE_MAPPINGS[resource_type]:
        parse_resource_id_from_arn = TAG_RESOURCE_TYPE_MAPPINGS[resource_type]['id_func']
        resource_id = parse_resource_id_from_arn(tag_mapping['ResourceARN'])
    return resource_id


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_tags_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_tags(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    region: str,
    resource_type: str,
    current_aws_account_id: str,
    update_tag: int,
) -> None:
    logger.debug(f"BEGIN processing tags for {region} & {resource_type}")

    tag_data = get_tags(boto3_session, resource_type, region)
    transform_tags(tag_data, resource_type)
    load_tags(neo4j_session=neo4j_session, tag_data=tag_data, resource_type=resource_type, region=region, current_aws_account_id=current_aws_account_id, aws_update_tag=update_tag)

    logger.debug(f"END processing tags for {region} & {resource_type}")


def concurrent_execution(
    config: Config,
    region: str,
    resource_type: str,
    current_aws_account_id,
    update_tag: int,
):
    logger.info(f"BEGIN concurrent execution of tags for {region} & {resource_type}")

    if config.credentials['type'] == 'self':
        boto3_session = boto3.Session(
            aws_access_key_id=config.credentials['aws_access_key_id'],
            aws_secret_access_key=config.credentials['aws_secret_access_key'],
        )

    elif config.credentials['type'] == 'assumerole':
        boto3_session = boto3.Session(
            aws_access_key_id=config.credentials['aws_access_key_id'],
            aws_secret_access_key=config.credentials['aws_secret_access_key'],
            aws_session_token=config.credentials['session_token'],
        )

    neo4j_auth = (config.neo4j_user, config.neo4j_password)
    neo4j_driver = GraphDatabase.driver(
        config.neo4j_uri,
        auth=neo4j_auth,
        max_connection_lifetime=config.neo4j_max_connection_lifetime,
    )

    neo4j_session = Session(neo4j_driver)
    sync_tags(neo4j_session, boto3_session, region, resource_type, current_aws_account_id, update_tag)
    neo4j_session.close()

    logger.info(f"END concurrent execution of tags for {region} & {resource_type}")

    return f"Tags Processing for {region} & {resource_type} completed successfully"


@timeit
def sync(
    config: Config,
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict,
    tag_resource_type_mappings: Dict = TAG_RESOURCE_TYPE_MAPPINGS,
) -> None:
    tic = time.perf_counter()

    logger.info("Begin processing tags for account '%s', at %s.", current_aws_account_id, tic)

    if os.environ.get("LOCAL_RUN", "0") == "1" or os.environ.get("CDX_RUN_AS") == "EKS":
        for region in regions:
            logger.info("Syncing AWS tags for region '%s'.", region)
            for resource_type in tag_resource_type_mappings.keys():
                if resource_type in GLOBAL_RESOURCE_TYPES:
                    continue
                sync_tags(neo4j_session, boto3_session, region, resource_type, current_aws_account_id, update_tag)
        for resource_type in GLOBAL_RESOURCE_TYPES & tag_resource_type_mappings.keys():
            sync_tags(neo4j_session, boto3_session, 'us-east-1', resource_type, current_aws_account_id, update_tag)

    else:
        if len(regions) == 0:
            logger.info("No regions to sync tags for.")
            logger.warning(
                "Skipping tags sync.",
                extra={
                    "aws_account": current_aws_account_id,
                    "regions": regions,
                    "update_tag": update_tag,
                    "config": config,
                    "common_job_parameters": common_job_parameters,
                },
            )
            return

        # Process each region in parallel.
        with ThreadPoolExecutor(max_workers=len(regions)) as executor:
            futures = []

            for region in regions:
                logger.info("Syncing AWS tags for region '%s'.", region)
                for resource_type in tag_resource_type_mappings.keys():
                    if resource_type in GLOBAL_RESOURCE_TYPES:
                        continue
                    futures.append(executor.submit(concurrent_execution, config, region, resource_type, current_aws_account_id, update_tag))
            for resource_type in GLOBAL_RESOURCE_TYPES & tag_resource_type_mappings.keys():
                futures.append(executor.submit(concurrent_execution, config, 'us-east-1', resource_type, current_aws_account_id, update_tag))

            for future in as_completed(futures):
                logger.info(f'Result from Future - Tags Processing: {future.result()}')

    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process tags: {toc - tic:0.4f} seconds")
