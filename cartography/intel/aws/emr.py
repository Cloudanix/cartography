import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import botocore.exceptions
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.models.aws.emr import EMRClusterSchema
from cartography.util import aws_handle_regions
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()

# ListClusters keeps terminated clusters for about two months, so accounts running transient clusters (a cluster per
# job) list 100k+ of them; describing each one (with a 1s sleep) never finished and the sync was disabled in 2025-06.
# Live states only, the same list the compliance evaluator uses (emrLiveClusterStates): a terminated cluster has
# nothing left to secure, and cleanup drops it from the graph.
LIVE_CLUSTER_STATES = ['STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING', 'TERMINATING']
# Hard bound per region on live clusters (one describe_cluster each). Throttling is left to botocore's standard
# retry mode (get_botocore_config) instead of fixed sleeps.
MAX_CLUSTERS_PER_REGION = 1000


@timeit
@aws_handle_regions
def get_emr_clusters(boto3_session: boto3.session.Session, region: str) -> List[Dict[str, Any]]:
    """Live cluster summaries in the region; reads at most MAX_CLUSTERS_PER_REGION + 1 so cap_clusters can tell."""
    client = boto3_session.client('emr', region_name=region, config=get_botocore_config())
    clusters: List[Dict] = []
    paginator = client.get_paginator('list_clusters')
    pages = paginator.paginate(
        ClusterStates=LIVE_CLUSTER_STATES, PaginationConfig={'MaxItems': MAX_CLUSTERS_PER_REGION + 1},
    )
    for page in pages:
        clusters.extend(page['Clusters'])

    return clusters


def cap_clusters(clusters: List[Dict[str, Any]], account_id: str, region: str) -> List[Dict[str, Any]]:
    if len(clusters) <= MAX_CLUSTERS_PER_REGION:
        return clusters
    logger.warning(
        f"EMR: more than {MAX_CLUSTERS_PER_REGION} live clusters in account {account_id} region {region}; "
        f"syncing the first {MAX_CLUSTERS_PER_REGION} only.",
    )
    return clusters[:MAX_CLUSTERS_PER_REGION]


def get_block_public_security_group_rules(client: Any, region: str) -> Any:
    """The region's EMR block-public-access setting (one call per region; it is not per cluster)."""
    try:
        response = client.get_block_public_access_configuration()
    except botocore.exceptions.ClientError as e:
        logger.warning(f"Could not read EMR block public access in {region}: {e.response['Error']['Code']}.")
        return None
    return response.get('BlockPublicAccessConfiguration', {}).get('BlockPublicSecurityGroupRules', True)


@timeit
def get_emr_describe_cluster(client: Any, cluster_id: str) -> Dict:
    cluster_details: Dict[str, Any] = {}
    try:
        cluster_details = client.describe_cluster(ClusterId=cluster_id)['Cluster']
    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        msg = e.response['Error']['Message']
        logger.warning(f"Could not run EMR describe_cluster due to boto3 error {code}: {msg}. Skipping.")
    return cluster_details


@timeit
def get_cluster_details(
    boto3_session: boto3.session.Session, region: str, clusters: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """describe_cluster per live cluster plus the region's block-public-access setting: len(clusters) + 1 calls."""
    if not clusters:
        return []
    client = boto3_session.client('emr', region_name=region, config=get_botocore_config())
    block_public = get_block_public_security_group_rules(client, region)
    details: List[Dict[str, Any]] = []
    for cluster in clusters:
        cluster_details = get_emr_describe_cluster(client, cluster['Id'])
        if cluster_details:
            cluster_details['public_access_configuration'] = block_public
            details.append(cluster_details)
    return details


def get_master_security_group_ids(cluster: Dict[str, Any]) -> List[str]:
    """
    Security groups on the cluster's master node (EMR-managed plus additional), from describe_cluster.
    aws_emr_asset_exposure.json reads them to tell whether the master is open to the internet.
    """
    attributes = cluster.get('Ec2InstanceAttributes', {})
    managed = attributes.get('EmrManagedMasterSecurityGroup')
    return ([managed] if managed else []) + attributes.get('AdditionalMasterSecurityGroups', [])


@timeit
def load_emr_clusters(
        neo4j_session: neo4j.Session,
        cluster_data: List[Dict[str, Any]],
        region: str,
        current_aws_account_id: str,
        aws_update_tag: int,
) -> None:
    logger.info(f"Loading EMR {len(cluster_data)} clusters for region '{region}' into graph.")
    for cluster in cluster_data:
        cluster['consolelink'] = (
            aws_console_link.get_console_link(arn=cluster['ClusterArn']) if cluster.get('ClusterArn') else None
        )
        cluster['MasterSecurityGroupIds'] = get_master_security_group_ids(cluster)
    load(
        neo4j_session,
        EMRClusterSchema(),
        cluster_data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict[str, Any]) -> None:
    logger.debug("Running EMR cleanup job.")
    cleanup_job = GraphJob.from_node_schema(EMRClusterSchema(), common_job_parameters)
    cleanup_job.run(neo4j_session)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict[str, Any],
) -> None:
    tic = time.perf_counter()

    for region in regions:
        logger.info(f"Syncing EMR for region '{region}' in account '{current_aws_account_id}'.")
        clusters = cap_clusters(get_emr_clusters(boto3_session, region), current_aws_account_id, region)
        cluster_data = get_cluster_details(boto3_session, region, clusters)
        load_emr_clusters(neo4j_session, cluster_data, region, current_aws_account_id, update_tag)

    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process EMR: {toc - tic:0.4f} seconds")
