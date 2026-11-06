import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import EndpointConnectionError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.client.core.tx import run_write_query
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


def _paginate(boto3_session: boto3.session.Session, region: str, operation: str, key: str) -> List[Dict]:
    """
    Read every page of a DMS describe call. Regions without DMS (EndpointConnectionError) have nothing to read;
    denials are skipped by aws_handle_regions on the callers; any other error propagates so the sync fails before
    the cleanup job would delete resources of a region that was not read.
    """
    client = boto3_session.client('dms', region_name=region, config=get_botocore_config())
    items: List[Dict] = []
    try:
        for page in client.get_paginator(operation).paginate():
            items.extend(page.get(key, []))
    except EndpointConnectionError:
        logger.warning(f"DMS is not available in region {region}. Skipping.")
        return []
    return items


@timeit
@aws_handle_regions
def get_replication_instances(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    return _paginate(boto3_session, region, 'describe_replication_instances', 'ReplicationInstances')


@timeit
@aws_handle_regions
def get_endpoints(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    return _paginate(boto3_session, region, 'describe_endpoints', 'Endpoints')


def _public_ip_addresses(instance: Dict) -> List[str]:
    # The plural field supersedes the deprecated singular one; either may be absent while the instance is created.
    addresses = instance.get('ReplicationInstancePublicIpAddresses') or []
    single = instance.get('ReplicationInstancePublicIpAddress')
    return [a for a in addresses if a] or ([single] if single else [])


@timeit
def transform_replication_instances(instances: List[Dict], region: str) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for instance in instances:
        arn = instance.get('ReplicationInstanceArn')
        if not arn:
            continue
        subnet_group = instance.get('ReplicationSubnetGroup') or {}
        transformed.append({
            'arn': arn,
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=arn),
            'identifier': instance.get('ReplicationInstanceIdentifier'),
            'instanceClass': instance.get('ReplicationInstanceClass'),
            'status': instance.get('ReplicationInstanceStatus'),
            'engineVersion': instance.get('EngineVersion'),
            'publiclyAccessible': instance.get('PubliclyAccessible'),
            'autoMinorVersionUpgrade': instance.get('AutoMinorVersionUpgrade'),
            'multiAz': instance.get('MultiAZ'),
            'kmsKeyId': instance.get('KmsKeyId'),
            'networkType': instance.get('NetworkType'),
            'availabilityZone': instance.get('AvailabilityZone'),
            'publicIpAddresses': _public_ip_addresses(instance),
            'privateIpAddresses': [a for a in instance.get('ReplicationInstancePrivateIpAddresses') or [] if a],
            'securityGroupIds': [
                sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', []) if sg.get('VpcSecurityGroupId')
            ],
            'subnetGroupIdentifier': subnet_group.get('ReplicationSubnetGroupIdentifier'),
            'vpcId': subnet_group.get('VpcId'),
            'subnetIds': [s['SubnetIdentifier'] for s in subnet_group.get('Subnets', []) if s.get('SubnetIdentifier')],
        })
    return transformed


@timeit
def transform_endpoints(endpoints: List[Dict], region: str) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for endpoint in endpoints:
        arn = endpoint.get('EndpointArn')
        if not arn:
            continue
        transformed.append({
            'arn': arn,
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=arn),
            'identifier': endpoint.get('EndpointIdentifier'),
            'endpointType': endpoint.get('EndpointType'),
            'engineName': endpoint.get('EngineName'),
            'serverName': endpoint.get('ServerName'),
            'port': endpoint.get('Port'),
            'databaseName': endpoint.get('DatabaseName'),
            'status': endpoint.get('Status'),
            # Absent means no TLS; the evaluator's dms_ssl_configured reads it the same way.
            'sslMode': endpoint.get('SslMode', 'none'),
            'certificateArn': endpoint.get('CertificateArn'),
            'kmsKeyId': endpoint.get('KmsKeyId'),
        })
    return transformed


@timeit
def load_replication_instances(
    neo4j_session: neo4j.Session, instances: List[Dict[str, Any]], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    # Label and replication_instance_identifier / publicly_accessible / auto_minor_version_upgrade match the
    # aws-compliance-analyst-python SCHEDULED graph source (dms_replication_not_public); keep them stable.
    query = """
    UNWIND $DictList AS inst
    MERGE (n:DMSReplicationInstance{id: inst.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = inst.arn
    SET n.lastupdated = $aws_update_tag,
        n.name = inst.identifier,
        n.replication_instance_identifier = inst.identifier,
        n.region = inst.region,
        n.consolelink = inst.consolelink,
        n.replication_instance_class = inst.instanceClass,
        n.status = inst.status,
        n.engine_version = inst.engineVersion,
        n.publicly_accessible = inst.publiclyAccessible,
        n.auto_minor_version_upgrade = inst.autoMinorVersionUpgrade,
        n.multi_az = inst.multiAz,
        n.kms_key_id = inst.kmsKeyId,
        n.network_type = inst.networkType,
        n.availability_zone = inst.availabilityZone,
        n.public_ip_addresses = inst.publicIpAddresses,
        n.private_ip_addresses = inst.privateIpAddresses,
        n.security_group_ids = inst.securityGroupIds,
        n.subnet_group_identifier = inst.subnetGroupIdentifier,
        n.vpc_id = inst.vpcId,
        n.subnet_ids = inst.subnetIds
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    load_graph_data(
        neo4j_session, query, instances, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def load_endpoints(
    neo4j_session: neo4j.Session, endpoints: List[Dict[str, Any]], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $DictList AS ep
    MERGE (n:DMSEndpoint{id: ep.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = ep.arn
    SET n.lastupdated = $aws_update_tag,
        n.name = ep.identifier,
        n.endpoint_identifier = ep.identifier,
        n.region = ep.region,
        n.consolelink = ep.consolelink,
        n.endpoint_type = ep.endpointType,
        n.engine_name = ep.engineName,
        n.server_name = ep.serverName,
        n.port = ep.port,
        n.database_name = ep.databaseName,
        n.status = ep.status,
        n.ssl_mode = ep.sslMode,
        n.certificate_arn = ep.certificateArn,
        n.kms_key_id = ep.kmsKeyId
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    load_graph_data(
        neo4j_session, query, endpoints, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_dms_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def link_replication_instance_networks(neo4j_session: neo4j.Session, common_job_parameters: Dict[str, Any]) -> None:
    """
    Post-sync step: `dms` runs in parallel with `ec2:security_group` / `ec2:subnet`, so it links to the security
    groups and subnets stored as ids on the instance only after both loaded (see sync_eks_node_links). Matches stay
    inside the workspace's account; an id that is not in the graph gets no edge, and the exposure job reads that
    as unresolved.
    """
    link_security_groups = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization{id: $ORGANIZATION_ID})
        -[:OWNER]->(a:AWSAccount{id: $AWS_ID})-[:RESOURCE]->(n:DMSReplicationInstance)
    MATCH (a)-[:RESOURCE]->(sg:EC2SecurityGroup)
    WHERE sg.id IN coalesce(n.security_group_ids, [])
    MERGE (n)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UPDATE_TAG
    """
    link_subnets = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization{id: $ORGANIZATION_ID})
        -[:OWNER]->(a:AWSAccount{id: $AWS_ID})-[:RESOURCE]->(n:DMSReplicationInstance)
    MATCH (a)-[:RESOURCE]->(subnet:EC2Subnet)
    WHERE subnet.subnetid IN coalesce(n.subnet_ids, [])
    MERGE (n)-[r:PART_OF_SUBNET]->(subnet)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UPDATE_TAG
    """
    cleanup_query = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization{id: $ORGANIZATION_ID})
        -[:OWNER]->(:AWSAccount{id: $AWS_ID})-[:RESOURCE]->(:DMSReplicationInstance)
        -[r:MEMBER_OF_EC2_SECURITY_GROUP|PART_OF_SUBNET]->()
    WHERE r.lastupdated <> $UPDATE_TAG
    DELETE r
    """
    for query in (link_security_groups, link_subnets, cleanup_query):
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
    logger.info("Syncing DMS for account '%s', at %s.", current_aws_account_id, tic)

    instances: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []
    for region in regions:
        logger.info("Syncing DMS for region '%s' in account '%s'.", region, current_aws_account_id)
        instances.extend(transform_replication_instances(get_replication_instances(boto3_session, region), region))
        endpoints.extend(transform_endpoints(get_endpoints(boto3_session, region), region))

    logger.info(f"Total DMS replication instances: {len(instances)}, endpoints: {len(endpoints)}")
    load_replication_instances(neo4j_session, instances, current_aws_account_id, update_tag)
    load_endpoints(neo4j_session, endpoints, current_aws_account_id, update_tag)
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process DMS: {toc - tic:0.4f} seconds")
