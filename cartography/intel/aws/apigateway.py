import json
import logging
import time
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Tuple

import boto3
import botocore
import neo4j
from botocore.config import Config
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker
from policyuniverse.policy import Policy

from cartography.client.core.tx import load_graph_data
from cartography.client.core.tx import run_write_query
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.intel.aws.util.arns import DEFAULT_PARTITION
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.util import aws_handle_regions
from cartography.util import log_aws_error
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


def build_apigateway_arn(region: str, path: str, partition: str = DEFAULT_PARTITION) -> str:
    """
    Build an API Gateway ARN in AWS's documented form: no account id and a path with a
    leading slash, e.g. arn:aws:apigateway:us-east-1::/restapis/a1b2c3.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/arn-format-reference.html
    """
    return f"arn:{partition}:apigateway:{region}::/{path}"


def get_apigateway_console_link(arn: str) -> str:
    # cloudconsolelink only deep-links the legacy slashless form (::restapis/...);
    # the documented form falls back to the service home page.
    return aws_console_link.get_console_link(arn=arn.replace('::/', '::', 1))


@timeit
@aws_handle_regions
def get_client_certificates(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    certificates = []
    try:
        client = boto3_session.client('apigateway', region_name=region, config=get_botocore_config())
        paginator = client.get_paginator('get_client_certificates')

        page_iterator = paginator.paginate()
        for page in page_iterator:
            certificates.extend(page['items'])
        return certificates

    except ClientError as e:
        log_aws_error(logger, f'Failed to call Apigateway get_client_certificates: {region} - {e}', e)
        return certificates


@timeit
def transform_client_certificates(
    certs: List[Dict], region: str, account_id: str, partition: str = DEFAULT_PARTITION,
) -> List[Dict]:
    certificates = []
    for certificate in certs:
        certificate['region'] = region
        certificate['arn'] = build_apigateway_arn(
            region, f"clientcertificates/{certificate['clientCertificateId']}", partition,
        )
        certificate['consolelink'] = get_apigateway_console_link(certificate['arn'])
        certificates.append(certificate)

    return certificates


def load_client_certificates(session: neo4j.Session, certificates: List[Dict], current_aws_account_id: str, aws_update_tag: int) -> None:
    session.execute_write(_load_client_certificates_tx, certificates, current_aws_account_id, aws_update_tag)


@timeit
def _load_client_certificates_tx(tx: neo4j.Transaction, certificates: List[Dict], current_aws_account_id: str, aws_update_tag: int) -> None:
    query: str = """
    UNWIND $Records as record
    MERGE (certificate:APIGatewayClientCertificate{id: record.arn})
    ON CREATE SET certificate.firstseen = timestamp(),
        certificate.arn = record.arn
    SET certificate.lastupdated = $aws_update_tag,
        certificate.name = record.clientCertificateId,
        certificate.region = record.region,
        certificate.consolelink = record.consolelink,
        certificate.pem_encoded_certificate = record.pemEncodedCertificate,
        certificate.expiration_date = record.expirationDate,
        certificate.description = record.description,
        certificate.created_date = record.createdDate
    WITH certificate
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(certificate)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        query,
        Records=certificates,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_client_certificates(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_client_certificates_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_client_certificates(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    aws_update_tag: int, common_job_parameters: Dict,
) -> None:
    partition = get_partition_from_params(common_job_parameters)
    data = []
    for region in regions:
        certs = get_client_certificates(boto3_session, region)
        data.extend(transform_client_certificates(certs, region, current_aws_account_id, partition))

    logger.info(f"Total API Gateway Certificates: {len(data)}")

    load_client_certificates(neo4j_session, data, current_aws_account_id, aws_update_tag)

    cleanup_client_certificates(neo4j_session, common_job_parameters)


@timeit
@aws_handle_regions
def get_apigateway_rest_apis(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('apigateway', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('get_rest_apis')
    apis: List[Any] = []
    for page in paginator.paginate():
        apis.extend(page['items'])
    for api in apis:
        api['region'] = region
    return apis


@timeit
def transform_apigateway_rest_apis(apis):
    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for api in apis:
        api['CreatedDate'] = str(api['createdDate']) if 'createdDate' in api else None


@timeit
@aws_handle_regions
def get_rest_api_details(
        boto3_session: boto3.session.Session, rest_apis: List[Dict], aws_account_id: str,
        partition: str = DEFAULT_PARTITION,
) -> Generator[Any, Any, Any]:
    """
    Iterates over all API Gateway REST APIs.
    """

    for api in rest_apis:
        client = boto3_session.client('apigateway', region_name=api['region'], config=get_botocore_config())
        stages = get_rest_api_stages(api, client)
        cert = get_rest_api_client_certificate(stages, client)
        certificate = transform_rest_api_client_certificate(cert, api['region'], aws_account_id, partition)
        resources = get_rest_api_resources(api, client)
        policy = get_rest_api_policy(api, client)
        yield api['id'], stages, certificate, resources, policy, api['region']


@timeit
def get_rest_api_stages(api: Dict, client: botocore.client.BaseClient) -> List[Any]:
    """
    Gets the REST API Stage Resources.
    """
    try:
        stages = client.get_stages(restApiId=api['id'])
    except ClientError as e:
        logger.warning(f'Failed to retrieve Stages for Api Id - {api["id"]} - {e}')
        raise

    return stages['item']


@timeit
def get_rest_api_client_certificate(stages: Dict, client: botocore.client.BaseClient) -> Optional[Any]:
    """
    Gets the current ClientCertificate resource if present, else returns None.
    """
    response = None
    certificates = []
    for stage in stages:
        if 'clientCertificateId' in stage:
            try:
                response = client.get_client_certificate(clientCertificateId=stage['clientCertificateId'])
                response['stageName'] = stage['stageName']
                certificates.append(response)
            except ClientError as e:
                logger.warning(f"Failed to retrieve Client Certificate for Stage {stage['stageName']} - {e}")
                raise
        else:
            return []

    return certificates


@timeit
def transform_rest_api_client_certificate(
    certs: List[Dict], api_region: str, aws_account_id: str, partition: str = DEFAULT_PARTITION,
) -> List[Dict]:
    certificates = []

    # neo4j does not accept datetime objects and values. This loop is used to convert date values to string.
    for certificate in certs:
        certificate['region'] = api_region
        certificate['createdDate'] = str(certificate['createdDate'])
        certificate['expirationDate'] = str(certificate.get('expirationDate'))
        certificate['arn'] = build_apigateway_arn(
            api_region, f"clientcertificates/{certificate['clientCertificateId']}", partition,
        )
        certificate['consolelink'] = get_apigateway_console_link(certificate['arn'])

        certificates.append(certificate)

    return certificates


@timeit
def get_rest_api_resources(api: Dict, client: botocore.client.BaseClient) -> List[Any]:
    """
    Gets the collection of Resource resources.
    """
    resources: List[Any] = []
    paginator = client.get_paginator('get_resources')
    response_iterator = paginator.paginate(restApiId=api['id'])
    for page in response_iterator:
        resources.extend(page['items'])

    return resources


@timeit
def get_rest_api_policy(api: Dict, client: botocore.client.BaseClient) -> List[Any]:
    """
    Gets the REST API policy. Returns policy string or None if no policy is present.
    """
    policy = api['policy'] if 'policy' in api and api['policy'] else None
    return policy


@timeit
def load_apigateway_rest_apis(
    neo4j_session: neo4j.Session, rest_apis: List[Dict], current_aws_account_id: str,
    aws_update_tag: int, partition: str = DEFAULT_PARTITION,
) -> None:
    """
    Ingest the details of API Gateway REST APIs into neo4j.
    """
    ingest_rest_apis = """
    UNWIND $DictList AS r
    MERGE (rest_api:APIGatewayRestAPI{id:r.id})
    ON CREATE SET rest_api.firstseen = timestamp(),
    rest_api.createddate = r.createdDate
    SET rest_api.version = r.version,
    rest_api.minimumcompressionsize = r.minimumCompressionSize,
    rest_api.name = r.name,
    rest_api.disableexecuteapiendpoint = r.disableExecuteApiEndpoint,
    rest_api.endpoint_conf_types = r.endpointConfiguration.types,
    rest_api.lastupdated = $aws_update_tag,
    rest_api.region = r.region,
    rest_api.consolelink = r.consolelink,
    rest_api.arn = r.Arn
    WITH rest_api
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(rest_api)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for api in rest_apis:
        region = api['region']
        api['createdDate'] = str(api['createdDate']) if 'createdDate' in api else None
        api['Arn'] = build_apigateway_arn(region, f"restapis/{api['id']}", partition)
        api['consolelink'] = get_apigateway_console_link(api['Arn'])

    load_graph_data(
        neo4j_session,
        ingest_rest_apis,
        rest_apis,
        aws_update_tag=aws_update_tag,
        AWS_ACCOUNT_ID=current_aws_account_id,
    )


@timeit
def _load_apigateway_policies(
        neo4j_session: neo4j.Session, policies: List[Dict], aws_account_id: str, update_tag: int,
) -> None:
    """
    Store on each REST API whether its resource policy is internet accessible (policy_internet_accessible).

    Plain SET of this sync's result. anonymous_access is deliberately left alone: the exposure job flags a
    REGIONAL/EDGE API public unless this says the policy shuts the internet out, and a PRIVATE API is never
    reachable from the internet whatever its policy says.
    """
    ingest_policies = """
    UNWIND $DictList as policy
    MATCH (:AWSAccount{id: $AWS_ACCOUNT_ID})-[:RESOURCE]->(r:APIGatewayRestAPI{id: policy.api_id})
    SET r.policy_internet_accessible = policy.internet_accessible,
    r.lastupdated = $UpdateTag
    """

    load_graph_data(
        neo4j_session,
        ingest_policies,
        policies,
        AWS_ACCOUNT_ID=aws_account_id,
        UpdateTag=update_tag,
    )


def _set_default_values(neo4j_session: neo4j.Session, aws_account_id: str) -> None:
    set_defaults = """
    MATCH (:AWSAccount{id: $AWS_ID})-[:RESOURCE]->(restApi:APIGatewayRestAPI)
    where restApi.anonymous_actions IS NULL
    SET restApi.anonymous_access = false, restApi.anonymous_actions = []
    """

    run_write_query(
        neo4j_session,
        set_defaults,
        AWS_ID=aws_account_id,
    )


@timeit
def _load_apigateway_stages(
        neo4j_session: neo4j.Session, stages: List, update_tag: int, partition: str = DEFAULT_PARTITION,
) -> None:
    """
    Ingest the Stage resource details into neo4j.
    """
    ingest_stages = """
    UNWIND $DictList AS stage
    MERGE (s:APIGatewayStage{id: stage.arn})
    ON CREATE SET s.firstseen = timestamp(), s.stagename = stage.stageName,
    s.createddate = stage.createdDate
    SET s.deploymentid = stage.deploymentId,
    s.clientcertificateid = stage.clientCertificateId,
    s.region=stage.region,
    s.consolelink = stage.consolelink,
    s.cacheclusterenabled = stage.cacheClusterEnabled,
    s.cacheclusterstatus = stage.cacheClusterStatus,
    s.tracingenabled = stage.tracingEnabled,
    s.webaclarn = stage.webAclArn,
    s.lastupdated = $UpdateTag,
    s.arn = stage.arn
    WITH s, stage
    MATCH (rest_api:APIGatewayRestAPI{id: stage.apiId})
    MERGE (rest_api)-[r:ASSOCIATED_WITH]->(s)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """

    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for stage in stages:
        stage['createdDate'] = str(stage['createdDate'])
        stage['arn'] = build_apigateway_arn(
            stage['region'], f"restapis/{stage['apiId']}/stages/{stage['stageName']}", partition,
        )
        stage['consolelink'] = get_apigateway_console_link(stage['arn'])

    load_graph_data(
        neo4j_session,
        ingest_stages,
        stages,
        UpdateTag=update_tag,
    )


@timeit
def _load_apigateway_certificates(
        neo4j_session: neo4j.Session, certificates: List, update_tag: int,
) -> None:
    """
    Ingest the API Gateway Client Certificate details into neo4j.
    """
    ingest_certificates = """
    UNWIND $DictList as certificate
    MERGE (c:APIGatewayClientCertificate{id: certificate.arn})
    ON CREATE SET c.firstseen = timestamp(), c.createddate = certificate.createdDate
    SET c.lastupdated = $UpdateTag, c.expirationdate = certificate.expirationDate,
    c.region = certificate.region,
    c.consolelink = certificate.consolelink,
    c.client_certificate_id = certificate.clientCertificateId,
    c.arn = certificate.arn
    WITH c, certificate
    MATCH (stage:APIGatewayStage{clientcertificateid: certificate.clientCertificateId})
    MERGE (stage)-[r:HAS_CERTIFICATE]->(c)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """

    load_graph_data(
        neo4j_session,
        ingest_certificates,
        certificates,
        UpdateTag=update_tag,
    )


@timeit
def _load_apigateway_resources(
        neo4j_session: neo4j.Session, resources: List, update_tag: int, partition: str = DEFAULT_PARTITION,
) -> None:
    """
    Ingest the API Gateway Resource details into neo4j.
    """
    ingest_resources = """
    UNWIND $DictList AS res
    MERGE (s:APIGatewayResource{id: res.id})
    ON CREATE SET s.firstseen = timestamp()
    SET s.path = res.path,
    s.pathpart = res.pathPart,
    s.parentid = res.parentId,
    s.consolelink = res.consolelink,
    s.region=res.region,
    s.lastupdated =$UpdateTag,
    s.arn = res.arn
    WITH s, res
    MATCH (rest_api:APIGatewayRestAPI{id: res.apiId})
    MERGE (rest_api)-[r:RESOURCE]->(s)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """

    for resource in resources:
        resource['arn'] = build_apigateway_arn(
            resource['region'], f"restapis/{resource['apiId']}/resources/{resource['id']}", partition,
        )
        resource['consolelink'] = get_apigateway_console_link(resource['arn'])

    load_graph_data(
        neo4j_session,
        ingest_resources,
        resources,
        UpdateTag=update_tag,
    )


@timeit
def load_rest_api_details(
        neo4j_session: neo4j.Session, stages_certificate_resources: List[Tuple[Any, Any, Any, Any, Any, Any]],
        aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    """
    Create dictionaries for Stages, Client certificates, policies and Resource resources
    so we can import them in a single query
    """
    stages: List[Dict] = []
    certificates: List[Dict] = []
    resources: List[Dict] = []
    policies: List = []
    for api_id, stage, certificate, resource, policy, region in stages_certificate_resources:
        # One row per API, policy or not, so a deleted policy clears the previous sync's value.
        policies.append(parse_policy(api_id, policy))

        if len(stage) > 0:
            for s in stage:
                s['apiId'] = api_id
                s['region'] = region

            stages.extend(stage)

        if len(resource) > 0:
            for r in resource:
                r['apiId'] = api_id
                r['region'] = region

            resources.extend(resource)

        if len(certificate) > 0:
            for cert in certificate:
                cert['apiId'] = api_id
                cert['region'] = region

            certificates.extend(certificate)

    # cleanup existing properties
    run_cleanup_job(
        'aws_apigateway_details.json',
        neo4j_session,
        common_job_parameters,
    )

    partition = get_partition_from_params(common_job_parameters)
    _load_apigateway_policies(neo4j_session, policies, aws_account_id, update_tag)
    _load_apigateway_stages(neo4j_session, stages, update_tag, partition)
    _load_apigateway_certificates(neo4j_session, certificates, update_tag)
    _load_apigateway_resources(neo4j_session, resources, update_tag, partition)
    _set_default_values(neo4j_session, aws_account_id)


@timeit
def parse_policy(api_id: str, policy: Optional[str]) -> Dict[str, Any]:
    """
    Uses PolicyUniverse to tell whether an API Gateway REST API resource policy lets anyone on the internet invoke it.

    internet_accessible is None when there is no policy or it cannot be parsed: nothing then narrows the API's
    endpoint type, and the exposure job keeps a REGIONAL/EDGE API public.
    """
    if policy is None:
        return {"api_id": api_id, "internet_accessible": None}
    try:
        # unescape doubly escaped JSON
        parsed = Policy(json.loads(policy.replace("\\", "")))
    except json.JSONDecodeError:
        logger.warning(f"failed to decode policy json : {policy}")
        return {"api_id": api_id, "internet_accessible": None}
    return {"api_id": api_id, "internet_accessible": parsed.is_internet_accessible()}


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_apigateway_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_apigateway_rest_apis(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    aws_update_tag: int, common_job_parameters: Dict,
) -> None:
    data = []
    for region in regions:
        data.extend(get_apigateway_rest_apis(boto3_session, region))

    logger.info(f"Total API Gateway APIs: {len(data)}")

    partition = get_partition_from_params(common_job_parameters)
    load_apigateway_rest_apis(neo4j_session, data, current_aws_account_id, aws_update_tag, partition)

    stages_certificate_resources = get_rest_api_details(boto3_session, data, current_aws_account_id, partition)

    load_rest_api_details(
        neo4j_session, stages_certificate_resources, current_aws_account_id, aws_update_tag, common_job_parameters,
    )


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing AWS APIGateway for account '%s', at %s.", current_aws_account_id, tic)
    sync_apigateway_rest_apis(
        neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters,
    )
    sync_client_certificates(
        neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters,
    )
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process AWS APIGateway: {toc - tic:0.4f} seconds")
