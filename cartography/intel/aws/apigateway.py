import json
import logging

from botocore.exceptions import ClientError
from policyuniverse.policy import Policy

from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_apigateway_rest_apis(boto3_session, region):
    client = boto3_session.client('apigateway', region_name=region)
    paginator = client.get_paginator('get_rest_apis')
    apis = []
    for page in paginator.paginate():
        apis.extend(page['items'])
    return apis


@timeit
def transform_apigateway_rest_apis(apis):
    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for api in apis:
        api['CreatedDate'] = str(api['createdDate']) if 'createdDate' in api else None


@timeit
@aws_handle_regions
def get_rest_api_details(boto3_session, rest_apis, region):
    """
    Iterates over all API Gateway REST APIs.
    """
    client = boto3_session.client('apigateway', region_name=region)
    for api in rest_apis:
        stages = get_rest_api_stages(api, client)
        certificate = get_rest_api_client_certificate(stages, client)  # clientcertificate id is given by the api stage
        resources = get_rest_api_resources(api, client)
        policy = get_rest_api_policy(api, client)
        yield api['id'], stages, certificate, resources, policy


@timeit
def get_rest_api_stages(api, client):
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
def get_rest_api_client_certificate(stages, client):
    """
    Gets the current ClientCertificate resource if present, else returns None.
    """
    response = None
    for stage in stages:
        if 'clientCertificateId' in stage:
            try:
                response = client.get_client_certificate(clientCertificateId=stage['clientCertificateId'])
                response['stageName'] = stage['stageName']
            except ClientError as e:
                logger.warning(f"Failed to retrive Client Certificate for Stage {stage['stageName']} - {e}")
                raise
        else:
            return None

    return response


@timeit
def get_rest_api_resources(api, client):
    """
    Gets the collection of Resource resources.
    """
    resources = []
    paginator = client.get_paginator('get_resources')
    response_iterator = paginator.paginate(restApiId=api['id'])
    for page in response_iterator:
        resources.extend(page['items'])

    return resources


@timeit
def get_rest_api_policy(api, client):
    """
    Gets the REST API policy. Returns policy string or None if no policy is present.
    """
    policy = api['policy'] if 'policy' in api and api['policy'] else None
    return policy


@timeit
@aws_handle_regions
def load_apigateway_rest_apis(neo4j_session, rest_apis, region, current_aws_account_id, aws_update_tag):
    """
    Ingest the details of API Gateway REST APIs into neo4j.
    """
    ingest_rest_apis = """
    UNWIND {rest_apis_list} AS r
    MERGE (rest_api:APIGatewayRestAPI{id:r.id})
    ON CREATE SET rest_api.firstseen = timestamp(),
    rest_api.createddate = r.createdDate
    SET rest_api.version = r.version,
    rest_api.minimumcompressionsize = r.minimumCompressionSize,
    rest_api.disableexecuteapiendpoint = r.disableExecuteApiEndpoint,
    rest_api.lastupdated = {aws_update_tag},
    rest_api.region = {Region}
    WITH rest_api
    MATCH (aa:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (aa)-[r:RESOURCE]->(rest_api)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    neo4j_session.run(
        ingest_rest_apis,
        rest_apis_list=rest_apis,
        aws_update_tag=aws_update_tag,
        Region=region,
        AWS_ACCOUNT_ID=current_aws_account_id,
    )


@timeit
def _load_apigateway_policies(neo4j_session, policies, update_tag):
    """
    Ingest API Gateway REST API policy results into neo4j.
    """
    ingest_policies = """
    UNWIND {policies} as policy
    MATCH (r:APIGatewayRestAPI) where r.name = policy.api_id
    SET r.anonymous_access = (coalesce(r.anonymous_access, false) OR policy.internet_accessible),
    r.anonymous_actions = coalesce(r.anonymous_actions, []) + policy.accessible_actions,
    r.lastupdated = {UpdateTag}
    """

    neo4j_session.run(
        ingest_policies,
        policies=policies,
        UpdateTag=update_tag,
    )


def _set_default_values(neo4j_session, aws_account_id):
    set_defaults = """
    MATCH (:AWSAccount{id: {AWS_ID}})-[:RESOURCE]->(restApi:APIGatewayRestAPI) where NOT EXISTS(restApi.anonymous_actions)
    SET restApi.anonymous_access = false, restApi.anonymous_actions = []
    """

    neo4j_session.run(
        set_defaults,
        AWS_ID=aws_account_id,
    )


@timeit
def _load_apigateway_stages(neo4j_session, stages, update_tag):
    """
    Ingest the Stage resource details into neo4j.
    """
    ingest_stages = """
    UNWIND {stages_list} AS stage
    MERGE (s:APIGatewayStage{id: stage.stageName})
    ON CREATE SET s.firstseen = timestamp(), s.createddate = stage.createdDate
    SET s.deploymentid = stage.deploymentId,
    s.clientcertificateid = stage.clientCertificateId,
    s.cacheclusterenabled = stage.cacheClusterEnabled,
    s.cacheclusterstatus = stage.cacheClusterStatus,
    s.tracingenabled = stage.tracingEnabled,
    s.webaclarn = stage.webAclArn,
    s.lastupdated = {UpdateTag}
    WITH s, stage
    MATCH (rest_api:APIGatewayRestAPI{id: stage.apiId})
    MERGE (rest_api)-[r:ASSOCIATED_WITH]->(s)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {UpdateTag}
    """

    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for stage in stages:
        stage['createdDate'] = str(stage['createdDate'])

    neo4j_session.run(
        ingest_stages,
        stages_list=stages,
        UpdateTag=update_tag,
    )


@timeit
def _load_apigateway_certificates(neo4j_session, certificates, update_tag):
    """
    Ingest the API Gateway Client Certificate details into neo4j.
    """
    ingest_certificates = """
    UNWIND {certificates_list} as certificate
    MERGE (c:APIGatewayClientCertificate{id: certificate.clientCertificateId})
    ON CREATE SET c.firstseen = timestamp(), c.createddate = certificate.createdDate
    SET c.lastupdated = {UpdateTag}, c.expirationdate = certificate.expirationDate
    WITH c, certificate
    MATCH (stage:APIGatewayStage{id: certificate.stageName})
    MERGE (stage)-[r:HAS_CERTIFICATE]->(c)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {UpdateTag}
    """

    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for certificate in certificates:
        certificate['createdDate'] = str(certificate['createdDate'])
        certificate['expirationDate'] = str(certificate.get('expirationDate'))

    neo4j_session.run(
        ingest_certificates,
        certificates_list=certificates,
        UpdateTag=update_tag,
    )


@timeit
def _load_apigateway_resources(neo4j_session, resources, update_tag):
    ingest_resources = """
    UNWIND {resources_list} AS res
    MERGE (s:APIGatewayResource{id: res.id})
    ON CREATE SET s.firstseen = timestamp()
    SET s.path = res.path,
    s.pathpart = res.pathPart,
    s.parentid = res.parentId,
    s.lastupdated ={UpdateTag}
    WITH s, res
    MATCH (rest_api:APIGatewayRestAPI{id: res.apiId})
    MERGE (rest_api)-[r:RESOURCE]->(s)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {UpdateTag}
    """

    neo4j_session.run(
        ingest_resources,
        resources_list=resources,
        UpdateTag=update_tag,
    )


@timeit
def load_rest_api_details(neo4j_session, stages_certificate_resources, aws_account_id, update_tag):
    """
    Create dictionaries for Stages, Client certificates, policies and Resource resources so we can import them in a single query
    """
    stages = []
    certificates = []
    resources = []
    policies = []
    apiId = ""
    for api_id, stage, certificate, resource, policy in stages_certificate_resources:
        parsed_policy = parse_policy(api_id, policy)
        if parsed_policy is not None:
            policies.extend(parsed_policy)
        if len(stage) > 0:
            for s in stage:
                s['apiId'] = api_id
            stages.extend(stage)
        if len(resource) > 0:
            for r in resource:
                r['apiId'] = api_id
            resources.extend(resource)
        if certificate:
            certificates.extend(certificate)

    # cleanup existing properties
    run_cleanup_job(
        'aws_apigateway_details.json',
        neo4j_session,
        {'UPDATE_TAG': update_tag, 'AWS_ID': aws_account_id},
    )

    _load_apigateway_policies(neo4j_session, policies, update_tag)
    _load_apigateway_stages(neo4j_session, stages, update_tag)
    _load_apigateway_certificates(neo4j_session, certificates, update_tag)
    _load_apigateway_resources(neo4j_session, resources, update_tag)
    _set_default_values(neo4j_session, aws_account_id)


@timeit
def parse_policy(api_id, policy):
    """
    Uses PolicyUniverse to parse API Gateway REST API policy and returns the internet accessibility results
    """
    if policy is not None:
        policy = Policy(json.loads(policy))
        if policy.is_internet_accessible():
            return {
                "api_id": api_id,
                "internet_accessible": True,
                "accessible_actions": list(policy.internet_accessible_actions()),
            }
        else:
            return None
    else:
        return None


@timeit
def cleanup(neo4j_session, common_job_parameters):
    run_cleanup_job('aws_import_apigateway_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_apigateway_rest_apis(neo4j_session, boto3_session, region, current_aws_account_id, aws_update_tag):
    rest_apis = get_apigateway_rest_apis(boto3_session, region)
    transform_apigateway_rest_apis(rest_apis)
    load_apigateway_rest_apis(neo4j_session, rest_apis, region, current_aws_account_id, aws_update_tag)

    stages_certificate_resources = get_rest_api_details(boto3_session, rest_apis, region)
    load_rest_api_details(neo4j_session, stages_certificate_resources, current_aws_account_id, aws_update_tag)


@timeit
def sync(neo4j_session, boto3_session, regions, account_id, sync_tag, common_job_parameters):
    for region in regions:
        logger.info(f"Syncing AWS APIGateway Rest APIs for region '{region}' in account '{account_id}'.")
        sync_apigateway_rest_apis(neo4j_session, boto3_session, region, account_id, sync_tag)
    cleanup(neo4j_session, common_job_parameters)
