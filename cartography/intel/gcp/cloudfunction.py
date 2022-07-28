import json
import logging
from typing import Dict
from typing import List
from util.common import transform_bindings

import time
import neo4j
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource
from cloudconsolelink.clouds.gcp import GCPLinker

from cartography.util import run_cleanup_job
from . import label
from cartography.util import timeit

logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()


@timeit
def get_gcp_functions(function: Resource, project_id: str, regions: list, common_job_parameters) -> List[Dict]:
    """
        Returns a list of functions for a given project.

        :type functions: Resource
        :param function: The function resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :type region: string
        :param region: The region in which the function is defined

        :rtype: list
        :return: List of Functions
    """
    try:
        locations = []
        request = function.projects().locations().list(name=f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            for location in response['locations']:
                location["id"] = location.get("name", None)
                location['location_name'] = location['name'].split('/')[-1]
                if regions is None:
                    locations.append(location)
                else:
                    if location['locationId'] in regions or location['locationId'] == 'global':
                        locations.append(location)

            request = function.projects().locations().list_next(previous_request=request, previous_response=response)
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
            logger.warning(
                (
                    "Could not retrieve Functions locations on project %s due to permissions issues.\
                        Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise

    try:
        functions = []
        for region in locations:
            request = function.projects().locations().functions().list(
                parent=region.get('name', None),
            )
            while request is not None:
                response = request.execute()
                for func in response.get('functions', []):
                    func['id'] = func['name']
                    func['function_name'] = func['name'].split('/')[-1]
                    func['region'] = region.get('locationId', 'global')
                    function_entities, public_access = get_function_policy_entities(function, func, project_id)
                    func['entities'] = function_entities
                    func['public_access'] = public_access
                    func['is_public_facing'] = False
                    if func['public_access']:
                        if func.get('ingressSettings',None) in ('INGRESS_SETTINGS_UNSPECIFIED','ALLOW_ALL'):
                            func['is_public_facing'] = True
                    func['consolelink'] = gcp_console_link.get_console_link(
                        resource_name='cloud_function', project_id=project_id, cloud_function_name=func['name'].split('/')[-1], region=func['region'])
                    functions.append(func)
                request = function.projects().locations().functions().list_next(
                    previous_request=request,
                    previous_response=response,
                )
        if common_job_parameters.get('pagination').get('cloudfunction', None):
            page_start = (common_job_parameters.get('pagination').get('cloudfunction', None)[
                          'pageNo'] - 1) * common_job_parameters.get('pagination').get('cloudfunction', None)['pageSize']
            page_end = page_start + common_job_parameters.get('pagination').get('cloudfunction', None)['pageSize']
            if page_end > len(functions) or page_end == len(functions):
                functions = functions[page_start:]
            else:
                has_next_page = True
                functions = functions[page_start:page_end]
                common_job_parameters['pagination']['cloudfunction']['hasNextPage'] = has_next_page
        return functions
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
            logger.warning(
                (
                    "Could not retrieve Functions on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


def get_function_policy_entities(function: Resource, fns: Dict, project_id: str) -> List[Dict]:
    """
        Returns a list of users attached to IAM policy of a Function within the given project.

        :type function: The GCP function resource object
        :param function: The functions resource object created by googleapiclient.discovery.build()

        :type Func: Dict
        :param fns: The Dict object of function

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of gcp function iam policy users
    """
    try:
        iam_policy = function.projects().locations().functions().getIamPolicy(resource=fns['name']).execute()
        bindings = iam_policy.get('bindings', [])
        entity_list, public_access = transform_bindings(bindings, project_id)
        return entity_list, public_access
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
            logger.warning(
                (
                    "Could not retrieve iam policy of function on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def load_functions(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_functions_tx, data_list, project_id, update_tag)


@timeit
def _load_functions_tx(tx: neo4j.Transaction, functions: List[Resource], project_id: str, gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type function_resp: List
        :param function_resp: A list GCP Functions

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_functions = """
    UNWIND {functions} as func
    MERGE (function:GCPFunction{id:func.id})
    ON CREATE SET
        function.firstseen = timestamp()
    SET
        function.name = func.name,
        function.function_name = func.function_name,
        function.description = func.description,
        function.status = func.status,
        function.region = func.region,
        function.entryPoint = func.entryPoint,
        function.runtime = func.runtime,
        function.timeout = func.timeout,
        function.public_access = func.public_access,
        function.availableMemoryMb = func.availableMemoryMb,
        function.serviceAccountEmail = func.serviceAccountEmail,
        function.updateTime = func.updateTime,
        function.versionId = func.versionId,
        function.ingressSettings = func.ingressSettings,
        function.network = func.network,
        function.maxInstances = func.maxInstances,
        function.vpcConnector = func.vpcConnector,
        function.vpcConnectorEgressSettings = func.vpcConnectorEgressSettings,
        function.ingressSettings = func.ingressSettings,
        function.is_public_facing = func.is_public_facing,
        function.buildWorkerPool = func.buildWorkerPool,
        function.buildId = func.buildId,
        function.sourceToken = func.sourceToken,
        function.sourceArchiveUrl = func.sourceArchiveUrl,
        function.consolelink = func.consolelink,
        function.lastupdated = {gcp_update_tag}
    WITH function
    MATCH (owner:GCPProject{id:{ProjectId}})
    MERGE (owner)-[r:RESOURCE]->(function)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_functions,
        functions=functions,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def load_function_entity_relation(session: neo4j.Session, function: Dict, update_tag: int) -> None:
    session.write_transaction(load_function_entity_relation_tx, function, update_tag)


@timeit
def load_function_entity_relation_tx(tx: neo4j.Transaction, function: Dict, gcp_update_tag: int) -> None:
    """
        :type neo4j_session: Neo4j session object
        :param neo4j session: The Neo4j session object

        :type function: Dict
        :param fucntion: Function Dict object

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with

        :rtype: NoneType
        :return: Nothing
    """
    ingest_entities = """
    UNWIND {entities} AS entity
    MATCH (principal:GCPPrincipal{email:entity.email})
    WITH principal
    MATCH (function:GCPFunction{id: {function_id}})
    MERGE (principal)-[r:USES]->(function)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}    """
    tx.run(
        ingest_entities,
        function_id=function.get('id', None),
        entities=function.get('entities', []),
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_gcp_functions(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Delete out-of-date GCP Functions and relationships

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    run_cleanup_job('gcp_function_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, function: Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict, regions: list
) -> None:
    """
    Get GCP Cloud Functions using the Cloud Function resource object, ingest to Neo4j, and clean up old data.

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session

    :type function: The GCP Cloud Function resource object created by googleapiclient.discovery.build()
    :param function: The GCP Cloud Function resource object

    :type project_id: str
    :param project_id: The project ID of the corresponding project

    :type gcp_update_tag: timestamp
    :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    tic = time.perf_counter()

    logger.info("Syncing Cloud Functions for project '%s', at %s.", project_id, tic)

    # FUNCTIONS
    functions = get_gcp_functions(function, project_id, regions, common_job_parameters)
    load_functions(neo4j_session, functions, project_id, gcp_update_tag)
    for function in functions:
        load_function_entity_relation(neo4j_session, function, gcp_update_tag)
    cleanup_gcp_functions(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, functions, gcp_update_tag, common_job_parameters, 'functions', 'GCPFunction')

    toc = time.perf_counter()
    logger.info(f"Time to process Cloud Functions: {toc - tic:0.4f} seconds")
