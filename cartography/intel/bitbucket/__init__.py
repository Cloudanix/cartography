import json
import logging
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j
from neo4j import GraphDatabase
from requests import exceptions

from . import workspace
from .repositories import BitbucketAuthError
from .repositories import ensure_repository_list_readable
from .resources import RESOURCE_FUNCTIONS
from cartography.config import Config
from cartography.graph.session import Session
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


def _withhold_dataset(message: str) -> dict:
    """A Bitbucket sync that did not authenticate or did not finish.

    Callers must not run graph cleanup and must not publish an inventory
    snapshot. An empty snapshot is what Rails treats as "these resources
    were removed".
    """
    return {"authFailed": True, "message": message}


def concurrent_execution(
    service: str, service_func: Any, config: Config, workspace_name: str, access_token: str, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    _status = "success"
    _err: Dict = {}
    try:
        neo4j_auth = (config.neo4j_user, config.neo4j_password)
        neo4j_driver = GraphDatabase.driver(
            config.neo4j_uri,
            auth=neo4j_auth,
            max_connection_lifetime=config.neo4j_max_connection_lifetime,
        )
        service_func(
            Session(neo4j_driver), workspace_name, access_token,
            common_job_parameters,
        )
    except Exception as e:
        _status = "error"
        _err = {"error_type": type(e).__name__, "error_message": str(e)}
        logger.warning(f"error processing service {service} workspace={workspace_name} — {e}")
    finally:
        _ev: Dict = {
            "event": "bitbucket_service_timing",
            "workspace": workspace_name,
            "service": service,
            "run_mode": "parallel",
            "duration_seconds": round(time.perf_counter() - tic, 4),
            "status": _status,
        }
        if _err:
            _ev.update(_err)
        logger.info(json.dumps(_ev))


def _sync_one_workspace(
    neo4j_session: neo4j.Session,
    workspace_name: str,
    access_token: str,
    common_job_parameters: Dict[str, Any],
    config: Config,
) -> None:
    _ws_tic = time.perf_counter()
    _service_timings: Dict = {}
    _failed_services: Dict = {}
    # No readable repository list means this run has nothing to publish.
    # Stop before any service cleanup.
    ensure_repository_list_readable(access_token, workspace_name)
    requested_syncs: List[str] = list(RESOURCE_FUNCTIONS.keys())

    sync_args = {
        'neo4j_session': neo4j_session,
        'common_job_parameters': common_job_parameters,
        'workspace_name': workspace_name,
        'bitbucket_access_token': access_token,
    }

    for func_name in requested_syncs:
        if func_name in RESOURCE_FUNCTIONS:
            _svc_tic = time.perf_counter()
            _svc_status = "success"
            _svc_err: Dict = {}
            try:
                logger.info(f"Processing {func_name} workspace={workspace_name}")
                RESOURCE_FUNCTIONS[func_name](**sync_args)
                _svc_elapsed = round(time.perf_counter() - _svc_tic, 4)
                _service_timings[func_name] = _svc_elapsed
            except BitbucketAuthError:
                _svc_status = "error"
                _svc_elapsed = round(time.perf_counter() - _svc_tic, 4)
                raise
            except Exception as e:
                _svc_status = "error"
                _svc_elapsed = round(time.perf_counter() - _svc_tic, 4)
                _svc_err = {"error_type": type(e).__name__, "error_message": str(e)}
                _failed_services[func_name] = str(e)
                logger.warning(f"error to process service {func_name} - {e}")
            finally:
                _ev: Dict = {
                    "event": "bitbucket_service_timing",
                    "workspace": workspace_name,
                    "service": func_name,
                    "run_mode": "sequential",
                    "duration_seconds": _svc_elapsed,
                    "status": _svc_status,
                }
                if _svc_err:
                    _ev.update(_svc_err)
                logger.info(json.dumps(_ev))
        else:
            logger.warning(f'BITBUCKET sync function "{func_name}" was specified but does not exist. Did you misspell it?')

    logger.info(
        json.dumps({
            "event": "bitbucket_workspace_timing_summary",
            "workspace": workspace_name,
            "total_duration_seconds": round(time.perf_counter() - _ws_tic, 4),
            "service_timings": _service_timings,
            "slowest_service": max(_service_timings, key=_service_timings.get) if _service_timings else None,
            "failed_services": _failed_services,
        }),
    )


def _sync_multiple_workspaces(
    neo4j_session: neo4j.Session,
    access_token: str,
    workspaces: List[Dict],
    common_job_parameters: Dict[str, Any],
    config: Config,
) -> bool:
    for ws in workspaces:
        if config.params['workspace']['account_id'] != ws.get('slug'):
            continue

        logger.info(f'processing workspace: {ws.get("slug")}')
        common_job_parameters['WORKSPACE_UUID'] = ws.get('uuid')
        _sync_one_workspace(neo4j_session, ws['slug'], access_token, common_job_parameters, config)
        run_cleanup_job('bitbucket_workspace_cleanup.json', neo4j_session, common_job_parameters)

        del common_job_parameters['WORKSPACE_UUID']

    return True


@timeit
def start_bitbucket_ingestion(neo4j_session: neo4j.Session, config: Config) -> dict:
    """
    If this module is configured, perform ingestion of bitbucket data. Otherwise
    return an auth failure and exit without writing or cleaning the graph.
    :param neo4j_session: Neo4J session for database interface
    :param config: A cartography.config object
    :return: Sync parameters, or an authFailed marker when no snapshot should be published.
    """
    if not config.bitbucket_access_token:
        logger.info('bitbucket import is not configured - skipping this module. See docs to configure.')
        return _withhold_dataset("bitbucket authentication failed: access token is missing")

    access_token = config.bitbucket_access_token
    common_job_parameters = {
        "WORKSPACE_ID": config.params['workspace']['id_string'],
        "UPDATE_TAG": config.update_tag,
    }

    try:

        workspaces_list = workspace.get_workspaces(access_token)

        has_workspace_data = False
        if len(workspaces_list) > 0:
            for ws in workspaces_list:
                if ws.get('slug', "") == config.params['workspace']['account_id']:
                    has_workspace_data = True

        if has_workspace_data is False:
            workspace_obj = workspace.get_workspace(access_token, config.params['workspace']['account_id'])
            if workspace_obj:
                workspaces_list = [workspace_obj]
                has_workspace_data = True

        if has_workspace_data is False:
            logger.warning(
                "Could not process. Bitbucket workspace(s) do not exist or unable to access them",
                extra={"workspace": common_job_parameters["WORKSPACE_ID"]},
            )
            return _withhold_dataset("bitbucket authentication failed: workspace is not accessible")

        workspace.sync(
            neo4j_session,
            workspaces_list,
            common_job_parameters,
        )

        _sync_multiple_workspaces(
            neo4j_session,
            access_token,
            workspaces_list,
            common_job_parameters,
            config,
        )

    except BitbucketAuthError as e:
        logger.error("Bitbucket repository list was not readable: %s", e)
        return _withhold_dataset(str(e))

    except exceptions.RequestException as e:
        logger.error("Could not complete request to the Bitbucket API: %s", e)
        return _withhold_dataset(f"bitbucket request failed before sync completed: {e}")

    return common_job_parameters
