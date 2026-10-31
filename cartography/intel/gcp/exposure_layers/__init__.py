"""
GCP exposure layers (docs/exposure-layers/plan.md):

    L1 public / L2 internet reachable  reach.py (network.py: firewall + route evaluation)
    L3 accessible without credentials  access.py
    L4 software identity (CVE input)   software.py
    L5 network blast radius            blast_radius.py

Runs after the analysis jobs of the synced project; reads the graph only, calls no GCP API.
Leaves the legacy exposed_internet / exposed_internet_type / publicContext properties untouched.
"""
import logging
import time
from typing import Dict

import neo4j

from cartography.intel.exposure.layers import set_node_properties
from cartography.intel.gcp.exposure_layers import access
from cartography.intel.gcp.exposure_layers import blast_radius
from cartography.intel.gcp.exposure_layers import reach
from cartography.intel.gcp.exposure_layers import software
from cartography.intel.gcp.exposure_layers.network import read_instances
from cartography.intel.gcp.exposure_layers.network import read_vpcs
from cartography.util import timeit

logger = logging.getLogger(__name__)

_PARAM_KEYS = ("WORKSPACE_ID", "GCP_ORGANIZATION_ID", "GCP_PROJECT_ID", "UPDATE_TAG")


def _write(session: neo4j.Session, by_label: Dict[str, Dict[str, Dict]]) -> None:
    for label, by_id in by_label.items():
        set_node_properties(session, label, [{"id": i, "props": p} for i, p in by_id.items()])


@timeit
def run(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Compute and write L1-L5 for one GCP project.

    :param neo4j_session: Neo4j session
    :param common_job_parameters: needs WORKSPACE_ID, GCP_ORGANIZATION_ID, GCP_PROJECT_ID, UPDATE_TAG
    :raises KeyError: a parameter is missing (the caller logs and goes on)
    """
    tic = time.perf_counter()
    params = {k: common_job_parameters[k] for k in _PARAM_KEYS}

    vpcs = read_vpcs(neo4j_session, params)
    instances = read_instances(neo4j_session, params)
    access_results = access.compute(neo4j_session, params)
    reach_results = reach.compute(neo4j_session, params, vpcs, instances, access_results)
    _write(neo4j_session, {label: {i: r.props() for i, r in by_id.items()} for label, by_id in reach_results.items()})
    _write(neo4j_session, access_results)
    _write(neo4j_session, software.compute(neo4j_session, params))
    blast_radius.sync(neo4j_session, params, vpcs, instances)

    logger.info(
        "exposure layers project=%s done in %.2fs", params["GCP_PROJECT_ID"], time.perf_counter() - tic,
    )
