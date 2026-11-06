"""
Azure exposure layers (docs/exposure-layers/plan.md):

    L1 public / L2 internet reachable  reach.py (NSG walk in network.py, App Gateway /
                                       Azure Firewall DNAT in gateways.py)
    L3 accessible without credentials  access.py
    L4 software identity (CVE input)   software.py
    L5 network blast radius            blast_radius.py

Runs after every Azure subscription sync; reads the graph only, calls no Azure API.
Leaves the legacy exposed_internet / exposed_internet_type / publicContext untouched.
"""
import logging
import time
from typing import Dict

import neo4j

from cartography.intel.azure.exposure_layers import access
from cartography.intel.azure.exposure_layers import blast_radius
from cartography.intel.azure.exposure_layers import reach
from cartography.intel.azure.exposure_layers import software
from cartography.intel.exposure.layers import set_node_properties
from cartography.util import timeit

logger = logging.getLogger(__name__)

_PARAM_KEYS = ("WORKSPACE_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "UPDATE_TAG")


def _write(session: neo4j.Session, by_label: Dict[str, Dict[str, Dict]], update_tag: int) -> None:
    for label, by_id in by_label.items():
        rows = [{"id": i, "props": p} for i, p in by_id.items()]
        set_node_properties(session, label, rows, evaluated_at=update_tag)


@timeit
def run(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Compute and write L1-L5 for the subscription in common_job_parameters.

    :param common_job_parameters: needs WORKSPACE_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID, UPDATE_TAG.
    :raises KeyError: when one of those is missing. Callers log and continue.
    """
    tic = time.perf_counter()
    params = {k: common_job_parameters[k] for k in _PARAM_KEYS}
    tag = params["UPDATE_TAG"]

    reach_results = reach.compute(neo4j_session, params)
    reach_props = {label: {i: r.props() for i, r in by_id.items()} for label, by_id in reach_results.items()}
    # L2 first: blast_radius counts how many internet-reachable VMs reach each data store.
    _write(neo4j_session, reach_props, tag)
    _write(neo4j_session, access.compute(neo4j_session, params), tag)
    _write(neo4j_session, software.compute(neo4j_session, params), tag)
    blast_radius.sync(neo4j_session, params, reach_results)

    logger.info(
        "exposure layers subscription=%s done in %.2fs", params["AZURE_SUBSCRIPTION_ID"], time.perf_counter() - tic,
    )
