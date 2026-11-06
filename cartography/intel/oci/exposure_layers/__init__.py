"""
OCI exposure layers (docs/exposure-layers/plan.md):

    L1 public / L2 internet reachable  reach.py (network facts in network.py)
    L3 accessible without credentials  access.py
    L4 software identity (CVE input)   software.py
    L5 network blast radius            blast_radius.py

Runs after the OCI analysis jobs of each compartment; reads the graph only, calls no OCI API.
Writes nodes of the compartment being analysed; network objects are read tenancy-wide.
Leaves the legacy exposed_internet / exposed_internet_type / publicContext untouched.
"""
import logging
import time
from typing import Dict

import neo4j

from cartography.intel.exposure.layers import set_node_properties
from cartography.intel.oci.exposure_layers import access
from cartography.intel.oci.exposure_layers import blast_radius
from cartography.intel.oci.exposure_layers import reach
from cartography.intel.oci.exposure_layers import software
from cartography.intel.oci.exposure_layers.network import read_instance_vnics
from cartography.intel.oci.exposure_layers.network import read_network
from cartography.util import timeit

logger = logging.getLogger(__name__)

_PARAM_KEYS = ("WORKSPACE_ID", "OCI_TENANCY_ID", "OCI_COMPARTMENT_ID", "UPDATE_TAG")


def _write(session: neo4j.Session, by_label: Dict[str, Dict[str, Dict]], update_tag: int) -> None:
    for label, by_id in by_label.items():
        rows = [{"id": i, "props": p} for i, p in by_id.items()]
        set_node_properties(session, label, rows, evaluated_at=update_tag)


@timeit
def run(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Compute and write L1-L5 for one OCI compartment.

    :param common_job_parameters: needs WORKSPACE_ID, OCI_TENANCY_ID, OCI_COMPARTMENT_ID, UPDATE_TAG.
    :raises KeyError: when one of those is missing.
    """
    tic = time.perf_counter()
    params = {k: common_job_parameters[k] for k in _PARAM_KEYS}

    net = read_network(neo4j_session, params)
    vnic_rows = read_instance_vnics(neo4j_session, params)
    tag = params["UPDATE_TAG"]
    reach_results = reach.compute(neo4j_session, params, net, vnic_rows)
    # L1/L2 first: blast_radius counts which sources are internet_reachable.
    reach_props = {label: {i: r.props() for i, r in by_id.items()} for label, by_id in reach_results.items()}
    _write(neo4j_session, reach_props, tag)
    _write(neo4j_session, access.compute(neo4j_session, params), tag)
    _write(neo4j_session, software.compute(neo4j_session, params), tag)
    blast_radius.sync(neo4j_session, params, net, vnic_rows)

    logger.info(
        "exposure layers compartment=%s done in %.2fs", params["OCI_COMPARTMENT_ID"], time.perf_counter() - tic,
    )
