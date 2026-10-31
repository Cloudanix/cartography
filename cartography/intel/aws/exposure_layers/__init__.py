"""
AWS exposure layers (docs/exposure-layers/plan.md):

    L1 public / L2 internet reachable  reach.py
    L3 accessible without credentials  access.py
    L4 software identity (CVE input)   software.py
    L5 network blast radius            blast_radius.py

Runs after every AWS sync of an account; reads the graph only, calls no AWS API.
Leaves the legacy exposed_internet / exposed_internet_type properties untouched.
"""
import logging
import time
from typing import Dict

import neo4j

from cartography.intel.aws.exposure_layers import access
from cartography.intel.aws.exposure_layers import blast_radius
from cartography.intel.aws.exposure_layers import reach
from cartography.intel.aws.exposure_layers import software
from cartography.intel.aws.exposure_layers.network import read_security_groups
from cartography.intel.exposure.layers import set_node_properties
from cartography.util import timeit

logger = logging.getLogger(__name__)

_PARAM_KEYS = ("WORKSPACE_ID", "ORGANIZATION_ID", "AWS_ID", "UPDATE_TAG")


def _write(session: neo4j.Session, by_label: Dict[str, Dict[str, Dict]]) -> None:
    for label, by_id in by_label.items():
        set_node_properties(session, label, [{"id": i, "props": p} for i, p in by_id.items()])


@timeit
def run(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    tic = time.perf_counter()
    params = {k: common_job_parameters[k] for k in _PARAM_KEYS}

    reach_results = reach.compute(neo4j_session, params)
    _write(neo4j_session, {label: {i: r.props() for i, r in by_id.items()} for label, by_id in reach_results.items()})
    _write(neo4j_session, access.compute(neo4j_session, params))
    _write(neo4j_session, software.compute(neo4j_session, params))
    blast_radius.sync(neo4j_session, params, read_security_groups(neo4j_session, params))

    logger.info(
        "exposure layers account=%s done in %.2fs", params["AWS_ID"], time.perf_counter() - tic,
    )
