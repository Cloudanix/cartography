"""
When the exposure layers run, shared by the four cloud syncs.

The layers read the whole account's graph, so they belong after every resource sync of a run.
cloudanix-web splits a run into service-group subruns that run in parallel; computing in each of
them would recompute N times from a half-written graph. The step therefore runs only when the
request names it (a final subrun with services ["exposure_layers"]) or asks for everything (the CLI
default, where one process syncs every resource first).
"""
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Optional

import neo4j

from cartography.util import run_analysis_step_logged

EXPOSURE_LAYERS_SYNC = "exposure_layers"


def is_requested(requested_syncs: Optional[Iterable[str]], all_syncs: Iterable[str]) -> bool:
    """
    :param requested_syncs: the services this request syncs; None or empty means everything.
    :param all_syncs: every resource sync key of the cloud (its RESOURCE_FUNCTIONS keys).
    """
    requested = set(requested_syncs or [])
    return not requested or EXPOSURE_LAYERS_SYNC in requested or requested >= set(all_syncs)


def run_if_requested(
    run: Callable[[neo4j.Session, Dict], Any],
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
    requested_syncs: Optional[Iterable[str]],
    all_syncs: Iterable[str],
) -> None:
    """Run one cloud's exposure layers; a failure is reported in the sync response, never raised."""
    if not is_requested(requested_syncs, all_syncs):
        return
    run_analysis_step_logged(
        EXPOSURE_LAYERS_SYNC, lambda: run(neo4j_session, common_job_parameters), common_job_parameters,
    )
