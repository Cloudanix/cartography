"""
Post-sync analysis of one cloud scope (AWS account, GCP project, Azure subscription, OCI compartment): the analysis
jobs and the exposure layers that run after its resource syncs.

The work reads the whole scope's graph. cloudanix-web splits an inventory run into service-group subruns that sync in
parallel, so running it at the end of every subrun recomputes it once per group from a half-written graph. A run that
has a dedicated analysis subrun (services ["analysis"]) runs every phase there, once, and tells its group subruns to
skip it (request param deferAnalysis). A caller that does not defer keeps the old behaviour: every subrun runs the
analysis jobs, and only a dedicated or full run computes the exposure layers.
"""
import json
import logging
import time
from dataclasses import dataclass
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import Tuple

import neo4j

from cartography.util import ANALYSIS_SCOPE_KEYS
from cartography.util import run_analysis_job_logged as run_analysis_job
from cartography.util import run_analysis_step_logged

logger = logging.getLogger(__name__)

ANALYSIS_SYNC = "analysis"
EXPOSURE_LAYERS_SYNC = "exposure_layers"
# Request keys that name the post-sync work rather than a resource sync. exposure_layers is the older, narrower name.
POST_SYNC_SYNCS = frozenset({ANALYSIS_SYNC, EXPOSURE_LAYERS_SYNC})
# Request param a group subrun carries when its run has a dedicated analysis subrun.
DEFER_ANALYSIS_PARAM = "deferAnalysis"


@dataclass(frozen=True)
class Phases:
    """
    One cloud's analysis jobs, in run order. A phase may read what an earlier phase wrote, never a later one.

    link: jobs that add relationships later phases read (e.g. subnet to route table).
    exposure: internet exposure (exposed_internet, exposed_internet_type, publicContext); dependent jobs come later.
    posture: other derived properties (IAM, key, encryption, monitoring risk); independent of exposure.
    The exposure layers run between exposure and posture: they read the exposure jobs' output.
    """
    link: Tuple[str, ...] = ()
    exposure: Tuple[str, ...] = ()
    posture: Tuple[str, ...] = ()


def defer_requested(params: Optional[Dict[str, Any]]) -> bool:
    """
    :param params: the sync request's params (config.params).
    True only for a literal JSON true: anything else keeps the analysis in this subrun, the safe default.
    """
    return (params or {}).get(DEFER_ANALYSIS_PARAM) is True


def is_dedicated(requested_syncs: Optional[Iterable[str]], all_syncs: Iterable[str]) -> bool:
    """
    :param requested_syncs: the syncs this request names; None or empty means everything.
    :param all_syncs: every resource sync key of the cloud (its RESOURCE_FUNCTIONS keys).
    True for the analysis subrun and for a run that syncs everything first (the CLI default).
    """
    requested = set(requested_syncs or [])
    return not requested or bool(requested & POST_SYNC_SYNCS) or requested >= set(all_syncs)


def run(
    phases: Phases,
    layers: Callable[[neo4j.Session, Dict], Any],
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
    requested_syncs: Optional[Iterable[str]],
    all_syncs: Iterable[str],
    defer: bool = False,
) -> None:
    """
    Run one scope's post-sync phases, or skip them when another subrun of the run does them.
    A failing job or layers step is logged and reported in the sync response (collect_failed_analysis_jobs), and the
    remaining steps still run.

    :param phases: the cloud's analysis jobs.
    :param layers: the cloud's exposure_layers.run.
    :param defer: defer_requested(config.params); ignored by a dedicated run.
    """
    dedicated = is_dedicated(requested_syncs, all_syncs)
    if defer and not dedicated:
        logger.info("Post-sync analysis deferred to the run's analysis subrun.")
        return

    phase_seconds: Dict[str, float] = {}
    job_seconds: Dict[str, float] = {}

    def run_jobs(jobs: Tuple[str, ...]) -> None:
        for job in jobs:
            _timed(job_seconds, job, lambda: run_analysis_job(job, neo4j_session, common_job_parameters))

    _timed(phase_seconds, "link", lambda: run_jobs(phases.link))
    _timed(phase_seconds, "exposure", lambda: run_jobs(phases.exposure))
    if dedicated:
        _timed(
            phase_seconds, EXPOSURE_LAYERS_SYNC, lambda: run_analysis_step_logged(
                EXPOSURE_LAYERS_SYNC, lambda: layers(neo4j_session, common_job_parameters), common_job_parameters,
            ),
        )
    _timed(phase_seconds, "posture", lambda: run_jobs(phases.posture))

    scope = {key: common_job_parameters[key] for key in ANALYSIS_SCOPE_KEYS if key in common_job_parameters}
    logger.info(
        json.dumps({
            "event": "post_sync_timing", "scope": scope, "dedicated": dedicated,
            "phase_seconds": phase_seconds, "job_seconds": job_seconds,
        }),
    )


def _timed(seconds: Dict[str, float], name: str, step: Callable[[], Any]) -> None:
    tic = time.perf_counter()
    step()
    seconds[name] = round(time.perf_counter() - tic, 4)
