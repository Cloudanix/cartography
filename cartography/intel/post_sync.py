"""
Post-sync analysis of one cloud scope (AWS account, GCP project, Azure subscription, OCI compartment): the analysis
jobs and the exposure layers that run after its resource syncs.

The work reads the whole scope's graph, so it is its own service, "analysis": cloudanix-web runs it as a separate
subrun after the service-group subruns finish. A group subrun skips it; running it there would recompute it once per
group from a half-written graph and race on the same nodes. A full run (the CLI default) syncs everything, then runs it.
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

# Request service that names the post-sync work rather than a resource sync. A failed exposure layers step is
# reported under this name in the sync response's failed_analysis_jobs.
ANALYSIS_SYNC = "analysis"


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


def analysis_requested(requested_syncs: Optional[Iterable[str]], all_syncs: Iterable[str]) -> bool:
    """
    :param requested_syncs: the syncs this request names; None or empty means everything.
    :param all_syncs: every resource sync key of the cloud (its RESOURCE_FUNCTIONS keys).
    True for the analysis service and for a run that syncs everything first (the CLI default).
    """
    requested = set(requested_syncs or [])
    return not requested or ANALYSIS_SYNC in requested or requested >= set(all_syncs)


def run(
    phases: Phases,
    layers: Callable[[neo4j.Session, Dict], Any],
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
    requested_syncs: Optional[Iterable[str]],
    all_syncs: Iterable[str],
) -> None:
    """
    Run one scope's post-sync phases when the request asks for the analysis service (analysis_requested); otherwise
    do nothing. A failing job or layers step is logged and reported in the sync response
    (collect_failed_analysis_jobs), and the remaining steps still run.

    :param phases: the cloud's analysis jobs.
    :param layers: the cloud's exposure_layers.run.
    """
    if not analysis_requested(requested_syncs, all_syncs):
        return

    phase_seconds: Dict[str, float] = {}
    job_seconds: Dict[str, float] = {}

    def run_jobs(jobs: Tuple[str, ...]) -> None:
        for job in jobs:
            _timed(job_seconds, job, lambda: run_analysis_job(job, neo4j_session, common_job_parameters))

    _timed(phase_seconds, "link", lambda: run_jobs(phases.link))
    _timed(phase_seconds, "exposure", lambda: run_jobs(phases.exposure))
    _timed(
        phase_seconds, "layers", lambda: run_analysis_step_logged(
            ANALYSIS_SYNC, lambda: layers(neo4j_session, common_job_parameters), common_job_parameters,
        ),
    )
    _timed(phase_seconds, "posture", lambda: run_jobs(phases.posture))

    scope = {key: common_job_parameters[key] for key in ANALYSIS_SCOPE_KEYS if key in common_job_parameters}
    logger.info(
        json.dumps({
            "event": "post_sync_timing", "scope": scope,
            "phase_seconds": phase_seconds, "job_seconds": job_seconds,
        }),
    )


def _timed(seconds: Dict[str, float], name: str, step: Callable[[], Any]) -> None:
    tic = time.perf_counter()
    step()
    seconds[name] = round(time.perf_counter() - tic, 4)
