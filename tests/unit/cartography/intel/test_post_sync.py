from unittest.mock import patch

import pytest

from cartography.intel import post_sync
from cartography.util import collect_failed_analysis_jobs

ALL_SYNCS = ["ec2:instance", "rds"]
PHASES = post_sync.Phases(link=("link.json",), exposure=("exp1.json", "exp2.json"), posture=("posture.json",))
EVERY_STEP = ["link.json", "exp1.json", "exp2.json", "layers", "posture.json"]
JOBS_ONLY = ["link.json", "exp1.json", "exp2.json", "posture.json"]


def _run(requested, defer=False, phases=PHASES):
    """Run the post-sync work and return what ran, in order."""
    ran = []
    params = {"AWS_ID": "123", "UPDATE_TAG": 1}
    with patch.object(post_sync, "run_analysis_job", side_effect=lambda job, *_args: ran.append(job)):
        post_sync.run(phases, lambda _s, _p: ran.append("layers"), None, params, requested, ALL_SYNCS, defer=defer)
    return ran


@pytest.mark.parametrize("requested", [["analysis"], ["exposure_layers"], None, [], ["rds", "ec2:instance"]])
def test_dedicated_or_full_run_runs_every_phase_in_order(requested):
    assert _run(requested) == EVERY_STEP


@pytest.mark.parametrize("defer", [False, True])
def test_dedicated_run_ignores_defer(defer):
    assert _run(["analysis"], defer=defer) == EVERY_STEP


def test_group_subrun_keeps_todays_jobs_without_layers():
    # A caller that does not defer gets what every subrun ran before: the jobs, not the exposure layers.
    assert _run(["rds"]) == JOBS_ONLY


def test_group_subrun_skips_everything_when_its_run_defers():
    assert _run(["rds"], defer=True) == []


def test_a_failing_job_is_reported_and_later_phases_still_run():
    ran = []

    def job(name, *_args):
        if name == "exp1.json":
            raise RuntimeError("bug")
        ran.append(name)

    with collect_failed_analysis_jobs() as failed, patch("cartography.util.run_analysis_job", side_effect=job):
        post_sync.run(PHASES, lambda _s, _p: ran.append("layers"), None, {"AWS_ID": "123"}, ["analysis"], ALL_SYNCS)

    assert ran == ["link.json", "exp2.json", "layers", "posture.json"]
    assert failed == [{"job": "exp1.json", "scope": {"AWS_ID": "123"}}]


def test_a_failing_exposure_layers_step_is_reported_not_raised():
    def boom(_session, _params):
        raise RuntimeError("bug")

    with collect_failed_analysis_jobs() as failed, patch.object(post_sync, "run_analysis_job"):
        post_sync.run(post_sync.Phases(), boom, None, {"AWS_ID": "123"}, ["analysis"], ALL_SYNCS)

    assert failed == [{"job": "exposure_layers", "scope": {"AWS_ID": "123"}}]


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (None, False), ({}, False), ({"deferAnalysis": False}, False), ({"deferAnalysis": "true"}, False),
        ({"deferAnalysis": True}, True),
    ],
)
def test_defer_requested_reads_the_request_param(params, expected):
    assert post_sync.defer_requested(params) is expected


def test_post_sync_keys_are_not_resource_syncs():
    assert post_sync.POST_SYNC_SYNCS == {"analysis", "exposure_layers"}
