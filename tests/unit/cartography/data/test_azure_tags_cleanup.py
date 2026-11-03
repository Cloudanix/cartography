from pathlib import Path

from cartography.graph.job import GraphJob

CLEANUP_JOB = (
    Path(__file__).resolve().parents[4] /
    'cartography' / 'data' / 'jobs' / 'cleanup' / 'azure_import_tags_cleanup.json'
)


def test_azure_tags_cleanup_job_parses():
    job = GraphJob.from_json(CLEANUP_JOB.read_text(), parameters={})
    assert job.name == "cleanup Azure tag resources"
    assert len(job.statements) == 2


def test_azure_tags_cleanup_path_is_bounded_like_the_ingest():
    # regression: an unbounded <-[*]- from the subscription ran 30-76 min per batch on US prod, and a pending
    # schema change queued every sync behind it. tag.py only TAGs nodes at (:AzureSubscription)-[*1..4]->(l).
    job = GraphJob.from_json(CLEANUP_JOB.read_text(), parameters={})
    for statement in job.statements:
        assert '<-[*]-' not in statement.query
        assert '(m)<-[*1..4]-(:AzureSubscription' in statement.query
