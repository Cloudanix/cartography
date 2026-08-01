from pathlib import Path

from cartography.graph.job import GraphJob

CLEANUP_JOB = (
    Path(__file__).resolve().parents[4]
    / 'cartography' / 'data' / 'jobs' / 'cleanup' / 'aws_import_tags_cleanup.json'
)


def test_aws_tags_cleanup_job_parses():
    job = GraphJob.from_json(CLEANUP_JOB.read_text(), parameters={})
    assert job.name == "cleanup AWS Tags"
    assert len(job.statements) == 5


def test_aws_tags_cleanup_no_duplicated_workspace_hop():
    # regression: a duplicated CloudanixWorkspace hop made the RedshiftCluster
    # statement unmatchable
    text = CLEANUP_JOB.read_text()
    assert 'CloudanixWorkspace{id: $WORKSPACE_ID})<-[:OWNER]-(:CloudanixWorkspace' not in text


def test_aws_tags_cleanup_never_detach_deletes_scoped_tag_nodes():
    # AWSTag.id is key:value — nodes are shared across accounts, so account-
    # scoped statements may only delete relationships; nodes go only via the
    # orphan catch-all
    job = GraphJob.from_json(CLEANUP_JOB.read_text(), parameters={})
    for statement in job.statements[:-1]:
        assert 'DETACH DELETE' not in statement.query
    assert 'NOT (n)--()' in job.statements[-1].query
