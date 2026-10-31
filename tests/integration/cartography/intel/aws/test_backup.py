from cartography.intel.aws import backup
from tests.data.aws.backup import LIST_BACKUP_JOBS
from tests.data.aws.backup import LIST_PROTECTED_RESOURCES
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_ACCOUNT_ID = '123456789012'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = 'ws-test_backup'
TEST_ORG_ID = 'org-test_backup'


def _load(neo4j_session, update_tag):
    backup.load_backup_jobs(
        neo4j_session, backup.transform_backup_jobs(LIST_BACKUP_JOBS), TEST_REGION, TEST_ACCOUNT_ID, update_tag,
    )
    backup.load_protected_resources(
        neo4j_session, backup.transform_protected_resources(LIST_PROTECTED_RESOURCES), TEST_REGION,
        TEST_ACCOUNT_ID, update_tag,
    )


def test_backup_nodes_hang_off_the_account_with_the_fields_the_evaluator_reads(neo4j_session):
    create_test_org_account(neo4j_session, TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID)
    _load(neo4j_session, TEST_UPDATE_TAG)

    jobs = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $id})-[:RESOURCE]->(n:AWSBackupJob)
        RETURN n.id AS id, n.resource_arn AS resource_arn, n.recovery_point_arn AS rp,
               n.creation_date AS created, n.recovery_point_delete_after_days AS keep, n.region AS region
        ORDER BY id
        """,
        id=TEST_ACCOUNT_ID,
    ).data()
    assert jobs == [
        {
            'id': 'job-completed-1',
            'resource_arn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
            'rp': 'arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1',
            'created': '2026-10-30T05:00:00+00:00',
            'keep': 35,
            'region': TEST_REGION,
        },
        {
            'id': 'job-running-2',
            'resource_arn': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc',
            'rp': None,
            'created': '2026-10-31T05:00:00+00:00',
            'keep': None,
            'region': TEST_REGION,
        },
    ]

    protected = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $id})-[:RESOURCE]->(n:AWSBackupProtectedResource)
        RETURN n.id AS id, n.resource_type AS type, n.last_backup_time AS last
        """,
        id=TEST_ACCOUNT_ID,
    ).data()
    assert protected == [
        {
            'id': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
            'type': 'EFS',
            'last': '2026-10-30T05:20:00+00:00',
        },
    ]


def test_cleanup_drops_jobs_that_left_the_lookback_window(neo4j_session):
    create_test_org_account(neo4j_session, TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID)
    _load(neo4j_session, TEST_UPDATE_TAG)
    # Next sync: the completed job aged out of ListBackupJobs, the resource is still protected.
    next_tag = TEST_UPDATE_TAG + 1
    backup.load_backup_jobs(
        neo4j_session, backup.transform_backup_jobs(LIST_BACKUP_JOBS[1:]), TEST_REGION, TEST_ACCOUNT_ID, next_tag,
    )
    backup.load_protected_resources(
        neo4j_session, backup.transform_protected_resources(LIST_PROTECTED_RESOURCES), TEST_REGION,
        TEST_ACCOUNT_ID, next_tag,
    )

    backup.cleanup_backup(
        neo4j_session, exposure_job_parameters(TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID, next_tag),
    )

    jobs = {r['id'] for r in neo4j_session.run('MATCH (n:AWSBackupJob) RETURN n.id AS id')}
    protected = {r['id'] for r in neo4j_session.run('MATCH (n:AWSBackupProtectedResource) RETURN n.id AS id')}
    assert jobs == {'job-running-2'}
    assert protected == {'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123'}
