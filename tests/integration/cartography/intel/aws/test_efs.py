from cartography.intel.aws import efs
from tests.data.aws.efs import DESCRIBE_FILE_SYSTEMS as EFS_FILE_SYSTEMS
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_ACCOUNT_ID = '123456789012'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = 'ws-test_efs'
TEST_ORG_ID = 'org-test_efs'


def test_efs_file_systems_hang_off_the_account(neo4j_session):
    create_test_org_account(neo4j_session, TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID)

    efs.load_efs_file_systems(
        neo4j_session, efs.transform_efs_file_systems(EFS_FILE_SYSTEMS), TEST_REGION, TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $id})-[:RESOURCE]->(n:EFSFileSystem)
        RETURN n.arn AS arn, n.file_system_id AS fid, n.creation_time AS created, n.encrypted AS encrypted,
               n.kms_key_id AS kms, n.region AS region, n.consolelink IS NOT NULL AS has_link
        ORDER BY arn
        """,
        id=TEST_ACCOUNT_ID,
    ).data()
    assert rows == [
        {
            'arn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123', 'fid': 'fs-0123',
            'created': '2026-01-02T03:04:05+00:00', 'encrypted': True,
            'kms': 'arn:aws:kms:us-east-1:123456789012:key/1111-2222', 'region': TEST_REGION, 'has_link': True,
        },
        {
            'arn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0456', 'fid': 'fs-0456',
            'created': '2026-10-01T00:00:00+00:00', 'encrypted': False, 'kms': None, 'region': TEST_REGION,
            'has_link': True,
        },
    ]

    # A file system deleted before the next sync is cleaned up.
    efs.load_efs_file_systems(
        neo4j_session, efs.transform_efs_file_systems(EFS_FILE_SYSTEMS[:1]), TEST_REGION, TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG + 1,
    )
    efs.cleanup_efs(
        neo4j_session, exposure_job_parameters(TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )
    remaining = {r['id'] for r in neo4j_session.run('MATCH (n:EFSFileSystem) RETURN n.id AS id')}
    assert remaining == {'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123'}
