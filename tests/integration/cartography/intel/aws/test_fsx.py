from cartography.intel.aws import fsx
from tests.data.aws.fsx import DESCRIBE_FILE_SYSTEMS as FSX_FILE_SYSTEMS
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_ACCOUNT_ID = '123456789012'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = 'ws-test_fsx'
TEST_ORG_ID = 'org-test_fsx'


def test_fsx_file_systems_hang_off_the_account_and_their_vpc(neo4j_session):
    create_test_org_account(neo4j_session, TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID)
    neo4j_session.run('MERGE (v:AWSVpc{id: $id})', id='vpc-0fsx')

    fsx.load_fsx_file_systems(
        neo4j_session, fsx.transform_fsx_file_systems(FSX_FILE_SYSTEMS), TEST_REGION, TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $id})-[:RESOURCE]->(n:FSxFileSystem)
        OPTIONAL MATCH (n)-[:MEMBER_OF_AWS_VPC]->(v:AWSVpc)
        RETURN n.arn AS arn, n.creation_time AS created, n.automatic_backup_retention_days AS native_days,
               n.subnet_ids AS subnets, n.consolelink IS NOT NULL AS has_link, v.id AS vpc
        ORDER BY arn
        """,
        id=TEST_ACCOUNT_ID,
    ).data()
    assert rows == [
        {
            'arn': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc', 'created': '2026-02-03T04:05:06+00:00',
            'native_days': 7, 'subnets': ['subnet-0a', 'subnet-0b'], 'has_link': True, 'vpc': 'vpc-0fsx',
        },
        {
            'arn': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0def', 'created': '2026-09-01T00:00:00+00:00',
            'native_days': 0, 'subnets': ['subnet-0a'], 'has_link': True, 'vpc': 'vpc-0fsx',
        },
    ]

    # A file system deleted before the next sync is cleaned up, with its VPC edge.
    fsx.load_fsx_file_systems(
        neo4j_session, fsx.transform_fsx_file_systems(FSX_FILE_SYSTEMS[:1]), TEST_REGION, TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG + 1,
    )
    fsx.cleanup_fsx(
        neo4j_session, exposure_job_parameters(TEST_WORKSPACE_ID, TEST_ORG_ID, TEST_ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )
    remaining = {r['id'] for r in neo4j_session.run('MATCH (n:FSxFileSystem) RETURN n.id AS id')}
    assert remaining == {'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc'}
    vpc_members = neo4j_session.run(
        'MATCH (:FSxFileSystem)-[:MEMBER_OF_AWS_VPC]->(v:AWSVpc{id: $id}) RETURN count(*) AS n', id='vpc-0fsx',
    ).single()['n']
    assert vpc_members == 1
