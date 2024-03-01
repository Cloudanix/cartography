import cartography.intel.aws.s3
import tests.data.aws.s3
from cartography.util import run_analysis_job


TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '123'


def test_load_s3_buckets(neo4j_session, *args):
    """
    Ensure that expected buckets get loaded with their key fields.
    """
    neo4j_session.run(
        """
            MERGE (aws:AWSAccount{id: $aws_account_id})<-[:OWNER]-(:CloudanixWorkspace{id: $workspace_id})
            ON CREATE SET aws.firstseen = timestamp()
            SET aws.lastupdated = $aws_update_tag
            """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
        workspace_id=TEST_WORKSPACE_ID
    )
    data = tests.data.aws.s3.LIST_BUCKETS
    cartography.intel.aws.s3.load_s3_buckets(neo4j_session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
    expected_nodes = {
        (
            "bucket-1",
            "bucket-1",
            "eu-west-1",
        ),
        (
            "bucket-2",
            "bucket-2",
            "me-south-1",
        ),
        (
            "bucket-3",
            "bucket-3",
            None,
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (s:S3Bucket) return s.id, s.name, s.region
        """,
    )
    actual_nodes = {
        (
            n['s.id'],
            n['s.name'],
            n['s.region'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes


def test_load_s3_encryption(neo4j_session, *args):
    """
    Ensure that expected bucket gets loaded with their encryption fields.
    """
    data = tests.data.aws.s3.GET_ENCRYPTION
    cartography.intel.aws.s3._load_s3_encryption(neo4j_session, data, TEST_UPDATE_TAG)

    expected_nodes = {
        (
            "bucket-1",
            True,
            "aws:kms",
            "arn:aws:kms:eu-east-1:000000000000:key/9a1ad414-6e3b-47ce-8366-6b8f26ba467d",
            False,
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (s:S3Bucket)
        WHERE s.id = 'bucket-1'
        RETURN s.id, s.default_encryption, s.encryption_algorithm, s.encryption_key_id, s.bucket_key_enabled
        """,
    )
    actual_nodes = {
        (
            n['s.id'],
            n['s.default_encryption'],
            n['s.encryption_algorithm'],
            n['s.encryption_key_id'],
            n['s.bucket_key_enabled'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes


def test_load_s3_policies(neo4j_session, *args):
    """
    Ensure that expected bucket policy statements are loaded with their key fields.
    """
    data = cartography.intel.aws.s3.parse_policy_statements("bucket-1", tests.data.aws.s3.LIST_STATEMENTS)
    cartography.intel.aws.s3._load_s3_policy_statements(neo4j_session, data, TEST_UPDATE_TAG)

    expected_nodes = [
        (
            "S3PolicyId1",
            "2012-10-17",
            "bucket-1/policy_statement/1/IPAllow",
            "IPAllow",
            "Deny",
            "\"*\"",
            "s3:*",
            [
                "arn:aws:s3:::DOC-EXAMPLE-BUCKET",
                "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*",
            ],
            "{\"NotIpAddress\": {\"aws:SourceIp\": \"54.240.143.0/24\"}}",
        ),
        (
            "S3PolicyId1",
            "2012-10-17",
            "bucket-1/policy_statement/2/S3PolicyId2",
            "S3PolicyId2",
            "Deny",
            "\"*\"",
            "s3:*",
            "arn:aws:s3:::DOC-EXAMPLE-BUCKET/taxdocuments/*",
            "{\"Null\": {\"aws:MultiFactorAuthAge\": true}}",
        ),
        (
            "S3PolicyId1",
            "2012-10-17",
            "bucket-1/policy_statement/3/",
            "",
            "Allow",
            "\"*\"",
            ["s3:GetObject"],
            "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*",
            None,
        ),
    ]

    nodes = neo4j_session.run(
        """
        MATCH (s:S3PolicyStatement)
        WHERE s.bucket = 'bucket-1'
        RETURN
        s.policy_id, s.policy_version, s.id, s.sid, s.effect, s.principal, s.action, s.resource, s.condition
        """,
    )
    actual_nodes = [
        (
            n['s.policy_id'],
            n['s.policy_version'],
            n['s.id'],
            n['s.sid'],
            n['s.effect'],
            n['s.principal'],
            n['s.action'],
            n['s.resource'],
            n['s.condition'],
        )
        for n in nodes
    ]
    assert len(actual_nodes) == 3
    for node in actual_nodes:
        assert node in expected_nodes

    actual_relationships = neo4j_session.run(
        """
        MATCH (:S3Bucket{id:"bucket-1"})-[r:POLICY_STATEMENT]->(:S3PolicyStatement) RETURN count(r)
        """,
    )

    assert actual_relationships.single().value() == 3


def test_load_s3_policy_statuses(neo4j_session, *args):
    cartography.intel.aws.s3._load_s3_policy_statuses(neo4j_session, tests.data.aws.s3.LIST_STATUSES, TEST_UPDATE_TAG)

    common_job_parameters = {
        'UPDATE_TAG': TEST_UPDATE_TAG + 1,  # Simulate a new sync run finished so the old update tag is obsolete now
        'AWS_ID': TEST_ACCOUNT_ID,
        'WORKSPACE_ID': TEST_WORKSPACE_ID,
    }

    run_analysis_job(
        'aws_s3_asset_exposure.json',
        neo4j_session,
        common_job_parameters
    )

    nodes = neo4j_session.run(
        """
        MATCH (s:S3Bucket{anonymous_access:true}) RETURN s.id;
        """
    )

    actual_nodes = {
        (
            n['s.id'],
        )
        for n in nodes
    }

    expected_nodes = {
        ('bucket-2',), ('bucket-1',)
    }
    assert actual_nodes == expected_nodes
