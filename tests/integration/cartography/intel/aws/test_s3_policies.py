import cartography.intel.aws.s3
import tests.data.aws.s3
import json

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '123'


def test_load_bucket_policy(neo4j_session):
    """
    Test the creation of the BucketPolicy node and its relationship with S3Bucket.
    """
    bucket_name = 'bucket-1'
    policy_document = tests.data.aws.s3.BUCKET_POLICIES['bucket-1']['Policy']
    policy_id = json.loads(policy_document)['Id']
    cartography.intel.aws.s3.load_bucket_policy(
        neo4j_session,
        bucket_name,
        policy_document,
        policy_id,
        TEST_UPDATE_TAG
    )

    # Check if BucketPolicy node was created/updated
    result = neo4j_session.run(
        """
        MATCH (bucket:S3Bucket {name: $BucketName})-[r:POLICY]->(policy:BucketPolicy)
        RETURN policy.id, policy.policy_document, r.lastupdated
        """,
        BucketName=bucket_name
    ).single()

    assert result is not None
    assert result['policy.id'] == policy_id
    assert result['policy.policy_document'] == policy_document
    assert result['r.lastupdated'] == TEST_UPDATE_TAG


def test_load_policy_statements(neo4j_session):
    """
    Test the creation of PolicyStatement nodes and their relationships with BucketPolicy.
    """
    policy_id = 'S3PolicyId1'
    policy_statements = json.loads(tests.data.aws.s3.BUCKET_POLICIES['bucket-1']['Policy'])['Statement']
    cartography.intel.aws.s3.load_policy_statements(
        neo4j_session,
        policy_id,
        policy_statements,
        TEST_UPDATE_TAG
    )

    # Check if PolicyStatement nodes were created/updated
    result = neo4j_session.run(
        """
        MATCH (:BucketPolicy {id: $PolicyId})-[r:POLICY_STATEMENT]->(statement:PolicyStatement)
        RETURN statement.id AS sid, statement.effect AS effect, statement.principal AS principal, statement.action AS action, statement.resource AS resource
        """,
        PolicyId=policy_id
    )

    expected_statements = {
        (
            s['Sid'],
            s['Effect'],
            s.get('Principal', ''),
            s['Action'],
            s['Resource']
        )
        for s in policy_statements
    }

    actual_statements = {
        (
            stmt['sid'],
            stmt['effect'],
            stmt['principal'],
            stmt['action'],
            stmt['resource']
        )
        for stmt in result
    }

    assert actual_statements == expected_statements
