from unittest.mock import MagicMock

import cartography.intel.aws.s3
import tests.data.aws.s3
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_exposure_test_account


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
        workspace_id=TEST_WORKSPACE_ID,
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
        common_job_parameters,
    )

    nodes = neo4j_session.run(
        """
        MATCH (s:S3Bucket{anonymous_access:true}) RETURN s.id;
        """,
    )

    actual_nodes = {
        (
            n['s.id'],
        )
        for n in nodes
    }

    expected_nodes = {
        ('bucket-2',), ('bucket-1',),
    }
    assert actual_nodes == expected_nodes


BPA_ACCOUNT_ID = '333344445555'
BPA_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': BPA_ACCOUNT_ID,
    'ORGANIZATION_ID': 'o-s3-bpa',
    'WORKSPACE_ID': 'ws-s3-bpa',
    'LIMIT_SIZE': 100,
}
ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
# iterationsize of the job's reset; GraphStatement uses it as LIMIT_SIZE whatever the parameters say.
RESET_BATCH = 100


def _seed_bpa_buckets(neo4j_session, buckets):
    create_exposure_test_account(
        neo4j_session, BPA_JOB_PARAMETERS['WORKSPACE_ID'], BPA_JOB_PARAMETERS['ORGANIZATION_ID'], BPA_ACCOUNT_ID,
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        UNWIND $buckets AS b
        MERGE (aa)-[:RESOURCE]->(s:S3Bucket{id: b.name})
        SET s.name = b.name, s.is_public = b.is_public, s.restrict_public_buckets = b.restrict,
            s.ignore_public_acls = b.ignore_acls, s.anonymous_access = b.stale,
            s.anonymous_access_type = CASE WHEN b.stale THEN ['policy'] END
        FOREACH (_ IN CASE WHEN b.acl IS NULL THEN [] ELSE [1] END |
            MERGE (:S3Acl{id: b.name + '-acl', uri: $all_users, permission: b.acl})-[:APPLIES_TO]->(s))
        """,
        account_id=BPA_ACCOUNT_ID, buckets=buckets, all_users=ALL_USERS,
    )


def _public_bpa_buckets(neo4j_session):
    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(s:S3Bucket{anonymous_access: true})
        RETURN s.name AS name, s.anonymous_access_type AS types
        """,
        account_id=BPA_ACCOUNT_ID,
    )
    return {n['name']: sorted(n['types'] or []) for n in nodes}


def test_s3_exposure_honours_bucket_public_access_block(neo4j_session):
    # Buckets with nothing to reset sit on both sides of the stale one (in creation order), so
    # a reset that stops at the first batch (of RESET_BATCH) with no updates never reaches it,
    # whichever end the planner starts from.
    _seed_bpa_buckets(
        neo4j_session, [{'name': f'bpa-clean-{i}'} for i in range(RESET_BATCH + 1)] + [
            # Flagged by an earlier sync, now private.
            {'name': 'bpa-stale', 'stale': True},
        ] + [{'name': f'bpa-clean-after-{i}'} for i in range(RESET_BATCH + 1)] + [
            {'name': 'bpa-policy-public', 'is_public': True},
            # RestrictPublicBuckets: only AWS principals and the owner account reach the bucket.
            {'name': 'bpa-policy-restricted', 'is_public': True, 'restrict': True},
            {'name': 'bpa-acl-public', 'acl': 'READ'},
            # IgnorePublicAcls: S3 ignores the AllUsers grant.
            {'name': 'bpa-acl-ignored', 'acl': 'FULL_CONTROL', 'ignore_acls': True},
            {'name': 'bpa-acl-ignored-policy-public', 'acl': 'READ', 'ignore_acls': True, 'is_public': True},
            {'name': 'bpa-acl-public-policy-restricted', 'acl': 'READ', 'is_public': True, 'restrict': True},
        ],
    )

    run_analysis_job('aws_s3_asset_exposure.json', neo4j_session, BPA_JOB_PARAMETERS)

    assert _public_bpa_buckets(neo4j_session) == {
        'bpa-policy-public': ['policy'],
        'bpa-acl-public': ['acl'],
        'bpa-acl-ignored-policy-public': ['policy'],
        'bpa-acl-public-policy-restricted': ['acl'],
    }


def test_s3_ingest_policy_access_honours_restrict_public_buckets(neo4j_session):
    public_policy = {
        'Policy': '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", '
                  '"Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}',
    }
    restricted = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': False, 'IgnorePublicAcls': False,
            'BlockPublicPolicy': False, 'RestrictPublicBuckets': True,
        },
    }
    _seed_bpa_buckets(
        neo4j_session, [
            {'name': 'ingest-public'}, {'name': 'ingest-restricted'},
            # Restricted on an earlier sync, block configuration since deleted.
            {'name': 'ingest-pab-removed', 'restrict': True},
        ],
    )
    boto3_session = MagicMock()
    boto3_session.client.return_value.get_bucket_policy.return_value = public_policy
    details = [
        ('ingest-public', None, public_policy, None, None, None, None),
        ('ingest-restricted', None, public_policy, None, None, None, restricted),
        ('ingest-pab-removed', None, public_policy, None, None, None, None),
    ]

    cartography.intel.aws.s3.load_s3_details(
        neo4j_session, iter(details), BPA_ACCOUNT_ID, TEST_UPDATE_TAG, BPA_JOB_PARAMETERS, boto3_session,
    )

    nodes = neo4j_session.run(
        """
        MATCH (s:S3Bucket) WHERE s.name STARTS WITH 'ingest-'
        RETURN s.name AS name, s.anonymous_access AS access, s.anonymous_actions AS actions
        """,
    )
    assert {n['name']: (n['access'], n['actions']) for n in nodes} == {
        'ingest-public': (True, ['s3:GetObject']),
        'ingest-restricted': (False, []),
        'ingest-pab-removed': (True, ['s3:GetObject']),
    }
