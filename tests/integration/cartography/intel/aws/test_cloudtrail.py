from unittest.mock import MagicMock

from cartography.intel.aws.cloudtrail import load_trails
from cartography.intel.aws.s3 import _load_s3_policies
from cartography.intel.aws.s3 import load_s3_buckets
from cartography.intel.aws.s3 import parse_policy
from cartography.util import run_analysis_job
from tests.data.aws.cloudtrail import DESCRIBE_TRAILS
from tests.data.aws.s3 import LIST_BUCKETS
from tests.data.aws.s3 import LIST_STATEMENTS

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '12345'


def test_load_cloudtrails(neo4j_session):
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
    load_trails(neo4j_session, DESCRIBE_TRAILS, TEST_ACCOUNT_ID, TEST_WORKSPACE_ID, TEST_UPDATE_TAG)

    nodes = neo4j_session.run(
        """
        MATCH (n:AWSCloudTrailTrail) return n.id
        """,
    )

    actual_nodes = {n["n.id"] for n in nodes}

    expected_nodes = {'trail1_arn', 'trail2_arn'}

    assert expected_nodes == actual_nodes


def test_cloudtrails_analysis(neo4j_session):
    load_s3_buckets(neo4j_session, LIST_BUCKETS, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
    policy = parse_policy('bucket-1', LIST_STATEMENTS)
    _load_s3_policies(neo4j_session, [policy], TEST_ACCOUNT_ID, TEST_UPDATE_TAG, MagicMock())
    load_trails(neo4j_session, DESCRIBE_TRAILS, TEST_ACCOUNT_ID, TEST_WORKSPACE_ID, TEST_UPDATE_TAG)

    nodes = neo4j_session.run(
        """
        MATCH (s3:S3Bucket)<-[:HAS_BUCKET]-(n:AWSCloudTrailTrail) return s3.id, n.id
        """,
    )

    actual_nodes = {(n["n.id"], n["s3.id"]) for n in nodes}

    expected_nodes = {('trail1_arn', 'bucket-1'), ('trail2_arn', 'bucket-2')}

    assert expected_nodes == actual_nodes

    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG + 1,
        "WORKSPACE_ID": TEST_WORKSPACE_ID,
        "AWS_ID": TEST_ACCOUNT_ID,
    }

    run_analysis_job('aws_cloudtrail_asset_exposure.json', neo4j_session, common_job_parameters)

    nodes = neo4j_session.run(
        """
        MATCH (n:AWSCloudTrailTrail{anonymous_access: true}) RETURN n.id
        """,
    )

    actual_nodes = {n["n.id"] for n in nodes}

    expected_nodes = {'trail1_arn'}

    assert expected_nodes == actual_nodes


def _exposure_job_params(update_tag):
    return {
        "UPDATE_TAG": update_tag,
        "WORKSPACE_ID": "ws-trail-reset",
        "ORGANIZATION_ID": "o-trail-reset",
        "AWS_ID": "111111111111",
        "LIMIT_SIZE": 100,
    }


def _trail_exposure(neo4j_session):
    record = neo4j_session.run(
        """
        MATCH (t:AWSCloudTrailTrail{id: 'trail-reset-arn'})
        RETURN t.anonymous_access AS access, t.anonymous_actions AS actions,
               t.anonymous_access_type AS access_type, t.publicContext AS context
        """,
    ).single()
    return dict(record)


def test_cloudtrail_exposure_clears_the_flag_once_the_bucket_is_no_longer_public(neo4j_session):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: 'ws-trail-reset'})-[:OWNER]->(:AWSOrganization{id: 'o-trail-reset'})
              -[:OWNER]->(a:AWSAccount{id: '111111111111'})
        MERGE (a)-[:RESOURCE]->(t:AWSCloudTrailTrail{id: 'trail-reset-arn'})
        SET t.name = 'trail-reset'
        MERGE (t)-[:HAS_BUCKET]->(b:S3Bucket{id: 'trail-reset-bucket'})
        SET b.name = 'trail-reset-bucket', b.anonymous_access = true, b.anonymous_actions = ['s3:GetObject']
        """,
    )

    run_analysis_job('aws_cloudtrail_asset_exposure.json', neo4j_session, _exposure_job_params(1))
    flagged = _trail_exposure(neo4j_session)

    assert flagged["access"] is True
    assert flagged["actions"] == ['s3:GetObject']
    assert flagged["access_type"] == ['public_bucket']
    assert flagged["context"] is not None

    # The bucket stops being public (e.g. Block Public Access): the S3 sync resets it, and the next run of this job
    # must clear what it derived for the trail instead of leaving it "public" forever.
    neo4j_session.run(
        "MATCH (b:S3Bucket{id: 'trail-reset-bucket'}) SET b.anonymous_access = false, b.anonymous_actions = []",
    )
    run_analysis_job('aws_cloudtrail_asset_exposure.json', neo4j_session, _exposure_job_params(2))

    assert _trail_exposure(neo4j_session) == {"access": None, "actions": None, "access_type": None, "context": None}
