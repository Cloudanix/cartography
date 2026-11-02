"""SNS, SQS, S3, ElastiCache and Neptune detail statements reach only the syncing account's resources."""
from unittest.mock import patch

from cartography.intel.aws import elasticache
from cartography.intel.aws import neptune
from cartography.intel.aws import s3
from cartography.intel.aws import sns
from cartography.intel.aws import sqs
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = 'rd-own', 'rd-other'


def _seed(neo4j_session, label, key, own_value, other_value):
    create_test_org_account(neo4j_session, 'rd-ws-own', 'rd-org-own', OWN)
    create_test_org_account(neo4j_session, 'rd-ws-other', 'rd-org-other', OTHER)
    neo4j_session.run(
        f"""
        MATCH (own:AWSAccount{{id: $own}}), (other:AWSAccount{{id: $other}})
        MERGE (own)-[:RESOURCE]->(o:{label}{{{key}: $own_value}}) SET o.id = $own_value, o.name = $own_value
        MERGE (other)-[:RESOURCE]->(x:{label}{{{key}: $other_value}}) SET x.id = $other_value, x.name = $other_value
        """,
        own=OWN, other=OTHER, own_value=own_value, other_value=other_value,
    )


def _neighbours(neo4j_session, node_id, rel):
    return {
        r['n'] for r in neo4j_session.run(
            f"MATCH ({{id: $id}})-[:{rel}]-(n) WHERE NOT n:AWSAccount RETURN coalesce(n.id, n.ruleid) AS n",
            id=node_id,
        )
    }


def test_sns_subscriptions_attach_only_to_the_accounts_topic(neo4j_session):
    _seed(neo4j_session, 'AWSSNSTopic', 'id', 'topic-own', 'topic-other')

    for topic in ('topic-own', 'topic-other'):
        sns.load_sns_subscription_topic(
            neo4j_session, [{'SubscriptionArn': f'{topic}:sub', 'region': REGION}], topic, OWN, TAG,
        )

    assert _neighbours(neo4j_session, 'topic-own', 'RESOURCE') == {'topic-own:sub'}
    assert _neighbours(neo4j_session, 'topic-other', 'RESOURCE') == set()


def test_sqs_dead_letter_queues_stay_in_the_account(neo4j_session):
    _seed(neo4j_session, 'SQSQueue', 'id', 'q-own', 'q-other')
    neo4j_session.run("MATCH (a:AWSAccount{id: $own}) MERGE (a)-[:RESOURCE]->(:SQSQueue{id: 'q-own-dlq'})", own=OWN)

    sqs._attach_dead_letter_queues(
        neo4j_session,
        [
            {'arn': 'q-own', 'dead_letter_arn': 'q-own-dlq'},
            {'arn': 'q-own', 'dead_letter_arn': 'q-other'},
            {'arn': 'q-other', 'dead_letter_arn': 'q-own-dlq'},
        ],
        OWN, TAG,
    )

    assert _neighbours(neo4j_session, 'q-own', 'HAS_DEADLETTER_QUEUE') == {'q-own-dlq'}
    assert _neighbours(neo4j_session, 'q-other', 'HAS_DEADLETTER_QUEUE') == set()


def test_s3_details_are_written_only_on_the_accounts_buckets(neo4j_session):
    _seed(neo4j_session, 'S3Bucket', 'id', 'b-own', 'b-other')
    buckets = ('b-own', 'b-other')

    s3._load_s3_acls(
        neo4j_session, [{'id': f'{b}-acl', 'bucket': b} for b in buckets], OWN, TAG, {},
    )
    s3._load_s3_public_access_block(
        neo4j_session, [{'bucket': b, 'restrict_public_buckets': True} for b in buckets], OWN, TAG,
    )
    with patch.object(s3, 'add_bucket_policy_documents', side_effect=lambda policies, _: policies):
        s3._load_s3_policies(
            neo4j_session,
            [{'bucket': b, 'internet_accessible': True, 'accessible_actions': [], 'policyDocument': ''} for b in buckets],
            OWN, TAG, None,
        )
    s3._load_s3_policy_statuses(neo4j_session, [{'bucket': b, 'is_public': True} for b in buckets], OWN, TAG)
    s3._load_s3_policy_statements(neo4j_session, [{'statement_id': f'{b}-st', 'bucket': b} for b in buckets], OWN, TAG)
    s3._load_s3_encryption(neo4j_session, [{'bucket': b, 'default_encryption': True} for b in buckets], OWN, TAG)
    s3._load_s3_versioning(neo4j_session, [{'bucket': b, 'status': 'Enabled'} for b in buckets], OWN, TAG)

    rows = neo4j_session.run(
        """
        MATCH (s:S3Bucket)
        RETURN s.id AS id, [s.restrict_public_buckets, s.policy_document, s.is_public, s.default_encryption,
            s.versioning_status] AS props, size([(s)--(n) WHERE NOT n:AWSAccount | n]) AS links
        """,
    )
    assert {r['id']: (r['props'], r['links']) for r in rows} == {
        'b-own': ([True, '', True, True, 'Enabled'], 2),
        'b-other': ([None, None, None, None, None], 0),
    }


def test_elasticache_clusters_join_groups_only_from_the_account(neo4j_session):
    _seed(neo4j_session, 'ElasticacheCluster', 'id', 'ec-own', 'ec-other')

    elasticache.attach_elasticache_clusters_to_security_groups(
        neo4j_session,
        [{'ARN': c, 'SecurityGroups': [{'SecurityGroupId': f'sg-{c}'}]} for c in ('ec-own', 'ec-other')],
        OWN, TAG,
    )

    assert _neighbours(neo4j_session, 'ec-own', 'MEMBER_OF_EC2_SECURITY_GROUP') == {'sg-ec-own'}
    assert _neighbours(neo4j_session, 'ec-other', 'MEMBER_OF_EC2_SECURITY_GROUP') == set()


def test_neptune_clusters_join_groups_only_from_the_account(neo4j_session):
    _seed(neo4j_session, 'NeptuneCluster', 'id', 'np-own', 'np-other')
    clusters = [
        {'DBClusterArn': c, 'security_groups': [f'sg-{c}'], 'DBSubnetGroup': f'sng-{c}', 'region': REGION}
        for c in ('np-own', 'np-other')
    ]

    neptune._attach_security_groups(neo4j_session, clusters, OWN, TAG)
    neptune._attach_db_subnet_groups(neo4j_session, clusters, OWN, TAG, 'aws')

    assert _neighbours(neo4j_session, 'np-own', 'MEMBER_OF_EC2_SECURITY_GROUP|MEMBER_OF_DB_SUBNET_GROUP') == {
        'sg-np-own', f'arn:aws:rds:{REGION}:{OWN}:subgrp:sng-np-own',
    }
    assert _neighbours(neo4j_session, 'np-other', 'MEMBER_OF_EC2_SECURITY_GROUP|MEMBER_OF_DB_SUBNET_GROUP') == set()
