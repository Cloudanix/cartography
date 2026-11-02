"""EventBridge rule, Elastic IP and EBS snapshot links reach only the syncing account's nodes."""
from cartography.intel.aws import cloudwatch
from cartography.intel.aws.ec2 import elastic_ip_addresses
from cartography.intel.aws.ec2 import snapshots
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
OWN, OTHER = 'ml-own', 'ml-other'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'ml-ws-own', 'ml-org-own', OWN)
    create_test_org_account(neo4j_session, 'ml-ws-other', 'ml-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:AWSEventBridgeEventBus{id: 'bus-own', arn: 'bus-own'})
        MERGE (other)-[:RESOURCE]->(:AWSEventBridgeEventBus{id: 'bus-other', arn: 'bus-other'})
        MERGE (own)-[:RESOURCE]->(:EC2Instance{id: 'i-own'})
        MERGE (other)-[:RESOURCE]->(:EC2Instance{id: 'i-other'})
        MERGE (own)-[:RESOURCE]->(:NetworkInterface{id: 'eni-own'})
        MERGE (other)-[:RESOURCE]->(:NetworkInterface{id: 'eni-other'})
        MERGE (own)-[:RESOURCE]->(:EBSSnapshot{id: 'snap-own'})
        MERGE (other)-[:RESOURCE]->(:EBSSnapshot{id: 'snap-other'})
        """,
        own=OWN, other=OTHER,
    )


def _pairs(neo4j_session, rel):
    return {
        (r['a'], r['b']) for r in neo4j_session.run(
            f"MATCH (a)-[:{rel}]->(b) RETURN coalesce(a.id, a.arn) AS a, b.id AS b",
        )
    }


def test_event_rules_join_only_the_accounts_bus(neo4j_session):
    _seed(neo4j_session)

    cloudwatch.load_event_rules(
        neo4j_session, [{'Arn': f'rule-{bus}', 'EventBusName': bus} for bus in ('bus-own', 'bus-other')], OWN, TAG,
    )

    assert _pairs(neo4j_session, 'HAS') == {('bus-own', 'rule-bus-own')}


def test_elastic_ips_attach_only_to_the_accounts_instance_and_interface(neo4j_session):
    _seed(neo4j_session)

    elastic_ip_addresses.load_elastic_ip_addresses(
        neo4j_session,
        [
            {'AllocationId': f'eipalloc-{side}', 'InstanceId': f'i-{side}', 'NetworkInterfaceId': f'eni-{side}'}
            for side in ('own', 'other')
        ],
        OWN, TAG,
    )

    assert _pairs(neo4j_session, 'ELASTIC_IP_ADDRESS') == {('i-own', 'eipalloc-own'), ('eni-own', 'eipalloc-own')}


def test_snapshot_volume_links_reach_only_the_accounts_snapshot(neo4j_session):
    _seed(neo4j_session)

    snapshots.load_snapshot_volume_relations(
        neo4j_session, [{'VolumeId': f'vol-{s}', 'SnapshotId': s} for s in ('snap-own', 'snap-other')], OWN, TAG,
    )

    assert _pairs(neo4j_session, 'CREATED_FROM') == {('snap-own', 'vol-snap-own')}
