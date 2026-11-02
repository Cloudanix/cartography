from importlib.resources import read_text

from cartography.graph.job import GraphJob
from cartography.intel import dns
from cartography.intel.aws import cloudtrail
from cartography.intel.aws.ec2 import tgw
from tests.integration.cartography.intel.aws.common import create_test_org_account

REGION = 'us-east-1'
OWNER_TAG, PARTICIPANT_TAG = 100, 200
# Hub account owning a transit gateway, and a customer of another workspace it is shared with (RAM).
HUB, SPOKE = 'fr-hub', 'fr-spoke'
TGW_ID = 'tgw-fr0000000000001'
TGW_ARN = f'arn:aws:ec2:{REGION}:{HUB}:transit-gateway/{TGW_ID}'


def _cleanup(neo4j_session, filename, workspace_id, account_id, update_tag):
    GraphJob.run_from_json(
        neo4j_session, read_text('cartography.data.jobs.cleanup', filename), {
            'WORKSPACE_ID': workspace_id, 'ORGANIZATION_ID': f'{workspace_id}-org', 'AWS_ID': account_id,
            'UPDATE_TAG': update_tag, 'LIMIT_SIZE': 100,
        },
    )


def _gateway(description):
    return {
        'TransitGatewayId': TGW_ID, 'TransitGatewayArn': TGW_ARN, 'State': 'available', 'OwnerId': HUB,
        'Description': description,
    }


def _vpc_attachment(attachment_id, vpc_owner, vpc_id, subnet_id):
    return [
        {
            'TransitGatewayAttachmentId': attachment_id, 'TransitGatewayId': TGW_ID, 'State': 'available',
            'ResourceType': 'vpc', 'ResourceOwnerId': vpc_owner, 'ResourceId': vpc_id,
        },
        {
            'TransitGatewayAttachmentId': attachment_id, 'TransitGatewayId': TGW_ID, 'State': 'available',
            'VpcId': vpc_id, 'VpcOwnerId': vpc_owner, 'SubnetIds': [subnet_id],
        },
    ]


VPN_ATTACHMENT = {
    'TransitGatewayAttachmentId': 'tgw-attach-fr-vpn', 'TransitGatewayId': TGW_ID, 'State': 'available',
    'ResourceType': 'vpn', 'TransitGatewayOwnerId': HUB, 'ResourceOwnerId': HUB, 'ResourceId': 'vpn-fr-1',
}


def _seed_tgw(neo4j_session):
    create_test_org_account(neo4j_session, 'fr-ws-hub', 'fr-ws-hub-org', HUB)
    create_test_org_account(neo4j_session, 'fr-ws-spoke', 'fr-ws-spoke-org', SPOKE)
    neo4j_session.run(
        """
        MATCH (h:AWSAccount{id: $hub}), (s:AWSAccount{id: $spoke})
        SET h.lastupdated = 1, s.lastupdated = 1
        MERGE (s)-[:RESOURCE]->(:AWSVpc{id: 'vpc-fr-spoke', lastupdated: 1})
        """,
        hub=HUB, spoke=SPOKE,
    )
    hub_attachments = _vpc_attachment('tgw-attach-fr-hub', HUB, 'vpc-fr-hub', 'subnet-fr-hub') + \
        _vpc_attachment('tgw-attach-fr-spoke', SPOKE, 'vpc-fr-spoke', 'subnet-fr-spoke') + [VPN_ATTACHMENT]
    tgw.load_transit_gateways(neo4j_session, [_gateway('hub network')], REGION, HUB, OWNER_TAG)
    tgw.load_tgw_attachments(neo4j_session, hub_attachments, REGION, HUB, OWNER_TAG)
    # The spoke sees the shared gateway (without its description), its own attachment and the hub's VPN.
    tgw.load_transit_gateways(neo4j_session, [_gateway(None)], REGION, SPOKE, PARTICIPANT_TAG)
    tgw.load_tgw_attachments(
        neo4j_session,
        _vpc_attachment('tgw-attach-fr-spoke', SPOKE, 'vpc-fr-spoke', 'subnet-fr-spoke') + [VPN_ATTACHMENT],
        REGION, SPOKE, PARTICIPANT_TAG,
    )


def _claims(neo4j_session, node_id):
    return {
        r['id'] for r in neo4j_session.run(
            "MATCH (a:AWSAccount)-[:RESOURCE]->({id: $id}) RETURN a.id AS id", id=node_id,
        )
    }


def test_shared_transit_gateway_is_claimed_and_written_by_its_owner_only(neo4j_session):
    _seed_tgw(neo4j_session)

    assert _claims(neo4j_session, TGW_ARN) == {HUB}
    gateway = neo4j_session.run(
        """
        MATCH (t:AWSTransitGateway{id: $arn})-[:SHARED_WITH]->(:AWSAccount{id: $spoke})
        MATCH (h:AWSAccount{id: $hub})
        RETURN t.description AS description, t.lastupdated AS tag, h.lastupdated AS hub_tag
        """,
        arn=TGW_ARN, spoke=SPOKE, hub=HUB,
    ).single()
    assert (gateway['description'], gateway['tag'], gateway['hub_tag']) == ('hub network', OWNER_TAG, 1)

    # The spoke VPC's attachment is the spoke's: the hub neither claims it nor writes onto the spoke VPC.
    assert _claims(neo4j_session, 'tgw-attach-fr-spoke') == {SPOKE}
    assert _claims(neo4j_session, 'tgw-attach-fr-hub') == {HUB}
    # A VPN attachment lives in the gateway owner's account, whoever lists it.
    assert _claims(neo4j_session, 'tgw-attach-fr-vpn') == {HUB}
    assert neo4j_session.run(
        "MATCH (v:AWSVpc{id: 'vpc-fr-spoke'}) RETURN v.lastupdated AS tag",
    ).single()['tag'] == PARTICIPANT_TAG


def test_tgw_cleanup_never_deletes_the_other_tenants_gateway_or_attachment(neo4j_session):
    _seed_tgw(neo4j_session)

    # Each account's cleanup runs with its own tag right after its load.
    _cleanup(neo4j_session, 'aws_import_tgw_cleanup.json', 'fr-ws-spoke', SPOKE, PARTICIPANT_TAG)
    _cleanup(neo4j_session, 'aws_import_tgw_cleanup.json', 'fr-ws-hub', HUB, OWNER_TAG)

    assert _claims(neo4j_session, TGW_ARN) == {HUB}
    attached = {
        r['id'] for r in neo4j_session.run(
            "MATCH (a:AWSTransitGatewayAttachment)-[:ATTACHED_TO]->(:AWSTransitGateway{id: $arn}) RETURN a.id AS id",
            arn=TGW_ARN,
        )
    }
    assert attached == {'tgw-attach-fr-hub', 'tgw-attach-fr-spoke', 'tgw-attach-fr-vpn'}


def test_cloudtrail_links_only_a_log_bucket_of_its_workspace(neo4j_session):
    # Central log archive in a sibling account (linked), and a bucket of another tenant (not linked,
    # not stamped). An unknown bucket is not created.
    create_test_org_account(neo4j_session, 'fr-ws-ct', 'fr-ws-ct-org', 'fr-ct-a1')
    create_test_org_account(neo4j_session, 'fr-ws-ct', 'fr-ws-ct-org', 'fr-ct-archive')
    create_test_org_account(neo4j_session, 'fr-ws-ct-other', 'fr-ws-ct-other-org', 'fr-ct-other')
    neo4j_session.run(
        """
        MATCH (archive:AWSAccount{id: 'fr-ct-archive'}), (other:AWSAccount{id: 'fr-ct-other'})
        MERGE (archive)-[:RESOURCE]->(:S3Bucket{id: 'fr-ct-archive-logs', name: 'fr-ct-archive-logs', lastupdated: 1})
        MERGE (other)-[:RESOURCE]->(:S3Bucket{id: 'fr-ct-vendor-logs', name: 'fr-ct-vendor-logs', lastupdated: 1})
        """,
    )
    trails = [
        {'TrailARN': f'fr-ct-trail-{bucket}', 'Name': bucket, 'S3BucketName': bucket, 'consolelink': ''}
        for bucket in ('fr-ct-archive-logs', 'fr-ct-vendor-logs', 'fr-ct-unknown-logs')
    ]

    cloudtrail.load_trails(neo4j_session, trails, 'fr-ct-a1', 'fr-ws-ct', OWNER_TAG)

    links = {
        (r['trail'], r['bucket']) for r in neo4j_session.run(
            "MATCH (t:AWSCloudTrailTrail)-[:HAS_BUCKET]->(b:S3Bucket) WHERE t.id STARTS WITH 'fr-ct-' "
            "RETURN t.id AS trail, b.id AS bucket",
        )
    }
    assert links == {('fr-ct-trail-fr-ct-archive-logs', 'fr-ct-archive-logs')}
    buckets = {
        (r['id'], r['tag']) for r in neo4j_session.run(
            "MATCH (b:S3Bucket) WHERE b.id STARTS WITH 'fr-ct-' RETURN b.id AS id, b.lastupdated AS tag",
        )
    }
    assert buckets == {('fr-ct-archive-logs', 1), ('fr-ct-vendor-logs', 1)}
    assert _claims(neo4j_session, 'fr-ct-trail-fr-ct-vendor-logs') == {'fr-ct-a1'}


def test_dns_ip_node_is_not_stamped_by_each_tenant(neo4j_session):
    neo4j_session.run(
        """
        MERGE (:Ip{id: '10.250.0.1', ip: '10.250.0.1', lastupdated: 1})
        MERGE (:DNSRecord{id: 'fr-es.example+A'})
        """,
    )

    dns._link_ip_to_A_record(neo4j_session, OWNER_TAG, ['10.250.0.1', '10.250.0.2'], 'fr-es.example+A')

    ips = {
        (r['id'], r['tag']) for r in neo4j_session.run(
            "MATCH (:DNSRecord{id: 'fr-es.example+A'})-[:DNS_POINTS_TO]->(i:Ip) "
            "RETURN i.id AS id, i.lastupdated AS tag",
        )
    }
    assert ips == {('10.250.0.1', 1), ('10.250.0.2', OWNER_TAG)}
