from cartography.intel.aws.ec2 import tgw
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

REGION = 'us-east-1'
OLD_TAG = 1_793_500_000
NEW_TAG = 1_793_600_000
ACCOUNT_A = '777777777809'
ACCOUNT_B = '888888888809'


def _attachment(attachment_id, resource_type):
    return {
        'TransitGatewayAttachmentId': attachment_id, 'TransitGatewayId': 'tgw-ppa', 'State': 'available',
        'ResourceType': resource_type,
    }


def _attachments(neo4j_session):
    rows = neo4j_session.run(
        """
        MATCH (a:AWSAccount)-[:RESOURCE]->(t:AWSTransitGatewayAttachment)
        WHERE t.attachment_id STARTS WITH 'tgw-attach-ppa'
        RETURN a.id AS account, t.id AS id, t.attachment_id AS attachment_id, t.arn AS arn
        """,
    )
    return {(r['account'], r['id'], r['attachment_id'], r['arn'].split(':')[4]) for r in rows}


def test_peering_attachment_gets_a_node_per_account_and_survives_the_other_accounts_cleanup(neo4j_session):
    # Two tenants' accounts both list one peering attachment (the two peered gateways' owners). A VPC attachment
    # has a real owner and keeps a single node.
    create_test_org_account(neo4j_session, 'ws-ppa-a', 'o-ppa-a', ACCOUNT_A)
    create_test_org_account(neo4j_session, 'ws-ppa-b', 'o-ppa-b', ACCOUNT_B)
    tgw.load_tgw_attachments(
        neo4j_session, [_attachment('tgw-attach-ppa-peer', 'peering')], REGION, ACCOUNT_A, OLD_TAG,
    )
    tgw.load_tgw_attachments(
        neo4j_session,
        [_attachment('tgw-attach-ppa-peer', 'peering'), _attachment('tgw-attach-ppa-vpn', 'client-vpn')],
        REGION, ACCOUNT_B, NEW_TAG,
    )

    assert _attachments(neo4j_session) == {
        (ACCOUNT_A, f'tgw-attach-ppa-peer|{ACCOUNT_A}', 'tgw-attach-ppa-peer', ACCOUNT_A),
        (ACCOUNT_B, f'tgw-attach-ppa-peer|{ACCOUNT_B}', 'tgw-attach-ppa-peer', ACCOUNT_B),
        (ACCOUNT_B, f'tgw-attach-ppa-vpn|{ACCOUNT_B}', 'tgw-attach-ppa-vpn', ACCOUNT_B),
    }

    # Account A syncs again without the attachment: its stale node goes, B's copy stays.
    run_cleanup_job(
        'aws_import_tgw_cleanup.json', neo4j_session,
        exposure_job_parameters('ws-ppa-a', 'o-ppa-a', ACCOUNT_A, NEW_TAG + 1),
    )
    assert {row[0] for row in _attachments(neo4j_session)} == {ACCOUNT_B}


def test_owned_attachment_types_keep_the_attachment_id_as_node_id():
    assert tgw.tgw_attachment_node_id(_attachment('tgw-attach-1', 'vpc'), ACCOUNT_A) == 'tgw-attach-1'
    assert tgw.tgw_attachment_node_id(_attachment('tgw-attach-1', 'vpn'), ACCOUNT_A) == 'tgw-attach-1'
    assert tgw.tgw_attachment_node_id(
        {'TransitGatewayAttachmentId': 'tgw-attach-1'}, ACCOUNT_A,
    ) == 'tgw-attach-1'
    assert tgw.tgw_attachment_node_id(_attachment('tgw-attach-1', 'tgw-peering'), ACCOUNT_A) == \
        f'tgw-attach-1|{ACCOUNT_A}'
