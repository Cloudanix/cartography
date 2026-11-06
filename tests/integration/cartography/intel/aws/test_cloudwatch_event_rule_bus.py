import cartography.intel.aws.cloudwatch
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
NEXT_UPDATE_TAG = 123456790
ACCOUNT_ID = '777777777792'
OTHER_ACCOUNT_ID = '888888888892'


def _bus(account_id, region, name):
    # Every account has a bus named "default" in every region: the name repeats across regions and tenants.
    arn = f'arn:aws:events:{region}:{account_id}:event-bus/{name}'
    return {'Name': name, 'Arn': arn, 'region': region, 'consolelink': '', 'Policy': None}


def _rule(name, bus_name, region='us-east-1'):
    # ListRules returns the bus NAME in EventBusName (its shape forbids ':'), never the bus ARN.
    return {
        'Name': name,
        'Arn': f'arn:aws:events:{region}:{ACCOUNT_ID}:rule/{name}',
        'EventBusName': bus_name,
        'State': 'ENABLED',
        'region': region,
        'consolelink': '',
    }


def _rule_links(neo4j_session, rule_name):
    rows = neo4j_session.run(
        """
        MATCH (rule:AWSEventBridgeRule{name: $name})
        OPTIONAL MATCH (bus:AWSEventBridgeEventBus)-[:HAS]->(rule)
        OPTIONAL MATCH (owner:AWSAccount)-[:RESOURCE]->(rule)
        RETURN collect(DISTINCT bus.id) AS buses, collect(DISTINCT owner.id) AS owners
        """,
        name=rule_name,
    ).single()
    return set(rows['buses']), set(rows['owners'])


def test_event_rule_links_its_own_accounts_bus_in_its_region(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-evb', 'o-evb', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-evb-other', 'o-evb-other', OTHER_ACCOUNT_ID)
    cartography.intel.aws.cloudwatch.load_event_buses(
        neo4j_session,
        [_bus(ACCOUNT_ID, 'us-east-1', 'default'), _bus(ACCOUNT_ID, 'us-west-2', 'default')],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.cloudwatch.load_event_buses(
        neo4j_session, [_bus(OTHER_ACCOUNT_ID, 'us-east-1', 'default')], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    cartography.intel.aws.cloudwatch.load_event_rules(
        neo4j_session, [_rule('evb-rule', 'default'), _rule('evb-rule-no-bus', 'missing-bus')],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    # Only the account's own "default" bus in the rule's region: never another region's, never another tenant's.
    assert _rule_links(neo4j_session, 'evb-rule') == (
        {f'arn:aws:events:us-east-1:{ACCOUNT_ID}:event-bus/default'}, {ACCOUNT_ID},
    )
    # A rule whose bus was not synced is still owned by the account.
    assert _rule_links(neo4j_session, 'evb-rule-no-bus') == (set(), {ACCOUNT_ID})


def test_event_rule_cleanup_removes_stale_bus_link(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-evb', 'o-evb', ACCOUNT_ID)
    cartography.intel.aws.cloudwatch.load_event_buses(
        neo4j_session,
        [_bus(ACCOUNT_ID, 'us-east-1', 'default'), _bus(ACCOUNT_ID, 'us-east-1', 'evb-custom')],
        ACCOUNT_ID, NEXT_UPDATE_TAG,
    )
    cartography.intel.aws.cloudwatch.load_event_rules(
        neo4j_session, [_rule('evb-moved-rule', 'default')], ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.cloudwatch.load_event_rules(
        neo4j_session, [_rule('evb-moved-rule', 'evb-custom')], ACCOUNT_ID, NEXT_UPDATE_TAG,
    )

    run_cleanup_job(
        'aws_import_cloudwatch_event_rules_cleanup.json', neo4j_session,
        exposure_job_parameters('ws-evb', 'o-evb', ACCOUNT_ID, NEXT_UPDATE_TAG),
    )

    assert _rule_links(neo4j_session, 'evb-moved-rule') == (
        {f'arn:aws:events:us-east-1:{ACCOUNT_ID}:event-bus/evb-custom'}, {ACCOUNT_ID},
    )
