"""
SQL lookups reach servers, databases and resource groups only through the subscription being synced
(AGENTS.md "Tenant isolation"). The API data names the parent by ARM id; an id that points into another
customer's subscription must not link to that customer's node.
"""
from cartography.intel.azure import sql
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

SERVER_A = arm_id(SUB_A, 'Microsoft.Sql/servers/sql')
SERVER_B = arm_id(SUB_B, 'Microsoft.Sql/servers/sql')
# Returned while syncing SUB_A, but its id names SUB_B: the id's subscription segment is not an anchor.
SERVER_FOREIGN_ID = arm_id(SUB_B, 'Microsoft.Sql/servers/sql-foreign')
DB_A = f'{SERVER_A}/databases/db'
DB_B = f'{SERVER_B}/databases/db'
DB_FOREIGN_ID = f'{SERVER_FOREIGN_ID}/databases/db'
FW_B = f'{SERVER_B}/firewallRules/all'

SERVER_CHILDREN = [
    (sql._load_server_dns_aliases, 'AzureServerDNSAlias', 'USED_BY', 'dnsAliases'),
    (sql._load_server_ad_admins, 'AzureServerADAdministrator', 'ADMINISTERED_BY', 'administrators'),
    (sql._load_recoverable_databases, 'AzureRecoverableDatabase', 'RESOURCE', 'recoverableDatabases'),
    (sql._load_restorable_dropped_databases, 'AzureRestorableDroppedDatabase', 'RESOURCE', 'droppedDatabases'),
    (sql._load_failover_groups, 'AzureFailoverGroup', 'RESOURCE', 'failoverGroups'),
    (sql._load_elastic_pools, 'AzureElasticPool', 'RESOURCE', 'elasticPools'),
    (sql._load_firewall_rules, 'AzureFirewallRule', 'HAS', 'firewallRules'),
]
DATABASE_CHILDREN = [
    (sql._load_replication_links, 'AzureReplicationLink', 'replicationLinks'),
    (sql._load_db_threat_detection_policies, 'AzureDatabaseThreatDetectionPolicy', 'securityAlertPolicies'),
    (sql._load_restore_points, 'AzureRestorePoint', 'restorePoints'),
    (sql._load_transparent_data_encryptions, 'AzureTransparentDataEncryption', 'transparentDataEncryption'),
]


def _seed_other_customer(neo4j_session):
    seed_node(neo4j_session, SUB_B, 'AzureSQLServer', SERVER_B)
    seed_node(neo4j_session, SUB_B, 'AzureSQLDatabase', DB_B, 'AzureSQLServer', SERVER_B)
    neo4j_session.run(
        "MATCH (:AzureSubscription{id: $sub})-[:RESOURCE]->(s:AzureSQLServer{id: $server}) "
        "MERGE (s)-[:HAS]->(:AzureFirewallRule{id: $rule})",
        sub=SUB_B, server=SERVER_B, rule=FW_B,
    )


def _children(parents, segment, field):
    """One child per parent, keyed under that parent, as the API returns them (parent id on the child)."""
    return [{'id': f'{parent}/{segment}/x', 'name': 'x', field: parent} for parent in parents]


def _load_servers_and_databases(neo4j_session):
    sql.load_server_data(
        neo4j_session, SUB_A, [{'id': SERVER_A, 'name': 'sql'}, {'id': SERVER_FOREIGN_ID, 'name': 'sql-foreign'}],
        UPDATE_TAG,
    )
    sql._load_databases(
        neo4j_session, SUB_A,
        [
            {'id': DB_A, 'name': 'db', 'server_id': SERVER_A},
            {'id': DB_FOREIGN_ID, 'name': 'db', 'server_id': SERVER_FOREIGN_ID},
            {'id': f'{DB_B}-x', 'name': 'db', 'server_id': SERVER_B},
        ],
        UPDATE_TAG,
    )


def test_sql_lookups_stay_in_the_syncing_subscription(neo4j_session):
    seed_customers(neo4j_session)
    _seed_other_customer(neo4j_session)
    _load_servers_and_databases(neo4j_session)

    # Servers and databases: grouped under the syncing subscription, never the one their id names.
    for label, node_id in [
        ('AzureSQLServer', SERVER_A), ('AzureSQLServer', SERVER_FOREIGN_ID),
        ('AzureSQLDatabase', DB_A), ('AzureSQLDatabase', DB_FOREIGN_ID),
    ]:
        assert resource_group_of(neo4j_session, label, node_id) == {rg_id(SUB_A)}, node_id
    assert linked_ids(neo4j_session, 'AzureSQLServer', SERVER_B, 'RESOURCE', 'AzureSQLDatabase') == {DB_B}
    assert resource_group_of(neo4j_session, 'AzureSQLDatabase', f'{DB_B}-x') == set()

    for load, label, rel, segment in SERVER_CHILDREN:
        load(neo4j_session, SUB_A, _children([SERVER_A, SERVER_FOREIGN_ID, SERVER_B], segment, 'server_id'), UPDATE_TAG)
        assert linked_ids(neo4j_session, 'AzureSQLServer', SERVER_A, rel, label) == {f'{SERVER_A}/{segment}/x'}
        assert linked_ids(neo4j_session, 'AzureSQLServer', SERVER_B, rel, label) - {FW_B} == set(), label
        assert resource_group_of(neo4j_session, label, f'{SERVER_FOREIGN_ID}/{segment}/x') == {rg_id(SUB_A)}
        assert resource_group_of(neo4j_session, label, f'{SERVER_B}/{segment}/x') == set(), label

    for load, label, segment in DATABASE_CHILDREN:
        load(neo4j_session, SUB_A, _children([DB_A, DB_FOREIGN_ID, DB_B], segment, 'database_id'), UPDATE_TAG)
        assert linked_ids(neo4j_session, 'AzureSQLDatabase', DB_A, 'CONTAINS', label) == {f'{DB_A}/{segment}/x'}
        assert linked_ids(neo4j_session, 'AzureSQLDatabase', DB_B, 'CONTAINS', label) == set(), label
        assert resource_group_of(neo4j_session, label, f'{DB_FOREIGN_ID}/{segment}/x') == {rg_id(SUB_A)}
        assert resource_group_of(neo4j_session, label, f'{DB_B}/{segment}/x') == set(), label


def test_private_endpoint_connections_stay_in_the_syncing_subscription(neo4j_session):
    seed_customers(neo4j_session)
    _seed_other_customer(neo4j_session)
    _load_servers_and_databases(neo4j_session)

    def server(server_id):
        pec = {'id': f'{server_id}/privateEndpointConnections/pec', 'properties': {'private_endpoint': {'id': 'pe'}}}
        return {'id': server_id, 'private_endpoint_connections': [pec]}

    sql.load_server_private_endpoint_connection(
        neo4j_session, SUB_A, [server(SERVER_A), server(SERVER_FOREIGN_ID), server(SERVER_B)], UPDATE_TAG,
    )

    label = 'AzureServerPrivateEndpointConnection'
    assert linked_ids(neo4j_session, 'AzureSQLServer', SERVER_A, 'HAS', label) == {
        f'{SERVER_A}/privateEndpointConnections/pec',
    }
    assert linked_ids(neo4j_session, 'AzureSQLServer', SERVER_B, 'HAS', label) == set()
    assert resource_group_of(neo4j_session, label, f'{SERVER_FOREIGN_ID}/privateEndpointConnections/pec') == {
        rg_id(SUB_A),
    }


def test_firewall_lookups_stay_in_the_syncing_subscription(neo4j_session):
    seed_customers(neo4j_session)
    _seed_other_customer(neo4j_session)
    _load_servers_and_databases(neo4j_session)
    fw_a = f'{SERVER_A}/firewallRules/all'
    sql._load_firewall_rules(
        neo4j_session, SUB_A, [{
            'id': fw_a, 'name': 'all', 'server_id': SERVER_A, 'start_ip_address': '1.1.1.1',
            'end_ip_address': '1.1.1.1',
        }],
        UPDATE_TAG,
    )
    neo4j_session.run(
        "MATCH (s:AzureSubscription{id: $sub}) MERGE (s)-[:RESOURCE]->(:AzurePublicIPAddress{id: $id, ipAddress: $ip})",
        sub=SUB_A, id=arm_id(SUB_A, 'Microsoft.Network/publicIPAddresses/pip'), ip='20.0.0.9',
    )

    sql._load_firewall_rules_fetched(
        neo4j_session, SUB_A, [{'id': SERVER_A, 'fetched': True}, {'id': SERVER_B, 'fetched': True}],
    )
    for rule in (fw_a, FW_B):
        for ip, kind in (('20.0.0.9', 'Internal'), ('1.1.1.1', 'External')):
            sql.attach_firewall_rule_to_public_ip(
                neo4j_session, {'id': rule, 'type': 'Microsoft.Sql/servers/firewallRules'}, ip, 'Azure', kind,
                UPDATE_TAG, SUB_A,
            )

    fetched = neo4j_session.run(
        "MATCH (s:AzureSQLServer) WHERE s.id IN [$a, $b] RETURN s.id AS id, s.firewall_rules_fetched AS fetched",
        a=SERVER_A, b=SERVER_B,
    )
    assert {row['id']: row['fetched'] for row in fetched} == {SERVER_A: True, SERVER_B: None}
    own_ips = linked_ids(neo4j_session, 'AzureFirewallRule', fw_a, 'MEMBER_PUBLIC_IP_ADDRESS', 'AzurePublicIPAddress')
    assert len(own_ips) == 2
    assert linked_ids(
        neo4j_session, 'AzureFirewallRule', FW_B, 'MEMBER_PUBLIC_IP_ADDRESS', 'AzurePublicIPAddress',
    ) == set()
