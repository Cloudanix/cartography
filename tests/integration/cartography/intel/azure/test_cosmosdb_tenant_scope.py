import pytest

from cartography.intel.azure import cosmosdb
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

CJP = {'Azure_Primary_AD_Domain_Name': 'cdx'}


def _account(sub):
    return arm_id(sub, 'Microsoft.DocumentDB/databaseAccounts/cosmos')


# Ids the API returned while syncing SUB_A that name SUB_B: the subscription segment of an id is API data,
# not an anchor, so these land in SUB_A's group of that name.
FOREIGN_ACCOUNT = arm_id(SUB_B, 'Microsoft.DocumentDB/databaseAccounts/cosmos-foreign')


def _foreign(node_id):
    return node_id.replace(SUB_A, SUB_B) + '-foreign'


# Account-level loaders: (relationship, child label, payload builder, loader)
ACCOUNT_CHILDREN = [
    ('FIREWALL_RULE', 'AzureFirewallRule', lambda: {'ipruleslist': ['20.1.2.3']},
     cosmosdb._load_database_account_associated_iprules),
    ('CAN_WRITE_FROM', 'AzureCosmosDBLocation', lambda: {'write_locations': [{'id': 'w', 'location_name': 'East US'}]},
     cosmosdb._load_database_account_write_locations),
    ('CAN_READ_FROM', 'AzureCosmosDBLocation', lambda: {'read_locations': [{'id': 'r', 'location_name': 'East US'}]},
     cosmosdb._load_database_account_read_locations),
    ('ASSOCIATED_WITH', 'AzureCosmosDBLocation', lambda: {'locations': [{'id': 'l', 'location_name': 'East US'}]},
     cosmosdb._load_database_account_associated_locations),
    ('CONTAINS', 'AzureCosmosDBCorsPolicy', lambda: {'cors': [{'allowed_origins': '*'}]},
     cosmosdb._load_cosmosdb_cors_policy),
    ('CONTAINS', 'AzureCosmosDBAccountFailoverPolicy',
     lambda: {'failover_policies': [{'id': 'f', 'location_name': 'eastus', 'failover_priority': 0}]},
     cosmosdb._load_cosmosdb_failover_policies),
    ('CONFIGURED_WITH', 'AzureCosmosDBVirtualNetworkRule',
     lambda: {'virtual_network_rules': [{'id': arm_id(SUB_A, 'Microsoft.Network/virtualNetworks/v/subnets/s')}]},
     lambda session, sub, account, tag: cosmosdb._load_cosmosdb_virtual_network_rules(session, sub, account, tag, CJP)),
]
# Database loaders: (child label, id segment, loader), each CONTAINS-linked from the account.
DATABASES = [
    ('AzureCosmosDBSqlDatabase', 'sqlDatabases', cosmosdb._load_sql_databases),
    ('AzureCosmosDBCassandraKeySpace', 'cassandraKeyspaces', cosmosdb._load_cassandra_keyspaces),
    ('AzureCosmosDBMongoDBDatabase', 'mongodbDatabases', cosmosdb._load_mongodb_databases),
    ('AzureCosmosDBTableResource', 'tables', cosmosdb._load_table_resources),
]
# Database children: (database label, segment, database loader, child label, child segment, parent key, loader)
DATABASE_CHILDREN = [
    ('AzureCosmosDBSqlDatabase', 'sqlDatabases', cosmosdb._load_sql_databases,
     'AzureCosmosDBSqlContainer', 'containers', 'database_id', cosmosdb._load_sql_containers),
    ('AzureCosmosDBCassandraKeySpace', 'cassandraKeyspaces', cosmosdb._load_cassandra_keyspaces,
     'AzureCosmosDBCassandraTable', 'tables', 'keyspace_id', cosmosdb._load_cassandra_tables),
    ('AzureCosmosDBMongoDBDatabase', 'mongodbDatabases', cosmosdb._load_mongodb_databases,
     'AzureCosmosDBMongoDBCollection', 'collections', 'database_id', cosmosdb._load_collections),
]


def _database(sub, segment):
    return f'{_account(sub)}/{segment}/db'


def _seed(neo4j_session):
    """Both customers' accounts; SUB_B also holds its databases, the ids a hostile payload could name."""
    seed_customers(neo4j_session)
    cosmosdb.load_database_account_data(neo4j_session, SUB_B, [{'id': _account(SUB_B), 'name': 'cosmos'}], UPDATE_TAG)
    for _, segment, load in DATABASES:
        load(
            neo4j_session, SUB_B, [{'id': _database(SUB_B, segment), 'database_account_id': _account(SUB_B)}],
            UPDATE_TAG,
        )
    cosmosdb.load_database_account_data(
        neo4j_session, SUB_A, [{'id': _account(SUB_A), 'name': 'cosmos'}, {'id': FOREIGN_ACCOUNT, 'name': 'x'}],
        UPDATE_TAG,
    )


def test_cosmosdb_account_group_stays_in_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)

    assert resource_group_of(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_A)) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureCosmosDBAccount', FOREIGN_ACCOUNT) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_B)) == {rg_id(SUB_B)}


@pytest.mark.parametrize('rel,label,payload,load', ACCOUNT_CHILDREN)
def test_cosmosdb_account_settings_link_only_to_the_syncing_subscriptions_account(
    neo4j_session, rel, label, payload, load,
):
    _seed(neo4j_session)

    load(neo4j_session, SUB_A, {'id': _account(SUB_A), 'type': 'cosmos', **payload()}, UPDATE_TAG)
    # The same payload for SUB_B's account id while syncing SUB_A: nothing may attach to SUB_B's account.
    load(neo4j_session, SUB_A, {'id': _account(SUB_B), 'type': 'cosmos', **payload()}, UPDATE_TAG)

    assert linked_ids(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_A), rel, label)
    assert linked_ids(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_B), rel, label) == set()


def test_cosmosdb_private_endpoint_connections_stay_in_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)
    own = f'{_account(SUB_A)}/privateEndpointConnections/pec'

    def account(account_id, *connection_ids):
        return {
            'id': account_id, 'location': 'eastus',
            'private_endpoint_connections': [{'id': i, 'name': 'pec'} for i in connection_ids],
        }

    load = cosmosdb._load_cosmosdb_private_endpoint_connections
    load(neo4j_session, SUB_A, account(_account(SUB_A), own, _foreign(own)), UPDATE_TAG)
    # a connection listed for SUB_B's account id while syncing SUB_A: nothing attaches to SUB_B's account
    load(neo4j_session, SUB_A, account(_account(SUB_B), own + '-x'), UPDATE_TAG)

    label = 'AzureCDBPrivateEndpointConnection'
    assert linked_ids(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_A), 'CONFIGURED_WITH', label) == {
        own, _foreign(own),
    }
    assert linked_ids(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_B), 'CONFIGURED_WITH', label) == set()
    assert resource_group_of(neo4j_session, label, own) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, label, _foreign(own)) == {rg_id(SUB_A)}


@pytest.mark.parametrize('label,segment,load', DATABASES)
def test_cosmosdb_databases_link_only_to_the_syncing_subscriptions_account(neo4j_session, label, segment, load):
    _seed(neo4j_session)
    own, other = _database(SUB_A, segment), _database(SUB_B, segment)

    load(
        neo4j_session, SUB_A,
        [
            {'id': own, 'database_account_id': _account(SUB_A)},
            {'id': _foreign(own), 'database_account_id': _account(SUB_A)},
            # a database claiming SUB_B's account: no CONTAINS edge into the other customer
            {'id': own + '-x', 'database_account_id': _account(SUB_B)},
        ],
        UPDATE_TAG,
    )

    assert linked_ids(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_A), 'CONTAINS', label) == {
        own, _foreign(own),
    }
    assert linked_ids(neo4j_session, 'AzureCosmosDBAccount', _account(SUB_B), 'CONTAINS', label) == {other}
    if label == 'AzureCosmosDBTableResource':
        assert resource_group_of(neo4j_session, label, own) == {rg_id(SUB_A)}
        assert resource_group_of(neo4j_session, label, _foreign(own)) == {rg_id(SUB_A)}


@pytest.mark.parametrize('db_label,segment,load_db,label,child_segment,parent_key,load', DATABASE_CHILDREN)
def test_cosmosdb_database_children_link_only_inside_the_syncing_subscription(
    neo4j_session, db_label, segment, load_db, label, child_segment, parent_key, load,
):
    _seed(neo4j_session)
    own_db, other_db = _database(SUB_A, segment), _database(SUB_B, segment)
    load_db(neo4j_session, SUB_A, [{'id': own_db, 'database_account_id': _account(SUB_A)}], UPDATE_TAG)
    own = f'{own_db}/{child_segment}/c1'

    load(
        neo4j_session, SUB_A,
        [
            {'id': own, parent_key: own_db},
            {'id': _foreign(own), parent_key: own_db},
            # a child claiming SUB_B's database: no CONTAINS edge into the other customer
            {'id': own + '-x', parent_key: other_db},
        ],
        UPDATE_TAG,
    )

    assert linked_ids(neo4j_session, db_label, own_db, 'CONTAINS', label) == {own, _foreign(own)}
    assert linked_ids(neo4j_session, db_label, other_db, 'CONTAINS', label) == set()
    assert resource_group_of(neo4j_session, label, own) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, label, _foreign(own)) == {rg_id(SUB_A)}
