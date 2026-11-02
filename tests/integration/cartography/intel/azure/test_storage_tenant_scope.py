import pytest

from cartography.intel.azure import storage
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

# (service label, service id segment, loader, child label, child id segment, child loader)
SERVICES = [
    ('AzureStorageQueueService', 'queueServices', storage._load_queue_services,
     'AzureStorageQueue', 'queues', storage._load_queues),
    ('AzureStorageTableService', 'tableServices', storage._load_table_services,
     'AzureStorageTable', 'tables', storage._load_tables),
    ('AzureStorageFileService', 'fileServices', storage._load_file_services,
     'AzureStorageFileShare', 'shares', storage._load_shares),
    ('AzureStorageBlobService', 'blobServices', storage._load_blob_services,
     'AzureStorageBlobContainer', 'containers', storage._load_blob_containers),
]


def _account(sub):
    return arm_id(sub, 'Microsoft.Storage/storageAccounts/st')


def _service(sub, segment):
    return f'{_account(sub)}/{segment}/default'


def _child(sub, segment, child_segment, name='c1'):
    return f'{_service(sub, segment)}/{child_segment}/{name}'


def _seed_other_customer(neo4j_session):
    """SUB_B's own storage account, services and children, with the ids a hostile payload could name."""
    storage.load_storage_account_data(neo4j_session, SUB_B, [{'id': _account(SUB_B), 'name': 'st'}], UPDATE_TAG)
    for _, segment, load_service, _, child_segment, load_child in SERVICES:
        load_service(
            neo4j_session, SUB_B, [{'id': _service(SUB_B, segment), 'storage_account_id': _account(SUB_B)}],
            UPDATE_TAG,
        )
        load_child(
            neo4j_session, SUB_B,
            [{'id': _child(SUB_B, segment, child_segment), 'service_id': _service(SUB_B, segment),
              'public_access': 'none'}],
            UPDATE_TAG,
        )


# Ids the API returned while syncing SUB_A that name SUB_B: the subscription segment of an id is API data,
# not an anchor, so these land in SUB_A's group of that name.
FOREIGN_ACCOUNT = arm_id(SUB_B, 'Microsoft.Storage/storageAccounts/st-foreign')


def _foreign(node_id):
    return f'{node_id}-foreign'


def _load_customer_a(neo4j_session, segment, load_service, child_segment, load_child):
    seed_customers(neo4j_session)
    _seed_other_customer(neo4j_session)
    storage.load_storage_account_data(
        neo4j_session, SUB_A, [{'id': _account(SUB_A), 'name': 'st'}, {'id': FOREIGN_ACCOUNT, 'name': 'x'}],
        UPDATE_TAG,
    )
    load_service(
        neo4j_session, SUB_A,
        [
            {'id': _service(SUB_A, segment), 'storage_account_id': _account(SUB_A)},
            {'id': _foreign(_service(SUB_B, segment)), 'storage_account_id': _account(SUB_A)},
            # a service claiming SUB_B's account: no USES edge into the other customer
            {'id': f'{_service(SUB_A, segment)}-x', 'storage_account_id': _account(SUB_B)},
        ],
        UPDATE_TAG,
    )
    load_child(
        neo4j_session, SUB_A,
        [
            {'id': _child(SUB_A, segment, child_segment), 'service_id': _service(SUB_A, segment),
             'public_access': 'none'},
            {'id': _foreign(_child(SUB_B, segment, child_segment)), 'service_id': _service(SUB_A, segment),
             'public_access': 'none'},
            # a child claiming SUB_B's service: no CONTAINS edge into the other customer
            {'id': _child(SUB_A, segment, child_segment, 'c2'), 'service_id': _service(SUB_B, segment),
             'public_access': 'none'},
        ],
        UPDATE_TAG,
    )


def test_storage_account_group_stays_in_the_syncing_subscription(neo4j_session):
    _, segment, load_service, _, child_segment, load_child = SERVICES[0]
    _load_customer_a(neo4j_session, segment, load_service, child_segment, load_child)

    assert resource_group_of(neo4j_session, 'AzureStorageAccount', _account(SUB_A)) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureStorageAccount', FOREIGN_ACCOUNT) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureStorageAccount', _account(SUB_B)) == {rg_id(SUB_B)}


@pytest.mark.parametrize('service_label,segment,load_service,child_label,child_segment,load_child', SERVICES)
def test_storage_services_link_only_inside_the_syncing_subscription(
    neo4j_session, service_label, segment, load_service, child_label, child_segment, load_child,
):
    _load_customer_a(neo4j_session, segment, load_service, child_segment, load_child)
    own_service, other_service = _service(SUB_A, segment), _service(SUB_B, segment)

    assert linked_ids(neo4j_session, 'AzureStorageAccount', _account(SUB_A), 'USES', service_label) == {
        own_service, _foreign(other_service),
    }
    assert linked_ids(neo4j_session, 'AzureStorageAccount', _account(SUB_B), 'USES', service_label) == {other_service}
    assert resource_group_of(neo4j_session, service_label, own_service) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, service_label, _foreign(other_service)) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, service_label, other_service) == {rg_id(SUB_B)}


@pytest.mark.parametrize('service_label,segment,load_service,child_label,child_segment,load_child', SERVICES)
def test_storage_children_link_only_inside_the_syncing_subscription(
    neo4j_session, service_label, segment, load_service, child_label, child_segment, load_child,
):
    _load_customer_a(neo4j_session, segment, load_service, child_segment, load_child)
    own_service, other_service = _service(SUB_A, segment), _service(SUB_B, segment)
    own_child, other_child = _child(SUB_A, segment, child_segment), _child(SUB_B, segment, child_segment)

    assert linked_ids(neo4j_session, service_label, own_service, 'CONTAINS', child_label) == {
        own_child, _foreign(other_child),
    }
    assert linked_ids(neo4j_session, service_label, other_service, 'CONTAINS', child_label) == {other_child}
    assert resource_group_of(neo4j_session, child_label, own_child) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, child_label, _foreign(other_child)) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, child_label, other_child) == {rg_id(SUB_B)}
