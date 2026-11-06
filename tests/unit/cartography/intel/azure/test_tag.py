from unittest.mock import MagicMock

import cartography.intel.azure.sql as sql
import cartography.intel.azure.tag as tag

COMMON_JOB_PARAMETERS = {
    'WORKSPACE_ID': 'ws-1',
    'AZURE_TENANT_ID': 'tenant-1',
    'AZURE_SUBSCRIPTION_ID': 'sub-1',
}


def test_load_tags_tx_matches_resource_before_merging_tag():
    """
    The MATCH must precede the MERGE: tags belonging to resources that are not
    in the graph must not create orphan AzureTag nodes (they would never be
    cleaned up, since the cleanup job only walks TAGGED relationships).
    """
    tx = MagicMock()
    tags_list = [{
        'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'
              '/providers/Microsoft.Resources/tags/env',
        'key': 'env', 'value': 'prod', 'type': 'Microsoft.Resources/tags',
        'resource_id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1',
        'resource_group': 'rg',
    }]
    tag._load_tags_tx(tx, tags_list, 123, COMMON_JOB_PARAMETERS)

    query = tx.run.call_args[0][0]
    assert query.index('MATCH') < query.index('MERGE (t:AzureTag')


def test_load_database_tags_builds_arm_tag_shape(mocker):
    load_tags = mocker.patch.object(sql.azure_tag, 'load_tags')
    db_id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/databases/db1'
    databases = [
        {'id': db_id, 'resource_group_name': 'rg', 'tags': {'env': 'prod', 'dataclassification': 'pii'}},
        {'id': db_id + '2', 'resource_group_name': 'rg', 'tags': None},
        {'id': db_id + '3', 'resource_group_name': 'rg'},
    ]

    sql._load_database_tags(MagicMock(), databases, 123, COMMON_JOB_PARAMETERS)

    load_tags.assert_called_once()
    tags_list = load_tags.call_args[0][1]
    assert len(tags_list) == 2
    by_key = {t['key']: t for t in tags_list}
    assert by_key['env']['id'] == db_id + '/providers/Microsoft.Resources/tags/env'
    assert by_key['env']['resource_id'] == db_id
    assert by_key['dataclassification']['value'] == 'pii'


def test_load_database_tags_noop_without_tags(mocker):
    load_tags = mocker.patch.object(sql.azure_tag, 'load_tags')
    sql._load_database_tags(MagicMock(), [{'id': 'x', 'tags': {}}], 1, COMMON_JOB_PARAMETERS)
    load_tags.assert_not_called()


def test_tag_match_is_case_insensitive_and_bounded():
    """
    ARM ids are case-insensitive; an exact match dropped tags for any module that
    normalized ids differently. The descent is also bounded — the old unbounded
    -[*]-> walked the whole subscription subgraph for every tag row.
    """
    tx = MagicMock()
    resource_id = '/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1'
    tags_list = [{
        'id': resource_id + '/providers/Microsoft.Resources/tags/env',
        'key': 'env', 'value': 'prod', 'type': 'Microsoft.Resources/tags',
        'resource_id': resource_id, 'resource_group': 'rg',
    }]

    tag._load_tags_tx(tx, tags_list, 123, COMMON_JOB_PARAMETERS)

    query = tx.run.call_args[0][0]
    assert 'toLower(l.id) = tag.resource_id_lower' in query
    assert '-[*]->' not in query
    assert '-[*1..4]->' in query
    # the lowercased id is derived centrally, so every producer stays correct
    assert tx.run.call_args[1]['tags_list'][0]['resource_id_lower'] == resource_id.lower()
