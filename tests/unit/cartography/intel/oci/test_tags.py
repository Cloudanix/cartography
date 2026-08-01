from unittest.mock import MagicMock

from cartography.intel.oci import tags

RAW_INSTANCES = [
    {
        'id': 'ocid1.instance.oc1..aaa',
        'display-name': 'web-1',
        'freeform-tags': {'env': 'prod', 'team': 'platform'},
        'defined-tags': {
            'Operations': {'CostCenter': '42'},
            'Oracle-Tags': {'CreatedBy': 'user@example.com'},
        },
    },
    {
        'id': 'ocid1.instance.oc1..bbb',
        'display-name': 'no-tags',
        'freeform-tags': {},
        'defined-tags': {},
    },
    {
        # no id — must be skipped entirely
        'display-name': 'orphan',
        'freeform-tags': {'env': 'prod'},
    },
    {
        'id': 'ocid1.instance.oc1..ccc',
        # tag fields absent / null — must not raise
        'freeform-tags': None,
    },
]


def test_get_tags_list_flattens_freeform_and_defined():
    result = tags.get_tags_list(RAW_INSTANCES)

    by_id = {t['id']: t for t in result}
    assert len(result) == 4
    assert by_id['ocid1.instance.oc1..aaa/tag/env'] == {
        'id': 'ocid1.instance.oc1..aaa/tag/env',
        'key': 'env',
        'value': 'prod',
        'resource_id': 'ocid1.instance.oc1..aaa',
    }
    # defined tags are namespaced <namespace>.<key>
    assert by_id['ocid1.instance.oc1..aaa/tag/Operations.CostCenter']['key'] == 'Operations.CostCenter'
    assert by_id['ocid1.instance.oc1..aaa/tag/Operations.CostCenter']['value'] == '42'
    assert by_id['ocid1.instance.oc1..aaa/tag/Oracle-Tags.CreatedBy']['value'] == 'user@example.com'
    # no entry for the id-less or tag-less items
    assert all(t['resource_id'] == 'ocid1.instance.oc1..aaa' for t in result)


def test_get_tags_list_stringifies_values():
    raw = [{
        'id': 'ocid1.bucket.oc1..xyz',
        'freeform-tags': {'count': 3},
        'defined-tags': {'ns': {'flag': True}},
    }]
    result = {t['key']: t['value'] for t in tags.get_tags_list(raw)}
    assert result == {'count': '3', 'ns.flag': 'True'}


def test_load_tags_tx_interpolates_label_and_scopes_query():
    tx = MagicMock()
    common_job_parameters = {'OCI_TENANCY_ID': 'ocid1.tenancy.oc1..t', 'WORKSPACE_ID': 'ws-1'}
    tag_list = tags.get_tags_list(RAW_INSTANCES)

    tags._load_tags_tx(tx, tag_list, 'OCIInstance', 123, common_job_parameters)

    query = tx.run.call_args[0][0]
    assert 'MERGE (t:OCITag{id: tag.id})' in query
    assert '(r:OCIInstance{id: tag.resource_id})' in query
    assert 'MERGE (r)-[rel:TAGGED]->(t)' in query
    # MATCH must precede MERGE so tags for absent resources create no orphan
    # OCITag nodes and no wasted MERGE work
    assert query.index('MATCH') < query.index('MERGE (t:OCITag')
    kwargs = tx.run.call_args[1]
    assert kwargs['OCI_TENANCY_ID'] == 'ocid1.tenancy.oc1..t'
    assert kwargs['WORKSPACE_ID'] == 'ws-1'
    assert kwargs['update_tag'] == 123


def test_sync_tags_noop_without_tags():
    session = MagicMock()
    tags.sync_tags(session, [{'id': 'x', 'freeform-tags': {}}], 'OCIInstance', 1, {})
    session.execute_write.assert_not_called()
