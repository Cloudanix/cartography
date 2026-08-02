from pathlib import Path
from unittest.mock import MagicMock

from cartography.intel.gcp import label


def test_crypto_key_labels_match_through_their_key_ring():
    # GCPKMSCryptoKey hangs off GCPKMSKeyRing, not off the project, so a
    # direct-only MATCH would drop every crypto key label
    tx = MagicMock()
    label._load_labels_tx(
        tx, [{'id': 'k/label/env', 'key': 'env', 'value': 'prod', 'resource_id': 'k'}],
        123, {'GCP_PROJECT_ID': 'p', 'GCP_ORGANIZATION_ID': 'o', 'WORKSPACE_ID': 'w'},
        'GCPKMSCryptoKey',
    )

    query = tx.run.call_args[0][0]
    assert '(r:GCPKMSCryptoKey{id:label.resource_id})' in query
    assert '<-[:RESOURCE]-(:GCPKMSKeyRing)<-[:RESOURCE]-(:GCPProject' in query


def test_direct_resources_keep_the_default_path():
    tx = MagicMock()
    label._load_labels_tx(
        tx, [{'id': 'i/label/env', 'key': 'env', 'value': 'prod', 'resource_id': 'i'}],
        123, {'GCP_PROJECT_ID': 'p', 'GCP_ORGANIZATION_ID': 'o', 'WORKSPACE_ID': 'w'},
        'GCPInstance',
    )

    query = tx.run.call_args[0][0]
    assert '(r:GCPInstance{id:label.resource_id})\n    <-[:RESOURCE]-(:GCPProject' in query


def test_match_precedes_merge():
    # labels for resources absent from the graph must not create orphan GCPLabel
    # nodes: the account-scoped cleanup statements would never reach them
    tx = MagicMock()
    label._load_labels_tx(
        tx, [{'id': 'i/label/env', 'key': 'env', 'value': 'prod', 'resource_id': 'i'}],
        123, {'GCP_PROJECT_ID': 'p', 'GCP_ORGANIZATION_ID': 'o', 'WORKSPACE_ID': 'w'},
        'GCPInstance',
    )

    query = tx.run.call_args[0][0]
    assert query.index('MATCH') < query.index('MERGE (l:GCPLabel')


def test_every_nested_path_has_cleanup_coverage():
    cleanup = (
        Path(__file__).resolve().parents[5]
        / 'cartography' / 'data' / 'jobs' / 'cleanup' / 'gcp_labels_cleanup.json'
    ).read_text()
    for service_label in label.OWNERSHIP_PATHS:
        assert f'(m:{service_label})<-[:RESOURCE]-' in cleanup, service_label
