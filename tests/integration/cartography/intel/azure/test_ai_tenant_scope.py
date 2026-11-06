"""
Tenant isolation (AGENTS.md rule 7) for the Azure AI inventory links: a second
workspace owns a key vault, storage account and Cognitive Services accounts that
the first workspace's API data points at (same id, URL or endpoint). No edge from
the first workspace may reach them, and no AzureKeyVault / AzureStorageAccount may
be created from API data.
"""
from cartography.intel.azure import cognitiveservices
from cartography.intel.azure import machinelearning

UPDATE_TAG = 123456789
SUB1 = 'ait-s1'
SUB2 = 'ait-s2'
WORKSPACE1 = 'ait-w1'
FOREIGN_KV = '/subscriptions/ait-s2/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kvforeign'
FOREIGN_SA = '/subscriptions/ait-s2/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/saforeign'
OWN_KV = '/subscriptions/ait-s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kvown'
SHARED_ENDPOINT = 'https://eastus.api.cognitive.microsoft.com/'
FOREIGN_CUSTOM_ENDPOINT = 'https://oai-foreign.openai.azure.com/'
OWN_CUSTOM_ENDPOINT = 'https://oai-own.openai.azure.com/'
WS_ID = '/subscriptions/ait-s1/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws'


def _seed(neo4j_session):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace {id: 'ait-w1'})-[:OWNER]->(:AzureTenant {id: 'ait-t1'})
            -[:RESOURCE]->(s1:AzureSubscription {id: $sub1})
        MERGE (:CloudanixWorkspace {id: 'ait-w2'})-[:OWNER]->(:AzureTenant {id: 'ait-t2'})
            -[:RESOURCE]->(s2:AzureSubscription {id: $sub2})
        MERGE (s2)-[:RESOURCE]->(:AzureKeyVault {id: $foreign_kv, uri: 'https://kvforeign.vault.azure.net/'})
        MERGE (s2)-[:RESOURCE]->(:AzureStorageAccount {id: $foreign_sa})
        MERGE (s2)-[:RESOURCE]->(:AzureCognitiveServicesAccount {id: 'ait-acc-shared', endpoint: $shared})
        MERGE (s2)-[:RESOURCE]->(:AzureCognitiveServicesAccount {
            id: 'ait-acc-foreign', endpoint: $foreign_custom, custom_sub_domain_name: 'oai-foreign'
        })
        MERGE (s1)-[:RESOURCE]->(:AzureKeyVault {id: $own_kv, uri: 'https://kvown.vault.azure.net/'})
        MERGE (s1)-[:RESOURCE]->(:AzureCognitiveServicesAccount {
            id: 'ait-acc-own', endpoint: $own_custom, custom_sub_domain_name: 'oai-own'
        })
        """,
        sub1=SUB1, sub2=SUB2, foreign_kv=FOREIGN_KV, foreign_sa=FOREIGN_SA, own_kv=OWN_KV,
        shared=SHARED_ENDPOINT, foreign_custom=FOREIGN_CUSTOM_ENDPOINT, own_custom=OWN_CUSTOM_ENDPOINT,
    )


def _edges(neo4j_session, rel):
    return {
        (r['a'], r['b']) for r in neo4j_session.run(
            f"MATCH (a)-[:{rel}]->(b) WHERE a.id STARTS WITH 'ait-' OR a.id STARTS WITH '/subscriptions/ait-' "
            "RETURN a.id AS a, b.id AS b",
        )
    }


def _count(neo4j_session, label):
    return neo4j_session.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()['c']


def test_ai_links_never_reach_another_tenant(neo4j_session):
    _seed(neo4j_session)
    kv_before = _count(neo4j_session, 'AzureKeyVault')
    sa_before = _count(neo4j_session, 'AzureStorageAccount')

    machinelearning.load_workspaces(
        neo4j_session, SUB1, [
            {'id': WS_ID, 'name': 'ws', 'key_vault': FOREIGN_KV, 'storage_account': FOREIGN_SA},
            {'id': f'{WS_ID}2', 'name': 'ws2', 'key_vault': OWN_KV.upper(), 'storage_account': None},
        ], UPDATE_TAG,
    )
    machinelearning.load_connections(
        neo4j_session, SUB1, [
            {'id': 'ait-conn-shared', 'workspace_id': WS_ID, 'target': SHARED_ENDPOINT},
            {'id': 'ait-conn-foreign', 'workspace_id': WS_ID, 'target': FOREIGN_CUSTOM_ENDPOINT},
            {'id': 'ait-conn-own', 'workspace_id': WS_ID, 'target': OWN_CUSTOM_ENDPOINT},
        ], UPDATE_TAG, WORKSPACE1,
    )
    cognitiveservices.load_accounts(
        neo4j_session, SUB1, [
            {'id': 'ait-acc-cmk-foreign', 'key_vault_uri': 'https://kvforeign.vault.azure.net/'},
            {'id': 'ait-acc-cmk-own', 'key_vault_uri': 'https://kvown.vault.azure.net'},
        ], UPDATE_TAG,
    )

    assert _edges(neo4j_session, 'USES_KEY_VAULT') == {(f'{WS_ID}2', OWN_KV)}
    assert _edges(neo4j_session, 'USES_STORAGE') == set()
    assert _edges(neo4j_session, 'CONNECTS_TO') == {('ait-conn-own', 'ait-acc-own')}
    assert _edges(neo4j_session, 'ENCRYPTED_BY') == {('ait-acc-cmk-own', OWN_KV)}
    assert _count(neo4j_session, 'AzureKeyVault') == kv_before
    assert _count(neo4j_session, 'AzureStorageAccount') == sa_before
