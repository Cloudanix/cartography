"""
Cosmos DB IP firewall rules must be scoped to their account: two accounts in
different workspaces that allow the same IP get separate rule and public IP
nodes, and the cosmos cleanup removes only the syncing account's stale ones.
"""
from cartography.intel.azure import cosmosdb

IP = '20.30.40.50'
ACCOUNTS = {
    'a': ('cfx-ws-a', 'cfx-tenant-a', 'cfx-sub-a'),
    'b': ('cfx-ws-b', 'cfx-tenant-b', 'cfx-sub-b'),
}
NETWORK_PIP = '/subscriptions/cfx-sub-c/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip'


def _account_id(key):
    sub = ACCOUNTS[key][2]
    return f'/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/db-{key}'


def _account(key, ip_rules):
    return {
        'id': _account_id(key), 'name': f'db-{key}', 'location': 'eastus',
        'type': 'Microsoft.DocumentDB/databaseAccounts', 'ipruleslist': ip_rules,
    }


def _rules(session, key):
    return session.run(
        "MATCH (:AzureCosmosDBAccount{id: $acc})-[:FIREWALL_RULE]->(rule:AzureFirewallRule)"
        "-[:MEMBER_OF_PUBLIC_IP]->(ip:AzurePublicIPAddress) "
        "RETURN rule.id AS rule, rule.lastupdated AS rule_tag, ip.id AS ip, ip.ipAddress AS address",
        acc=_account_id(key),
    ).data()


def test_same_ip_on_two_accounts_is_scoped_and_cleaned_per_account(neo4j_session):
    for key, (ws, tenant, sub) in ACCOUNTS.items():
        neo4j_session.run(
            "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
            "(:AzureSubscription{id: $sub})",
            ws=ws, tenant=tenant, sub=sub,
        )
        cosmosdb.load_database_account_data(neo4j_session, sub, [_account(key, [IP])], 10)
    # Another subscription's own public IP that happens to hold the same address.
    neo4j_session.run(
        "MERGE (:AzureSubscription{id: 'cfx-sub-c'})-[:RESOURCE]->"
        "(:AzurePublicIPAddress{id: $id, ipAddress: $ip, name: 'pip', lastupdated: 1})",
        id=NETWORK_PIP, ip=IP,
    )

    for key in ACCOUNTS:
        cosmosdb._load_database_account_associated_iprules(neo4j_session, _account(key, [IP]), 10)

    rules_a, rules_b = _rules(neo4j_session, 'a'), _rules(neo4j_session, 'b')
    assert rules_a == [{
        'rule': f"{_account_id('a')}/ipRules/{IP}", 'rule_tag': 10,
        'ip': f"{_account_id('a')}/ipRules/{IP}/publicIp", 'address': IP,
    }]
    assert rules_b == [{
        'rule': f"{_account_id('b')}/ipRules/{IP}", 'rule_tag': 10,
        'ip': f"{_account_id('b')}/ipRules/{IP}/publicIp", 'address': IP,
    }]

    # What the old loader left in prod: a bare-IP rule node, never given lastupdated,
    # linked to account a and to sub-c's own public IP.
    neo4j_session.run(
        "MATCH (d:AzureCosmosDBAccount{id: $acc}), (pip:AzurePublicIPAddress{id: $pip}) "
        "MERGE (legacy:AzureFirewallRule{id: $ip}) MERGE (d)-[:FIREWALL_RULE{lastupdated: 10}]->(legacy) "
        "MERGE (legacy)-[:MEMBER_OF_PUBLIC_IP{lastupdated: 10}]->(pip)",
        acc=_account_id('a'), pip=NETWORK_PIP, ip=IP,
    )

    # Account a drops the IP; its next sync (tag 11) runs the cosmos cleanup.
    ws, tenant, sub = ACCOUNTS['a']
    cosmosdb.load_database_account_data(neo4j_session, sub, [_account('a', [])], 11)
    cosmosdb._load_database_account_associated_iprules(neo4j_session, _account('a', []), 11)
    cosmosdb.cleanup_azure_database_accounts(
        neo4j_session, {
            'UPDATE_TAG': 11, 'WORKSPACE_ID': ws, 'AZURE_TENANT_ID': tenant, 'AZURE_SUBSCRIPTION_ID': sub,
            'LIMIT_SIZE': 1000,
        },
    )

    assert _rules(neo4j_session, 'a') == []
    assert neo4j_session.run(
        "MATCH (n) WHERE n.id STARTS WITH $acc RETURN count(n) AS c", acc=f"{_account_id('a')}/ipRules/",
    ).single()['c'] == 0
    assert neo4j_session.run(
        "MATCH (legacy:AzureFirewallRule{id: $ip}) RETURN count(legacy) AS c", ip=IP,
    ).single()['c'] == 0
    assert _rules(neo4j_session, 'b') == rules_b
    other = neo4j_session.run(
        "MATCH (ip:AzurePublicIPAddress{id: $id}) RETURN ip.name AS name, "
        "EXISTS { (ip)<-[:MEMBER_OF_PUBLIC_IP]-() } AS linked",
        id=NETWORK_PIP,
    ).data()
    assert other == [{'name': 'pip', 'linked': False}]
