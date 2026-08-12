MOCK_VAULTS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/my-test-key-vault",
        "name": "my-test-key-vault",
        "location": "eastus",
        "properties": {
            "tenant_id": "00-00-00-00",
            "sku": {
                "name": "standard",
            },
            "vault_uri": "https://my-test-key-vault.vault.azure.net/",
        },
    },
]

MOCK_SECRETS = [
    {
        "id": "https://my-test-key-vault.vault.azure.net/secrets/my-secret",
        "name": "my-secret",
        "enabled": True,
        "created_on": "2025-01-01T12:00:00.000Z",
        "updated_on": "2025-01-01T12:05:00.000Z",
        "tags": {"env": "prod"},
    },
]

MOCK_KEYS = [
    {
        "id": "https://my-test-key-vault.vault.azure.net/keys/my-key",
        "name": "my-key",
        "key_type": "RSA",
        "enabled": True,
        "created_on": "2025-01-02T12:00:00.000Z",
        "updated_on": "2025-01-02T12:05:00.000Z",
    },
]

MOCK_CERTIFICATES = [
    {
        "id": "https://my-test-key-vault.vault.azure.net/certificates/my-cert",
        "name": "my-cert",
        "enabled": True,
        "created_on": "2025-01-03T12:00:00.000Z",
        "updated_on": "2025-01-03T12:05:00.000Z",
        "x5t": "THUMBPRINT_STRING",
    },
]


DESCRIBE_CERTIFICATES = [
    {

        "id": "https://vault1.vault.azure.net/certificates/selfSignedCert01/012abc",
        "managed": True,
        "vault_uri": "https://vault1.vault.azure.net/",
        "content_type": "content1",
        "kid": "https://vault1.vault.azure.net/keys/key1",
        "sid": "https://vault1.vault.azure.net/secrets/secret1/abcdefg",
        "vault_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault1",

    },
    {
        "id": "https://vault1.vault.azure.net/certificates/selfSignedCert02/123ghj",
        "managed": True,
        "vault_uri": "https://vault2.vault.azure.net/",
        "content_type": "content2",
        "kid": "https://vault2.vault.azure.net/keys/key2",
        "sid": "https://vault1.vault.azure.net/secrets/secret2/hijklm",
        "vault_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault2",

    },
]


DESCRIBE_KEYS = [
    {

        'id': "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault2",
        "kid": "https://vault1.vault.azure.net/keys/key1",
        "managed": True,
        "vault_uri": "https://vault1.vault.azure.net/",
        "vault_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault1",

    },
    {
        'id': "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault2",
        "kid": "https://vault2.vault.azure.net/keys/key2",
        "managed": True,
        "vault_uri": "https://vault2.vault.azure.net/",
        "vault_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault2",

    },
]


DESCRIBE_KEYVAULTS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault1",
        "type": "Microsoft.KeyVault/vaults",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "vault1",
        "properties": {
            "vault_uri": "https://vault1.vault.azure.net/",
            "network_acls": {
                "default_action": "Deny",
            },
        },
    },
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault2",
        "type": "Microsoft.KeyVault/vaults",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "vault2",
        "properties": {
            "vault_uri": "https://vault2.vault.azure.net/",
        },
    },
]


DESCRIBE_SECRETS = [
    {

        "id": "https://vault1.vault.azure.net/secrets/secret1/abcdefg",
        "managed": True,
        "vault_uri": "https://vault1.vault.azure.net/",
        "content_type": "content1",
        "vault_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault1",
    },
    {
        "id": "https://vault1.vault.azure.net/secrets/secret2/hijklm",
        "managed": True,
        "vault_uri": "https://vault2.vault.azure.net/",
        "content_type": "content2",
        "vault_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.KeyVault/vaults/vault2",

    },
]

