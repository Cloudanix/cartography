GET_EMAIL_IDENTITIES = [
    {
        "Arn": "arn:aws:ses:us-east-1:000000000000:identity/example.com",
        "IdentityName": "example.com",
        "IdentityType": "DOMAIN",
        "SendingEnabled": True,
        "VerificationStatus": "SUCCESS",
        "DkimSigningEnabled": True,
        "DkimStatus": "SUCCESS",
    },
    {
        "Arn": "arn:aws:ses:us-east-1:000000000000:identity/user@example.com",
        "IdentityName": "user@example.com",
        "IdentityType": "EMAIL_ADDRESS",
        "SendingEnabled": True,
        "VerificationStatus": "SUCCESS",
        "DkimSigningEnabled": False,
        "DkimStatus": "NOT_STARTED",
    },
    {
        "Arn": "arn:aws:ses:us-east-1:000000000000:identity/pending.io",
        "IdentityName": "pending.io",
        "IdentityType": "DOMAIN",
        "SendingEnabled": False,
        "VerificationStatus": "PENDING",
        "DkimSigningEnabled": False,
        "DkimStatus": "PENDING",
    },
]


DESCRIBE_IDENTITIES_RESPONSE = [
    {
        "name": 'example.com',
        'region': 'us-east-1',
        'arn': "arn:aws:ses:us-east-1:123456789012:identity/example.com",
        "dkim": {
            "DkimTokens": [
               "EXAMPLEjcs5xoyqytjsotsijas7236gr",
               "EXAMPLEjr76cvoc6mysspnioorxsn6ep",
               "EXAMPLEkbmkqkhlm2lyz77ppkulerm4k",
            ],
            "DkimEnabled": True,
            "DkimVerificationStatus": "Success",
        },
        "verification": {
            "VerificationStatus": "Success",
        },
    },
]
