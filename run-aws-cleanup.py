import cartography.cli


body = {
    "neo4j": {
        "uri": "neo4j://127.0.0.1:7687",
        "user": "neo4j",
        "pwd": "",
        "connection_lifetime": 200,
    },
    "logging": {
        "mode": "verbose",
    },
    "params": {
        "workspace": {
            "id_string": "",
            "name": "CDX Workspace",
            "account_id": "",
            "organization_id": ""
        },
    }
}
resp = cartography.cli.run_aws_cleanup(body)
