MOCK_METRIC_ALERTS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/CartographyTest-RG/providers/microsoft.insights/metricAlerts/Cartography-Test-Alert",
        "name": "Cartography-Test-Alert",
        "location": "global",
        "description": "Test alert for Cartography sync",
        "severity": 3,
        "enabled": True,
        "window_size": "PT5M",
        "evaluation_frequency": "PT1M",
        "properties": {"last_updated_time": "2025-10-13T21:00:00Z"},
        "tags": {"env": "prod", "service": "monitor"},
    }
]


DESCRIBE_LOGPROFILES = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.LogProfiles/logprofile/logprofile1",
        "type": "Microsoft.LogProfiles/logprofiles",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "logprofile1",
        "service_bus_rule_id": "rule123",
        "storage_account_id": "storage123",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.LogProfiles/logprofile/logprofile2",
        "type": "Microsoft.LogProfiles/logprofile",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "logprofile2",
        "service_bus_rule_id": "rule456",
        "storage_account_id": "storage456",
    },
]

