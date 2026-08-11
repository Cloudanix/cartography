# Copyright (c) 2020, Oracle and/or its affiliates.
# Raw OCI Monitoring API fixtures (hyphenated keys), as the load_* functions receive them.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaamon000000000000000000000000000000000000000000000000000000"
TEST_TENANCY_ID = "ocid1.tenancy.oc1..mon"
TEST_REGION = "us-phoenix-1"

ALARMS = [
    {
        "id": "oci.alarm.0",
        "display-name": "alarm-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "namespace": "oci_computeagent",
        "query": "CpuUtilization[1m].mean() > 80",
        "severity": "CRITICAL",
        "is-enabled": True,
        "lifecycle-state": "ACTIVE",
        "metric-compartment-id": TEST_COMPARTMENT_ID,
        "destinations": ["oci.topic.0"],
    },
]

EVENT_RULES = [
    {
        "id": "oci.rule.0",
        "display-name": "rule-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "condition": "{}",
        "is-enabled": True,
        "lifecycle-state": "ACTIVE",
        "description": "a rule",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

NOTIFICATION_TOPICS = [
    {
        "topic-id": "oci.topic.0",
        "id": "oci.topic.0",
        "name": "topic-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "lifecycle-state": "ACTIVE",
        "description": "a topic",
        "api-endpoint": "https://notification.example",
        "time-created": "2024-01-01T00:00:00Z",
    },
]
