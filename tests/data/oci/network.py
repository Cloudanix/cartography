# Copyright (c) 2020, Oracle and/or its affiliates.
# Raw OCI Network API fixtures (hyphenated keys), as the load_* functions receive them.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaanet000000000000000000000000000000000000000000000000000000"
TEST_TENANCY_ID = "ocid1.tenancy.oc1..net"
TEST_REGION = "us-phoenix-1"

VCN_ID = "oci.vcn.0"
SUBNET_ID = "oci.subnet.0"
NSG_ID = "oci.nsg.0"

VCNS = [
    {
        "id": VCN_ID,
        "display-name": "vcn-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "cidr-block": "10.0.0.0/16",
        "dns-label": "vcn0",
        "lifecycle-state": "AVAILABLE",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

SUBNETS = [
    {
        "id": SUBNET_ID,
        "display-name": "subnet-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "cidr-block": "10.0.1.0/24",
        "availability-domain": "AD-1",
        "dns-label": "sub0",
        "lifecycle-state": "AVAILABLE",
        "vcn-id": VCN_ID,
        "route-table-id": "oci.rt.0",
        "security-list-ids": ["oci.sl.0"],
        "subnet-domain-name": "sub0.vcn0.oraclevcn.com",
        "prohibit-public-ip-on-vnic": False,
        "time-created": "2024-01-01T00:00:00Z",
    },
]

SECURITY_LISTS = [
    {
        "id": "oci.sl.0",
        "display-name": "sl-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "vcn-id": VCN_ID,
        "lifecycle-state": "AVAILABLE",
        "ingress-security-rules": [{"protocol": "6", "source": "0.0.0.0/0"}],
        "egress-security-rules": [{"protocol": "all", "destination": "0.0.0.0/0"}],
        "time-created": "2024-01-01T00:00:00Z",
    },
]

NETWORK_SECURITY_GROUPS = [
    {
        "id": NSG_ID,
        "display-name": "nsg-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "vcn-id": VCN_ID,
        "lifecycle-state": "AVAILABLE",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

NSG_SECURITY_RULES = [
    {
        "id": "oci.nsgrule.0",
        "direction": "INGRESS",
        "protocol": "6",
        "description": "ssh",
        "source": "0.0.0.0/0",
        "source-type": "CIDR_BLOCK",
        "destination": None,
        "destination-type": None,
        "is-stateless": False,
        "is-valid": True,
        "tcp-options": {"destination-port-range": {"min": 22, "max": 22}},
    },
]

INTERNET_GATEWAYS = [
    {
        "id": "oci.igw.0",
        "display-name": "igw-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "vcn-id": VCN_ID,
        "is-enabled": True,
        "lifecycle-state": "AVAILABLE",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

NAT_GATEWAYS = [
    {
        "id": "oci.nat.0",
        "display-name": "nat-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "vcn-id": VCN_ID,
        "nat-ip": "203.0.113.1",
        "block-traffic": False,
        "lifecycle-state": "AVAILABLE",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

ROUTE_TABLES = [
    {
        "id": "oci.rt.0",
        "display-name": "rt-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "vcn-id": VCN_ID,
        "lifecycle-state": "AVAILABLE",
        "route-rules": [{"destination": "0.0.0.0/0", "network-entity-id": "oci.igw.0"}],
        "time-created": "2024-01-01T00:00:00Z",
    },
]

VNICS = [
    {
        "id": "oci.vnic.0",
        "display-name": "vnic-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "lifecycle-state": "AVAILABLE",
        "private-ip": "10.0.1.5",
        "public-ip": "203.0.113.5",
        "is-primary": True,
        "hostname-label": "host0",
        "mac-address": "00:00:00:00:00:00",
        "skip-source-dest-check": False,
        "subnet-id": SUBNET_ID,
        "time-created": "2024-01-01T00:00:00Z",
    },
]

# Flow log sourced from the subnet (configuration.source.resource = SUBNET_ID).
FLOW_LOGS = [
    {
        "id": "oci.flowlog.0",
        "display-name": "flowlog-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "log-group-id": "oci.lg.0",
        "log-type": "SERVICE",
        "is-enabled": True,
        "lifecycle-state": "ACTIVE",
        "configuration": {
            "source": {
                "service": "flowlogs",
                "category": "all",
                "resource": SUBNET_ID,
            },
        },
        "time-created": "2024-01-01T00:00:00Z",
    },
]
