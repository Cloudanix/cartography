# Copyright (c) 2020, Oracle and/or its affiliates.
# Runs the real OCI exposure analysis jobs against network data loaded by the real loaders.
from cartography.intel.oci import database
from cartography.intel.oci import network
from cartography.util import run_analysis_job

WORKSPACE_ID = 'ws-oci-exposure'
TENANCY_ID = 'ocid1.tenancy.oc1..exposure'
COMPARTMENT_ID = 'ocid1.compartment.oc1..exposure'
OTHER_WORKSPACE_ID = 'ws-oci-other'
OTHER_TENANCY_ID = 'ocid1.tenancy.oc1..other'
OTHER_COMPARTMENT_ID = 'ocid1.compartment.oc1..other'
REGION = 'us-phoenix-1'
UPDATE_TAG = 123456789
JOB_PARAMETERS = {
    'UPDATE_TAG': UPDATE_TAG,
    'WORKSPACE_ID': WORKSPACE_ID,
    'OCI_TENANCY_ID': TENANCY_ID,
    'OCI_COMPARTMENT_ID': COMPARTMENT_ID,
    'LIMIT_SIZE': 100,
}

# Rules of the security list OCI creates with every VCN (Default Security List).
OPEN_SSH = {
    'protocol': '6', 'source': '0.0.0.0/0', 'source-type': 'CIDR_BLOCK',
    'tcp-options': {'destination-port-range': {'min': 22, 'max': 22}},
}
PATH_MTU_FROM_ANYWHERE = {
    'protocol': '1', 'source': '0.0.0.0/0', 'source-type': 'CIDR_BLOCK', 'icmp-options': {'type': 3, 'code': 4},
}
ICMP_FROM_VCN = {'protocol': '1', 'source': '10.0.0.0/16', 'source-type': 'CIDR_BLOCK', 'icmp-options': {'type': 3}}
DEFAULT_SECURITY_LIST_RULES = [OPEN_SSH, PATH_MTU_FROM_ANYWHERE, ICMP_FROM_VCN]
HTTPS_FROM_VCN = {'protocol': '6', 'source': '10.0.0.0/16', 'source-type': 'CIDR_BLOCK'}
ALL_FROM_ANYWHERE_V6 = {'protocol': 'all', 'source': '::/0', 'source-type': 'CIDR_BLOCK'}


def _seed_tenancy(neo4j_session, workspace_id, tenancy_id, compartment_id):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(t:OCITenancy{id: $tenancy_id})
        MERGE (t)-[:OWNER]->(:OCICompartment{id: $compartment_id})
        """,
        workspace_id=workspace_id, tenancy_id=tenancy_id, compartment_id=compartment_id,
    )


def _load_vcn(neo4j_session, vcn_id, compartment_id=COMPARTMENT_ID, security_lists=(), nsgs=None):
    """
    Load a VCN with its security lists ({id: ingress rules}) and NSGs ({id: rules}) via the real loaders.
    """
    args = (TENANCY_ID, compartment_id, REGION, UPDATE_TAG)
    network.load_vcns(neo4j_session, [{'id': vcn_id, 'compartment-id': compartment_id}], *args)
    network.load_security_lists(
        neo4j_session,
        [{'id': sl_id, 'vcn-id': vcn_id, 'ingress-security-rules': rules} for sl_id, rules in security_lists],
        *args,
    )
    for nsg_id, rules in (nsgs or {}).items():
        network.load_network_security_groups(neo4j_session, [{'id': nsg_id, 'vcn-id': vcn_id}], *args)
        network.load_nsg_security_rules(
            neo4j_session,
            [{'id': f'{nsg_id}.rule{i}', 'direction': 'INGRESS', **rule} for i, rule in enumerate(rules)],
            nsg_id, UPDATE_TAG,
        )


def _load_subnet(
    neo4j_session, subnet_id, vcn_id, security_list_ids=(), route_table_id='', prohibit_public_ip=False,
    compartment_id=COMPARTMENT_ID,
):
    network.load_subnets(
        neo4j_session,
        [{
            'id': subnet_id, 'vcn-id': vcn_id, 'security-list-ids': list(security_list_ids),
            'route-table-id': route_table_id, 'prohibit-public-ip-on-vnic': prohibit_public_ip,
        }],
        TENANCY_ID, compartment_id, REGION, UPDATE_TAG,
    )


def _load_route_table(neo4j_session, route_table_id, vcn_id, destination, target_id):
    network.load_route_tables(
        neo4j_session,
        [{
            'id': route_table_id, 'vcn-id': vcn_id,
            'route-rules': [{'destination': destination, 'network-entity-id': target_id}],
        }],
        TENANCY_ID, COMPARTMENT_ID, REGION, UPDATE_TAG,
    )


def _load_internet_gateway(neo4j_session, igw_id, vcn_id, enabled=True):
    network.load_internet_gateways(
        neo4j_session, [{'id': igw_id, 'vcn-id': vcn_id, 'is-enabled': enabled}],
        TENANCY_ID, COMPARTMENT_ID, REGION, UPDATE_TAG,
    )


def _load_instance(neo4j_session, instance_id, subnet_id, public_ip, nsg_ids=(), compartment_id=COMPARTMENT_ID):
    vnic_id = f'{instance_id}.vnic'
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment_id})
        MERGE (c)-[:RESOURCE]->(i:OCIInstance{id: $instance_id})
        SET i.ocid = $instance_id
        MERGE (i)-[:OCI_VNIC_ATTACHMENT]->(:OCIVnicAttachment{id: $vnic_id + '.att', vnic_id: $vnic_id})
        """,
        compartment_id=compartment_id, instance_id=instance_id, vnic_id=vnic_id,
    )
    network.load_vnics(
        neo4j_session,
        [{'id': vnic_id, 'subnet-id': subnet_id, 'public-ip': public_ip, 'nsg-ids': list(nsg_ids)}],
        REGION, UPDATE_TAG,
    )


def _exposed(neo4j_session, label, id_prefix):
    # Tests share the module's graph; each owns the nodes whose id starts with its prefix.
    rows = neo4j_session.run(
        f"""
        MATCH (n:{label}) WHERE n.id STARTS WITH $id_prefix AND n.exposed_internet = true
        RETURN n.id AS id, n.exposed_internet_type AS types
        """,
        id_prefix=id_prefix,
    )
    return {r['id']: sorted(r['types']) for r in rows}


def test_instance_exposure_needs_public_ip_and_own_open_rules(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    _load_vcn(
        neo4j_session, 'inst-vcn',
        security_lists=[
            ('inst-sl-default', DEFAULT_SECURITY_LIST_RULES),
            ('inst-sl-closed', [HTTPS_FROM_VCN, PATH_MTU_FROM_ANYWHERE]),
            ('inst-sl-v6', [ALL_FROM_ANYWHERE_V6]),
        ],
        nsgs={
            'inst-nsg-open': [OPEN_SSH],
            'inst-nsg-closed': [HTTPS_FROM_VCN, PATH_MTU_FROM_ANYWHERE],
        },
    )
    _load_subnet(neo4j_session, 'inst-subnet-default', 'inst-vcn', ['inst-sl-default'])
    _load_subnet(neo4j_session, 'inst-subnet-closed', 'inst-vcn', ['inst-sl-closed'])
    _load_subnet(neo4j_session, 'inst-subnet-v6', 'inst-vcn', ['inst-sl-v6'])
    # Lists a security list that is not in the graph (another compartment, not synced yet).
    _load_subnet(neo4j_session, 'inst-subnet-unknown-sl', 'inst-vcn', ['inst-sl-not-synced'])

    # Default Security List opens SSH to the world, but without a public IP nothing reaches the VM.
    _load_instance(neo4j_session, 'inst-private-default-sl', 'inst-subnet-default', None)
    _load_instance(neo4j_session, 'inst-public-default-sl', 'inst-subnet-default', '203.0.113.1')
    # Public IP but the subnet's own list only admits the VCN (and path-MTU ICMP). The VCN's
    # open Default Security List and open NSG are not attached to this VM.
    _load_instance(neo4j_session, 'inst-public-closed-sl', 'inst-subnet-closed', '203.0.113.2')
    _load_instance(
        neo4j_session, 'inst-public-closed-nsg', 'inst-subnet-closed', '203.0.113.3', nsg_ids=['inst-nsg-closed'],
    )
    _load_instance(
        neo4j_session, 'inst-public-open-nsg', 'inst-subnet-closed', '203.0.113.4', nsg_ids=['inst-nsg-open'],
    )
    _load_instance(neo4j_session, 'inst-public-v6', 'inst-subnet-v6', '203.0.113.5')
    # Rules we cannot see stay public, as before this change.
    _load_instance(neo4j_session, 'inst-public-unknown-sl', 'inst-subnet-unknown-sl', '203.0.113.6')
    _load_instance(neo4j_session, 'inst-public-unknown-subnet', 'inst-subnet-not-synced', '203.0.113.7')
    _load_instance(
        neo4j_session, 'inst-public-unknown-nsg', 'inst-subnet-closed', '203.0.113.8', nsg_ids=['inst-nsg-not-synced'],
    )
    # Another workspace's open VM is out of this run's scope.
    _seed_tenancy(neo4j_session, OTHER_WORKSPACE_ID, OTHER_TENANCY_ID, OTHER_COMPARTMENT_ID)
    _load_instance(
        neo4j_session, 'inst-other-workspace', 'inst-subnet-default', '203.0.113.9',
        compartment_id=OTHER_COMPARTMENT_ID,
    )

    run_analysis_job('oci_instance_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCIInstance', 'inst-') == {
        'inst-public-default-sl': ['unrestricted_securitylist_ingress'],
        'inst-public-open-nsg': ['unrestricted_nsg_ingress'],
        'inst-public-v6': ['unrestricted_securitylist_ingress'],
        'inst-public-unknown-sl': ['public_ip_unresolved_rules'],
        'inst-public-unknown-subnet': ['public_ip_unresolved_rules'],
        'inst-public-unknown-nsg': ['public_ip_unresolved_rules'],
    }
    context = neo4j_session.run(
        "MATCH (i:OCIInstance{id: 'inst-public-open-nsg'}) RETURN i.publicContext AS c",
    ).single()['c']
    assert 'inst-nsg-open.rule0' in context and '203.0.113.4' in context


def test_subnet_exposure_needs_public_ips_and_own_default_route_to_internet_gateway(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    _load_vcn(neo4j_session, 'sub-vcn')
    igw = 'ocid1.internetgateway.oc1.phx.sub-igw'
    disabled_igw = 'ocid1.internetgateway.oc1.phx.sub-igw-off'
    _load_internet_gateway(neo4j_session, igw, 'sub-vcn')
    _load_internet_gateway(neo4j_session, disabled_igw, 'sub-vcn', enabled=False)
    _load_route_table(neo4j_session, 'sub-rt-igw', 'sub-vcn', '0.0.0.0/0', igw)
    _load_route_table(neo4j_session, 'sub-rt-igw-v6', 'sub-vcn', '::/0', igw)
    _load_route_table(neo4j_session, 'sub-rt-igw-off', 'sub-vcn', '0.0.0.0/0', disabled_igw)
    _load_route_table(neo4j_session, 'sub-rt-nat', 'sub-vcn', '0.0.0.0/0', 'ocid1.natgateway.oc1.phx.sub-nat')

    _load_subnet(neo4j_session, 'sub-public-igw', 'sub-vcn', route_table_id='sub-rt-igw')
    _load_subnet(neo4j_session, 'sub-public-igw-v6', 'sub-vcn', route_table_id='sub-rt-igw-v6')
    # Private subnet: no VNIC in it can get a public IP, whatever the route table says.
    _load_subnet(neo4j_session, 'sub-private-igw', 'sub-vcn', route_table_id='sub-rt-igw', prohibit_public_ip=True)
    # Public IPs allowed, but its own route table sends 0.0.0.0/0 to a NAT gateway (the VCN still has an IGW).
    _load_subnet(neo4j_session, 'sub-public-nat', 'sub-vcn', route_table_id='sub-rt-nat')
    _load_subnet(neo4j_session, 'sub-public-igw-off', 'sub-vcn', route_table_id='sub-rt-igw-off')
    # Route table not in the graph: cannot be proven private, stays public as before.
    _load_subnet(neo4j_session, 'sub-public-unknown-rt', 'sub-vcn', route_table_id='sub-rt-not-synced')

    run_analysis_job('oci_subnet_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCISubnet', 'sub-') == {
        'sub-public-igw': ['internet_gateway_route'],
        'sub-public-igw-v6': ['internet_gateway_route'],
        'sub-public-unknown-rt': ['public_subnet_unresolved_route_table'],
    }
    context = neo4j_session.run(
        "MATCH (s:OCISubnet{id: 'sub-public-igw'}) RETURN s.publicContext AS c",
    ).single()['c']
    assert igw in context and 'sub-rt-igw' in context


def test_mount_targets_and_file_systems_are_never_internet_exposed(neo4j_session):
    # Mount targets only get private IPs, so a public subnet, an IGW route or an open security
    # list / NSG cannot put them (or the file systems they export) on the internet.
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    igw = 'ocid1.internetgateway.oc1.phx.fss-igw'
    _load_vcn(
        neo4j_session, 'fss-vcn',
        security_lists=[('fss-sl-default', DEFAULT_SECURITY_LIST_RULES)], nsgs={'fss-nsg-open': [OPEN_SSH]},
    )
    _load_internet_gateway(neo4j_session, igw, 'fss-vcn')
    _load_route_table(neo4j_session, 'fss-rt-igw', 'fss-vcn', '0.0.0.0/0', igw)
    _load_subnet(neo4j_session, 'fss-subnet', 'fss-vcn', ['fss-sl-default'], route_table_id='fss-rt-igw')
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment_id})
        MERGE (c)-[:RESOURCE]->(mt:OCIMountTarget{id: 'fss-mt'})
        SET mt.subnet_id = 'fss-subnet', mt.nsg_ids = ['fss-nsg-open']
        MERGE (c)-[:RESOURCE]->(fs:OCIFileSystem{id: 'fss-fs'})
        MERGE (mt)-[:OCI_EXPORT]->(fs)
        // Flags written by the previous version of the job must be cleared.
        SET mt.exposed_internet = true, mt.exposed_internet_type = ['public_subnet'], mt.publicContext = '[]',
            fs.exposed_internet = true, fs.exposed_internet_type = ['public_subnet'], fs.publicContext = '[]'
        """,
        compartment_id=COMPARTMENT_ID,
    )

    run_analysis_job('oci_file_storage_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCIMountTarget', 'fss-') == {}
    assert _exposed(neo4j_session, 'OCIFileSystem', 'fss-') == {}
    row = neo4j_session.run(
        "MATCH (n) WHERE n.id IN ['fss-mt', 'fss-fs'] AND n.publicContext IS NOT NULL RETURN count(n) AS c",
    ).single()
    assert row['c'] == 0


def test_autonomous_database_exposed_only_with_public_endpoint_and_open_acl(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    raw = [
        # Public endpoint, "secure access from everywhere": no ACL at all.
        {'id': 'adb-public-no-acl'},
        {'id': 'adb-public-open-acl', 'whitelisted-ips': ['198.51.100.7', '0.0.0.0/0']},
        # Public endpoint restricted to one address and to a VCN (via service gateway).
        {'id': 'adb-public-ip-acl', 'whitelisted-ips': ['198.51.100.7']},
        {'id': 'adb-public-vcn-acl', 'whitelisted-ips': ['ocid1.vcn.oc1.phx.x;10.0.0.0/16']},
        {'id': 'adb-private-endpoint', 'subnet-id': 'ocid1.subnet.oc1.phx.adb'},
        # Dedicated Exadata infrastructure is only reachable from the customer's VCN.
        {'id': 'adb-dedicated', 'is-dedicated': True},
    ]
    database.load_autonomous_databases(
        neo4j_session,
        database.transform_autonomous_databases([{'lifecycle-state': 'AVAILABLE', **adb} for adb in raw], REGION),
        COMPARTMENT_ID, UPDATE_TAG,
    )

    run_analysis_job('oci_autonomous_database_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCIAutonomousDatabase', 'adb-') == {
        'adb-public-no-acl': ['public_endpoint_no_acl'],
        'adb-public-open-acl': ['public_endpoint_open_acl'],
    }
    context = neo4j_session.run(
        "MATCH (a:OCIAutonomousDatabase{id: 'adb-public-open-acl'}) RETURN a.publicContext AS c",
    ).single()['c']
    assert '0.0.0.0/0' in context and 'oci-database-autonomous-database' in context
