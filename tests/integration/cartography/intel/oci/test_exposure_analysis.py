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


def test_security_list_exposed_when_attached_to_public_subnet_and_open(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    igw = 'ocid1.internetgateway.oc1.phx.sl-igw'
    _load_vcn(
        neo4j_session, 'sl-vcn',
        security_lists=[
            ('sl-open-on-public', DEFAULT_SECURITY_LIST_RULES),
            ('sl-closed-on-public', [HTTPS_FROM_VCN, PATH_MTU_FROM_ANYWHERE]),
            ('sl-open-on-private', [OPEN_SSH]),
            ('sl-open-unattached', [OPEN_SSH]),
        ],
    )
    _load_internet_gateway(neo4j_session, igw, 'sl-vcn')
    _load_route_table(neo4j_session, 'sl-rt-igw', 'sl-vcn', '0.0.0.0/0', igw)
    _load_subnet(
        neo4j_session, 'sl-subnet-public', 'sl-vcn', ['sl-open-on-public', 'sl-closed-on-public'],
        route_table_id='sl-rt-igw',
    )
    _load_subnet(
        neo4j_session, 'sl-subnet-private', 'sl-vcn', ['sl-open-on-private'],
        route_table_id='sl-rt-igw', prohibit_public_ip=True,
    )

    run_analysis_job('oci_subnet_asset_exposure.json', neo4j_session, JOB_PARAMETERS)
    run_analysis_job('oci_security_list_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCISecurityList', 'sl-') == {
        'sl-open-on-public': ['public_subnet_internet_ingress'],
    }
    context = neo4j_session.run(
        "MATCH (s:OCISecurityList{id: 'sl-open-on-public'}) RETURN s.publicContext AS c",
    ).single()['c']
    assert 'sl-subnet-public' in context and 'sl-subnet-private' not in context


def test_boot_volume_inherits_exposure_from_attached_instance(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, 'ocid1.compartment.oc1..bv-instances')
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment_id}), (ic:OCICompartment{id: 'ocid1.compartment.oc1..bv-instances'})
        MERGE (c)-[:RESOURCE]->(public:OCIInstance{id: 'bv-inst-public'}) SET public.exposed_internet = true
        MERGE (c)-[:RESOURCE]->(private:OCIInstance{id: 'bv-inst-private'})
        // An exposed instance in another compartment whose boot volume lives in this one.
        MERGE (ic)-[:RESOURCE]->(remote:OCIInstance{id: 'bv-inst-remote'}) SET remote.exposed_internet = true
        MERGE (c)-[:RESOURCE]->(bv1:OCIBootVolume{id: 'bv-public'})
        MERGE (c)-[:RESOURCE]->(bv2:OCIBootVolume{id: 'bv-private'})
        MERGE (c)-[:RESOURCE]->(bv3:OCIBootVolume{id: 'bv-remote'})
        MERGE (c)-[:RESOURCE]->(bv4:OCIBootVolume{id: 'bv-detached'})
        MERGE (public)-[:OCI_BOOT_VOLUME]->(bv1)
        MERGE (private)-[:OCI_BOOT_VOLUME]->(bv2)
        MERGE (remote)-[:OCI_BOOT_VOLUME]->(bv3)
        // Flag left by an earlier run, when the volume's instance was still exposed.
        SET bv2.exposed_internet = true, bv2.exposed_internet_type = ['attached_instance_exposed'],
            bv2.publicContext = '[]'
        """,
        compartment_id=COMPARTMENT_ID,
    )

    run_analysis_job('oci_boot_volume_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCIBootVolume', 'bv-') == {
        'bv-public': ['attached_instance_exposed'],
        'bv-remote': ['attached_instance_exposed'],
    }
    row = neo4j_session.run(
        "MATCH (b:OCIBootVolume) WHERE b.id IN ['bv-public', 'bv-private'] "
        "RETURN b.id AS id, b.publicContext AS c ORDER BY id",
    ).data()
    assert 'bv-inst-public' in row[1]['c'] and row[0]['c'] is None


def test_load_db_node_vnics_links_db_nodes_to_their_vnics(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    _load_vcn(neo4j_session, 'dbv-vcn')
    _load_subnet(neo4j_session, 'dbv-subnet', 'dbv-vcn')
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment_id})
        MERGE (c)-[:RESOURCE]->(:OCIDbSystem{id: 'dbv-system'})
        """,
        compartment_id=COMPARTMENT_ID,
    )
    database.load_db_nodes(
        neo4j_session,
        [{'id': 'dbv-node', 'db_system_id': 'dbv-system', 'vnic_id': 'dbv-vnic'}],
        UPDATE_TAG,
    )

    database.load_db_node_vnics(
        neo4j_session,
        [{'id': 'dbv-vnic', 'subnet-id': 'dbv-subnet', 'public-ip': '203.0.113.20', 'nsg-ids': ['dbv-nsg']}],
        REGION, UPDATE_TAG,
    )

    row = neo4j_session.run(
        """
        MATCH (:OCIDbSystem{id: 'dbv-system'})-[:HAS_DB_NODE]->(:OCIDbNode{id: 'dbv-node'})-[:OCI_VNIC]->(v:OCIVnic)
        MATCH (:OCISubnet{id: 'dbv-subnet'})-[:OCI_VNIC]->(v)
        RETURN v.id AS id, v.public_ip AS ip, v.nsg_ids AS nsgs
        """,
    ).single()
    assert (row['id'], row['ip'], row['nsgs']) == ('dbv-vnic', '203.0.113.20', ['dbv-nsg'])


def test_database_cleanup_removes_stale_db_node_vnics(neo4j_session):
    # A DB node VNIC whose subnet is in another (unsynced) compartment is only reachable from the DB side.
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment_id})
        MERGE (c)-[:RESOURCE]->(:OCIDbSystem{id: 'dbc-system', lastupdated: $tag})
        """,
        compartment_id=COMPARTMENT_ID, tag=UPDATE_TAG + 1,
    )
    database.load_db_nodes(
        neo4j_session, [{'id': 'dbc-node', 'db_system_id': 'dbc-system', 'vnic_id': 'dbc-vnic'}], UPDATE_TAG,
    )
    database.load_db_node_vnics(neo4j_session, [{'id': 'dbc-vnic', 'subnet-id': 'dbc-subnet'}], REGION, UPDATE_TAG)

    database.cleanup(neo4j_session, {**JOB_PARAMETERS, 'UPDATE_TAG': UPDATE_TAG + 1})

    left = neo4j_session.run(
        "MATCH (n) WHERE n.id IN ['dbc-node', 'dbc-vnic'] RETURN n.id AS id ORDER BY id",
    ).value()
    assert left == []


def _load_db_system(neo4j_session, system_id, subnet_id, nodes):
    """
    nodes: [(node_id, vnic) ...]; vnic is None when GetVnic returned nothing, else
    {'public-ip': ..., 'nsg-ids': [...]}, loaded into subnet_id with the real loaders.
    """
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment_id})
        MERGE (c)-[:RESOURCE]->(s:OCIDbSystem{id: $system_id})
        SET s.subnet_id = $subnet_id
        """,
        compartment_id=COMPARTMENT_ID, system_id=system_id, subnet_id=subnet_id,
    )
    database.load_db_nodes(
        neo4j_session,
        [{'id': node_id, 'db_system_id': system_id, 'vnic_id': f'{node_id}.vnic'} for node_id, _ in nodes],
        UPDATE_TAG,
    )
    vnics = [{'id': f'{node_id}.vnic', 'subnet-id': subnet_id, **vnic} for node_id, vnic in nodes if vnic is not None]
    database.load_db_node_vnics(neo4j_session, vnics, REGION, UPDATE_TAG)


def test_db_system_exposure_needs_node_public_ip_and_own_open_rules(neo4j_session):
    _seed_tenancy(neo4j_session, WORKSPACE_ID, TENANCY_ID, COMPARTMENT_ID)
    _load_vcn(
        neo4j_session, 'dbs-vcn',
        security_lists=[
            ('dbs-sl-default', DEFAULT_SECURITY_LIST_RULES),
            ('dbs-sl-closed', [HTTPS_FROM_VCN, PATH_MTU_FROM_ANYWHERE]),
        ],
        nsgs={'dbs-nsg-open': [OPEN_SSH], 'dbs-nsg-closed': [HTTPS_FROM_VCN]},
    )
    _load_subnet(neo4j_session, 'dbs-subnet-default', 'dbs-vcn', ['dbs-sl-default'])
    _load_subnet(neo4j_session, 'dbs-subnet-closed', 'dbs-vcn', ['dbs-sl-closed'])
    _load_subnet(neo4j_session, 'dbs-subnet-private', 'dbs-vcn', ['dbs-sl-default'], prohibit_public_ip=True)
    public = '203.0.113.30'

    # Default Security List opens SSH, but the node has no public IP.
    _load_db_system(neo4j_session, 'dbs-private-default-sl', 'dbs-subnet-default', [('dbs-n1', {'public-ip': None})])
    _load_db_system(neo4j_session, 'dbs-public-default-sl', 'dbs-subnet-default', [('dbs-n2', {'public-ip': public})])
    _load_db_system(
        neo4j_session, 'dbs-public-closed', 'dbs-subnet-closed',
        [('dbs-n3', {'public-ip': public, 'nsg-ids': ['dbs-nsg-closed']})],
    )
    _load_db_system(
        neo4j_session, 'dbs-public-open-nsg', 'dbs-subnet-closed',
        [('dbs-n4', {'public-ip': public, 'nsg-ids': ['dbs-nsg-open']})],
    )
    # Two-node RAC: one node private, the other public behind an open list.
    _load_db_system(
        neo4j_session, 'dbs-two-nodes', 'dbs-subnet-default',
        [('dbs-n5', {'public-ip': None}), ('dbs-n6', {'public-ip': public})],
    )
    # Rules or VNICs we cannot see stay public.
    _load_db_system(
        neo4j_session, 'dbs-public-unknown-nsg', 'dbs-subnet-closed',
        [('dbs-n7', {'public-ip': public, 'nsg-ids': ['dbs-nsg-not-synced']})],
    )
    _load_db_system(neo4j_session, 'dbs-no-vnic-public-subnet', 'dbs-subnet-default', [('dbs-n8', None)])
    _load_db_system(neo4j_session, 'dbs-no-vnic-unknown-subnet', 'dbs-subnet-not-synced', [('dbs-n9', None)])
    # A private subnet cannot give the node a public IP, so a missing VNIC does not matter.
    _load_db_system(neo4j_session, 'dbs-no-vnic-private-subnet', 'dbs-subnet-private', [('dbs-n10', None)])
    # Flag left by an earlier run must be cleared.
    neo4j_session.run(
        "MATCH (s:OCIDbSystem{id: 'dbs-public-closed'}) "
        "SET s.exposed_internet = true, s.exposed_internet_type = ['unrestricted_securitylist_ingress'], "
        "s.publicContext = '[]'",
    )

    run_analysis_job('oci_db_system_asset_exposure.json', neo4j_session, JOB_PARAMETERS)

    assert _exposed(neo4j_session, 'OCIDbSystem', 'dbs-') == {
        'dbs-public-default-sl': ['unrestricted_securitylist_ingress'],
        'dbs-public-open-nsg': ['unrestricted_nsg_ingress'],
        'dbs-two-nodes': ['unrestricted_securitylist_ingress'],
        'dbs-public-unknown-nsg': ['public_ip_unresolved_rules'],
        'dbs-no-vnic-public-subnet': ['db_node_vnic_unresolved'],
        'dbs-no-vnic-unknown-subnet': ['db_node_vnic_unresolved'],
    }
    rows = neo4j_session.run(
        "MATCH (s:OCIDbSystem) WHERE s.id IN ['dbs-two-nodes', 'dbs-public-closed'] "
        "RETURN s.id AS id, s.publicContext AS c ORDER BY id",
    ).data()
    assert rows[0]['c'] is None
    assert 'dbs-n6.vnic' in rows[1]['c'] and 'dbs-sl-default' in rows[1]['c'] and 'dbs-n5.vnic' not in rows[1]['c']
