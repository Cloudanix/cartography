from cartography.intel.oci import audit_logging
from cartography.intel.oci import database
from cartography.intel.oci import iam
from cartography.intel.oci import network
from cartography.intel.oci import utils
from cartography.util import run_cleanup_job

OLD_TAG = 1
NEW_TAG = 2
DB_LINK_TYPES = ('OCI_SUBNET', 'OCI_NSG', 'OCI_KMS_KEY')


def _seed_tenant(neo4j_session, prefix):
    """Workspace -> tenancy -> compartment chain for one tenant; returns the job parameters for it."""
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: $prefix + '-ws'})
        MERGE (t:OCITenancy{id: $prefix + '-tenancy'})
        MERGE (c:OCICompartment{id: $prefix + '-compartment'})
        MERGE (w)-[:OWNER]->(t)
        MERGE (t)-[:OWNER]->(c)
        """,
        prefix=prefix,
    )
    return {
        'WORKSPACE_ID': f'{prefix}-ws',
        'OCI_TENANCY_ID': f'{prefix}-tenancy',
        'OCI_COMPARTMENT_ID': f'{prefix}-compartment',
    }


def _seed_db_links(neo4j_session, prefix, tag):
    """One ADB, DB system and DB home of the tenant, all current, with network/KMS edges stamped `tag`."""
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $prefix + '-compartment'})
        MERGE (c)-[ra:RESOURCE]->(adb:OCIAutonomousDatabase{id: $prefix + '-adb'})
        MERGE (c)-[rs:RESOURCE]->(sys:OCIDbSystem{id: $prefix + '-dbsys'})
        MERGE (sys)-[rh:HAS_DB_HOME]->(home:OCIDbHome{id: $prefix + '-dbhome'})
        SET adb.lastupdated = $new, sys.lastupdated = $new, home.lastupdated = $new,
            ra.lastupdated = $new, rs.lastupdated = $new, rh.lastupdated = $new
        MERGE (subnet:OCISubnet{id: $prefix + '-subnet'})
        MERGE (nsg:OCINetworkSecurityGroup{id: $prefix + '-nsg'})
        MERGE (key:OCIKmsKey{id: $prefix + '-key'})
        MERGE (adb)-[e1:OCI_SUBNET]->(subnet) SET e1.lastupdated = $tag
        MERGE (adb)-[e2:OCI_NSG]->(nsg) SET e2.lastupdated = $tag
        MERGE (adb)-[e3:OCI_KMS_KEY]->(key) SET e3.lastupdated = $tag
        MERGE (sys)-[e4:OCI_SUBNET]->(subnet) SET e4.lastupdated = $tag
        MERGE (sys)-[e5:OCI_NSG]->(nsg) SET e5.lastupdated = $tag
        MERGE (sys)-[e6:OCI_KMS_KEY]->(key) SET e6.lastupdated = $tag
        MERGE (home)-[e7:OCI_KMS_KEY]->(key) SET e7.lastupdated = $tag
        """,
        prefix=prefix, tag=tag, new=NEW_TAG,
    )


def _db_links(neo4j_session, prefix):
    rows = neo4j_session.run(
        """
        MATCH (n)-[r:OCI_SUBNET|OCI_NSG|OCI_KMS_KEY]->()
        WHERE n.id IN [$prefix + '-adb', $prefix + '-dbsys', $prefix + '-dbhome']
        RETURN n.id AS source, type(r) AS rel
        """,
        prefix=prefix,
    )
    return {(row['source'], row['rel']) for row in rows}


def test_database_cleanup_deletes_only_the_syncing_compartments_edges(neo4j_session):
    params = _seed_tenant(neo4j_session, 'db-a')
    _seed_tenant(neo4j_session, 'db-b')
    # Tenant A's edges were not refreshed by this sync (stale); tenant B synced earlier with its own tag.
    _seed_db_links(neo4j_session, 'db-a', OLD_TAG)
    _seed_db_links(neo4j_session, 'db-b', OLD_TAG)

    database.cleanup(neo4j_session, {**params, 'UPDATE_TAG': NEW_TAG})

    assert _db_links(neo4j_session, 'db-a') == set()
    expected_b = {(source, rel) for source in ('db-b-adb', 'db-b-dbsys') for rel in DB_LINK_TYPES}
    assert _db_links(neo4j_session, 'db-b') == expected_b | {('db-b-dbhome', 'OCI_KMS_KEY')}


def _nsg_rules(neo4j_session, nsg_id):
    rows = neo4j_session.run(
        """
        MATCH (:OCINetworkSecurityGroup{id: $nsg_id})-[:OCI_NSG_RULE]->(r:OCINsgSecurityRule)
        RETURN r.id AS id, r.ocid AS ocid, r.tcp_dest_port_min AS port
        """,
        nsg_id=nsg_id,
    )
    return {(row['id'], row['ocid'], row['port']) for row in rows}


def test_nsg_rule_ids_are_scoped_to_their_nsg(neo4j_session):
    # OCI security rule ids are short codes ("04ABEC") unique only within one NSG.
    nsgs = {}
    for prefix, port in (('nsg-a', 22), ('nsg-b', 443)):
        _seed_tenant(neo4j_session, prefix)
        nsg_id = f'ocid1.networksecuritygroup.oc1.phx.{prefix}'
        neo4j_session.run(
            """
            MATCH (c:OCICompartment{id: $prefix + '-compartment'})
            MERGE (c)-[:RESOURCE]->(v:OCIVcn{id: $prefix + '-vcn'})
            MERGE (v)-[:OCI_NETWORK_SECURITY_GROUP]->(:OCINetworkSecurityGroup{id: $nsg_id})
            """,
            prefix=prefix, nsg_id=nsg_id,
        )
        rule = {
            'id': '04ABEC', 'direction': 'INGRESS', 'protocol': '6', 'source': '0.0.0.0/0',
            'tcp-options': {'destination-port-range': {'min': port, 'max': port}},
        }
        network.load_nsg_security_rules(neo4j_session, [rule], nsg_id, f'{prefix}-tenancy', NEW_TAG)
        nsgs[nsg_id] = port

    for nsg_id, port in nsgs.items():
        assert _nsg_rules(neo4j_session, nsg_id) == {(f'{nsg_id}/04ABEC', '04ABEC', port)}


def _compartment_logging_services(neo4j_session, compartment_id):
    rows = neo4j_session.run(
        """
        MATCH (:OCICompartment{id: $compartment_id})-[:RESOURCE]->(ls:OCILoggingService)
        RETURN ls.id AS id, ls.compartment_id AS compartment_id
        """,
        compartment_id=compartment_id,
    )
    return {(row['id'], row['compartment_id']) for row in rows}


def test_logging_service_nodes_belong_to_one_compartment(neo4j_session):
    # ListServices returns the same catalog ("objectstorage") to every tenancy.
    services = [{'id': 'objectstorage', 'name': 'Object Storage'}]
    for prefix in ('ls-a', 'ls-b'):
        _seed_tenant(neo4j_session, prefix)
        audit_logging.load_logging_services(
            neo4j_session, services, f'{prefix}-tenancy', f'{prefix}-compartment', 'us-phoenix-1', NEW_TAG,
        )

    for prefix in ('ls-a', 'ls-b'):
        compartment_id = f'{prefix}-compartment'
        assert _compartment_logging_services(neo4j_session, compartment_id) == {
            (f'oci.logging.service.{compartment_id}.objectstorage.us-phoenix-1', compartment_id),
        }


def test_logging_cleanup_of_one_tenant_keeps_the_other_tenants_logging_services(neo4j_session):
    services = [{'id': 'objectstorage', 'name': 'Object Storage'}]
    for prefix in ('lsc-a', 'lsc-b'):
        _seed_tenant(neo4j_session, prefix)
        audit_logging.load_logging_services(
            neo4j_session, services, f'{prefix}-tenancy', f'{prefix}-compartment', 'us-phoenix-1', OLD_TAG,
        )

    # Tenant B's next sync could not list services (e.g. a permission error), so its cleanup sees them stale.
    params_b = _seed_tenant(neo4j_session, 'lsc-b')
    run_cleanup_job('oci_import_logging_cleanup.json', neo4j_session, {**params_b, 'UPDATE_TAG': NEW_TAG})

    assert len(_compartment_logging_services(neo4j_session, 'lsc-a-compartment')) == 1
    assert _compartment_logging_services(neo4j_session, 'lsc-b-compartment') == set()


OWN_TENANCY = 'ocid1.tenancy.oc1..ownaaaa'
OWN_SECOND_TENANCY = 'ocid1.tenancy.oc1..ownbbbb'
OTHER_CUSTOMER_TENANCY = 'ocid1.tenancy.oc1..othercccc'


def _seed_cross_tenancy_policy(neo4j_session):
    """Workspace ws-iam owns two tenancies; another customer (ws-iam-other) owns a third one."""
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: 'ws-iam'})
        MERGE (other:CloudanixWorkspace{id: 'ws-iam-other'})
        MERGE (t:OCITenancy{id: $own})
        MERGE (t2:OCITenancy{id: $own2})
        MERGE (t3:OCITenancy{id: $other})
        MERGE (w)-[:OWNER]->(t)
        MERGE (w)-[:OWNER]->(t2)
        MERGE (other)-[:OWNER]->(t3)
        MERGE (t)-[:RESOURCE]->(p:OCIPolicy{id: 'iam-policy'})
        SET p.ocid = 'iam-policy', p.name = 'cross-tenancy', p.compartmentid = $own,
            p.statements = [
                'Endorse group Admins to manage all-resources in tenancy ' + $own2,
                'Endorse group Admins to manage all-resources in tenancy ' + $other
            ]
        """,
        own=OWN_TENANCY, own2=OWN_SECOND_TENANCY, other=OTHER_CUSTOMER_TENANCY,
    )


def _trusted_principals(neo4j_session, policy_id):
    """(principal, access_type, statement_verb) as this policy's trust edge records them."""
    rows = neo4j_session.run(
        """
        MATCH (:OCIPolicy{id: $policy_id})-[r:TRUSTS_OCI_PRINCIPAL]->(ep:OCIExternalPrincipal)
        RETURN ep.principal AS principal, r.access_type AS access_type, r.statement_verb AS verb
        """,
        policy_id=policy_id,
    )
    return {(row['principal'], row['access_type'], row['verb']) for row in rows}


def _sync_policy_references(neo4j_session, workspace_id, tenancy_id):
    iam.sync_oci_policy_references(
        neo4j_session, tenancy_id, NEW_TAG,
        {'WORKSPACE_ID': workspace_id, 'OCI_TENANCY_ID': tenancy_id, 'UPDATE_TAG': NEW_TAG},
    )


def test_cross_tenancy_classification_only_knows_the_workspaces_own_tenancies(neo4j_session):
    _seed_cross_tenancy_policy(neo4j_session)

    _sync_policy_references(neo4j_session, 'ws-iam', OWN_TENANCY)

    # Another Cloudanix customer's tenancy is a third party to this workspace, not "known".
    assert _trusted_principals(neo4j_session, 'iam-policy') == {
        (OWN_SECOND_TENANCY, 'CrossAccount', 'endorse'), (OTHER_CUSTOMER_TENANCY, 'ThirdParty', 'endorse'),
    }


def test_trust_classification_lives_on_each_policys_edge(neo4j_session):
    _seed_cross_tenancy_policy(neo4j_session)
    # The other customer admits a group of ws-iam's second tenancy: to them it is a third party.
    neo4j_session.run(
        """
        MATCH (t:OCITenancy{id: $other})
        MERGE (t)-[:RESOURCE]->(p:OCIPolicy{id: 'iam-policy-other'})
        SET p.ocid = 'iam-policy-other', p.name = 'admit-vendor', p.compartmentid = $other,
            p.statements = ['Admit group Vendors of tenancy ' + $own2 + ' to read all-resources in tenancy']
        """,
        other=OTHER_CUSTOMER_TENANCY, own2=OWN_SECOND_TENANCY,
    )

    _sync_policy_references(neo4j_session, 'ws-iam', OWN_TENANCY)
    _sync_policy_references(neo4j_session, 'ws-iam-other', OTHER_CUSTOMER_TENANCY)

    # Both policies trust the same OCIExternalPrincipal node; the last sync must not rewrite ws-iam's view.
    assert (OWN_SECOND_TENANCY, 'CrossAccount', 'endorse') in _trusted_principals(neo4j_session, 'iam-policy')
    assert _trusted_principals(neo4j_session, 'iam-policy-other') == {(OWN_SECOND_TENANCY, 'ThirdParty', 'admit')}
    # The shared node holds only global facts.
    node = neo4j_session.run(
        "MATCH (ep:OCIExternalPrincipal{principal: $p}) RETURN ep.access_type AS a, ep.statement_verb AS v, "
        "ep.account_id AS account_id",
        p=OWN_SECOND_TENANCY,
    ).single()
    assert (node['a'], node['v'], node['account_id']) == (None, None, OWN_SECOND_TENANCY)


def test_tenancy_lookups_return_only_the_tenancys_own_iam_objects(neo4j_session):
    tenancies = {'lk-a': 'ocid1.tenancy.oc1..lookupaaaa', 'lk-b': 'ocid1.tenancy.oc1..lookupbbbb'}
    for prefix, tenancy_id in tenancies.items():
        neo4j_session.run(
            """
            MERGE (w:CloudanixWorkspace{id: $prefix + '-ws'})
            MERGE (t:OCITenancy{id: $tenancy_id})
            MERGE (w)-[:OWNER]->(t)
            MERGE (t)-[:OWNER]->(c:OCICompartment{id: $prefix + '-compartment'})
            SET c.ocid = c.id, c.name = $prefix + '-compartment'
            MERGE (t)-[:RESOURCE]->(g:OCIGroup{id: $prefix + '-group'}) SET g.ocid = g.id, g.name = 'Administrators'
            MERGE (t)-[:RESOURCE]->(p:OCIPolicy{id: $prefix + '-policy'}) SET p.ocid = p.id, p.name = 'admins'
            MERGE (region:OCIRegion{id: 'IAD'}) SET region.key = 'IAD', region.name = 'us-ashburn-1'
            MERGE (t)-[:OCI_REGION_SUBSCRIPTION]->(region)
            """,
            prefix=prefix, tenancy_id=tenancy_id,
        )
    # Both tenancies reach the shared region node. The current model has no edge out of a shared node into a
    # tenancy, so this one is synthetic: it stands for any such link and must not pull B's IAM objects into A.
    neo4j_session.run(
        "MATCH (r:OCIRegion{id: 'IAD'}), (t:OCITenancy{id: $b}) MERGE (r)-[:SYNTHETIC_SHARED_LINK]->(t)",
        b=tenancies['lk-b'],
    )
    # A node of another label carrying tenancy A's OCID must not act as the anchor either.
    neo4j_session.run(
        "MERGE (x:OCICompartment{id: $a}) MERGE (x)-[:RESOURCE]->(:OCIGroup{id: 'lk-x-group', name: 'x'})",
        a=tenancies['lk-a'],
    )

    tenancy_a, ws_a = tenancies['lk-a'], 'lk-a-ws'
    assert {g['ocid'] for g in utils.get_groups_in_tenancy(neo4j_session, tenancy_a, ws_a)} == {'lk-a-group'}
    assert {p['ocid'] for p in utils.get_policies_in_tenancy(neo4j_session, tenancy_a, ws_a)} == {'lk-a-policy'}
    assert {
        c['ocid'] for c in utils.get_compartments_in_tenancy(neo4j_session, tenancy_a, ws_a)
    } == {'lk-a-compartment'}
    assert {r['key'] for r in utils.get_regions_in_tenancy(neo4j_session, tenancy_a, ws_a)} == {'IAD'}

    # Tenancy A looked up through a workspace that does not own it: nothing.
    lookups = (
        utils.get_groups_in_tenancy, utils.get_policies_in_tenancy,
        utils.get_compartments_in_tenancy, utils.get_regions_in_tenancy,
    )
    for lookup in lookups:
        assert lookup(neo4j_session, tenancy_a, 'lk-b-ws') == [], lookup.__name__
