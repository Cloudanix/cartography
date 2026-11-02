from cartography.intel.oci import database

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
