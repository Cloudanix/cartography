from typing import Dict


def seed_tenancy(neo4j_session, prefix: str) -> Dict[str, str]:
    """
    Seed one tenant's root chain, workspace -> tenancy -> compartment, as organizations.py and
    compartment.py write it. Returns its ids and the job parameters a sync of it would carry.
    """
    ids = {
        'WORKSPACE_ID': f'{prefix}-ws',
        'OCI_TENANCY_ID': f'ocid1.tenancy.oc1..{prefix}',
        'OCI_COMPARTMENT_ID': f'ocid1.compartment.oc1..{prefix}',
    }
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: $WORKSPACE_ID})
        MERGE (t:OCITenancy{id: $OCI_TENANCY_ID})
        MERGE (c:OCICompartment{id: $OCI_COMPARTMENT_ID})
        MERGE (w)-[:OWNER]->(t)
        MERGE (t)-[:OWNER]->(c)
        """,
        **ids,
    )
    return ids


def linked(neo4j_session, source_id: str, rel: str, target_id: str) -> bool:
    """True when (source{id})-[rel]->(target{id}) exists, whatever the labels."""
    return neo4j_session.run(
        f"MATCH ({{id: $source_id}})-[:{rel}]->({{id: $target_id}}) RETURN count(*) > 0 AS found",
        source_id=source_id, target_id=target_id,
    ).single()['found']
