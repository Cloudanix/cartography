import logging

import neo4j

from cartography.util import run_cleanup_job  # noqa: F401
from cartography.util import timeit

logger = logging.getLogger(__name__)

WORKSPACE_ID_CONSTRAINT = 'cloudanix_workspace_id_unique'


@timeit
def run(neo4j_session, config):
    common_job_parameters = {
        "UPDATE_TAG": config.update_tag,
        "WORKSPACE_ID": config.params['workspace']['id_string'],
        "WORKSPACE_NAME": config.params['workspace']['name'],
        "WORKSPACE_ACCOUNT_ID": config.params['workspace']['account_id'],
    }

    try:
        ensure_workspace_id_unique(neo4j_session)
    except neo4j.exceptions.Neo4jError as e:
        # Never fail a sync over the constraint: the MERGE below still works without it.
        logger.warning(f"Could not ensure the {WORKSPACE_ID_CONSTRAINT} constraint: {e}")

    load_cloudanix_workspace(neo4j_session, config.update_tag, common_job_parameters)

    # TODO: do we need to cleanup?
    # run_cleanup_job('cloudanix_workspace_cleanup.json', neo4j_session, common_job_parameters)


def ensure_workspace_id_unique(neo4j_session: neo4j.Session) -> bool:
    """
    Make CloudanixWorkspace.id unique, so concurrent syncs of one workspace MERGE one node instead of racing into
    duplicates. Every tenant anchor starts from this node, so a duplicate splits a tenant's subtree.

    Returns True when the constraint exists. While duplicate nodes exist the constraint cannot be created: this
    logs an error and returns False, leaving the plain index in place; merge the duplicates, the next sync adds it.
    Neo4j refuses a uniqueness constraint over a schema a plain index already covers, so that index (from
    indexes.cypher) is dropped first; the constraint's own index replaces it.
    """
    existing = neo4j_session.run(
        "SHOW CONSTRAINTS YIELD name WHERE name = $name RETURN count(*) AS n", name=WORKSPACE_ID_CONSTRAINT,
    ).single()['n']
    if existing:
        return True

    duplicate_ids = neo4j_session.run(
        "MATCH (w:CloudanixWorkspace) WHERE w.id IS NOT NULL "
        "WITH w.id AS id, count(*) AS nodes WHERE nodes > 1 RETURN count(id) AS ids",
    ).single()['ids']
    if duplicate_ids:
        logger.error(
            f"{duplicate_ids} workspace ids have more than one CloudanixWorkspace node; merge them so the "
            f"{WORKSPACE_ID_CONSTRAINT} constraint can be created",
        )
        return False

    plain_indexes = [
        record['name'] for record in neo4j_session.run(
            "SHOW INDEXES YIELD name, labelsOrTypes, properties, owningConstraint "
            "WHERE labelsOrTypes = ['CloudanixWorkspace'] AND properties = ['id'] AND owningConstraint IS NULL "
            "RETURN name",
        )
    ]
    for name in plain_indexes:
        neo4j_session.run(f"DROP INDEX `{name}` IF EXISTS")
    neo4j_session.run(
        f"CREATE CONSTRAINT {WORKSPACE_ID_CONSTRAINT} IF NOT EXISTS "
        "FOR (w:CloudanixWorkspace) REQUIRE w.id IS UNIQUE",
    )
    logger.info(f"Created the {WORKSPACE_ID_CONSTRAINT} constraint (dropped plain indexes: {plain_indexes})")
    return True


def load_cloudanix_workspace(neo4j_session, update_tag, common_job_parameters):
    neo4j_session.execute_write(load_cloudanix_workspace_tx, update_tag, common_job_parameters)


def load_cloudanix_workspace_tx(tx, update_tag, common_job_parameters):
    # TODO: do we need to assign `account_id`, it changes for each inventory run. Is it used anywhere?
    query = """
    MERGE (w:CloudanixWorkspace{id: $WORKSPACE_ID})
    ON CREATE SET
        w.firstseen = timestamp()
    SET
        w.lastupdated = $UPDATE_TAG,
        w.name = $WORKSPACE_NAME,
        w.account_id= $WORKSPACE_ACCOUNT_ID
    """

    tx.run(
        query,
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
        WORKSPACE_NAME=common_job_parameters['WORKSPACE_NAME'],
        WORKSPACE_ACCOUNT_ID=common_job_parameters['WORKSPACE_ACCOUNT_ID'],
        UPDATE_TAG=update_tag,
    )
