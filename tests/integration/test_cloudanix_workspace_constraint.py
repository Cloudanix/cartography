import neo4j
import pytest

import cloudanix
from cartography.intel import create_indexes

CONSTRAINT = cloudanix.WORKSPACE_ID_CONSTRAINT


def _drop_schema(neo4j_session):
    neo4j_session.run(f"DROP CONSTRAINT {CONSTRAINT} IF EXISTS")
    for record in list(
        neo4j_session.run(
            "SHOW INDEXES YIELD name, labelsOrTypes WHERE labelsOrTypes = ['CloudanixWorkspace'] RETURN name",
        ),
    ):
        neo4j_session.run(f"DROP INDEX `{record['name']}` IF EXISTS")
    neo4j_session.run("MATCH (w:CloudanixWorkspace) DETACH DELETE w")


def _constraint_count(neo4j_session):
    return neo4j_session.run(
        "SHOW CONSTRAINTS YIELD name WHERE name = $name RETURN count(*) AS n", name=CONSTRAINT,
    ).single()['n']


def test_replaces_the_plain_index_with_a_unique_constraint(neo4j_session):
    _drop_schema(neo4j_session)
    neo4j_session.run("CREATE INDEX IF NOT EXISTS FOR (n:CloudanixWorkspace) ON (n.id)")
    neo4j_session.run("CREATE (:CloudanixWorkspace{id: 'ws-unique-1'})")

    assert cloudanix.ensure_workspace_id_unique(neo4j_session) is True
    assert cloudanix.ensure_workspace_id_unique(neo4j_session) is True  # idempotent

    assert _constraint_count(neo4j_session) == 1
    with pytest.raises(neo4j.exceptions.ConstraintError):
        neo4j_session.run("CREATE (:CloudanixWorkspace{id: 'ws-unique-1'})").consume()
    # indexes.cypher and schema-model loaders keep issuing this; it must stay a no-op next to the constraint.
    create_indexes.run(neo4j_session, None)
    neo4j_session.run("CREATE INDEX IF NOT EXISTS FOR (n:CloudanixWorkspace) ON (n.id)").consume()
    _drop_schema(neo4j_session)


def test_leaves_duplicates_and_index_in_place_until_they_are_merged(neo4j_session):
    _drop_schema(neo4j_session)
    neo4j_session.run("CREATE INDEX IF NOT EXISTS FOR (n:CloudanixWorkspace) ON (n.id)")
    neo4j_session.run("CREATE (:CloudanixWorkspace{id: 'ws-dup-1'}), (:CloudanixWorkspace{id: 'ws-dup-1'})")

    assert cloudanix.ensure_workspace_id_unique(neo4j_session) is False

    assert _constraint_count(neo4j_session) == 0
    assert neo4j_session.run(
        "MATCH (w:CloudanixWorkspace{id: 'ws-dup-1'}) RETURN count(w) AS n",
    ).single()['n'] == 2
    indexes = neo4j_session.run(
        "SHOW INDEXES YIELD labelsOrTypes WHERE labelsOrTypes = ['CloudanixWorkspace'] RETURN count(*) AS n",
    ).single()['n']
    assert indexes == 1
    _drop_schema(neo4j_session)
