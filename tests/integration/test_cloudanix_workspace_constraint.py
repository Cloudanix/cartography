import neo4j
import pytest

from cartography.intel import create_indexes

CONSTRAINT = 'cloudanix_workspace_id_unique'


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


def test_indexes_cypher_creates_the_workspace_id_constraint(neo4j_session):
    _drop_schema(neo4j_session)

    create_indexes.run(neo4j_session, None)
    create_indexes.run(neo4j_session, None)  # idempotent

    assert _constraint_count(neo4j_session) == 1
    neo4j_session.run("CREATE (:CloudanixWorkspace{id: 'ws-unique-1'})").consume()
    with pytest.raises(neo4j.exceptions.ConstraintError):
        neo4j_session.run("CREATE (:CloudanixWorkspace{id: 'ws-unique-1'})").consume()
    # schema-model loaders may still issue this; it must stay a no-op next to the constraint.
    neo4j_session.run("CREATE INDEX IF NOT EXISTS FOR (n:CloudanixWorkspace) ON (n.id)").consume()
    _drop_schema(neo4j_session)
