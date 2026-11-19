import logging
from typing import Any

import neo4j

from cartography.client.core.tx import run_write_query
from cartography.config import Config
from cartography.intel.rippling import api as rippling_api
from cartography.intel.rippling.transform import build_graph
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

_CHUNK = 200


def _chunks(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    return [rows[index : index + _CHUNK] for index in range(0, len(rows), _CHUNK)] or [[]]


def _drop_members(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in row.items() if key != "members"} for row in rows]


def _load_company(session: neo4j.Session, company_id: str, workspace_id: str, update_tag: int) -> None:
    run_write_query(
        session,
        """
        MERGE (company:RipplingCompany {id: $company_id})
        ON CREATE SET company.firstseen = timestamp()
        SET company.lastupdated = $update_tag
        WITH company
        MATCH (owner:CloudanixWorkspace {id: $workspace_id})
        MERGE (owner)-[rel:OWNER]->(company)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $update_tag
        """,
        company_id=company_id,
        workspace_id=workspace_id,
        update_tag=update_tag,
    )


def _load_nodes(
    session: neo4j.Session,
    company_id: str,
    label: str,
    rows: list[dict[str, Any]],
    update_tag: int,
    properties: list[str],
) -> None:
    assignments = ", ".join(f"node.{prop} = row.{prop}" for prop in properties)
    query = f"""
        UNWIND $rows AS row
        MERGE (node:{label} {{id: row.id}})
        ON CREATE SET node.firstseen = timestamp()
        SET node.lastupdated = $update_tag, {assignments}
        WITH node
        MATCH (company:RipplingCompany {{id: $company_id}})
        MERGE (company)-[rel:RESOURCE]->(node)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $update_tag
    """
    for chunk in _chunks(rows):
        if not chunk or not chunk[0]:
            continue
        run_write_query(session, query, rows=chunk, company_id=company_id, update_tag=update_tag)


def _replace_edges(
    session: neo4j.Session,
    company_id: str,
    query: str,
    rows: list[dict[str, Any]],
    update_tag: int,
) -> None:
    for chunk in _chunks(rows):
        if not chunk or not chunk[0]:
            continue
        run_write_query(session, query, rows=chunk, company_id=company_id, update_tag=update_tag)


def load_graph(session: neo4j.Session, company_id: str, workspace_id: str, update_tag: int, graph: dict[str, Any]) -> None:
    _load_company(session, company_id, workspace_id, update_tag)
    _load_nodes(
        session,
        company_id,
        "RipplingUser",
        graph["users"],
        update_tag,
        [
            "name",
            "is_active",
            "username",
            "given_name",
            "family_name",
            "email",
            "identity_id",
            "worker_id",
            "worker_status",
            "created_at",
            "updated_at",
        ],
    )
    shared = [
        "name",
        "internal_name",
        "group_type",
        "sub_group_type",
        "read_only",
        "membership_available",
        "member_count",
        "created_at",
        "updated_at",
    ]
    _load_nodes(session, company_id, "RipplingGroup", _drop_members(graph["groups"]), update_tag, shared)
    _load_nodes(
        session,
        company_id,
        "RipplingAccessGroup",
        _drop_members(graph["accessgroups"]),
        update_tag,
        shared + ["application_id", "parent_id", "grant_mechanism"],
    )
    _load_nodes(
        session,
        company_id,
        "RipplingApplication",
        graph["applications"],
        update_tag,
        ["name", "access_count"],
    )

    fetched_groups = [row["id"] for row in graph["groups"] if row.get("members") is not None]
    fetched_access = [row["id"] for row in graph["accessgroups"] if row.get("members") is not None]
    if fetched_groups:
        run_write_query(
            session,
            """
            UNWIND $ids AS id
            MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(group:RipplingGroup {id: id})
            OPTIONAL MATCH (:RipplingUser)-[rel:MEMBER_OF]->(group)
            DELETE rel
            """,
            ids=fetched_groups,
            company_id=company_id,
        )
    if fetched_access:
        run_write_query(
            session,
            """
            UNWIND $ids AS id
            MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(group:RipplingAccessGroup {id: id})
            OPTIONAL MATCH (:RipplingUser)-[rel:HAS_ACCESS]->(group)
            DELETE rel
            """,
            ids=fetched_access,
            company_id=company_id,
        )
    run_write_query(
        session,
        """
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(node)
        WHERE node:RipplingAccessGroup OR node:RipplingApplication
        OPTIONAL MATCH (node)-[rel:CHILD_OF|HAS_ACCESSGROUP]->()
        DELETE rel
        """,
        company_id=company_id,
    )
    member_of = [row for row in graph["member_edges"] if row["relationship"] == "MEMBER_OF"]
    has_access = [row for row in graph["member_edges"] if row["relationship"] == "HAS_ACCESS"]
    _replace_edges(
        session,
        company_id,
        """
        UNWIND $rows AS row
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(user:RipplingUser {id: row.user_id})
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(target:RipplingGroup {id: row.target_id})
        MERGE (user)-[rel:MEMBER_OF]->(target)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $update_tag
        """,
        member_of,
        update_tag,
    )
    _replace_edges(
        session,
        company_id,
        """
        UNWIND $rows AS row
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(user:RipplingUser {id: row.user_id})
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(target:RipplingAccessGroup {id: row.target_id})
        MERGE (user)-[rel:HAS_ACCESS]->(target)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $update_tag
        """,
        has_access,
        update_tag,
    )
    _replace_edges(
        session,
        company_id,
        """
        UNWIND $rows AS row
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(child:RipplingAccessGroup {id: row.from_id})
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(parent:RipplingAccessGroup {id: row.to_id})
        MERGE (child)-[rel:CHILD_OF]->(parent)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $update_tag
        """,
        graph["child_edges"],
        update_tag,
    )
    _replace_edges(
        session,
        company_id,
        """
        UNWIND $rows AS row
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(app:RipplingApplication {id: row.from_id})
        MATCH (:RipplingCompany {id: $company_id})-[:RESOURCE]->(access:RipplingAccessGroup {id: row.to_id})
        MERGE (app)-[rel:HAS_ACCESSGROUP]->(access)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $update_tag
        """,
        graph["application_edges"],
        update_tag,
    )


def _company_id(companies: list[dict[str, Any]], account_id: str) -> str | None:
    for company in companies:
        if company.get("id") == account_id:
            return account_id
    return None


@timeit
def start_rippling_ingestion(neo4j_session: neo4j.Session, config: Config) -> dict[str, Any]:
    """Pull one Rippling company into Neo4j. A failed core call leaves the previous graph."""
    access_token = config.rippling_access_token
    workspace_id = (config.params or {}).get("workspace", {}).get("id_string", "")
    account_id = (config.params or {}).get("workspace", {}).get("account_id", "")
    if not access_token:
        return {"authFailed": True, "message": "rippling authentication failed: access token is missing"}
    if not isinstance(account_id, str) or not account_id or not workspace_id:
        return {"authFailed": True, "message": "rippling sync did not complete: company id is missing"}

    try:
        companies = rippling_api.list_results(access_token, "/companies/")
        if _company_id(companies, account_id) is None:
            logger.error("rippling token company does not match account_id %s", account_id)
            return {
                "authFailed": True,
                "message": "rippling sync did not complete: token company does not match account_id",
            }
        users = rippling_api.list_results(access_token, "/users/")
        workers = rippling_api.list_results(access_token, "/workers/", {"expand": "department,employment_type"})
        supergroups = rippling_api.list_results(access_token, "/supergroups/")
        members_by_supergroup: dict[str, list[dict[str, Any]] | None] = {}
        for supergroup in supergroups:
            supergroup_id = supergroup.get("id")
            if isinstance(supergroup_id, str) and supergroup_id:
                members_by_supergroup[supergroup_id] = rippling_api.list_members(access_token, supergroup_id)
    except rippling_api.RipplingRequestError as exc:
        logger.error("rippling request failed before the graph was replaced: %s", exc)
        return {"authFailed": True, "message": f"rippling request failed before sync completed: {exc}"}

    update_tag = config.update_tag
    graph = build_graph(users, workers, supergroups, members_by_supergroup)
    load_graph(neo4j_session, account_id, workspace_id, update_tag, graph)
    run_cleanup_job(
        "rippling_company_cleanup.json",
        neo4j_session,
        {
            "WORKSPACE_ID": workspace_id,
            "RIPPLING_COMPANY_ID": account_id,
            "UPDATE_TAG": update_tag,
        },
    )
    return {
        "WORKSPACE_ID": workspace_id,
        "RIPPLING_COMPANY_ID": account_id,
        "UPDATE_TAG": update_tag,
    }
