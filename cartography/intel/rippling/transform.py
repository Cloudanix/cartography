from typing import Any

# Lower rank wins. Same rank keeps the worker with the latest updated_at.
WORKER_STATUS_RANK = {
    "ACTIVE": 0,
    "HIRED": 1,
    "ACCEPTED": 2,
    "INIT": 3,
    "TERMINATED": 4,
}


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _parent_id(supergroup: dict[str, Any]) -> str | None:
    parent = supergroup.get("parent")
    if isinstance(parent, dict):
        return _text(parent.get("id"))
    return _text(parent)


def _pick_worker(workers: list[dict[str, Any]]) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    for worker in workers:
        if best is None:
            best = worker
            continue
        rank = WORKER_STATUS_RANK.get(worker.get("status") or "", 99)
        best_rank = WORKER_STATUS_RANK.get(best.get("status") or "", 99)
        if rank < best_rank or (
            rank == best_rank and (worker.get("updated_at") or "") > (best.get("updated_at") or "")
        ):
            best = worker
    return best


def _work_email(user: dict[str, Any], worker: dict[str, Any] | None) -> str | None:
    if worker is not None:
        email = _text(worker.get("work_email"))
        if email:
            return email
    for email in user.get("emails") or []:
        if isinstance(email, dict) and email.get("type") == "WORK":
            value = _text(email.get("value"))
            if value:
                return value
    return None


def _user_name(user: dict[str, Any]) -> str:
    name = user.get("name") if isinstance(user.get("name"), dict) else {}
    return (
        _text(user.get("display_name"))
        or _text(name.get("formatted"))
        or _text(user.get("username"))
        or str(user.get("id"))
    )


def _is_active(user: dict[str, Any], worker: dict[str, Any] | None) -> bool:
    active = user.get("active") is not False
    if worker is not None and worker.get("status") == "TERMINATED":
        return False
    return active


def _group_name(supergroup: dict[str, Any]) -> str:
    return _text(supergroup.get("display_name")) or _text(supergroup.get("name")) or str(supergroup.get("id"))


def build_graph(
    users: list[dict[str, Any]],
    workers: list[dict[str, Any]],
    supergroups: list[dict[str, Any]],
    members_by_supergroup: dict[str, list[dict[str, Any]] | None],
) -> dict[str, Any]:
    """Turn Rippling list payloads into the four inventory node kinds and their edges.

    `members_by_supergroup` value None means the members call returned 404.
    """
    workers_by_user: dict[str, list[dict[str, Any]]] = {}
    worker_to_user: dict[str, str] = {}
    for worker in workers:
        user_id = _text(worker.get("user_id"))
        worker_id = _text(worker.get("id"))
        if user_id:
            workers_by_user.setdefault(user_id, []).append(worker)
        if worker_id and user_id:
            worker_to_user[worker_id] = user_id

    user_nodes = []
    for user in users:
        user_id = _text(user.get("id"))
        if not user_id:
            continue
        worker = _pick_worker(workers_by_user.get(user_id, []))
        name_obj = user.get("name") if isinstance(user.get("name"), dict) else {}
        email = _work_email(user, worker)
        node = {
            "id": user_id,
            "name": _user_name(user),
            "is_active": _is_active(user, worker),
            "username": _text(user.get("username")),
            "given_name": _text(name_obj.get("given_name")),
            "family_name": _text(name_obj.get("family_name")),
            "email": email,
            "identity_id": email,
            "created_at": _text(user.get("created_at")),
            "updated_at": _text(user.get("updated_at")),
        }
        if worker is not None:
            node["worker_id"] = _text(worker.get("id"))
            node["worker_status"] = _text(worker.get("status"))
        user_nodes.append(node)

    groups = []
    accessgroups = []
    for supergroup in supergroups:
        supergroup_id = _text(supergroup.get("id"))
        if not supergroup_id:
            continue
        app_owner_id = _text(supergroup.get("app_owner_id"))
        members = members_by_supergroup.get(supergroup_id)
        record = {
            "id": supergroup_id,
            "name": _group_name(supergroup),
            "internal_name": _text(supergroup.get("name")),
            "group_type": _text(supergroup.get("group_type")),
            "sub_group_type": _text(supergroup.get("sub_group_type")),
            "read_only": supergroup.get("read_only") is True,
            "created_at": _text(supergroup.get("created_at")),
            "updated_at": _text(supergroup.get("updated_at")),
            "membership_available": members is not None,
            "parent_id": _parent_id(supergroup),
            "application_id": app_owner_id,
            "members": members,
        }
        if members is not None:
            record["member_count"] = len(members)
        if app_owner_id:
            record["grant_mechanism"] = "none" if record["read_only"] else "direct_user"
            accessgroups.append(record)
        else:
            groups.append(record)

    accessgroup_ids = {row["id"] for row in accessgroups}
    child_edges = []
    for accessgroup in accessgroups:
        parent_id = accessgroup.get("parent_id")
        if parent_id in accessgroup_ids and parent_id != accessgroup["id"]:
            child_edges.append({"from_id": accessgroup["id"], "to_id": parent_id})

    applications: dict[str, dict[str, Any]] = {}
    app_edges = []
    for accessgroup in accessgroups:
        app_id = accessgroup["application_id"]
        application = applications.setdefault(
            app_id,
            {"id": app_id, "name": app_id, "access_count": 0},
        )
        application["access_count"] += 1
        app_edges.append({"from_id": app_id, "to_id": accessgroup["id"]})

    known_users = {node["id"] for node in user_nodes}
    member_edges = []
    for collection, relationship in ((groups, "MEMBER_OF"), (accessgroups, "HAS_ACCESS")):
        for row in collection:
            members = row.get("members")
            if not members:
                continue
            for member in members:
                worker_id = _text(member.get("worker_id"))
                user_id = worker_to_user.get(worker_id or "")
                if user_id and user_id in known_users:
                    member_edges.append(
                        {
                            "user_id": user_id,
                            "target_id": row["id"],
                            "relationship": relationship,
                        },
                    )

    return {
        "users": user_nodes,
        "groups": groups,
        "accessgroups": accessgroups,
        "applications": list(applications.values()),
        "member_edges": member_edges,
        "child_edges": child_edges,
        "application_edges": app_edges,
    }
