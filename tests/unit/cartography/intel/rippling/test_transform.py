from cartography.intel.rippling.transform import build_graph


def _user():
    return {
        "id": "u_1",
        "active": True,
        "username": "alice",
        "display_name": "Alice Doe",
        "created_at": "2024-01-02T00:00:00Z",
        "updated_at": "2024-06-02T00:00:00Z",
        "name": {"formatted": "Alice D", "given_name": "Alice", "family_name": "Doe"},
        "emails": [
            {"type": "HOME", "value": "alice.home@example"},
            {"type": "WORK", "value": "alice.work@example"},
        ],
    }


def test_user_prefers_active_worker_and_work_email():
    graph = build_graph(
        users=[_user()],
        workers=[
            {"id": "w_old", "user_id": "u_1", "status": "TERMINATED", "updated_at": "2024-06-01T00:00:00Z", "work_email": "old@example"},
            {"id": "w_1", "user_id": "u_1", "status": "ACTIVE", "updated_at": "2024-05-01T00:00:00Z", "work_email": "alice.doe@acme.example"},
        ],
        supergroups=[],
        members_by_supergroup={},
    )

    user = graph["users"][0]
    assert user["worker_id"] == "w_1"
    assert user["worker_status"] == "ACTIVE"
    assert user["is_active"] is True
    assert user["email"] == "alice.doe@acme.example"
    assert user["identity_id"] == "alice.doe@acme.example"
    assert user["name"] == "Alice Doe"


def test_terminated_worker_is_inactive_and_home_email_is_ignored():
    user = _user()
    user["emails"] = [{"type": "HOME", "value": "alice.home@example"}]
    graph = build_graph(
        users=[user],
        workers=[{"id": "w_1", "user_id": "u_1", "status": "TERMINATED", "work_email": None}],
        supergroups=[],
        members_by_supergroup={},
    )

    assert graph["users"][0]["is_active"] is False
    assert graph["users"][0]["email"] is None


def test_supergroups_split_and_members_404_omits_count():
    graph = build_graph(
        users=[_user()],
        workers=[{"id": "w_1", "user_id": "u_1", "status": "ACTIVE"}],
        supergroups=[
            {"id": "sg_eng", "name": "engineering", "display_name": "Engineering", "read_only": False},
            {
                "id": "sg_admin",
                "name": "github_admin",
                "display_name": "Admin",
                "app_owner_id": "app_github",
                "parent": "sg_prov",
                "read_only": False,
            },
            {
                "id": "sg_prov",
                "name": "github_prov",
                "display_name": "PROVISIONING",
                "app_owner_id": "app_github",
                "read_only": True,
            },
        ],
        members_by_supergroup={
            "sg_eng": [{"worker_id": "w_1"}],
            "sg_admin": None,
            "sg_prov": [{"worker_id": "w_1"}],
        },
    )

    assert [row["id"] for row in graph["groups"]] == ["sg_eng"]
    assert graph["groups"][0]["member_count"] == 1
    assert graph["groups"][0]["membership_available"] is True
    admin = next(row for row in graph["accessgroups"] if row["id"] == "sg_admin")
    assert "member_count" not in admin
    assert admin["membership_available"] is False
    assert admin["grant_mechanism"] == "direct_user"
    provisioning = next(row for row in graph["accessgroups"] if row["id"] == "sg_prov")
    assert provisioning["grant_mechanism"] == "none"
    assert graph["applications"] == [{"id": "app_github", "name": "app_github", "access_count": 2}]
    assert {"from_id": "sg_admin", "to_id": "sg_prov"} in graph["child_edges"]
    assert {"user_id": "u_1", "target_id": "sg_eng", "relationship": "MEMBER_OF"} in graph["member_edges"]
    assert {"user_id": "u_1", "target_id": "sg_prov", "relationship": "HAS_ACCESS"} in graph["member_edges"]
    assert all(edge["target_id"] != "sg_admin" for edge in graph["member_edges"])
    assert {edge["to_id"] for edge in graph["application_edges"]} == {"sg_admin", "sg_prov"}
