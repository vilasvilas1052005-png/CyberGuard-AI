"""Detection history deletion: DELETE /detections/history removes only the authenticated
account's own detections and related events/agents/incidents/responses/URL checks, keeps a
deletion audit entry, and never touches another account's data (the seeded Admin included).
"""

import asyncio

from tests.helpers import login, seed_analyst_user


def test_delete_history_scoped_to_own_account_and_audited(client):
    # Baseline: read (never mutate) the seeded Admin's detection count for the isolation check.
    admin = login(client)
    assert admin["role"] == "ADMIN"
    admin_before = client.get("/detections")
    assert admin_before.status_code == 200
    admin_count_before = len(admin_before.json())
    client.post("/auth/logout")

    # Fixture ANALYST account (direct-DB seed; public /auth/register only ever creates VIEWER).
    analyst = asyncio.run(seed_analyst_user(prefix="tscheck-delete-analyst"))
    login_response = client.post("/auth/login", json={"username": analyst["username"], "password": analyst["password"]})
    assert login_response.status_code == 200, f"POST /auth/login {login_response.status_code}: {login_response.text[:200]}"
    assert login_response.json()["role"] == "ANALYST"

    analyze_response = client.post("/detection/analyze", json={"event_type": "Port Scan Pattern", "source_ip": "10.0.0.77", "failed_attempts": 5, "traffic_volume": 500})
    assert analyze_response.status_code == 200, f"POST /detection/analyze {analyze_response.status_code}: {analyze_response.text[:200]}"
    created_threat_id = analyze_response.json()["threat_id"]

    own_detections = client.get("/detections")
    assert own_detections.status_code == 200
    assert any(item["id"] == created_threat_id for item in own_detections.json()), "created detection missing from own history before deletion"

    delete_response = client.delete("/detections/history")
    assert delete_response.status_code == 200, f"DELETE /detections/history {delete_response.status_code}: {delete_response.text[:200]}"
    deleted = delete_response.json()["deleted"]
    assert deleted["detections"] >= 1, f"expected at least one deleted detection, got {deleted}"

    after_delete = client.get("/detections")
    assert after_delete.status_code == 200
    assert after_delete.json() == [], f"expected empty history for {analyst['username']} after deletion, got {after_delete.json()[:2]}"

    detail_after_delete = client.get(f"/detections/{created_threat_id}")
    assert detail_after_delete.status_code == 404, f"GET /detections/{{id}} after deletion {detail_after_delete.status_code}: {detail_after_delete.text[:200]}"

    audit_response = client.get("/audit-logs")
    assert audit_response.status_code == 200, f"GET /audit-logs {audit_response.status_code}: {audit_response.text[:200]}"
    audit_entries = [row for row in audit_response.json() if row.get("action") == "DETECTION_HISTORY_DELETED" and row.get("user") == analyst["username"]]
    assert len(audit_entries) >= 1, "expected a retained DETECTION_HISTORY_DELETED audit entry for this account"

    client.post("/auth/logout")

    # The seeded Admin account's own history must be completely unaffected.
    login(client)
    admin_after = client.get("/detections")
    assert admin_after.status_code == 200
    assert len(admin_after.json()) == admin_count_before, "another account's Delete History call must not change Admin's detection count"
