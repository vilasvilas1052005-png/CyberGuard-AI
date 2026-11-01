"""Cross-account data isolation: a newly registered VIEWER sees an empty private detection
history and cannot fetch an existing Admin detection by ID.
"""

from tests.helpers import login, register_viewer


def test_viewer_has_empty_history_and_cannot_read_admin_detection(client):
    admin = login(client)
    assert admin["role"] == "ADMIN"
    admin_detections = client.get("/detections")
    assert admin_detections.status_code == 200, f"GET /detections {admin_detections.status_code}: {admin_detections.text[:200]}"
    admin_items = admin_detections.json()
    assert len(admin_items) > 0, "expected the seeded Admin account to already have detection history"
    admin_detection_id = admin_items[0]["id"]
    client.post("/auth/logout")

    viewer = register_viewer(client, prefix="tscheck-isolation-viewer")
    login_response = client.post("/auth/login", json={"username": viewer["username"], "password": viewer["password"]})
    assert login_response.status_code == 200, f"POST /auth/login {login_response.status_code}: {login_response.text[:200]}"

    viewer_detections = client.get("/detections")
    assert viewer_detections.status_code == 200, f"GET /detections {viewer_detections.status_code}: {viewer_detections.text[:200]}"
    assert viewer_detections.json() == [], f"expected an empty private history for a brand-new VIEWER, got {viewer_detections.json()[:2]}"

    forbidden_read = client.get(f"/detections/{admin_detection_id}")
    assert forbidden_read.status_code == 404, f"GET /detections/{{admin_id}} {forbidden_read.status_code}: {forbidden_read.text[:200]}"
