"""Role protection: public sign-up always creates VIEWER, and VIEWER is rejected (403) from
writer/admin-only controls while read-only pages remain accessible.
"""

from tests.helpers import register_viewer


def test_public_signup_forces_viewer_role_and_blocks_writer_actions(client):
    viewer = register_viewer(client, prefix="tscheck-role-viewer")

    login_response = client.post("/auth/login", json={"username": viewer["username"], "password": viewer["password"]})
    assert login_response.status_code == 200, f"POST /auth/login {login_response.status_code}: {login_response.text[:200]}"
    assert login_response.json()["role"] == "VIEWER", f"expected VIEWER role, got {login_response.json()}"

    # Writer/admin-only controls must all reject VIEWER with 403.
    simulator_response = client.post("/simulator/start", json={})
    assert simulator_response.status_code == 403, f"POST /simulator/start {simulator_response.status_code}: {simulator_response.text[:200]}"

    analyze_response = client.post("/detection/analyze", json={"event_type": "Port Scan Pattern", "source_ip": "10.0.0.9"})
    assert analyze_response.status_code == 403, f"POST /detection/analyze {analyze_response.status_code}: {analyze_response.text[:200]}"

    url_response = client.post("/url-checks/analyze", json={"url": "https://example.com", "authorized": True})
    assert url_response.status_code == 403, f"POST /url-checks/analyze {url_response.status_code}: {url_response.text[:200]}"

    upload_response = client.post("/datasets/upload", files={"file": ("tscheck.csv", b"duration,label\n1,normal\n", "text/csv")})
    assert upload_response.status_code == 403, f"POST /datasets/upload {upload_response.status_code}: {upload_response.text[:200]}"

    incident_response = client.patch("/incidents/nonexistent-tscheck-id", json={"status": "INVESTIGATING"})
    assert incident_response.status_code == 403, f"PATCH /incidents/{{id}} {incident_response.status_code}: {incident_response.text[:200]}"

    train_response = client.post("/models/train", json={})
    assert train_response.status_code == 403, f"POST /models/train {train_response.status_code}: {train_response.text[:200]}"

    # Read-only pages remain accessible to VIEWER.
    dashboard_response = client.get("/dashboard/summary")
    assert dashboard_response.status_code == 200, f"GET /dashboard/summary {dashboard_response.status_code}: {dashboard_response.text[:200]}"

    detections_response = client.get("/detections")
    assert detections_response.status_code == 200, f"GET /detections {detections_response.status_code}: {detections_response.text[:200]}"

    agents_response = client.get("/agents")
    assert agents_response.status_code == 200, f"GET /agents {agents_response.status_code}: {agents_response.text[:200]}"
