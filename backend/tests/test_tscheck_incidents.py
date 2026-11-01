from tests.helpers import login


def test_incident_admin_update(client):
    login(client)
    analyzed = client.post('/detection/analyze', json={'source_ip': 'tscheck-incident-unique', 'event_type': 'BRUTE_FORCE', 'failed_attempts': 20, 'traffic_volume': 900})
    assert analyzed.status_code == 200
    threat_id = analyzed.json()['threat_id']
    incidents = client.get('/incidents')
    assert incidents.status_code == 200
    incident = next((row for row in incidents.json() if row.get('threat_id') == threat_id), None)
    assert incident is not None, 'pipeline did not create incident for high-risk threat'
    updated = client.patch(f"/incidents/{incident['id']}", json={'status': 'INVESTIGATING'})
    assert updated.status_code == 200, f'PATCH /incidents/{incident["id"]} {updated.status_code}: {updated.text[:200]}'
    assert updated.json()['status'] == 'INVESTIGATING'
