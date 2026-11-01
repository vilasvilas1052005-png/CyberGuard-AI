from tests.helpers import login


def test_detection_and_agent_details(client):
    login(client)
    analyzed = client.post('/detection/analyze', json={'source_ip': 'tscheck-detection-unique', 'event_type': 'BRUTE_FORCE', 'failed_attempts': 12, 'traffic_volume': 850})
    assert analyzed.status_code == 200, f'POST /detection/analyze {analyzed.status_code}: {analyzed.text[:200]}'
    threat_id = analyzed.json()['threat_id']
    detail = client.get(f'/detections/{threat_id}')
    assert detail.status_code == 200, f'GET /detections/{threat_id} {detail.status_code}: {detail.text[:200]}'
    data = detail.json()
    assert data['id'] == threat_id and data['confidence'] and data['risk_score'] is not None and data['severity']
    assert len(data.get('agent_executions', [])) == 5
    agents = client.get('/agents')
    assert agents.status_code == 200 and len(agents.json()) == 5
