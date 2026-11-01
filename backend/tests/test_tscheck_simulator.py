from tests.helpers import login


def test_simulator_safe_flow_and_realtime_records(client):
    login(client)
    client.post('/simulator/stop')
    started = client.post('/simulator/start', json={'events_per_second': 5, 'threat_probability': 1.0})
    assert started.status_code == 200, f'POST /simulator/start {started.status_code}: {started.text[:200]}'
    assert started.json()['status'] == 'RUNNING'
    status = client.get('/simulator/status')
    assert status.status_code == 200 and status.json()['status'] == 'RUNNING'
    client.post('/simulator/stop')
    assert client.get('/health').json()['safe_mode'] == 'true'
