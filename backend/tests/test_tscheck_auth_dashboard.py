import pytest


def login(client):
    response = client.post('/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert response.status_code == 200, f'POST /auth/login {response.status_code}: {response.text[:200]}'
    return response.json()


def test_admin_authentication_and_dashboard(client):
    user = login(client)
    assert user['username'] == 'admin' and user['role'] == 'ADMIN'
    assert client.get('/auth/me').status_code == 200
    response = client.get('/dashboard/summary')
    assert response.status_code == 200, f'GET /dashboard/summary {response.status_code}: {response.text[:200]}'
    data = response.json()
    assert all(key in data for key in ('total_events', 'threats_detected', 'severity_distribution'))


def test_dashboard_requires_auth(client):
    client.cookies.clear()
    response = client.get('/dashboard/summary')
    assert response.status_code == 401
