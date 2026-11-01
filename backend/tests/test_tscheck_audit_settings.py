from tests.helpers import login


def test_audit_logs_and_safe_settings(client):
    login(client)
    logs = client.get('/audit-logs')
    assert logs.status_code == 200
    assert all('password' not in str(row).lower() and 'password_hash' not in str(row).lower() for row in logs.json())
    settings = client.get('/settings')
    assert settings.status_code == 200 and settings.json().get('safe_mode') is True
    patched = client.patch('/settings', json={'key': 'detection_threshold', 'value': 0.81})
    assert patched.status_code == 200, f'PATCH /settings {patched.status_code}: {patched.text[:200]}'
    assert patched.json()['value'] == 0.81
