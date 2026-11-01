from tests.helpers import login


def test_ml_metrics_evaluation_and_reports_exports(client):
    login(client)
    models = client.get('/models')
    assert models.status_code == 200 and models.json()['models'] and models.json()['safe_mode'] is True
    trained = client.post('/models/train')
    assert trained.status_code == 200, f'POST /models/train {trained.status_code}: {trained.text[:200]}'
    assert trained.json()['status'] == 'completed'
    report = client.get('/reports/summary')
    assert report.status_code == 200 and report.json()['statistics']
    csv = client.get('/reports/export.csv')
    assert csv.status_code == 200 and 'text/csv' in csv.headers.get('content-type', '')
    pdf = client.get('/reports/export.pdf')
    assert pdf.status_code == 200 and pdf.content[:4] == b'%PDF'
