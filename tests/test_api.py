import io, zipfile, time
from fastapi.testclient import TestClient
from backend.app.main import app, init

init()
c = TestClient(app)

def fake():
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        z.writestr('AndroidManifest.xml', b'x')
        z.writestr('classes.dex', b'dex\n035\x00' + b'\x00' * 104)
    return b.getvalue()

def test_flow():
    assert c.get('/api/health').status_code == 200
    assert len(c.get('/api/testers').json()) == 10
    assert c.get('/api/devices').status_code == 200
    assert c.get('/api/device/state').status_code == 200
    
    a = c.post('/api/apks/upload', files={'file': ('a.apk', fake())}).json()
    assert 'id' in a
    r = c.post('/api/tests/start', json={'apk_id': a['id'], 'concurrency': 10}).json()
    assert 'id' in r
    
    x = None
    for _ in range(100):
        x = c.get('/api/tests/' + r['id']).json()
        if x['status'] == 'completed':
            break
        time.sleep(0.05)
        
    assert x is not None
    assert x['status'] == 'completed'
    assert len(x['results']) == 10
    assert all(y['status'] in ('passed', 'warning', 'failed', 'blocked') for y in x['results'])
    
    # Verify sub-tests presence
    assert 'sub_tests' in x['results'][0]
    
    # Verify reports
    rep_html = c.get('/api/reports/' + r['id'] + '?format=html')
    assert rep_html.status_code == 200
    assert 'APKSandbox Pro' in rep_html.text
    
    rep_json = c.get('/api/reports/' + r['id'] + '?format=json')
    assert rep_json.status_code == 200
    assert 'results' in rep_json.json()

def test_device_and_stress_apis():
    assert c.get('/api/device/logcat').status_code == 200
    assert c.post('/api/tests/benchmark_launch').status_code == 200
    assert c.post('/api/tests/profile_memory').status_code == 200
    assert c.post('/api/tests/run_monkey?events=10').status_code == 200
    assert c.get('/api/device/telemetry').status_code == 200
    loc_resp = c.post('/api/device/location', json={'latitude': 37.7749, 'longitude': -122.4194, 'altitude': 10.0})
    assert loc_resp.status_code == 200
    assert c.get('/api/runs/latest').status_code == 200

def test_audit_engine_100_subtests():
    from backend.app.audit_engine import evaluate_dimension
    apk_data = {'manifest': {'package_name': 'com.spadac.bantrkey', 'version_name': '7.0.3', 'target_sdk': '35'}}
    total_checks = 0
    for dim_id in range(1, 11):
        res = evaluate_dimension(dim_id, apk_data)
        assert len(res['sub_tests']) == 10
        total_checks += len(res['sub_tests'])
    assert total_checks == 100

def test_invalid():
    assert c.post('/api/apks/upload', files={'file': ('x.txt', b'x')}).status_code == 400
    assert c.post('/api/apks/upload', files={'file': ('x.apk', b'')}).status_code == 422
