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
    assert len(c.get('/api/testers').json()) == 20
    assert c.get('/api/devices').status_code == 200
    assert c.get('/api/device/state').status_code == 200
    
    a = c.post('/api/apks/upload', files={'file': ('a.apk', fake())}).json()
    assert 'id' in a
    r = c.post('/api/tests/start', json={'apk_id': a['id'], 'concurrency': 20}).json()
    assert 'id' in r
    
    x = None
    for _ in range(120):
        x = c.get('/api/tests/' + r['id']).json()
        if x['status'] == 'completed':
            break
        time.sleep(0.05)
        
    assert x is not None
    assert x['status'] == 'completed'
    assert len(x['results']) == 20
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

def test_endurance_engine_lifecycle():
    # Start a quick 5-minute endurance run
    start_resp = c.post('/api/endurance/start', json={'duration_minutes': 5, 'intensity': 'low', 'package_name': 'com.spadac.bantrkey'})
    assert start_resp.status_code == 200
    data = start_resp.json()
    assert data['status'] == 'running'
    assert 'session_id' in data
    
    # Pause
    pause_resp = c.post('/api/endurance/pause')
    assert pause_resp.status_code == 200
    assert pause_resp.json()['status'] == 'paused'
    
    # Resume
    resume_resp = c.post('/api/endurance/resume')
    assert resume_resp.status_code == 200
    assert resume_resp.json()['status'] == 'running'
    
    # Status
    status_resp = c.get('/api/endurance/status')
    assert status_resp.status_code == 200
    s_data = status_resp.json()
    assert 'leak_analysis' in s_data
    assert 'slope_mb_per_hour' in s_data['leak_analysis']
    
    # Report
    rep_resp = c.get('/api/endurance/report')
    assert rep_resp.status_code == 200
    assert 'endurance_score' in rep_resp.json()
    
    # Stop
    stop_resp = c.post('/api/endurance/stop')
    assert stop_resp.status_code == 200
    assert stop_resp.json()['status'] == 'stopped'

def test_audit_engine_200_subtests():
    from backend.app.audit_engine import evaluate_dimension
    apk_data = {'manifest': {'package_name': 'com.spadac.bantrkey', 'version_name': '7.0.3', 'target_sdk': '35'}}
    total_checks = 0
    for dim_id in range(1, 21):
        res = evaluate_dimension(dim_id, apk_data)
        assert len(res['sub_tests']) == 10
        total_checks += len(res['sub_tests'])
    assert total_checks == 200

def test_invalid():
    assert c.post('/api/apks/upload', files={'file': ('x.txt', b'x')}).status_code == 400
    assert c.post('/api/apks/upload', files={'file': ('x.apk', b'')}).status_code == 422
    # Invalid GPS coordinates
    assert c.post('/api/device/location', json={'latitude': 95.0, 'longitude': 0.0}).status_code == 422
    assert c.post('/api/device/location', json={'latitude': 0.0, 'longitude': 200.0}).status_code == 422

def test_touch_and_text_robustness():
    # Touch clamping on extreme coordinates
    touch_res = c.post('/api/device/touch', json={'x': -50, 'y': 9999})
    assert touch_res.status_code == 200
    assert touch_res.json()['x'] == 0
    assert touch_res.json()['y'] == 2400

    # Swipe clamping
    swipe_res = c.post('/api/device/swipe', json={'x1': -10, 'y1': 5000, 'x2': 2000, 'y2': -10, 'duration_ms': 10})
    assert swipe_res.status_code == 200

    # Special characters escaping
    text_res = c.post('/api/device/text', json={'text': 'Test $VAR; & | () "quote"'})
    assert text_res.status_code == 200
    assert text_res.json()['text'] == 'Test $VAR; & | () "quote"'
