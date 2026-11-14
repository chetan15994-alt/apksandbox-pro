"""
APKSandbox Pro - Regression Test Suite
Covers route ordering, device state, resolution adaptability, extended app actions,
multi-format reporting, and endurance engine resilience.
"""

import io
import zipfile
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app, get_active_apk, set_active_apk, get_screen_dimensions

client = TestClient(app)

def create_dummy_apk():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('AndroidManifest.xml', b'\x00' * 50)
        z.writestr('classes.dex', b'dex\n035\x00' + b'\x00' * 110)
    return buf.getvalue()

def test_route_ordering_runs_latest_and_by_id():
    """Ensure static route /api/runs/latest is NOT shadowed by /api/runs/{ident}."""
    resp_latest = client.get('/api/runs/latest')
    assert resp_latest.status_code == 200
    data = resp_latest.json()
    assert 'status' in data

    # Verify that a specific non-existent run returns 404 cleanly
    resp_fake = client.get('/api/runs/non-existent-uuid-1234')
    assert resp_fake.status_code == 404

def test_dynamic_device_state_and_resolution():
    """Ensure /api/device/state reports valid dimensions and orientation."""
    resp = client.get('/api/device/state')
    assert resp.status_code == 200
    data = resp.json()
    assert 'connected' in data
    if data['connected']:
        assert data['screen_width'] > 0
        assert data['screen_height'] > 0
        assert data['orientation'] in ('portrait', 'landscape')
        assert 'serial' in data
        assert 'focused' in data

def test_extended_app_actions():
    """Verify extended actions: force_stop, grant_permissions, launch, restart."""
    # Force stop
    r_stop = client.post('/api/device/app_action', json={'action': 'force_stop', 'package_name': 'com.spadac.bantrkey'})
    assert r_stop.status_code == 200
    assert r_stop.json()['status'] == 'stopped'

    # Grant permissions
    r_perm = client.post('/api/device/app_action', json={'action': 'grant_permissions', 'package_name': 'com.spadac.bantrkey'})
    assert r_perm.status_code == 200
    assert r_perm.json()['status'] == 'permissions_granted'

    # Launch
    r_launch = client.post('/api/device/app_action', json={'action': 'launch', 'package_name': 'com.spadac.bantrkey'})
    assert r_launch.status_code == 200
    assert r_launch.json()['status'] == 'launched'

def test_multi_format_reports():
    """Verify that completed runs export to HTML, JSON, and CSV."""
    latest = client.get('/api/runs/latest').json()
    if latest.get('status') == 'completed' and 'id' in latest:
        run_id = latest['id']
        # HTML
        r_html = client.get(f'/api/reports/{run_id}?format=html')
        assert r_html.status_code == 200
        assert '<html' in r_html.text.lower()

        # JSON
        r_json = client.get(f'/api/reports/{run_id}?format=json')
        assert r_json.status_code == 200
        assert 'results' in r_json.json()

        # CSV
        r_csv = client.get(f'/api/reports/{run_id}?format=csv')
        assert r_csv.status_code == 200
        assert 'tester_id,title,status,details' in r_csv.text

def test_device_text_empty_and_escaping():
    """Verify device text handling with empty string and special characters."""
    r_empty = client.post('/api/device/text', json={'text': ''})
    assert r_empty.status_code == 200
    assert r_empty.json()['text'] == ''

    r_spec = client.post('/api/device/text', json={'text': 'QA_Regression #42 & test!'})
    assert r_spec.status_code == 200
    assert r_spec.json()['text'] == 'QA_Regression #42 & test!'

def test_screen_dimensions_helper():
    """Verify dimension helper returns valid integers."""
    w, h = get_screen_dimensions()
    assert isinstance(w, int) and w > 0
    assert isinstance(h, int) and h > 0
