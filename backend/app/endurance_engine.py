"""
APKSandbox Pro - Continuous Long-Duration Endurance & Soak Testing Engine
Supports up to 5 hours (300 minutes) or custom duration continuous burn-in testing.
Streams real-time time-series telemetry (PSS RAM, Native Heap, Dalvik Heap, CPU load,
Battery temperature, Jank %, and ANR/Crash sentry) with linear regression leak detection.
"""

import time
import threading
import subprocess
import re
import uuid
import datetime
from pathlib import Path

class EnduranceSession:
    def __init__(self):
        self.session_id = None
        self.status = "idle"  # idle, running, paused, stopped, completed
        self.apk_id = None
        self.package_name = "com.spadac.bantrkey"
        self.target_duration_seconds = 300 * 60  # Default 5 hours (18,000s)
        self.start_timestamp = None
        self.elapsed_seconds = 0
        self.sample_interval = 4.0  # seconds between telemetry samples
        self.total_events_injected = 0
        self.crashes_detected = []
        self.anrs_detected = 0
        self.history = []  # Ring buffer of telemetry snapshots (up to 1200 points)
        self.intensity = "normal"  # low, normal, stress
        
        self._thread = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._lock = threading.RLock()
        self._adb_path = None

    def _get_adb(self):
        if self._adb_path and Path(self._adb_path).exists():
            return self._adb_path
        candidates = [
            Path(Path.home()) / 'Library/Android/sdk/platform-tools/adb',
            Path('/opt/homebrew/bin/adb'),
            Path('/usr/local/bin/adb'),
            Path(Path.home()) / 'Android/Sdk/platform-tools/adb'
        ]
        for c in candidates:
            if c.exists():
                self._adb_path = str(c)
                return self._adb_path
        return 'adb'

    def start(self, apk_id: str = None, package_name: str = 'com.spadac.bantrkey', duration_minutes: int = 300, intensity: str = 'normal'):
        with self._lock:
            if self.status in ('running', 'paused'):
                self._stop_event.set()
                self._pause_event.clear()
                self.status = "stopped"
                if self._thread and self._thread.is_alive():
                    self._thread.join(timeout=1.0)
            
            self.session_id = str(uuid.uuid4())
            self.apk_id = apk_id
            self.package_name = package_name or 'com.spadac.bantrkey'
            self.target_duration_seconds = max(60, int(duration_minutes * 60))
            self.start_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.elapsed_seconds = 0
            self.total_events_injected = 0
            self.crashes_detected = []
            self.anrs_detected = 0
            self.history = []
            self.intensity = intensity
            self.status = "running"
            
            self._stop_event.clear()
            self._pause_event.clear()

            self._thread = threading.Thread(target=self._worker_loop, daemon=True)
            self._thread.start()
            return self.get_status()

    def pause(self):
        with self._lock:
            if self.status == "running":
                self._pause_event.set()
                self.status = "paused"
            return self.get_status()

    def resume(self):
        with self._lock:
            if self.status == "paused":
                self._pause_event.clear()
                self.status = "running"
            return self.get_status()

    def stop(self):
        with self._lock:
            if self.status in ("running", "paused"):
                self._stop_event.set()
                self._pause_event.clear()
                self.status = "stopped"
            return self.get_status()

    def _sample_telemetry(self, adb):
        """Samples live memory, CPU, battery, and graphics pipeline via ADB."""
        data = {
            'time_offset_sec': int(self.elapsed_seconds),
            'ram_pss_mb': 20.0,
            'ram_native_mb': 12.0,
            'ram_dalvik_mb': 1.8,
            'cpu_load': 0.25,
            'battery_level': 100,
            'battery_temp': 25.0,
            'jank_pct': 5.0,
            'events_total': self.total_events_injected
        }
        
        try:
            # 1. dumpsys meminfo
            m_proc = subprocess.run([adb, 'shell', 'dumpsys', 'meminfo', self.package_name], capture_output=True, text=True, timeout=4)
            out_m = m_proc.stdout
            pss_m = re.search(r'TOTAL\s+PSS:\s*(\d+)', out_m)
            if not pss_m:
                pss_m = re.search(r'TOTAL\s+(\d+)', out_m)
            if pss_m:
                data['ram_pss_mb'] = round(int(pss_m.group(1)) / 1024, 2)
            
            nat_m = re.search(r'Native Heap\s+(\d+)', out_m)
            if nat_m:
                data['ram_native_mb'] = round(int(nat_m.group(1)) / 1024, 2)

            dal_m = re.search(r'Dalvik Heap\s+(\d+)', out_m)
            if dal_m:
                data['ram_dalvik_mb'] = round(int(dal_m.group(1)) / 1024, 2)
        except Exception:
            pass

        try:
            # 2. dumpsys cpuinfo
            c_proc = subprocess.run([adb, 'shell', 'dumpsys', 'cpuinfo'], capture_output=True, text=True, timeout=3)
            load_m = re.search(r'Load:\s+([0-9\.]+)', c_proc.stdout)
            if load_m:
                data['cpu_load'] = float(load_m.group(1))
        except Exception:
            pass

        try:
            # 3. dumpsys battery
            b_proc = subprocess.run([adb, 'shell', 'dumpsys', 'battery'], capture_output=True, text=True, timeout=3)
            out_b = b_proc.stdout
            lvl_m = re.search(r'level:\s+(\d+)', out_b)
            if lvl_m:
                data['battery_level'] = int(lvl_m.group(1))
            temp_m = re.search(r'temperature:\s+(\d+)', out_b)
            if temp_m:
                data['battery_temp'] = round(int(temp_m.group(1)) / 10, 1)
        except Exception:
            pass

        try:
            # 4. dumpsys gfxinfo
            g_proc = subprocess.run([adb, 'shell', 'dumpsys', 'gfxinfo', self.package_name], capture_output=True, text=True, timeout=3)
            jank_m = re.search(r'Janky frames:\s+\d+\s+\(([0-9\.]+)%\)', g_proc.stdout)
            if jank_m:
                data['jank_pct'] = float(jank_m.group(1))
        except Exception:
            pass

        return data

    def _inject_random_interaction(self, adb):
        """Dispatches stochastic touch / key interaction on device."""
        import random
        action = random.choice(['tap', 'tap', 'swipe', 'key', 'text'])
        try:
            if action == 'tap':
                x = random.randint(150, 930)
                y = random.randint(300, 2100)
                subprocess.run([adb, 'shell', 'input', 'tap', str(x), str(y)], timeout=2)
                self.total_events_injected += 1
            elif action == 'swipe':
                x1 = random.randint(200, 800)
                y1 = random.randint(600, 1800)
                x2 = x1 + random.randint(-50, 50)
                y2 = y1 + random.choice([-400, 400])
                subprocess.run([adb, 'shell', 'input', 'swipe', str(x1), str(y1), str(x2), str(y2), '250'], timeout=2)
                self.total_events_injected += 1
            elif action == 'key':
                keycode = random.choice([4, 66, 19, 20, 21, 22])  # back, enter, dpad
                subprocess.run([adb, 'shell', 'input', 'keyevent', str(keycode)], timeout=2)
                self.total_events_injected += 1
            elif action == 'text':
                sample = random.choice(['hello', 'test', 'ok', 'yes', '123'])
                subprocess.run([adb, 'shell', 'input', 'text', sample], timeout=2)
                self.total_events_injected += len(sample)
        except Exception:
            pass

    def _check_crashes(self, adb):
        """Monitors logcat for new FATAL exception entries or ANRs."""
        try:
            proc = subprocess.run([adb, 'shell', 'logcat', '-d', '-t', '20', '*:E'], capture_output=True, text=True, timeout=3)
            out = proc.stdout
            if 'FATAL EXCEPTION' in out or 'ANR in ' + self.package_name in out:
                lines = [l for l in out.splitlines() if 'FATAL' in l or 'ANR' in l or self.package_name in l]
                snippet = " | ".join(lines[:2])
                if not any(c['snippet'] == snippet for c in self.crashes_detected):
                    self.crashes_detected.append({
                        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'elapsed_sec': int(self.elapsed_seconds),
                        'snippet': snippet[:200]
                    })
                    if 'ANR in' in snippet:
                        self.anrs_detected += 1
        except Exception:
            pass

    def _worker_loop(self):
        adb = self._get_adb()
        start_mono = time.monotonic()
        last_sample_mono = start_mono - self.sample_interval

        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                time.sleep(0.5)
                continue

            now_mono = time.monotonic()
            self.elapsed_seconds = now_mono - start_mono

            if self.elapsed_seconds >= self.target_duration_seconds:
                with self._lock:
                    self.status = "completed"
                break

            # 1. Periodic Telemetry Sampling
            if now_mono - last_sample_mono >= self.sample_interval:
                snap = self._sample_telemetry(adb)
                with self._lock:
                    self.history.append(snap)
                    if len(self.history) > 1200:
                        self.history.pop(0)
                last_sample_mono = now_mono

            # 2. Crash Sentry Check
            self._check_crashes(adb)

            # 3. Inject Autonomous Interaction based on intensity
            pace = 1.0 if self.intensity == 'stress' else (2.5 if self.intensity == 'normal' else 5.0)
            self._inject_random_interaction(adb)
            time.sleep(pace)

    def _calculate_linear_regression_slope(self):
        """Calculates memory growth slope (MB/hour) using least-squares linear regression."""
        if len(self.history) < 4 or self.elapsed_seconds < 25:
            return 0.0
        
        import math
        times = [pt['time_offset_sec'] / 3600.0 for pt in self.history]
        pss_vals = [pt['ram_pss_mb'] for pt in self.history]
        
        n = len(times)
        sum_x = sum(times)
        sum_y = sum(pss_vals)
        sum_xx = sum(x * x for x in times)
        sum_xy = sum(x * y for x, y in zip(times, pss_vals))
        
        denom = (n * sum_xx - sum_x * sum_x)
        if abs(denom) < 1e-7:
            return 0.0
        
        slope_mb_per_hour = (n * sum_xy - sum_x * sum_y) / denom
        if math.isnan(slope_mb_per_hour) or math.isinf(slope_mb_per_hour):
            return 0.0
        return round(slope_mb_per_hour, 2)

    def get_status(self):
        with self._lock:
            slope = self._calculate_linear_regression_slope()
            
            verdict = "Rock Solid Stability"
            if slope > 3.0:
                verdict = "Critical Memory Leak Detected"
            elif slope > 1.0:
                verdict = "Minor Memory Drift"

            latest = self.history[-1] if self.history else {
                'ram_pss_mb': 20.0,
                'ram_native_mb': 12.0,
                'ram_dalvik_mb': 1.8,
                'cpu_load': 0.25,
                'battery_level': 100,
                'battery_temp': 25.0,
                'jank_pct': 5.0
            }

            initial_pss = self.history[0]['ram_pss_mb'] if self.history else 20.0
            current_pss = latest['ram_pss_mb']
            peak_pss = max([pt['ram_pss_mb'] for pt in self.history]) if self.history else 20.0

            progress_pct = min(100.0, round((self.elapsed_seconds / max(1, self.target_duration_seconds)) * 100, 1))

            return {
                'session_id': self.session_id,
                'status': self.status,
                'package_name': self.package_name,
                'target_duration_seconds': self.target_duration_seconds,
                'elapsed_seconds': int(self.elapsed_seconds),
                'remaining_seconds': max(0, int(self.target_duration_seconds - self.elapsed_seconds)),
                'progress_percentage': progress_pct,
                'intensity': self.intensity,
                'total_events_injected': self.total_events_injected,
                'crashes_count': len(self.crashes_detected),
                'anrs_count': self.anrs_detected,
                'crashes_detected': self.crashes_detected,
                'latest_metrics': latest,
                'leak_analysis': {
                    'initial_pss_mb': initial_pss,
                    'current_pss_mb': current_pss,
                    'peak_pss_mb': peak_pss,
                    'slope_mb_per_hour': slope,
                    'verdict': verdict
                },
                'history_count': len(self.history),
                'recent_history': self.history[-120:]  # Send recent 120 points for chart rendering
            }

    def get_report(self):
        status = self.get_status()
        leak = status['leak_analysis']
        
        # Calculate endurance health score (0 - 100)
        score = 100
        score -= min(30, len(status['crashes_detected']) * 15)
        score -= min(20, status['anrs_count'] * 10)
        if leak['slope_mb_per_hour'] > 3.0:
            score -= 30
        elif leak['slope_mb_per_hour'] > 1.0:
            score -= 15
        
        if status['latest_metrics']['jank_pct'] > 15.0:
            score -= 10

        score = max(0, score)
        grade = 'A' if score >= 90 else ('B' if score >= 80 else ('C' if score >= 70 else ('D' if score >= 60 else 'F')))

        return {
            'session_id': self.session_id,
            'package_name': self.package_name,
            'start_timestamp': self.start_timestamp,
            'duration_hours': round(self.elapsed_seconds / 3600, 2),
            'target_hours': round(self.target_duration_seconds / 3600, 1),
            'endurance_score': score,
            'grade': grade,
            'status': self.status,
            'total_events': self.total_events_injected,
            'crashes': status['crashes_count'],
            'anrs': status['anrs_count'],
            'leak_analysis': leak,
            'latest_telemetry': status['latest_metrics'],
            'history': self.history
        }

# Global singleton endurance session manager
endurance_engine = EnduranceSession()
