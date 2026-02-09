import asyncio
import time
from typing import List, Dict
import httpx
import socket
from urllib.parse import urlparse

class SmartDetector:
    """
    Uses Exponentially Weighted Moving Average (EWMA) for adaptive anomaly detection.
    This is superior to simple Mean/StdDev for time-series monitoring.
    """
    def __init__(self, alpha=0.2, threshold=2.5):
        self.alpha = alpha  # Smoothing factor (0.1 to 0.5). Higher = reacts faster.
        self.threshold = threshold  # How many standard deviations away is "bad"?
        self.ema = 0.0  # Exponential Moving Average
        self.emsd = 1.0  # Exponential Moving Standard Deviation
        self.is_initialized = False
        self.consecutive_anomalies = 0
        self.required_failures = 3  # Voting system: Need 3 bad pings in a row to call it "DOWN"

    def update(self, new_value):
        if not self.is_initialized:
            # Cold start: initialize with the first value
            self.ema = new_value
            self.is_initialized = True
            return "TRAINING", False
        # 1. Update EMA (The learned baseline)
        self.ema = self.alpha * new_value + (1 - self.alpha) * self.ema
        # 2. Update EMSD (The dynamic volatility)
        diff = abs(new_value - self.ema)
        self.emsd = self.alpha * diff + (1 - self.alpha) * self.emsd
        # 3. Calculate Z-Score (How far away is this point from the norm?)
        # Avoid division by zero
        if self.emsd == 0:
            self.emsd = 0.001
        z_score = (new_value - self.ema) / self.emsd
        # 4. Decision Logic
        # If the latency is significantly higher than baseline, it's an anomaly candidate
        if z_score > self.threshold:
            self.consecutive_anomalies += 1
            if self.consecutive_anomalies >= self.required_failures:
                return "DOWN", True
            else:
                return "UNSTABLE", False
        else:
            # If it's good, reset the failure counter (Recovery)
            self.consecutive_anomalies = 0
            return "UP", False

class MonitorState:
    def __init__(self):
        self.is_monitoring = False
        self.target_url: str = ""
        self.targets: List[str] = []
        self.detectors: Dict[str, SmartDetector] = {}
        self.histories: Dict[str, List[float]] = {}
        self.timestamps: Dict[str, List[float]] = {}
        self.baseline_avgs: Dict[str, float] = {}
        self.current_statuses: Dict[str, str] = {}
        self.http_status_codes: Dict[str, int] = {}

async def monitoring_loop(state: MonitorState):
    headers = {
        'User-Agent': 'Mozilla/5.0 (ServerPulse-AI/2.0; +https://serverpulse.ai)'
    }
    while state.is_monitoring:
        for target in state.targets:
            try:
                start_time = time.time()
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    # Using HEAD request to focus on server response time (TTFB)
                    response = await client.head(target, headers=headers)
                duration_ms = (time.time() - start_time) * 1000
                state.http_status_codes[target] = response.status_code
                # 1. Basic Health Check (HTTP Code)
                if response.status_code >= 400:
                    # If server returns 404, 500, etc., it's definitely down
                    state.current_statuses[target] = f"HTTP {response.status_code} ERROR"
                    # Push a high value to chart to show error visually
                    update_history(state, target, 0)
                else:
                    # 2. ML Anomaly Detection (Latency)
                    status_text, is_anomaly = state.detectors[target].update(duration_ms)
                    if status_text == "TRAINING":
                        state.current_statuses[target] = "Learning Baseline..."
                    elif status_text == "DOWN":
                        state.current_statuses[target] = "CRITICAL: High Latency"
                    elif status_text == "UNSTABLE":
                        state.current_statuses[target] = "Warning: Unstable"
                    else:
                        state.current_statuses[target] = "Operational"
                    update_history(state, target, duration_ms)
            except httpx.ConnectTimeout:
                state.current_statuses[target] = "TIMEOUT (Firewall/Net)"
                update_history(state, target, 0)
            except httpx.ConnectError:
                state.current_statuses[target] = "CONNECTION REFUSED"
                update_history(state, target, 0)
            except Exception as e:
                state.current_statuses[target] = f"ERROR: {str(e)[:20]}"
                update_history(state, target, 0)
        await asyncio.sleep(1.5)  # Poll every 1.5 seconds

def update_history(state: MonitorState, target: str, val: float):
    if target not in state.histories:
        state.histories[target] = []
        state.timestamps[target] = []
    state.histories[target].append(val)
    state.timestamps[target].append(time.time())
    # Sync baseline for display purposes
    state.baseline_avgs[target] = state.detectors[target].ema
    if len(state.histories[target]) > 50:
        state.histories[target].pop(0)
        state.timestamps[target].pop(0)