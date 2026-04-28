# detector.py — Anomaly detection engine
# Maintains deque-based sliding windows (per-IP and global).
# Computes z-scores and rate multiples against rolling baseline.
# Fires ban or alert decisions within 10 seconds of detection.
# No rate-limiting libraries used — pure deque + math.

import time
import math
import logging
import threading
from collections import deque, defaultdict
from datetime import datetime, timezone

from config import get
from monitor import LogEntry

logger = logging.getLogger("detector")


# ══════════════════════════════════════════════════════════════
# Sliding Window — core deque structure
# ══════════════════════════════════════════════════════════════

class SlidingWindow:
    """
    Deque-based sliding window tracking request timestamps.

    Structure:
        deque of float (Unix timestamps), one per request.

    Eviction logic:
        On every read, pop from the LEFT while the oldest
        timestamp is outside the window duration.
        This is O(k) where k = number of evicted entries —
        amortized O(1) per request.

    Why deque?
        appendright  O(1) — add new request
        popleft      O(1) — evict expired request
        len()        O(1) — current count in window
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._dq: deque = deque()
        self._error_dq: deque = deque()  # Parallel error tracker

    def add(self, timestamp: float, is_error: bool = False):
        """Record one request at the given timestamp."""
        self._dq.append(timestamp)
        if is_error:
            self._error_dq.append(timestamp)

    def evict(self, now: float):
        """
        Remove all entries older than window_seconds from now.
        Must be called before reading count() or error_count().
        """
        cutoff = now - self.window_seconds

        # Evict main window
        while self._dq and self._dq[0] < cutoff:
            self._dq.popleft()

        # Evict error window
        while self._error_dq and self._error_dq[0] < cutoff:
            self._error_dq.popleft()

    def count(self) -> int:
        """Requests in window. Call evict() first."""
        return len(self._dq)

    def error_count(self) -> int:
        """Error requests in window. Call evict() first."""
        return len(self._error_dq)

    def rate(self) -> float:
        """Requests per second over the window."""
        return self.count() / self.window_seconds

    def error_rate(self) -> float:
        """Error requests per second over the window."""
        return self.error_count() / self.window_seconds

    def is_empty(self) -> bool:
        return len(self._dq) == 0

    def oldest(self) -> float:
        """Timestamp of oldest entry, or 0 if empty."""
        return self._dq[0] if self._dq else 0.0


# ══════════════════════════════════════════════════════════════
# Detector
# ══════════════════════════════════════════════════════════════

class Detector:
    """
    Reads LogEntry objects from the monitor queue.
    Maintains per-IP and global sliding windows.
    Fires callbacks on anomaly detection.

    Callbacks:
        on_ip_anomaly(ip, rate, baseline, condition, z_score)
        on_global_anomaly(rate, baseline, condition, z_score)
    """

    def __init__(self, baseline, monitor_queue):
        # ── Dependencies ────────────────────────────────────────
        self.baseline       = baseline
        self.queue          = monitor_queue

        # ── Config ──────────────────────────────────────────────
        self.window_seconds    = get("sliding_window.per_ip_seconds", 60)
        self.global_seconds    = get("sliding_window.global_seconds", 60)
        self.cleanup_interval  = get("sliding_window.cleanup_interval", 30)

        self.zscore_threshold  = get("detection.zscore_threshold", 3.0)
        self.rate_multiplier   = get("detection.rate_multiplier", 5.0)
        self.error_multiplier  = get("detection.error_rate_multiplier", 3.0)
        self.tight_zscore      = get("detection.tightened_zscore", 2.0)
        self.tight_multiplier  = get("detection.tightened_multiplier", 3.0)
        self.global_alert_only = get("detection.global_alert_only", True)

        # ── Sliding windows ─────────────────────────────────────
        # Per-IP: dict of ip → SlidingWindow
        self._ip_windows: dict = defaultdict(
            lambda: SlidingWindow(self.window_seconds)
        )
        # Global: single window across all IPs
        self._global_window = SlidingWindow(self.global_seconds)

        # ── State ───────────────────────────────────────────────
        self._last_cleanup    = time.time()
        self._stop_event      = threading.Event()
        self._thread          = None

        # ── Callbacks (set by main.py) ──────────────────────────
        self.on_ip_anomaly     = None   # fn(ip, rate, baseline, condition, z)
        self.on_global_anomaly = None   # fn(rate, baseline, condition, z)

        # ── Stats ───────────────────────────────────────────────
        self.entries_processed = 0
        self.ip_anomalies      = 0
        self.global_anomalies  = 0
        self.started_at        = None

        # ── Top IPs tracker (for dashboard) ────────────────────
        self._ip_totals: dict = defaultdict(int)  # ip → total request count

        logger.info(
            f"Detector initialized — "
            f"window={self.window_seconds}s, "
            f"zscore_threshold={self.zscore_threshold}, "
            f"rate_multiplier={self.rate_multiplier}x"
        )

    # ══════════════════════════════════════════════════════════
    # Public API
    # ══════════════════════════════════════════════════════════

    def start(self):
        """Start detector in a background daemon thread."""
        logger.info("Detector starting...")
        self.started_at = datetime.utcnow()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="detector",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        logger.info("Detector stopping...")
        self._stop_event.set()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_global_rate(self) -> float:
        """Current global requests/second (for dashboard)."""
        now = time.time()
        self._global_window.evict(now)
        return round(self._global_window.rate(), 3)

    def get_top_ips(self, n: int = 10) -> list:
        """
        Return top N IPs by total request count.
        Format: [{"ip": str, "total": int, "rate": float}, ...]
        """
        now = time.time()
        results = []
        for ip, total in sorted(
            self._ip_totals.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]:
            win = self._ip_windows.get(ip)
            if win:
                win.evict(now)
                rate = round(win.rate(), 3)
            else:
                rate = 0.0
            results.append({"ip": ip, "total": total, "rate": rate})
        return results

    def get_stats(self) -> dict:
        uptime = (
            (datetime.utcnow() - self.started_at).total_seconds()
            if self.started_at else 0
        )
        return {
            "entries_processed": self.entries_processed,
            "ip_anomalies"     : self.ip_anomalies,
            "global_anomalies" : self.global_anomalies,
            "active_ips"       : len(self._ip_windows),
            "global_rate"      : self.get_global_rate(),
            "uptime_secs"      : round(uptime, 1),
        }

    # ══════════════════════════════════════════════════════════
    # Internal — Main Loop
    # ══════════════════════════════════════════════════════════

    def _run_loop(self):
        """
        Continuously pull LogEntry objects from the monitor queue.
        For each entry: update windows, check for anomalies.
        """
        import queue as q_module

        while not self._stop_event.is_set():
            try:
                # Block for up to 1 second waiting for entries
                entry: LogEntry = self.queue.get(timeout=1.0)
            except q_module.Empty:
                # No entries — still run cleanup if due
                self._maybe_cleanup()
                continue

            self._process_entry(entry)
            self._maybe_cleanup()

    def _process_entry(self, entry: LogEntry):
        """
        Process one LogEntry:
        1. Record in baseline
        2. Add to sliding windows
        3. Evict expired entries
        4. Check for anomalies
        """
        now       = time.time()
        ip        = entry.source_ip
        is_error  = entry.is_error

        # 1. Feed baseline (it tracks per-second counts)
        self.baseline.record(is_error=is_error)

        # 2. Add to per-IP window
        self._ip_windows[ip].add(now, is_error=is_error)
        self._ip_totals[ip] += 1

        # 3. Add to global window
        self._global_window.add(now, is_error=is_error)

        # 4. Evict expired entries from both windows
        self._ip_windows[ip].evict(now)
        self._global_window.evict(now)

        self.entries_processed += 1

        # 5. Check anomalies (only if baseline is ready)
        bl = self.baseline.get_effective()
        if not bl["ready"]:
            return

        self._check_ip_anomaly(ip, now, bl)
        self._check_global_anomaly(now, bl)

    # ══════════════════════════════════════════════════════════
    # Internal — Anomaly Checks
    # ══════════════════════════════════════════════════════════

    def _check_ip_anomaly(self, ip: str, now: float, bl: dict):
        """
        Check if a single IP's current rate is anomalous.

        Steps:
        1. Get IP's current rate from its sliding window
        2. Check if IP has an error surge (tighten thresholds)
        3. Compute z-score against baseline
        4. Fire if z-score > threshold OR rate > multiplier * mean
        """
        win  = self._ip_windows[ip]
        rate = win.rate()
        mean = bl["mean"]
        std  = bl["stddev"]

        # Determine thresholds — tighten if error surge detected
        error_surge = self._is_error_surge(win, bl)
        if error_surge:
            z_threshold  = self.tight_zscore
            r_multiplier = self.tight_multiplier
            condition_prefix = "ERROR_SURGE+"
        else:
            z_threshold  = self.zscore_threshold
            r_multiplier = self.rate_multiplier
            condition_prefix = ""

        # Compute z-score
        z = self._zscore(rate, mean, std)

        # Check: z-score rule
        if z > z_threshold:
            condition = f"{condition_prefix}ZSCORE"
            self._fire_ip_anomaly(ip, rate, bl, condition, z)
            return

        # Check: rate multiplier rule (whichever fires first)
        if rate > r_multiplier * mean:
            condition = f"{condition_prefix}RATE_MULTIPLE"
            self._fire_ip_anomaly(ip, rate, bl, condition, z)
            return

    def _check_global_anomaly(self, now: float, bl: dict):
        """
        Check if overall traffic rate is anomalous.
        Global anomaly → Slack alert only, no IP block.
        """
        rate = self._global_window.rate()
        mean = bl["mean"]
        std  = bl["stddev"]
        z    = self._zscore(rate, mean, std)

        if z > self.zscore_threshold:
            condition = "GLOBAL_ZSCORE"
            self._fire_global_anomaly(rate, bl, condition, z)
            return

        if rate > self.rate_multiplier * mean:
            condition = "GLOBAL_RATE_MULTIPLE"
            self._fire_global_anomaly(rate, bl, condition, z)
            return

    def _is_error_surge(self, win: SlidingWindow, bl: dict) -> bool:
        """
        Returns True if this IP's error rate is more than
        error_rate_multiplier * baseline error mean.
        """
        ip_error_rate    = win.error_rate()
        baseline_err_mean = bl.get("error_mean", self.baseline.floor_mean)

        return ip_error_rate > (self.error_multiplier * baseline_err_mean)

    # ══════════════════════════════════════════════════════════
    # Internal — Fire Callbacks
    # ══════════════════════════════════════════════════════════

    def _fire_ip_anomaly(
        self, ip: str, rate: float,
        bl: dict, condition: str, z: float
    ):
        """
        Log and invoke the on_ip_anomaly callback.
        Callback must complete (ban + alert) within 10 seconds.
        """
        self.ip_anomalies += 1
        logger.warning(
            f"IP ANOMALY detected | "
            f"ip={ip} | condition={condition} | "
            f"rate={rate:.3f} req/s | "
            f"baseline_mean={bl['mean']:.3f} | "
            f"z={z:.2f}"
        )

        if self.on_ip_anomaly:
            try:
                self.on_ip_anomaly(
                    ip=ip,
                    rate=rate,
                    baseline=bl,
                    condition=condition,
                    z_score=z,
                )
            except Exception as e:
                logger.error(f"on_ip_anomaly callback error: {e}")

    def _fire_global_anomaly(
        self, rate: float, bl: dict,
        condition: str, z: float
    ):
        """
        Log and invoke the on_global_anomaly callback.
        No blocking — alert only.
        """
        self.global_anomalies += 1
        logger.warning(
            f"GLOBAL ANOMALY detected | "
            f"condition={condition} | "
            f"rate={rate:.3f} req/s | "
            f"baseline_mean={bl['mean']:.3f} | "
            f"z={z:.2f}"
        )

        if self.on_global_anomaly:
            try:
                self.on_global_anomaly(
                    rate=rate,
                    baseline=bl,
                    condition=condition,
                    z_score=z,
                )
            except Exception as e:
                logger.error(f"on_global_anomaly callback error: {e}")

    # ══════════════════════════════════════════════════════════
    # Internal — Utilities
    # ══════════════════════════════════════════════════════════

    @staticmethod
    def _zscore(rate: float, mean: float, stddev: float) -> float:
        """
        Z-score = (observed - mean) / stddev.
        Guards against division by zero.
        """
        if stddev == 0:
            return 0.0
        return (rate - mean) / stddev

    def _maybe_cleanup(self):
        """
        Periodically remove stale per-IP windows (IPs with no
        recent activity) to prevent unbounded memory growth.
        """
        now = time.time()
        if now - self._last_cleanup < self.cleanup_interval:
            return

        self._last_cleanup = now
        cutoff = now - self.window_seconds
        stale  = [
            ip for ip, win in self._ip_windows.items()
            if win.is_empty() or win.oldest() < cutoff
        ]

        for ip in stale:
            del self._ip_windows[ip]

        if stale:
            logger.debug(f"Cleaned up {len(stale)} stale IP windows")
