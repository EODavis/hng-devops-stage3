# baseline.py — Rolling baseline calculator
# Learns normal traffic patterns from real request data.
# Maintains a 30-minute rolling window of per-second counts.
# Recalculates mean/stddev every 60 seconds.
# Maintains per-hour slots for time-aware baselines.
# Thread-safe — designed to be called from multiple threads.

import math
import time
import logging
import threading
from collections import deque
from datetime import datetime, timezone

from config import get

# ── Module logger ─────────────────────────────────────────────
logger = logging.getLogger("baseline")


class Baseline:
    """
    Rolling baseline engine.

    Tracks per-second request counts in a deque-based sliding window.
    Recalculates mean and stddev on a fixed interval.
    Maintains 24 hourly slot buckets for time-of-day awareness.

    Thread-safe via a single RLock.
    """

    def __init__(self):
        # ── Config values ───────────────────────────────────────
        self.window_minutes       = get("baseline.window_minutes", 30)
        self.recalc_interval      = get("baseline.recalc_interval", 60)
        self.min_samples          = get("baseline.min_samples", 30)
        self.floor_mean           = get("baseline.floor_mean", 1.0)
        self.floor_stddev         = get("baseline.floor_stddev", 0.5)
        self.hourly_slots         = get("baseline.hourly_slots", 24)
        self.prefer_current_hour  = get("baseline.prefer_current_hour", True)
        self.hour_min_samples     = get("baseline.current_hour_min_samples", 20)

        # ── Rolling window ──────────────────────────────────────
        # Stores (timestamp, count) tuples
        # Maximum entries = window_minutes * 60 seconds
        self._window_maxlen = self.window_minutes * 60
        self._window: deque = deque(maxlen=self._window_maxlen)

        # Current second accumulator
        self._current_second: int  = self._now_second()
        self._current_count:  int  = 0

        # ── Error rate window ───────────────────────────────────
        # Parallel window tracking error (4xx/5xx) counts per second
        self._error_window: deque = deque(maxlen=self._window_maxlen)
        self._current_error_count: int = 0

        # ── Per-hour slots ──────────────────────────────────────
        # Each slot: {"counts": deque, "mean": float, "stddev": float}
        self._hour_slots: list = [
            {
                "counts": deque(maxlen=self._window_maxlen),
                "mean"  : self.floor_mean,
                "stddev": self.floor_stddev,
                "n"     : 0,
            }
            for _ in range(self.hourly_slots)
        ]

        # ── Effective baseline (what detector uses) ─────────────
        self._effective_mean:   float = self.floor_mean
        self._effective_stddev: float = self.floor_stddev
        self._effective_error_mean:   float = self.floor_mean
        self._effective_error_stddev: float = self.floor_stddev

        # ── Recalculation tracking ──────────────────────────────
        self._last_recalc:    float = time.time()
        self._recalc_count:   int   = 0
        self._baseline_ready: bool  = False

        # ── History for graph/dashboard ─────────────────────────
        # Stores (timestamp, mean, stddev) tuples for plotting
        self._history: deque = deque(maxlen=720)  # 12 hours at 1/min

        # ── Thread safety ───────────────────────────────────────
        self._lock = threading.RLock()

        logger.info(
            f"Baseline initialized — "
            f"window={self.window_minutes}min, "
            f"recalc={self.recalc_interval}s, "
            f"floor_mean={self.floor_mean}"
        )

    # ══════════════════════════════════════════════════════════
    # Public API — called by monitor/detector
    # ══════════════════════════════════════════════════════════

    def record(self, is_error: bool = False):
        """
        Record one incoming request.
        Call this for every LogEntry that comes off the monitor queue.
        Automatically flushes the current second bucket when the
        clock ticks over to a new second.
        """
        with self._lock:
            now_sec = self._now_second()

            if now_sec != self._current_second:
                # Clock ticked — flush accumulated count into window
                self._flush_second(self._current_second, self._current_count, self._current_error_count)
                self._current_second     = now_sec
                self._current_count      = 0
                self._current_error_count = 0

            self._current_count += 1
            if is_error:
                self._current_error_count += 1

            # Trigger recalculation if interval has passed
            if time.time() - self._last_recalc >= self.recalc_interval:
                self._recalculate()

    def tick(self):
        """
        Call this from a background loop every second
        to flush the current second even during quiet traffic.
        Ensures the window advances during slow periods.
        """
        with self._lock:
            now_sec = self._now_second()
            if now_sec != self._current_second:
                self._flush_second(
                    self._current_second,
                    self._current_count,
                    self._current_error_count
                )
                self._current_second      = now_sec
                self._current_count       = 0
                self._current_error_count = 0

            if time.time() - self._last_recalc >= self.recalc_interval:
                self._recalculate()

    def get_effective(self) -> dict:
        """
        Return the current effective baseline values.
        This is what detector.py reads to make decisions.

        Returns:
            {
              "mean":         float,
              "stddev":       float,
              "error_mean":   float,
              "error_stddev": float,
              "ready":        bool,
              "samples":      int,
              "recalc_count": int,
            }
        """
        with self._lock:
            return {
                "mean"        : self._effective_mean,
                "stddev"      : self._effective_stddev,
                "error_mean"  : self._effective_error_mean,
                "error_stddev": self._effective_error_stddev,
                "ready"       : self._baseline_ready,
                "samples"     : len(self._window),
                "recalc_count": self._recalc_count,
            }

    def get_history(self) -> list:
        """
        Return baseline history for dashboard graphing.
        Each entry: {"timestamp": str, "mean": float, "stddev": float}
        """
        with self._lock:
            return list(self._history)

    def get_hourly_summary(self) -> list:
        """
        Return per-hour slot summaries for dashboard.
        """
        with self._lock:
            return [
                {
                    "hour"  : h,
                    "mean"  : round(self._hour_slots[h]["mean"], 3),
                    "stddev": round(self._hour_slots[h]["stddev"], 3),
                    "n"     : self._hour_slots[h]["n"],
                }
                for h in range(self.hourly_slots)
            ]

    # ══════════════════════════════════════════════════════════
    # Internal Methods
    # ══════════════════════════════════════════════════════════

    def _flush_second(self, second: int, count: int, error_count: int):
        """
        Flush accumulated count for a completed second into:
        - Rolling window (deque evicts oldest automatically)
        - Current hour slot
        """
        self._window.append((second, count))
        self._error_window.append((second, error_count))

        # Also record into the appropriate hour slot
        hour = datetime.fromtimestamp(second, tz=timezone.utc).hour
        self._hour_slots[hour]["counts"].append(count)
        self._hour_slots[hour]["n"] = len(self._hour_slots[hour]["counts"])

    def _recalculate(self):
        """
        Recompute mean and stddev from the rolling window.
        Prefer current hour's baseline if it has enough samples.
        Apply floor values to prevent division-by-zero or oversensitivity.
        Write to _history for graphing.
        Write to audit log.
        """
        self._last_recalc  = time.time()
        self._recalc_count += 1

        # ── Global rolling window stats ─────────────────────────
        global_mean, global_stddev = self._compute_stats(
            [c for _, c in self._window]
        )

        error_mean, error_stddev = self._compute_stats(
            [c for _, c in self._error_window]
        )

        # ── Hourly slot stats ───────────────────────────────────
        current_hour = datetime.now(tz=timezone.utc).hour
        slot = self._hour_slots[current_hour]

        # Recalculate this hour's slot stats
        slot_counts = list(slot["counts"])
        slot_mean, slot_stddev = self._compute_stats(slot_counts)
        slot["mean"]   = slot_mean
        slot["stddev"] = slot_stddev

        # ── Choose effective baseline ───────────────────────────
        # Prefer hourly slot if it has enough data
        use_hourly = (
            self.prefer_current_hour
            and slot["n"] >= self.hour_min_samples
        )

        if use_hourly:
            self._effective_mean   = slot_mean
            self._effective_stddev = slot_stddev
            source = f"hourly[{current_hour:02d}]"
        else:
            self._effective_mean   = global_mean
            self._effective_stddev = global_stddev
            source = "global"

        self._effective_error_mean   = error_mean
        self._effective_error_stddev = error_stddev

        # Mark baseline as ready once we have enough samples
        if len(self._window) >= self.min_samples:
            self._baseline_ready = True

        # ── Record history entry ────────────────────────────────
        self._history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "mean"     : round(self._effective_mean, 4),
            "stddev"   : round(self._effective_stddev, 4),
            "source"   : source,
            "samples"  : len(self._window),
        })

        # ── Audit log ───────────────────────────────────────────
        self._write_audit(source, global_mean, global_stddev)

        logger.info(
            f"Baseline recalculated #{self._recalc_count} "
            f"source={source} "
            f"mean={self._effective_mean:.3f} "
            f"stddev={self._effective_stddev:.3f} "
            f"samples={len(self._window)}"
        )

    def _compute_stats(self, counts: list) -> tuple:
        """
        Compute mean and stddev from a list of per-second counts.
        Applies floor values if result is below minimum.

        Returns: (mean, stddev)
        """
        if not counts:
            return self.floor_mean, self.floor_stddev

        n    = len(counts)
        mean = sum(counts) / n

        # Population stddev
        variance = sum((x - mean) ** 2 for x in counts) / n
        stddev   = math.sqrt(variance)

        # Apply floors
        mean   = max(mean, self.floor_mean)
        stddev = max(stddev, self.floor_stddev)

        return round(mean, 4), round(stddev, 4)

    def _write_audit(self, source: str, mean: float, stddev: float):
        """
        Write a structured audit log entry for baseline recalculation.
        Format: [timestamp] BASELINE_RECALC | source | mean | stddev | samples
        """
        audit_path = get("audit.path", "/app/audit.log")
        timestamp  = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"[{timestamp}] BASELINE_RECALC "
            f"source={source} | "
            f"mean={mean:.4f} | "
            f"stddev={stddev:.4f} | "
            f"samples={len(self._window)}\n"
        )
        try:
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            logger.warning(f"Could not write audit log: {e}")

    @staticmethod
    def _now_second() -> int:
        """Return current Unix timestamp floored to the second."""
        return int(time.time())
