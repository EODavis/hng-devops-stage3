# monitor.py — Continuous Nginx JSON log tailer
# Reads hng-access.log line by line in real time.
# Parses each JSON entry and puts it on a shared queue.
# Handles: file not found, rotation, truncation, malformed lines.

import json
import os
import time
import queue
import logging
import threading
from datetime import datetime
from pathlib import Path

from config import get

# ── Module logger ─────────────────────────────────────────────
logger = logging.getLogger("monitor")


# ── Data class for a parsed log entry ─────────────────────────
class LogEntry:
    """
    Represents one parsed line from hng-access.log.
    All fields guaranteed to exist — defaults applied if missing.
    """
    __slots__ = (
        "source_ip", "timestamp", "method", "path",
        "status", "response_size", "http_host",
        "user_agent", "request_time", "raw"
    )

    def __init__(self, data: dict, raw: str):
        self.source_ip    = data.get("source_ip", "0.0.0.0").strip()
        self.timestamp    = data.get("timestamp", "")
        self.method       = data.get("method", "UNKNOWN")
        self.path         = data.get("path", "/")
        self.status       = int(data.get("status", 0))
        self.response_size= int(data.get("response_size", 0))
        self.http_host    = data.get("http_host", "")
        self.user_agent   = data.get("user_agent", "")
        self.request_time = float(data.get("request_time", 0.0))
        self.raw          = raw  # Original line for debugging

    @property
    def is_error(self) -> bool:
        """True if status is 4xx or 5xx."""
        return self.status >= 400

    @property
    def parsed_time(self) -> datetime:
        """Parse ISO8601 timestamp into datetime object."""
        try:
            # Handle timezone offset like +00:00
            ts = self.timestamp
            if ts.endswith("+00:00"):
                ts = ts[:-6]
            return datetime.fromisoformat(ts)
        except Exception:
            return datetime.utcnow()

    def __repr__(self):
        return (
            f"LogEntry(ip={self.source_ip}, "
            f"method={self.method}, path={self.path}, "
            f"status={self.status})"
        )


# ── Log Monitor Class ──────────────────────────────────────────
class LogMonitor:
    """
    Continuously tails the Nginx JSON access log.
    Puts LogEntry objects onto self.queue for consumers.

    Usage:
        monitor = LogMonitor()
        monitor.start()
        # Elsewhere: entry = monitor.queue.get()
    """

    def __init__(self):
        self.log_path     = get("log.path")
        self.poll_interval= get("log.poll_interval", 0.1)
        self.queue        = queue.Queue(maxsize=10000)
        self._stop_event  = threading.Event()
        self._thread      = None

        # Stats
        self.lines_read   = 0
        self.lines_failed = 0
        self.started_at   = None

    # ── Public API ─────────────────────────────────────────────

    def start(self):
        """Start the monitor in a background daemon thread."""
        logger.info(f"LogMonitor starting — watching {self.log_path}")
        self.started_at = datetime.utcnow()
        self._thread = threading.Thread(
            target=self._tail_loop,
            name="log-monitor",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Signal the monitor to stop."""
        logger.info("LogMonitor stopping...")
        self._stop_event.set()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internal Tail Loop ─────────────────────────────────────

    def _tail_loop(self):
        """
        Main loop — opens file, seeks to end, reads new lines forever.
        Handles:
          - File not existing yet (waits until it appears)
          - File truncation/rotation (resets position)
          - Malformed JSON lines (skips with warning)
          - Slow traffic (polls at configurable interval)
        """
        log_path = Path(self.log_path)

        # Wait for log file to exist
        while not self._stop_event.is_set():
            if log_path.exists():
                break
            logger.warning(f"Waiting for log file: {self.log_path}")
            time.sleep(2)

        logger.info(f"Log file found: {self.log_path}")

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            # Seek to end — we only care about new lines from now on
            f.seek(0, 2)
            last_size = f.tell()
            logger.info(f"Seeked to end of log (offset {last_size})")

            while not self._stop_event.is_set():
                try:
                    current_size = log_path.stat().st_size
                except FileNotFoundError:
                    # File was deleted (log rotation) — reopen
                    logger.warning("Log file disappeared — waiting for recreation")
                    time.sleep(1)
                    self._tail_loop()   # Recurse to reopen
                    return

                # Detect truncation (log rotation)
                if current_size < last_size:
                    logger.warning("Log truncated — resetting to beginning")
                    f.seek(0)
                    last_size = 0

                line = f.readline()

                if not line:
                    # No new data — wait and poll again
                    time.sleep(self.poll_interval)
                    continue

                last_size = f.tell()
                self._process_line(line.strip())

    def _process_line(self, line: str):
        """
        Parse one raw JSON line into a LogEntry.
        Silently skips empty lines.
        Logs a warning for malformed JSON.
        """
        if not line:
            return

        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            self.lines_failed += 1
            logger.warning(f"Malformed JSON line (skipped): {e} | raw: {line[:80]}")
            return

        # Validate minimum required fields
        if "source_ip" not in data:
            logger.debug(f"Line missing source_ip — skipping: {line[:80]}")
            return

        entry = LogEntry(data, raw=line)
        self.lines_read += 1

        # Put on queue — drop if full (backpressure protection)
        try:
            self.queue.put_nowait(entry)
        except queue.Full:
            logger.warning("Log queue full — dropping entry (detector may be slow)")

        # Debug log every 100 lines
        if self.lines_read % 100 == 0:
            logger.debug(
                f"Monitor stats: read={self.lines_read} "
                f"failed={self.lines_failed} "
                f"queue_size={self.queue.qsize()}"
            )

    # ── Stats ──────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return current monitor statistics."""
        uptime = (
            (datetime.utcnow() - self.started_at).total_seconds()
            if self.started_at else 0
        )
        return {
            "lines_read"  : self.lines_read,
            "lines_failed": self.lines_failed,
            "queue_size"  : self.queue.qsize(),
            "uptime_secs" : round(uptime, 1),
            "alive"       : self.is_alive(),
        }
