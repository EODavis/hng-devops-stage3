# unbanner.py — Automatic IP unban scheduler
# Scans active bans every 30 seconds.
# Lifts expired bans and schedules re-bans on backoff schedule.
# Sends Slack notification on every unban.

import time
import logging
import threading
from datetime import datetime

from config import get

logger = logging.getLogger("unbanner")


class Unbanner:
    """
    Background thread that scans active bans and lifts
    those whose duration has expired.

    Backoff schedule (from config):
        Offense 1 → ban for 10 min, then unban
        Offense 2 → ban for 30 min, then unban
        Offense 3 → ban for 120 min, then unban
        Offense 4+ → permanent (never unban)

    The blocker tracks offense counts across bans.
    The unbanner just triggers the removal — blocker
    handles duration logic on re-ban.
    """

    def __init__(self, blocker):
        self.blocker       = blocker
        self.scan_interval = 30        # Scan every 30 seconds
        self._stop_event   = threading.Event()
        self._thread       = None
        self.unbans_done   = 0
        self.started_at    = None

        logger.info(
            f"Unbanner initialized — "
            f"scan_interval={self.scan_interval}s"
        )

    # ══════════════════════════════════════════════════════════
    # Public API
    # ══════════════════════════════════════════════════════════

    def start(self):
        """Start unbanner in a background daemon thread."""
        logger.info("Unbanner starting...")
        self.started_at = datetime.utcnow()
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="unbanner",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        logger.info("Unbanner stopping...")
        self._stop_event.set()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_stats(self) -> dict:
        uptime = (
            (datetime.utcnow() - self.started_at).total_seconds()
            if self.started_at else 0
        )
        return {
            "unbans_done"  : self.unbans_done,
            "active_bans"  : len(self.blocker.get_active_bans()),
            "uptime_secs"  : round(uptime, 1),
        }

    # ══════════════════════════════════════════════════════════
    # Internal — Scan Loop
    # ══════════════════════════════════════════════════════════

    def _scan_loop(self):
        """
        Main loop — wakes every scan_interval seconds,
        finds expired bans, lifts them via blocker.unban().
        """
        while not self._stop_event.is_set():
            try:
                self._scan_and_unban()
            except Exception as e:
                logger.error(f"Unbanner scan error: {e}")

            # Sleep in small increments so stop_event
            # is checked promptly
            for _ in range(self.scan_interval * 2):
                if self._stop_event.is_set():
                    break
                time.sleep(0.5)

    def _scan_and_unban(self):
        """
        Get all expired bans from blocker and unban them.
        blocker.unban() handles iptables removal + audit + Slack.
        """
        expired = self.blocker.get_pending_unbans()

        if not expired:
            logger.debug("Unbanner scan: no expired bans")
            return

        logger.info(f"Unbanner scan: found {len(expired)} expired ban(s)")

        for entry in expired:
            ip = entry.ip
            logger.info(
                f"Unbanning {ip} | "
                f"offense={entry.offense} | "
                f"served={entry.duration_min}min"
            )
            success = self.blocker.unban(ip)
            if success:
                self.unbans_done += 1
                logger.info(f"Successfully unbanned {ip}")
            else:
                logger.warning(f"Failed to unban {ip}")
