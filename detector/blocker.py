# blocker.py — iptables-based IP blocker
# Adds DROP rules for anomalous IPs within 10 seconds of detection.
# Maintains a ban registry tracking offense counts and ban times.
# Thread-safe — called from detector callback thread.

import time as _time
import subprocess
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from config import get

logger = logging.getLogger("blocker")


# ══════════════════════════════════════════════════════════════
# Ban Registry Entry
# ══════════════════════════════════════════════════════════════

class BanEntry:
    """
    Represents one active or historical ban.
    Uses time.time() for expiry checks — no timezone mismatch.
    """

    def __init__(
        self, ip: str, offense: int, duration_min: int,
        condition: str, rate: float, baseline: dict, z_score: float
    ):
        self.ip           = ip
        self.offense      = offense
        self.banned_at    = datetime.now(tz=timezone.utc)
        self.banned_ts    = _time.time()          # Plain float for expiry math
        self.duration_min = duration_min
        self.condition    = condition
        self.rate         = rate
        self.baseline     = baseline
        self.z_score      = z_score
        self.active       = True

    @property
    def is_permanent(self) -> bool:
        return self.duration_min == -1

    @property
    def expires_at(self) -> Optional[str]:
        if self.is_permanent:
            return "permanent"
        expire_ts = self.banned_ts + (self.duration_min * 60)
        return datetime.fromtimestamp(expire_ts, tz=timezone.utc).isoformat()

    @property
    def is_expired(self) -> bool:
        """Check expiry using plain float timestamps — no tz issues."""
        if self.is_permanent:
            return False
        elapsed_minutes = (_time.time() - self.banned_ts) / 60
        return elapsed_minutes >= self.duration_min

    def to_dict(self) -> dict:
        return {
            "ip"          : self.ip,
            "offense"     : self.offense,
            "banned_at"   : self.banned_at.isoformat(),
            "duration_min": self.duration_min,
            "expires_at"  : self.expires_at,
            "condition"   : self.condition,
            "rate"        : round(self.rate, 3),
            "z_score"     : round(self.z_score, 2),
            "active"      : self.active,
        }


# ══════════════════════════════════════════════════════════════
# Blocker
# ══════════════════════════════════════════════════════════════

class Blocker:
    """
    Manages iptables DROP rules for anomalous IPs.

    Public methods:
        ban(ip, condition, rate, baseline, z_score)
        unban(ip)
        is_banned(ip) -> bool
        get_active_bans() -> list[dict]
        get_pending_unbans() -> list[BanEntry]
        get_offense_count(ip) -> int
    """

    def __init__(self, notifier=None):
        # ── Config ──────────────────────────────────────────────
        self.enabled        = get("blocking.enabled", True)
        self.chain          = get("blocking.chain", "INPUT")
        self.unban_schedule = get("blocking.unban_schedule", [10, 30, 120, -1])
        self.audit_path     = get("audit.path", "/app/audit.log")

        # ── State ───────────────────────────────────────────────
        self._bans: dict     = {}   # ip → BanEntry
        self._offenses: dict = {}   # ip → lifetime offense count

        # ── Dependencies ────────────────────────────────────────
        self.notifier = notifier

        # ── Thread safety ───────────────────────────────────────
        self._lock = threading.RLock()

        logger.info(
            f"Blocker initialized — "
            f"chain={self.chain}, "
            f"schedule={self.unban_schedule}, "
            f"enabled={self.enabled}"
        )

    # ══════════════════════════════════════════════════════════
    # Public API
    # ══════════════════════════════════════════════════════════

    def ban(
        self, ip: str, condition: str,
        rate: float, baseline: dict, z_score: float
    ) -> bool:
        """
        Ban an IP. Determines duration from offense count + schedule.
        Works in both enabled (real iptables) and disabled (test) modes.
        Returns True if ban was registered, False if already banned.
        """
        with self._lock:
            # Skip if already actively banned
            if self.is_banned(ip):
                logger.debug(f"IP {ip} already banned — skipping")
                return False

            # Increment offense count
            self._offenses[ip] = self._offenses.get(ip, 0) + 1
            offense      = self._offenses[ip]
            duration_min = self._get_duration(offense)

            # Create and register ban entry
            entry = BanEntry(
                ip=ip,
                offense=offense,
                duration_min=duration_min,
                condition=condition,
                rate=rate,
                baseline=baseline,
                z_score=z_score,
            )
            self._bans[ip] = entry

            duration_str = (
                "PERMANENT" if duration_min == -1
                else f"{duration_min}min"
            )

            # Write audit log (always — even in test mode)
            self._write_audit_ban(entry)

            # Send Slack alert
            if self.notifier:
                self.notifier.send_ban(entry)

            if not self.enabled:
                # Test/dry-run mode — skip real iptables
                logger.warning(
                    f"[DRY-RUN] BANNED {ip} | "
                    f"offense={offense} | condition={condition} | "
                    f"rate={rate:.3f} req/s | z={z_score:.2f} | "
                    f"duration={duration_str}"
                )
                return True

            # Apply real iptables rule
            success = self._iptables_drop(ip)
            if not success:
                logger.error(f"iptables ban FAILED for {ip}")
                # Entry is registered so unbanner can still clean up
                return False

            logger.warning(
                f"BANNED {ip} | "
                f"offense={offense} | condition={condition} | "
                f"rate={rate:.3f} req/s | z={z_score:.2f} | "
                f"duration={duration_str}"
            )
            return True

    def unban(self, ip: str) -> bool:
        """
        Remove ban for an IP.
        Handles both real iptables and dry-run modes.
        Returns True if successfully unbanned.
        """
        with self._lock:
            entry = self._bans.get(ip)
            if not entry or not entry.active:
                return False

            if self.enabled:
                success = self._iptables_unban(ip)
                if not success:
                    return False

            # Mark inactive regardless of mode
            entry.active = False
            self._write_audit_unban(entry)

            if self.notifier:
                self.notifier.send_unban(entry)

            logger.info(
                f"UNBANNED {ip} | "
                f"offense={entry.offense} | "
                f"served={entry.duration_min}min"
            )
            return True

    def is_banned(self, ip: str) -> bool:
        """Return True if IP has an active ban."""
        with self._lock:
            entry = self._bans.get(ip)
            return entry is not None and entry.active

    def get_active_bans(self) -> list:
        """Return list of active ban dicts (for dashboard)."""
        with self._lock:
            return [
                e.to_dict() for e in self._bans.values()
                if e.active
            ]

    def get_all_bans(self) -> list:
        """Return all bans including expired (for audit view)."""
        with self._lock:
            return [e.to_dict() for e in self._bans.values()]

    def get_offense_count(self, ip: str) -> int:
        with self._lock:
            return self._offenses.get(ip, 0)

    def get_pending_unbans(self) -> list:
        """
        Return BanEntry objects whose duration has expired.
        Called by unbanner.py every scan cycle.
        Uses is_expired which compares plain float timestamps.
        """
        with self._lock:
            pending = [
                e for e in self._bans.values()
                if e.active and not e.is_permanent and e.is_expired
            ]
            if pending:
                logger.debug(
                    f"get_pending_unbans: found {len(pending)} expired — "
                    + ", ".join(
                        f"{e.ip}(elapsed="
                        f"{(_time.time()-e.banned_ts)/60:.2f}min/"
                        f"{e.duration_min}min)"
                        for e in pending
                    )
                )
            return pending

    # ══════════════════════════════════════════════════════════
    # Internal — iptables
    # ══════════════════════════════════════════════════════════

    def _iptables_drop(self, ip: str) -> bool:
        """Insert DROP rule at top of INPUT chain."""
        try:
            result = subprocess.run(
                ["iptables", "-I", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.error(f"iptables DROP failed for {ip}: {result.stderr}")
                return False
            logger.debug(f"iptables DROP rule added for {ip}")
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"iptables command timed out for {ip}")
            return False
        except FileNotFoundError:
            logger.error("iptables not found — is NET_ADMIN capability set?")
            return False
        except Exception as e:
            logger.error(f"iptables error for {ip}: {e}")
            return False

    def _iptables_unban(self, ip: str) -> bool:
        """Remove DROP rule from INPUT chain."""
        try:
            result = subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.warning(
                    f"iptables DELETE failed for {ip} "
                    f"(may already be removed): {result.stderr}"
                )
                return False
            logger.debug(f"iptables DROP rule removed for {ip}")
            return True
        except Exception as e:
            logger.error(f"iptables unban error for {ip}: {e}")
            return False

    # ══════════════════════════════════════════════════════════
    # Internal — Schedule + Audit
    # ══════════════════════════════════════════════════════════

    def _get_duration(self, offense: int) -> int:
        """
        Look up ban duration from backoff schedule.
        offense 1 → schedule[0], offense 2 → schedule[1], etc.
        Beyond schedule length → last value (permanent).
        """
        idx = min(offense - 1, len(self.unban_schedule) - 1)
        return self.unban_schedule[idx]

    def _write_audit_ban(self, entry: BanEntry):
        timestamp    = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        duration_str = (
            "PERMANENT" if entry.is_permanent
            else f"{entry.duration_min}min"
        )
        line = (
            f"[{timestamp}] BAN "
            f"{entry.ip} | "
            f"condition={entry.condition} | "
            f"rate={entry.rate:.3f} | "
            f"baseline_mean={entry.baseline.get('mean', 0):.3f} | "
            f"z={entry.z_score:.2f} | "
            f"offense={entry.offense} | "
            f"duration={duration_str}\n"
        )
        self._append_audit(line)

    def _write_audit_unban(self, entry: BanEntry):
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"[{timestamp}] UNBAN "
            f"{entry.ip} | "
            f"offense={entry.offense} | "
            f"duration_served={entry.duration_min}min | "
            f"condition={entry.condition}\n"
        )
        self._append_audit(line)

    def _append_audit(self, line: str):
        try:
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            logger.warning(f"Audit write error: {e}")
