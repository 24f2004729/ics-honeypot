# =============================================================================
#  ics_honeypot / shared / guard.py
#  ---------------------------------------------------------------------------
#  Connection Guard & Anti-DoS Resource Limiter
#  ---------------------------------------------------------------------------
#  Tracks active connections globally and per-IP to prevent thread exhaustion,
#  SYN floods, and slowloris-style denial of service attacks against the honeypot.
# =============================================================================

import threading
from collections import defaultdict
from honeypot.shared.config import MAX_ACTIVE_CONNECTIONS, MAX_CONNS_PER_IP


class ConnectionGuard:
    """
    Thread-safe connection limiter.
    Ensures that a single IP or mass scan cannot consume all available
    system sockets and threads.
    """

    def __init__(self, max_total: int = MAX_ACTIVE_CONNECTIONS, max_per_ip: int = MAX_CONNS_PER_IP):
        self._lock = threading.Lock()
        self.max_total = max_total
        self.max_per_ip = max_per_ip
        self._active_ips = defaultdict(int)
        self._total_active = 0

    def acquire(self, ip: str) -> bool:
        """
        Check if an incoming connection is permitted.
        Returns True and increments counter if allowed, False if limit exceeded.
        """
        with self._lock:
            if self._total_active >= self.max_total:
                return False
            if self._active_ips[ip] >= self.max_per_ip:
                return False

            self._active_ips[ip] += 1
            self._total_active += 1
            return True

    def release(self, ip: str):
        """Release active connection count for IP."""
        with self._lock:
            if self._active_ips[ip] > 0:
                self._active_ips[ip] -= 1
                if self._active_ips[ip] == 0:
                    del self._active_ips[ip]
            if self._total_active > 0:
                self._total_active -= 1

    @property
    def active_count(self) -> int:
        with self._lock:
            return self._total_active


# Global singleton connection guard
guard = ConnectionGuard()
