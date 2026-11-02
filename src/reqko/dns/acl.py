"""Client Access Control List (ACL) matching (FR-13).

Restricts DNS resolver access to configured networks (e.g. RFC 1918 + loopback).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence


class ClientACL:
    """Evaluates whether client IP addresses belong to allowed CIDR networks."""

    def __init__(
        self, allowed_networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network]
    ) -> None:
        self.allowed_networks = tuple(allowed_networks)

    def is_allowed(self, client_ip: str) -> bool:
        """Returns True if client_ip belongs to any configured network."""
        try:
            ip = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            return False

        for net in self.allowed_networks:
            if ip in net:
                return True
        return False
