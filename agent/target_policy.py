"""Target policy checks to keep NeuralKali focused on lab/internal assessments."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import requests


@dataclass
class TargetAssessment:
    """Result of policy checks for a candidate target."""

    target: str
    category: str
    allowed: bool
    reason: str


class TargetPolicy:
    """Heuristic policy engine for differentiating lab/internal vs public targets."""

    LAB_HINTS = (
        "lab",
        "ctf",
        "hackthebox",
        "htb",
        "tryhackme",
        "thm",
        "internal",
        "local",
        "staging",
        "dev",
        "test",
    )
    ORG_HINTS = (
        "university",
        "bank",
        "government",
        "ministry",
        "official",
        "corporate",
        "enterprise",
        "production",
    )

    def _normalize(self, target: str) -> str:
        parsed = urlparse(target)
        candidate = parsed.hostname or parsed.path or target
        return candidate.strip().lower()

    def _looks_like_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, value: str) -> bool:
        ip_obj = ipaddress.ip_address(value)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local

    def _resolve_public_ip(self, host: str) -> str | None:
        try:
            resolved = socket.gethostbyname(host)
            ip_obj = ipaddress.ip_address(resolved)
            if ip_obj.is_private or ip_obj.is_loopback:
                return None
            return resolved
        except Exception:
            return None

    def _page_has_org_markers(self, target: str) -> bool:
        # Passive check only: we inspect homepage text for production/org indicators.
        url = target if re.match(r"^https?://", target, re.IGNORECASE) else f"http://{target}"
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
            return any(marker in content for marker in self.ORG_HINTS)
        except requests.RequestException:
            return False

    def assess(self, target: str) -> TargetAssessment:
        normalized = self._normalize(target)
        if not normalized:
            return TargetAssessment(target=target, category="invalid", allowed=False, reason="Empty target provided")

        if self._looks_like_ip(normalized):
            if self._is_private_ip(normalized):
                return TargetAssessment(target=target, category="internal_ip", allowed=True, reason="Private/internal IP target")
            return TargetAssessment(
                target=target,
                category="public_ip",
                allowed=False,
                reason="Public IP detected. Only internal/lab targets are allowed by default.",
            )

        if any(hint in normalized for hint in self.LAB_HINTS):
            return TargetAssessment(target=target, category="lab_domain", allowed=True, reason="Domain contains lab/testing indicators")

        public_ip = self._resolve_public_ip(normalized)
        if public_ip and self._page_has_org_markers(normalized):
            return TargetAssessment(
                target=target,
                category="public_org_site",
                allowed=False,
                reason="Likely live organizational website. Blocked for safety.",
            )

        if public_ip:
            return TargetAssessment(
                target=target,
                category="public_unknown",
                allowed=False,
                reason="Public internet target without lab indicators. Blocked unless explicitly authorized.",
            )

        return TargetAssessment(target=target, category="unresolved", allowed=False, reason="Could not verify as lab/internal target")
