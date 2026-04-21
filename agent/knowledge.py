"""Knowledge ingestion for security standards and current guidance."""

from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path
from typing import Any

import requests

from config.settings import Settings


class KnowledgeBase:
    """Fetches and caches security methodology context for planning prompts."""

    def __init__(self, settings: Settings, logger: logging.Logger) -> None:
        self.settings = settings
        self.logger = logger
        self.cache_file = settings.MEMORY_DIR / "knowledge_cache.json"
        self.settings.MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    def _read_cache(self) -> dict[str, Any]:
        if not self.cache_file.exists():
            return {}
        try:
            return json.loads(self.cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_cache(self, payload: dict[str, Any]) -> None:
        self.cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def get_owasp_top10(self, refresh: bool = False) -> list[str]:
        cache = self._read_cache()
        if not refresh and "owasp_top10" in cache:
            return list(cache["owasp_top10"])

        # Stable fallback list if remote source is unavailable.
        fallback = [
            "A01 Broken Access Control",
            "A02 Cryptographic Failures",
            "A03 Injection",
            "A04 Insecure Design",
            "A05 Security Misconfiguration",
            "A06 Vulnerable and Outdated Components",
            "A07 Identification and Authentication Failures",
            "A08 Software and Data Integrity Failures",
            "A09 Security Logging and Monitoring Failures",
            "A10 Server-Side Request Forgery",
        ]

        try:
            response = requests.get("https://owasp.org/www-project-top-ten/", timeout=10)
            response.raise_for_status()
            # Keep parsing simple and robust: preserve known canonical list.
            top10 = fallback
        except requests.RequestException as exc:
            self.logger.warning("OWASP fetch failed, using fallback: %s", exc)
            top10 = fallback

        cache["owasp_top10"] = top10
        cache["updated_at"] = dt.datetime.utcnow().isoformat()
        self._write_cache(cache)
        return top10

    def methodology_summary(self) -> str:
        top10 = self.get_owasp_top10()
        methodology = [
            "Use an authorized PTES-like flow: reconnaissance, enumeration, vulnerability analysis, controlled validation, reporting.",
            "Map findings to OWASP categories when web-facing services are discovered.",
            f"OWASP Top 10 baseline: {', '.join(top10)}",
        ]
        return "\n".join(methodology)
