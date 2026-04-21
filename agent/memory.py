"""Memory subsystem using ChromaDB with JSON fallback."""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from config.settings import Settings

try:
    import chromadb
except ImportError:  # pragma: no cover
    chromadb = None


class Memory:
    """Stores and retrieves findings for a target execution session."""

    def __init__(self, settings: Settings, logger: logging.Logger) -> None:
        self.settings = settings
        self.logger = logger
        self.settings.MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        self.settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self._fallback_file = self.settings.MEMORY_DIR / "fallback_findings.json"
        self.client = None
        self.collection = None
        self._init_chroma()

    def _init_chroma(self) -> None:
        if chromadb is None:
            self.logger.warning("ChromaDB unavailable, using JSON fallback.")
            return
        try:
            self.client = chromadb.PersistentClient(path=str(self.settings.MEMORY_DIR))
            self.collection = self.client.get_or_create_collection("findings")
        except Exception as exc:  # pragma: no cover
            self.logger.warning("Failed to initialize ChromaDB: %s", exc)
            self.client = None
            self.collection = None

    def _fallback_read(self) -> list[dict[str, Any]]:
        if not self._fallback_file.exists():
            return []
        try:
            return json.loads(self._fallback_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

    def _fallback_write(self, records: list[dict[str, Any]]) -> None:
        self._fallback_file.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def store_finding(self, target: str, tool: str, output: str, step_number: int) -> dict[str, Any]:
        """Store a tool finding into memory backend."""
        record = {
            "id": str(uuid.uuid4()),
            "target": target,
            "tool": tool,
            "output": output,
            "step_number": step_number,
            "timestamp": dt.datetime.utcnow().isoformat(),
        }

        if self.collection is not None:
            self.collection.add(
                ids=[record["id"]],
                documents=[output],
                metadatas=[
                    {
                        "target": target,
                        "tool": tool,
                        "timestamp": record["timestamp"],
                        "step_number": step_number,
                    }
                ],
            )
        else:
            records = self._fallback_read()
            records.append(record)
            self._fallback_write(records)
        return record

    def stores_finding(self, target: str, tool: str, output: str, step_number: int) -> dict[str, Any]:
        """Compatibility alias requested by the original spec."""
        return self.store_finding(target, tool, output, step_number)

    def get_context(self, target: str, query: str, n_results: int = 5) -> list[dict[str, Any]]:
        if self.collection is not None:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where={"target": target},
            )
            contexts: list[dict[str, Any]] = []
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            for doc, meta in zip(docs, metas):
                contexts.append({"output": doc, "metadata": meta})
            return contexts

        records = [r for r in self._fallback_read() if r.get("target") == target]
        return records[-n_results:]

    def get_full_history(self, target: str) -> list[dict[str, Any]]:
        if self.collection is not None:
            data = self.collection.get(where={"target": target})
            documents = data.get("documents", [])
            metadatas = data.get("metadatas", [])
            combined = [
                {"output": doc, "metadata": meta}
                for doc, meta in zip(documents, metadatas)
            ]
            return sorted(combined, key=lambda x: x["metadata"].get("timestamp", ""))

        records = [r for r in self._fallback_read() if r.get("target") == target]
        return sorted(records, key=lambda x: x.get("timestamp", ""))

    def save_session(self, target: str, task: str, status: str) -> Path:
        payload = {
            "target": target,
            "task": task,
            "status": status,
            "timestamp": dt.datetime.utcnow().isoformat(),
        }
        path = self.settings.REPORTS_DIR / f"session_{target.replace(':', '_')}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def load_session(self, target: str) -> dict[str, Any] | None:
        path = self.settings.REPORTS_DIR / f"session_{target.replace(':', '_')}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def clear_target(self, target: str) -> None:
        if self.collection is not None:
            self.collection.delete(where={"target": target})

        records = [r for r in self._fallback_read() if r.get("target") != target]
        self._fallback_write(records)
