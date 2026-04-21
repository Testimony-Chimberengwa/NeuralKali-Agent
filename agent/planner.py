"""Planning subsystem for structured attack workflow."""

from __future__ import annotations

import json
import logging
from typing import Any

import ollama
from pydantic import BaseModel, Field

from config.settings import Settings


class Step(BaseModel):
    """One actionable planning step."""

    phase: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    reasoning: str
    priority: int
    depends_on: list[str] = Field(default_factory=list)


class Planner:
    """Generates and adapts test plans from findings and task goals."""

    def __init__(self, settings: Settings, logger: logging.Logger) -> None:
        self.settings = settings
        self.logger = logger
        self.client = ollama.Client(host=settings.OLLAMA_HOST)
        self.model = settings.AI_MODEL
        self._plan: list[Step] = []

    def generate_plan(self, target: str, task: str) -> list[Step]:
        base = [
            Step(phase="Reconnaissance", tool="nmap", args={"target": target, "flags": "-sC -sV -O"}, reasoning="Discover open ports and services.", priority=1),
            Step(phase="Enumeration", tool="whatweb", args={"target": target}, reasoning="Fingerprint technologies for attack surface understanding.", priority=2, depends_on=["nmap"]),
            Step(phase="Enumeration", tool="gobuster", args={"target": target}, reasoning="Find hidden web content if web services are present.", priority=3, depends_on=["nmap"]),
            Step(phase="Enumeration", tool="enum4linux", args={"target": target}, reasoning="Enumerate SMB and NetBIOS if available.", priority=4, depends_on=["nmap"]),
            Step(phase="Vulnerability Analysis", tool="nikto", args={"target": target}, reasoning="Run vulnerability checks on web service.", priority=5, depends_on=["whatweb"]),
            Step(phase="Exploitation", tool="sqlmap", args={"target": target, "params": "", "confirmed_vulnerable": False}, reasoning="Attempt SQLi only with prior evidence.", priority=6, depends_on=["nikto"]),
            Step(phase="Reporting", tool="report", args={"target": target}, reasoning="Generate a final report with remediation guidance.", priority=7),
        ]

        prompt = (
            "You are a pentest planning assistant. Refine this plan for a legal authorized target. "
            "Return JSON list of Step objects only. "
            f"Target: {target}\nTask: {task}\nBasePlan: {json.dumps([s.model_dump() for s in base])}"
        )
        try:
            response = self.client.generate(model=self.model, prompt=prompt)
            text = response.get("response", "").strip()
            parsed = json.loads(text)
            self._plan = [Step(**item) for item in parsed]
        except Exception:
            self._plan = base
        return self._plan

    def next_step(self, current_findings: list[dict[str, Any]]) -> Step | None:
        completed_tools = {f.get("tool_name") for f in current_findings}
        for step in sorted(self._plan, key=lambda s: s.priority):
            if step.tool in completed_tools:
                continue
            if all(dep in completed_tools for dep in step.depends_on):
                return step
        return None

    def adjust_plan(self, findings: list[dict[str, Any]]) -> list[Step]:
        prompt = (
            "Given current findings, adjust the pentest plan. Keep JSON list of Step objects. "
            f"Findings: {json.dumps(findings)}\nCurrentPlan: {json.dumps([s.model_dump() for s in self._plan])}"
        )
        try:
            response = self.client.generate(model=self.model, prompt=prompt)
            text = response.get("response", "").strip()
            parsed = json.loads(text)
            self._plan = [Step(**item) for item in parsed]
        except Exception as exc:
            self.logger.warning("Plan adjustment failed, keeping current plan: %s", exc)
        return self._plan
