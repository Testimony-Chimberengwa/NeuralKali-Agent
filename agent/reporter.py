"""Report generation subsystem."""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

import ollama
from rich.console import Console
from rich.table import Table

from config.settings import Settings


class Reporter:
    """Generates text and markdown reports from findings."""

    def __init__(self, settings: Settings, logger: logging.Logger) -> None:
        self.settings = settings
        self.logger = logger
        self.client = ollama.Client(host=settings.OLLAMA_HOST)
        self.model = settings.AI_MODEL
        self.console = Console()

    def generate_report(self, target: str, findings: list[dict[str, Any]], session_data: dict[str, Any]) -> dict[str, str]:
        timestamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(":", "_")
        md_path = self.settings.REPORTS_DIR / f"report_{safe_target}_{timestamp}.md"
        txt_path = self.settings.REPORTS_DIR / f"report_{safe_target}_{timestamp}.txt"

        prompt = (
            "Write a professional penetration test report with sections: "
            "Executive Summary, Methodology, Findings, Risk Ratings, Recommendations. "
            "Use concise and practical language. "
            f"Target: {target}\nSession: {session_data}\nFindings: {findings}"
        )

        response = self.client.generate(model=self.model, prompt=prompt)
        report_text = response.get("response", "No report content generated.")

        md_path.write_text(report_text, encoding="utf-8")
        txt_path.write_text(report_text, encoding="utf-8")
        self.logger.info("Report written to %s and %s", md_path, txt_path)
        return {"md": str(md_path), "txt": str(txt_path)}

    def generate_htb_writeup(self, target: str, findings: list[dict[str, Any]]) -> str:
        prompt = (
            "Generate a HackTheBox style writeup with sections: Enumeration, Foothold, "
            "Privilege Escalation, Flags. Keep it factual based on provided findings. "
            f"Target: {target}\nFindings: {findings}"
        )
        response = self.client.generate(model=self.model, prompt=prompt)
        writeup = response.get("response", "No writeup generated.")
        path = self.settings.REPORTS_DIR / f"htb_writeup_{target.replace(':', '_')}.md"
        path.write_text(writeup, encoding="utf-8")
        return writeup

    def risk_rate(self, finding: str) -> dict[str, str]:
        prompt = (
            "Rate this finding as one of Critical, High, Medium, Low, Info and give a one-line justification. "
            f"Finding: {finding}. Return format: LEVEL|JUSTIFICATION"
        )
        response = self.client.generate(model=self.model, prompt=prompt)
        raw = response.get("response", "Info|Unable to determine")
        if "|" in raw:
            level, justification = raw.split("|", 1)
        else:
            level, justification = "Info", raw
        return {"level": level.strip(), "justification": justification.strip()}

    def print_summary(self, findings: list[dict[str, Any]]) -> None:
        table = Table(title="NeuralKali Findings Summary")
        table.add_column("Tool", style="cyan")
        table.add_column("Finding", style="white", overflow="fold")
        table.add_column("Severity")

        color = {
            "Critical": "red",
            "High": "bright_red",
            "Medium": "yellow",
            "Low": "green",
            "Info": "blue",
        }
        for finding in findings:
            output = str(finding.get("output", ""))
            risk = self.risk_rate(output)
            level = risk["level"]
            level_style = color.get(level, "white")
            table.add_row(
                str(finding.get("tool_name", "unknown")),
                output[:120],
                f"[{level_style}]{level}[/{level_style}]",
            )
        self.console.print(table)
