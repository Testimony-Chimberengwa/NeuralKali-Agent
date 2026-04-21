"""Main orchestration loop for NeuralKali."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import ollama
from rich.console import Console
from rich.panel import Panel

from agent.memory import Memory
from agent.planner import Planner, Step
from agent.reporter import Reporter
from agent.tools import ToolExecutor
from config.settings import Settings, setup_logging


class NeuralKaliAgent:
    """Coordinates planning, execution, memory, and reporting."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self.logger: logging.Logger = setup_logging(self.settings)
        self.console = Console()
        self.scope = self._load_scope(self.settings.SCOPE_FILE)
        self.tools = ToolExecutor(self.settings, self.logger)
        self.memory = Memory(self.settings, self.logger)
        self.planner = Planner(self.settings, self.logger)
        self.reporter = Reporter(self.settings, self.logger)
        self.client = ollama.Client(host=self.settings.OLLAMA_HOST)
        self.model = self.settings.AI_MODEL

    def _load_scope(self, path: Path) -> set[str]:
        if not path.exists():
            return set()
        lines = path.read_text(encoding="utf-8").splitlines()
        return {line.strip() for line in lines if line.strip() and not line.strip().startswith("#")}

    def _in_scope(self, target: str) -> bool:
        return target in self.scope

    def _llm_decision(self, target: str, task: str, findings: list[dict[str, Any]], last_result: dict[str, Any]) -> dict[str, Any]:
        prompt = (
            "You are an authorized security testing assistant. "
            "Given findings, return JSON exactly with keys action, tool, args, reasoning. "
            "Valid action values: continue, adjust, exploit, complete. "
            f"Target: {target}\nTask: {task}\nFindings: {findings[-5:]}\nLastResult: {last_result}"
        )
        response = self.client.generate(model=self.model, prompt=prompt)
        text = response.get("response", "").strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"action": "continue", "tool": "", "args": {}, "reasoning": "Fallback continue due to parse error."}

    def _execute_step(self, step: Step) -> dict[str, Any]:
        tool = step.tool
        args = step.args

        if tool == "nmap":
            return self.tools.run_nmap(**args)
        if tool == "gobuster":
            return self.tools.run_gobuster(**args)
        if tool == "nikto":
            return self.tools.run_nikto(**args)
        if tool == "sqlmap":
            return self.tools.run_sqlmap(**args)
        if tool == "whatweb":
            return self.tools.run_whatweb(**args)
        if tool == "enum4linux":
            return self.tools.run_enum4linux(**args)
        return {
            "tool_name": tool,
            "command_run": "",
            "output": f"Unsupported tool: {tool}",
            "success": False,
            "timestamp": "",
        }

    def run(self, target: str, task: str, interactive: bool = True) -> dict[str, Any]:
        if not self._in_scope(target):
            message = f"Target {target} is out of scope. Hard stop."
            self.logger.error(message)
            self.console.print(Panel(message, style="bold red"))
            return {"success": False, "reason": message}

        findings: list[dict[str, Any]] = []
        plan = self.planner.generate_plan(target, task)
        self.console.print(Panel(f"Starting NeuralKali run for {target}", style="bold cyan"))

        for step_number in range(1, self.settings.MAX_STEPS + 1):
            step = self.planner.next_step(findings)
            if step is None:
                break

            self.console.print(f"[yellow]Step {step_number}[/yellow] {step.phase}: {step.tool} {step.args}")
            if interactive:
                approved = self.console.input("Proceed? [y/N]: ").strip().lower() == "y"
                if not approved:
                    self.logger.info("Step %s skipped by operator.", step_number)
                    continue

            result = self._execute_step(step)
            findings.append(result)
            self.memory.store_finding(target, result["tool_name"], result["output"], step_number)

            decision = self._llm_decision(target, task, findings, result)
            action = decision.get("action", "continue")
            self.logger.info("Decision: %s", decision)

            if action == "complete":
                break
            if action == "adjust":
                plan = self.planner.adjust_plan(findings)
                self.logger.info("Plan adjusted to %s steps", len(plan))

        session_data = self.memory.load_session(target) or {}
        report_paths = self.reporter.generate_report(target, findings, session_data)
        self.memory.save_session(target, task, "complete")
        self.reporter.print_summary(findings)
        return {
            "success": True,
            "target": target,
            "findings": findings,
            "report_paths": report_paths,
        }

    def daemon(self) -> None:
        self.console.print("[green]Daemon mode started.[/green]")
        self.settings.TASKS_DIR.mkdir(parents=True, exist_ok=True)

        while True:
            task_files = list(self.settings.TASKS_DIR.glob("*.json"))
            for task_file in task_files:
                try:
                    payload = json.loads(task_file.read_text(encoding="utf-8"))
                    target = payload["target"]
                    task = payload["task"]
                    interactive = bool(payload.get("interactive", False))
                    self.logger.info("Picked task file %s", task_file)
                    self.run(target, task, interactive=interactive)
                    task_file.unlink(missing_ok=True)
                except Exception as exc:  # pragma: no cover
                    self.logger.exception("Failed processing task file %s: %s", task_file, exc)
            time.sleep(5)
