"""Tool execution layer with strict scope enforcement."""

from __future__ import annotations

import datetime as dt
import logging
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from config.settings import Settings


class ToolExecutor:
    """Executes approved recon tools and returns structured outputs."""

    def __init__(self, settings: Settings, logger: logging.Logger) -> None:
        self.settings = settings
        self.logger = logger
        self.blacklist = {"rm", "mkfs", "dd", ":(){", "fork", "wget"}
        self._unknown_wget_pattern = re.compile(r"wget\s+(?!https?://(github\.com|gitlab\.com|raw\.githubusercontent\.com))", re.IGNORECASE)
        self.tool_registry: dict[str, dict[str, Any]] = {
            "nmap": {"binary": "nmap", "installer": "nmap", "method": self.run_nmap},
            "gobuster": {"binary": "gobuster", "installer": "gobuster", "method": self.run_gobuster},
            "nikto": {"binary": "nikto", "installer": "nikto", "method": self.run_nikto},
            "sqlmap": {"binary": "sqlmap", "installer": "sqlmap", "method": self.run_sqlmap},
            "whatweb": {"binary": "whatweb", "installer": "whatweb", "method": self.run_whatweb},
            "enum4linux": {"binary": "enum4linux", "installer": "enum4linux", "method": self.run_enum4linux},
            "wpscan": {"binary": "wpscan", "installer": "wpscan", "method": None},
            "ffuf": {"binary": "ffuf", "installer": "ffuf", "method": None},
            "amass": {"binary": "amass", "installer": "amass", "method": None},
            "burpsuite": {"binary": "burpsuite", "installer": "burpsuite", "method": None},
            "zap": {"binary": "zaproxy", "installer": "zaproxy", "method": None},
        }

    def _timestamp(self) -> str:
        return dt.datetime.utcnow().isoformat()

    def _read_scope(self) -> set[str]:
        try:
            lines = self.settings.SCOPE_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            return set()
        return {line.strip() for line in lines if line.strip() and not line.strip().startswith("#")}

    def _target_in_scope(self, target: str) -> bool:
        target = target.strip()
        if not target:
            return False
        parsed = urlparse(target)
        normalized = parsed.hostname or parsed.path or target
        normalized = normalized.strip().lower()
        scope = {entry.lower() for entry in self._read_scope()}
        return normalized in scope

    def _result(self, tool_name: str, command_run: str, output: str, success: bool) -> dict[str, Any]:
        return {
            "tool_name": tool_name,
            "command_run": command_run,
            "output": output,
            "success": success,
            "timestamp": self._timestamp(),
        }

    def _guard_scope(self, target: str, tool_name: str, command: str) -> dict[str, Any] | None:
        if not self._target_in_scope(target):
            message = f"Target '{target}' not in allowed scope. Blocked by policy."
            self.logger.warning(message)
            return self._result(tool_name, command, message, False)
        return None

    def _run(self, tool_name: str, command: str, timeout: int) -> dict[str, Any]:
        self.logger.info("Executing %s: %s", tool_name, command)
        try:
            completed = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
            return self._result(tool_name, command, output.strip(), completed.returncode == 0)
        except subprocess.TimeoutExpired:
            output = f"Command timed out after {timeout} seconds"
            self.logger.error(output)
            return self._result(tool_name, command, output, False)
        except Exception as exc:  # pragma: no cover
            output = f"Execution failed: {exc}"
            self.logger.exception(output)
            return self._result(tool_name, command, output, False)

    def available_tools(self) -> list[dict[str, Any]]:
        """Return availability and install package mapping for known tools."""
        tools: list[dict[str, Any]] = []
        for name, meta in sorted(self.tool_registry.items()):
            binary = str(meta["binary"])
            tools.append(
                {
                    "name": name,
                    "binary": binary,
                    "installed": shutil.which(binary) is not None,
                    "installer": str(meta["installer"]),
                }
            )
        return tools

    def install_tools(self, tools: list[str]) -> dict[str, Any]:
        """Install supported tooling via apt-get in Linux environments."""
        results: dict[str, Any] = {"installed": [], "failed": []}
        for tool in tools:
            entry = self.tool_registry.get(tool)
            if entry is None:
                results["failed"].append({"tool": tool, "reason": "Unknown tool"})
                continue
            if shutil.which(str(entry["binary"])) is not None:
                results["installed"].append({"tool": tool, "status": "already-installed"})
                continue

            package = str(entry["installer"])
            cmd = f"apt-get update && apt-get install -y {package}"
            try:
                subprocess.run(
                    ["bash", "-lc", cmd],
                    capture_output=True,
                    text=True,
                    timeout=900,
                    check=True,
                )
                results["installed"].append({"tool": tool, "status": "installed"})
            except Exception as exc:
                results["failed"].append({"tool": tool, "reason": str(exc)})
        return results

    def bootstrap_recommended_tools(self) -> dict[str, Any]:
        """Install the common lab toolset that the current registry knows about."""
        recommended = [name for name, meta in self.tool_registry.items() if meta.get("binary")]
        return self.install_tools(recommended)

    def execute_registered_tool(self, tool: str, target: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute known tool methods or fall back to a safe custom command path."""
        args = args or {}
        entry = self.tool_registry.get(tool)
        if entry is None:
            return self._result(tool, "", f"Unknown tool: {tool}", False)

        method = entry.get("method")
        if callable(method):
            payload = {"target": target}
            payload.update(args)
            return method(**payload)

        command = args.get("command") or f"{entry['binary']} {target}"
        return self.run_custom_command(str(command))

    def run_nmap(self, target: str, flags: str = "-sC -sV") -> dict[str, Any]:
        report_file = self.settings.REPORTS_DIR / f"nmap_{target.replace(':', '_')}_{int(dt.datetime.utcnow().timestamp())}.txt"
        command = f"nmap {flags} {target} -oN {report_file}"
        blocked = self._guard_scope(target, "nmap", command)
        if blocked:
            return blocked
        return self._run("nmap", command, timeout=120)

    def run_gobuster(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> dict[str, Any]:
        command = f"gobuster dir -u {target} -w {wordlist}"
        blocked = self._guard_scope(target, "gobuster", command)
        if blocked:
            return blocked
        return self._run("gobuster", command, timeout=120)

    def run_nikto(self, target: str) -> dict[str, Any]:
        command = f"nikto -h {target}"
        blocked = self._guard_scope(target, "nikto", command)
        if blocked:
            return blocked
        return self._run("nikto", command, timeout=180)

    def run_sqlmap(self, target: str, params: str = "", confirmed_vulnerable: bool = False) -> dict[str, Any]:
        command = f"sqlmap -u {target} {params}".strip()
        blocked = self._guard_scope(target, "sqlmap", command)
        if blocked:
            return blocked
        if not confirmed_vulnerable:
            return self._result("sqlmap", command, "Blocked: target not confirmed vulnerable for SQL injection.", False)
        return self._run("sqlmap", command, timeout=self.settings.TOOL_TIMEOUT)

    def run_whatweb(self, target: str) -> dict[str, Any]:
        command = f"whatweb {target}"
        blocked = self._guard_scope(target, "whatweb", command)
        if blocked:
            return blocked
        return self._run("whatweb", command, timeout=120)

    def run_enum4linux(self, target: str) -> dict[str, Any]:
        command = f"enum4linux -a {target}"
        blocked = self._guard_scope(target, "enum4linux", command)
        if blocked:
            return blocked
        return self._run("enum4linux", command, timeout=120)

    def run_custom_command(self, command: str) -> dict[str, Any]:
        lowered = command.lower()
        if any(token in lowered for token in self.blacklist) or self._unknown_wget_pattern.search(command):
            message = "Blocked command due to blacklist policy."
            self.logger.warning(message)
            return self._result("custom", command, message, False)

        host_match = re.search(r"(https?://[^\s]+|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b)", command)
        if not host_match:
            message = "Blocked command: unable to infer target for scope validation."
            self.logger.warning(message)
            return self._result("custom", command, message, False)

        inferred_target = host_match.group(1)
        blocked = self._guard_scope(inferred_target, "custom", command)
        if blocked:
            return blocked
        return self._run("custom", command, timeout=self.settings.TOOL_TIMEOUT)
