"""Simulation test for HTB-like workflow using DVWA in Docker."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from agent.agent import NeuralKaliAgent
from config.settings import Settings


@pytest.mark.integration
def test_htb_simulation(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is not available")

    container_name = "neuralkali-dvwa-test"
    subprocess.run(["docker", "rm", "-f", container_name], check=False, capture_output=True)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-p",
            "8081:80",
            "vulnerables/web-dvwa",
        ],
        check=True,
    )

    try:
        time.sleep(5)
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("127.0.0.1\n", encoding="utf-8")

        settings = Settings(
            SCOPE_FILE=scope_file,
            REPORTS_DIR=tmp_path / "reports",
            MEMORY_DIR=tmp_path / "memory",
            TASKS_DIR=tmp_path / "tasks",
            OLLAMA_HOST="http://localhost:11434",
            AI_MODEL="mistral",
            MAX_STEPS=5,
        )
        agent = NeuralKaliAgent(settings=settings)

        result = agent.run(
            target="127.0.0.1",
            task="Perform full penetration test, find all vulnerabilities, attempt to gain access",
            interactive=False,
        )

        findings = result.get("findings", [])
        tool_names = {f.get("tool_name") for f in findings}

        checks = {
            "ran_nmap": "nmap" in tool_names,
            "ran_web_enumeration": bool({"gobuster", "whatweb"} & tool_names),
            "attempted_vuln_scan": "nikto" in tool_names,
            "generated_report": bool(result.get("report_paths")),
        }

        for name, passed in checks.items():
            print(f"{name}: {'PASS' if passed else 'FAIL'}")

        assert all(checks.values())
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], check=False, capture_output=True)
