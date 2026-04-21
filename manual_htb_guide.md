# Manual HTB Guide

This guide is for authorized lab use only (HTB, THM, private labs you own).

## 1. Add HTB Machine To Scope

1. Start your VPN and confirm machine IP.
2. Add the target to scope:

```bash
python cli.py scope --add 10.10.10.100
python cli.py scope --list
```

## 2. Start Agent Against The Machine

```bash
python cli.py run --target 10.10.10.100 --task "Perform full authorized assessment"
```

For unattended mode:

```bash
python cli.py run --target 10.10.10.100 --task "Perform full authorized assessment" --no-interactive
```

## 3. What To Expect Step By Step

1. Scope validation check before any tool execution.
2. Recon phase with nmap.
3. Enumeration phase (whatweb, gobuster, enum4linux depending on findings).
4. Vulnerability analysis phase (nikto and supporting logic).
5. Optional exploitation suggestions from planner logic.
6. Report generation into reports directory.

## 4. Read Generated Reports

Report files are written to:

- /opt/neuralkali/reports/report_<target>_<timestamp>.md
- /opt/neuralkali/reports/report_<target>_<timestamp>.txt

Core sections:

1. Executive Summary
2. Methodology
3. Findings
4. Risk Ratings
5. Recommendations

## 5. Common Failure Modes

1. Ollama not reachable:
	- Run: python cli.py health
	- Verify OLLAMA_HOST and service availability.
2. Tool not installed in container:
	- Rebuild image: make build
3. Target blocked out of scope:
	- Add exact target string to config/scope.txt or with scope command.
4. No report generated:
	- Check logs in /var/log/neuralkali.log
	- Confirm reports directory is writable.
