# NeuralKali Agent

NeuralKali is a local-first AI-assisted security testing orchestrator designed for authorized labs (HTB, THM, and private environments). It combines a planning loop, tool execution layer, memory, and reporting pipeline.

## Intelligence Upgrades

- Extensible tool registry with install/list support from CLI.
- Web-informed methodology context (OWASP Top 10 baseline cache).
- Dynamic planning that can add focused steps based on findings.
- Interactive operator console mode for live task steering.

## Safety Model

- Scope-based hard enforcement before all tool execution.
- Explicit blacklist for dangerous shell commands in custom execution path.
- Intended only for legal, authorized testing.

## Quick Start In 5 Commands

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python cli.py scope --add 127.0.0.1
python cli.py run --target 127.0.0.1 --task "Perform authorized recon" --no-interactive
```

## Machine Bootstrap Flow

```bash
python cli.py setup --target 10.10.10.100 --model mistral --install-tools --auto
python cli.py run --target 10.10.10.100 --task "Perform authorized assessment" --no-interactive
```

If you are using Docker, run the agent container and Ollama service first, then use the setup command from inside the container or from the host with the Ollama endpoint reachable.

## Interactive Interface

```bash
python cli.py console
```

## Tool Management

```bash
python cli.py tools --list
python cli.py tools --install nmap zap burpsuite
```

## Target Safety Precheck

Use passive target classification before execution:

```bash
python cli.py precheck --target 10.10.10.100
python cli.py precheck --target example.org
```

By default, likely live public organizational websites are blocked. Internal/lab targets proceed when also present in scope.

## HTB/THM Usage

1. Add machine IP to scope.
2. Verify environment health.
3. Run the agent in interactive or non-interactive mode.
4. Review report files in reports output directory.

```bash
python cli.py scope --add 10.10.10.100
python cli.py health
python cli.py run --target 10.10.10.100 --task "Perform full authorized assessment"
```

## Architecture Diagram

```text
					 +---------------------+
					 |      cli.py         |
					 +----------+----------+
									|
									v
					 +----------+----------+
					 |   NeuralKaliAgent   |
					 +--+--------+------+--+
						 |        |      |
						 v        v      v
				 +-----+--+ +---+--+ +--+------+
				 |Planner | |Tools | |Memory   |
				 +--+-----+ +---+--+ +----+----+
					 |           |          |
					 v           v          v
				 +--------------------------------+
				 |           Reporter             |
				 +--------------------------------+
```

## Project Layout

- agent/: core orchestration and subsystems
- config/: settings and scope
- docker/: container runtime
- reports/: generated outputs
- tasks/: daemon task queue
- tests/: simulation tests

## Development

```bash
make build
make run
make test
```

## Contributing Guidelines

1. Keep all tool execution paths scope-gated.
2. Avoid hardcoded paths and use config/settings.py values.
3. Add tests for new planner or execution logic.
4. Keep logs structured and readable.
5. Open pull requests with clear threat model notes for changes.
