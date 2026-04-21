"""CLI entrypoint for NeuralKali."""

from __future__ import annotations

import argparse
from pathlib import Path

import ollama
from rich.console import Console
from rich.table import Table

from agent.agent import NeuralKaliAgent
from config.settings import Settings, validate_environment


BANNER = r"""
 _   _                      _ _  __    _ _
| \ | | ___ _   _ _ __ __ _| | |/ /_ _| (_)
|  \| |/ _ \ | | | '__/ _` | | ' / _` | | |
| |\  |  __/ |_| | | | (_| | | . \ (_| | | |
|_| \_|\___|\__,_|_|  \__,_|_|_|\_\__,_|_|_|
"""


def _load_scope(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def _add_scope(path: Path, target: str) -> None:
    entries = set(_load_scope(path))
    entries.add(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(entries)) + "\n", encoding="utf-8")


def main() -> int:
    settings = Settings()
    console = Console()
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    parser = argparse.ArgumentParser(prog="neuralkali", description="NeuralKali pentest orchestration CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run agent for one target")
    run_p.add_argument("--target", required=True)
    run_p.add_argument("--task", required=True)
    run_p.add_argument("--no-interactive", action="store_true")

    sub.add_parser("daemon", help="Run daemon mode")

    scope_p = sub.add_parser("scope", help="Manage scope")
    scope_group = scope_p.add_mutually_exclusive_group(required=True)
    scope_group.add_argument("--add")
    scope_group.add_argument("--list", action="store_true")
    scope_group.add_argument("--clear", action="store_true")

    sub.add_parser("health", help="Run environment checks")

    report_p = sub.add_parser("report", help="Regenerate report from memory")
    report_p.add_argument("--target", required=True)

    models_p = sub.add_parser("models", help="Manage Ollama models")
    models_group = models_p.add_mutually_exclusive_group(required=True)
    models_group.add_argument("--pull")
    models_group.add_argument("--list", action="store_true")

    args = parser.parse_args()
    agent = NeuralKaliAgent(settings=settings)

    if args.command == "run":
        result = agent.run(args.target, args.task, interactive=not args.no_interactive)
        console.print(result)
        return 0 if result.get("success") else 1

    if args.command == "daemon":
        agent.daemon()
        return 0

    if args.command == "scope":
        if args.add:
            _add_scope(settings.SCOPE_FILE, args.add)
            console.print(f"[green]Added to scope:[/green] {args.add}")
            return 0
        if args.list:
            table = Table(title="Scope Entries")
            table.add_column("Target", style="cyan")
            for item in _load_scope(settings.SCOPE_FILE):
                table.add_row(item)
            console.print(table)
            return 0
        if args.clear:
            confirm = console.input("Clear scope file? type YES to continue: ")
            if confirm == "YES":
                settings.SCOPE_FILE.write_text("", encoding="utf-8")
                console.print("[yellow]Scope cleared.[/yellow]")
            else:
                console.print("[blue]Cancelled.[/blue]")
            return 0

    if args.command == "health":
        health = validate_environment(settings)
        table = Table(title="NeuralKali Health")
        table.add_column("Component")
        table.add_column("Status")
        for key, value in health.items():
            table.add_row(key, str(value))
        console.print(table)
        return 0 if health.get("healthy") else 1

    if args.command == "report":
        findings = agent.memory.get_full_history(args.target)
        session = agent.memory.load_session(args.target) or {"status": "restored"}
        paths = agent.reporter.generate_report(args.target, findings, session)
        console.print(paths)
        return 0

    if args.command == "models":
        client = ollama.Client(host=settings.OLLAMA_HOST)
        if args.pull:
            client.pull(args.pull)
            console.print(f"[green]Pulled model[/green] {args.pull}")
            return 0
        if args.list:
            models = client.list()
            table = Table(title="Local Models")
            table.add_column("Name")
            for model in models.get("models", []):
                table.add_row(model.get("name", "unknown"))
            console.print(table)
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
