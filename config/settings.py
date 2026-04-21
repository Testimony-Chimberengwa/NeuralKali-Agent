"""Application settings, logging, and environment checks."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover - compatibility path
    from pydantic import BaseSettings  # type: ignore

    SettingsConfigDict = dict  # type: ignore


load_dotenv()


class Settings(BaseSettings):
    """Runtime configuration loaded from env vars and .env files."""

    OLLAMA_HOST: str = "http://localhost:11434"
    AI_MODEL: str = "mistral"
    MAX_STEPS: int = 20
    TOOL_TIMEOUT: int = 300
    REPORTS_DIR: Path = Path("/opt/neuralkali/reports")
    MEMORY_DIR: Path = Path("/opt/neuralkali/memory")
    TASKS_DIR: Path = Path("/opt/neuralkali/tasks")
    SCOPE_FILE: Path = Path("/opt/neuralkali/config/scope.txt")
    LOG_FILE: Path = Path("/var/log/neuralkali.log")
    INTERACTIVE_MODE: bool = True
    AUTO_EXPLOIT: bool = False
    TOOLKIT_AUTO_INSTALL: bool = False
    ENABLE_WEB_KNOWLEDGE: bool = True
    ALLOW_PUBLIC_TARGETS: bool = False
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


def setup_logging(settings: Settings) -> logging.Logger:
    """Configure file and console logging for the project."""
    logger = logging.getLogger("neuralkali")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    if logger.handlers:
        return logger

    settings.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(settings.LOG_FILE)
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def validate_environment(settings: Settings) -> dict[str, Any]:
    """Run health checks for dependencies, tools, and paths."""
    health: dict[str, Any] = {
        "ollama_reachable": False,
        "tools": {},
        "scope_file": False,
        "reports_dir": False,
        "memory_dir": False,
        "tasks_dir": False,
    }

    for path_key, path in (
        ("reports_dir", settings.REPORTS_DIR),
        ("memory_dir", settings.MEMORY_DIR),
        ("tasks_dir", settings.TASKS_DIR),
    ):
        try:
            path.mkdir(parents=True, exist_ok=True)
            health[path_key] = True
        except OSError:
            health[path_key] = False

    try:
        if settings.SCOPE_FILE.exists() and settings.SCOPE_FILE.read_text(encoding="utf-8").strip():
            health["scope_file"] = True
    except OSError:
        health["scope_file"] = False

    tools = ["nmap", "gobuster", "nikto", "sqlmap", "whatweb", "enum4linux", "curl"]
    for tool in tools:
        health["tools"][tool] = shutil.which(tool) is not None

    try:
        response = requests.get(f"{settings.OLLAMA_HOST}/api/tags", timeout=5)
        health["ollama_reachable"] = response.ok
        if response.ok:
            payload = response.json()
            health["models"] = [m.get("name", "") for m in payload.get("models", [])]
        else:
            health["models"] = []
    except requests.RequestException:
        health["ollama_reachable"] = False
        health["models"] = []

    health["healthy"] = bool(
        health["ollama_reachable"]
        and health["scope_file"]
        and health["reports_dir"]
        and health["memory_dir"]
        and health["tasks_dir"]
        and all(health["tools"].values())
    )
    return health
