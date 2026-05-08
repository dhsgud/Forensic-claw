"""Docker-backed infrastructure helpers for native Forensic-Claw installs."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console

infra_app = typer.Typer(help="Manage optional storage infrastructure")
console = Console()
InfraBackend = Literal["docker", "native", "external"]


INFRA_COMPOSE_YAML = """name: forensic-claw-infra

services:
  neo4j:
    image: neo4j:5-community
    container_name: forensic-claw-neo4j
    restart: unless-stopped
    environment:
      FORENSIC_CLAW_NEO4J_PASSWORD: ${FORENSIC_CLAW_NEO4J_PASSWORD:-forensic1234}
      NEO4J_AUTH: neo4j/${FORENSIC_CLAW_NEO4J_PASSWORD:-forensic1234}
      NEO4J_server_memory_heap_initial__size: ${FORENSIC_CLAW_NEO4J_HEAP_INITIAL:-512m}
      NEO4J_server_memory_heap_max__size: ${FORENSIC_CLAW_NEO4J_HEAP_MAX:-1G}
    ports:
      - "127.0.0.1:7474:7474"
      - "127.0.0.1:7687:7687"
    volumes:
      - forensic-claw-neo4j-data:/data
      - forensic-claw-neo4j-logs:/logs
      - forensic-claw-neo4j-import:/import
      - forensic-claw-neo4j-plugins:/plugins
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "cypher-shell -u neo4j -p \\"$${FORENSIC_CLAW_NEO4J_PASSWORD}\\" 'RETURN 1' >/dev/null 2>&1 || exit 1",
        ]
      interval: 10s
      timeout: 10s
      retries: 12
      start_period: 30s

volumes:
  forensic-claw-neo4j-data:
  forensic-claw-neo4j-logs:
  forensic-claw-neo4j-import:
  forensic-claw-neo4j-plugins:
"""


INFRA_ENV_EXAMPLE = """# Copy this file to .env and change the password before real evidence work.
FORENSIC_CLAW_NEO4J_PASSWORD=change-this-password
FORENSIC_CLAW_NEO4J_HEAP_INITIAL=512m
FORENSIC_CLAW_NEO4J_HEAP_MAX=1G
"""


NATIVE_NEO4J_ENV_EXAMPLE = """# Native Neo4j backend.
# Install Neo4j and a compatible JDK on Windows, then copy this file to .env.native.
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=change-this-password
NEO4J_DATABASE=neo4j
NEO4J_HOME=C:\\Tools\\neo4j
JAVA_HOME=C:\\Tools\\jdk
"""


EXTERNAL_NEO4J_ENV_EXAMPLE = """# External Neo4j backend.
# Use this when the database is hosted on an analysis server.
NEO4J_URI=bolt://your-analysis-server:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=change-this-password
NEO4J_DATABASE=neo4j
"""


def get_default_infra_dir() -> Path:
    """Return the user-scoped infra directory used by installed builds."""
    return Path.home() / ".forensic-claw" / "infra"


def ensure_infra_files(infra_dir: Path | None = None, *, force: bool = False) -> tuple[Path, Path]:
    """Write the Docker Compose and .env example files used by infra commands."""
    target_dir = infra_dir or get_default_infra_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    compose_path = target_dir / "docker-compose.yml"
    env_example_path = target_dir / ".env.example"

    if force or not compose_path.exists():
        compose_path.write_text(INFRA_COMPOSE_YAML, encoding="utf-8")
    if force or not env_example_path.exists():
        env_example_path.write_text(INFRA_ENV_EXAMPLE, encoding="utf-8")

    return compose_path, env_example_path


def ensure_backend_files(
    backend: InfraBackend = "docker",
    infra_dir: Path | None = None,
    *,
    force: bool = False,
) -> tuple[Path, Path]:
    """Write backend-specific infra files for installed/native deployments."""
    if backend == "docker":
        return ensure_infra_files(infra_dir, force=force)

    target_dir = infra_dir or get_default_infra_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    if backend == "native":
        path = target_dir / ".env.native.example"
        if force or not path.exists():
            path.write_text(NATIVE_NEO4J_ENV_EXAMPLE, encoding="utf-8")
        return path, path

    path = target_dir / ".env.external.example"
    if force or not path.exists():
        path.write_text(EXTERNAL_NEO4J_ENV_EXAMPLE, encoding="utf-8")
    return path, path


def _compose_command(compose_path: Path, args: list[str]) -> list[str]:
    return ["docker", "compose", "-f", str(compose_path), *args]


def run_compose(args: list[str], infra_dir: Path | None = None) -> int:
    """Run docker compose against the generated infra compose file."""
    compose_path, _ = ensure_infra_files(infra_dir)
    try:
        result = subprocess.run(
            _compose_command(compose_path, args),
            cwd=compose_path.parent,
            check=False,
        )
    except FileNotFoundError:
        console.print("[red]Docker CLI was not found.[/red] Install Docker Desktop first.")
        return 127
    return result.returncode


@infra_app.command("init")
def infra_init(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option("docker", "--backend", help="docker, native, or external"),
    force: bool = typer.Option(False, "--force", help="Overwrite generated infra files"),
) -> None:
    """Create storage infrastructure files for installed/native deployments."""
    primary_path, env_example_path = ensure_backend_files(backend, path, force=force)
    console.print(f"[green]Infra files ready[/green]: {primary_path}")
    console.print(f"[dim]Backend[/dim]: {backend}")
    console.print(f"[dim]Env example[/dim]: {env_example_path}")


@infra_app.command("up")
def infra_up(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option("docker", "--backend", help="docker, native, or external"),
) -> None:
    """Start or describe the selected Neo4j storage backend."""
    if backend == "native":
        ensure_backend_files("native", path)
        console.print(
            "[yellow]Native backend selected.[/yellow] Start the installed Neo4j service or "
            "Neo4j console, then use bolt://127.0.0.1:7687 in WebUI."
        )
        raise typer.Exit(0)
    if backend == "external":
        ensure_backend_files("external", path)
        console.print(
            "[yellow]External backend selected.[/yellow] No local database is started. "
            "Configure the remote Neo4j URI in WebUI."
        )
        raise typer.Exit(0)
    code = run_compose(["up", "-d"], path)
    raise typer.Exit(code)


@infra_app.command("down")
def infra_down(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option("docker", "--backend", help="docker, native, or external"),
    delete_data: bool = typer.Option(False, "--delete-data", help="Also delete Docker volumes"),
) -> None:
    """Stop Neo4j storage infrastructure."""
    if backend != "docker":
        console.print(f"[yellow]{backend} backend is not managed by Docker Compose.[/yellow]")
        raise typer.Exit(0)
    args = ["down", "-v"] if delete_data else ["down"]
    code = run_compose(args, path)
    raise typer.Exit(code)


@infra_app.command("status")
def infra_status(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option("docker", "--backend", help="docker, native, or external"),
) -> None:
    """Show Docker Compose status for the storage infrastructure."""
    if backend != "docker":
        console.print(f"[yellow]{backend} backend status is checked through WebUI connection test.[/yellow]")
        raise typer.Exit(0)
    code = run_compose(["ps"], path)
    raise typer.Exit(code)
