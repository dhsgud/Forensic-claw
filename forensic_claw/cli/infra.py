"""HelixDB infrastructure helpers for installed Forensic-Claw builds."""

from __future__ import annotations

import subprocess
from importlib.resources import files
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console

infra_app = typer.Typer(help="Manage optional graph-vector storage infrastructure")
console = Console()
InfraBackend = Literal["helix"]


HELIX_TOML = """[project]
name = "forensic-claw-knowledge"
queries = "./db/"

[local.dev]
port = 6969
build_mode = "dev"
bm25 = true
mcp = false
"""


HELIX_README = """# Forensic-Claw HelixDB Backend

This directory is a HelixDB project for the Forensic-Claw knowledge store.

Requirements:
- Docker Desktop
- Helix CLI: curl -sSL https://install.helix-db.com | bash

Commands:

```powershell
helix check dev
helix push dev
helix status
helix logs dev --live
helix stop dev
```

Forensic-Claw should point to localhost port 6969 with knowledge.backend = "helix".
"""


def get_default_infra_dir() -> Path:
    """Return the user-scoped infra directory used by installed builds."""
    return Path.home() / ".forensic-claw" / "infra"


def ensure_infra_files(infra_dir: Path | None = None, *, force: bool = False) -> tuple[Path, Path]:
    """Write the default HelixDB project used by installed/native deployments."""
    return ensure_helix_files(infra_dir, force=force)


def ensure_backend_files(
    backend: InfraBackend = "helix",
    infra_dir: Path | None = None,
    *,
    force: bool = False,
) -> tuple[Path, Path]:
    """Write backend-specific infra files for installed/native deployments."""
    if backend != "helix":
        raise ValueError("Only the HelixDB backend is supported.")
    return ensure_helix_files(infra_dir, force=force)


def ensure_helix_files(infra_dir: Path | None = None, *, force: bool = False) -> tuple[Path, Path]:
    """Write the HelixDB project used by installed/native deployments."""
    target_dir = infra_dir or get_default_infra_dir()
    helix_dir = target_dir / "helix"
    db_dir = helix_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    toml_path = helix_dir / "helix.toml"
    query_path = db_dir / "forensic_claw.hx"
    readme_path = helix_dir / "README.md"

    if force or not toml_path.exists():
        toml_path.write_text(HELIX_TOML, encoding="utf-8")
    if force or not query_path.exists():
        query_path.write_text(_default_helix_queries(), encoding="utf-8")
    if force or not readme_path.exists():
        readme_path.write_text(HELIX_README, encoding="utf-8")

    return toml_path, readme_path


def _default_helix_queries() -> str:
    """Return the packaged HelixQL query contract."""
    return (
        files("forensic_claw.knowledge")
        .joinpath("helix_queries.hx")
        .read_text(encoding="utf-8")
    )


def _helix_project_dir(infra_dir: Path | None = None) -> Path:
    target_dir = infra_dir or get_default_infra_dir()
    return target_dir / "helix"


def run_helix(args: list[str], infra_dir: Path | None = None) -> int:
    """Run Helix CLI against the generated Helix project."""
    ensure_helix_files(infra_dir)
    project_dir = _helix_project_dir(infra_dir)
    try:
        result = subprocess.run(["helix", *args], cwd=project_dir, check=False)
    except FileNotFoundError:
        console.print("[red]Helix CLI was not found.[/red] Install it with:")
        console.print("[cyan]curl -sSL https://install.helix-db.com | bash[/cyan]")
        return 127
    return result.returncode


@infra_app.command("init")
def infra_init(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option(
        "helix",
        "--backend",
        help="helix",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite generated infra files"),
) -> None:
    """Create storage infrastructure files for installed/native deployments."""
    primary_path, readme_path = ensure_backend_files(backend, path, force=force)
    console.print(f"[green]Infra files ready[/green]: {primary_path}")
    console.print(f"[dim]Backend[/dim]: {backend}")
    console.print(f"[dim]README[/dim]: {readme_path}")


@infra_app.command("up")
def infra_up(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option(
        "helix",
        "--backend",
        help="helix",
    ),
) -> None:
    """Start the selected storage backend."""
    check_code = run_helix(["check", "dev"], path)
    if check_code != 0:
        raise typer.Exit(check_code)
    code = run_helix(["push", "dev"], path)
    raise typer.Exit(code)


@infra_app.command("down")
def infra_down(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option(
        "helix",
        "--backend",
        help="helix",
    ),
    delete_data: bool = typer.Option(False, "--delete-data", help="Also delete backend data"),
) -> None:
    """Stop storage infrastructure."""
    if delete_data:
        console.print("[yellow]Helix data deletion is not handled here. Use Helix backup/delete tools.[/yellow]")
    code = run_helix(["stop", "dev"], path)
    raise typer.Exit(code)


@infra_app.command("status")
def infra_status(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option(
        "helix",
        "--backend",
        help="helix",
    ),
) -> None:
    """Show status for the storage infrastructure."""
    code = run_helix(["status"], path)
    raise typer.Exit(code)


@infra_app.command("logs")
def infra_logs(
    path: Path | None = typer.Option(None, "--path", help="Infra directory"),
    backend: InfraBackend = typer.Option(
        "helix",
        "--backend",
        help="helix",
    ),
) -> None:
    """Stream logs for storage infrastructure."""
    code = run_helix(["logs", "dev", "--live"], path)
    raise typer.Exit(code)
