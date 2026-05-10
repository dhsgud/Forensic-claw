from types import SimpleNamespace

from typer.testing import CliRunner

from forensic_claw.cli.commands import app
from forensic_claw.cli.infra import ensure_backend_files, ensure_infra_files, run_helix

runner = CliRunner()


def test_ensure_infra_files_writes_helix_project_when_directory_is_empty(tmp_path) -> None:
    toml_path, readme_path = ensure_infra_files(tmp_path)
    query_path = tmp_path / "helix" / "db" / "forensic_claw.hx"

    assert toml_path == tmp_path / "helix" / "helix.toml"
    assert readme_path == tmp_path / "helix" / "README.md"
    assert 'name = "forensic-claw-knowledge"' in toml_path.read_text(encoding="utf-8")
    assert "QUERY SearchEvidenceHybrid" in query_path.read_text(encoding="utf-8")


def test_infra_init_writes_helix_files_to_requested_path(tmp_path) -> None:
    result = runner.invoke(app, ["infra", "init", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / "helix" / "helix.toml").exists()
    assert (tmp_path / "helix" / "README.md").exists()


def test_ensure_backend_files_rejects_unknown_backend(tmp_path) -> None:
    try:
        ensure_backend_files("docker", tmp_path)  # type: ignore[arg-type]
    except ValueError as exc:
        assert "Only the HelixDB backend is supported." in str(exc)
    else:
        raise AssertionError("expected unknown backend to be rejected")


def test_run_helix_executes_helix_from_generated_project(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(command, *, cwd, check):
        calls.append({"command": command, "cwd": cwd, "check": check})
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("forensic_claw.cli.infra.subprocess.run", fake_run)

    result = run_helix(["status"], tmp_path)

    assert result == 0
    assert calls == [
        {
            "command": ["helix", "status"],
            "cwd": tmp_path / "helix",
            "check": False,
        }
    ]


def test_run_helix_returns_127_when_cli_is_missing(tmp_path, monkeypatch) -> None:
    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("forensic_claw.cli.infra.subprocess.run", fake_run)

    assert run_helix(["status"], tmp_path) == 127


def test_infra_up_can_start_helix_backend(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(command, *, cwd, check):
        calls.append({"command": command, "cwd": cwd, "check": check})
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("forensic_claw.cli.infra.subprocess.run", fake_run)

    result = runner.invoke(app, ["infra", "up", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert calls == [
        {
            "command": ["helix", "check", "dev"],
            "cwd": tmp_path / "helix",
            "check": False,
        },
        {
            "command": ["helix", "push", "dev"],
            "cwd": tmp_path / "helix",
            "check": False,
        },
    ]
