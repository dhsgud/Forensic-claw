from types import SimpleNamespace

from typer.testing import CliRunner

from forensic_claw.cli.commands import app
from forensic_claw.cli.infra import ensure_backend_files, ensure_infra_files, run_compose

runner = CliRunner()


def test_ensure_infra_files_writes_neo4j_compose_when_directory_is_empty(tmp_path) -> None:
    compose_path, env_example_path = ensure_infra_files(tmp_path)

    compose = compose_path.read_text(encoding="utf-8")
    env_example = env_example_path.read_text(encoding="utf-8")

    assert "neo4j:" in compose
    assert "forensic-claw-gateway" not in compose
    assert '"127.0.0.1:7474:7474"' in compose
    assert '"127.0.0.1:7687:7687"' in compose
    assert "FORENSIC_CLAW_NEO4J_PASSWORD=change-this-password" in env_example


def test_infra_init_writes_files_to_requested_path(tmp_path) -> None:
    result = runner.invoke(app, ["infra", "init", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / "docker-compose.yml").exists()
    assert (tmp_path / ".env.example").exists()


def test_infra_init_can_prepare_native_backend_without_docker_compose(tmp_path) -> None:
    result = runner.invoke(app, ["infra", "init", "--backend", "native", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / ".env.native.example").exists()
    assert not (tmp_path / "docker-compose.yml").exists()


def test_ensure_backend_files_writes_external_connection_example(tmp_path) -> None:
    path, _ = ensure_backend_files("external", tmp_path)

    assert path.name == ".env.external.example"
    assert "NEO4J_URI=bolt://your-analysis-server:7687" in path.read_text(encoding="utf-8")


def test_run_compose_executes_docker_compose_from_infra_directory(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(command, *, cwd, check):
        calls.append({"command": command, "cwd": cwd, "check": check})
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("forensic_claw.cli.infra.subprocess.run", fake_run)

    result = run_compose(["ps"], tmp_path)

    assert result == 0
    assert calls == [
        {
            "command": ["docker", "compose", "-f", str(tmp_path / "docker-compose.yml"), "ps"],
            "cwd": tmp_path,
            "check": False,
        }
    ]


def test_run_compose_returns_127_when_docker_cli_is_missing(tmp_path, monkeypatch) -> None:
    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("forensic_claw.cli.infra.subprocess.run", fake_run)

    assert run_compose(["ps"], tmp_path) == 127
