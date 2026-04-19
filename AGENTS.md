# Repository Guidelines

## Project Structure & Module Organization
`forensic_claw/` contains the runtime package. Main areas are `agent/`, `cli/`, `channels/`, and `providers/`, with shared services in `config/`, `session/`, `security/`, `cron/`, and `utils/`. WebUI assets live in `forensic_claw/webui/static/`; packaged templates and skills live in `forensic_claw/templates/` and `forensic_claw/skills/`. Tests mirror the package layout under `tests/`, and longer design notes live in `docs/`.

## Build, Test, and Development Commands
- `uv sync --all-extras`: install the same dependency set used in CI.
- `python -m pip install -e ".[dev]"`: editable local install without `uv`.
- `python -m forensic_claw --help`: verify the CLI entry point.
- `python -m forensic_claw onboard`: create the local config and workspace.
- `python -m pytest tests -q`: run the full test suite.
- `ruff check forensic_claw tests`: lint and sort imports.
- `ruff format forensic_claw tests`: apply formatting.
- `bash tests/test_docker.sh`: run the Docker smoke path when Docker is available.

## Coding Style & Naming Conventions
Target Python 3.11+ with 4-space indentation. Keep type hints on public functions and classes, and add docstrings only when they clarify behavior. Ruff is the formatter and linter; `pyproject.toml` sets line length to `100` and enables rules `E`, `F`, `I`, `N`, and `W`. Use `snake_case` for modules, functions, and tests, `PascalCase` for classes, and keep config identifiers aligned with names such as `vllm`, `custom`, `discord`, and `kakaotalk`.

## Testing Guidelines
Pytest uses `asyncio_mode = "auto"` and `tests/` as the only test root. Add tests in the matching area, for example `tests/channels/` for channel changes or `tests/tools/` for tool behavior. Name files `test_*.py` and prefer behavior-focused names such as `test_default_hosts_bind_to_loopback`. Cover error paths and security-sensitive logic, especially shell, filesystem, and access-control code.

## Testing Rules
Rules for any agent (`Claude Code`, `Codex`, `Cursor`) writing or modifying tests in this repo. This file lives at the project root, so agents should treat the rules below as default policy.

### Core Philosophy
1. Test behavior, not implementation. Pure refactors must not break tests.
2. Mock only at the system boundary. Everything inside is real.
3. Prefer Classist (Chicago) TDD. Mockist (London) tests rot fast in AI-driven codebases.
4. Fewer meaningful tests beat many leaky ones.

### Mocking Rules
Mock these, and only these:
- Database / ORM
- Third-party HTTP APIs
- Filesystem, clock, randomness, network
- Anything crossing a process boundary

Never mock these:
- Value objects, DTOs, entities you own
- Pure functions and utilities
- Internal collaborators in the same codebase
- The unit under test

Prefer an HTTP-level fake over an interface mock, and prefer a real temp filesystem over a mocked filesystem.

### Assertion Rules
- Assert on return values and observable state.
- Do not make `toHaveBeenCalledWith(...)`, `verify(...)`, or spy assertions the primary verification.
- Compare whole objects when practical, for example `expect(result).toEqual(expected)`.
- Never snapshot non-deterministic output such as LLM text, timestamps, or ordering-free sets.

### Naming Rules
Test names must state observable behavior, not method names or internal calls.

```text
Bad
test_findUnique_called_once()
test_calls_upsert_then_emits_event()
should_work()

Good
returns_cached_result_when_fetched_within_ttl()
rejects_login_when_password_is_expired()
charges_full_price_for_non_vip_users()
```

Template: `<subject>_<expected_behavior>_when_<condition>`

### Structure Rules
| Layer | Purpose | Budget |
|---|---|---|
| Unit | Pure logic, entities, utils | Many, in-memory, milliseconds |
| Integration | Module plus real DB or queue | Moderate, per critical module |
| E2E | Critical user journeys | Few, one per journey |
| Regression | One per past incident | As bugs happen |

- Keep one E2E per critical journey and a small set of integration tests per domain.
- Write unit tests only where logic is non-trivial. Do not unit test getters, DI wiring, or framework glue.
- In this repository, keep tests under `tests/` in the matching domain folder such as `tests/agent/` or `tests/tools/`.
- Gate expensive live tests behind an environment flag such as `LIVE_TEST=true` or `RUN_EXPENSIVE=1`.

### Domain Entity Rules
Extract a domain entity when any of these are true:
- Business logic is scattered across two or more services on the same data.
- A service does arithmetic or state transitions on a plain DB row.
- You need a DB just to test logic that is actually pure.

```python
# Before: logic in the service, tied to persistence
user.hunger = user.hunger - EAT * 2
user.energy = user.energy + SLEEP * 2
user_repo.save(user)

# After: logic in the entity, service only persists
user.eat()
user.sleep()
user_repo.save(user)
```

Then `User.eat()` becomes a fast in-memory unit test with no mocks.

### Property-Based Testing
For anything with a clear invariant over a large input space, such as parsers, encoders, sorters, validators, or state machines, add property-based tests alongside example tests. In this Python repository, prefer `hypothesis`.

Rule: if you are writing the fourth example test for the same function, switch to a property.

### Flaky Test Rules
1. Never commit a flaky test. If one lands, quarantine it within 24 hours.
2. Quarantine means skip it with a linked issue, owner, and deadline. No owner means delete it.
3. Fix flakiness at the root, never with retry loops, `sleep()`, or larger timeouts.
4. Common roots are shared global state, real clock usage, test ordering, unseeded randomness, and live network calls.

### Migration Rules
Do not rewrite existing tests for sport. Apply these rules incrementally:
1. New tests from today onward should follow these rules fully.
2. In touched files, convert mocks so they exist only at the boundary.
3. Tackle the worst offenders first, especially files dominated by call-verification assertions.
4. Introduce a real database or containerized integration setup for one high-risk domain first, then expand only after the pattern proves itself.
5. Delete snapshot tests on non-deterministic output and replace them with structural assertions when the behavior matters.

### Workflow Rules
- Write the failing test from the spec first, then implement against it.
- Do not generate code first and ask an agent to write tests afterward.
- Keep one behavior per test. Multiple assertions are fine when they describe one behavior; split the test when they describe several.

### PR Red Flags
- More mock setup than real assertions
- `toHaveBeenCalledWith(...)` or `verify(...)` as the only assertion
- Imports reaching into private module paths
- Snapshots of LLM, timestamp, or network output
- `it.skip` or `skip` without a linked issue and owner
- Tests renamed every time the implementation name changes
- A test file longer than the file it tests when the target exposes one public function
- New full-repo mocking layers instead of a boundary mock or real integration path

### When Not to Write a Test
- Plain CRUD with no logic: one E2E is enough.
- Framework wiring such as DI, routing, or module registration
- Config or constants already protected by types or schema validation
- Throwaway scripts, unless they touch production data
- Code you are about to delete

If you cannot state the behavior the test protects in one sentence, do not write it.

### One Line to Remember
> Hide the implementation from the test. Hide the test from the implementation. Only behavior connects them.

## Commit & Pull Request Guidelines
Recent commits use short, imperative summaries; both English and Korean appear in history, so keep the subject concise and consistent with the surrounding work. Per `CONTRIBUTING.md`, target `main` for low-risk fixes and docs, and `nightly` for features or refactors. PRs should describe the user-visible change, note config or security impact, link related issues, and include screenshots or terminal snippets for WebUI or CLI changes. Confirm the lint/test commands you ran in the PR body.

## Security & Configuration Tips
Never commit secrets or machine-local data from `~/.forensic-claw/`. Keep `allowFrom` restrictive for channel configs, prefer loopback bindings (`127.0.0.1`) for local services, and call out any change that affects command execution, network access, or credential handling.
