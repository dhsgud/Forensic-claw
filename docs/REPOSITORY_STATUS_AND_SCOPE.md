# Repository Status and Scope

## 해결 체크리스트

- [x] README에서 존재하지 않는 `docs/WINDOWS_NATIVE_PACKAGING.md` 링크 제거
- [x] README에서 존재하지 않는 `docs/MASTER_DEVELOPMENT_SPEC.md` 기준 문서 링크 제거
- [x] README에서 존재하지 않는 과거 계획 문서 링크 제거
- [x] README의 저장소 상태 링크가 실제 문서를 가리키도록 복구
- [x] `skill-creator` 생성 템플릿의 `TODO` marker를 `REPLACE` marker로 변경
- [x] abstract/base hook의 `pass`와 `NotImplementedError`는 의도된 확장 지점으로 분류
- [x] 64-bit Python 3.12 환경에 editable dev dependency 설치 확인
- [x] 전체 테스트와 lint 실행 확인

## 현재 범위

이 저장소는 로컬 LLM 기반 에이전트 프레임워크이자 Native Windows 지향 포렌식 워크벤치 기반입니다. 현재 런타임 패키지는 `forensic_claw/` 아래에 있으며 주요 영역은 `agent/`, `cli/`, `channels/`, `providers/`, `forensics/`, `knowledge/`, `security/`, `session/`, `cron/`, `utils/`입니다.

WebUI 정적 자산은 `forensic_claw/webui/static/`에 있고, 패키지 템플릿과 기본 skill은 `forensic_claw/templates/`, `forensic_claw/skills/`에 있습니다. 테스트는 `tests/` 아래 패키지 구조를 따릅니다.

## 검증 기준

권장 검증 명령:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests -q
ruff check forensic_claw tests
```

현재 로컬에서 확인된 제한:

- 32-bit Python(`Python312-32`)은 `sqlite-vec` Windows wheel이 없어 editable install에 실패합니다.
- 64-bit Python은 `py -3.12`로 실행합니다.
- `uv sync --all-extras`는 `uv`가 설치된 환경에서만 사용할 수 있습니다.

이번 확인 결과:

```text
py -3.12 -m pytest tests -q
531 passed

py -3.12 -m ruff check forensic_claw tests
All checks passed!
```

## 운영 주의사항

- `~/.forensic-claw/` 아래 machine-local 설정과 secret은 커밋하지 않습니다.
- 채널 설정의 `allowFrom`은 좁게 유지합니다.
- 로컬 서비스는 가능한 `127.0.0.1` loopback binding을 사용합니다.
- 명령 실행, 네트워크 접근, credential 처리 변경은 PR 설명에 별도 표시합니다.
