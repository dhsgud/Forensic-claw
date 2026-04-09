# Forensic-Claw

<div align="center">
  <img src="forensic_claw_logo.png" alt="Forensic-Claw Logo" width="400">
</div>

로컬 LLM 기반의 경량 에이전트 프레임워크입니다. 현재 이 저장소는 `Discord`와 `KakaoTalk` 채널, 그리고 `vLLM` 또는 `Custom OpenAI-compatible endpoint (llama.cpp 등)`만 지원하도록 정리되어 있습니다.

## 현재 지원 범위

### 채널

- `discord`
- `kakaotalk`

### 프로바이더

- `vllm`
- `custom`

### 유지되는 핵심 엔진

- agent loop
- context/session/memory
- tools
- bus
- cron
- heartbeat

## 설치

Python 3.11+ 환경에서 설치합니다.

```bash
pip install -e .
```

또는 일반 설치:

```bash
pip install .
```

## 빠른 시작

### 1. 초기 설정 파일 생성

```bash
nanobot onboard
```

또는 대화형 설정:

```bash
nanobot onboard --wizard
```

### 2. 기본 설정

설정 파일 경로:

```text
~/.nanobot/config.json
```

기본 설정 예시:

```json
{
  "agents": {
    "defaults": {
      "workspace": "~/.nanobot/workspace",
      "model": "qwen1.5-35b-4bit",
      "provider": "vllm",
      "maxTokens": 8192,
      "contextWindowTokens": 65536,
      "temperature": 0.1
    }
  },
  "providers": {
    "vllm": {
      "apiBase": "http://localhost:8000/v1",
      "apiKey": ""
    },
    "custom": {
      "apiBase": "http://127.0.0.1:8080/v1",
      "apiKey": "",
      "extraHeaders": {}
    }
  }
}
```

### 3. CLI에서 바로 실행

```bash
nanobot agent
```

### 4. 채널 게이트웨이 실행

```bash
nanobot gateway
```

## 프로바이더 설정

## vLLM

로컬 또는 원격 vLLM OpenAI-compatible 서버를 사용할 때 설정합니다.

```json
{
  "agents": {
    "defaults": {
      "provider": "vllm",
      "model": "qwen1.5-35b-4bit"
    }
  },
  "providers": {
    "vllm": {
      "apiBase": "http://localhost:8000/v1",
      "apiKey": ""
    }
  }
}
```

메모:

- `apiBase`를 비우면 기본값 `http://localhost:8000/v1`을 사용합니다.
- 로컬 서버가 API 키를 요구하지 않으면 `apiKey`는 빈 문자열이어도 됩니다.

## Custom

`llama.cpp`, LM Studio, 기타 OpenAI-compatible 서버를 직접 연결할 때 사용합니다.

```json
{
  "agents": {
    "defaults": {
      "provider": "custom",
      "model": "llama.cpp/local"
    }
  },
  "providers": {
    "custom": {
      "apiBase": "http://127.0.0.1:8080/v1",
      "apiKey": "",
      "extraHeaders": {
        "x-session-affinity": "sticky-session"
      }
    }
  }
}
```

메모:

- `model`은 그대로 upstream 서버로 전달됩니다.
- 필요하면 `extraHeaders`에 커스텀 헤더를 넣을 수 있습니다.

## Discord 채널 설정

### 준비 사항

1. Discord Developer Portal에서 봇 생성
2. Bot Token 발급
3. `MESSAGE CONTENT INTENT` 활성화
4. 본인 User ID 확인

### 설정 예시

```json
{
  "channels": {
    "discord": {
      "enabled": true,
      "token": "YOUR_BOT_TOKEN",
      "allowFrom": ["YOUR_USER_ID"],
      "groupPolicy": "mention"
    }
  }
}
```

### 동작 방식

- DM은 `allowFrom` 허용 사용자에 대해 응답
- 서버 채널은 기본적으로 `@mention`일 때만 응답
- 긴 메시지는 Discord 제한에 맞춰 자동 분할
- 첨부 파일 다운로드/전송 지원

## KakaoTalk 채널 설정

이 저장소의 카카오톡 채널은 `카카오 i 오픈빌더 스킬 서버(webhook) + callback API` 방식으로 구현되어 있습니다.

### 준비 사항

1. 카카오 i 오픈빌더에서 스킬 서버 URL 등록
2. callback 기능 사용 가능한 환경 준비
3. 외부에서 접근 가능한 webhook URL 준비

### 설정 예시

```json
{
  "channels": {
    "kakaotalk": {
      "enabled": true,
      "host": "0.0.0.0",
      "port": 3000,
      "skillPath": "/skill",
      "healthPath": "/health",
      "allowFrom": ["*"],
      "pairingCode": "CHANGE_ME",
      "adminKakaoId": "",
      "callbackTimeout": 55,
      "pendingText": "분석 중입니다. 잠시만 기다려 주세요."
    }
  }
}
```

### 동작 방식

- `POST /skill`로 카카오 요청 수신
- 즉시 `useCallback: true` 응답 반환
- 실제 모델 응답은 `callbackUrl`로 전송
- `/pair [코드] [이름]` 명령으로 사용자 연결 가능
- 페어링 정보는 런타임 디렉터리의 `kakaotalk/pairs.json`에 저장
- 일반 텍스트는 `simpleText` 기준으로 자동 분할
- JSON 문자열을 `basicCard` 또는 `outputs` 템플릿으로 응답 가능

### 헬스체크

```text
GET /health
```

응답 예시:

```json
{
  "ok": true,
  "channel": "kakaotalk"
}
```

## 최소 설정 예시

### Discord + vLLM

```json
{
  "agents": {
    "defaults": {
      "model": "qwen1.5-35b-4bit",
      "provider": "vllm"
    }
  },
  "providers": {
    "vllm": {
      "apiBase": "http://localhost:8000/v1"
    }
  },
  "channels": {
    "discord": {
      "enabled": true,
      "token": "YOUR_BOT_TOKEN",
      "allowFrom": ["YOUR_USER_ID"],
      "groupPolicy": "mention"
    }
  }
}
```

### KakaoTalk + llama.cpp

```json
{
  "agents": {
    "defaults": {
      "model": "llama.cpp/local",
      "provider": "custom"
    }
  },
  "providers": {
    "custom": {
      "apiBase": "http://127.0.0.1:8080/v1"
    }
  },
  "channels": {
    "kakaotalk": {
      "enabled": true,
      "host": "0.0.0.0",
      "port": 3000,
      "allowFrom": ["*"],
      "pairingCode": "CHANGE_ME"
    }
  }
}
```

## CLI 명령어

```bash
nanobot --help
nanobot onboard
nanobot gateway
nanobot agent
nanobot status
nanobot channels status
nanobot channels login discord
nanobot channels login kakaotalk
```

메모:

- `provider login`은 현재 로컬 전용 빌드에서는 사용하지 않습니다.

## 테스트

전체 테스트 실행:

```bash
python -m pytest tests -q
```

현재 정리 작업 이후 기준 결과:

```text
387 passed
```

## 프로젝트 구조

```text
nanobot/
├── agent/
├── bus/
├── channels/
│   ├── base.py
│   ├── discord.py
│   ├── kakaotalk.py
│   ├── manager.py
│   └── registry.py
├── cli/
├── config/
├── providers/
│   ├── base.py
│   ├── openai_compat_provider.py
│   ├── registry.py
│   └── __init__.py
├── session/
├── memory/
├── cron/
└── heartbeat/
```

## 이번 정리에서 제거된 범위

아래 항목은 이 저장소에서 제거되었습니다.

- Telegram
- Slack
- WhatsApp
- Feishu
- DingTalk
- Weixin
- QQ
- Email
- Matrix
- Mochat
- WeCom
- Anthropic provider
- Azure OpenAI provider
- OpenAI Codex provider
- transcription provider
- WhatsApp bridge
- case GIF 자산
- clawhub/weather/tmux/github 스킬

상세 내역은 [CHANGE_REPORT_2026-04-07.md](./CHANGE_REPORT_2026-04-07.md)를 참고하세요.

## 주의사항

1. 예전 문서나 외부 글에 있는 다채널/다프로바이더 설명은 현재 저장소 상태와 다를 수 있습니다.
2. 이 저장소는 현재 `Discord + KakaoTalk`, `vLLM + Custom` 기준으로 맞춰져 있습니다.
3. 카카오톡 연동은 webhook/callback 인프라가 있어야 정상 운영 가능합니다.
