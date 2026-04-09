# 나노봇 전격 해설 Part 1: 진입점과 설정 파일 🚀

우리가 로봇을 만들려면 전원 스위치도 필요하고, 로봇의 성격을 입력할설정창도 필요하겠죠? Part 1에서는 **나노봇의 전원 스위치가 되는 파일들**과 **로봇의 설정(어떤 뇌를 쓸지, 권한은 어디까지 줄지)을 관리하는 파일들**을 하나도 빠짐없이 해설합니다! 

---

## 1. `nanobot/__init__.py` (나노봇 명함)
이 파일은 파이썬에게 "나노봇은 이런 패키지야!"라고 알려주는 명함 같은 파일입니다.

```python
"""
nanobot - A lightweight AI agent framework
"""
# 나노봇이 어떤 프로그램인지 적어둔 짧은 소개 글이에요. (가벼운 AI 에이전트 프레임워크)

__version__ = "0.1.4.post5"
# 현재 나노봇의 버전(나이)을 알려줍니다.

__logo__ = "🐈"
# 나노봇의 귀여운 로고(고양이 이모티콘) 설정이에요! 화면에 시작할 때 🐈 모양이 뜨게 해줍니다.
```

---

## 2. `nanobot/__main__.py` (나노봇 전원 스위치)
터미널(까만 창)에 `python -m nanobot`이라고 치면 가장 먼저 실행되는 '진짜 첫 번째' 파일입니다.

```python
"""
Entry point for running nanobot as a module: python -m nanobot
"""
# 이 파일은 나노봇을 실행시키는 출발점이라는 뜻의 메모장 역할이에요.

from nanobot.cli.commands import app
# 다른 폴더(cli.commands)에 만들어둔 봇을 조종하는 리모컨(`app`)을 가져와요.

if __name__ == "__main__":
    app()
# "이 파일이 가장 먼저 켜졌다면, 리모컨 기능을 실행해 줘!" 라는 뜻이에요. 전원 스위치 꾹!
```

---

## 3. `nanobot/config/__init__.py` (설정 정보 모음집)
다른 곳에서 나노봇 설정을 쉽게 가져다 쓰도록, 설정 관련 도구들을 예쁘게 하나의 쇼윈도우에 모아둔 파일이에요.

```python
"""Configuration module for nanobot."""
# 나노봇의 설정 관련 파일 모음집입니다!

from nanobot.config.loader import get_config_path, load_config
from nanobot.config.paths import ( 
    get_bridge_install_dir, get_cli_history_path, get_cron_dir, 
    get_data_dir, get_legacy_sessions_dir, is_default_workspace, 
    get_logs_dir, get_media_dir, get_runtime_subdir, get_workspace_path,
)
from nanobot.config.schema import Config
# paths.py와 schema.py 등에서 필요한 13개의 도구들을 쏙쏙 뽑아서 수입해옵니다.

__all__ = [
    "Config", "load_config", "get_config_path", ... 생략 ...
]
# "다른 파일에서 나노봇의 설정을 쓰려고 할 때는, 내가 모아둔 이 목록에 있는 것만 가져가렴!" 하고 메뉴판을 만들어 준 거예요.
```

---

## 4. `nanobot/config/paths.py` (폴더 위치 안내원)
내 컴퓨터(윈도우/맥)에 나노봇을 깔면, 각종 대화 기록이나 설정 파일이 저장되는 '경로(위치)'를 계산해 주는 안내원 파일입니다.

```python
"""Runtime path helpers derived from the active config context."""
from __future__ import annotations
from pathlib import Path
from nanobot.config.loader import get_config_path
from nanobot.utils.helpers import ensure_dir

# --- 아래 함수들은 전부 '비밀기지(폴더) 위치'를 알려주는 역할이에요 ---

def get_data_dir() -> Path:
    # 나노봇 설정 파일이 있는 가장 큰 상위 폴더 경로를 반환해요.
    # (+ ensure_dir 이라는 함수를 통해 폴더가 없으면 알아서 만들어줘요!)

def get_runtime_subdir(name: str) -> Path:
    # "로그 폴더 만들어 줘" 처럼 이름표를 주면, 방금 만든 최상위 폴더 안에 하위 폴더를 만들어 줘요.

def get_media_dir(channel: str | None = None) -> Path:
    # 사용자들이 보낸 이미지/영상을 저장할 폴더 위치 지정! 채널별(예: 텔레그램, 디스코드)로 방을 따로따로 파줍니다.

def get_cron_dir() -> Path:
    # 정해진 시간(알람)에 작동해야 하는 스케줄러 기록을 모아둘 폴더 위치!

def get_logs_dir() -> Path:
    # 에러가 났을 때 기록(로그)을 남길 장소 위치!

def get_workspace_path(workspace: str | None = None) -> Path:
    # 나노봇의 '놀이터(Workspace)' 경로. 보통 바탕화면에 깔거나 기본 경로인 '~/.nanobot/workspace'로 지정해 줘요.

def is_default_workspace(workspace: str | Path | None) -> bool:
    # 현재 나노봇의 놀이터가 기본 놀이터인지, 사용자가 따로 만든 놀이터인지 팩트 체크를 해줌!

def get_cli_history_path() -> Path:
    # 우리가 과거에 쳤던 터미널 방향키(↑) 기록들을 보관해두는 창고의 위치를 알려줘요.

def get_bridge_install_dir() -> Path:
    # 왓츠앱 같은 메신저와 연결할 때 필요한 추가 장비(브릿지)를 설치할 폴더 위치를 알려줘요!
```

---

## 5. `nanobot/config/schema.py` (로봇 입사지원서/스펙표)
나노봇을 구동할 때 어떤 스펙과 조건을 가질 것인지 모든 항목을 빈틈없이 규정하는 '입사지원서 규칙' 파일이에요. (총 263줄짜리 뼈대 구조)

```python
"""Configuration schema using Pydantic."""
# Pydantic이라는 외부 마법도구를 써서 설정 파일이 올바르게 씌어졌는지 자동 검사하는 파일!
from pydantic import BaseModel, ConfigDict, Field
# ... 기타 수입 재료들 ...

class Base(BaseModel):
    # 가장 기본이 되는 설정판! 여기서 설정 이름이 대문자/소문자로 오락가락해도 한 가지로 예쁘게 맞춰주는 룰을 정해요.

class ChannelsConfig(Base):
    # 나노봇과 어떤 메신저로 대화할지 채널 설정. 
    # 글씨를 칠 때 한글자씩 타자 치듯 보여줄지(send_progress), 생각 과정도 보여줄지 결정해 줘요.

class AgentDefaults(Base):
    # 나노봇의 기본 뇌 용량!
    # model: 어떤 AI (ex: "anthropic/claude-opus-4-5")를 쓸까?
    # max_tokens: 한 번에 최대로 뱉어내는 글자 수 (8192)
    # temperature: 얼마나 창의적으로(돌아이처럼) 말하게 할까? (0.1이면 아주 모범생)
    # max_tool_iterations: 최대 몇 번 스스로 혼잣말(검색 행동 반복)을 할 수 있게 할까? (기본 40번)

class ProviderConfig(Base):
    # AI 엔진 회사(OpenAI 등)들에 접속하기 위한 입장권(API 키)과 주소를 적는 칸.

class ProvidersConfig(Base):
    # 무려 20개가 넘는 전 세계 AI 엔진 회사들의 이름을 줄 세워둔 곳이야.
    # 챗GPT부터 Claude, DeepSeek, 구글 제미나이 등등!

class GatewayConfig(Base):
    # 나노봇이 서버 역할을 할 때 필요한 인터넷 주소와 포트를 정해요!

class WebToolsConfig(Base):
    # 인터넷 검색 도구를 사용할 때 IP 우회를 할지(proxy), 어떤 웹 검색엔진(Brave)을 쓸지 저장해 둬 

class ExecToolConfig(Base):
    # 나노봇이 네 컴퓨터에서 직접 cmd 명령어(파일 삭제/생성 등)를 치게 놔둘지 말지 권한을 주는 스위치야. (enable: bool)

class ToolsConfig(Base):
    # 위에 말한 실행 도구, 웹사이트 도구, 혹은 외부 특수 스킬(MCP 서버)들을 사용할지 말지 다 통제하는 장치.

class Config(BaseSettings):
    # 위에서 길게 적어둔 모든 상세 설정들을 하나로 딱 합쳐서 "이것이 바로 완전체 나노봇의 규칙이다!" 라고 만드는 최종 관리실장님이야!
    # 내부의 여러 _match_provider 같은 고급 함수는 사용자가 단순히 'GPT' 라고만 쳐도, 알아서 찰떡같이 OpenAI 열쇠를 꺼내오는 매칭 시스템 역할을 해줘.
```

---

## 6. `nanobot/config/loader.py` (설정지 읽어주는 아나운서)
`schema.py`가 설계도(규칙)라면, `loader.py`는 우리가 직접 쓴 `config.json` 파일을 가져와서 제대로 씌어졌는지 검토하고 나노봇에게 장착시켜 주는 역할이에요!

```python
"""Configuration loading utilities."""
import json
from pathlib import Path
import pydantic
from loguru import logger
from nanobot.config.schema import Config

_current_config_path: Path | None = None
# 나노봇이 어떤 경로의 설정 파일을 읽고 있는지 기억하는 전역 변수 공간!

def set_config_path(path: Path) -> None:
    # "오늘부터 이 파일(A)을 우리 설정 파일로 한다!" 라고 못 박는 함수야.

def get_config_path() -> Path:
    # "우리 설정 파일 위치가 어디였지?" 물어보면, 미리 찍어둔 위치를 반환하거나 없으면 기본 경로(`~/.nanobot/config.json`)를 반환해.

def load_config(config_path: Path | None = None) -> Config:
    # 가장 중요한 함수! 설정 파일(.json)을 직접 열어보고, 
    # "비밀번호(글로벌 설정) 다 잘 적혔나?"를 확인해서 Config 객체(로봇의 뇌)에 넣어줘.
    # 만약 오타가 있어서 로딩 실패하면? 뻗지 않고 알아서 '기본 공장 설정'으로 만들어 버려. (방어 기능)

def save_config(config: Config, config_path: Path | None = None) -> None:
    # 우리가 로봇에게 새 명령을 주거나 세팅을 바꿨을 때, 까먹지 않도록 다시 파일(.json)에 예쁘게 저장(세이브) 해주는 기능!

def _migrate_config(data: dict) -> dict:
    # 옛날 버전 나노봇 규칙으로 써둔 내용을 요즘 최신 버전 규칙으로 자동으로 바꿔주는(마이그레이션) 아주 친절한 일꾼 함수!
```

---
> 이상으로 나노봇의 기본 세팅과 출입문을 담당하는 **Part 1 핵심 파일**들을 하나도 빠짐없이 뜯어보았어요! 생각보다 어렵지 않죠? 로봇의 설명서, 안내데스크 창구라는 것만 기억하면 됩니다!
> 
> 다음은 나노봇이 실제로 생각하고 일을 처리하도록 반복하는 두뇌인 **Part 2: 핵심 뇌와 반복 루프 (agent/loop.py 등)** 으로 이어집니다!🔥
