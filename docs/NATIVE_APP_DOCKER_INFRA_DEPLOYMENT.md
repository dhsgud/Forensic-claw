# Native App + Docker Infra Deployment

이 문서는 Forensic-Claw 본체는 Windows 네이티브 실행 파일 또는 MSI로 배포하고,
Docker는 Neo4j 같은 저장소 인프라만 담당하게 하는 실사용 구조를 설명한다.

## 목표 구조

```text
Windows host
  ├─ Forensic-Claw.exe 또는 forensic-claw CLI
  │   ├─ Local WebUI
  │   ├─ Local LLM endpoint 연결
  │   ├─ Chrome History DB, 로그, 증거 파일 직접 조사
  │   └─ RAG 로컬 인덱스 저장
  │
  ├─ Local LLM
  │   ├─ LM Studio: http://127.0.0.1:1234/v1
  │   └─ Ollama:    http://127.0.0.1:11434/v1
  │
  └─ Docker Desktop
      └─ Neo4j: bolt://127.0.0.1:7687
```

핵심은 앱을 Docker 안에 넣지 않는 것이다. Forensic-Claw가 Windows 네이티브로 실행되면
사용자 프로필, Chrome DB, 로컬 로그, 증거 폴더를 별도 마운트 없이 직접 볼 수 있다.

## 기본 실행 순서

저장소를 받은 뒤 인프라만 Docker로 올린다.

```powershell
git clone -b dev https://github.com/dhsgud/Forensic-claw.git
cd Forensic-claw
docker compose up -d
```

설치형 배포에서는 repo를 clone하지 않아도 앱이 인프라 파일을 생성하고 실행할 수 있다.

```powershell
forensic-claw infra init
forensic-claw infra up
forensic-claw infra status
```

backend를 명시적으로 고를 수도 있다.

```powershell
forensic-claw infra init --backend docker
forensic-claw infra init --backend native
forensic-claw infra init --backend external
```

또는 제공 스크립트를 사용할 수 있다.

```powershell
.\scripts\infra-up.ps1
```

Neo4j Browser:

```text
http://127.0.0.1:7474
```

기본 접속값:

```text
Username: neo4j
Password: forensic1234
Database: neo4j
Bolt URI: bolt://127.0.0.1:7687
```

실제 사건 환경에서는 `.env.example`을 `.env`로 복사한 뒤 비밀번호를 바꾼다.

```powershell
Copy-Item .env.example .env
notepad .env
docker compose up -d
```

## Forensic-Claw 본체 실행

개발 환경에서는 다음처럼 실행한다.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
forensic-claw gateway
```

최종 배포에서는 이 부분이 Windows 설치형 실행으로 바뀐다.

```powershell
Forensic-Claw.exe gateway --open-browser
```

또는

```powershell
Forensic-Claw.msi 설치 후 Start Menu에서 Forensic-Claw WebUI 실행
```

WebUI는 기본적으로 다음 주소를 사용한다.

```text
http://127.0.0.1:8765/ui
```

## WebUI 초기 설정값

Forensic-Claw 본체가 Windows host에서 직접 실행되는 경우에는 `host.docker.internal`을 쓰지 않는다.
그 이름은 앱이 Docker 컨테이너 안에서 실행될 때 host를 가리키기 위한 주소다.

Local LLM 설정 예시:

```text
LM Studio API Base: http://127.0.0.1:1234/v1
Ollama API Base:    http://127.0.0.1:11434/v1
vLLM API Base:      http://127.0.0.1:8000/v1
```

Neo4j 설정:

```text
URI: bolt://127.0.0.1:7687
Username: neo4j
Password: forensic1234
Database: neo4j
```

## RAG 저장 위치

현재 구현 기준으로 RAG 텍스트 인덱스는 Forensic-Claw workspace 아래에 저장된다.

```text
%USERPROFILE%\.forensic-claw\workspace\knowledge
```

Neo4j는 Docker 볼륨에 그래프 데이터를 저장한다.

```text
forensic-claw-neo4j-data
forensic-claw-neo4j-logs
forensic-claw-neo4j-import
forensic-claw-neo4j-plugins
```

즉 현재 구조는 다음처럼 나뉜다.

```text
RAG 검색 인덱스: Windows 로컬 workspace
그래프 지식 저장소: Docker Neo4j
```

나중에 RAG 벡터 DB까지 Docker로 분리하려면 Qdrant, Chroma, Milvus 같은 별도 저장소를 추가하고
`KnowledgeConfig`에 vector backend 설정을 확장하면 된다. 지금 코드에는 Neo4j 연동이 먼저 들어가 있다.

## 증거 파일 조사 방식

본체가 네이티브로 실행되므로 수사관은 Docker 볼륨 마운트를 신경 쓰지 않아도 된다.
채팅에서 다음처럼 요청하면 된다.

```text
크롬 검색기록 조사해줘
이 폴더의 로그 파일 전처리해서 질문 가능하게 준비해줘: C:\Cases\case-001
```

Forensic-Claw는 필요한 경우 Chrome History DB나 대용량 로그를 찾아 RAG로 전처리하고,
Neo4j가 켜져 있으면 그래프 노드와 관계도 동기화한다.

## 종료와 삭제

인프라만 내릴 때:

```powershell
docker compose down
forensic-claw infra down
```

스크립트:

```powershell
.\scripts\infra-down.ps1
```

Neo4j 데이터까지 삭제할 때:

```powershell
docker compose down -v
forensic-claw infra down --delete-data
```

스크립트:

```powershell
.\scripts\infra-down.ps1 -DeleteData
```

## 예전 앱 컨테이너 방식

필요하면 앱까지 Docker로 띄울 수 있도록 기존 구성은 `docker-compose.app.yml`에 보존했다.

```powershell
docker compose -f docker-compose.app.yml up -d --build
```

하지만 실사용 권장 구조는 앱 컨테이너 방식이 아니라 네이티브 본체 + Docker 인프라 방식이다.
이 방식이 Windows 증거 접근, Local LLM 연결, Chrome DB 자동 탐지에 더 적합하다.
