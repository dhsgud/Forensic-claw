# Windows Native Packaging

Forensic-Claw의 실무 배포 기본값은 Windows 네이티브 본체와 선택형 저장소 인프라다.

```text
Forensic-Claw.exe 또는 MSI
  ├─ Local WebUI
  ├─ Windows 증거 파일 직접 접근
  ├─ Local LLM 연결
  └─ Neo4j/RAG backend 선택
```

Docker는 앱을 실행하는 용도가 아니라 Neo4j 같은 저장소를 쉽게 띄우는 선택지로 둔다.

## 배포 산출물

권장 릴리스 산출물은 두 가지다.

```text
dist/windows/Forensic-Claw/Forensic-Claw.exe
dist/installer/Forensic-Claw-<version>.msi
```

EXE 폴더는 압축 배포나 현장 USB 실행용으로 쓸 수 있고, MSI는 조직 배포와 반복 설치에 적합하다.

## EXE 빌드

처음 한 번은 빌드 의존성을 설치한다.

```powershell
.\scripts\build-windows-exe.ps1 -InstallDeps -Clean
```

PowerShell 실행 정책이 막힌 빌드 PC에서는 다음처럼 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows-exe.ps1 -InstallDeps -Clean
```

그 다음부터는 다음 명령으로 충분하다.

```powershell
.\scripts\build-windows-exe.ps1
```

산출물:

```text
dist/windows/Forensic-Claw/Forensic-Claw.exe
```

실행:

```powershell
.\dist\windows\Forensic-Claw\Forensic-Claw.exe gateway --open-browser
```

## MSI 빌드

MSI는 WiX Toolset CLI가 필요하다. 빌드 머신에 `wix` 명령이 잡혀 있어야 한다.

```powershell
.\scripts\build-windows-msi.ps1 -InstallPythonBuildDeps
```

실행 정책이 막혀 있으면:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows-msi.ps1 -InstallPythonBuildDeps
```

이미 EXE 산출물이 있으면 MSI만 다시 만들 수 있다.

```powershell
.\scripts\build-windows-msi.ps1 -SkipExeBuild
```

MSI 설치 후 Start Menu에는 두 개의 바로가기가 생긴다.

```text
Forensic-Claw WebUI
Forensic-Claw Infra Manager
```

`Forensic-Claw WebUI`는 다음 명령과 같은 역할을 한다.

```powershell
Forensic-Claw.exe gateway --open-browser
```

## 인프라 선택

설치 후 저장소 backend는 세 가지 중 하나를 고른다.

```powershell
Forensic-Claw.exe infra init --backend docker
Forensic-Claw.exe infra init --backend native
Forensic-Claw.exe infra init --backend external
```

Docker backend:

```powershell
Forensic-Claw.exe infra up --backend docker
```

WebUI Neo4j 설정:

```text
URI: bolt://127.0.0.1:7687
Username: neo4j
Password: forensic1234
Database: neo4j
```

Native backend는 조사 PC에 Neo4j를 직접 설치하거나 portable로 둔 뒤 WebUI에
`bolt://127.0.0.1:7687`을 입력하는 방식이다.

External backend는 분석실 서버나 중앙 Neo4j를 사용하는 방식이다.

```text
URI: bolt://analysis-server:7687
```

## 권장 릴리스 프로파일

현장 USB/소규모 배포:

```text
EXE folder zip + docker backend optional
```

기관 내부 표준 배포:

```text
MSI + Docker backend optional + Native Neo4j fallback
```

분석실 중앙 서버 운영:

```text
MSI + external backend
```

## 주의사항

Docker Desktop이 막힌 PC에서도 Forensic-Claw 본체는 계속 쓸 수 있어야 한다.
그래서 Docker는 필수 의존성이 아니라 선택형 저장소 backend로만 둔다.

Local LLM이 Windows host에서 실행되면 Forensic-Claw도 Windows native로 실행되므로
API 주소는 보통 `http://127.0.0.1:<port>/v1`을 사용한다. 앱이 Docker 안에서 실행될 때만
`host.docker.internal`을 사용한다.
