"""Local browser-based Web UI channel."""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
import webbrowser
from collections import defaultdict
from pathlib import Path
from typing import Any

from aiohttp import WSMsgType, web
from loguru import logger
from pydantic import Field

from forensic_claw.bus.events import OutboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.base import BaseChannel
from forensic_claw.command import get_builtin_command_specs
from forensic_claw.config.schema import Base
from forensic_claw.session.manager import Session, SessionManager
from forensic_claw.session.scopes import build_scoped_session_key, parse_scoped_session_key
from forensic_claw.utils.helpers import current_time_str, extract_message_thinking_text, safe_filename


class WebUIConfig(Base):
    """Configuration for the local web UI channel."""

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8765
    allow_from: list[str] = Field(default_factory=lambda: ["*"])
    streaming: bool = True
    open_browser: bool = False
    session_cookie_name: str = "forensic_claw_webui_session"
    title: str = "Forensic-Claw Local Workbench"


class WebUIChannel(BaseChannel):
    """Serve a browser UI and route messages through the normal channel bus."""

    name = "webui"
    display_name = "WebUI"
    _MAX_SHELL_TRACES = 200

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return WebUIConfig().model_dump(by_alias=True)

    def __init__(self, config: Any, bus: MessageBus):
        if isinstance(config, dict):
            config = WebUIConfig.model_validate(config)
        super().__init__(config, bus)
        self.config: WebUIConfig = config
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._stop_event = asyncio.Event()
        self._sockets: dict[str, set[web.WebSocketResponse]] = defaultdict(set)
        self._shell_traces: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._session_manager: SessionManager | None = None
        self._app: web.Application | None = None

    def bind_runtime(self, *, session_manager: SessionManager | None = None) -> None:
        """Inject runtime services that channels do not own directly."""
        self._session_manager = session_manager

    def create_app(self) -> web.Application:
        """Create the aiohttp application used by the channel."""
        if self._app is not None:
            return self._app

        app = web.Application(client_max_size=4 * 1024 * 1024)
        app.router.add_get("/", self._handle_root)
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/ui", self._handle_ui)
        app.router.add_get("/ui/assets/{asset}", self._handle_asset)
        app.router.add_get("/ws", self._handle_ws)
        app.router.add_get("/api/bootstrap", self._handle_bootstrap)
        app.router.add_post("/api/chat", self._handle_chat)
        app.router.add_post("/api/stop", self._handle_stop)
        app.router.add_get("/api/cases", self._handle_cases_list)
        app.router.add_get("/api/cases/{case_id}", self._handle_case_detail)
        app.router.add_get("/api/cases/{case_id}/report", self._handle_case_report)
        app.router.add_get("/api/cases/{case_id}/graph", self._handle_case_graph)
        app.router.add_get("/api/cases/{case_id}/evidence/{evidence_id}", self._handle_evidence_detail)
        app.router.add_get("/api/cases/{case_id}/sources/{source_id}", self._handle_source_detail)
        app.router.add_get("/api/wiki", self._handle_wiki_list)
        app.router.add_get("/api/wiki/{note_id}", self._handle_wiki_detail)
        app.router.add_get("/api/sessions", self._handle_sessions_list)
        app.router.add_get(r"/api/sessions/{session_key:.+}", self._handle_session_detail)
        self._app = app
        return app

    async def start(self) -> None:
        """Start the local HTTP/WebSocket server and keep it alive."""
        if self._runner is not None:
            return

        app = self.create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=self.config.host, port=self.config.port)
        self._stop_event.clear()
        self._running = True

        await self._site.start()
        ui_url = self._ui_url
        logger.info("WebUI channel listening on {}", ui_url)

        if self.config.open_browser:
            try:
                webbrowser.open_new_tab(ui_url)
            except Exception:
                logger.exception("Failed to open browser for {}", ui_url)

        try:
            await self._stop_event.wait()
        finally:
            self._running = False

    async def stop(self) -> None:
        """Stop the HTTP server and close connected websockets."""
        self._running = False
        self._stop_event.set()

        sockets = [ws for group in self._sockets.values() for ws in group]
        for ws in sockets:
            try:
                await ws.close()
            except Exception:
                pass
        self._sockets.clear()

        if self._site is not None:
            await self._site.stop()
            self._site = None
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def send(self, msg: OutboundMessage) -> None:
        """Push a final message or progress event to connected browsers."""
        metadata = dict(msg.metadata or {})
        event = self._event_base(msg.chat_id, metadata)
        event["content"] = msg.content
        event["media"] = list(msg.media or [])

        if metadata.get("_shell_trace"):
            event["type"] = "shell_trace"
            event["trace"] = (
                metadata.get("shell_trace")
                if isinstance(metadata.get("shell_trace"), dict)
                else {"summary": str(metadata.get("shell_trace") or "")}
            )
            self._remember_shell_trace(msg.chat_id, event)
        elif metadata.get("_progress"):
            event["type"] = "tool_hint" if metadata.get("_tool_hint") else "progress"
        else:
            event["type"] = "message"
            event["role"] = "assistant"
            if metadata.get("render_as"):
                event["renderAs"] = metadata["render_as"]
            if metadata.get("_replace_stream_id"):
                event["replaceStreamId"] = metadata["_replace_stream_id"]
            if metadata.get("thinking_text"):
                event["thinkingText"] = metadata["thinking_text"]
            if metadata.get("thinking_blocks"):
                event["thinkingBlocks"] = metadata["thinking_blocks"]
            if metadata.get("webui_reset_browser_session"):
                event["resetBrowserSession"] = True

        await self._emit_to_chat(msg.chat_id, event)

    async def send_delta(
        self,
        chat_id: str,
        delta: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Push a streaming delta or stream-end marker to connected browsers."""
        metadata = dict(metadata or {})
        event = self._event_base(chat_id, metadata)
        event["streamId"] = metadata.get("_stream_id") or ""

        if metadata.get("_stream_end"):
            event["type"] = "stream_end"
            event["content"] = ""
            event["resuming"] = bool(metadata.get("_resuming"))
        else:
            event["type"] = "stream_delta"
            event["content"] = delta

        await self._emit_to_chat(chat_id, event)

    @property
    def _ui_url(self) -> str:
        return f"http://{self.config.host}:{self.config.port}/ui"

    @staticmethod
    def _new_browser_session_id() -> str:
        return f"sess_{uuid.uuid4().hex[:12]}"

    @property
    def _static_root(self) -> Path:
        return Path(__file__).resolve().parent.parent / "webui" / "static"

    @property
    def _workspace_root(self) -> Path | None:
        return self._session_manager.workspace if self._session_manager else None

    @property
    def _wiki_root(self) -> Path | None:
        workspace = self._workspace_root
        return workspace / "wiki" if workspace else None

    @property
    def _cases_root(self) -> Path | None:
        workspace = self._workspace_root
        return workspace / "forensics" / "cases" if workspace else None

    def _event_base(self, chat_id: str, metadata: dict[str, Any]) -> dict[str, Any]:
        case_id = metadata.get("case_id") or metadata.get("caseId")
        artifact_id = metadata.get("artifact_id") or metadata.get("artifactId")
        return {
            "sessionId": chat_id,
            "sessionKey": build_scoped_session_key(
                self.name,
                chat_id,
                case_id=case_id,
                artifact_id=artifact_id,
            ),
            "timestamp": current_time_str(),
        }

    def _remember_shell_trace(self, chat_id: str, event: dict[str, Any]) -> None:
        """Keep a short in-memory history of shell trace events per browser session."""
        trace_event = {
            "type": "shell_trace",
            "sessionId": event.get("sessionId"),
            "sessionKey": event.get("sessionKey"),
            "timestamp": event.get("timestamp"),
            "trace": dict(event.get("trace") or {}),
        }
        bucket = self._shell_traces[chat_id]
        bucket.append(trace_event)
        if len(bucket) > self._MAX_SHELL_TRACES:
            del bucket[:-self._MAX_SHELL_TRACES]

    async def _drop_browser_state(self, session_id: str | None) -> None:
        """Forget in-memory browser state after a hard reset."""
        if not session_id:
            return

        self._shell_traces.pop(session_id, None)

        sockets = list(self._sockets.pop(session_id, set()))
        for ws in sockets:
            try:
                await ws.close()
            except Exception:
                pass

    async def _emit_to_chat(self, chat_id: str, event: dict[str, Any]) -> None:
        dead: list[web.WebSocketResponse] = []
        for ws in list(self._sockets.get(chat_id, set())):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)

        if dead:
            for ws in dead:
                self._sockets.get(chat_id, set()).discard(ws)
            if not self._sockets.get(chat_id):
                self._sockets.pop(chat_id, None)

    def _browser_session_from_request(self, request: web.Request, *, create: bool) -> str | None:
        session_id = (
            request.query.get("sessionId")
            or request.headers.get("X-Session-ID")
            or request.cookies.get(self.config.session_cookie_name)
        )
        if session_id:
            return session_id
        if create:
            return self._new_browser_session_id()
        return None

    @staticmethod
    def _is_truthy(value: str | None) -> bool:
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    def _json_response(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        status: int = 200,
    ) -> web.Response:
        response = web.json_response(payload, status=status)
        if session_id:
            response.set_cookie(
                self.config.session_cookie_name,
                session_id,
                path="/",
                samesite="Lax",
            )
        return response

    def _asset_path(self, name: str) -> Path | None:
        root = self._static_root.resolve()
        candidate = (root / name).resolve()
        if candidate.parent != root or not candidate.is_file():
            return None
        return candidate

    @staticmethod
    def _resolve_child(root: Path, relative: str) -> Path | None:
        try:
            candidate = (root / Path(relative)).resolve(strict=False)
            candidate.relative_to(root.resolve(strict=False))
        except Exception:
            return None
        return candidate

    @staticmethod
    def _load_json_file(path: Path) -> Any | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    @staticmethod
    def _directory_names(path: Path) -> list[str]:
        if not path.exists() or not path.is_dir():
            return []
        return sorted(item.name for item in path.iterdir() if item.is_dir())

    @staticmethod
    def _file_listing(path: Path) -> list[str]:
        if not path.exists() or not path.is_dir():
            return []
        return sorted(
            candidate.relative_to(path).as_posix()
            for candidate in path.rglob("*")
            if candidate.is_file()
        )

    def _case_dir(self, case_id: str) -> Path | None:
        root = self._cases_root
        if root is None:
            return None
        candidate = self._resolve_child(root, case_id)
        if candidate is None or not candidate.is_dir():
            return None
        return candidate

    def _case_manifest(self, case_dir: Path) -> dict[str, Any]:
        manifest = self._load_json_file(case_dir / "manifest.json")
        return manifest if isinstance(manifest, dict) else {}

    def _case_summary(self, case_dir: Path) -> dict[str, Any]:
        manifest = self._case_manifest(case_dir)
        evidence_ids = self._directory_names(case_dir / "evidence")
        source_ids = self._directory_names(case_dir / "sources")
        return {
            "id": case_dir.name,
            "title": manifest.get("title") or case_dir.name,
            "status": manifest.get("status"),
            "summary": manifest.get("summary"),
            "tags": manifest.get("tags") or [],
            "createdAt": manifest.get("createdAt"),
            "updatedAt": manifest.get("updatedAt"),
            "hasReport": (case_dir / "report.md").is_file(),
            "hasGraph": (case_dir / "graph.json").is_file(),
            "evidenceCount": len(evidence_ids),
            "sourceCount": len(source_ids),
        }

    @staticmethod
    def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
        if not text.startswith("---"):
            return {}, text

        lines = text.splitlines()
        if not lines or lines[0].strip() != "---":
            return {}, text

        end_idx = None
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                end_idx = idx
                break
        if end_idx is None:
            return {}, text

        metadata: dict[str, Any] = {}
        for line in lines[1:end_idx]:
            if ":" not in line:
                continue
            key, raw_value = line.split(":", 1)
            value = raw_value.strip()
            if not key.strip():
                continue
            if not value:
                metadata[key.strip()] = ""
                continue
            try:
                metadata[key.strip()] = json.loads(value)
            except Exception:
                metadata[key.strip()] = value.strip("\"'")

        body = "\n".join(lines[end_idx + 1 :])
        return metadata, body

    @staticmethod
    def _markdown_summary(text: str, *, max_len: int = 160) -> str:
        lines: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lines.append(stripped)
            if len(" ".join(lines)) >= max_len:
                break

        summary = " ".join(lines).strip()
        if len(summary) > max_len:
            summary = summary[: max_len - 3].rstrip() + "..."
        return summary or "(empty)"

    @staticmethod
    def _encode_note_id(relative_path: str) -> str:
        raw = relative_path.encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_note_id(note_id: str) -> str | None:
        if not note_id:
            return None
        padding = "=" * (-len(note_id) % 4)
        try:
            return base64.urlsafe_b64decode(note_id + padding).decode("utf-8")
        except Exception:
            return None

    def _wiki_dir_for_scope(
        self,
        *,
        browser_session_id: str,
        case_id: str | None = None,
        artifact_id: str | None = None,
    ) -> Path | None:
        root = self._wiki_root
        if root is None:
            return None

        session_key = build_scoped_session_key(
            self.name,
            browser_session_id,
            case_id=case_id,
            artifact_id=artifact_id,
        )
        scope = parse_scoped_session_key(session_key)

        if scope.case_id:
            wiki_dir = root / "cases" / safe_filename(scope.case_id)
            if scope.artifact_id:
                wiki_dir = wiki_dir / "artifacts" / safe_filename(scope.artifact_id)
            return wiki_dir
        if scope.artifact_id:
            return root / "artifacts" / safe_filename(scope.artifact_id)
        return root / "sessions" / safe_filename(scope.base_key.replace(":", "_"))

    def _wiki_note_summary(self, path: Path, *, wiki_root: Path) -> dict[str, Any]:
        text = path.read_text(encoding="utf-8")
        metadata, body = self._parse_frontmatter(text)
        relative_path = path.relative_to(wiki_root).as_posix()
        return {
            "id": self._encode_note_id(relative_path),
            "relativePath": relative_path,
            "title": metadata.get("title") or path.stem,
            "createdAt": metadata.get("created_at"),
            "caseId": metadata.get("case_id"),
            "artifactId": metadata.get("artifact_id"),
            "summary": self._markdown_summary(body),
        }

    def _list_wiki_notes(
        self,
        *,
        browser_session_id: str,
        case_id: str | None = None,
        artifact_id: str | None = None,
    ) -> list[dict[str, Any]]:
        root = self._wiki_root
        wiki_dir = self._wiki_dir_for_scope(
            browser_session_id=browser_session_id,
            case_id=case_id,
            artifact_id=artifact_id,
        )
        if root is None or wiki_dir is None or not wiki_dir.is_dir():
            return []

        notes = [self._wiki_note_summary(path, wiki_root=root) for path in wiki_dir.glob("*.md")]
        return sorted(notes, key=lambda row: row.get("createdAt", ""), reverse=True)

    def _wiki_note_path(self, note_id: str) -> Path | None:
        root = self._wiki_root
        relative_path = self._decode_note_id(note_id)
        if root is None or relative_path is None:
            return None
        candidate = self._resolve_child(root, relative_path)
        if candidate is None or not candidate.is_file() or candidate.suffix.lower() != ".md":
            return None
        return candidate

    def _serialize_message_content(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "text":
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            parts.append(text)
                    elif item.get("type") == "image_url":
                        parts.append("[image]")
                    else:
                        parts.append(json.dumps(item, ensure_ascii=False))
                else:
                    parts.append(str(item))
            return "\n".join(part for part in parts if part)
        if content is None:
            return ""
        return json.dumps(content, ensure_ascii=False)

    def _session_preview(self, session: Session) -> str:
        fallback = ""
        for message in reversed(session.messages):
            content = self._serialize_message_content(message.get("content"))
            if content:
                if message.get("role") != "tool":
                    return content[:120]
                if not fallback:
                    fallback = f"[tool] {content[:112]}"
        return fallback

    def _session_summary(self, session: Session) -> dict[str, Any]:
        scope = parse_scoped_session_key(session.key)
        return {
            "key": session.key,
            "baseKey": scope.base_key,
            "caseId": scope.case_id,
            "artifactId": scope.artifact_id,
            "updatedAt": session.updated_at.isoformat(),
            "createdAt": session.created_at.isoformat(),
            "messageCount": len(session.messages),
            "preview": self._session_preview(session),
        }

    def _sessions_for_browser(self, browser_session_id: str) -> list[dict[str, Any]]:
        if not self._session_manager:
            return []
        prefix = f"{self.name}:{browser_session_id}"
        items: list[dict[str, Any]] = []
        for item in self._session_manager.list_sessions():
            key = item.get("key") or ""
            if not key.startswith(prefix):
                continue
            session = self._session_manager.get_or_create(key)
            items.append(self._session_summary(session))
        return sorted(items, key=lambda row: row.get("updatedAt", ""), reverse=True)

    def _find_browser_session(self, browser_session_id: str, session_key: str) -> Session | None:
        if not self._session_manager:
            return None
        prefix = f"{self.name}:{browser_session_id}"
        if not session_key.startswith(prefix):
            return None
        for item in self._session_manager.list_sessions():
            if item.get("key") == session_key:
                return self._session_manager.get_or_create(session_key)
        return None

    async def _handle_root(self, _request: web.Request) -> web.Response:
        raise web.HTTPFound("/ui")

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "channel": self.name})

    async def _handle_ui(self, request: web.Request) -> web.Response:
        session_id = self._browser_session_from_request(request, create=True)
        index_path = self._static_root / "index.html"
        response = web.FileResponse(index_path)
        if session_id:
            response.set_cookie(
                self.config.session_cookie_name,
                session_id,
                path="/",
                samesite="Lax",
            )
        return response

    async def _handle_asset(self, request: web.Request) -> web.Response:
        asset_name = request.match_info["asset"]
        path = self._asset_path(asset_name)
        if path is None:
            raise web.HTTPNotFound(text="asset not found")
        return web.FileResponse(path)

    async def _handle_bootstrap(self, request: web.Request) -> web.Response:
        reset_requested = self._is_truthy(request.query.get("reset"))
        previous_session_id = self._browser_session_from_request(request, create=False)
        if reset_requested:
            await self._drop_browser_state(previous_session_id)
            session_id = self._new_browser_session_id()
        else:
            session_id = previous_session_id or self._new_browser_session_id()
        cases_root = self._cases_root
        wiki_root = self._wiki_root
        has_cases = bool(cases_root and cases_root.is_dir() and any(cases_root.iterdir()))
        has_wiki = bool(wiki_root and wiki_root.is_dir() and any(wiki_root.iterdir()))
        return self._json_response(
            {
                "appName": "Forensic-Claw",
                "channel": self.name,
                "title": self.config.title,
                "sessionId": session_id,
                "scopes": {"caseId": None, "artifactId": None},
                "features": {"streaming": self.supports_streaming},
                "commands": [
                    {
                        "command": item.command,
                        "description": item.description,
                        "kind": item.kind,
                    }
                    for item in get_builtin_command_specs()
                ],
                "workspace": {
                    "hasSessions": bool(self._sessions_for_browser(session_id or "")) if session_id else False,
                    "hasCases": has_cases,
                    "hasWiki": has_wiki,
                },
                "shellTraces": list(self._shell_traces.get(session_id or "", [])) if session_id else [],
            },
            session_id=session_id,
        )

    async def _handle_chat(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return self._json_response({"ok": False, "error": "invalid_json"}, status=400)

        session_id = body.get("sessionId") or self._browser_session_from_request(request, create=True)
        text = str(body.get("text") or "").strip()
        case_id = body.get("caseId") or body.get("case_id")
        artifact_id = body.get("artifactId") or body.get("artifact_id")

        if not session_id:
            return self._json_response({"ok": False, "error": "missing_session"}, status=400)
        if not text:
            return self._json_response({"ok": False, "error": "empty_text"}, session_id=session_id, status=400)

        metadata = {
            "_wants_stream": self.supports_streaming,
            **({"case_id": case_id} if case_id else {}),
            **({"artifact_id": artifact_id} if artifact_id else {}),
        }

        await self._handle_message(
            sender_id=session_id,
            chat_id=session_id,
            content=text,
            metadata=metadata,
        )

        return self._json_response(
            {
                "ok": True,
                "sessionId": session_id,
                "sessionKey": build_scoped_session_key(
                    self.name,
                    session_id,
                    case_id=case_id,
                    artifact_id=artifact_id,
                ),
            },
            session_id=session_id,
        )

    async def _handle_stop(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return self._json_response({"ok": False, "error": "invalid_json"}, status=400)

        session_id = body.get("sessionId") or self._browser_session_from_request(request, create=False)
        case_id = body.get("caseId") or body.get("case_id")
        artifact_id = body.get("artifactId") or body.get("artifact_id")

        if not session_id:
            return self._json_response({"ok": False, "error": "missing_session"}, status=400)

        metadata = {
            **({"case_id": case_id} if case_id else {}),
            **({"artifact_id": artifact_id} if artifact_id else {}),
        }

        await self._handle_message(
            sender_id=session_id,
            chat_id=session_id,
            content="/stop",
            metadata=metadata,
        )

        return self._json_response(
            {
                "ok": True,
                "sessionId": session_id,
                "sessionKey": build_scoped_session_key(
                    self.name,
                    session_id,
                    case_id=case_id,
                    artifact_id=artifact_id,
                ),
            },
            session_id=session_id,
        )

    async def _handle_ws(self, request: web.Request) -> web.StreamResponse:
        session_id = self._browser_session_from_request(request, create=True)
        if not session_id:
            raise web.HTTPBadRequest(text="missing session id")

        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._sockets[session_id].add(ws)

        await ws.send_json(
            {
                "type": "ready",
                "sessionId": session_id,
                "title": self.config.title,
            }
        )

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        payload = json.loads(msg.data)
                    except Exception:
                        continue
                    if payload.get("type") == "ping":
                        await ws.send_json({"type": "pong"})
                elif msg.type in {WSMsgType.ERROR, WSMsgType.CLOSE, WSMsgType.CLOSED}:
                    break
        finally:
            self._sockets.get(session_id, set()).discard(ws)
            if not self._sockets.get(session_id):
                self._sockets.pop(session_id, None)

        return ws

    async def _handle_sessions_list(self, request: web.Request) -> web.Response:
        session_id = request.query.get("sessionId") or self._browser_session_from_request(request, create=False)
        if not session_id:
            return self._json_response({"sessions": []})
        if not self._session_manager:
            return self._json_response({"error": "session_manager_unavailable"}, status=503)
        return self._json_response(
            {"sessions": self._sessions_for_browser(session_id)},
            session_id=session_id,
        )

    async def _handle_session_detail(self, request: web.Request) -> web.Response:
        browser_session_id = request.query.get("sessionId") or self._browser_session_from_request(request, create=False)
        if not browser_session_id:
            return self._json_response({"error": "missing_session"}, status=400)
        if not self._session_manager:
            return self._json_response({"error": "session_manager_unavailable"}, status=503)

        session_key = request.match_info["session_key"]
        session = self._find_browser_session(browser_session_id, session_key)
        if session is None:
            return self._json_response({"error": "session_not_found"}, session_id=browser_session_id, status=404)

        scope = parse_scoped_session_key(session.key)
        messages = [
            {
                "role": message.get("role"),
                "timestamp": message.get("timestamp"),
                "content": self._serialize_message_content(message.get("content")),
                "thinkingText": extract_message_thinking_text(message),
            }
            for message in session.messages
        ]
        return self._json_response(
            {
                "session": {
                    "key": session.key,
                    "baseKey": scope.base_key,
                    "caseId": scope.case_id,
                    "artifactId": scope.artifact_id,
                    "createdAt": session.created_at.isoformat(),
                    "updatedAt": session.updated_at.isoformat(),
                    "messages": messages,
                }
            },
            session_id=browser_session_id,
        )

    async def _handle_cases_list(self, request: web.Request) -> web.Response:
        cases_root = self._cases_root
        if cases_root is None:
            return self._json_response({"error": "session_manager_unavailable"}, status=503)
        if not cases_root.is_dir():
            return self._json_response({"cases": []})

        cases = [
            self._case_summary(case_dir)
            for case_dir in sorted(cases_root.iterdir(), key=lambda item: item.name)
            if case_dir.is_dir()
        ]
        return self._json_response({"cases": cases})

    async def _handle_case_detail(self, request: web.Request) -> web.Response:
        case_id = request.match_info["case_id"]
        case_dir = self._case_dir(case_id)
        if case_dir is None:
            return self._json_response({"error": "case_not_found"}, status=404)

        manifest = self._case_manifest(case_dir)
        evidence_ids = self._directory_names(case_dir / "evidence")
        source_ids = self._directory_names(case_dir / "sources")
        return self._json_response(
            {
                "case": {
                    **self._case_summary(case_dir),
                    "manifest": manifest,
                    "evidenceIds": evidence_ids,
                    "sourceIds": source_ids,
                }
            }
        )

    async def _handle_case_report(self, request: web.Request) -> web.Response:
        case_dir = self._case_dir(request.match_info["case_id"])
        if case_dir is None:
            return self._json_response({"error": "case_not_found"}, status=404)

        report_path = case_dir / "report.md"
        if not report_path.is_file():
            return self._json_response({"error": "report_not_found"}, status=404)
        return self._json_response(
            {
                "caseId": case_dir.name,
                "content": report_path.read_text(encoding="utf-8"),
            }
        )

    async def _handle_case_graph(self, request: web.Request) -> web.Response:
        case_dir = self._case_dir(request.match_info["case_id"])
        if case_dir is None:
            return self._json_response({"error": "case_not_found"}, status=404)

        graph_path = case_dir / "graph.json"
        graph = self._load_json_file(graph_path)
        if graph is None:
            return self._json_response({"error": "graph_not_found"}, status=404)
        return self._json_response({"caseId": case_dir.name, "graph": graph})

    async def _handle_evidence_detail(self, request: web.Request) -> web.Response:
        case_dir = self._case_dir(request.match_info["case_id"])
        if case_dir is None:
            return self._json_response({"error": "case_not_found"}, status=404)

        evidence_root = case_dir / "evidence"
        evidence_dir = self._resolve_child(evidence_root, request.match_info["evidence_id"])
        if evidence_dir is None or not evidence_dir.is_dir():
            return self._json_response({"error": "evidence_not_found"}, status=404)

        metadata = self._load_json_file(evidence_dir / "metadata.json")
        return self._json_response(
            {
                "caseId": case_dir.name,
                "evidenceId": evidence_dir.name,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "files": self._file_listing(evidence_dir / "files"),
            }
        )

    async def _handle_source_detail(self, request: web.Request) -> web.Response:
        case_dir = self._case_dir(request.match_info["case_id"])
        if case_dir is None:
            return self._json_response({"error": "case_not_found"}, status=404)

        sources_root = case_dir / "sources"
        source_dir = self._resolve_child(sources_root, request.match_info["source_id"])
        if source_dir is None or not source_dir.is_dir():
            return self._json_response({"error": "source_not_found"}, status=404)

        metadata = self._load_json_file(source_dir / "metadata.json")
        return self._json_response(
            {
                "caseId": case_dir.name,
                "sourceId": source_dir.name,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "files": self._file_listing(source_dir / "raw"),
            }
        )

    async def _handle_wiki_list(self, request: web.Request) -> web.Response:
        session_id = request.query.get("sessionId") or self._browser_session_from_request(request, create=False)
        case_id = request.query.get("caseId") or request.query.get("case_id")
        artifact_id = request.query.get("artifactId") or request.query.get("artifact_id")

        if not session_id:
            return self._json_response({"error": "missing_session"}, status=400)
        if self._workspace_root is None:
            return self._json_response({"error": "session_manager_unavailable"}, status=503)

        notes = self._list_wiki_notes(
            browser_session_id=session_id,
            case_id=case_id,
            artifact_id=artifact_id,
        )
        return self._json_response(
            {
                "notes": notes,
                "scope": {
                    "caseId": case_id or None,
                    "artifactId": artifact_id or None,
                },
            },
            session_id=session_id,
        )

    async def _handle_wiki_detail(self, request: web.Request) -> web.Response:
        note_path = self._wiki_note_path(request.match_info["note_id"])
        if note_path is None:
            return self._json_response({"error": "note_not_found"}, status=404)

        text = note_path.read_text(encoding="utf-8")
        metadata, body = self._parse_frontmatter(text)
        return self._json_response(
            {
                "note": {
                    "id": request.match_info["note_id"],
                    "title": metadata.get("title") or note_path.stem,
                    "metadata": metadata,
                    "content": body,
                }
            }
        )
