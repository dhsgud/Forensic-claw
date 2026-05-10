"""Local browser-based Web UI channel."""

from __future__ import annotations

import asyncio
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
from forensic_claw.uploads import (
    UploadNotFoundError,
    UploadProcessingError,
    UploadService,
    build_attachment_context,
)
from forensic_claw.utils.helpers import (
    current_time_str,
    extract_message_thinking_text,
)


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
        self._model_settings: Any | None = None
        self._knowledge_settings: Any | None = None
        self._app: web.Application | None = None

    def bind_runtime(
        self,
        *,
        session_manager: SessionManager | None = None,
        model_settings: Any | None = None,
        knowledge_settings: Any | None = None,
    ) -> None:
        """Inject runtime services that channels do not own directly."""
        self._session_manager = session_manager
        self._model_settings = model_settings
        self._knowledge_settings = knowledge_settings

    def create_app(self) -> web.Application:
        """Create the aiohttp application used by the channel."""
        if self._app is not None:
            return self._app

        app = web.Application(client_max_size=128 * 1024 * 1024)
        app.router.add_get("/", self._handle_root)
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/ui", self._handle_ui)
        app.router.add_get("/ui/assets/{asset}", self._handle_asset)
        app.router.add_get("/ws", self._handle_ws)
        app.router.add_get("/api/bootstrap", self._handle_bootstrap)
        app.router.add_get("/api/model-config", self._handle_model_config)
        app.router.add_patch("/api/model-config", self._handle_model_config_update)
        app.router.add_post("/api/model-config/test", self._handle_model_config_test)
        app.router.add_get("/api/knowledge-config", self._handle_knowledge_config)
        app.router.add_patch("/api/knowledge-config", self._handle_knowledge_config_update)
        app.router.add_post("/api/knowledge-config/test", self._handle_knowledge_config_test)
        app.router.add_post("/api/uploads", self._handle_upload)
        app.router.add_post("/api/chat", self._handle_chat)
        app.router.add_post("/api/stop", self._handle_stop)
        app.router.add_get("/api/cases", self._handle_cases_list)
        app.router.add_get("/api/cases/{case_id}", self._handle_case_detail)
        app.router.add_get("/api/cases/{case_id}/report", self._handle_case_report)
        app.router.add_get("/api/cases/{case_id}/graph", self._handle_case_graph)
        app.router.add_get("/api/cases/{case_id}/evidence/{evidence_id}", self._handle_evidence_detail)
        app.router.add_get("/api/cases/{case_id}/sources/{source_id}", self._handle_source_detail)
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

    def _upload_service(self) -> UploadService | None:
        workspace = self._workspace_root
        if workspace is None:
            return None
        return UploadService(
            workspace,
            knowledge_service=getattr(self._knowledge_settings, "service", None),
        )

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

    @staticmethod
    def _attachment_ids(value: Any) -> list[str]:
        if value in (None, ""):
            return []
        if not isinstance(value, list):
            raise ValueError("attachments must be a list")
        upload_ids: list[str] = []
        for item in value:
            if isinstance(item, str):
                upload_id = item
            elif isinstance(item, dict):
                upload_id = item.get("uploadId") or item.get("upload_id") or item.get("id")
            else:
                upload_id = None
            if not upload_id:
                raise ValueError("attachment is missing uploadId")
            upload_ids.append(str(upload_id))
        return upload_ids

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
        has_cases = bool(cases_root and cases_root.is_dir() and any(cases_root.iterdir()))
        model_config = self._model_settings.snapshot() if self._model_settings else None
        knowledge_config = (
            await asyncio.to_thread(self._knowledge_settings.snapshot)
            if self._knowledge_settings
            else None
        )
        return self._json_response(
            {
                "appName": "Forensic-Claw",
                "channel": self.name,
                "title": self.config.title,
                "sessionId": session_id,
                "scopes": {"caseId": None, "artifactId": None},
                "features": {"streaming": self.supports_streaming},
                "modelConfig": model_config,
                "knowledgeConfig": knowledge_config,
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
                },
                "shellTraces": list(self._shell_traces.get(session_id or "", [])) if session_id else [],
            },
            session_id=session_id,
        )

    async def _handle_model_config(self, _request: web.Request) -> web.Response:
        if not self._model_settings:
            return self._json_response({"error": "model_settings_unavailable"}, status=503)
        return self._json_response({"modelConfig": self._model_settings.snapshot()})

    async def _handle_model_config_update(self, request: web.Request) -> web.Response:
        if not self._model_settings:
            return self._json_response({"ok": False, "error": "model_settings_unavailable"}, status=503)
        try:
            body = await request.json()
        except Exception:
            return self._json_response({"ok": False, "error": "invalid_json"}, status=400)

        api_base_supplied = "apiBase" in body or "api_base" in body
        try:
            model_config = await self._model_settings.apply(
                provider=body.get("provider"),
                model=body.get("model"),
                api_base=body.get("apiBase", body.get("api_base")),
                api_base_supplied=api_base_supplied,
            )
        except ValueError as exc:
            return self._json_response({"ok": False, "error": str(exc)}, status=400)
        return self._json_response({"ok": True, "modelConfig": model_config})

    async def _handle_model_config_test(self, request: web.Request) -> web.Response:
        if not self._model_settings:
            return self._json_response({"ok": False, "error": "model_settings_unavailable"}, status=503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        result = await self._model_settings.test_connection(
            provider=body.get("provider"),
            api_base=body.get("apiBase", body.get("api_base")),
        )
        return self._json_response({"ok": bool(result.get("ok")), "result": result})

    @staticmethod
    def _knowledge_config_args(body: dict[str, Any]) -> dict[str, Any]:
        neo4j = body.get("neo4j") if isinstance(body.get("neo4j"), dict) else {}
        helix = body.get("helix") if isinstance(body.get("helix"), dict) else {}
        return {
            "enabled": body.get("enabled"),
            "backend": body.get("backend"),
            "store_dir": body.get("storeDir", body.get("store_dir")),
            "neo4j_enabled": body.get(
                "neo4jEnabled",
                body.get("neo4j_enabled", neo4j.get("enabled")),
            ),
            "uri": body.get("uri", neo4j.get("uri")),
            "username": body.get("username", neo4j.get("username")),
            "password": body.get("password", neo4j.get("password")),
            "password_supplied": "password" in body or "password" in neo4j,
            "database": body.get("database", neo4j.get("database")),
            "helix_enabled": body.get("helixEnabled", body.get("helix_enabled", helix.get("enabled"))),
            "helix_local": body.get("helixLocal", body.get("helix_local", helix.get("local"))),
            "helix_port": body.get("helixPort", body.get("helix_port", helix.get("port"))),
            "helix_api_endpoint": body.get(
                "helixApiEndpoint",
                body.get("helix_api_endpoint", helix.get("apiEndpoint", helix.get("api_endpoint"))),
            ),
            "helix_fallback_to_sqlite": body.get(
                "helixFallbackToSqlite",
                body.get("helix_fallback_to_sqlite", helix.get("fallbackToSqlite", helix.get("fallback_to_sqlite"))),
            ),
        }

    async def _handle_knowledge_config(self, _request: web.Request) -> web.Response:
        if not self._knowledge_settings:
            return self._json_response({"error": "knowledge_settings_unavailable"}, status=503)
        snapshot = await asyncio.to_thread(self._knowledge_settings.snapshot)
        return self._json_response({"knowledgeConfig": snapshot})

    async def _handle_knowledge_config_update(self, request: web.Request) -> web.Response:
        if not self._knowledge_settings:
            return self._json_response({"ok": False, "error": "knowledge_settings_unavailable"}, status=503)
        try:
            body = await request.json()
        except Exception:
            return self._json_response({"ok": False, "error": "invalid_json"}, status=400)
        if not isinstance(body, dict):
            return self._json_response({"ok": False, "error": "invalid_json"}, status=400)

        try:
            knowledge_config = await asyncio.to_thread(
                self._knowledge_settings.apply,
                **self._knowledge_config_args(body),
            )
        except ValueError as exc:
            return self._json_response({"ok": False, "error": str(exc)}, status=400)
        return self._json_response({"ok": True, "knowledgeConfig": knowledge_config})

    async def _handle_knowledge_config_test(self, request: web.Request) -> web.Response:
        if not self._knowledge_settings:
            return self._json_response({"ok": False, "error": "knowledge_settings_unavailable"}, status=503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        args = self._knowledge_config_args(body)
        result = await asyncio.to_thread(
            self._knowledge_settings.test_connection,
            backend=args["backend"],
            enabled=args["neo4j_enabled"],
            uri=args["uri"],
            username=args["username"],
            password=args["password"],
            password_supplied=args["password_supplied"],
            database=args["database"],
            helix_enabled=args["helix_enabled"],
            helix_local=args["helix_local"],
            helix_port=args["helix_port"],
            helix_api_endpoint=args["helix_api_endpoint"],
        )
        connected = result.get("state") in {"connected", "configured", "disabled", "available"}
        return self._json_response({"ok": connected, "result": result})

    async def _handle_upload(self, request: web.Request) -> web.Response:
        upload_service = self._upload_service()
        if upload_service is None:
            logger.warning("WebUI upload rejected because session manager is unavailable")
            return self._json_response({"ok": False, "error": "session_manager_unavailable"}, status=503)
        if not request.content_type.startswith("multipart/"):
            logger.warning("WebUI upload rejected because request is not multipart: contentType={}", request.content_type)
            return self._json_response({"ok": False, "error": "multipart_required"}, status=400)

        session_id = self._browser_session_from_request(request, create=True)
        logger.info(
            "WebUI upload request started: sessionId={} contentLength={}",
            session_id,
            request.content_length,
        )
        form_values: dict[str, str] = {}
        file_name: str | None = None
        file_content: bytes | None = None

        try:
            reader = await request.multipart()
            while True:
                part = await reader.next()
                if part is None:
                    break
                if part.name == "file":
                    file_name = part.filename
                    chunks = bytearray()
                    while True:
                        chunk = await part.read_chunk(size=1024 * 1024)
                        if not chunk:
                            break
                        chunks.extend(chunk)
                    file_content = bytes(chunks)
                    continue
                if part.name:
                    form_values[part.name] = (await part.text()).strip()
        except Exception:
            logger.exception("Failed to read WebUI upload payload")
            return self._json_response({"ok": False, "error": "invalid_multipart"}, status=400)

        session_id = form_values.get("sessionId") or session_id
        if not session_id:
            logger.warning("WebUI upload rejected because session id is missing")
            return self._json_response({"ok": False, "error": "missing_session"}, status=400)
        if file_content is None:
            logger.warning("WebUI upload rejected because file field is missing: sessionId={}", session_id)
            return self._json_response({"ok": False, "error": "missing_file"}, session_id=session_id, status=400)

        try:
            record = await asyncio.to_thread(
                upload_service.save_bytes,
                file_name=file_name,
                content=file_content,
                session_id=session_id,
                case_name=form_values.get("caseName") or form_values.get("case_name"),
                investigator_name=form_values.get("investigatorName") or form_values.get("investigator_name"),
            )
        except UploadProcessingError as exc:
            logger.warning(
                "WebUI upload processing failed: sessionId={} fileName={} error={}",
                session_id,
                file_name,
                exc,
            )
            return self._json_response({"ok": False, "error": str(exc)}, session_id=session_id, status=400)

        logger.info(
            "WebUI upload request completed: sessionId={} uploadId={} status={} kind={} sizeBytes={}",
            session_id,
            record.upload_id,
            record.status,
            record.kind,
            record.size_bytes,
        )
        return self._json_response(
            {"ok": True, "sessionId": session_id, "upload": record.to_dict()},
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
        case_name = str(body.get("caseName") or body.get("case_name") or "").strip()
        investigator_name = str(
            body.get("investigatorName") or body.get("investigator_name") or ""
        ).strip()
        try:
            upload_ids = self._attachment_ids(body.get("attachments"))
        except ValueError as exc:
            return self._json_response({"ok": False, "error": str(exc)}, status=400)

        if not session_id:
            return self._json_response({"ok": False, "error": "missing_session"}, status=400)
        if not text and not upload_ids:
            return self._json_response({"ok": False, "error": "empty_text"}, session_id=session_id, status=400)
        if not case_name or not investigator_name:
            return self._json_response(
                {"ok": False, "error": "missing_case_setup"},
                session_id=session_id,
                status=400,
            )

        metadata = {
            "_wants_stream": self.supports_streaming,
            **({"case_id": case_id} if case_id else {}),
            **({"artifact_id": artifact_id} if artifact_id else {}),
            "case_name": case_name,
            "investigator_name": investigator_name,
        }
        content = text
        media: list[str] = []
        if upload_ids:
            upload_service = self._upload_service()
            if upload_service is None:
                logger.warning("WebUI chat rejected because upload service is unavailable: sessionId={}", session_id)
                return self._json_response(
                    {"ok": False, "error": "session_manager_unavailable"},
                    session_id=session_id,
                    status=503,
                )
            try:
                records = await asyncio.to_thread(upload_service.load_many, upload_ids)
            except UploadNotFoundError as exc:
                logger.warning(
                    "WebUI chat referenced missing attachment: sessionId={} uploadId={}",
                    session_id,
                    exc.args[0],
                )
                return self._json_response(
                    {"ok": False, "error": f"attachment_not_found:{exc.args[0]}"},
                    session_id=session_id,
                    status=404,
                )
            attachment_context = build_attachment_context(records)
            user_request = text or "첨부 파일을 분석해줘."
            content = f"{attachment_context}\n\nUser Request:\n{user_request}"
            media = [record.stored_path for record in records if record.kind == "image"]
            metadata["attachments"] = [record.to_dict() for record in records]
            logger.info(
                "WebUI chat attached upload context: sessionId={} attachments={} imageMedia={}",
                session_id,
                len(records),
                len(media),
            )

        await self._handle_message(
            sender_id=session_id,
            chat_id=session_id,
            content=content,
            media=media,
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
        case_name = str(body.get("caseName") or body.get("case_name") or "").strip()
        investigator_name = str(
            body.get("investigatorName") or body.get("investigator_name") or ""
        ).strip()

        if not session_id:
            return self._json_response({"ok": False, "error": "missing_session"}, status=400)

        metadata = {
            **({"case_id": case_id} if case_id else {}),
            **({"artifact_id": artifact_id} if artifact_id else {}),
            **({"case_name": case_name} if case_name else {}),
            **({"investigator_name": investigator_name} if investigator_name else {}),
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
