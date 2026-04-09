"""KakaoTalk channel via Kakao i Open Builder webhook + callback API."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from aiohttp import ClientSession, ClientTimeout, web
from loguru import logger
from pydantic import Field

from forensic_claw.bus.events import OutboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.base import BaseChannel
from forensic_claw.config.paths import get_runtime_subdir
from forensic_claw.config.schema import Base
from forensic_claw.utils.helpers import split_message

MAX_SIMPLE_TEXT_LEN = 1000
MAX_SIMPLE_TEXT_BUBBLES = 3


class KakaoTalkConfig(Base):
    """KakaoTalk webhook server configuration."""

    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 3000
    skill_path: str = "/skill"
    health_path: str = "/health"
    allow_from: list[str] = Field(default_factory=lambda: ["*"])
    pairing_code: str = "CHANGE_ME"
    admin_kakao_id: str = ""
    callback_timeout: int = 55
    pending_text: str = "분석 중입니다. 잠시만 기다려 주세요."


class KakaoTalkChannel(BaseChannel):
    """KakaoTalk Open Builder skill server."""

    name = "kakaotalk"
    display_name = "KakaoTalk"

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return KakaoTalkConfig().model_dump(by_alias=True)

    def __init__(self, config: Any, bus: MessageBus):
        if isinstance(config, dict):
            config = KakaoTalkConfig.model_validate(config)
        super().__init__(config, bus)
        self.config: KakaoTalkConfig = config
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._http: ClientSession | None = None
        self._stop_event = asyncio.Event()
        self._callback_cache: dict[str, dict[str, str]] = {}
        self._pairs_path = get_runtime_subdir("kakaotalk") / "pairs.json"
        self._paired_users = self._load_paired_users()

    async def login(self, force: bool = False) -> bool:
        """Webhook channels do not need an interactive login flow."""
        logger.info(
            "KakaoTalk uses webhook setup. Configure Open Builder to POST to http://{}:{}{}",
            self.config.host,
            self.config.port,
            self.config.skill_path,
        )
        return True

    async def start(self) -> None:
        """Start the aiohttp webhook server and keep it alive."""
        if self._runner is not None:
            return

        app = web.Application(client_max_size=10 * 1024 * 1024)
        app.router.add_post(self.config.skill_path, self._handle_skill_request)
        app.router.add_get(self.config.health_path, self._handle_health)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=self.config.host, port=self.config.port)
        self._http = ClientSession(timeout=ClientTimeout(total=self.config.callback_timeout))
        self._stop_event.clear()
        self._running = True

        await self._site.start()
        logger.info(
            "KakaoTalk channel listening on http://{}:{}{}",
            self.config.host,
            self.config.port,
            self.config.skill_path,
        )

        try:
            await self._stop_event.wait()
        finally:
            self._running = False

    async def stop(self) -> None:
        """Stop the webhook server and close HTTP resources."""
        self._running = False
        self._stop_event.set()

        if self._site is not None:
            await self._site.stop()
            self._site = None

        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

        if self._http is not None:
            await self._http.close()
            self._http = None

    async def send(self, msg: OutboundMessage) -> None:
        """Send the final KakaoTalk response via callback API."""
        if msg.metadata.get("_progress"):
            return

        callback = self._get_callback_info(msg)
        if not callback or not self._http:
            logger.warning("KakaoTalk callback missing for chat {}", msg.chat_id)
            return

        payload = self._build_response_payload(msg.content, msg.metadata)
        headers = {"Content-Type": "application/json; charset=utf-8"}
        callback_token = callback.get("callback_token")
        if callback_token:
            headers["X-Kakao-Callback-Token"] = callback_token

        response = await self._http.post(callback["callback_url"], json=payload, headers=headers)
        response.raise_for_status()

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "channel": self.name})

    async def _handle_skill_request(self, request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            return web.json_response(self._simple_text_response("유효한 JSON 요청이 아닙니다."), status=400)

        utterance = self._extract_utterance(payload)
        sender_id = self._extract_sender_id(payload)
        chat_id = self._extract_chat_id(payload, sender_id)
        callback_info = self._extract_callback_info(request, payload)
        metadata = {
            "request_id": request.headers.get("X-Request-ID", ""),
            **callback_info,
        }

        if not sender_id:
            return web.json_response(self._simple_text_response("사용자 식별자를 찾을 수 없습니다."), status=400)

        if pairing_response := self._handle_pairing_command(sender_id, utterance):
            return web.json_response(pairing_response)

        if not self.is_allowed(sender_id):
            return web.json_response(
                self._simple_text_response("먼저 /pair [코드] [이름] 으로 연결해 주세요.")
            )

        if callback_info.get("callback_url"):
            self._callback_cache[chat_id] = callback_info
        else:
            return web.json_response(
                self._simple_text_response(
                    "callbackUrl 이 없습니다. 카카오 오픈빌더 콜백 기능을 활성화해 주세요."
                ),
                status=400,
            )

        await self._handle_message(
            sender_id=sender_id,
            chat_id=chat_id,
            content=utterance or "[empty message]",
            metadata=metadata,
            session_key=f"{self.name}:{sender_id}",
        )
        return web.json_response(self._callback_ack(self.config.pending_text))

    def is_allowed(self, sender_id: str) -> bool:
        if sender_id == self.config.admin_kakao_id:
            return True
        if sender_id in self._paired_users:
            return True

        allow_list = list(self.config.allow_from or [])
        if not allow_list:
            return False
        if "*" in allow_list:
            return True
        return str(sender_id) in allow_list

    def _handle_pairing_command(self, sender_id: str, utterance: str) -> dict[str, Any] | None:
        if not utterance.startswith("/pair"):
            return None

        parts = utterance.split(maxsplit=2)
        if len(parts) < 2:
            return self._simple_text_response("사용법: /pair [코드] [이름]")

        configured_code = (self.config.pairing_code or "").strip()
        if not configured_code or configured_code.upper() in {"CHANGE_ME", "변경필수"}:
            return self._simple_text_response("pairing_code 설정이 아직 준비되지 않았습니다.")

        if parts[1] != configured_code:
            return self._simple_text_response("페어링 코드가 올바르지 않습니다.")

        display_name = parts[2].strip() if len(parts) > 2 else sender_id
        self._paired_users[sender_id] = display_name
        self._save_paired_users()
        return self._simple_text_response(f"{display_name} 님 연결이 완료되었습니다.")

    def _build_response_payload(
        self, content: str, metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        metadata = metadata or {}
        if isinstance(metadata.get("kakaotalk_template"), dict):
            return {"version": "2.0", "template": metadata["kakaotalk_template"]}

        if structured := self._parse_structured_content(content):
            return {"version": "2.0", "template": structured}

        return self._simple_text_response(content)

    def _parse_structured_content(self, content: str) -> dict[str, Any] | None:
        try:
            data = json.loads(content)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        if "outputs" in data:
            template = {"outputs": data["outputs"]}
            if "quickReplies" in data:
                template["quickReplies"] = data["quickReplies"]
            return template

        if "simpleText" in data or "basicCard" in data:
            outputs: list[dict[str, Any]] = []
            if "simpleText" in data:
                outputs.append({"simpleText": data["simpleText"]})
            if "basicCard" in data:
                outputs.append({"basicCard": data["basicCard"]})
            template = {"outputs": outputs}
            if "quickReplies" in data:
                template["quickReplies"] = data["quickReplies"]
            return template

        if any(key in data for key in ("title", "description", "buttons")):
            buttons = data.get("buttons") or []
            card = {
                "title": str(data.get("title") or "").strip(),
                "description": str(data.get("description") or "").strip(),
            }
            if buttons:
                card["buttons"] = buttons
            template = {"outputs": [{"basicCard": card}]}
            if "quickReplies" in data:
                template["quickReplies"] = data["quickReplies"]
            return template

        return None

    def _simple_text_response(self, content: str) -> dict[str, Any]:
        chunks = split_message(content or "", MAX_SIMPLE_TEXT_LEN)[:MAX_SIMPLE_TEXT_BUBBLES]
        if not chunks:
            chunks = ["응답이 비어 있습니다."]
        return {
            "version": "2.0",
            "template": {
                "outputs": [{"simpleText": {"text": chunk}} for chunk in chunks],
            },
        }

    @staticmethod
    def _callback_ack(text: str) -> dict[str, Any]:
        return {
            "version": "2.0",
            "useCallback": True,
            "data": {"text": text},
        }

    @staticmethod
    def _extract_utterance(payload: dict[str, Any]) -> str:
        return str(
            (payload.get("userRequest") or {}).get("utterance")
            or (payload.get("action") or {}).get("clientExtra", {}).get("utterance")
            or ""
        ).strip()

    @classmethod
    def _extract_sender_id(cls, payload: dict[str, Any]) -> str:
        user = (payload.get("userRequest") or {}).get("user") or {}
        properties = user.get("properties") or {}
        for value in (
            user.get("id"),
            properties.get("botUserKey"),
            properties.get("plusfriendUserKey"),
            properties.get("appUserId"),
        ):
            if value:
                return str(value)
        return ""

    @classmethod
    def _extract_chat_id(cls, payload: dict[str, Any], fallback: str) -> str:
        user = (payload.get("userRequest") or {}).get("user") or {}
        properties = user.get("properties") or {}
        return str(
            (payload.get("userRequest") or {}).get("chatId")
            or properties.get("botUserKey")
            or user.get("id")
            or fallback
        )

    @staticmethod
    def _extract_callback_info(
        request: web.Request, payload: dict[str, Any]
    ) -> dict[str, str]:
        callback_url = str(
            payload.get("callbackUrl")
            or (payload.get("userRequest") or {}).get("callbackUrl")
            or ""
        ).strip()
        callback_token = (
            request.headers.get("X-Kakao-Callback-Token")
            or request.headers.get("Kakao-Callback-Token")
            or ""
        ).strip()
        result: dict[str, str] = {}
        if callback_url:
            result["callback_url"] = callback_url
        if callback_token:
            result["callback_token"] = callback_token
        return result

    def _get_callback_info(self, msg: OutboundMessage) -> dict[str, str] | None:
        metadata = msg.metadata or {}
        callback_url = metadata.get("callback_url")
        if callback_url:
            info = {"callback_url": str(callback_url)}
            if metadata.get("callback_token"):
                info["callback_token"] = str(metadata["callback_token"])
            return info
        return self._callback_cache.get(msg.chat_id)

    def _load_paired_users(self) -> dict[str, str]:
        if not self._pairs_path.is_file():
            return {}
        try:
            data = json.loads(self._pairs_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load KakaoTalk pairs: {}", exc)
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(key): str(value) for key, value in data.items()}

    def _save_paired_users(self) -> None:
        self._pairs_path.parent.mkdir(parents=True, exist_ok=True)
        self._pairs_path.write_text(
            json.dumps(self._paired_users, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
