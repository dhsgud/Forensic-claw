"""Agent loop: the core processing engine."""

from __future__ import annotations

import asyncio
import json
import re
import os
import time
from contextlib import AsyncExitStack, nullcontext
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from loguru import logger

from forensic_claw.agent.context import ContextBuilder
from forensic_claw.agent.memory import MemoryConsolidator
from forensic_claw.agent.subagent import SubagentManager
from forensic_claw.agent.tools.cron import CronTool
from forensic_claw.agent.skills import BUILTIN_SKILLS_DIR
from forensic_claw.agent.tools.filesystem import EditFileTool, ListDirTool, ReadFileTool, WriteFileTool
from forensic_claw.agent.tools.message import MessageTool
from forensic_claw.agent.tools.registry import ToolRegistry
from forensic_claw.agent.tools.shell import ExecTool
from forensic_claw.agent.tools.spawn import SpawnTool
from forensic_claw.agent.tools.web import WebFetchTool, WebSearchTool
from forensic_claw.bus.events import InboundMessage, OutboundMessage
from forensic_claw.command import CommandContext, CommandRouter, register_builtin_commands
from forensic_claw.bus.queue import MessageBus
from forensic_claw.providers.base import LLMProvider
from forensic_claw.session.manager import Session, SessionManager
from forensic_claw.utils.helpers import extract_message_thinking_text, extract_think
from forensic_claw.wiki import WikiArchive

if TYPE_CHECKING:
    from forensic_claw.config.schema import ChannelsConfig, ExecToolConfig, WebSearchConfig
    from forensic_claw.cron.service import CronService


class AgentLoop:
    """
    The agent loop is the core processing engine.

    It:
    1. Receives messages from the bus
    2. Builds context with history, memory, skills
    3. Calls the LLM
    4. Executes tool calls
    5. Sends responses back
    """

    _TOOL_RESULT_MAX_CHARS = 16_000
    _AUTO_BACKGROUND_LOG_PATTERNS = (
        "시스템 로그",
        "이벤트 로그",
        "system log",
        "system logs",
        "event log",
        "event logs",
        "windows log",
        "windows logs",
        "evtx",
    )
    _AUTO_BACKGROUND_ANALYSIS_PATTERNS = (
        "분석",
        "조사",
        "검토",
        "살펴",
        "점검",
        "analyze",
        "analyse",
        "inspect",
        "review",
    )
    _AUTO_BACKGROUND_NARROW_PATTERNS = (
        "event id",
        "eventid",
        "source",
        "provider",
        "최근 ",
        "last ",
        "first ",
        "top ",
        "maxevents",
        "특정",
    )

    def __init__(
        self,
        bus: MessageBus,
        provider: LLMProvider,
        workspace: Path,
        model: str | None = None,
        max_iterations: int = 40,
        context_window_tokens: int = 65_536,
        web_search_config: WebSearchConfig | None = None,
        web_proxy: str | None = None,
        exec_config: ExecToolConfig | None = None,
        cron_service: CronService | None = None,
        restrict_to_workspace: bool = False,
        session_manager: SessionManager | None = None,
        mcp_servers: dict | None = None,
        channels_config: ChannelsConfig | None = None,
        timezone: str | None = None,
        thinking_language: str = "en",
        response_language: str = "ko",
        enforce_response_language: bool = True,
        archive_final_answer_as_wiki: bool = False,
        reset_session_after_answer: bool = False,
    ):
        from forensic_claw.config.schema import ExecToolConfig, WebSearchConfig

        self.bus = bus
        self.channels_config = channels_config
        self.provider = provider
        self.workspace = workspace
        self.model = model or provider.get_default_model()
        self.max_iterations = max_iterations
        self.context_window_tokens = context_window_tokens
        self.web_search_config = web_search_config or WebSearchConfig()
        self.web_proxy = web_proxy
        self.exec_config = exec_config or ExecToolConfig()
        self.cron_service = cron_service
        self.restrict_to_workspace = restrict_to_workspace
        self._start_time = time.time()
        self._last_usage: dict[str, int] = {}
        self.thinking_language = thinking_language
        self.response_language = response_language
        self.enforce_response_language = enforce_response_language
        self.archive_final_answer_as_wiki = archive_final_answer_as_wiki
        self.reset_session_after_answer = reset_session_after_answer
        self.wiki_archive = WikiArchive(workspace) if archive_final_answer_as_wiki else None

        self.context = ContextBuilder(
            workspace,
            timezone=timezone,
            thinking_language=thinking_language,
            response_language=response_language,
            enforce_response_language=enforce_response_language,
        )
        self.sessions = session_manager or SessionManager(workspace)
        self.tools = ToolRegistry()
        self.subagents = SubagentManager(
            provider=provider,
            workspace=workspace,
            bus=bus,
            model=self.model,
            web_search_config=self.web_search_config,
            web_proxy=web_proxy,
            exec_config=self.exec_config,
            restrict_to_workspace=restrict_to_workspace,
            thinking_language=thinking_language,
            response_language=response_language,
        )

        self._running = False
        self._mcp_servers = mcp_servers or {}
        self._mcp_stack: AsyncExitStack | None = None
        self._mcp_connected = False
        self._mcp_connecting = False
        self._active_tasks: dict[str, list[asyncio.Task]] = {}  # session_key -> tasks
        self._background_tasks: list[asyncio.Task] = []
        self._session_locks: dict[str, asyncio.Lock] = {}
        # FORENSIC_CLAW_MAX_CONCURRENT_REQUESTS: <=0 means unlimited; default 3.
        _max = int(os.environ.get("FORENSIC_CLAW_MAX_CONCURRENT_REQUESTS", "3"))
        self._concurrency_gate: asyncio.Semaphore | None = (
            asyncio.Semaphore(_max) if _max > 0 else None
        )
        self.memory_consolidator = MemoryConsolidator(
            workspace=workspace,
            provider=provider,
            model=self.model,
            sessions=self.sessions,
            context_window_tokens=context_window_tokens,
            build_messages=self.context.build_messages,
            get_tool_definitions=self.tools.get_definitions,
            max_completion_tokens=provider.generation.max_tokens,
        )
        self._register_default_tools()
        self.commands = CommandRouter()
        register_builtin_commands(self.commands)

    def _register_default_tools(self) -> None:
        """Register the default set of tools."""
        allowed_dir = self.workspace if self.restrict_to_workspace else None
        extra_read = [BUILTIN_SKILLS_DIR] if allowed_dir else None
        self.tools.register(ReadFileTool(workspace=self.workspace, allowed_dir=allowed_dir, extra_allowed_dirs=extra_read))
        for cls in (WriteFileTool, EditFileTool, ListDirTool):
            self.tools.register(cls(workspace=self.workspace, allowed_dir=allowed_dir))
        if self.exec_config.enable:
            self.tools.register(ExecTool(
                working_dir=str(self.workspace),
                timeout=self.exec_config.timeout,
                restrict_to_workspace=self.restrict_to_workspace,
                path_append=self.exec_config.path_append,
            ))
        self.tools.register(WebSearchTool(config=self.web_search_config, proxy=self.web_proxy))
        self.tools.register(WebFetchTool(proxy=self.web_proxy))
        self.tools.register(MessageTool(
            send_callback=self.bus.publish_outbound,
            content_transform=self._normalize_user_facing_text,
        ))
        self.tools.register(SpawnTool(manager=self.subagents))
        if self.cron_service:
            self.tools.register(
                CronTool(self.cron_service, default_timezone=self.context.timezone or "UTC")
            )

    async def _connect_mcp(self) -> None:
        """Connect to configured MCP servers (one-time, lazy)."""
        if self._mcp_connected or self._mcp_connecting or not self._mcp_servers:
            return
        self._mcp_connecting = True
        from forensic_claw.agent.tools.mcp import connect_mcp_servers
        try:
            self._mcp_stack = AsyncExitStack()
            await self._mcp_stack.__aenter__()
            await connect_mcp_servers(self._mcp_servers, self.tools, self._mcp_stack)
            self._mcp_connected = True
        except BaseException as e:
            logger.error("Failed to connect MCP servers (will retry next message): {}", e)
            if self._mcp_stack:
                try:
                    await self._mcp_stack.aclose()
                except Exception:
                    pass
                self._mcp_stack = None
        finally:
            self._mcp_connecting = False

    def _set_tool_context(
        self,
        channel: str,
        chat_id: str,
        message_id: str | None = None,
        session_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update context for all tools that need routing info."""
        if tool := self.tools.get("message"):
            if hasattr(tool, "set_context"):
                tool.set_context(channel, chat_id, message_id)
        if tool := self.tools.get("spawn"):
            if hasattr(tool, "set_context"):
                tool.set_context(
                    channel,
                    chat_id,
                    session_key=session_key,
                    metadata=metadata,
                )
        if tool := self.tools.get("cron"):
            if hasattr(tool, "set_context"):
                tool.set_context(channel, chat_id)

    @staticmethod
    def _strip_think(text: str | None) -> str | None:
        """Remove <think>…</think> blocks that some models embed in content."""
        if not text:
            return None
        from forensic_claw.utils.helpers import strip_think
        return strip_think(text) or None

    @staticmethod
    def _tool_hint(tool_calls: list) -> str:
        """Format tool calls as concise hint, e.g. 'web_search("query")'."""
        def _fmt(tc):
            args = (tc.arguments[0] if isinstance(tc.arguments, list) else tc.arguments) or {}
            val = next(iter(args.values()), None) if isinstance(args, dict) else None
            if not isinstance(val, str):
                return tc.name
            return f'{tc.name}("{val[:40]}…")' if len(val) > 40 else f'{tc.name}("{val}")'
        return ", ".join(_fmt(tc) for tc in tool_calls)

    @staticmethod
    def _count_hangul(text: str) -> int:
        """Count Hangul syllables/jamo in text."""
        return sum(
            1 for ch in text
            if ("\uac00" <= ch <= "\ud7a3") or ("\u1100" <= ch <= "\u11ff") or ("\u3130" <= ch <= "\u318f")
        )

    @staticmethod
    def _count_latin_letters(text: str) -> int:
        """Count Latin alphabet letters in text."""
        return sum(1 for ch in text if ("a" <= ch.lower() <= "z"))

    def _needs_response_language_normalization(self, text: str | None) -> bool:
        """Heuristic check for whether user-facing text should be normalized."""
        if not self.enforce_response_language or not text:
            return False
        if self.response_language.lower() not in {"ko", "korean"}:
            return False

        hangul = self._count_hangul(text)
        latin = self._count_latin_letters(text)
        if hangul == 0 and latin == 0:
            return False
        if hangul >= max(12, latin // 2):
            return False
        return latin > hangul

    async def _normalize_user_facing_text(self, text: str) -> str:
        """Force final user-facing text into the configured response language when needed."""
        if not self._needs_response_language_normalization(text):
            return text

        policy = "한국어" if self.response_language.lower() in {"ko", "korean"} else self.response_language
        prompt = (
            f"Rewrite the assistant draft into natural {policy}. "
            "Preserve facts, markdown structure, bulleting, file paths, command names, hashes, code blocks, "
            "quoted literals, and identifiers exactly when possible. "
            "Do not add new information. If the draft is already in the target language, return it unchanged."
        )

        response = await self.provider.chat_with_retry(
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": text},
            ],
            tools=None,
            model=self.model,
            temperature=0.1,
        )
        normalized = self._strip_think(response.content) if response and response.content else None
        return normalized or text

    async def _run_agent_loop(
        self,
        initial_messages: list[dict],
        on_progress: Callable[..., Awaitable[None]] | None = None,
        on_stream: Callable[[str], Awaitable[None]] | None = None,
        on_stream_end: Callable[..., Awaitable[None]] | None = None,
        *,
        channel: str = "cli",
        chat_id: str = "direct",
        message_id: str | None = None,
        session_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str | None, list[str], list[dict]]:
        """Run the agent iteration loop.

        *on_stream*: called with each content delta during streaming.
        *on_stream_end(resuming)*: called when a streaming session finishes.
        ``resuming=True`` means tool calls follow (spinner should restart);
        ``resuming=False`` means this is the final response.
        """
        messages = initial_messages
        iteration = 0
        final_content = None
        tools_used: list[str] = []

        # Wrap on_stream with stateful think-tag filter so downstream
        # consumers (CLI, channels) never see <think> blocks.
        _raw_stream = on_stream
        _stream_buf = ""
        _reasoning_buf = ""

        async def _filtered_stream(delta: str) -> None:
            nonlocal _stream_buf
            from forensic_claw.utils.helpers import strip_think
            prev_clean = strip_think(_stream_buf)
            prev_think = extract_think(_stream_buf) or ""
            _stream_buf += delta
            new_clean = strip_think(_stream_buf)
            new_think = extract_think(_stream_buf) or ""
            incremental = new_clean[len(prev_clean):]
            thinking_delta = new_think[len(prev_think):]
            if thinking_delta and channel == "webui" and on_progress:
                await on_progress(thinking_delta)
            if incremental and _raw_stream:
                await _raw_stream(incremental)

        async def _filtered_reasoning(delta: str) -> None:
            nonlocal _reasoning_buf
            if not delta or channel != "webui" or not on_progress:
                return

            normalized = extract_think(delta) or delta
            if not normalized:
                return

            if normalized.startswith(_reasoning_buf):
                incremental = normalized[len(_reasoning_buf):]
                _reasoning_buf = normalized
            else:
                incremental = normalized
                _reasoning_buf += normalized

            if incremental:
                await on_progress(incremental)

        while iteration < self.max_iterations:
            iteration += 1

            tool_defs = self.tools.get_definitions()

            use_stream = on_stream is not None and (
                not self.enforce_response_language or channel == "webui"
            )

            if use_stream:
                response = await self.provider.chat_stream_with_retry(
                    messages=messages,
                    tools=tool_defs,
                    model=self.model,
                    on_content_delta=_filtered_stream,
                    on_reasoning_delta=_filtered_reasoning,
                )
            else:
                response = await self.provider.chat_with_retry(
                    messages=messages,
                    tools=tool_defs,
                    model=self.model,
                )

            usage = response.usage or {}
            self._last_usage = {
                "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
                "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
            }

            if response.has_tool_calls:
                if use_stream and on_stream_end:
                    await on_stream_end(resuming=True)
                    _stream_buf = ""

                if on_progress:
                    if not on_stream:
                        thought = self._strip_think(response.content)
                        if thought:
                            await on_progress(thought)
                    tool_hint = self._tool_hint(response.tool_calls)
                    tool_hint = self._strip_think(tool_hint)
                    await on_progress(tool_hint, tool_hint=True)

                tool_call_dicts = [
                    tc.to_openai_tool_call()
                    for tc in response.tool_calls
                ]
                reasoning_text = response.reasoning_content or extract_think(response.content)
                messages = self.context.add_assistant_message(
                    messages, response.content, tool_call_dicts,
                    reasoning_content=reasoning_text,
                    thinking_blocks=response.thinking_blocks,
                )

                for tc in response.tool_calls:
                    tools_used.append(tc.name)
                    args_str = json.dumps(tc.arguments, ensure_ascii=False)
                    logger.info("Tool call: {}({})", tc.name, args_str[:200])

                # Re-bind tool context right before execution so that
                # concurrent sessions don't clobber each other's routing.
                self._set_tool_context(
                    channel,
                    chat_id,
                    message_id,
                    session_key=session_key,
                    metadata=metadata,
                )

                # Execute all tool calls concurrently — the LLM batches
                # independent calls in a single response on purpose.
                # return_exceptions=True ensures all results are collected
                # even if one tool is cancelled or raises BaseException.
                results = await asyncio.gather(*(
                    self.tools.execute(tc.name, tc.arguments)
                    for tc in response.tool_calls
                ), return_exceptions=True)

                for tool_call, result in zip(response.tool_calls, results):
                    if isinstance(result, BaseException):
                        result = f"Error: {type(result).__name__}: {result}"
                    messages = self.context.add_tool_result(
                        messages, tool_call.id, tool_call.name, result
                    )
            else:
                if use_stream and on_stream_end:
                    await on_stream_end(resuming=False)
                    _stream_buf = ""

                clean = self._strip_think(response.content)
                clean = await self._normalize_user_facing_text(clean or "") if clean else clean
                if response.finish_reason == "error":
                    logger.error("LLM returned error: {}", (clean or "")[:200])
                    final_content = clean or "Sorry, I encountered an error calling the AI model."
                    break
                reasoning_text = response.reasoning_content or extract_think(response.content)
                messages = self.context.add_assistant_message(
                    messages, clean, reasoning_content=reasoning_text,
                    thinking_blocks=response.thinking_blocks,
                )
                final_content = clean
                break

        if final_content is None and iteration >= self.max_iterations:
            logger.warning("Max iterations ({}) reached", self.max_iterations)
            final_content = (
                f"I reached the maximum number of tool call iterations ({self.max_iterations}) "
                "without completing the task. You can try breaking the task into smaller steps."
            )

        return final_content, tools_used, messages

    async def run(self) -> None:
        """Run the agent loop, dispatching messages as tasks to stay responsive to /stop."""
        self._running = True
        await self._connect_mcp()
        logger.info("Agent loop started")

        while self._running:
            try:
                msg = await asyncio.wait_for(self.bus.consume_inbound(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                # Preserve real task cancellation so shutdown can complete cleanly.
                # Only ignore non-task CancelledError signals that may leak from integrations.
                if not self._running or asyncio.current_task().cancelling():
                    raise
                continue
            except Exception as e:
                logger.warning("Error consuming inbound message: {}, continuing...", e)
                continue

            raw = msg.content.strip()
            if self.commands.is_priority(raw):
                ctx = CommandContext(msg=msg, session=None, key=msg.session_key, raw=raw, loop=self)
                result = await self.commands.dispatch_priority(ctx)
                if result:
                    await self.bus.publish_outbound(result)
                continue
            task = asyncio.create_task(self._dispatch(msg))
            self._active_tasks.setdefault(msg.session_key, []).append(task)
            task.add_done_callback(lambda t, k=msg.session_key: self._active_tasks.get(k, []) and self._active_tasks[k].remove(t) if t in self._active_tasks.get(k, []) else None)

    async def _dispatch(self, msg: InboundMessage) -> None:
        """Process a message: per-session serial, cross-session concurrent."""
        lock = self._session_locks.setdefault(msg.session_key, asyncio.Lock())
        gate = self._concurrency_gate or nullcontext()
        async with lock, gate:
            try:
                on_stream = on_stream_end = None
                did_stream_output = False
                last_stream_id: str | None = None
                if msg.metadata.get("_wants_stream"):
                    # Split one answer into distinct stream segments.
                    stream_base_id = f"{msg.session_key}:{time.time_ns()}"
                    stream_segment = 0

                    def _current_stream_id() -> str:
                        return f"{stream_base_id}:{stream_segment}"

                    async def on_stream(delta: str) -> None:
                        nonlocal did_stream_output, last_stream_id
                        did_stream_output = True
                        last_stream_id = _current_stream_id()
                        await self.bus.publish_outbound(OutboundMessage(
                            channel=msg.channel, chat_id=msg.chat_id,
                            content=delta,
                            metadata={
                                "_stream_delta": True,
                                "_stream_id": _current_stream_id(),
                            },
                        ))

                    async def on_stream_end(*, resuming: bool = False) -> None:
                        nonlocal stream_segment, last_stream_id
                        last_stream_id = _current_stream_id()
                        await self.bus.publish_outbound(OutboundMessage(
                            channel=msg.channel, chat_id=msg.chat_id,
                            content="",
                            metadata={
                                "_stream_end": True,
                                "_resuming": resuming,
                                "_stream_id": _current_stream_id(),
                            },
                        ))
                        stream_segment += 1

                response = await self._process_message(
                    msg, on_stream=on_stream, on_stream_end=on_stream_end,
                )
                if response is not None:
                    if did_stream_output:
                        if msg.channel == "webui" and last_stream_id:
                            response.metadata["_replace_stream_id"] = last_stream_id
                        else:
                            response.metadata["_streamed"] = True
                    await self.bus.publish_outbound(response)
                elif msg.channel == "cli":
                    await self.bus.publish_outbound(OutboundMessage(
                        channel=msg.channel, chat_id=msg.chat_id,
                        content="", metadata=msg.metadata or {},
                    ))
            except asyncio.CancelledError:
                logger.info("Task cancelled for session {}", msg.session_key)
                raise
            except Exception:
                logger.exception("Error processing message for session {}", msg.session_key)
                await self.bus.publish_outbound(OutboundMessage(
                    channel=msg.channel, chat_id=msg.chat_id,
                    content="Sorry, I encountered an error.",
                ))

    async def close_mcp(self) -> None:
        """Drain pending background archives, then close MCP connections."""
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()
        if self._mcp_stack:
            try:
                await self._mcp_stack.aclose()
            except (RuntimeError, BaseExceptionGroup):
                pass  # MCP SDK cancel scope cleanup is noisy but harmless
            self._mcp_stack = None

    def _schedule_background(self, coro) -> None:
        """Schedule a coroutine as a tracked background task (drained on shutdown)."""
        task = asyncio.create_task(coro)
        self._background_tasks.append(task)
        task.add_done_callback(self._background_tasks.remove)

    def stop(self) -> None:
        """Stop the agent loop."""
        self._running = False
        logger.info("Agent loop stopping")

    @classmethod
    def _should_auto_background_large_log_task(cls, msg: InboundMessage) -> bool:
        """Detect broad local log-analysis requests that should move to the background."""
        if msg.channel == "system":
            return False
        if (msg.metadata or {}).get("_background_task"):
            return False

        raw = msg.content.strip()
        if not raw or raw.startswith("/"):
            return False

        lowered = raw.lower()
        has_log_target = any(token in lowered for token in cls._AUTO_BACKGROUND_LOG_PATTERNS)
        has_analysis_intent = any(token in lowered for token in cls._AUTO_BACKGROUND_ANALYSIS_PATTERNS)
        has_narrow_scope = any(token in lowered for token in cls._AUTO_BACKGROUND_NARROW_PATTERNS)
        return has_log_target and has_analysis_intent and not has_narrow_scope

    @staticmethod
    def _build_background_log_task(msg: InboundMessage) -> str:
        """Create a focused subagent task for large local log analysis."""
        scope_bits: list[str] = []
        metadata = msg.metadata or {}
        if metadata.get("case_id") or metadata.get("caseId"):
            scope_bits.append(f"case={metadata.get('case_id') or metadata.get('caseId')}")
        if metadata.get("artifact_id") or metadata.get("artifactId"):
            scope_bits.append(f"artifact={metadata.get('artifact_id') or metadata.get('artifactId')}")
        scope_text = f"Scope: {', '.join(scope_bits)}\n" if scope_bits else ""

        return (
            "Handle this as a large local log-analysis job running in the background.\n"
            f"{scope_text}"
            f"Original user request: {msg.content}\n\n"
            "Requirements:\n"
            "- Keep the foreground chat responsive.\n"
            "- Do not dump raw Windows event logs into the conversation unless strictly necessary.\n"
            "- Prefer filtered queries, counts, grouped findings, and structured summaries.\n"
            "- When showing timestamps, include both UTC and Asia/Seoul (UTC+09:00).\n"
            "- Focus on notable warnings/errors, repeated event IDs, boot/shutdown anomalies, and service or driver failures.\n"
            "- Final user-facing result should be concise, forensic, and written in Korean."
        )

    async def _process_message(
        self,
        msg: InboundMessage,
        session_key: str | None = None,
        on_progress: Callable[[str], Awaitable[None]] | None = None,
        on_stream: Callable[[str], Awaitable[None]] | None = None,
        on_stream_end: Callable[..., Awaitable[None]] | None = None,
    ) -> OutboundMessage | None:
        """Process a single inbound message and return the response."""
        # System messages: parse origin from chat_id ("channel:chat_id")
        if msg.channel == "system":
            channel, chat_id = (msg.chat_id.split(":", 1) if ":" in msg.chat_id
                                else ("cli", msg.chat_id))
            logger.info("Processing system message from {}", msg.sender_id)
            key = session_key or msg.session_key_override or f"{channel}:{chat_id}"
            session = self.sessions.get_or_create(key)
            await self.memory_consolidator.maybe_consolidate_by_tokens(session)
            self._set_tool_context(
                channel,
                chat_id,
                msg.metadata.get("message_id"),
                session_key=key,
                metadata=msg.metadata,
            )
            history = session.get_history(max_messages=0)
            current_role = "assistant" if msg.sender_id == "subagent" else "user"
            messages = self.context.build_messages(
                history=history,
                current_message=msg.content, channel=channel, chat_id=chat_id,
                current_role=current_role,
            )
            final_content, _, all_msgs = await self._run_agent_loop(
                messages, channel=channel, chat_id=chat_id,
                message_id=msg.metadata.get("message_id"),
                session_key=key,
                metadata=msg.metadata,
            )
            turn_skip = 1 + len(history)
            thinking_text, thinking_blocks = self._collect_turn_thinking(all_msgs, skip=turn_skip)
            self._save_turn(session, all_msgs, turn_skip)
            self._archive_final_answer(
                session_key=key,
                channel=channel,
                chat_id=chat_id,
                request=msg.content,
                answer=final_content or "Background task completed.",
            )
            self.sessions.save(session)
            self._schedule_background(self.memory_consolidator.maybe_consolidate_by_tokens(session))
            meta = dict(msg.metadata or {})
            if thinking_text:
                meta["thinking_text"] = thinking_text
            if thinking_blocks:
                meta["thinking_blocks"] = thinking_blocks
            return OutboundMessage(
                channel=channel,
                chat_id=chat_id,
                content=final_content or "Background task completed.",
                metadata=meta,
            )

        preview = msg.content[:80] + "..." if len(msg.content) > 80 else msg.content
        logger.info("Processing message from {}:{}: {}", msg.channel, msg.sender_id, preview)

        key = session_key or msg.session_key
        session = self.sessions.get_or_create(key)

        # Slash commands
        raw = msg.content.strip()
        ctx = CommandContext(msg=msg, session=session, key=key, raw=raw, loop=self)
        if result := await self.commands.dispatch(ctx):
            return result

        if self._should_auto_background_large_log_task(msg):
            await self.subagents.spawn(
                task=self._build_background_log_task(msg),
                label="large-log-analysis",
                origin_channel=msg.channel,
                origin_chat_id=msg.chat_id,
                session_key=key,
                metadata={**(msg.metadata or {}), "_background_task": True},
            )
            ack = (
                "대규모 시스템 로그 분석을 백그라운드로 시작했습니다. "
                "이 세션이나 다른 세션에서 계속 작업하셔도 되고, 완료되면 같은 scope로 결과를 보내드리겠습니다."
            )
            session.add_message("user", msg.content)
            session.add_message("assistant", ack)
            self.sessions.save(session)
            self._schedule_background(self.memory_consolidator.maybe_consolidate_by_tokens(session))
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=ack,
                metadata={**(msg.metadata or {}), "render_as": "text"},
            )

        await self.memory_consolidator.maybe_consolidate_by_tokens(session)

        self._set_tool_context(
            msg.channel,
            msg.chat_id,
            msg.metadata.get("message_id"),
            session_key=key,
            metadata=msg.metadata,
        )
        if message_tool := self.tools.get("message"):
            if isinstance(message_tool, MessageTool):
                message_tool.start_turn()

        history = session.get_history(max_messages=0)
        initial_messages = self.context.build_messages(
            history=history,
            current_message=msg.content,
            media=msg.media if msg.media else None,
            channel=msg.channel, chat_id=msg.chat_id,
        )

        async def _bus_progress(content: str, *, tool_hint: bool = False) -> None:
            meta = dict(msg.metadata or {})
            meta["_progress"] = True
            meta["_tool_hint"] = tool_hint
            await self.bus.publish_outbound(OutboundMessage(
                channel=msg.channel, chat_id=msg.chat_id, content=content, metadata=meta,
            ))

        final_content, _, all_msgs = await self._run_agent_loop(
            initial_messages,
            on_progress=on_progress or _bus_progress,
            on_stream=on_stream,
            on_stream_end=on_stream_end,
            channel=msg.channel, chat_id=msg.chat_id,
            message_id=msg.metadata.get("message_id"),
            session_key=key,
            metadata=msg.metadata,
        )

        if final_content is None:
            final_content = "I've completed processing but have no response to give."

        turn_skip = 1 + len(history)
        thinking_text, thinking_blocks = self._collect_turn_thinking(all_msgs, skip=turn_skip)
        self._save_turn(session, all_msgs, turn_skip)
        self._archive_final_answer(
            session_key=key,
            channel=msg.channel,
            chat_id=msg.chat_id,
            request=msg.content,
            answer=final_content,
        )

        if self.reset_session_after_answer:
            session.clear()
            self.sessions.save(session)
            self.sessions.invalidate(session.key)
        else:
            self.sessions.save(session)
            self._schedule_background(self.memory_consolidator.maybe_consolidate_by_tokens(session))

        if (mt := self.tools.get("message")) and isinstance(mt, MessageTool) and mt._sent_in_turn:
            return None

        preview = final_content[:120] + "..." if len(final_content) > 120 else final_content
        logger.info("Response to {}:{}: {}", msg.channel, msg.sender_id, preview)

        meta = dict(msg.metadata or {})
        if thinking_text:
            meta["thinking_text"] = thinking_text
        if thinking_blocks:
            meta["thinking_blocks"] = thinking_blocks
        return OutboundMessage(
            channel=msg.channel, chat_id=msg.chat_id, content=final_content,
            metadata=meta,
        )

    @staticmethod
    def _image_placeholder(block: dict[str, Any]) -> dict[str, str]:
        """Convert an inline image block into a compact text placeholder."""
        path = (block.get("_meta") or {}).get("path", "")
        return {"type": "text", "text": f"[image: {path}]" if path else "[image]"}

    def _sanitize_persisted_blocks(
        self,
        content: list[dict[str, Any]],
        *,
        truncate_text: bool = False,
        drop_runtime: bool = False,
    ) -> list[dict[str, Any]]:
        """Strip volatile multimodal payloads before writing session history."""
        filtered: list[dict[str, Any]] = []
        for block in content:
            if not isinstance(block, dict):
                filtered.append(block)
                continue

            if (
                drop_runtime
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
                and block["text"].startswith(ContextBuilder._RUNTIME_CONTEXT_TAG)
            ):
                continue

            if (
                block.get("type") == "image_url"
                and block.get("image_url", {}).get("url", "").startswith("data:image/")
            ):
                filtered.append(self._image_placeholder(block))
                continue

            if block.get("type") == "text" and isinstance(block.get("text"), str):
                text = block["text"]
                if truncate_text and len(text) > self._TOOL_RESULT_MAX_CHARS:
                    text = text[:self._TOOL_RESULT_MAX_CHARS] + "\n... (truncated)"
                filtered.append({**block, "text": text})
                continue

            filtered.append(block)

        return filtered

    def _save_turn(self, session: Session, messages: list[dict], skip: int) -> None:
        """Save new-turn messages into session, truncating large tool results."""
        from datetime import datetime
        for m in messages[skip:]:
            entry = dict(m)
            role, content = entry.get("role"), entry.get("content")
            if role == "assistant" and not content and not entry.get("tool_calls"):
                continue  # skip empty assistant messages — they poison session context
            if role == "tool":
                if isinstance(content, str) and len(content) > self._TOOL_RESULT_MAX_CHARS:
                    entry["content"] = content[:self._TOOL_RESULT_MAX_CHARS] + "\n... (truncated)"
                elif isinstance(content, list):
                    filtered = self._sanitize_persisted_blocks(content, truncate_text=True)
                    if not filtered:
                        continue
                    entry["content"] = filtered
            elif role == "user":
                if isinstance(content, str) and content.startswith(ContextBuilder._RUNTIME_CONTEXT_TAG):
                    # Strip the runtime-context prefix, keep only the user text.
                    parts = content.split("\n\n", 1)
                    if len(parts) > 1 and parts[1].strip():
                        entry["content"] = parts[1]
                    else:
                        continue
                if isinstance(content, list):
                    filtered = self._sanitize_persisted_blocks(content, drop_runtime=True)
                    if not filtered:
                        continue
                    entry["content"] = filtered
            entry.setdefault("timestamp", datetime.now().isoformat())
            session.messages.append(entry)
        session.updated_at = datetime.now()

    @staticmethod
    def _collect_turn_thinking(
        messages: list[dict[str, Any]],
        *,
        skip: int,
    ) -> tuple[str | None, list[dict] | None]:
        """Collect normalized thinking text from new assistant messages in the turn."""
        parts: list[str] = []
        blocks: list[dict] = []

        for message in messages[skip:]:
            if message.get("role") != "assistant":
                continue
            thinking_text = extract_message_thinking_text(message)
            if thinking_text:
                parts.append(thinking_text)
            thinking_blocks = message.get("thinking_blocks")
            if isinstance(thinking_blocks, list):
                blocks.extend(block for block in thinking_blocks if isinstance(block, dict))

        deduped: list[str] = []
        seen: set[str] = set()
        for part in parts:
            if part not in seen:
                deduped.append(part)
                seen.add(part)

        return ("\n\n".join(deduped) if deduped else None, blocks or None)

    def _archive_final_answer(
        self,
        *,
        session_key: str,
        channel: str,
        chat_id: str,
        request: str,
        answer: str,
    ) -> None:
        """Persist the final answer as a markdown wiki note when enabled."""
        if not self.wiki_archive:
            return
        try:
            entry = self.wiki_archive.save_final_answer(
                session_key=session_key,
                channel=channel,
                chat_id=chat_id,
                request=request,
                answer=answer,
            )
            logger.info("Archived final answer for {} to {}", session_key, entry.path)
        except Exception:
            logger.exception("Failed to archive final answer for {}", session_key)

    async def process_direct(
        self,
        content: str,
        session_key: str | None = None,
        channel: str = "cli",
        chat_id: str = "direct",
        case_id: str | None = None,
        artifact_id: str | None = None,
        on_progress: Callable[[str], Awaitable[None]] | None = None,
        on_stream: Callable[[str], Awaitable[None]] | None = None,
        on_stream_end: Callable[..., Awaitable[None]] | None = None,
    ) -> OutboundMessage | None:
        """Process a message directly and return the outbound payload."""
        await self._connect_mcp()
        metadata: dict[str, Any] = {}
        if case_id:
            metadata["case_id"] = case_id
        if artifact_id:
            metadata["artifact_id"] = artifact_id
        msg = InboundMessage(
            channel=channel,
            sender_id="user",
            chat_id=chat_id,
            content=content,
            metadata=metadata,
        )
        return await self._process_message(
            msg, session_key=session_key, on_progress=on_progress,
            on_stream=on_stream, on_stream_end=on_stream_end,
        )
