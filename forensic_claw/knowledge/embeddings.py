"""Embedding client for local semantic search.

Embeddings are produced by an OpenAI-compatible ``/v1/embeddings`` endpoint —
the same local LLM server (LM Studio / Ollama / vLLM) used for chat. The client
degrades gracefully: when it is not configured or the endpoint fails, it returns
``None`` so callers fall back to keyword-only search instead of erroring.
"""

from __future__ import annotations

from typing import Any

from loguru import logger


class Embedder:
    """Compute text embeddings via an OpenAI-compatible endpoint."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        model: str = "",
        api_base: str = "",
        api_key: str | None = None,
        dimensions: int = 0,
        timeout: float = 30.0,
    ) -> None:
        self.enabled = bool(enabled)
        self.model = (model or "").strip()
        self.api_base = (api_base or "").strip()
        self.api_key = api_key or "not-needed"
        self.dimensions = int(dimensions or 0)
        self.timeout = float(timeout)
        self._client: Any | None = None
        self._client_base: str | None = None

    @property
    def ready(self) -> bool:
        """Whether the embedder can attempt calls (config-level readiness)."""
        return self.enabled and bool(self.model) and bool(self.api_base)

    def _get_client(self) -> Any | None:
        if not self.ready:
            return None
        if self._client is not None and self._client_base == self.api_base:
            return self._client
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - openai is a hard dependency
            logger.warning("Embeddings disabled: openai SDK unavailable: {}", exc)
            return None
        self._client = OpenAI(base_url=self.api_base, api_key=self.api_key, timeout=self.timeout)
        self._client_base = self.api_base
        return self._client

    def embed(self, texts: list[str]) -> list[list[float]] | None:
        """Return one embedding per input text, or ``None`` if unavailable.

        Never raises: any failure logs and returns ``None`` so ingestion and
        search continue in keyword-only mode.
        """
        cleaned = [text if isinstance(text, str) else str(text) for text in texts]
        if not cleaned:
            return []
        client = self._get_client()
        if client is None:
            return None
        kwargs: dict[str, Any] = {"model": self.model, "input": cleaned}
        if self.dimensions > 0:
            kwargs["dimensions"] = self.dimensions
        try:
            response = client.embeddings.create(**kwargs)
        except Exception as exc:
            logger.warning("Embedding request failed; using keyword-only search: {}", exc)
            return None
        try:
            vectors = [list(item.embedding) for item in response.data]
        except Exception as exc:  # pragma: no cover - defensive parsing
            logger.warning("Embedding response could not be parsed: {}", exc)
            return None
        if len(vectors) != len(cleaned):
            logger.warning(
                "Embedding count mismatch: got {} for {} inputs", len(vectors), len(cleaned)
            )
            return None
        return vectors

    def embed_one(self, text: str) -> list[float] | None:
        """Embed a single text, or ``None`` if unavailable."""
        result = self.embed([text])
        if not result:
            return None
        return result[0]


def create_embedder(config: Any, *, api_key: str | None = None) -> Embedder:
    """Build an :class:`Embedder` from a knowledge ``vector`` config block."""
    vector = getattr(config, "vector", None)
    if vector is None:
        return Embedder(enabled=False)
    return Embedder(
        enabled=bool(getattr(vector, "enabled", True)),
        model=getattr(vector, "model", "") or "",
        api_base=getattr(vector, "api_base", "") or "",
        api_key=api_key,
        dimensions=int(getattr(vector, "dimensions", 0) or 0),
        timeout=float(getattr(vector, "request_timeout_seconds", 30.0) or 30.0),
    )
