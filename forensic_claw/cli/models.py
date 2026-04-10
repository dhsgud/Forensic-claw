"""Model information helpers for the onboard wizard.

Model database / autocomplete is temporarily disabled while litellm is
being replaced.  All public function signatures are preserved so callers
continue to work without changes.
"""

from __future__ import annotations

from typing import Any

import httpx

from forensic_claw.config.schema import normalize_openai_api_base


def get_all_models() -> list[str]:
    return []


def find_model_info(model_name: str) -> dict[str, Any] | None:
    return None


def get_model_context_limit(model: str, provider: str = "auto") -> int | None:
    return None


def get_model_suggestions(partial: str, provider: str = "auto", limit: int = 20) -> list[str]:
    return []


def fetch_openai_compatible_models(api_base: str | None, timeout: float = 5.0) -> list[str]:
    """Fetch model IDs from an OpenAI-compatible `/models` endpoint."""
    base = normalize_openai_api_base(api_base)
    if not base:
        return []

    try:
        response = httpx.get(f"{base.rstrip('/')}/models", timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return []

    data = payload.get("data")
    if not isinstance(data, list):
        return []

    models: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if isinstance(model_id, str) and model_id:
            models.append(model_id)
    return models


def format_token_count(tokens: int) -> str:
    """Format token count for display (e.g., 200000 -> '200,000')."""
    return f"{tokens:,}"
