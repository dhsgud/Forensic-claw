"""Runtime model endpoint settings and hot-swap support."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

from forensic_claw.config.loader import save_config
from forensic_claw.config.schema import Config, ModelProfile, normalize_openai_api_base
from forensic_claw.providers.base import LLMProvider
from forensic_claw.providers.factory import create_provider
from forensic_claw.providers.registry import PROVIDERS, find_by_name

ApplyCallback = Callable[[LLMProvider, str], Awaitable[None] | None]
ProviderFactory = Callable[[Config], LLMProvider]


class RuntimeModelSettings:
    """Own model endpoint config updates for a running process."""

    def __init__(
        self,
        config: Config,
        *,
        config_path: Path | None = None,
        provider_factory: ProviderFactory = create_provider,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.provider_factory = provider_factory
        self._callbacks: list[ApplyCallback] = []

    def add_apply_callback(self, callback: ApplyCallback) -> None:
        self._callbacks.append(callback)

    def snapshot(self) -> dict[str, Any]:
        provider_name = self.config.get_provider_name()
        provider_config = self.config.get_provider()
        spec = find_by_name(provider_name) if provider_name else None
        explicit_api_base = provider_config.api_base if provider_config else None

        return {
            "provider": provider_name,
            "providerLabel": spec.label if spec else provider_name,
            "model": self.config.agents.defaults.model,
            "apiBase": self.config.get_api_base(),
            "explicitApiBase": explicit_api_base,
            "apiKeyConfigured": bool(provider_config and provider_config.api_key),
            "activeProfile": self.config.models.active_profile or None,
            "profiles": [
                {
                    "name": name,
                    "provider": profile.provider,
                    "model": profile.model,
                    "apiBase": profile.api_base,
                }
                for name, profile in sorted(self.config.models.profiles.items())
            ],
            "availableProviders": [
                {
                    "name": item.name,
                    "label": item.label,
                    "defaultApiBase": item.default_api_base or "",
                    "local": item.is_local or item.is_direct,
                }
                for item in PROVIDERS
            ],
        }

    async def apply(
        self,
        *,
        provider: str | None = None,
        model: str | None = None,
        api_base: str | None = None,
        api_base_supplied: bool = False,
        profile_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist model settings and apply them to runtime callbacks."""
        updated = self.config.model_copy(deep=True)

        if provider is not None:
            requested_provider = provider.strip()
            spec = find_by_name(requested_provider)
            if spec is None:
                compact = requested_provider.replace("-", "").replace("_", "").lower()
                spec = next((item for item in PROVIDERS if item.name == compact), None)
            if spec is None:
                raise ValueError(f"Unknown provider: {provider}")
            updated.agents.defaults.provider = spec.name

        if model is not None:
            normalized_model = model.strip()
            if not normalized_model:
                raise ValueError("Model must not be empty.")
            updated.agents.defaults.model = normalized_model

        target_provider = updated.get_provider_name()
        target_provider_config = updated.get_provider()
        if not target_provider or target_provider_config is None:
            raise ValueError("Selected provider is not configured.")

        if api_base_supplied:
            target_provider_config.api_base = normalize_openai_api_base(api_base)

        new_provider = self.provider_factory(updated)

        if profile_name is not None:
            name = self._normalize_profile_name(profile_name)
            updated.models.active_profile = name
            updated.models.profiles[name] = ModelProfile(
                provider=target_provider,
                model=updated.agents.defaults.model,
                api_base=target_provider_config.api_base,
            )

        self.config.agents = updated.agents
        self.config.providers = updated.providers
        self.config.models = updated.models
        save_config(self.config, self.config_path)

        for callback in self._callbacks:
            result = callback(new_provider, self.config.agents.defaults.model)
            if inspect.isawaitable(result):
                await result

        return self.snapshot()

    @staticmethod
    def _normalize_profile_name(name: str) -> str:
        normalized = name.strip()
        if not normalized:
            raise ValueError("Profile name must not be empty.")
        return normalized

    def save_profile(self, name: str) -> dict[str, Any]:
        """Persist the current model endpoint as a named profile."""
        profile_name = self._normalize_profile_name(name)
        provider_name = self.config.get_provider_name()
        provider_config = self.config.get_provider()
        if not provider_name or provider_config is None:
            raise ValueError("Selected provider is not configured.")

        self.config.models.active_profile = profile_name
        self.config.models.profiles[profile_name] = ModelProfile(
            provider=provider_name,
            model=self.config.agents.defaults.model,
            api_base=provider_config.api_base,
        )
        save_config(self.config, self.config_path)
        return self.snapshot()

    async def use_profile(self, name: str) -> dict[str, Any]:
        """Apply a saved named profile to the running process."""
        profile_name = self._normalize_profile_name(name)
        profile = self.config.models.profiles.get(profile_name)
        if profile is None:
            raise ValueError(f"Unknown model profile: {profile_name}")
        return await self.apply(
            provider=profile.provider,
            model=profile.model,
            api_base=profile.api_base,
            api_base_supplied=True,
            profile_name=profile_name,
        )

    async def test_connection(
        self,
        *,
        provider: str | None = None,
        api_base: str | None = None,
    ) -> dict[str, Any]:
        """Probe an OpenAI-compatible /models endpoint."""
        snapshot = self.snapshot()
        provider_name = provider or snapshot["provider"]
        spec = None
        if provider_name:
            spec = find_by_name(provider_name)
            if spec is None:
                compact = provider_name.replace("-", "").replace("_", "").lower()
                spec = next((item for item in PROVIDERS if item.name == compact), None)
            provider_name = spec.name if spec else provider_name
        if api_base is not None:
            effective_api_base = normalize_openai_api_base(api_base)
        elif provider_name != snapshot["provider"]:
            provider_config = getattr(self.config.providers, provider_name or "", None)
            effective_api_base = (
                provider_config.api_base
                if provider_config and provider_config.api_base
                else (spec.default_api_base if spec else None)
            )
        else:
            effective_api_base = snapshot["apiBase"]
        if not effective_api_base:
            return {"ok": False, "provider": provider_name, "error": "missing_api_base"}

        endpoint = f"{effective_api_base.rstrip('/')}/models"
        headers: dict[str, str] = {}
        provider_config = getattr(self.config.providers, provider_name or "", None)
        if provider_config and provider_config.api_key:
            headers["Authorization"] = f"Bearer {provider_config.api_key}"

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(endpoint, headers=headers)
            payload: dict[str, Any] = {}
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            models = [
                item.get("id")
                for item in payload.get("data", [])
                if isinstance(item, dict) and item.get("id")
            ]
            return {
                "ok": 200 <= response.status_code < 300,
                "provider": provider_name,
                "apiBase": effective_api_base,
                "status": response.status_code,
                "models": models,
                "error": None if 200 <= response.status_code < 300 else response.text[:300],
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": provider_name,
                "apiBase": effective_api_base,
                "error": str(exc),
            }
