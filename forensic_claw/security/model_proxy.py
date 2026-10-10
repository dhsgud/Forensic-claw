"""Destination checks and forwarding guard for model requests carrying evidence."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

import httpx

_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
    )
)
BLOCKED_MESSAGE = (
    "증거 외부 전송을 차단했습니다. 모델 설정에서 보안 판정을 확인하고, "
    "FAIL 서버는 두 번의 경고에 동의한 뒤 저장하세요."
)


def approval_scope(endpoint: str | None, model: str) -> str:
    return hashlib.sha256(f"{endpoint or ''}\n{model}".encode()).hexdigest()


def _local_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(
        address.version == network.version and address in network for network in _LOCAL_NETWORKS
    )


def assess_endpoint(endpoint: str | None) -> dict[str, Any]:
    """PASS means a private network destination, not model-weight attestation."""
    result: dict[str, Any] = {
        "status": "FAIL",
        "reason": "유효한 HTTP(S) 모델 주소가 필요합니다.",
        "addresses": [],
        "canOverride": False,
    }
    try:
        parsed = urlsplit(endpoint or "")
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            return result
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        result["canOverride"] = True
        try:
            addresses = [str(ipaddress.ip_address(parsed.hostname))]
        except ValueError:
            addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
                }
            )
        result["addresses"] = addresses
        if addresses and all(_local_address(value) for value in addresses):
            result.update(
                status="PASS",
                reason=(
                    "Loopback·LAN·사설망/오버레이 주소로 확인했습니다. "
                    "서버 내부의 외부 API 재전송 여부까지 증명하지는 않습니다."
                ),
            )
        else:
            result["reason"] = "공인 또는 특수 주소가 포함되어 로컬 모델로 확인되지 않았습니다."
    except (OSError, ValueError):
        result["reason"] = "주소를 해석할 수 없어 로컬 모델로 확인되지 않았습니다."
    return result


class ModelSecurityProxy:
    """In-process proxy: validate and pin the destination before forwarding."""

    def __init__(self, endpoint: str | None, *, approved: bool = False) -> None:
        self.endpoint = (endpoint or "").rstrip("/")
        self.approved = approved

    def assess(self) -> dict[str, Any]:
        result = assess_endpoint(self.endpoint)
        result["approved"] = self.approved and result["canOverride"]
        result["allowed"] = result["status"] == "PASS" or result["approved"]
        return result

    def guard_request(self, request: httpx.Request) -> None:
        target = urlsplit(self.endpoint)
        actual = urlsplit(str(request.url))
        if (
            actual.scheme,
            actual.hostname,
            actual.port or (443 if actual.scheme == "https" else 80),
        ) != (
            target.scheme,
            target.hostname,
            target.port or (443 if target.scheme == "https" else 80),
        ) or not actual.path.startswith(target.path.rstrip("/") + "/"):
            raise ValueError("Model proxy rejected a changed destination")
        result = self.assess()
        if not result["allowed"] or not result["addresses"]:
            raise ValueError(BLOCKED_MESSAGE)
        # Pin this DNS result, preserve HTTP Host and TLS certificate verification.
        request.extensions["sni_hostname"] = request.url.host
        request.url = request.url.copy_with(host=result["addresses"][0])

    async def guard_async_request(self, request: httpx.Request) -> None:
        await asyncio.to_thread(self.guard_request, request)


def evidence_allowed(provider: Any) -> bool:
    proxy = getattr(provider, "security_proxy", None)
    if isinstance(proxy, ModelSecurityProxy):
        return bool(proxy.assess()["allowed"])
    endpoint = getattr(provider, "api_base", None)
    # Providers without an HTTP endpoint (including in-memory adapters) do not transmit.
    return not isinstance(endpoint, str) or assess_endpoint(endpoint)["status"] == "PASS"
