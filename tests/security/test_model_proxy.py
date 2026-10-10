import socket

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from forensic_claw.security.model_proxy import ModelSecurityProxy, assess_endpoint


@given(st.integers(min_value=0, max_value=65535))
def test_private_lan_addresses_pass_without_loopback_only_restriction(number):
    address = f"192.168.{number // 256}.{number % 256}"
    assert assess_endpoint(f"http://{address}:8080/v1")["status"] == "PASS"


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "[::1]", "10.2.3.4", "172.20.1.2", "100.100.20.3", "[fd12::4]"]
)
def test_private_and_overlay_addresses_pass(address):
    assert assess_endpoint(f"http://{address}/v1")["status"] == "PASS"


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "169.254.169.254", "0.0.0.0", "[::]", "224.0.0.1", "203.0.113.1"]
)
def test_public_and_special_destinations_fail(address):
    assert assess_endpoint(f"http://{address}/v1")["status"] == "FAIL"


def test_dns_with_any_public_address_fails_even_when_another_address_is_private(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ],
    )
    result = assess_endpoint("https://server.ts.net/v1")
    assert result["status"] == "FAIL"
    assert result["addresses"] == ["10.0.0.3", "8.8.8.8"]


def test_unknown_dns_fails_instead_of_trusting_a_local_looking_name(monkeypatch):
    def unresolved(*args, **kwargs):
        raise socket.gaierror("not found")

    monkeypatch.setattr(socket, "getaddrinfo", unresolved)
    assert assess_endpoint("http://model.local/v1")["status"] == "FAIL"


def test_proxy_pins_checked_address_and_preserves_host_and_tls_name(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.100.20.3", 443)),
        ],
    )
    request = httpx.Request("POST", "https://model.ts.net/v1/chat/completions", json={})
    ModelSecurityProxy("https://model.ts.net/v1").guard_request(request)
    assert request.url.host == "100.100.20.3"
    assert request.headers["host"] == "model.ts.net"
    assert request.extensions["sni_hostname"] == "model.ts.net"


def test_proxy_rechecks_dns_before_each_request_and_blocks_public_rebinding(monkeypatch):
    current = ["10.0.0.3"]
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (current[0], 443)),
        ],
    )
    proxy = ModelSecurityProxy("https://model.local/v1")
    assert proxy.assess()["allowed"]
    current[0] = "8.8.8.8"
    with pytest.raises(ValueError, match="외부 전송을 차단"):
        proxy.guard_request(httpx.Request("POST", "https://model.local/v1/chat/completions"))


def test_approved_remote_proxy_still_rejects_a_different_origin_or_api_path():
    proxy = ModelSecurityProxy("https://8.8.8.8/v1", approved=True)
    assert proxy.assess()["status"] == "FAIL"
    assert proxy.assess()["allowed"]
    for url in ["https://1.1.1.1/v1/chat/completions", "https://8.8.8.8/other"]:
        with pytest.raises(ValueError):
            proxy.guard_request(httpx.Request("POST", url))
