from starlette.requests import Request

from sentinel.config import settings
from sentinel.core.http import get_client_ip
from typing import Any


def _request(peer: str | None, forwarded: str | None = None) -> Request:
    headers = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))

    scope: dict[str, Any] = {"type": "http", "headers": headers}
    if peer is not None:
        scope["client"] = (peer, 54321)

    return Request(scope)


def test_forwarded_header_ignored_without_trusted_proxies(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "")

    assert get_client_ip(_request("203.0.113.9", "1.2.3.4")) == "203.0.113.9"


def test_forwarded_header_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.1")

    assert get_client_ip(_request("203.0.113.9", "1.2.3.4")) == "203.0.113.9"


def test_forwarded_header_used_from_trusted_peer(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.1")

    assert get_client_ip(_request("10.0.0.1", "1.2.3.4")) == "1.2.3.4"


def test_spoofed_left_hand_entries_are_ignored(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.1")

    assert get_client_ip(_request("10.0.0.1", "6.6.6.6, 1.2.3.4")) == "1.2.3.4"


def test_chain_of_trusted_proxies_is_skipped(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.0/8")

    assert get_client_ip(_request("10.0.0.1", "1.2.3.4, 10.0.0.5")) == "1.2.3.4"


def test_garbage_in_forwarded_header_falls_back_to_peer(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.1")

    assert get_client_ip(_request("10.0.0.1", "not-an-ip")) == "10.0.0.1"


def test_missing_forwarded_header_from_trusted_peer(monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxies", "10.0.0.1")

    assert get_client_ip(_request("10.0.0.1")) == "10.0.0.1"


def test_no_client_is_unknown():
    assert get_client_ip(_request(None)) == "unknown"
