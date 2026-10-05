import ipaddress
from functools import lru_cache

from fastapi import Request

from sentinel.config import settings

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=8)
def _parse_trusted(raw: str) -> tuple[_Network, ...]:
    return tuple(
        ipaddress.ip_network(item.strip(), strict=False)
        for item in raw.split(",")
        if item.strip()
    )


def _is_trusted(address: str, networks: tuple[_Network, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    return any(ip in network for network in networks)


def get_client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"

    peer = request.client.host
    trusted = _parse_trusted(settings.trusted_proxies)

    if not trusted or not _is_trusted(peer, trusted):
        return peer

    forwarded = request.headers.get("x-forwarded-for")

    if not forwarded:
        return peer

    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]

    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer

        if not _is_trusted(hop, trusted):
            return hop

    return hops[0] if hops else peer
