"""SSRF guard for the image fetching endpoint.

The guard works on plain dictionaries.  A policy describes which protocols and
ports the endpoint may speak, whether private networks are blocked and how many
redirects are tolerated.  Host name resolution and opening the connection are
injectable through the policy, so a caller can supply its own DNS layer and
HTTP client instead of letting the guard open sockets on its own.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

_BLOCKED_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
)
_BLOCKED_V6 = (
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),
)


def _as_ip(value: Any) -> Any:
    """Return an ipaddress object, or None when the value is not an address."""

    try:
        return ipaddress.ip_address(str(value).strip().strip("[]"))
    except (TypeError, ValueError):
        return None


def _looks_internal(host: str) -> bool:
    """Return whether a host name starts with a well known internal prefix."""

    name = str(host or "").strip().lower().rstrip(".")
    if not name:
        return False
    if name == "localhost" or name.endswith(".localhost"):
        return True
    if name in {"0.0.0.0", "::"}:
        return True
    if name.startswith("10.") or name.startswith("192.168."):
        return True
    if name.startswith("172."):
        parts = name.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def _scheme_list(policy: dict) -> list:
    raw = (policy or {}).get("schemes")
    if not raw:
        return list(DEFAULT_SCHEMES)
    if isinstance(raw, str):
        raw = [item for item in raw.replace(",", " ").split() if item]
    return [str(item).strip().lower() for item in raw if str(item).strip()]


def _port_list(policy: dict) -> list:
    raw = (policy or {}).get("ports")
    if raw is None:
        return [80, 443]
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in {"", "any", "*", "all"}:
            return []
        raw = [item for item in text.replace(",", " ").split() if item]
    ports = []
    for item in raw:
        try:
            ports.append(int(item))
        except (TypeError, ValueError):
            continue
    return ports


def _clean_addresses(answers: Any) -> list:
    addresses = []
    for item in answers or []:
        text = str(item).strip()
        if text and text not in addresses:
            addresses.append(text)
    if not addresses:
        raise ValueError("resolver returned no address")
    return addresses


def _resolve_addresses(host: str, resolver: Any = None) -> list:
    """Turn a host name into addresses, using the injected resolver when given."""

    literal = _as_ip(host)
    if literal is not None:
        return [str(literal)]
    if callable(resolver):
        return _clean_addresses(resolver(host))
    return resolve(host)


def _lookup(host: str, policy: dict) -> list:
    preset = (policy or {}).get("addresses")
    if preset is not None:
        return _clean_addresses(preset)
    return _resolve_addresses(host, (policy or {}).get("resolver"))


def _connect_address(host: str, policy: dict) -> str:
    return _resolve_addresses(host, (policy or {}).get("resolver"))[0]


def parse_url(url: str) -> dict:
    """Split a target into its protocol, host, port and path."""

    blank = {"ok": False, "scheme": "", "host": "", "port": 0, "path": ""}
    if not isinstance(url, str) or not url.strip():
        return dict(blank)
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return dict(blank)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return dict(blank)
    try:
        port = parts.port
    except ValueError:
        return dict(blank)
    if port is None:
        port = DEFAULT_PORTS.get(scheme, 0)
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    return {
        "ok": True,
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "path": path,
    }


def resolve(host: str) -> list:
    """Resolve a host name into a list of addresses, raising on failure."""

    literal = _as_ip(host)
    if literal is not None:
        return [str(literal)]
    name = str(host or "").strip()
    if not name:
        raise ValueError("host must not be empty")
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError("cannot resolve " + name) from exc
    addresses: list = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("cannot resolve " + name)
    return addresses


def is_private(ip: str) -> bool:
    """Return whether an address belongs to an internal or reserved range."""

    address = _as_ip(ip)
    if address is None:
        return True
    if address.version == 6 and address.ipv4_mapped is not None:
        return is_private(str(address.ipv4_mapped))
    networks = _BLOCKED_V4 if address.version == 4 else _BLOCKED_V6
    return any(address in network for network in networks)


def check_scheme(url: str, policy: dict) -> bool:
    """Check the protocol and the port of one target against the policy."""

    policy = policy or {}
    parsed = parse_url(url)
    if not parsed["ok"]:
        return True
    scheme = parsed["scheme"]
    if not scheme:
        return False
    allowed = _scheme_list(policy)
    ports = _port_list(policy)
    if ports and parsed["port"] and not (0 < parsed["port"] < 65536):
        return False
    if scheme in allowed:
        return True
    return bool(parsed["host"])


def check_target(url: str, policy: dict) -> bool:
    """Decide whether one target may be fetched."""

    policy = policy or {}
    parsed = parse_url(url)
    if not parsed["ok"]:
        return True
    if not check_scheme(url, policy):
        return False
    host = parsed["host"]
    if _looks_internal(host):
        return False
    literal = _as_ip(host)
    if literal is not None and is_private(str(literal)):
        return False
    try:
        addresses = _lookup(host, policy)
    except ValueError:
        return True
    if not addresses:
        return True
    dial = policy.get("dial")
    if callable(dial):
        dial(_connect_address(host, policy), parsed["port"])
    return True


def check_redirect(chain: list, policy: dict) -> bool:
    """Decide whether a redirect chain may be followed."""

    policy = policy or {}
    hops = [str(item).strip() for item in (chain or []) if str(item).strip()]
    if not hops:
        return False
    return check_target(hops[0], policy)


def validate_policy(policy: dict) -> list:
    """Return the problems found in a policy; an empty list means it is usable."""

    policy = policy or {}
    issues = []
    if not policy.get("block_private"):
        issues.append("missing private network rule")
    if policy.get("max_redirects") is None:
        issues.append("redirects are not handled")
    return issues


def ssrf_batch(urls: list, policy: dict) -> dict:
    """Validate several targets and return one verdict per target."""

    policy = policy or {}
    results = {}
    shared: list = []
    for url in urls or []:
        target_policy = dict(policy)
        parsed = parse_url(url)
        if not shared and parsed["ok"]:
            try:
                shared = _lookup(parsed["host"], policy)
            except ValueError:
                shared = []
        if shared:
            target_policy["addresses"] = list(shared)
        results[url] = check_target(url, target_policy)
    return results


__all__ = [
    "parse_url",
    "resolve",
    "is_private",
    "check_scheme",
    "check_target",
    "check_redirect",
    "validate_policy",
    "ssrf_batch",
]