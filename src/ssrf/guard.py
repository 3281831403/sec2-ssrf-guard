"""SSRF guard for the image fetching endpoint.

The guard works on plain dictionaries.  A policy describes which protocols and
ports the endpoint may speak, whether private networks are blocked and how many
redirects are tolerated.  Host name resolution and opening the connection are
injectable through the policy, so a caller can supply its own DNS layer and
HTTP client instead of letting the guard open sockets on its own.

Security rules implemented here:

* a target is judged by the IP addresses it resolves to, never by the spelling
  of the host name;
* private, reserved, loopback, link-local and multicast ranges are refused;
* every redirect hop is validated on its own and the hop limit is enforced;
* the connection hook receives the very address that was validated, so the
  address cannot change between validation and use (DNS rebinding);
* unparseable targets, unresolvable hosts and empty chains fail closed;
* all checks are pure functions over the policy, so repeated calls agree.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}
SAFE_SCHEMES = frozenset({"http", "https"})

# Internal, reserved, loopback, link-local and multicast IPv4 ranges.
_BLOCKED_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),        # unspecified / reserved
    ipaddress.ip_network("10.0.0.0/8"),       # private
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("172.16.0.0/12"),    # private
    ipaddress.ip_network("192.0.0.0/24"),     # reserved
    ipaddress.ip_network("192.0.2.0/24"),     # documentation
    ipaddress.ip_network("192.168.0.0/16"),   # private
    ipaddress.ip_network("198.18.0.0/15"),    # benchmark
    ipaddress.ip_network("198.51.100.0/24"),  # documentation
    ipaddress.ip_network("203.0.113.0/24"),   # documentation
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
)

# Internal, loopback, link-local and multicast IPv6 ranges.
_BLOCKED_V6 = (
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("::1/128"),          # loopback
    ipaddress.ip_network("fe80::/10"),        # link-local
    ipaddress.ip_network("fec0::/10"),        # site-local (deprecated)
    ipaddress.ip_network("fc00::/7"),         # unique-local
    ipaddress.ip_network("ff00::/8"),         # multicast
)


def _as_ip(value: Any) -> Any:
    """Return an ipaddress object, or None when the value is not an address."""

    if value is None:
        return None
    try:
        text = str(value).strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1].strip()
        return ipaddress.ip_address(text)
    except (TypeError, ValueError):
        return None


def _v4_view(address: Any) -> Any:
    """Unwrap an IPv4-mapped IPv6 address so it is judged on its IPv4 range."""

    if address.version == 6 and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _matches(address: Any, v4_networks: tuple, v6_networks: tuple) -> bool:
    view = _v4_view(address)
    networks = v4_networks if view.version == 4 else v6_networks
    return any(view in network for network in networks)


def _scheme_list(policy: dict) -> list:
    raw = (policy or {}).get("schemes")
    if raw is None:
        return list(DEFAULT_SCHEMES)
    if isinstance(raw, str):
        raw = [item for item in raw.replace(",", " ").split() if item]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        raw = list(raw)
    else:
        return []
    return [str(item).strip().lower() for item in raw if str(item).strip()]


def _port_list(policy: dict):
    """Return allowed ports, or None when the policy puts no port restriction."""

    raw = (policy or {}).get("ports")
    if raw is None:
        return [80, 443]
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in {"", "any", "*", "all"}:
            return None
        raw = [item for item in text.replace(",", " ").split() if item]
        if not raw:
            return None
    elif isinstance(raw, (list, tuple, set, frozenset)):
        raw = list(raw)
        if not raw:
            return None
    else:
        raw = [raw]
    ports = []
    for item in raw:
        if isinstance(item, bool):
            continue
        try:
            value = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if 0 < value < 65536 and value not in ports:
            ports.append(value)
    # An explicitly configured list that contains no usable port allows nothing.
    return ports


def _clean_addresses(answers: Any) -> list:
    """Normalise a resolver answer into a list of address strings."""

    if isinstance(answers, str):
        answers = [answers]
    try:
        items = list(answers)
    except TypeError as exc:
        raise ValueError("resolver returned no address") from exc
    addresses = []
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if text and text not in addresses:
            addresses.append(text)
    if not addresses:
        raise ValueError("resolver returned no address")
    return addresses


def _resolve_addresses(host: str, resolver: Any = None) -> list:
    """Turn a host name into addresses, using the injected resolver when given.

    A literal IP is used as-is: it is the address the connection would target,
    so it is the address that has to be judged.  Host names are resolved exactly
    once per call; the returned addresses are those that get validated and used.
    """

    literal = _as_ip(host)
    if literal is not None:
        return [str(literal)]
    if callable(resolver):
        return _clean_addresses(resolver(host))
    return resolve(host)


def parse_url(url: str) -> dict:
    """Split a target into its protocol, host, port and path."""

    blank = {"ok": False, "scheme": "", "host": "", "port": 0, "path": ""}
    if not isinstance(url, str):
        return dict(blank)
    text = url.strip()
    if not text:
        return dict(blank)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text):
        # Control characters enable header/URL smuggling; refuse them outright.
        return dict(blank)
    try:
        parts = urlsplit(text)
        scheme = (parts.scheme or "").strip().lower()
        host = (parts.hostname or "").strip().lower()
        port = parts.port
    except (ValueError, UnicodeError):
        return dict(blank)
    if not scheme or not host:
        return dict(blank)
    if port is None:
        port = DEFAULT_PORTS.get(scheme, 0)
    if port is None:
        port = 0
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
    except (OSError, UnicodeError) as exc:
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
    """Return whether an address belongs to an internal or reserved range.

    Anything that is not a normal public unicast address counts as private:
    internal, reserved, loopback, link-local, multicast and unparseable values.
    """

    address = _as_ip(ip)
    if address is None:
        return True
    return _matches(address, _BLOCKED_V4, _BLOCKED_V6)


def check_scheme(url: str, policy: dict) -> bool:
    """Check the protocol and the port of one target against the policy."""

    parsed = parse_url(url)
    if not parsed["ok"]:
        return False
    scheme = parsed["scheme"]
    if scheme not in _scheme_list(policy):
        return False
    port = parsed["port"]
    if not isinstance(port, int) or not 0 < port < 65536:
        return False
    ports = _port_list(policy)
    if ports is not None and port not in ports:
        return False
    return True


def check_target(url: str, policy: dict) -> bool:
    """Decide whether one target may be fetched."""

    policy = policy or {}
    parsed = parse_url(url)
    if not parsed["ok"]:
        return False
    if not check_scheme(url, policy):
        return False
    host = parsed["host"]

    # Resolve once; these exact addresses are both judged and handed to dial.
    try:
        addresses = _resolve_addresses(host, policy.get("resolver"))
    except Exception:
        return False
    if not addresses:
        return False

    # Reaching an internal, reserved, loopback or link-local address is never
    # permitted; this does not depend on the policy flag, which only records
    # that the rule is switched on (validate_policy rejects a policy that turns
    # it off).  One internal answer is enough: DNS could hand that answer to
    # the connection even when the other answers look public.
    for raw_address in addresses:
        address = _as_ip(raw_address)
        if address is None or is_private(address):
            return False

    dial = policy.get("dial")
    if callable(dial):
        dial(addresses[0], parsed["port"])
    return True


def _max_redirects(policy: dict) -> int:
    raw = (policy or {}).get("max_redirects")
    if raw is None or isinstance(raw, bool):
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, value)


def check_redirect(chain: list, policy: dict) -> bool:
    """Decide whether a redirect chain may be followed.

    Every hop is treated as an independent target; the chain must not be empty
    and must not exceed the redirect budget of the policy.
    """

    policy = policy or {}
    if isinstance(chain, str):
        chain = [chain]
    if not isinstance(chain, (list, tuple)):
        return False
    hops = [
        item for item in chain
        if isinstance(item, str) and item.strip()
    ]
    if not hops:
        return False
    if len(hops) - 1 > _max_redirects(policy):
        return False
    for hop in hops:
        if not check_target(hop, policy):
            return False
    return True


def _port_issues(raw: Any) -> list:
    issues = []
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in {"", "any", "*", "all"}:
            return []
        items = [item for item in text.replace(",", " ").split() if item]
        if not items:
            return []
    elif isinstance(raw, (list, tuple, set, frozenset)):
        items = list(raw)
        if not items:
            return []
    else:
        items = [raw]
    for item in items:
        if isinstance(item, bool):
            issues.append("invalid port: " + str(item))
            continue
        try:
            value = int(str(item).strip())
        except (TypeError, ValueError):
            issues.append("invalid port: " + str(item))
            continue
        if not 0 < value < 65536:
            issues.append("port out of range: " + str(item))
    return issues


def validate_policy(policy: dict) -> list:
    """Return the problems found in a policy; an empty list means it is usable."""

    policy = policy or {}
    issues = []

    if not policy.get("block_private"):
        issues.append("private network blocking is not enabled")

    raw_schemes = policy.get("schemes")
    if raw_schemes is not None:
        if not isinstance(raw_schemes, (str, list, tuple, set, frozenset)):
            issues.append("schemes is not a list of protocols")
        else:
            for scheme in _scheme_list(policy):
                if scheme not in SAFE_SCHEMES:
                    issues.append("unsupported scheme: " + scheme)

    raw_ports = policy.get("ports")
    if raw_ports is not None:
        issues.extend(_port_issues(raw_ports))

    raw_redirects = policy.get("max_redirects")
    if raw_redirects is None:
        issues.append("redirect limit is missing")
    elif isinstance(raw_redirects, bool) or not isinstance(raw_redirects, int):
        issues.append("redirect limit is not an integer")
    elif raw_redirects < 0:
        issues.append("redirect limit is negative")

    for key in ("resolver", "dial"):
        hook = policy.get(key)
        if hook is not None and not callable(hook):
            issues.append(key + " is not callable")

    return issues


def ssrf_batch(urls: list, policy: dict) -> dict:
    """Validate several targets and return one verdict per target.

    Each target is resolved and judged on its own; no resolution is shared
    between entries, and repeated calls produce the same verdicts.
    """

    policy = policy or {}
    results = {}
    for url in urls or []:
        results[url] = check_target(url, policy)
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
