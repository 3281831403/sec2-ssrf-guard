"""SSRF guard for the image fetching endpoint.

The guard works on plain dictionaries.  A policy describes which protocols and
ports the endpoint may speak, whether private networks are blocked and how many
redirects are tolerated.  Host name resolution and opening the connection are
injectable through the policy, so a caller can supply its own DNS layer and
HTTP client instead of letting the guard open sockets on its own.

The decision is always taken on the addresses a host name resolves to, never on
the spelling of the host name itself.  A host name is resolved exactly once per
checked target and the very same address list is used for the verdict and for
the connection hook, so a name that changes its answer between lookups cannot
slip past the guard.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

#: Networks that either reach the local machine, a private network or a
#: reserved range.  Anything inside them is refused.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(text)
    for text in (
        # IPv4
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        # IPv6
        "::/96",  # unspecified, loopback and IPv4-compatible addresses
        "::ffff:0:0/96",  # IPv4-mapped addresses (judged by the mapped IPv4)
        "64:ff9b::/96",  # NAT64 well known prefix
        "64:ff9b:1::/48",  # NAT64 local use prefix
        "100::/64",  # discard-only
        "2001::/23",  # Teredo, ORCHID and friends
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4
        "fc00::/7",  # unique local
        "fe80::/10",  # link local
        "fec0::/10",  # site local (deprecated)
        "ff00::/8",  # multicast
        "5f00::/16",  # SRv6
        "3fff::/20",  # documentation (RFC 9637)
    )
)

#: Characters that have no business being in a target URL.  A backslash is
#: treated as an error because some HTTP clients read it as a path separator
#: while URL parsers keep it verbatim, which is a classic parsing confusion.
_FORBIDDEN_CHARS = frozenset(chr(code) for code in range(0x20)) | {"\x7f", "\\"}

_ANY_PORT_WORDS = frozenset({"", "any", "*", "all"})

_BLANK_TARGET = {"ok": False, "scheme": "", "host": "", "port": 0, "path": ""}


def _policy(policy: Any) -> dict:
    return policy if isinstance(policy, dict) else {}


def _as_ip(value: Any) -> Any:
    """Return an ipaddress object, or None when the value is not an address."""

    try:
        text = str(value).strip()
    except Exception:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _normalise_host(value: Any) -> str:
    """Lower case a host name and drop the root label separators."""

    host = str(value or "").strip().lower()
    return host.rstrip(".")


def _is_localhost_name(host: str) -> bool:
    """Return whether a host name denotes the local machine by name."""

    name = _normalise_host(host)
    return name == "localhost" or name.endswith(".localhost")


def _scheme_list(policy: dict) -> list:
    if "schemes" not in policy or policy.get("schemes") is None:
        return list(DEFAULT_SCHEMES)
    raw = policy.get("schemes")
    if isinstance(raw, str):
        items = re.split(r"[,\s]+", raw.strip().lower())
    else:
        try:
            items = [str(item).strip().lower() for item in raw]
        except TypeError:
            return []
    return [item for item in items if item]


def _parse_ports(raw: Any) -> tuple:
    """Return ``(valid, unrestricted, ports)`` for a ``ports`` policy value."""

    if raw is None:
        return True, True, []
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in _ANY_PORT_WORDS:
            return True, True, []
        items = [item for item in re.split(r"[,\s]+", text) if item]
    else:
        try:
            items = list(raw)
        except TypeError:
            return False, False, []
    if not items:
        return True, True, []
    ports: list = []
    for item in items:
        if isinstance(item, bool):
            return False, False, []
        try:
            value = int(str(item).strip())
        except (TypeError, ValueError):
            return False, False, []
        if not 0 < value < 65536:
            return False, False, []
        if value not in ports:
            ports.append(value)
    return True, False, ports


def _port_list(policy: dict) -> Any:
    """Return the allowed ports, ``[]`` for no restriction and None if invalid."""

    if "ports" not in policy:
        return [DEFAULT_PORTS["http"], DEFAULT_PORTS["https"]]
    valid, unrestricted, ports = _parse_ports(policy.get("ports"))
    if not valid:
        return None
    return [] if unrestricted else ports


def _clean_addresses(answers: Any) -> list:
    """Turn a resolver answer into a non-empty list of address strings."""

    if isinstance(answers, (str, bytes)):
        answers = [answers]
    addresses: list = []
    try:
        items = list(answers or [])
    except TypeError:
        raise ValueError("resolver returned no address")
    for item in items:
        try:
            text = str(item).strip()
        except Exception:
            continue
        if text and text not in addresses:
            addresses.append(text)
    if not addresses:
        raise ValueError("resolver returned no address")
    return addresses


def _resolve_target(host: str, policy: dict) -> list:
    """Resolve a host name once, using the injected resolver when given.

    An address written literally is already an address: it is judged as such
    and never sent to the resolver, so a name and a literal can never disagree.
    """

    literal = _as_ip(host)
    if literal is not None:
        return [str(literal)]
    resolver = policy.get("resolver")
    if callable(resolver):
        return _clean_addresses(resolver(host))
    return resolve(host)


def parse_url(url: Any) -> dict:
    """Split a target into its protocol, host, port and path."""

    if not isinstance(url, str):
        return dict(_BLANK_TARGET)
    text = url.strip()
    if not text or any(char in _FORBIDDEN_CHARS for char in text):
        return dict(_BLANK_TARGET)
    try:
        parts = urlsplit(text)
    except ValueError:
        return dict(_BLANK_TARGET)
    scheme = (parts.scheme or "").strip().lower()
    host = _normalise_host(parts.hostname)
    if not scheme or not host:
        return dict(_BLANK_TARGET)
    if any(char.isspace() for char in host):
        return dict(_BLANK_TARGET)
    try:
        port = parts.port
    except ValueError:
        return dict(_BLANK_TARGET)
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


def resolve(host: Any) -> list:
    """Resolve a host name into a list of addresses, raising on failure."""

    literal = _as_ip(host)
    if literal is not None:
        return [str(literal)]
    name = _normalise_host(host)
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


def is_private(ip: Any) -> bool:
    """Return whether an address belongs to an internal or reserved range.

    ``True`` (blocked) is also returned for values that are not addresses at
    all, so an unparseable answer can never be mistaken for a public one.
    """

    address = _as_ip(ip)
    if address is None:
        return True
    if address.version == 6 and address.ipv4_mapped is not None:
        return is_private(str(address.ipv4_mapped))
    for network in _BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            return True
    if address.is_multicast or address.is_loopback or address.is_link_local:
        return True
    if address.is_unspecified:
        return True
    if not address.is_global:
        return True
    return False


def check_scheme(url: Any, policy: Any) -> bool:
    """Check the protocol and the port of one target against the policy."""

    policy = _policy(policy)
    parsed = parse_url(url)
    if not parsed["ok"]:
        return False
    scheme = parsed["scheme"]
    if scheme not in _scheme_list(policy):
        return False
    port = parsed["port"]
    if not isinstance(port, int) or isinstance(port, bool):
        return False
    if not 0 < port < 65536:
        return False
    allowed_ports = _port_list(policy)
    if allowed_ports is None:
        return False
    if allowed_ports and port not in allowed_ports:
        return False
    return True


def check_target(url: Any, policy: Any) -> bool:
    """Decide whether one target may be fetched."""

    policy = _policy(policy)
    parsed = parse_url(url)
    if not parsed["ok"]:
        return False
    if not check_scheme(url, policy):
        return False
    host = parsed["host"]
    if _is_localhost_name(host):
        return False
    try:
        addresses = _resolve_target(host, policy)
    except Exception:
        # A name that cannot be resolved cannot be proven safe.
        return False
    if not addresses:
        return False
    # Every answer has to be public: one private answer would let the client
    # pick it, so a mixed response is refused as a whole.
    for address in addresses:
        if is_private(address):
            return False
    dial = policy.get("dial")
    if callable(dial):
        # Hand over exactly the address that was judged, never a fresh lookup.
        dial(addresses[0], parsed["port"])
    return True


def _redirect_limit(policy: dict) -> Any:
    """Return the allowed redirect hops, or None when the value is unusable."""

    if "max_redirects" not in policy or policy.get("max_redirects") is None:
        return 0
    value = policy.get("max_redirects")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def check_redirect(chain: Any, policy: Any) -> bool:
    """Decide whether a redirect chain may be followed."""

    policy = _policy(policy)
    if isinstance(chain, str):
        chain = [chain]
    try:
        raw_hops = list(chain or [])
    except TypeError:
        return False
    hops = []
    for hop in raw_hops:
        if not isinstance(hop, str) or not hop.strip():
            return False
        hops.append(hop)
    if not hops:
        return False
    limit = _redirect_limit(policy)
    if limit is None:
        return False
    if len(hops) - 1 > limit:
        return False
    # Each hop is judged on its own, exactly like a single target.
    for hop in hops:
        if not check_target(hop, policy):
            return False
    return True


def validate_policy(policy: Any) -> list:
    """Return the problems found in a policy; an empty list means it is usable."""

    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    policy = _policy(policy)
    issues = []
    if policy.get("block_private") is not True:
        issues.append("private and reserved networks must be blocked")
    if "schemes" in policy and policy.get("schemes") is not None:
        if not _scheme_list(policy):
            issues.append("at least one protocol must be allowed")
    if "ports" in policy:
        valid, _unrestricted, _ports = _parse_ports(policy.get("ports"))
        if not valid:
            issues.append("ports must be a list of integers between 1 and 65535")
    raw_redirects = policy.get("max_redirects")
    if raw_redirects is None:
        issues.append("redirects are not handled")
    elif isinstance(raw_redirects, bool) or not isinstance(raw_redirects, int) or raw_redirects < 0:
        issues.append("max_redirects must be a non-negative integer")
    for key in ("resolver", "dial"):
        if key in policy and policy.get(key) is not None and not callable(policy.get(key)):
            issues.append(key + " must be callable")
    return issues


def ssrf_batch(urls: Any, policy: Any) -> dict:
    """Validate several targets and return one verdict per target.

    Targets never share a resolution: one target's answer must not influence
    the verdict for another one.
    """

    policy = _policy(policy)
    if isinstance(urls, str):
        urls = [urls]
    try:
        items = list(urls or [])
    except TypeError:
        return {}
    results = {}
    for url in items:
        verdict = check_target(url, dict(policy))
        try:
            results[url] = verdict
        except TypeError:
            # Unhashable input cannot be a key; key it by its text form.
            results[repr(url)] = verdict
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
