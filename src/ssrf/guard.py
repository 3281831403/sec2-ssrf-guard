"""SSRF guard for the image fetching endpoint.

The guard works on plain dictionaries.  A policy describes which protocols and
ports the endpoint may speak, whether private networks are blocked and how many
redirects are tolerated.  Host name resolution and opening the connection are
injectable through the policy, so a caller can supply its own DNS layer and
HTTP client instead of letting the guard open sockets on its own.

The verdict is always taken on the addresses a name resolves to, never on the
spelling of the name (with the reserved ``localhost`` name as a narrow
exception).  Every resolved address has to be safe because a client may be
handed any of them.  A target is resolved exactly once and the connection hook
receives that very same validated address, which closes the DNS-rebinding gap
between judgement and dialing.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

DEFAULT_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

#: IPv4 networks that can reach a private, local, link local or reserved
#: destination.  Every one of them is refused.  The list is explicit so the
#: behaviour does not depend on the IANA tables shipped with the interpreter.
_BLOCKED_V4 = tuple(
    ipaddress.ip_network(text)
    for text in (
        "0.0.0.0/8",            # "this" network / unspecified
        "10.0.0.0/8",           # RFC1918 private
        "100.64.0.0/10",        # carrier grade NAT
        "127.0.0.0/8",          # loopback
        "169.254.0.0/16",       # link local (incl. cloud metadata)
        "172.16.0.0/12",        # RFC1918 private
        "192.0.0.0/24",         # IETF protocol assignments
        "192.0.2.0/24",         # TEST-NET-1 documentation
        "192.88.99.0/24",       # 6to4 relay anycast (deprecated)
        "192.168.0.0/16",       # RFC1918 private
        "198.18.0.0/15",        # benchmarking
        "198.51.100.0/24",      # TEST-NET-2 documentation
        "203.0.113.0/24",       # TEST-NET-3 documentation
        "224.0.0.0/4",          # multicast (224.0.0.0 - 239.255.255.255)
        "240.0.0.0/4",          # reserved / limited broadcast
    )
)

#: IPv6 equivalents of the blocked ranges above.
_BLOCKED_V6 = tuple(
    ipaddress.ip_network(text)
    for text in (
        "::/128",               # unspecified
        "::1/128",              # loopback
        "::/96",                # IPv4-compatible addresses (and the two above)
        "100::/64",             # discard-only prefix
        "2001::/23",            # IETF special assignments incl. Teredo/ORCHID
        "2001:db8::/32",        # documentation
        "2002::/16",            # 6to4
        "64:ff9b::/96",         # NAT64 well known prefix
        "fc00::/7",             # unique local
        "fe80::/10",            # link local
        "fec0::/10",            # site local (deprecated)
        "ff00::/8",             # multicast
    )
)

_ANY_PORT_WORDS = frozenset({"", "any", "*", "all"})

#: Control characters and the confusion-prone backslash may not appear in a
#: target URL.  Some HTTP stacks treat "\\" as a path separator while others do
#: not, which is a classic parser differential.
_FORBIDDEN_URL_CHARS = frozenset(chr(code) for code in range(0x20)) | {"\x7f", "\\"}

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
    except (TypeError, ValueError):
        return None


def _normalise_host(value: Any) -> str:
    """Lower case a host name and drop the root label dot."""

    return str(value or "").strip().lower().rstrip(".")


def _is_localhost_name(host: str) -> bool:
    """Whether the name is the reserved ``localhost`` name (RFC 6761)."""

    name = _normalise_host(host)
    return bool(name) and (name == "localhost" or name.endswith(".localhost"))


def _scheme_list(policy: dict) -> list:
    """Normalise the allowed scheme list.

    A missing or null ``schemes`` key falls back to http/https; an explicitly
    empty list means that no scheme is allowed.
    """

    if "schemes" not in policy or policy.get("schemes") is None:
        return list(DEFAULT_SCHEMES)
    raw = policy.get("schemes")
    if isinstance(raw, str):
        raw = [item for item in raw.replace(",", " ").split() if item]
    schemes = []
    try:
        for item in raw:
            text = str(item).strip().lower()
            if text:
                schemes.append(text)
    except TypeError:
        return []
    return schemes


def _port_list(policy: dict) -> Any:
    """Return the allowed ports.

    ``[80, 443]`` is the default; an empty list means "any port".  A malformed
    port policy yields ``None`` so callers can fail closed instead of reading
    the empty list as "any port".
    """

    if "ports" not in policy or policy.get("ports") is None:
        return [80, 443]
    raw = policy.get("ports")
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in _ANY_PORT_WORDS:
            return []
        raw = [item for item in text.replace(",", " ").split() if item]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        raw = list(raw)
    else:
        raw = [raw]
    ports: list = []
    for item in raw:
        if isinstance(item, bool):
            return None
        try:
            port = int(str(item).strip())
        except (TypeError, ValueError):
            return None
        if not 0 < port < 65536:
            return None
        if port not in ports:
            ports.append(port)
    # An explicitly empty container is the documented "no restriction" value.
    return ports


def _port_problems(raw: Any) -> list:
    """Describe every problem with a user supplied ``ports`` policy value."""

    problems: list = []
    if raw is None:
        return problems
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in _ANY_PORT_WORDS:
            return ["ports are unrestricted"]
        items = [item for item in text.replace(",", " ").split() if item]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        items = list(raw)
        if not items:
            return ["ports are unrestricted"]
    else:
        items = [raw]
    for item in items:
        if isinstance(item, bool):
            problems.append("invalid port: " + str(item))
            continue
        try:
            port = int(str(item).strip())
        except (TypeError, ValueError):
            problems.append("invalid port: " + str(item))
            continue
        if not 0 < port < 65536:
            problems.append("port out of range: " + str(item))
    return problems


def _clean_addresses(answers: Any) -> list:
    """Normalise a resolver answer into a non-empty list of strings."""

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


def _resolve_addresses(host: str, resolver: Any = None) -> list:
    """Turn a host name into addresses, using the injected resolver when given.

    A literal IP address is canonicalised and returned directly: it must never
    trigger another DNS lookup whose answer could disagree with the literal.
    """

    literal = _as_ip(host)
    if literal is not None:
        return [str(literal)]
    if callable(resolver):
        return _clean_addresses(resolver(host))
    return resolve(host)


def _lookup(host: str, policy: dict) -> list:
    return _resolve_addresses(host, policy.get("resolver"))


def parse_url(url: str) -> dict:
    """Split a target into its protocol, host, port and path."""

    if not isinstance(url, str):
        return dict(_BLANK_TARGET)
    text = url.strip()
    if not text or any(char in _FORBIDDEN_URL_CHARS for char in text):
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


def resolve(host: str) -> list:
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


def is_private(ip: str) -> bool:
    """Return whether an address belongs to an internal or reserved range.

    The predicate answers the security question "could this address reach a
    non-public destination?".  It therefore fails closed: values that are not
    recognisable addresses are reported as private.  IPv4-mapped IPv6 addresses
    are judged as their embedded IPv4 counterpart.
    """

    address = _as_ip(ip)
    if address is None:
        return True

    if address.version == 6 and address.ipv4_mapped is not None:
        return is_private(str(address.ipv4_mapped))

    networks = _BLOCKED_V4 if address.version == 4 else _BLOCKED_V6
    if any(address in network for network in networks):
        return True

    # Interpreter-table backstop: loopback, link local, multicast, reserved,
    # unspecified and anything that is not a globally reachable address.
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    )


def check_scheme(url: str, policy: dict) -> bool:
    """Check the protocol and the port of one target against the policy."""

    policy = _policy(policy)
    parsed = parse_url(url)
    if not parsed["ok"]:
        return False

    scheme = parsed["scheme"]
    if scheme not in _scheme_list(policy):
        return False

    port = parsed["port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
        return False

    allowed_ports = _port_list(policy)
    if allowed_ports is None:
        # Malformed port policy: never interpret it as "allow every port".
        return False
    if allowed_ports and port not in allowed_ports:
        return False
    return True


def check_target(url: str, policy: dict) -> bool:
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
        # One lookup per target.  The resulting list is reused for both the
        # verdict and the dial hook, so a second DNS answer cannot disagree.
        addresses = _lookup(host, policy)
    except Exception:
        # A name that cannot be resolved cannot be proven safe.
        return False
    if not addresses:
        return False

    # Every answer must be public: if one answer is internal the client could
    # be handed that address, so a mixed answer set is refused as a whole.
    for address in addresses:
        if is_private(address):
            return False

    dial = policy.get("dial")
    if callable(dial):
        dial(addresses[0], parsed["port"])
    return True


def check_redirect(chain: list, policy: dict) -> bool:
    """Decide whether a redirect chain may be followed."""

    policy = _policy(policy)
    if isinstance(chain, (str, bytes)):
        chain = [chain]
    try:
        raw_hops = list(chain or [])
    except TypeError:
        return False

    hops: list = []
    for hop in raw_hops:
        # Every hop is a standalone target; a missing/blank hop is a refusal,
        # not an entry to silently drop.
        if not isinstance(hop, str) or not hop.strip():
            return False
        hops.append(hop)
    if not hops:
        return False

    limit = policy.get("max_redirects")
    if limit is not None:
        try:
            limit_value = int(limit)
        except (TypeError, ValueError):
            return False
        if limit_value < 0 or len(hops) - 1 > limit_value:
            return False

    # Every hop, including the final destination, is validated independently.
    for hop in hops:
        if not check_target(hop, policy):
            return False
    return True


def validate_policy(policy: dict) -> list:
    """Return the problems found in a policy; an empty list means it is usable."""

    if not isinstance(policy, dict):
        return ["policy must be a dictionary"]
    issues = []

    if not policy.get("block_private"):
        issues.append("missing private network rule")

    if "ports" in policy:
        issues.extend(_port_problems(policy.get("ports")))

    if policy.get("max_redirects") is None:
        issues.append("redirects are not handled")
    else:
        limit = policy.get("max_redirects")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            issues.append("max_redirects must be a non-negative integer")

    for key in ("resolver", "dial"):
        if key in policy:
            hook = policy[key]
            if hook is not None and not callable(hook):
                issues.append(key + " must be callable")

    return issues


def ssrf_batch(urls: list, policy: dict) -> dict:
    """Validate several targets and return one verdict per target.

    Targets never share a resolution or any mutable verdict state: one
    target's DNS answer cannot influence another target's result.
    """

    policy = _policy(policy)
    if isinstance(urls, (str, bytes)):
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
            # An unhashable target cannot be its own mapping key.
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
