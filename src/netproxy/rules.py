"""Matchers: predicates on a :class:`~netproxy.Connection`, combinable with ``&``, ``|``, ``~``.

Host patterns mean the same everywhere in this module: matching ignores case
on every platform, ``*`` matches any run of characters (dots included), ``?``
one character, and every other character, ``[`` included, is literal. A
pattern starting with ``.`` matches that domain and its subdomains, as in
``NO_PROXY``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Tuple, Union

from netimps import IPNetwork, parse, split_host, try_parse

from ._connection import Connection, normalize_host

__all__ = [
    "ALL",
    "AllOf",
    "AnyOf",
    "Host",
    "HostRegex",
    "Listener",
    "Matcher",
    "Network",
    "Not",
    "Path",
    "Port",
    "Scheme",
    "parse_matcher",
]


class Matcher:
    """A predicate on a connection. Subclasses implement :meth:`matches`."""

    def matches(self, connection: Connection) -> bool:
        raise NotImplementedError

    def __call__(self, connection: Connection) -> bool:
        return self.matches(connection)

    def __and__(self, other: "Matcher") -> "Matcher":
        return AllOf((self, other))

    def __or__(self, other: "Matcher") -> "Matcher":
        return AnyOf((self, other))

    def __invert__(self) -> "Matcher":
        return Not(self)


@dataclass(frozen=True)
class _All(Matcher):
    def matches(self, connection: Connection) -> bool:
        return True

    def __repr__(self) -> str:
        return "ALL"


ALL: Matcher = _All()
"""Matches every connection."""


def _glob(pattern: str) -> "re.Pattern[str]":
    pattern = normalize_host(pattern)
    if pattern.startswith("."):
        domain = re.escape(pattern[1:])
        return re.compile(f"(?:.*\\.)?{domain}", re.IGNORECASE)
    body = "".join(
        ".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern
    )
    return re.compile(body, re.IGNORECASE)


@dataclass(frozen=True)
class Host(Matcher):
    """The host matches any of the glob ``patterns`` (see the module notes).

    ``Host("*.corp.example")`` matches subdomains only;
    ``Host(".corp.example")`` the domain and its subdomains.
    """

    patterns: Tuple[str, ...]
    _compiled: Tuple["re.Pattern[str]", ...] = field(
        init=False, repr=False, compare=False
    )

    def __init__(self, *patterns: str) -> None:
        if not patterns or not all(isinstance(p, str) and p for p in patterns):
            raise ValueError("Host needs one or more non-empty patterns")
        object.__setattr__(self, "patterns", tuple(patterns))
        object.__setattr__(self, "_compiled", tuple(_glob(p) for p in patterns))

    def matches(self, connection: Connection) -> bool:
        return any(p.fullmatch(connection.host) for p in self._compiled)

    def __repr__(self) -> str:
        return f"Host({', '.join(map(repr, self.patterns))})"


@dataclass(frozen=True)
class HostRegex(Matcher):
    """The whole host matches ``pattern`` (case-insensitive unless ``flags`` says)."""

    pattern: str
    flags: int = re.IGNORECASE
    _compiled: "re.Pattern[str]" = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_compiled", re.compile(self.pattern, self.flags))

    def matches(self, connection: Connection) -> bool:
        return self._compiled.fullmatch(connection.host) is not None


@dataclass(frozen=True)
class Port(Matcher):
    """The destination port is one of ``ports`` (ints or ``range`` objects)."""

    ports: Tuple[Union[int, range], ...]

    def __init__(self, *ports: Union[int, range]) -> None:
        if not ports:
            raise ValueError("Port needs one or more ports")
        object.__setattr__(self, "ports", tuple(ports))

    def matches(self, connection: Connection) -> bool:
        return any(
            connection.port in p if isinstance(p, range) else connection.port == p
            for p in self.ports
        )

    def __repr__(self) -> str:
        return f"Port({', '.join(map(repr, self.ports))})"


@dataclass(frozen=True)
class Scheme(Matcher):
    """The connection's scheme (``https``, ``http``, ``tcp``) is one of ``schemes``."""

    schemes: Tuple[str, ...]

    def __init__(self, *schemes: str) -> None:
        if not schemes:
            raise ValueError("Scheme needs one or more schemes")
        object.__setattr__(self, "schemes", tuple(s.lower() for s in schemes))

    def matches(self, connection: Connection) -> bool:
        return connection.scheme in self.schemes

    def __repr__(self) -> str:
        return f"Scheme({', '.join(map(repr, self.schemes))})"


@dataclass(frozen=True)
class Network(Matcher):
    """The host is an IP address inside one of ``networks``.

    Names are never resolved: ``Network`` only matches destinations given as
    address literals.
    """

    networks: Tuple[IPNetwork, ...]

    def __init__(self, *networks: Union[str, IPNetwork]) -> None:
        if not networks:
            raise ValueError("Network needs one or more networks")
        object.__setattr__(
            self, "networks", tuple(parse(n, IPNetwork) for n in networks)
        )

    def matches(self, connection: Connection) -> bool:
        address = try_parse(connection.host)
        return address is not None and any(
            address.version == n.version and address in n for n in self.networks
        )

    def __repr__(self) -> str:
        return f"Network({', '.join(repr(str(n)) for n in self.networks)})"


@dataclass(frozen=True)
class Path(Matcher):
    """A forwarded HTTP request's path matches the regex ``pattern`` from its
    start. Never matches CONNECT or tunnel connections, which have no path."""

    pattern: str
    _compiled: "re.Pattern[str]" = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_compiled", re.compile(self.pattern))

    def matches(self, connection: Connection) -> bool:
        return connection.path is not None and bool(
            self._compiled.match(connection.path)
        )


@dataclass(frozen=True)
class Listener(Matcher):
    """The connection arrived on a listener named in ``names``."""

    names: Tuple[str, ...]

    def __init__(self, *names: str) -> None:
        object.__setattr__(self, "names", tuple(names))

    def matches(self, connection: Connection) -> bool:
        return connection.listener in self.names

    def __repr__(self) -> str:
        return f"Listener({', '.join(map(repr, self.names))})"


@dataclass(frozen=True)
class AllOf(Matcher):
    """Every matcher in ``matchers`` matches."""

    matchers: Tuple[Matcher, ...]

    def matches(self, connection: Connection) -> bool:
        return all(m(connection) for m in self.matchers)

    def __and__(self, other: Matcher) -> Matcher:
        return AllOf(self.matchers + (other,))


@dataclass(frozen=True)
class AnyOf(Matcher):
    """At least one matcher in ``matchers`` matches."""

    matchers: Tuple[Matcher, ...]

    def matches(self, connection: Connection) -> bool:
        return any(m(connection) for m in self.matchers)

    def __or__(self, other: Matcher) -> Matcher:
        return AnyOf(self.matchers + (other,))


@dataclass(frozen=True)
class Not(Matcher):
    """``matcher`` does not match."""

    matcher: Matcher

    def matches(self, connection: Connection) -> bool:
        return not self.matcher(connection)

    def __invert__(self) -> Matcher:
        return self.matcher


def parse_matcher(text: str) -> Matcher:
    """A matcher from one rule string, as configuration files spell them.

    ``re:<regex>`` is a :class:`HostRegex`; an address or CIDR network
    (``10.0.0.0/8``) a :class:`Network`; ``*`` is :data:`ALL`; anything else a
    :class:`Host` glob. A trailing ``:<port>`` (``*.corp.example:8443``)
    adds a :class:`Port`.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("a rule pattern must be a non-empty string")
    text = text.strip()
    if text.startswith("re:"):
        return HostRegex(text[3:])
    if text == "*":
        return ALL
    if try_parse(text, IPNetwork) is not None:
        return Network(text)
    host, port = split_host(text)
    matcher: Matcher = Network(host) if try_parse(host, IPNetwork) else Host(host)
    return matcher & Port(port) if port is not None else matcher
