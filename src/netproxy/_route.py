"""Routes (what to do with a connection) and the router that picks one."""

from __future__ import annotations

import enum
import ssl
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Protocol, Tuple, Union

from ._connection import Connection
from ._credential import Credential
from .rules import parse_matcher

__all__ = [
    "Action",
    "Route",
    "Router",
    "Routing",
    "Rule",
    "RuleLike",
    "TLSSource",
    "Upstream",
]

TLSSource = Union[ssl.SSLContext, Credential]
"""A client context used as is, or a :class:`Credential` that builds one."""

Upstream = Union[str, Any, None]
"""``None``: the server's egress; a string: a proxy URL, ``"direct"``, or a
PAC result such as ``"PROXY a:3128; DIRECT"``; anything else: a proxylib
``ProxyMap`` (indexed with the destination URL)."""


class Action(enum.Enum):
    """What the proxy does with a connection."""

    DIRECT = "direct"
    """Relay bytes to the destination unchanged."""
    TLS = "tls"
    """The proxy makes the TLS connection to the destination with the route's
    client context. Plain HTTP is upgraded to HTTPS; a CONNECT tunnel is
    intercepted (the client's TLS ends at the proxy)."""
    REJECT = "reject"
    """Refuse the connection."""


@dataclass(frozen=True)
class Route:
    """The decision for one connection.

    ``tls`` is required for, and only allowed with, :attr:`Action.TLS`.
    ``upstream`` overrides the server's egress for this route (see
    :data:`Upstream`). ``name`` labels the route in logs and ``check``.
    """

    action: Action = Action.DIRECT
    tls: Optional[TLSSource] = field(default=None, repr=False)
    upstream: Upstream = None
    name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            raise TypeError(
                f"action must be an Action, not {type(self.action).__name__}"
            )
        if self.action is Action.TLS and self.tls is None:
            raise ValueError("a TLS route needs tls= (an SSLContext or a Credential)")
        if self.action is not Action.TLS and self.tls is not None:
            raise ValueError("tls= is only used by Action.TLS routes")
        if self.tls is not None and not isinstance(
            self.tls, (ssl.SSLContext, Credential)
        ):
            raise TypeError(
                f"tls must be an ssl.SSLContext or a Credential, not {type(self.tls).__name__}"
            )

    @classmethod
    def direct(cls, *, upstream: Upstream = None, name: str = "") -> "Route":
        return cls(Action.DIRECT, upstream=upstream, name=name)

    @classmethod
    def with_tls(
        cls, tls: TLSSource, *, upstream: Upstream = None, name: str = ""
    ) -> "Route":
        return cls(Action.TLS, tls=tls, upstream=upstream, name=name)

    @classmethod
    def reject(cls, *, name: str = "") -> "Route":
        return cls(Action.REJECT, name=name)


class Routing(Protocol):
    """Anything that routes connections; :class:`Router` is the built-in one."""

    def route(self, connection: Connection) -> Route: ...


@dataclass(frozen=True)
class Rule:
    """``route`` applies to connections ``match`` accepts.

    ``match`` is a :class:`~netproxy.rules.Matcher`, any callable taking a
    :class:`~netproxy.Connection`, or a pattern string for
    :func:`~netproxy.rules.parse_matcher`.
    """

    match: Any
    route: Route
    name: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.match, str):
            object.__setattr__(self, "match", parse_matcher(self.match))
        elif not callable(self.match):
            raise TypeError("match must be a Matcher, a callable or a pattern string")
        if not isinstance(self.route, Route):
            raise TypeError(f"route must be a Route, not {type(self.route).__name__}")


RuleLike = Union[Rule, Tuple[Any, Route]]


class Router:
    """Ordered rules; the first that matches decides, else ``default``.

    Thread-safe for reading; :meth:`add` is meant for set-up.
    """

    def __init__(
        self, rules: Iterable[RuleLike] = (), *, default: Optional[Route] = None
    ) -> None:
        self.default = default if default is not None else Route.direct(name="default")
        self._rules: List[Rule] = []
        for rule in rules:
            self.add(rule)

    def __repr__(self) -> str:
        return f"Router({len(self._rules)} rules, default={self.default!r})"

    @property
    def rules(self) -> Tuple[Rule, ...]:
        return tuple(self._rules)

    def add(self, rule: Union[RuleLike, Any], route: Optional[Route] = None) -> Rule:
        """Append ``rule``: a :class:`Rule`, a ``(match, route)`` pair, or
        ``add(match, route)``. Returns the stored :class:`Rule`."""
        if route is not None:
            rule = Rule(rule, route)
        elif isinstance(rule, tuple):
            rule = Rule(*rule)
        if not isinstance(rule, Rule):
            raise TypeError(
                "add() takes a Rule, a (match, route) pair, or match and route"
            )
        self._rules.append(rule)
        return rule

    def route(self, connection: Connection) -> Route:
        return self.explain(connection)[1]

    def explain(self, connection: Connection) -> Tuple[Optional[Rule], Route]:
        """The rule that matched (``None`` for the default) and its route."""
        for rule in self._rules:
            if rule.match(connection):
                return rule, rule.route
        return None, self.default
