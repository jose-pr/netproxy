"""TOML configuration: read a document, then build a server from it.

:func:`loads` and :func:`load` return plain data (TOML's own dialect: no
duplicate keys, typed values). :func:`build_server` turns that data into an
:class:`~netproxy.AsyncProxyServer`; :func:`load_server` does both. Relative
paths in the document are relative to the file's directory. Secrets never
live in the file: PINs and key passwords are named by environment variable
(``pin_env``, ``password_env``), read when the credential is first used.

Document shape (every table optional)::

    [server]
    listen = "127.0.0.1:3128"            # or a list
    egress = "system"                     # "system" | "env" | "auto" | "direct" | "pac:<url>" | a proxy URL
    timeout = 30.0
    idle_timeout = 300.0
    allow_remote = false
    ca = { certificate = "ca.pem", key = "ca.key", password_env = "NETPROXY_CA_PASSWORD" }

    [credentials.work]                    # backend = "cng" | "pkcs11" | "pem"
    backend = "cng"
    options = { store = "MY" }            # the backend's constructor options
    query = { subject = "alice" }         # find_identity() criteria
    pin_env = "NETPROXY_WORK_PIN"         # or pin = "keystore": the OS dialog / PIN pad
    cafile = "corp-ca.pem"                # how the destination is verified (also verify = false)

    [[rules]]
    match = "*.corp.example"              # a pattern or a list of patterns (any of)
    port = 443                            # optional
    path = "^/api/"                       # optional regex, forwarded HTTP only
    action = "tls"                        # "tls" | "direct" | "reject"
    credential = "work"                   # required for "tls"
    upstream = "direct"                   # optional: "direct", a proxy URL or a PAC result
    name = "corp"

    [default]
    action = "direct"

    [[tunnels]]
    listen = "127.0.0.1:15432"
    target = "db.corp.example:5432"
    credential = "work"                   # optional: makes the tunnel's route TLS
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path as FilePath
from typing import Any, Dict, List, Mapping, Optional, Union

from ._credential import Credential
from ._route import Action, Route, Router
from ._server import AsyncProxyServer, Tunnel
from .exceptions import ConfigError
from .rules import AnyOf, Matcher, Path, Port, parse_matcher

__all__ = ["build_router", "build_server", "load", "load_server", "loads"]

_CONFIG_ENV = "NETPROXY_CONFIG"

_SERVER_KEYS = {"listen", "egress", "timeout", "idle_timeout", "allow_remote", "ca"}
_CA_KEYS = {"certificate", "key", "password_env"}
_CREDENTIAL_KEYS = {
    "backend",
    "options",
    "query",
    "pin_env",
    "pin",
    "certificate",
    "key",
    "password_env",
    "verify",
    "cafile",
    "capath",
}
_RULE_KEYS = {"match", "port", "path", "action", "credential", "upstream", "name"}
_DEFAULT_KEYS = {"action", "credential", "upstream", "name"}
_TUNNEL_KEYS = {"listen", "target", "credential", "action", "upstream", "name"}
_TOP_KEYS = {"server", "credentials", "rules", "default", "tunnels"}


def _toml() -> Any:
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - exercised on the 3.9/3.10 floor
        import tomli as tomllib
    return tomllib


def loads(text: Union[str, bytes], *, path: Optional[str] = None) -> Dict[str, Any]:
    """Parse TOML ``text`` into plain data. ``path`` only labels errors.

    Bytes are strict UTF-8 (one leading BOM ignored). Raises
    :class:`ConfigError` with ``lineno``/``colno`` when known; the message
    never quotes the document.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ConfigError(f"not UTF-8 at byte {error.start}", path) from None
    if text.startswith("﻿"):
        text = text[1:]
    tomllib = _toml()
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        # Python 3.14 exposes the position; before that it is only in the text,
        # as "(at line L, column C)". The text never contains document content.
        lineno = getattr(error, "lineno", None)
        colno = getattr(error, "colno", None)
        text = str(error)
        found = re.search(r"\(at line (\d+), column (\d+)\)", text)
        if lineno is None and found:
            lineno, colno = int(found.group(1)), int(found.group(2))
        reason = getattr(error, "msg", None) or re.sub(r"\s*\(at [^)]*\)$", "", text)
        raise ConfigError(reason, path, lineno, colno) from None


def load(source: Union[str, "os.PathLike[str]"]) -> Dict[str, Any]:
    """Read and parse the TOML file at ``source`` (``OSError`` if unreadable)."""
    path = FilePath(source)
    return loads(path.read_bytes(), path=str(path))


def default_path() -> FilePath:
    """``NETPROXY_CONFIG``, else ``netproxy/config.toml`` in the platform's
    configuration directory (``%APPDATA%`` on Windows, ``$XDG_CONFIG_HOME`` or
    ``~/.config`` elsewhere)."""
    configured = os.environ.get(_CONFIG_ENV)
    if configured:
        return FilePath(configured)
    if sys.platform == "win32" and os.environ.get("APPDATA"):
        base = FilePath(os.environ["APPDATA"])
    else:
        base = FilePath(
            os.environ.get("XDG_CONFIG_HOME") or FilePath.home() / ".config"
        )
    return base / "netproxy" / "config.toml"


# ---------------------------------------------------------------- building


class _Builder:
    def __init__(self, document: Mapping[str, Any], base: FilePath, label: str) -> None:
        self.document = document
        self.base = base
        self.label = label

    def fail(self, where: str, message: str) -> ConfigError:
        return ConfigError(f"{where}: {message}", self.label)

    def table(self, value: Any, where: str, keys: Optional[set]) -> Mapping[str, Any]:
        """``value`` as a table; ``keys=None`` accepts any key (backend options)."""
        if not isinstance(value, Mapping):
            raise self.fail(where, "expected a table")
        unknown = sorted(set(value) - keys) if keys is not None else []
        if unknown:
            raise self.fail(where, f"unknown key(s): {', '.join(unknown)}")
        return value

    def path(self, value: Any, where: str) -> str:
        if not isinstance(value, str) or not value:
            raise self.fail(where, "expected a path")
        candidate = FilePath(value).expanduser()
        return str(candidate if candidate.is_absolute() else self.base / candidate)

    def env_secret(self, name: Any, where: str) -> Any:
        if not isinstance(name, str) or not name:
            raise self.fail(where, "expected an environment variable name")

        def read() -> Optional[str]:
            return os.environ.get(name) or None

        return read

    def credentials(self) -> Dict[str, Credential]:
        tables = self.document.get("credentials", {})
        if not isinstance(tables, Mapping):
            raise self.fail("credentials", "expected a table of credentials")
        built = {}
        for name, value in tables.items():
            built[name] = self.credential(name, value)
        return built

    def credential(self, name: str, value: Any) -> Credential:
        where = f"credentials.{name}"
        table = self.table(value, where, _CREDENTIAL_KEYS)
        backend = table.get("backend")
        verify = table.get("verify")
        if verify is not None and not isinstance(verify, bool):
            raise self.fail(where, "verify must be true or false")
        context = {
            "verify": verify,
            "cafile": (
                self.path(table["cafile"], f"{where}.cafile")
                if "cafile" in table
                else None
            ),
            "capath": (
                self.path(table["capath"], f"{where}.capath")
                if "capath" in table
                else None
            ),
            "name": name,
        }
        if backend == "pem":
            if "certificate" not in table:
                raise self.fail(where, "a pem credential needs certificate")
            certificate = FilePath(
                self.path(table["certificate"], f"{where}.certificate")
            )
            key = table.get("key")
            password = (
                self.env_secret(table["password_env"], f"{where}.password_env")
                if "password_env" in table
                else None
            )
            try:
                key_bytes = (
                    FilePath(self.path(key, f"{where}.key")).read_bytes()
                    if key
                    else None
                )
                return Credential.from_pem(
                    certificate.read_bytes(), key_bytes, password, **context
                )
            except OSError as error:
                raise self.fail(where, f"cannot read: {error.strerror}") from None
        if not isinstance(backend, str):
            raise self.fail(where, 'backend must be "cng", "pkcs11" or "pem"')
        options = dict(self.table(table.get("options", {}), f"{where}.options", None))
        if "pin_env" in table and "pin" in table:
            raise self.fail(where, "give pin_env or pin, not both")
        if "pin_env" in table:
            read = self.env_secret(table["pin_env"], f"{where}.pin_env")
            options["pin"] = lambda request: read()
        elif "pin" in table:
            if table["pin"] != "keystore":
                raise self.fail(
                    where, 'pin may only be "keystore"; put PINs in pin_env'
                )
            from sslcontext import KEYSTORE_PROMPT

            options["pin"] = KEYSTORE_PROMPT
        query = dict(self.table(table.get("query", {}), f"{where}.query", None))
        try:
            return Credential(backend=backend, options=options, query=query, **context)
        except ValueError as error:
            raise self.fail(where, str(error)) from None

    def route(
        self,
        table: Mapping[str, Any],
        where: str,
        credentials: Mapping[str, Credential],
    ) -> Route:
        action = table.get("action", "direct")
        upstream = table.get("upstream")
        if upstream is not None and not isinstance(upstream, str):
            raise self.fail(where, "upstream must be a string")
        name = table.get("name", "")
        if action == "reject":
            return Route.reject(name=name)
        if action == "direct":
            if "credential" in table:
                raise self.fail(where, 'credential needs action = "tls"')
            return Route.direct(upstream=upstream, name=name)
        if action == "tls":
            credential = table.get("credential")
            if credential not in credentials:
                raise self.fail(where, f"unknown credential {credential!r}")
            return Route.with_tls(credentials[credential], upstream=upstream, name=name)
        raise self.fail(where, 'action must be "tls", "direct" or "reject"')

    def matcher(self, table: Mapping[str, Any], where: str) -> Matcher:
        patterns = table.get("match")
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list) or not patterns:
            raise self.fail(where, "match must be a pattern or a list of patterns")
        try:
            parts = [parse_matcher(p) for p in patterns]
            matcher: Matcher = parts[0] if len(parts) == 1 else AnyOf(tuple(parts))
            if "port" in table:
                ports = table["port"]
                ports = ports if isinstance(ports, list) else [ports]
                if not all(isinstance(p, int) for p in ports):
                    raise ValueError("port must be an integer or a list of them")
                matcher = matcher & Port(*ports)
            if "path" in table:
                matcher = matcher & Path(table["path"])
        except (ValueError, TypeError) as error:
            raise self.fail(where, str(error)) from None
        return matcher

    def router(self, credentials: Mapping[str, Credential]) -> Router:
        rules = self.document.get("rules", [])
        if not isinstance(rules, list):
            raise self.fail("rules", "expected an array of tables ([[rules]])")
        default = self.document.get("default", {})
        router = Router(
            default=self.route(
                self.table(default, "default", _DEFAULT_KEYS), "default", credentials
            )
        )
        for index, value in enumerate(rules):
            where = f"rules[{index}]"
            table = self.table(value, where, _RULE_KEYS)
            router.add(
                self.matcher(table, where), self.route(table, where, credentials)
            )
        return router

    def tunnels(self, credentials: Mapping[str, Credential]) -> List[Tunnel]:
        tables = self.document.get("tunnels", [])
        if not isinstance(tables, list):
            raise self.fail("tunnels", "expected an array of tables ([[tunnels]])")
        built = []
        for index, value in enumerate(tables):
            where = f"tunnels[{index}]"
            table = dict(self.table(value, where, _TUNNEL_KEYS))
            if "credential" in table and "action" not in table:
                table["action"] = "tls"
            route = (
                self.route(table, where, credentials)
                if {"action", "credential", "upstream"} & set(table)
                else None
            )
            try:
                built.append(
                    Tunnel(
                        table.get("listen", ""),
                        table.get("target", ""),
                        route,
                        table.get("name", ""),
                    )
                )
            except (ValueError, TypeError) as error:
                raise self.fail(where, str(error)) from None
        return built

    def egress(self, value: Any) -> Any:
        if value is None or value == "direct":
            return None
        if not isinstance(value, str):
            raise self.fail("server.egress", "expected a string")
        import proxylib

        if value == "system":
            return proxylib.system_proxy()
        if value == "env":
            return proxylib.EnvProxyConfig.from_env()
        if value == "auto":
            return proxylib.auto_proxy()
        if value.startswith("pac:"):
            return proxylib.load_pac(value[4:])
        return value

    def ca(self, value: Any) -> Any:
        table = self.table(value, "server.ca", _CA_KEYS)
        from sslcontext.issuing import CertificateAuthority

        password = (
            self.env_secret(table["password_env"], "server.ca.password_env")
            if "password_env" in table
            else None
        )
        try:
            certificate = FilePath(
                self.path(table.get("certificate"), "server.ca.certificate")
            )
            key = FilePath(self.path(table.get("key"), "server.ca.key"))
            return CertificateAuthority(
                certificate.read_bytes(), key.read_bytes(), password
            )
        except OSError as error:
            raise self.fail("server.ca", f"cannot read: {error.strerror}") from None

    def server(self) -> AsyncProxyServer:
        unknown = sorted(set(self.document) - _TOP_KEYS)
        if unknown:
            raise self.fail("document", f"unknown table(s): {', '.join(unknown)}")
        credentials = self.credentials()
        router = self.router(credentials)
        tunnels = self.tunnels(credentials)
        settings = self.table(self.document.get("server", {}), "server", _SERVER_KEYS)
        options: Dict[str, Any] = {}
        for key in ("timeout", "idle_timeout"):
            if key in settings:
                if not isinstance(settings[key], (int, float)) or settings[key] <= 0:
                    raise self.fail(
                        f"server.{key}", "expected a positive number of seconds"
                    )
                options[key] = float(settings[key])
        if "allow_remote" in settings:
            if not isinstance(settings["allow_remote"], bool):
                raise self.fail("server.allow_remote", "expected true or false")
            options["allow_remote"] = settings["allow_remote"]
        return AsyncProxyServer(
            router,
            listen=settings.get("listen"),
            egress=self.egress(settings.get("egress")),
            tunnels=tunnels,
            ca=self.ca(settings["ca"]) if "ca" in settings else None,
            **options,
        )


def build_router(
    document: Mapping[str, Any],
    *,
    base_dir: Union[str, "os.PathLike[str]", None] = None,
) -> Router:
    """The :class:`~netproxy.Router` the document's rules and default describe."""
    builder = _Builder(document, FilePath(base_dir or "."), "<document>")
    return builder.router(builder.credentials())


def build_server(
    document: Mapping[str, Any],
    *,
    base_dir: Union[str, "os.PathLike[str]", None] = None,
    label: str = "<document>",
) -> AsyncProxyServer:
    """An :class:`~netproxy.AsyncProxyServer` for ``document`` (from :func:`loads`).

    Raises :class:`ConfigError` naming the table and key at fault, or
    ``OSError`` for an egress PAC that cannot be fetched.
    """
    return _Builder(document, FilePath(base_dir or "."), label).server()


def load_server(source: Union[str, "os.PathLike[str]"]) -> AsyncProxyServer:
    """:func:`load` then :func:`build_server`, paths relative to the file."""
    path = FilePath(source)
    return build_server(load(path), base_dir=path.parent, label=str(path))
