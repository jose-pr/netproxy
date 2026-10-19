"""Configuration files: read a document, then build a server from it.

The file is ``netproxy.cfg``; its first line may name its format
(``#!toml``, ``#!yaml``, ``#!json``, ``#!ini``), and without one it is TOML
(see :func:`loads`). Documents are
read by anycfg. :func:`loads` and :func:`load` return plain data. :func:`build_server` turns that data into an
:class:`~netproxy.AsyncProxyServer`; :func:`load_server` does both. Relative
paths in the document are relative to the file's directory. Secrets never
live in the file: PINs and key passwords are named by environment variable
(``pin_env``, ``password_env``), read when the credential is first used.

Document shape, in TOML (every table optional)::

    [server]
    listen = "127.0.0.1:3128"            # or a list
    egress = "system"                     # "system" | "env" | "auto" | "direct" | "pac:<url>" | a proxy URL
    timeout = 30.0
    idle_timeout = 300.0
    allow_remote = false
    record = "proxy.pcap"                 # every relayed session, as a capture (extra "capture")
    keylog = "tls-keys.log"               # TLS secrets for Wireshark; a secret itself
    log_traffic = true                    # a log line per session opened and closed
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

In INI a dotted section nests (``[credentials.work]``, ``[server.ca]``),
``[rules.<name>]`` and ``[tunnels.<name>]`` are list entries in file order
with that ``name``, and values are typed: ``true``/``false`` (also
``yes``/``no``/``on``/``off``), integers, decimals, and JSON lists, objects
or strings (``match = ["*.corp.example", "corp"]``); anything else is a
string.
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

_SERVER_KEYS = {
    "listen",
    "egress",
    "timeout",
    "idle_timeout",
    "allow_remote",
    "ca",
    "keylog",
    "record",
    "log_traffic",
}
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


def _format_for(path: Optional[str]) -> Optional[str]:
    """The format a file name selects; ``.cfg`` (and no suffix) select none."""
    if not path or FilePath(path).suffix.lower() in ("", ".cfg"):
        return None
    from anycfg import formats

    found = formats.find_for_filename(FilePath(path).name)
    return found.name if found is not None else None


def loads(
    text: Union[str, bytes], *, path: Optional[str] = None, format: Optional[str] = None
) -> Dict[str, Any]:
    """Parse a configuration document into plain data. ``path`` labels errors
    and, by its suffix, may name the format.

    The format is the one a ``#!<format>`` first line names (``#!toml``,
    ``#!yaml``, ``#!json``, ``#!ini``; the line is not part of the document),
    else ``format``, else the one ``path``'s suffix selects (``.toml``,
    ``.yaml``/``.yml``, ``.json``, ``.ini``; not ``.cfg``), else TOML. An INI
    document is read as described in the module documentation. Bytes are strict UTF-8 (one leading BOM
    ignored). Raises :class:`ConfigError` with ``lineno``/``colno`` when
    known; the message never quotes the document.
    """
    import anycfg
    from anycfg import formats

    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ConfigError(f"not UTF-8 at byte {error.start}", path) from None
    if text.startswith("\ufeff"):
        text = text[1:]
    declared, _ = formats.declared(text)
    chosen = declared or format or _format_for(path) or "toml"
    try:
        if declared:
            data = anycfg.loads(text)  # removes the #! line
        else:
            data = anycfg.loads(text, format=chosen)
    except anycfg.MissingDependencyError as error:
        raise ConfigError(f"{chosen}: {error}", path) from None
    except anycfg.UnsupportedFormatError as error:
        raise ConfigError(str(error), path) from None
    except anycfg.ParseError as error:
        raise ConfigError(error.msg, path, error.lineno, error.colno) from None
    except anycfg.ConfigError as error:
        raise ConfigError(str(error), path) from None
    if formats.get(chosen).name == "ini":
        return _from_ini(data, path)
    if not isinstance(data, dict):
        raise ConfigError("the document is not a table", path)
    return data


def _ini_value(text: str) -> Any:
    stripped = text.strip()
    lowered = stripped.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if re.fullmatch(r"[+-]?\d+", stripped):
        return int(stripped)
    if re.fullmatch(r"[+-]?(\d+\.\d*|\.\d+)([eE][+-]?\d+)?", stripped):
        return float(stripped)
    if stripped[:1] in ("[", "{", '"'):
        import json

        try:
            return json.loads(stripped)
        except ValueError:
            pass
    return stripped


def _from_ini(data: Dict[str, Dict[str, str]], path: Optional[str]) -> Dict[str, Any]:
    """INI sections as the TOML document's shape (see the module documentation)."""
    out: Dict[str, Any] = {}
    for section, options in data.items():
        values = {key: _ini_value(value) for key, value in options.items()}
        parts = section.split(".")
        if parts[0] in ("rules", "tunnels"):
            if len(parts) != 2 or not parts[1]:
                raise ConfigError(
                    f"[{section}]: a {parts[0]} section is [{parts[0]}.<name>]", path
                )
            values.setdefault("name", parts[1])
            out.setdefault(parts[0], []).append(values)
            continue
        table = out
        for part in parts[:-1]:
            table = table.setdefault(part, {})
            if not isinstance(table, dict):
                raise ConfigError(f"[{section}]: {part} is not a table", path)
        if isinstance(table.get(parts[-1]), dict):
            table[parts[-1]].update(values)  # a [a.b] seen before [a]
        else:
            table[parts[-1]] = values
    return out


def load(
    source: Union[str, "os.PathLike[str]"], *, format: Optional[str] = None
) -> Dict[str, Any]:
    """Read and parse the configuration file at ``source`` (``OSError`` if
    unreadable); the format is chosen as :func:`loads` chooses it."""
    path = FilePath(source)
    return loads(path.read_bytes(), path=str(path), format=format)


def default_path() -> FilePath:
    """``NETPROXY_CONFIG``, else ``netproxy/netproxy.cfg`` in the platform's
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
    return base / "netproxy" / "netproxy.cfg"


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

        if value == "system":  # the OS's settings, whatever the environment says
            return proxylib.auto_proxy(environ={})
        if value == "env":
            return proxylib.EnvProxyConfig()
        if value == "auto":  # proxy variables when any is set, else the OS's
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
        for key in ("allow_remote", "log_traffic"):
            if key in settings and not isinstance(settings[key], bool):
                raise self.fail(f"server.{key}", "expected true or false")
        if "allow_remote" in settings:
            options["allow_remote"] = settings["allow_remote"]
        if "keylog" in settings:
            from ._server import KEYLOG_SUPPORTED

            if not KEYLOG_SUPPORTED:
                raise self.fail(
                    "server.keylog",
                    "this Python's TLS library cannot log keys (OpenSSL 1.1.1 or "
                    "later can)",
                )
            options["keylog"] = self.path(settings["keylog"], "server.keylog")
        recorders: List[Any] = []
        if settings.get("log_traffic"):
            from .recording import LogRecorder

            recorders.append(LogRecorder())
        owned: List[Any] = []
        if "record" in settings:
            from .recording import PcapRecorder

            target = self.path(settings["record"], "server.record")
            kind = "pcapng" if target.lower().endswith(".pcapng") else "pcap"
            try:
                owned.append(PcapRecorder(target, format=kind))
            except ImportError as error:
                raise self.fail("server.record", str(error)) from None
        egress = self.egress(settings.get("egress"))
        server = AsyncProxyServer(
            router,
            listen=settings.get("listen"),
            egress=egress,
            tunnels=tunnels,
            ca=self.ca(settings["ca"]) if "ca" in settings else None,
            recorders=recorders + owned,
            **options,
        )
        server._owned.extend(recorder.close for recorder in owned)
        # A PAC egress runs its script in a helper process, ended by close().
        for holder in (egress, getattr(egress, "script", None)):
            if callable(getattr(holder, "close", None)):
                server._owned.append(holder.close)
                break
        return server


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
