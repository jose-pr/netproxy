# `netproxy` — public API header

Header-file-style reference for the `netproxy` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/netproxy>.

Import from the root `netproxy`; topic modules are named in each section.
Modules whose names start with `_` are private.

`pip install netproxy`; extra `cli` adds the `netproxy` command (`duho`).

`netproxy.__version__` is the installed distribution's version.

## Connections (`netproxy`)

```python
@dataclass(frozen=True)
class Connection:
    host: str                   # normalised: lower case, no [], no trailing dot
    port: int                   # 1-65535, else ValueError
    scheme: str = "https"       # "https" CONNECT, "http" forwarded request, "tcp" tunnel
    path: str | None = None     # forwarded HTTP only
    client: tuple[str, int] | None = None
    listener: str = ""          # name of the accepting listener
    authority: str              # property: "host:port", IPv6 bracketed
    url: str                    # property: what an upstream ProxyMap is asked
```

## Matchers (`netproxy.rules`)

Predicates on a `Connection`; frozen, hashable, real `repr`; combine with
`&`, `|`, `~` (`AllOf`, `AnyOf`, `Not`). Host patterns ignore case on every
platform; `*` matches any run of characters (dots too), `?` one character,
every other character (`[` included) is literal; a leading `.` matches the
domain and its subdomains (`NO_PROXY` style).

| Matcher | Matches when |
| --- | --- |
| `Host(*patterns)` | the host matches a glob |
| `HostRegex(pattern, flags=re.IGNORECASE)` | the whole host matches the regex |
| `Port(*ports)` | the port equals an int or lies in a `range` |
| `Scheme(*schemes)` | `connection.scheme` is listed |
| `Network(*cidrs)` | the host is an address literal inside a network (names are never resolved) |
| `Path(pattern)` | a forwarded request's path matches the regex from its start |
| `Listener(*names)` | the connection came in on a named listener |
| `ALL` | always |

`parse_matcher(text) -> Matcher` reads configuration spellings: `re:<regex>`
→ `HostRegex`; an address or CIDR → `Network`; `*` → `ALL`; anything else a
`Host` glob; a trailing `:<port>` adds `Port` (`*.corp.example:8443`).
Empty or non-string text raises `ValueError`.

## Routes and routers (`netproxy`)

```python
class Action(enum.Enum):
    DIRECT = "direct"    # relay bytes unchanged
    TLS = "tls"          # the proxy makes the TLS connection with the route's client context
    REJECT = "reject"

@dataclass(frozen=True)
class Route:
    action: Action = Action.DIRECT
    tls: ssl.SSLContext | Credential | None = None   # required for, and only with, TLS
    upstream: str | ProxyMap | None = None
    name: str = ""
    @classmethod direct(*, upstream=None, name="")
    @classmethod with_tls(tls, *, upstream=None, name="")
    @classmethod reject(*, name="")
```

`Action.TLS` means the proxy owns the TLS to the destination: a forwarded
`http://` request is upgraded to HTTPS, and a CONNECT tunnel is intercepted
(the client's TLS ends at the proxy, which needs a CA). `upstream`: `None`
uses the server's egress; a string is a proxy URL, `"direct"`, or a PAC
result (`"PROXY a:3128; DIRECT"`); any other object is a proxylib `ProxyMap`
indexed with `connection.url`.

```python
@dataclass(frozen=True)
class Rule:
    match: Matcher | Callable[[Connection], bool] | str   # str goes through parse_matcher
    route: Route
    name: str = ""

class Router:
    def __init__(self, rules: Iterable[Rule | tuple[match, Route]] = (), *, default: Route | None = None)
    default: Route                       # Route.direct(name="default") when omitted
    rules: tuple[Rule, ...]
    def add(self, rule, route=None) -> Rule
    def route(self, connection) -> Route
    def explain(self, connection) -> tuple[Rule | None, Route]
```

First matching rule wins. `Routing` is the protocol (`route(connection) ->
Route`) any replacement router implements.

## Credentials (`netproxy`)

```python
class Credential:
    def __init__(self, identity: Identity | Callable[[], Identity] | None = None, *,
                 backend: str | None = None, pem: tuple | None = None,
                 options: Mapping | None = None, query: Mapping | None = None,
                 verify=None, cafile=None, capath=None, cadata=None,
                 minimum_version=None, name: str = "")
    @classmethod from_pem(certificate, key=None, password=None, *, name="", **context_options)
    def context(self) -> ssl.SSLContext
    def invalidate(self) -> None
```

Exactly one source (else `ValueError`): an `sslcontext.Identity` (or a
callable returning one); `pem=(certificate, key, password)` for
`sslcontext.load_pem`; or `backend` (an `sslcontext.backends` name; unknown →
`ValueError` at construction) with constructor `options` (`store`, `module`,
`token`, `pin`, ...) and a `find_identity` `query` (`subject`, `thumbprint`,
`label`, ...). `verify`/`cafile`/`capath`/`cadata`/`minimum_version` go to
`sslcontext.create_context` and decide how the destination is verified.
`context()` builds on first call (keystore I/O; may block, so the server
calls it from a worker thread) and caches; failures raise
`CredentialUnavailableError` and are not cached. `invalidate()` forces a
fresh lookup (a renewed certificate).

## Reaching destinations (`netproxy.upstream`)

```python
async def connect(connection: Connection, route: Route, *, egress=None,
                  timeout: float = 30.0) -> UpstreamStream
async def resolve_upstream(connection, route, egress=None) -> list[Proxy | None]

@dataclass
class UpstreamStream:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    via: str | None      # "scheme://host:port" of the upstream proxy, None = direct
    tls: bool            # the proxy made the TLS connection
```

`connect` asks the route's `upstream` (else `egress`) for answers to
`connection.url` and tries them in order (a PAC `PROXY a; DIRECT` fails over);
`None`/`KeyError`/empty means direct. HTTP and HTTPS upstream proxies are
reached with `CONNECT` (Basic `Proxy-Authorization` from the proxy URL's
credentials; missing port → the scheme's default); SOCKS answers are skipped
as unsupported. A TLS route then upgrades the stream with its context and
SNI = `connection.host` (a `Credential` is built in a worker thread). Raises
`UpstreamError` when every answer fails (one message listing each attempt,
never proxy credentials) or the TLS handshake fails;
`CredentialUnavailableError` from the credential; `ValueError` for a REJECT
route. Connections race IPv6/IPv4 addresses (Happy Eyeballs, 250 ms).
Every `ProxyMap` lookup in the process is serialised on one lock, because
JavaScript PAC engines in proxylib 1.0 crash on concurrent use.
