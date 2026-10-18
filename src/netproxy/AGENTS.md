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

## The server (`netproxy`)

```python
class AsyncProxyServer:
    def __init__(self, router: Routing | None = None, *, listen=None, egress=None,
                 tunnels: Iterable[Tunnel] = (), timeout: float = 30.0,
                 idle_timeout: float | None = None, allow_remote: bool = False)
    async def start(self) -> None
    async def serve_forever(self) -> None
    async def aclose(self) -> None          # also `async with`
    addresses: list[tuple[str, int]]        # HTTP proxy listeners, ports read back
    port: int                               # first HTTP proxy port; RuntimeError before start()
    def tunnel_address(self, tunnel) -> tuple[str, int]

class ProxyServer:                          # same arguments; `with`, start(), close()
    server: AsyncProxyServer
```

`router` defaults to `Router()` (everything direct). `listen` uses the
`netimps.parse_listen` grammar (`"127.0.0.1:3128"`, a list of them);
`None` → `127.0.0.1` on a free port; `()` → no HTTP proxy listener (tunnels
only). Listening on anything but loopback raises `ValueError` unless
`allow_remote=True`: whoever reaches the proxy uses its client credentials.
`egress` is the upstream for routes that set none (a proxylib `ProxyMap` or a
proxy/PAC-result string). `timeout` bounds each connect and handshake;
`idle_timeout` ends a relayed direction silent that long. The constructor
does no I/O; `start()` binds (`OSError` when an address is taken) and is
idempotent; `aclose()` stops listening, cancels every connection and waits
for them, and is harmless twice. `ProxyServer` runs the same server on its
own event loop in a daemon thread; `start()` returns once bound or raises
what binding raised.

```python
@dataclass(frozen=True)
class Tunnel:
    listen: str              # "127.0.0.1:15432"
    target: str              # "db.corp.example:5432"; no port → ValueError
    route: Route | None = None   # None: the server's router decides
    name: str = ""           # default "tunnel:<target>"
```

A tunnel connection is a `Connection(target host, port, scheme="tcp",
listener=name)`: the router (or `route`) decides direct, TLS with a
credential (a plain TCP client gets mTLS to the target), upstream, or reject
(the client's connection is closed). Relaying passes half-closes through on
plain TCP; with TLS on either side, one direction ending ends both.

## The HTTP proxy listener

Point clients at `http://<addresses[0]>` (`HTTP_PROXY`/`HTTPS_PROXY`, a
browser, `curl -x`). Every connection through it is routed as a
`Connection` with `listener="proxy"`.

- **`CONNECT host:port`** (default port 443) → `scheme="https"`. DIRECT
  routes answer `200 Connection established` and tunnel bytes. TLS routes
  are intercepted (the proxy needs a CA; without one: `502`).
- **Absolute-form requests** (`GET http://host/path`) → `scheme="http"` or
  `"https"`, `path` set (so `Path` rules apply). The request goes out in
  origin form; a TLS route upgrades a plain `http://` request to HTTPS with
  its client credential; an `https://` request on a DIRECT route uses a
  default verifying context. Through an upstream HTTP proxy, plain HTTP is
  sent in absolute form with the upstream's `Proxy-Authorization` (many
  proxies refuse CONNECT to port 80). Hop-by-hop headers and anything the
  client's `Connection` header lists are dropped, `Host` is rewritten, the
  response carries `Connection: close`: **one request per client
  connection**. Bodies (`Content-Length` or chunked) and `Upgrade`
  (WebSocket) traffic are relayed as bytes; 1xx interim responses pass
  through.
- **`GET /proxy.pac`** (origin form, to the proxy itself) → a PAC script
  from the router (below); other local paths `404`.
- Errors: `400` malformed request, `403` REJECT, `502` destination or
  upstream unreachable / credential unavailable (the body says which, never
  a secret), `504` timeout.

## PAC files (`netproxy.pac`)

```python
def generate_pac(router: Router, proxy: str, *, egress=None) -> str
```

A `FindProxyForURL` script sending to `PROXY <proxy>` every request the
router would not send straight to its destination; a route is `DIRECT` in the
script only if the proxy itself would connect directly (DIRECT route with
upstream `"direct"`, or none and no `egress`). Rules translate in order:
`Host` → `shExpMatch`/`dnsDomainIs` (host lower-cased first), `HostRegex` →
`RegExp` (only with `re.IGNORECASE` or no flags), `Port`, `Scheme`, IPv4
`Network` → `isInNet` on address literals only, `Listener` → true for
`"proxy"`, `&`/`|`/`~`. A rule with no PAC form (`Path`, IPv6 `Network`,
custom callables) makes the script send everything not yet decided to the
proxy, which routes exactly. `TypeError` for a router that is not a
`Router`.

## TLS interception (`netproxy.intercept`)

Pass `ca=` to the server (an `sslcontext.issuing.CertificateAuthority` or an
`Interceptor`). A CONNECT whose route is `Action.TLS` is then intercepted:
the proxy connects to the destination first with the route's credential
(failure → `502` before any TLS), answers `200`, completes the client's
handshake with a leaf for the CONNECT host (ALPN `http/1.1` only), and
relays the plaintext. Clients must trust `ca.certificate`. A client that
sends bytes before reading the `200` gets `400`.

```python
class Interceptor:
    def __init__(self, ca: CertificateAuthority, *, cache_size: int = 256, leaf_days: float = 7)
    def server_context(self, host: str) -> ssl.SSLContext   # minted once, LRU-cached

def permitted_names(router: Router) -> list[str] | None
def create_ca(router: Router, common_name: str = "netproxy local CA", *,
              days: float = 3650, constrain: bool = True) -> CertificateAuthority
```

`permitted_names` lists the `Host` patterns and `Network`s that bound the
router's TLS rules (through `|` and `&`), or `None` when a TLS rule or the
default route is not bounded that way (a regex, `Path`, a callable).
`create_ca` makes a CA name-constrained to them; when they are `None` it
raises `ValueError` unless `constrain=False` (an unconstrained CA can vouch
for any site: protect its key accordingly). `Interceptor(ca)` with a non-CA
is a `TypeError`.
