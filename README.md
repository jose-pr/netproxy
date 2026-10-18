# netproxy

[![Version](https://img.shields.io/pypi/v/netproxy.svg)](https://pypi.org/project/netproxy/)
[![Python versions](https://img.shields.io/pypi/pyversions/netproxy.svg)](https://pypi.org/project/netproxy/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jose-pr/netproxy/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://jose-pr.github.io/netproxy/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/netproxy/test.yml)](https://github.com/jose-pr/netproxy/actions/workflows/test.yml)

A local proxy server library in pure Python where **rules decide, per
destination, whether to connect with a client certificate and which one**.
Client certificates can live in the Windows certificate store, on a smart card
or in an HSM (via [`sslcontext`](https://github.com/jose-pr/sslcontext)), so
tools that cannot do mutual TLS reach mTLS-only services through it.
Documentation: <https://jose-pr.github.io/netproxy/>.

## Features

- **Rule routing** — glob and regex host rules, ports, networks and paths
  pick a route per connection: tunnel directly, originate TLS with a
  credential, chain through an upstream proxy, or reject.
- **mTLS from any keystore** — a route's credential is an `ssl.SSLContext`
  you build, or a keystore query resolved by `sslcontext`.
- **Three ways in** — an HTTP proxy (CONNECT and plain HTTP, upgraded to
  HTTPS when a rule says so), local tunnel ports, and optional TLS
  interception with a name-constrained local CA.
- **Recording** — every session as a capture Wireshark follows (plaintext
  for the TLS the proxy owns), a TLS key log, or your own `Recorder`.
- **Upstream proxies** — chain through a corporate proxy chosen by
  [`proxylib`](https://github.com/jose-pr/proxylib) (PAC, environment,
  system settings).

## Installation

```bash
pip install netproxy
```

| Extra | Adds | Needed for |
| --- | --- | --- |
| `cli` | `duho` | the `netproxy` command |
| `capture` | `pktcap` | `PcapRecorder`: sessions written as a pcap/pcapng capture |

## Quick start

A configuration file routes `*.corp.example` through a client certificate
from the Windows store; everything else goes direct:

```toml
[server]
listen = "127.0.0.1:3128"

[credentials.work]
backend = "cng"
query = { subject = "alice" }

[[rules]]
match = "*.corp.example"
action = "tls"
credential = "work"
```

```bash
netproxy run -c netproxy.toml
curl -x http://127.0.0.1:3128 http://api.corp.example/   # sent as HTTPS with alice's certificate
```

The same from Python:

```python
import asyncio
from netproxy import AsyncProxyServer, Credential, Route, Router

work = Credential(backend="cng", query={"subject": "alice"})
router = Router([("*.corp.example", Route.with_tls(work))])

async def main():
    async with AsyncProxyServer(router, listen="127.0.0.1:3128") as server:
        await server.serve_forever()

asyncio.run(main())
```

## Command line

```bash
netproxy run -c netproxy.toml          # serve
netproxy check -c netproxy.toml https://api.corp.example/   # which rule and route, no connection
netproxy pac -c netproxy.toml          # PAC script for browsers
netproxy ca init -c netproxy.toml      # local CA for intercepting https:// clients
```

## API overview

| Module | Purpose |
| --- | --- |
| `netproxy` | the server, routes, rules and credentials |
| `netproxy.rules` | matchers: host globs, regex, ports, networks, paths |
| `netproxy.upstream` | reaching destinations directly or through upstream proxies |
| `netproxy.intercept` | TLS interception with a name-constrained local CA |
| `netproxy.recording` | recorders: a hook per session, a log, pcap files |
| `netproxy.pac` | PAC scripts generated from the rules |
| `netproxy.config` | TOML configuration files |
| `netproxy.exceptions` | the package's errors |

## Development

```bash
dotagents pyvenv && dotagents pyvenv 3.9
.pyvenv/<tag>/Scripts/python -m pip install -e ../sslcontext -e ".[dev]"
.pyvenv/<tag>/Scripts/python -m pytest -q -rs
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/jose-pr/netproxy/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow: test gate → build
(checking the tag names the version built) → a strict docs build as a gate →
GitHub release → publish. The release workflow never deploys the docs site
itself: for a final release its last job dispatches the docs workflow at the
tag, which owns every Pages deploy.

## License

MIT — see [LICENSE](https://github.com/jose-pr/netproxy/blob/main/LICENSE).
