# netproxy

[![Version](https://img.shields.io/pypi/v/netproxy.svg)](https://pypi.org/project/netproxy/)
[![Python versions](https://img.shields.io/pypi/pyversions/netproxy.svg)](https://pypi.org/project/netproxy/)
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

## API overview

| Module | Purpose |
| --- | --- |
| `netproxy` | the server, routes, rules and credentials |
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
