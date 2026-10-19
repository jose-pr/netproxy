# netproxy

**A local proxy server where rules decide, per destination, whether to connect
with a client certificate and which one.** Client certificates can live in the
Windows certificate store, on a smart card or in an HSM (through
[sslcontext](https://github.com/jose-pr/sslcontext)), so tools that cannot do
mutual TLS (curl without the right build, a browser without the card's
middleware, a script) reach mTLS-only services through it. Pure Python on
asyncio and the standard `ssl` module; upstream proxies come from
[proxylib](https://github.com/jose-pr/proxylib) (PAC, WPAD, system settings).

## Installation

```bash
pip install netproxy
```

Requires Python 3.9 or newer.

| Extra | Adds | Needed for |
| --- | --- | --- |
| `cli` | `duho` | the `netproxy` command |
| `yaml` | `anycfg[yaml]` (PyYAML) | configuration files written in YAML (`#!yaml`, `.yaml`) |
| `capture` | `pktcap` | `PcapRecorder`: sessions written as a pcap/pcapng capture |

## 30-second tour

A configuration file routes `*.corp.example` through a client certificate from
the Windows store; everything else goes direct:

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
netproxy run -c netproxy.cfg
curl -x http://127.0.0.1:3128 http://api.corp.example/   # sent as HTTPS with alice's certificate
netproxy check -c netproxy.cfg https://api.corp.example/  # which rule decides, without connecting
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

## Learn more

- [The API header](header.md): every public name, its contract and gotchas,
  the configuration file and the command line.
- [API reference](api/reference.md), generated from the docstrings.
- [Changelog](changelog.md)
