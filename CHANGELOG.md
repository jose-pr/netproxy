# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.3.0] - 2026-10-19

### Added

- Routing: `Router`, `Rule`, `Route` (direct, TLS with a client credential,
  reject; optional upstream) and matchers in `netproxy.rules` (host globs,
  regex, ports, CIDR networks, paths, listeners, combinable with `&`, `|`,
  `~`).
- `Credential`: a client certificate for mTLS from an `sslcontext` keystore
  (Windows certificate store, PKCS#11 smart cards and HSMs), an identity or
  PEM, built on first use.
- `AsyncProxyServer` / `ProxyServer`: an HTTP proxy (CONNECT, forwarded
  `http://` requests upgraded to HTTPS by rule, `/proxy.pac`), local
  `Tunnel` ports, upstream proxy chaining through a proxylib `ProxyMap` with
  failover, loopback-only unless `allow_remote=True`.
- TLS interception (`netproxy.intercept`) with a CA name-constrained to the
  intercepted hosts.
- Recording (`netproxy.recording`): a `Recorder` hook per relayed session,
  `LogRecorder`, and `PcapRecorder` (extra `capture`) writing each session
  as a TCP connection in a pcap/pcapng file; `keylog=` writes the TLS
  secrets of every TLS connection the proxy owns (OpenSSL 1.1.1 or later;
  refused where the TLS library cannot log keys).
- Configuration files (`netproxy.config`, default `netproxy/netproxy.cfg`),
  read with anycfg: TOML, or YAML (extra `yaml`), JSON or INI when the
  first line says so (`#!yaml`); INI where no TOML reader is installed.
- The `netproxy` command line
  (`run`, `check`, `pac`, `ca init`, `ca show`; extra `cli`).

### Changed

- Rewritten from scratch on `asyncio` and the standard library's `ssl`.
  Twisted, the WSGI hosting and the TOML schema of 0.2 are gone; nothing of
  the 0.2 API remains.

[Unreleased]: https://github.com/jose-pr/netproxy/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jose-pr/netproxy/releases/tag/v0.3.0
