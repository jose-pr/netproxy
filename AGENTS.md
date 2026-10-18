# netproxy — contributor orientation

| Shipped header | Covers |
| --- | --- |
| [`src/netproxy/AGENTS.md`](src/netproxy/AGENTS.md) | the whole public API |

## Layout

- `src/netproxy/` — the package; `cli/` is the command line (extra `cli`).
- `tests/` — loopback tests; `tests/data/` is a throwaway test PKI (CA,
  server, RSA and P-256 clients), never real credentials.

## Environment

One venv per interpreter in `.pyvenv/<version>-<os>-<arch>/`
(`dotagents pyvenv`, `dotagents pyvenv 3.9`). `sslcontext` 2.x is not
released yet: install the sibling checkout editable.

```bash
.pyvenv/<tag>/Scripts/python -m pip install -e ../sslcontext -e ".[dev]"
```

## Checks

```bash
.pyvenv/<tag>/Scripts/python -m pytest -q -rs
.pyvenv/<tag>/Scripts/black --check src tests
```

## Conventions

- Every socket in tests binds 127.0.0.1 port 0; nothing reaches the network.
- The library configures no logging and installs no signal handlers; the
  command line does both.

## Releasing

Tag `vX.Y.Z` after the changelog entry and the version bump land together;
the release workflow does the rest.
