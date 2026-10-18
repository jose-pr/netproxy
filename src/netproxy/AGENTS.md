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
