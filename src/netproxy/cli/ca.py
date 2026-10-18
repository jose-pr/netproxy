"""``netproxy ca``: create and show the interception CA."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from duho import Cmd, CommandError

from ..config import build_router
from ..intercept import create_ca
from ._common import ConfigCommand

__all__ = ["Ca", "CaInit", "CaShow"]


class _CaFiles(ConfigCommand):
    def files(self) -> Tuple[Path, Path, str]:
        """The certificate and key paths, and the key password variable, from
        the configuration's ``[server.ca]``."""
        document = self.document()
        table = document.get("server", {}).get("ca")
        if (
            not isinstance(table, dict)
            or "certificate" not in table
            or "key" not in table
        ):
            raise CommandError(
                "the configuration has no [server.ca] with certificate and key paths", 2
            )
        base = self.config_path().parent
        certificate = base / Path(table["certificate"]).expanduser()
        key = base / Path(table["key"]).expanduser()
        return certificate, key, table.get("password_env", "")


class CaInit(_CaFiles):
    """Create the interception CA, name-constrained to the hosts the TLS rules intercept, at the paths in [server.ca]."""

    _parsername_ = "init"
    # Writes a private key: never by accident through a tool call.
    _mcp_ = False

    force: bool = False
    "Replace an existing CA. Omitted: refuse to overwrite"
    ("--force",)

    unconstrained: bool = False
    "Allow a CA without name constraints when the rules cannot bound it (it can then vouch for any site)"
    ("--unconstrained",)

    def __call__(self) -> int:
        certificate, key, password_env = self.files()
        if not self.force and (certificate.exists() or key.exists()):
            raise CommandError(
                f"{certificate} or {key} exists; pass --force to replace it"
            )
        router = build_router(self.document(), base_dir=self.config_path().parent)
        try:
            ca = create_ca(router, constrain=not self.unconstrained)
        except ValueError as error:
            raise CommandError(str(error), 2) from None
        password = os.environ.get(password_env) if password_env else None
        certificate.parent.mkdir(parents=True, exist_ok=True)
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_bytes(ca.private_key_pem(password))
        certificate.write_bytes(ca.certificate)
        print(certificate)
        return 0


class CaShow(_CaFiles):
    """Print the CA certificate (PEM): what clients must trust."""

    _parsername_ = "show"

    def __call__(self) -> int:
        certificate, _, _ = self.files()
        print(certificate.read_text(encoding="ascii"), end="")
        return 0


class Ca(Cmd):
    """The local CA used to intercept TLS routes."""

    _parsername_ = "ca"
    _subcommands_ = [CaInit, CaShow]
