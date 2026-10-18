"""What every command shares: the configuration file it reads."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from duho import Cmd

from .. import config

__all__ = ["ConfigCommand"]


class ConfigCommand(Cmd):
    """Base of the commands that read a netproxy configuration file."""

    config: Optional[str] = None
    "The TOML configuration file. Omitted: NETPROXY_CONFIG, else netproxy/config.toml in the user's configuration directory"
    ("--config", "-c")

    def config_path(self) -> Path:
        return Path(self.config) if self.config else config.default_path()

    def document(self) -> Dict[str, Any]:
        return config.load(self.config_path())

    def server(self) -> Any:
        return config.load_server(self.config_path())
