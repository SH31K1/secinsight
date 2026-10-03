"""Parser base class + registry so the CLI/backend can dispatch by tool name
or by auto-detecting the file format."""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Callable

from secinsight_core.models import ScanResult


class ParseError(Exception):
    pass


class BaseParser(ABC):
    tool_name: str = "unknown"

    @abstractmethod
    def can_parse(self, path: str, sample: str) -> bool:
        """Return True if this parser thinks it can handle the given file."""

    @abstractmethod
    def parse(self, path: str) -> ScanResult:
        """Parse the file at `path` into a normalized ScanResult."""


_REGISTRY: dict[str, BaseParser] = {}


def register(parser: BaseParser) -> None:
    _REGISTRY[parser.tool_name] = parser


def get_parser(tool_name: str) -> BaseParser:
    try:
        return _REGISTRY[tool_name]
    except KeyError as e:
        raise ParseError(
            f"Unknown tool '{tool_name}'. Supported tools: {', '.join(sorted(_REGISTRY))}"
        ) from e


def available_tools() -> list[str]:
    return sorted(_REGISTRY.keys())


def _read_sample(path: str, n: int = 4096) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(n)
    except OSError as e:
        raise ParseError(f"Could not read file '{path}': {e}") from e


def autodetect(path: str) -> BaseParser:
    """Guess the right parser for a file by extension + content sniffing."""
    if not os.path.isfile(path):
        raise ParseError(f"File not found: {path}")
    sample = _read_sample(path)
    candidates = sorted(_REGISTRY.values(), key=lambda p: p.tool_name)
    for parser in candidates:
        try:
            if parser.can_parse(path, sample):
                return parser
        except Exception:
            continue
    raise ParseError(
        "Could not auto-detect the tool that produced this file. "
        "Pass --tool explicitly (one of: " + ", ".join(available_tools()) + ")"
    )


def load_all_parsers() -> None:
    """Import all built-in parser modules so they self-register."""
    from secinsight_core.parsers import (  # noqa: F401
        nmap,
        nikto,
        gobuster,
        dirsearch,
        burp,
        zap,
        nessus,
        openvas,
    )
