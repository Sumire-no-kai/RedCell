"""Console compatibility helpers shared by CLI entry points."""

from __future__ import annotations

import sys
from typing import TextIO


def ensure_utf8_output(*streams: TextIO) -> None:
    """Keep Unicode status output usable under legacy Windows code pages."""
    selected = streams or (sys.stdout, sys.stderr)
    probe = "RedCell —— 授权测试"
    for stream in selected:
        encoding = getattr(stream, "encoding", None)
        reconfigure = getattr(stream, "reconfigure", None)
        if not encoding or reconfigure is None:
            continue
        try:
            probe.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            reconfigure(encoding="utf-8", errors="replace")
