"""Local file-reading tool used by AgentShield."""

from pathlib import Path


def read_file(path: str | Path) -> str:
    """Read and return a UTF-8 text file."""
    return Path(path).read_text(encoding="utf-8")
