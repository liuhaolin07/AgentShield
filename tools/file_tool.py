"""Local file-reading tool used by AgentShield."""

from pathlib import Path


def read_file(path: str | Path, *, max_chars: int | None = None) -> str:
    """Read and return a UTF-8 text file."""
    if max_chars is None:
        return Path(path).read_text(encoding="utf-8")
    if type(max_chars) is not int or max_chars < 1:
        raise ValueError("Invalid file read budget")
    with Path(path).open(encoding="utf-8") as source:
        content = source.read(max_chars + 1)
    if len(content) > max_chars:
        raise ValueError("File read budget exceeded")
    return content
