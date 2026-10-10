"""Trusted source-classification configuration, separate from read permissions."""

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security.taint import SourceRecord, TaintError, TaintPolicy, TaintedValue
from tools.file_tool import read_file


@dataclass(frozen=True)
class TaintContext:
    root: Path
    sensitive_files: tuple[str, ...] = ()
    sensitive_tools: frozenset[str] = frozenset()
    policy: TaintPolicy = TaintPolicy()

    def __post_init__(self) -> None:
        if (not isinstance(self.root, Path) or not isinstance(self.sensitive_files, tuple) or
                not isinstance(self.sensitive_tools, frozenset) or len(self.sensitive_files) > 128 or
                len(self.sensitive_tools) > 128 or not isinstance(self.policy, TaintPolicy)):
            raise TaintError("Invalid context")
        for pattern in self.sensitive_files:
            if not isinstance(pattern, str) or not 1 <= len(pattern) <= 4096 or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
                raise TaintError("Sensitive file patterns must be root-relative")
        if not all(isinstance(name, str) and 1 <= len(name) <= 128 for name in self.sensitive_tools):
            raise TaintError("Invalid sensitive tool names")
        object.__setattr__(self, "root", self.root.resolve())

    @classmethod
    def load(cls, path: Path, *, root: Path) -> "TaintContext":
        text = read_file(path, max_chars=65536)
        try:
            values = json.loads(text)
        except (ValueError, RecursionError) as error:
            raise TaintError("Invalid taint configuration") from error
        if (not isinstance(values, dict) or set(values) - {"sensitive_files", "sensitive_tools", "require_tracked"} or
                not isinstance(values.get("sensitive_files", []), list) or
                not isinstance(values.get("sensitive_tools", []), list)):
            raise TaintError("Invalid taint configuration schema")
        return cls(root, tuple(values.get("sensitive_files", [])), frozenset(values.get("sensitive_tools", [])),
                   TaintPolicy(values.get("require_tracked", True)))

    def file_value(self, approved_path: Path, content: str) -> TaintedValue:
        try:
            relative = approved_path.resolve().relative_to(self.root).as_posix()
        except ValueError as error:
            raise TaintError("File source outside tracking root") from error
        sensitive = any(fnmatch.fnmatchcase(relative, pattern) for pattern in self.sensitive_files)
        return TaintedValue.from_source(content, SourceRecord.create("file", relative), sensitive=sensitive)

    def tool_value(self, tool: str, content: Any, *, reference: str) -> TaintedValue:
        return TaintedValue.from_source(content, SourceRecord.create("tool", tool + ":" + reference),
                                        sensitive=tool in self.sensitive_tools)
