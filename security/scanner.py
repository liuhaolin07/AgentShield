"""Bounded JSON, percent-encoding and Base64 credential inspection.

This is heuristic detection, not taint tracking. Budget rejections are distinct
from detected credentials. Findings never contain matched values.
"""

import base64
import binascii
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, unquote_plus


@dataclass(frozen=True)
class ScanLimits:
    max_input_chars: int = 65536
    max_total_chars: int = 262144
    max_decode_depth: int = 4
    max_views: int = 128
    max_json_depth: int = 16
    max_json_nodes: int = 2048
    max_json_parses: int = 32
    max_base64_candidates: int = 64

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")


DEFAULT_SCAN_LIMITS = ScanLimits()


@dataclass(frozen=True)
class ScanFinding:
    kind: str
    transformations: tuple[str, ...]


@dataclass(frozen=True)
class ScanResult:
    finding: ScanFinding | None
    limit_reason: str | None
    views_examined: int
    chars_scheduled: int
    base64_attempts: int

    @property
    def detected(self) -> bool:
        return self.finding is not None

    @property
    def limited(self) -> bool:
        return self.limit_reason is not None

    @property
    def blocked(self) -> bool:
        return self.detected or self.limited


_CREDENTIAL_KEYS = frozenset({
    "password", "passwd", "pwd", "aws_secret", "aws_secret_access_key",
    "api_key", "apikey", "access_token", "refresh_token", "auth_token",
    "client_secret", "private_key", "secret_key",
})
_PLACEHOLDERS = frozenset({
    "", "null", "none", "true", "false", "redacted", "[redacted]",
    "<redacted>", "<password>", "<api_key>", "<token>",
    "your_password", "your_api_key", "your_token", "***", "********",
})
_KEY_NAMES = "|".join(sorted(_CREDENTIAL_KEYS, key=len, reverse=True))
_ASSIGNMENT = re.compile(
    rf"(?<![\w])(?:{_KEY_NAMES})[\"']?\s*[:=]\s*[\"']?(\$\{{[A-Za-z_][A-Za-z0-9_]*\}}|[^\s\"'&,;{{}}\[\]]+)",
    re.IGNORECASE,
)
_SIGNATURES = (
    ("private_key", re.compile(r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----", re.IGNORECASE)),
    ("api_key", re.compile(r"\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}|ak_[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)
_AUTHORIZATION = re.compile(r"\bauthorization[\"']?\s*[:=]\s*[\"']?\s*(?:Bearer|Basic)\s+([A-Za-z0-9._~+/-]{8,}={0,2})", re.IGNORECASE)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{6,}={0,2})(?![A-Za-z0-9+/_=-])")
_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_TEMPLATE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")


def _credential_value(value: Any) -> bool:
    if value is None or isinstance(value, (dict, list, _JSONObject)):
        return False
    text = str(value).strip()
    return text.casefold() not in _PLACEHOLDERS and _TEMPLATE.fullmatch(text) is None


def _raw_finding(text: str) -> str | None:
    for kind, pattern in _SIGNATURES:
        if pattern.search(text):
            return kind
    for match in _ASSIGNMENT.finditer(text):
        if _credential_value(match.group(1)):
            return "credential_assignment"
    for match in _AUTHORIZATION.finditer(text):
        if _credential_value(match.group(1)):
            return "authorization"
    return None


@dataclass(frozen=True)
class _JSONObject:
    # Preserve duplicate keys instead of hiding an earlier credential field.
    pairs: tuple[tuple[str, Any], ...]


class _BudgetExceeded(Exception):
    pass


@dataclass(frozen=True)
class _View:
    text: str
    depth: int
    transformations: tuple[str, ...]


class _Inspection:
    def __init__(self, limits: ScanLimits) -> None:
        self.limits = limits
        self.queue: deque[_View] = deque()
        self.seen: set[str] = set()
        self.candidates: set[str] = set()
        self.chars = 0
        self.examined = 0
        self.json_nodes = 0
        self.json_parses = 0
        self.attempts = 0

    def result(self, finding: ScanFinding | None = None,
               limit: str | None = None) -> ScanResult:
        return ScanResult(finding, limit, self.examined, self.chars, self.attempts)

    def enqueue(self, text: str, depth: int, transformations: tuple[str, ...]) -> None:
        if not text or text in self.seen:
            return
        if depth > self.limits.max_decode_depth:
            raise _BudgetExceeded("decode_depth")
        if len(self.seen) >= self.limits.max_views:
            raise _BudgetExceeded("view_count")
        if len(text) > self.limits.max_input_chars:
            raise _BudgetExceeded("input_length")
        if self.chars + len(text) > self.limits.max_total_chars:
            raise _BudgetExceeded("total_characters")
        self.seen.add(text)
        self.chars += len(text)
        self.queue.append(_View(text, depth, transformations))

    def json_guard(self, text: str) -> None:
        depth = separators = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > self.limits.max_json_depth:
                    raise _BudgetExceeded("json_depth")
            elif char in "}]":
                depth -= 1
            elif char in ",:":
                separators += 1
                if separators > self.limits.max_json_nodes:
                    raise _BudgetExceeded("json_nodes")

    def inspect_json(self, view: _View) -> ScanFinding | None:
        text = view.text.lstrip()
        if not text.startswith(("{", "[", '"')):
            return None
        self.json_guard(text)
        if self.json_parses >= self.limits.max_json_parses:
            raise _BudgetExceeded("json_parses")
        self.json_parses += 1
        try:
            value = json.loads(text, object_pairs_hook=lambda pairs: _JSONObject(tuple(pairs)),
                               parse_int=str, parse_float=str, parse_constant=str)
        except (ValueError, RecursionError):
            return None
        pending = [value]
        while pending:
            value = pending.pop()
            if self.json_nodes >= self.limits.max_json_nodes:
                raise _BudgetExceeded("json_nodes")
            self.json_nodes += 1
            if isinstance(value, _JSONObject):
                for key, child in value.pairs:
                    normalized = key.casefold().replace("-", "_")
                    if normalized in _CREDENTIAL_KEYS and _credential_value(child):
                        return ScanFinding("json_credential_field", view.transformations + ("json",))
                    if normalized == "authorization" and isinstance(child, str):
                        if _raw_finding("Authorization: " + child):
                            return ScanFinding("authorization", view.transformations + ("json",))
                    pending.append(child)
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str):
                self.enqueue(value, view.depth + 1, view.transformations + ("json",))
        return None

    def decode_base64(self, candidate: str, view: _View) -> None:
        if len(candidate) < 7 or candidate in self.candidates or len(candidate) % 4 == 1:
            return
        if self.attempts >= self.limits.max_base64_candidates:
            raise _BudgetExceeded("base64_candidates")
        self.candidates.add(candidate)
        self.attempts += 1
        try:
            encoded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            return
        # Preserve ASCII signatures inside binary envelopes without executing
        # or interpreting any binary format.
        text = decoded.decode("utf-8", errors="replace")
        self.enqueue(text, view.depth + 1, view.transformations + ("base64",))

    def inspect(self, data: str) -> ScanResult:
        try:
            self.enqueue(data, 0, ())
            while self.queue:
                view = self.queue.popleft()
                self.examined += 1
                kind = _raw_finding(view.text)
                if kind:
                    return self.result(ScanFinding(kind, view.transformations))
                finding = self.inspect_json(view)
                if finding:
                    return self.result(finding)
                if _PERCENT.search(view.text):
                    for decoder in (unquote, unquote_plus):
                        decoded = decoder(view.text, encoding="utf-8", errors="replace")
                        self.enqueue(decoded, view.depth + 1, view.transformations + ("url",))
                for match in _BASE64.finditer(view.text):
                    self.decode_base64(match.group(1), view)
                compact = "".join(view.text.split())
                if compact != view.text and _BASE64.fullmatch(compact):
                    self.decode_base64(compact, view)
        except _BudgetExceeded as error:
            return self.result(limit=str(error))
        return self.result()


def inspect_sensitive(data: str, *, limits: ScanLimits = DEFAULT_SCAN_LIMITS) -> ScanResult:
    """Return sanitized findings or an explicit limit rejection, never values."""
    if not isinstance(data, str):
        raise TypeError("Sensitive-data inspection requires text")
    return _Inspection(limits).inspect(data)


def scan_sensitive(data: str) -> bool:
    """Compatible boolean guard: detected credentials OR exhausted budget."""
    return inspect_sensitive(data).blocked
