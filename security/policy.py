"""Dependency-free policy loading and matching for AgentShield."""

import re
from dataclasses import dataclass
from ipaddress import ip_address
from os import PathLike
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "policy.yaml"


class PolicyError(ValueError):
    """Raised when a policy file does not use the supported shape."""


def _normalize_host(host: str) -> str | None:
    """Validate a DNS name or IP literal and produce a comparison key."""
    host = host.removesuffix(".")
    if not host or "%" in host:
        return None
    try:
        return str(ip_address(host))
    except ValueError:
        pass
    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(normalized) > 253:
        return None
    labels = normalized.split(".")
    if any(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
        for label in labels
    ):
        return None
    return normalized


@dataclass(frozen=True)
class SecurityPolicy:
    """The file and network controls supported by AgentShield V1.6."""

    blocked_files: tuple[str, ...]
    allowed_file_roots: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    base_directory: Path

    def blocks_file(self, path: str | Path) -> bool:
        """Return whether path matches a blocked filename or path suffix."""
        normalized_path = str(path).replace("\\", "/").strip("/").casefold()
        filename = normalized_path.rsplit("/", 1)[-1]

        for blocked_file in self.blocked_files:
            blocked = blocked_file.replace("\\", "/").strip("/").casefold()
            if filename == blocked or normalized_path == blocked:
                return True
            if blocked and normalized_path.endswith(f"/{blocked}"):
                return True
        return False

    def resolve_file(self, path: str | PathLike[str]) -> Path:
        """Resolve a file relative to the policy, including symlink targets."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.base_directory / candidate
        return candidate.resolve()

    def allows_file(self, path: str | PathLike[str]) -> bool:
        """Return whether path stays inside one of the configured read roots."""
        try:
            candidate = self.resolve_file(path)
            for configured_root in self.allowed_file_roots:
                allowed_root = self.resolve_file(configured_root)
                if candidate == allowed_root or allowed_root in candidate.parents:
                    return True
        except (OSError, RuntimeError, ValueError):
            return False
        return False

    def allows_url(self, url: str) -> bool:
        """Allow valid HTTP(S) destinations matching the domain allowlist.

        Bare hosts and scheme-relative destinations support the simulated
        HTTP tool. Credentials, backslashes and control characters are denied.
        """
        if not isinstance(url, str) or any(
            ord(char) < 32 or ord(char) == 127 for char in url
        ):
            return False
        candidate = url.strip()
        if not candidate or "\\" in candidate or any(
            char.isspace() for char in candidate
        ):
            return False
        target = (
            candidate
            if "://" in candidate or candidate.startswith("//")
            else f"//{candidate}"
        )
        try:
            parsed = urlsplit(target)
            if parsed.scheme not in {"", "http", "https"}:
                return False
            if (
                not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
            ):
                return False
            # Accessing .port validates both numeric syntax and range.
            port = parsed.port
            if parsed.netloc.endswith(":") or port == 0:
                return False
            hostname = _normalize_host(parsed.hostname or "")
        except ValueError:
            return False
        if hostname is None:
            return False

        for allowed_domain in self.allowed_domains:
            domain = _normalize_host(allowed_domain.removeprefix("*."))
            if hostname == domain:
                return True
            if domain is None:
                continue
            try:
                ip_address(domain)
            except ValueError:
                if hostname.endswith(f".{domain}"):
                    return True
        return False


def load_policy(path: str | Path = DEFAULT_POLICY_PATH) -> SecurityPolicy:
    """Load the small, dependency-free YAML subset used by V1.5.

    The supported shape is three top-level keys whose values are string lists.
    Rejecting unknown syntax keeps this prototype predictable and fail-closed.
    """
    policy_path = Path(path)
    values: dict[str, list[str]] = {
        "blocked_files": [],
        "allowed_file_roots": [],
        "allowed_domains": [],
    }
    seen_keys: set[str] = set()
    current_key: str | None = None

    for line_number, raw_line in enumerate(
        policy_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        without_comment = raw_line.split("#", 1)[0].rstrip()
        if not without_comment.strip():
            continue

        stripped = without_comment.strip()
        if not raw_line[0].isspace():
            if not stripped.endswith(":"):
                raise PolicyError(f"Invalid policy line {line_number}")
            current_key = stripped[:-1].strip()
            if current_key not in values:
                raise PolicyError(f"Unknown policy key on line {line_number}")
            if current_key in seen_keys:
                raise PolicyError(f"Duplicate policy key on line {line_number}")
            seen_keys.add(current_key)
            continue

        if current_key is None or not stripped.startswith("- "):
            raise PolicyError(f"Invalid policy item on line {line_number}")

        item = stripped[2:].strip()
        if item.startswith(("'", '"')):
            if len(item) < 2 or item[-1] != item[0]:
                raise PolicyError(f"Invalid quoted policy item on line {line_number}")
            item = item[1:-1]
        if not item or "\0" in item:
            raise PolicyError(f"Empty policy item on line {line_number}")
        if (
            current_key == "allowed_domains"
            and _normalize_host(item.removeprefix("*.")) is None
        ):
            raise PolicyError(f"Invalid allowed domain on line {line_number}")
        values[current_key].append(item)

    missing_keys = set(values) - seen_keys
    if missing_keys:
        raise PolicyError("Policy is missing required keys")

    return SecurityPolicy(
        blocked_files=tuple(values["blocked_files"]),
        allowed_file_roots=tuple(values["allowed_file_roots"]),
        allowed_domains=tuple(values["allowed_domains"]),
        base_directory=policy_path.resolve().parent,
    )
