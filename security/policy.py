"""Policy loading and matching for AgentShield V1.5."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "policy.yaml"


class PolicyError(ValueError):
    """Raised when a policy file does not use the supported V1.5 shape."""


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

    def allows_file(self, path: str | Path) -> bool:
        """Return whether path stays inside one of the configured read roots."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.base_directory / candidate
        candidate = candidate.resolve()

        for configured_root in self.allowed_file_roots:
            allowed_root = Path(configured_root)
            if not allowed_root.is_absolute():
                allowed_root = self.base_directory / allowed_root
            try:
                candidate.relative_to(allowed_root.resolve())
            except ValueError:
                continue
            return True
        return False

    def allows_url(self, url: str) -> bool:
        """Allow exact configured domains and their subdomains."""
        candidate = url.strip()
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        hostname = (parsed.hostname or "").rstrip(".").casefold()

        for allowed_domain in self.allowed_domains:
            domain = allowed_domain.strip().lstrip("*.").rstrip(".").casefold()
            if domain and (hostname == domain or hostname.endswith(f".{domain}")):
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

        item = stripped[2:].strip().strip("'\"")
        if not item:
            raise PolicyError(f"Empty policy item on line {line_number}")
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
