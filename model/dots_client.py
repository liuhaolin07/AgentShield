"""Minimal standard-library client for the Dots Chat Completions API."""

import json
import os
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_BASE_URL = "https://note3-prev-api.askdiandian.com"
DEFAULT_MODEL = "dots3-note-prev"
API_KEY_ENV = "AGENTSHIELD_API_KEY"
MAX_ERROR_DETAIL_LENGTH = 400
SECRET_PATTERNS = (
    re.compile(r"\bak_[A-Za-z0-9_-]{8,}\b", flags=re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b", flags=re.IGNORECASE),
)


class DotsAPIError(RuntimeError):
    """A sanitized Dots API configuration, transport, or response error."""


def _redact_secrets(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_API_KEY]", redacted)
    return redacted


def _safe_http_error_detail(error: HTTPError) -> str:
    """Extract bounded provider diagnostics without exposing credentials."""
    try:
        raw_body = error.read(4096)
    except OSError:
        return ""
    if not raw_body:
        return ""

    decoded_body = raw_body.decode("utf-8", errors="replace")
    try:
        parsed_body = json.loads(decoded_body)
    except json.JSONDecodeError:
        detail = decoded_body
    else:
        error_value = parsed_body.get("error", parsed_body) if isinstance(
            parsed_body, dict
        ) else parsed_body
        if isinstance(error_value, dict):
            detail_parts = [
                f"{key}={error_value[key]}"
                for key in ("code", "type", "message", "detail")
                if error_value.get(key) not in (None, "")
            ]
            detail = "; ".join(detail_parts)
        else:
            detail = str(error_value)

    normalized = " ".join(_redact_secrets(detail).split())
    return normalized[:MAX_ERROR_DETAIL_LENGTH]


class DotsClient:
    """Call the OpenAI-compatible Dots endpoint without external packages."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
    ) -> None:
        resolved_key = (api_key or os.environ.get(API_KEY_ENV) or "").strip()
        if not resolved_key:
            raise DotsAPIError(
                f"Missing API key. Set the {API_KEY_ENV} environment variable."
            )

        self._api_key = resolved_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/v1/chat/completions"

    def build_payload(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int = 512,
    ) -> dict[str, Any]:
        """Build the exact JSON body that will be checked and transmitted."""
        return {
            "model": self.model,
            "messages": list(messages),
            "tools": list(tools),
            "tool_choice": "auto",
            "stream": False,
            "max_tokens": max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }

    def send_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Send a pre-checked payload and return the parsed JSON response."""
        encoded_payload = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(
            self.endpoint,
            data=encoded_payload,
            headers={
                "Content-Type": "application/json",
                "api-key": self._api_key,
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw_response = response.read()
        except HTTPError as error:
            detail = _safe_http_error_detail(error)
            suffix = f" - {detail}" if detail else ""
            raise DotsAPIError(
                f"Dots API returned HTTP {error.code}{suffix}"
            ) from error
        except URLError as error:
            raise DotsAPIError("Could not connect to the Dots API") from error
        except TimeoutError as error:
            raise DotsAPIError("Dots API request timed out") from error

        try:
            parsed = json.loads(raw_response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DotsAPIError("Dots API returned invalid JSON") from error

        if not isinstance(parsed, dict) or not isinstance(parsed.get("choices"), list):
            raise DotsAPIError("Dots API response is missing choices")
        return parsed
