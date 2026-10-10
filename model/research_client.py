"""Opt-in, bounded DeepSeek/Qwen client; no redirects or credential diagnostics."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from model.dots_client import DotsClient


PROVIDERS = {
    "deepseek": ("https://api.deepseek.com/chat/completions", "DEEPSEEK_API_KEY", "deepseek-chat"),
    "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "DASHSCOPE_API_KEY", "qwen-plus"),
}
MAX_RESPONSE_BYTES = 1024 * 1024


class ResearchAPIError(RuntimeError):
    """Fixed reason/code only. Never echo a provider body, key or headers."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ResearchChatClient(DotsClient):
    is_live = True

    def __init__(self, *, provider: str = "deepseek", model: str | None = None,
                 credential_env: str | None = None, allow_live: bool = False, timeout: float = 30) -> None:
        if provider not in PROVIDERS:
            raise ResearchAPIError("unsupported_provider")
        endpoint, default_env, default_model = PROVIDERS[provider]
        env = credential_env or default_env
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env):
            raise ResearchAPIError("invalid_credential_env")
        key = os.environ.get(env, "").strip()
        if not key:
            raise ResearchAPIError("missing_credential")
        if not 1 <= timeout <= 60:
            raise ResearchAPIError("invalid_timeout")
        if model is not None and (not isinstance(model, str) or not 1 <= len(model) <= 128):
            raise ResearchAPIError("invalid_model")
        self.provider, self.model = provider, model or default_model
        self._endpoint, self._api_key = endpoint, key
        self.allow_live, self.timeout = allow_live, timeout

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def build_payload(self, *, messages, tools, max_tokens: int = 512) -> dict[str, Any]:
        if type(max_tokens) is not int or not 1 <= max_tokens <= 1024:
            raise ResearchAPIError("invalid_token_budget")
        payload = super().build_payload(messages=messages, tools=tools, max_tokens=max_tokens)
        payload.pop("chat_template_kwargs", None)
        payload["temperature"] = 0
        return payload

    def send_payload(self, payload) -> dict[str, Any]:
        if not self.allow_live:
            raise ResearchAPIError("live_disabled")
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > 256 * 1024:
            raise ResearchAPIError("request_budget")
        request = Request(self.endpoint, data=encoded, method="POST",
                          headers={"Content-Type":"application/json", "Authorization":"Bearer " + self._api_key})
        try:
            with build_opener(_NoRedirect()).open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            raise ResearchAPIError("provider_http_" + str(error.code)) from None
        except (URLError, OSError, TimeoutError):
            raise ResearchAPIError("provider_transport_failed") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ResearchAPIError("response_budget")
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise ResearchAPIError("invalid_response_json") from None
        if not isinstance(result, dict) or not isinstance(result.get("choices"), list) or not result["choices"]:
            raise ResearchAPIError("invalid_response_schema")
        return result
