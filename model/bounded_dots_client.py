"""Opt-in Dots transport with no redirects, proxies, or unbounded body reads.

The caller still owns the AgentShield decision for the exact payload/endpoint.
This adapter is not a source classifier, sandbox, or replacement for that gate.
The frozen DotsClient and all research protocols remain unchanged.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from model.dots_client import DEFAULT_BASE_URL, DEFAULT_MODEL, DotsAPIError, DotsClient


MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib raises HTTPError when no redirected request is produced.
        # Returning None covers 301/302/303/307/308, including same-origin hops.
        return None


def _encode_request(payload: Mapping[str, Any]) -> bytes:
    if not isinstance(payload, Mapping):
        raise DotsAPIError("bounded_dots_invalid_payload")
    body = bytearray()
    try:
        encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False)
        for chunk in encoder.iterencode(dict(payload)):
            # Check character length before allocating another encoded chunk.
            if len(chunk) > MAX_REQUEST_BYTES:
                raise DotsAPIError("bounded_dots_request_budget")
            part = chunk.encode("utf-8")
            if len(body) + len(part) > MAX_REQUEST_BYTES:
                raise DotsAPIError("bounded_dots_request_budget")
            body.extend(part)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise DotsAPIError("bounded_dots_invalid_payload") from None
    return bytes(body)


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("nonfinite_json")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite_json")
    return number


class BoundedDotsClient(DotsClient):
    """Compatible client injection; live execution is disabled by default.

    Body limits bound wire bytes, not all Python allocation or total wall time.
    The finite timeout is a socket-operation timeout. A reviewed task/provider
    budget and middleware permission are still required before live execution.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
        allow_live: bool = False,
    ) -> None:
        if type(allow_live) is not bool:
            raise DotsAPIError("bounded_dots_invalid_live_flag")
        if type(timeout) not in (int, float) or not 0 < timeout <= 60:
            raise DotsAPIError("bounded_dots_invalid_timeout")
        if not isinstance(base_url, str) or any(
            ord(char) <= 32 or ord(char) >= 127 or char == "\\" for char in base_url
        ):
            raise DotsAPIError("bounded_dots_invalid_endpoint")
        try:
            parsed = urlsplit(base_url)
            valid = (
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and not parsed.query
                and not parsed.fragment
                and parsed.port != 0
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise DotsAPIError("bounded_dots_invalid_endpoint")
        if not isinstance(model, str) or not 1 <= len(model) <= 128:
            raise DotsAPIError("bounded_dots_invalid_model")
        super().__init__(api_key=api_key, base_url=base_url, model=model, timeout=float(timeout))
        if len(self._api_key) > 4096 or any(
            ord(char) <= 32 or ord(char) >= 127 for char in self._api_key
        ):
            raise DotsAPIError("bounded_dots_invalid_credential")
        self._bounded_endpoint = super().endpoint
        self._bounded_timeout = float(timeout)
        self._allow_live = allow_live

    @property
    def endpoint(self) -> str:
        # Freeze the endpoint checked by the caller; later base_url edits do
        # not silently change where this adapter sends an approved request.
        return self._bounded_endpoint

    @property
    def is_live(self) -> bool:
        return self._allow_live

    def send_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not self._allow_live:
            raise DotsAPIError("bounded_dots_live_disabled")
        encoded = _encode_request(payload)
        request = Request(
            self.endpoint,
            data=encoded,
            headers={"Content-Type": "application/json", "api-key": self._api_key},
            method="POST",
        )
        # ProxyHandler({}) avoids importing proxy routes from the environment.
        # VPN/OS routing, DNS rebinding and arbitrary Python remain outside this
        # adapter's guarantee; no production-network containment is claimed.
        opener = build_opener(ProxyHandler({}), _RejectRedirects())
        try:
            with opener.open(request, timeout=self._bounded_timeout) as response:
                if 300 <= response.status < 400:
                    raise DotsAPIError("bounded_dots_redirect_refused")
                if not 200 <= response.status < 300:
                    raise DotsAPIError("bounded_dots_http_status")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            code = error.code
            error.close()
            if 300 <= code < 400:
                raise DotsAPIError("bounded_dots_redirect_refused") from None
            # Provider error bodies may contain payloads or credentials. Do
            # not read, quote, or attach their text to the public exception.
            raise DotsAPIError("bounded_dots_http_" + str(code)) from None
        except (URLError, OSError, TimeoutError):
            raise DotsAPIError("bounded_dots_transport_failed") from None
        if not isinstance(raw, bytes):
            raise DotsAPIError("bounded_dots_invalid_response")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise DotsAPIError("bounded_dots_response_budget")
        try:
            result = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_constant,
                parse_float=_finite_float,
            )
        except (ValueError, UnicodeError, RecursionError):
            raise DotsAPIError("bounded_dots_invalid_response_json") from None
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("choices"), list)
            or not result["choices"]
            or not isinstance(result["choices"][0], dict)
            or not isinstance(result["choices"][0].get("message"), dict)
        ):
            raise DotsAPIError("bounded_dots_invalid_response_schema")
        return result
