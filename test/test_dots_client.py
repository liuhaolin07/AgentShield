"""Offline tests for the Dots API adapter."""

import json
import io
import os
import unittest
from urllib.error import HTTPError
from unittest.mock import MagicMock, patch

from model.dots_client import API_KEY_ENV, DotsAPIError, DotsClient


class DotsClientTests(unittest.TestCase):
    def test_missing_key_fails_before_network_access(self) -> None:
        with patch.dict(os.environ, {API_KEY_ENV: ""}, clear=False):
            with self.assertRaises(DotsAPIError):
                DotsClient()

    def test_request_uses_documented_endpoint_and_header(self) -> None:
        response = MagicMock()
        response.read.return_value = b'{"choices": []}'
        response.__enter__.return_value = response

        with patch("model.dots_client.urlopen", return_value=response) as mocked_open:
            client = DotsClient(api_key="test-key")
            payload = client.build_payload(
                messages=[{"role": "user", "content": "hello"}],
                tools=[],
            )
            result = client.send_payload(payload)

        request = mocked_open.call_args.args[0]
        headers = {key.casefold(): value for key, value in request.header_items()}
        request_body = json.loads(request.data.decode("utf-8"))

        self.assertEqual(
            request.full_url,
            "https://note3-prev-api.askdiandian.com/v1/chat/completions",
        )
        self.assertEqual(headers["api-key"], "test-key")
        self.assertEqual(request_body["model"], "dots3-note-prev")
        self.assertFalse(request_body["stream"])
        self.assertEqual(result, {"choices": []})

    def test_http_error_detail_is_bounded_and_redacts_keys(self) -> None:
        fake_key = "ak_1234567890abcdef"
        error_body = json.dumps(
            {
                "error": {
                    "code": "invalid_api_key",
                    "message": f"Rejected credential {fake_key}",
                }
            }
        ).encode("utf-8")
        http_error = HTTPError(
            url="https://note3-prev-api.askdiandian.com/v1/chat/completions",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=io.BytesIO(error_body),
        )

        with patch("model.dots_client.urlopen", side_effect=http_error):
            client = DotsClient(api_key=f"  {fake_key}  ")
            with self.assertRaises(DotsAPIError) as raised:
                client.send_payload(
                    client.build_payload(
                        messages=[{"role": "user", "content": "hello"}],
                        tools=[],
                    )
                )

        error_message = str(raised.exception)
        self.assertIn("invalid_api_key", error_message)
        self.assertIn("[REDACTED_API_KEY]", error_message)
        self.assertNotIn(fake_key, error_message)


if __name__ == "__main__":
    unittest.main()
