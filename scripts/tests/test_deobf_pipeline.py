"""Unit tests for scripts/deobf_pipeline.py.

Runs with stdlib unittest only — no third-party deps.

    $ python3 -m unittest scripts.tests.test_deobf_pipeline -v

or via the runner helper:

    $ python3 scripts/tests/test_deobf_pipeline.py
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Make the sibling module importable when run as a script.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import deobf_pipeline as dp  # noqa: E402


# ---------------------------------------------------------------------------
# UsageMetadata parsing
# ---------------------------------------------------------------------------


class UsageMetadataTests(unittest.TestCase):
    def test_parses_all_fields(self):
        resp = {
            "usageMetadata": {
                "promptTokenCount": 812,
                "candidatesTokenCount": 42,
                "totalTokenCount": 854,
            }
        }
        u = dp.UsageMetadata.from_response(resp)
        self.assertEqual(u.prompt_tokens, 812)
        self.assertEqual(u.output_tokens, 42)
        self.assertEqual(u.total_tokens, 854)

    def test_defaults_to_zero_when_missing(self):
        u = dp.UsageMetadata.from_response({})
        self.assertEqual((u.prompt_tokens, u.output_tokens, u.total_tokens),
                         (0, 0, 0))

    def test_log_line_format(self):
        u = dp.UsageMetadata(prompt_tokens=100, output_tokens=10, total_tokens=110)
        line = u.as_log_line()
        self.assertIn("prompt_tokens=100", line)
        self.assertIn("output_tokens=10", line)
        self.assertIn("total_tokens=110", line)


# ---------------------------------------------------------------------------
# extract_text_result — covers every finishReason + malformed response
# ---------------------------------------------------------------------------


def _stop_response(text: str, *, prompt_tok: int = 100, out_tok: int = 20):
    return {
        "candidates": [{
            "content": {"parts": [{"text": text}]},
            "finishReason": "STOP",
        }],
        "usageMetadata": {
            "promptTokenCount": prompt_tok,
            "candidatesTokenCount": out_tok,
            "totalTokenCount": prompt_tok + out_tok,
        },
    }


class ExtractTextResultTests(unittest.TestCase):
    def test_normal_stop_returns_text(self):
        r = dp.extract_text_result(_stop_response("hello world"))
        self.assertTrue(r.ok)
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.text, "hello world")
        self.assertEqual(r.finish_reason, "STOP")
        self.assertEqual(r.usage.total_tokens, 120)

    def test_missing_finish_reason_is_ok(self):
        resp = {
            "candidates": [{"content": {"parts": [{"text": "x"}]}}],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.text, "x")

    def test_max_tokens_returns_truncated_with_partial_text(self):
        resp = {
            "candidates": [{
                "content": {"parts": [{"text": "partial answer"}]},
                "finishReason": "MAX_TOKENS",
            }],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "truncated")
        self.assertEqual(r.text, "partial answer")
        self.assertEqual(r.finish_reason, "MAX_TOKENS")
        self.assertFalse(r.ok)
        self.assertIsNotNone(r.error_message)

    def test_safety_block_at_candidate_level(self):
        resp = {
            "candidates": [{
                "content": {"parts": []},
                "finishReason": "SAFETY",
            }],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "safety_blocked")
        self.assertEqual(r.finish_reason, "SAFETY")
        self.assertEqual(r.text, "")

    def test_safety_block_at_prompt_level(self):
        resp = {
            "promptFeedback": {"blockReason": "HARM_CATEGORY_DANGEROUS_CONTENT"},
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "safety_blocked")
        self.assertTrue(r.finish_reason.startswith("prompt:"))
        self.assertIn("HARM_CATEGORY_DANGEROUS_CONTENT", r.finish_reason)

    def test_function_call_response_without_text(self):
        resp = {
            "candidates": [{
                "content": {
                    "parts": [{"functionCall": {"name": "foo", "args": {}}}],
                },
                "finishReason": "STOP",
            }],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "function_call")
        self.assertEqual(r.text, "")

    def test_empty_candidates(self):
        r = dp.extract_text_result({"candidates": []})
        self.assertEqual(r.status, "empty")

    def test_missing_candidates(self):
        r = dp.extract_text_result({})
        self.assertEqual(r.status, "empty")

    def test_missing_parts(self):
        resp = {
            "candidates": [{"content": {}, "finishReason": "STOP"}],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "empty")
        self.assertEqual(r.finish_reason, "STOP")

    def test_parts_not_a_list(self):
        resp = {
            "candidates": [{"content": {"parts": "nope"},
                            "finishReason": "STOP"}],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "empty")

    def test_exotic_finish_reason_is_error(self):
        resp = {
            "candidates": [{
                "content": {"parts": [{"text": "some text"}]},
                "finishReason": "RECITATION",
            }],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "error")
        self.assertIn("RECITATION", r.error_message)

    def test_malformed_candidate(self):
        r = dp.extract_text_result({"candidates": ["not an object"]})
        self.assertEqual(r.status, "error")

    def test_multiple_text_parts_concatenated(self):
        resp = {
            "candidates": [{
                "content": {"parts": [{"text": "aa"}, {"text": "bb"}]},
                "finishReason": "STOP",
            }],
        }
        r = dp.extract_text_result(resp)
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.text, "aabb")


# ---------------------------------------------------------------------------
# send_to_gemini wire format + urlopen patching
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
    def read(self):  # noqa: D401
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class SendToGeminiTests(unittest.TestCase):
    def _mk_payload(self):
        return {"task_prompt": "simplify", "inputs": [], "statements": []}

    def test_url_and_body_shape(self):
        captured = {}
        def fake_open(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["headers"] = dict(req.header_items())
            captured["method"] = req.get_method()
            return _FakeResponse(json.dumps(_stop_response("hi")).encode())
        with patch.object(dp.urllib.request, "urlopen", fake_open):
            dp.send_to_gemini(self._mk_payload(), "gemini-2.0-flash-lite",
                              "KEY_ABC")
        self.assertEqual(captured["method"], "POST")
        self.assertTrue(captured["url"].startswith(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-2.0-flash-lite:generateContent?key=KEY_ABC"
        ))
        self.assertIn("contents", captured["body"])
        self.assertIn("generationConfig", captured["body"])
        self.assertEqual(
            captured["headers"].get("Content-type"),
            "application/json",
        )

    def test_returns_parsed_json(self):
        with patch.object(dp.urllib.request, "urlopen",
                          lambda req, timeout=None:
                              _FakeResponse(json.dumps(_stop_response("x"))
                                            .encode())):
            resp = dp.send_to_gemini(self._mk_payload(), "m", "k")
        self.assertIn("candidates", resp)
        self.assertEqual(resp["candidates"][0]["content"]["parts"][0]["text"],
                         "x")


# ---------------------------------------------------------------------------
# _cmd_send CLI integration — covers stderr logging + exit codes
# ---------------------------------------------------------------------------


class CmdSendTests(unittest.TestCase):
    def _run_cmd_send(self, resp_dict, *, argv_extra=None, env_key="FAKE",
                      emit_usage=True, print_text=True):
        """Invoke _cmd_send with urlopen stubbed; return (rc, stdout, stderr)."""
        import io
        req_path = Path("/tmp/_test_send_req.json")
        req_path.write_text(json.dumps({"task_prompt": "x"}))

        class Args:
            pass
        args = Args()
        args.request_file = str(req_path)
        args.model = "m"
        args.api_key_env = "FAKE_KEY_ENV"
        args.out = None
        args.print_text = print_text
        args.emit_usage = emit_usage

        fake_open = lambda req, timeout=None: _FakeResponse(
            json.dumps(resp_dict).encode())

        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.dict(dp.os.environ, {"FAKE_KEY_ENV": "k"}, clear=False), \
             patch.object(dp.urllib.request, "urlopen", fake_open), \
             patch.object(dp.sys, "stdout", stdout), \
             patch.object(dp.sys, "stderr", stderr):
            rc = dp._cmd_send(args)
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_happy_path_logs_usage_and_prints_text(self):
        rc, out, err = self._run_cmd_send(_stop_response("hello"))
        self.assertEqual(rc, 0)
        self.assertIn("hello", out)
        self.assertIn("prompt_tokens=100", err)
        self.assertIn("total_tokens=120", err)

    def test_no_emit_usage_silences_stderr_usage(self):
        rc, out, err = self._run_cmd_send(_stop_response("hello"),
                                          emit_usage=False)
        self.assertEqual(rc, 0)
        self.assertNotIn("prompt_tokens", err)

    def test_safety_block_returns_nonzero(self):
        resp = {
            "candidates": [{
                "content": {"parts": []},
                "finishReason": "SAFETY",
            }],
        }
        rc, out, err = self._run_cmd_send(resp)
        self.assertEqual(rc, 1)
        self.assertIn("safety_blocked", err)

    def test_max_tokens_returns_zero_with_partial_text(self):
        resp = {
            "candidates": [{
                "content": {"parts": [{"text": "truncated"}]},
                "finishReason": "MAX_TOKENS",
            }],
        }
        rc, out, err = self._run_cmd_send(resp)
        self.assertEqual(rc, 0)  # truncated is recoverable
        self.assertIn("truncated", out)
        self.assertIn("truncated", err)  # diagnostic on stderr

    def test_function_call_returns_nonzero(self):
        resp = {
            "candidates": [{
                "content": {"parts": [
                    {"functionCall": {"name": "foo", "args": {}}}
                ]},
                "finishReason": "STOP",
            }],
        }
        rc, out, err = self._run_cmd_send(resp)
        self.assertEqual(rc, 1)
        self.assertIn("function_call", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
