"""Unit tests for scripts/deobf_pipeline.py.

Runs with stdlib unittest only — no third-party deps.

    $ python3 scripts/tests/test_deobf_pipeline.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

import deobf_pipeline as dp  # noqa: E402


# ---------------------------------------------------------------------------
# UsageMetadata — covers both Gemini and OpenRouter response shapes
# ---------------------------------------------------------------------------


class UsageMetadataTests(unittest.TestCase):
    def test_gemini_parses_all_fields(self):
        resp = {"usageMetadata": {
            "promptTokenCount": 812,
            "candidatesTokenCount": 42,
            "totalTokenCount": 854,
        }}
        u = dp.UsageMetadata.from_gemini_response(resp)
        self.assertEqual((u.prompt_tokens, u.output_tokens, u.total_tokens),
                         (812, 42, 854))

    def test_gemini_defaults_to_zero_when_missing(self):
        u = dp.UsageMetadata.from_gemini_response({})
        self.assertEqual((u.prompt_tokens, u.output_tokens, u.total_tokens),
                         (0, 0, 0))

    def test_openrouter_parses_all_fields(self):
        resp = {"usage": {
            "prompt_tokens": 750,
            "completion_tokens": 120,
            "total_tokens": 870,
        }}
        u = dp.UsageMetadata.from_openrouter_response(resp)
        self.assertEqual((u.prompt_tokens, u.output_tokens, u.total_tokens),
                         (750, 120, 870))

    def test_openrouter_defaults_to_zero_when_missing(self):
        u = dp.UsageMetadata.from_openrouter_response({})
        self.assertEqual((u.prompt_tokens, u.output_tokens, u.total_tokens),
                         (0, 0, 0))

    def test_log_line_format(self):
        u = dp.UsageMetadata(prompt_tokens=100, output_tokens=10, total_tokens=110)
        line = u.as_log_line()
        self.assertIn("prompt_tokens=100", line)
        self.assertIn("output_tokens=10", line)
        self.assertIn("total_tokens=110", line)


# ---------------------------------------------------------------------------
# Gemini response extractor — every finishReason + malformed shape
# ---------------------------------------------------------------------------


def _gemini_stop(text: str, *, prompt_tok: int = 100, out_tok: int = 20):
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


class ExtractTextResultGeminiTests(unittest.TestCase):
    def test_normal_stop_returns_text(self):
        r = dp.extract_text_result_gemini(_gemini_stop("hello world"))
        self.assertTrue(r.ok)
        self.assertEqual(r.text, "hello world")
        self.assertEqual(r.finish_reason, "STOP")
        self.assertEqual(r.usage.total_tokens, 120)

    def test_missing_finish_reason_is_ok(self):
        resp = {"candidates": [{"content": {"parts": [{"text": "x"}]}}]}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.status, "ok")

    def test_max_tokens_returns_truncated(self):
        resp = {"candidates": [{
            "content": {"parts": [{"text": "partial"}]},
            "finishReason": "MAX_TOKENS",
        }]}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.status, "truncated")
        self.assertEqual(r.text, "partial")

    def test_safety_block_candidate_level(self):
        resp = {"candidates": [{"content": {"parts": []},
                                 "finishReason": "SAFETY"}]}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.status, "safety_blocked")

    def test_safety_block_prompt_level(self):
        resp = {"promptFeedback": {"blockReason": "HARM_CATEGORY_DANGEROUS"}}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.status, "safety_blocked")
        self.assertIn("HARM_CATEGORY_DANGEROUS", r.finish_reason)

    def test_function_call_without_text(self):
        resp = {"candidates": [{
            "content": {"parts": [{"functionCall": {"name": "f", "args": {}}}]},
            "finishReason": "STOP",
        }]}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.status, "function_call")

    def test_empty_candidates(self):
        self.assertEqual(dp.extract_text_result_gemini({"candidates": []}).status,
                         "empty")

    def test_missing_candidates(self):
        self.assertEqual(dp.extract_text_result_gemini({}).status, "empty")

    def test_missing_parts(self):
        resp = {"candidates": [{"content": {}, "finishReason": "STOP"}]}
        self.assertEqual(dp.extract_text_result_gemini(resp).status, "empty")

    def test_parts_not_a_list(self):
        resp = {"candidates": [{"content": {"parts": "nope"},
                                 "finishReason": "STOP"}]}
        self.assertEqual(dp.extract_text_result_gemini(resp).status, "empty")

    def test_exotic_finish_reason_is_error(self):
        resp = {"candidates": [{
            "content": {"parts": [{"text": "x"}]},
            "finishReason": "RECITATION",
        }]}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.status, "error")
        self.assertIn("RECITATION", r.error_message)

    def test_malformed_candidate(self):
        self.assertEqual(
            dp.extract_text_result_gemini({"candidates": ["not-an-object"]}).status,
            "error")

    def test_multiple_text_parts_concatenated(self):
        resp = {"candidates": [{
            "content": {"parts": [{"text": "aa"}, {"text": "bb"}]},
            "finishReason": "STOP",
        }]}
        r = dp.extract_text_result_gemini(resp)
        self.assertEqual(r.text, "aabb")

    def test_legacy_alias_still_exposed(self):
        # A few callers may still import dp.extract_text_result (legacy name).
        r = dp.extract_text_result(_gemini_stop("legacy"))
        self.assertEqual(r.status, "ok")


# ---------------------------------------------------------------------------
# OpenRouter response extractor — OpenAI finish_reason + OR-specific shapes
# ---------------------------------------------------------------------------


def _openrouter_stop(text: str, *, p: int = 750, c: int = 120):
    return {
        "choices": [{
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": p,
            "completion_tokens": c,
            "total_tokens": p + c,
        },
    }


class ExtractTextResultOpenrouterTests(unittest.TestCase):
    def test_normal_stop_returns_text(self):
        r = dp.extract_text_result_openrouter(_openrouter_stop("hello world"))
        self.assertTrue(r.ok)
        self.assertEqual(r.text, "hello world")
        self.assertEqual(r.finish_reason, "stop")
        self.assertEqual(r.usage.total_tokens, 870)

    def test_missing_finish_reason_is_ok(self):
        resp = {"choices": [{"message": {"content": "x"}}]}
        self.assertEqual(dp.extract_text_result_openrouter(resp).status, "ok")

    def test_length_returns_truncated(self):
        resp = {"choices": [{"message": {"content": "partial"},
                             "finish_reason": "length"}]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "truncated")
        self.assertEqual(r.text, "partial")

    def test_content_filter_returns_safety_blocked(self):
        resp = {"choices": [{"message": {"content": ""},
                             "finish_reason": "content_filter"}]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "safety_blocked")

    def test_tool_calls_finish_reason_returns_function_call(self):
        resp = {"choices": [{
            "message": {"content": None,
                        "tool_calls": [{"id": "c1", "type": "function"}]},
            "finish_reason": "tool_calls",
        }]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "function_call")

    def test_legacy_function_call_finish_reason(self):
        resp = {"choices": [{
            "message": {"content": None,
                        "function_call": {"name": "f", "arguments": "{}"}},
            "finish_reason": "function_call",
        }]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "function_call")

    def test_tool_call_in_message_without_explicit_finish(self):
        # Some providers omit finish_reason for tool-call responses.
        resp = {"choices": [{
            "message": {"content": None,
                        "tool_calls": [{"id": "c1", "type": "function"}]},
        }]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "function_call")

    def test_empty_choices(self):
        r = dp.extract_text_result_openrouter({"choices": []})
        self.assertEqual(r.status, "empty")

    def test_missing_choices(self):
        r = dp.extract_text_result_openrouter({})
        self.assertEqual(r.status, "empty")

    def test_missing_content(self):
        resp = {"choices": [{"message": {}, "finish_reason": "stop"}]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "empty")

    def test_malformed_choice(self):
        r = dp.extract_text_result_openrouter({"choices": ["not-an-object"]})
        self.assertEqual(r.status, "error")

    def test_list_content_parts_concatenated(self):
        # OpenRouter sometimes mirrors the multi-part content shape.
        resp = {"choices": [{
            "message": {"content": [{"text": "aa"}, {"text": "bb"}]},
            "finish_reason": "stop",
        }]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.text, "aabb")

    def test_top_level_error_object(self):
        # OpenRouter surfaces upstream errors in the body, not just via HTTP.
        resp = {"error": {"code": 429, "message": "rate limited"}}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "error")
        self.assertIn("rate limited", r.error_message)

    def test_exotic_finish_reason_is_error(self):
        resp = {"choices": [{
            "message": {"content": "text"},
            "finish_reason": "something_weird",
        }]}
        r = dp.extract_text_result_openrouter(resp)
        self.assertEqual(r.status, "error")
        self.assertIn("something_weird", r.error_message)


# ---------------------------------------------------------------------------
# HTTP wire format — send_to_gemini + send_to_openrouter
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
    def read(self): return self._body
    def __enter__(self): return self
    def __exit__(self, *a): return False


class SendWireFormatTests(unittest.TestCase):
    def _mk_payload(self):
        return {"task_prompt": "simplify", "inputs": [], "statements": []}

    def test_gemini_url_and_body_shape(self):
        captured = {}
        def fake_open(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["method"] = req.get_method()
            return _FakeResponse(json.dumps(_gemini_stop("hi")).encode())
        with patch.object(dp.urllib.request, "urlopen", fake_open):
            dp.send_to_gemini(self._mk_payload(), "gemini-2.0-flash-lite", "KEY_ABC")
        self.assertEqual(captured["method"], "POST")
        self.assertTrue(captured["url"].startswith(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-2.0-flash-lite:generateContent?key=KEY_ABC"
        ))
        self.assertIn("contents", captured["body"])
        self.assertIn("generationConfig", captured["body"])

    def test_openrouter_url_and_body_shape(self):
        captured = {}
        def fake_open(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["headers"] = dict(req.header_items())
            captured["method"] = req.get_method()
            return _FakeResponse(json.dumps(_openrouter_stop("hi")).encode())
        with patch.object(dp.urllib.request, "urlopen", fake_open):
            dp.send_to_openrouter(self._mk_payload(),
                                  "google/gemini-2.5-flash", "OR_KEY_X")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["url"], dp.OPENROUTER_ENDPOINT)
        self.assertEqual(captured["headers"].get("Authorization"),
                         "Bearer OR_KEY_X")
        self.assertEqual(captured["headers"].get("Content-type"),
                         "application/json")
        self.assertIn("Http-referer", captured["headers"])  # etiquette header
        self.assertIn("X-title", captured["headers"])
        self.assertEqual(captured["body"]["model"], "google/gemini-2.5-flash")
        self.assertEqual(captured["body"]["temperature"], 0.2)
        self.assertEqual(captured["body"]["max_tokens"], 4096)
        self.assertEqual(captured["body"]["messages"][0]["role"], "user")

    def test_openrouter_returns_parsed_json(self):
        with patch.object(dp.urllib.request, "urlopen",
                          lambda req, timeout=None:
                              _FakeResponse(json.dumps(_openrouter_stop("x"))
                                            .encode())):
            resp = dp.send_to_openrouter(self._mk_payload(), "m", "k")
        self.assertEqual(resp["choices"][0]["message"]["content"], "x")


# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------


class LoadEnvFileTests(unittest.TestCase):
    def test_parses_quoted_and_unquoted(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text(
                '# comment line\n'
                'FOO=bar\n'
                'BAZ="quoted value"\n'
                "QUUX='single quoted'\n"
                '\n'
                'WITHEQUAL=a=b=c\n'
            )
            before = dict(os.environ)
            try:
                for k in ("FOO", "BAZ", "QUUX", "WITHEQUAL"):
                    os.environ.pop(k, None)
                out = dp.load_env_file(p)
                self.assertEqual(out["FOO"], "bar")
                self.assertEqual(out["BAZ"], "quoted value")
                self.assertEqual(out["QUUX"], "single quoted")
                self.assertEqual(out["WITHEQUAL"], "a=b=c")
                self.assertEqual(os.environ["FOO"], "bar")
            finally:
                os.environ.clear()
                os.environ.update(before)

    def test_does_not_overwrite_existing_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text('PREEXISTING="new-value"\n')
            before = dict(os.environ)
            try:
                os.environ["PREEXISTING"] = "old-value"
                dp.load_env_file(p)
                self.assertEqual(os.environ["PREEXISTING"], "old-value")
            finally:
                os.environ.clear()
                os.environ.update(before)

    def test_missing_file_returns_empty(self):
        self.assertEqual(dp.load_env_file("/tmp/does_not_exist_xyz"), {})


# ---------------------------------------------------------------------------
# _cmd_send CLI integration — both providers
# ---------------------------------------------------------------------------


class CmdSendTests(unittest.TestCase):
    def _run(self, resp_dict, *, provider="openrouter", emit_usage=True,
             print_text=True, model=None, api_key_env=None):
        import io
        req_path = Path("/tmp/_test_send_req.json")
        req_path.write_text(json.dumps({"task_prompt": "x"}))

        class Args: pass
        args = Args()
        args.request_file = str(req_path)
        args.provider = provider
        args.model = model
        args.api_key_env = api_key_env
        args.out = None
        args.print_text = print_text
        args.emit_usage = emit_usage

        fake_open = lambda req, timeout=None: _FakeResponse(
            json.dumps(resp_dict).encode())

        env = {
            "OPENROUTER_API_KEY": "or-key",
            "GEMINI_API_KEY": "gem-key",
            "OPENROUTER_MODEL": "google/gemini-2.5-flash",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.dict(dp.os.environ, env, clear=False), \
             patch.object(dp, "load_env_file", lambda *a, **kw: {}), \
             patch.object(dp.urllib.request, "urlopen", fake_open), \
             patch.object(dp.sys, "stdout", stdout), \
             patch.object(dp.sys, "stderr", stderr):
            rc = dp._cmd_send(args)
        return rc, stdout.getvalue(), stderr.getvalue()

    # -- OpenRouter happy-path + edge cases --

    def test_openrouter_happy_path(self):
        rc, out, err = self._run(_openrouter_stop("hello"),
                                 provider="openrouter")
        self.assertEqual(rc, 0)
        self.assertIn("hello", out)
        self.assertIn("prompt_tokens=750", err)
        self.assertIn("total_tokens=870", err)

    def test_openrouter_no_emit_usage(self):
        rc, _out, err = self._run(_openrouter_stop("hello"),
                                   provider="openrouter", emit_usage=False)
        self.assertEqual(rc, 0)
        self.assertNotIn("prompt_tokens", err)

    def test_openrouter_length_returns_zero_with_partial(self):
        resp = {"choices": [{"message": {"content": "part"},
                             "finish_reason": "length"}]}
        rc, out, err = self._run(resp, provider="openrouter")
        self.assertEqual(rc, 0)  # truncated is recoverable
        self.assertIn("part", out)
        self.assertIn("truncated", err)

    def test_openrouter_content_filter_returns_nonzero(self):
        resp = {"choices": [{"message": {"content": ""},
                             "finish_reason": "content_filter"}]}
        rc, _out, err = self._run(resp, provider="openrouter")
        self.assertEqual(rc, 1)
        self.assertIn("safety_blocked", err)

    def test_openrouter_tool_calls_returns_nonzero(self):
        resp = {"choices": [{
            "message": {"content": None,
                        "tool_calls": [{"id": "c1", "type": "function"}]},
            "finish_reason": "tool_calls",
        }]}
        rc, _out, err = self._run(resp, provider="openrouter")
        self.assertEqual(rc, 1)
        self.assertIn("function_call", err)

    # -- Gemini path still works via --provider gemini --

    def test_gemini_happy_path(self):
        rc, out, err = self._run(_gemini_stop("hello"), provider="gemini")
        self.assertEqual(rc, 0)
        self.assertIn("hello", out)
        self.assertIn("total_tokens=120", err)

    def test_gemini_safety_returns_nonzero(self):
        resp = {"candidates": [{"content": {"parts": []},
                                 "finishReason": "SAFETY"}]}
        rc, _out, err = self._run(resp, provider="gemini")
        self.assertEqual(rc, 1)
        self.assertIn("safety_blocked", err)

    # -- Missing API key --

    def test_missing_api_key_returns_2(self):
        req_path = Path("/tmp/_test_send_req.json")
        req_path.write_text("{}")

        class Args: pass
        args = Args()
        args.request_file = str(req_path)
        args.provider = "openrouter"
        args.model = None
        args.api_key_env = None
        args.out = None
        args.print_text = False
        args.emit_usage = False

        import io
        stderr = io.StringIO()
        with patch.object(dp, "load_env_file", lambda *a, **kw: {}), \
             patch.dict(dp.os.environ, {}, clear=True), \
             patch.object(dp.sys, "stderr", stderr):
            rc = dp._cmd_send(args)
        self.assertEqual(rc, 2)
        self.assertIn("OPENROUTER_API_KEY", stderr.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
