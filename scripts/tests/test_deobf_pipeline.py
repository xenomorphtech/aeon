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


# ---------------------------------------------------------------------------
# Structured lifter + local simplifier
# ---------------------------------------------------------------------------


def _toy_target():
    return dp.TARGETS["challenge_hash32_toy"]


def _toy_fixture():
    return json.loads(Path("/home/sdancer/aeon-ollvm-codex1/"
                           "fixtures/challenge_hash32_toy_block.json").read_text())


class LifterTests(unittest.TestCase):
    def test_lifter_builds_structured_statements(self):
        target = _toy_target()
        result = dp.lift_to_symbolic(_toy_fixture(), target)
        self.assertEqual(result.metadata["lifter_version"], 2)
        self.assertEqual(result.metadata["instruction_count"], 7)
        # Every non-ret statement should carry op/dst/args/width/node.
        for s in result.statements:
            if s.get("op") == "ret":
                continue
            self.assertIn("op", s)
            self.assertIn("dst", s)
            self.assertIn("args", s)
            self.assertIn("node", s)

    def test_register_map_aliases_inputs(self):
        target = _toy_target()
        result = dp.lift_to_symbolic(_toy_fixture(), target)
        # Final expr must reference the named inputs, not raw register names.
        self.assertIn("challenge_ascii16_lo_u64", result.final_expr)
        self.assertIn("challenge_ascii16_hi_u64", result.final_expr)

    def test_unknown_op_preserved_verbatim(self):
        target = _toy_target()
        block = {
            "instructions": [
                {"addr": "0x100", "il": "x = magic(y)", "op": "magic",
                 "dst": "x", "args": ["y"], "width": 64},
            ]
        }
        result = dp.lift_to_symbolic(block, target)
        # Magic op survives in the statements list; final_expr falls back.
        self.assertEqual(result.statements[0]["op"], "magic")


class SimplifierTests(unittest.TestCase):
    def test_constant_folding(self):
        n = dp._bv_op("add",
                      (dp._bv_const(3, 64), dp._bv_const(4, 64)), 64)
        s = dp._fixed_point_simplify(n)
        self.assertEqual(s.kind, "const")
        self.assertEqual(s.value, 7)

    def test_xor_with_zero_collapses(self):
        x = dp._bv_var("x", 64)
        n = dp._bv_op("xor", (x, dp._bv_const(0, 64)), 64)
        self.assertEqual(repr(dp._fixed_point_simplify(n)), "x")

    def test_x_xor_x_is_zero(self):
        x = dp._bv_var("x", 64)
        n = dp._bv_op("xor", (x, x), 64)
        s = dp._fixed_point_simplify(n)
        self.assertEqual(s.kind, "const")
        self.assertEqual(s.value, 0)

    def test_x_minus_x_is_zero(self):
        x = dp._bv_var("x", 64)
        n = dp._bv_op("sub", (x, x), 64)
        s = dp._fixed_point_simplify(n)
        self.assertEqual(s.kind, "const")
        self.assertEqual(s.value, 0)

    def test_add_then_subtract_same_cancels(self):
        x = dp._bv_var("x", 64); y = dp._bv_var("y", 64)
        n = dp._bv_op("sub", (dp._bv_op("add", (x, y), 64), y), 64)
        self.assertEqual(repr(dp._fixed_point_simplify(n)), "x")

    def test_mba_xor_plus_two_and_to_add(self):
        # (x^y) + 2*(x&y) = x + y
        x = dp._bv_var("x", 64); y = dp._bv_var("y", 64)
        xy_xor = dp._bv_op("xor", (x, y), 64)
        xy_and = dp._bv_op("and", (x, y), 64)
        two_and = dp._bv_op("mul", (xy_and, dp._bv_const(2, 64)), 64)
        n = dp._bv_op("add", (xy_xor, two_and), 64)
        s = dp._fixed_point_simplify(n)
        self.assertEqual(s.op, "add")
        self.assertIn("x", repr(s))
        self.assertIn("y", repr(s))
        self.assertNotIn("xor", repr(s))

    def test_mba_xor_plus_shl_and_to_add(self):
        # (x^y) + ((x&y) << 1) = x + y  (shift form)
        x = dp._bv_var("x", 64); y = dp._bv_var("y", 64)
        xy_xor = dp._bv_op("xor", (x, y), 64)
        xy_and = dp._bv_op("and", (x, y), 64)
        shl_and = dp._bv_op("shl", (xy_and, dp._bv_const(1, 64)), 64)
        n = dp._bv_op("add", (xy_xor, shl_and), 64)
        self.assertEqual(dp._fixed_point_simplify(n).op, "add")

    def test_mba_or_minus_and_to_xor(self):
        x = dp._bv_var("x", 64); y = dp._bv_var("y", 64)
        n = dp._bv_op("sub",
                      (dp._bv_op("or", (x, y), 64),
                       dp._bv_op("and", (x, y), 64)),
                      64)
        s = dp._fixed_point_simplify(n)
        self.assertEqual(s.op, "xor")

    def test_toy_fixture_simplifies_to_xor_truncated(self):
        target = _toy_target()
        result = dp.lift_to_symbolic(_toy_fixture(), target)
        result = dp.simplify_local(result)
        # Closed form is (trunc (xor x0 x1)) — no longer carries any add/sub
        # MBA structure.
        simp = result.metadata["simplified"]
        self.assertIn("xor", simp)
        self.assertNotIn("add", simp)
        self.assertNotIn("sub", simp)
        self.assertIn("trunc", simp)
        self.assertTrue(result.metadata["fully_reduced"])

    def test_emit_includes_simplified_expr(self):
        target = _toy_target()
        result = dp.lift_to_symbolic(_toy_fixture(), target)
        result = dp.simplify_local(result)
        req = dp.emit_llm_request(target, target.block_addrs[0], result)
        self.assertIn("simplified_expr", req["symbolic"])
        self.assertTrue(req["symbolic"]["fully_reduced_locally"])


# ---------------------------------------------------------------------------
# Wide-output verify (192-bit cert) + wire-vector loader
# ---------------------------------------------------------------------------


class WireCertTargetTests(unittest.TestCase):
    def test_popcount_handles_192_bit_values(self):
        # Every bit set across 192 bits.
        v = (1 << 192) - 1
        self.assertEqual(dp._popcount(v), 192)
        # A single high bit should not be silently masked to zero.
        self.assertEqual(dp._popcount(1 << 191), 1)

    def test_wire_vector_loader_handles_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "empty.json"
            p.write_text("")
            self.assertEqual(dp._wire_cert_vectors_from_capture(str(p)), ())

    def test_wire_vector_loader_skips_malformed_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mixed.json"
            p.write_text(
                '{"challenge": "ABABABABABABABAB", '
                '"cert": "' + ("AA" * 24) + '", "ts": 1}\n'
                'not-json\n'
                '{"challenge": "xx", "cert": "short"}\n'
            )
            vs = dp._wire_cert_vectors_from_capture(str(p))
            self.assertEqual(len(vs), 1)
            self.assertEqual(vs[0].output, int("AA" * 24, 16))

    def test_wire_vector_loader_packs_challenge_as_le_u64_halves(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "single.json"
            # challenge ASCII = "0123456789ABCDEF"
            # lo = LE u64 of b"01234567" = 0x3736353433323130
            # hi = LE u64 of b"89ABCDEF" = 0x4645444342413938
            p.write_text(
                '{"challenge": "0123456789ABCDEF", '
                '"cert": "' + ("00" * 24) + '", "ts": 0}\n'
            )
            vs = dp._wire_cert_vectors_from_capture(str(p))
            self.assertEqual(vs[0].inputs["challenge_ascii16_lo_u64"],
                             0x3736353433323130)
            self.assertEqual(vs[0].inputs["challenge_ascii16_hi_u64"],
                             0x4645444342413938)

    def test_null_stub_fails_all_wire_vectors(self):
        target = dp.TARGETS["cert_from_wire_session5"]
        if not target.test_vectors:
            self.skipTest("no wire vectors captured")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "null_stub.py"
            p.write_text(
                "def simplified(challenge_ascii16_lo_u64, "
                "challenge_ascii16_hi_u64):\n    return 0\n"
            )
            report = dp.verify_expression(target, p, fuzz_runs=50)
        self.assertEqual(report.ground_truth_passed, 0)
        self.assertEqual(report.ground_truth_failed, len(target.test_vectors))
        # Avalanche should be exactly 0 for a constant-returning stub.
        self.assertEqual(report.avalanche_ratio_mean, 0.0)
        # Every bit should be flagged biased (constant 0 → all bits zero).
        assert report.distribution_bit_bias is not None
        self.assertEqual(len(report.distribution_bit_bias), 192)


if __name__ == "__main__":
    unittest.main(verbosity=2)
