"""Pins the guard-client contract, including its fail-closed behaviour.

The client runs a real HTTP server on a loopback port rather than mocking
urllib, so status-code handling, timeouts and malformed bodies are exercised the
way the daemon would actually produce them.
"""

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot import guard as guard_client  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    """Serves whatever the enclosing test parked on the server object."""

    def _respond(self):
        status, body = self.server.reply  # type: ignore[attr-defined]
        payload = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        self.server.last_body = json.loads(self.rfile.read(length) or "{}")  # type: ignore
        self.server.last_auth = self.headers.get("authorization")  # type: ignore
        self._respond()

    def do_GET(self):  # noqa: N802
        self._respond()

    def log_message(self, *args):
        pass  # keep test output clean


class FakeGuard:
    def __enter__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.server.reply = (200, {"ok": True})  # type: ignore[attr-defined]
        self.server.last_body = None  # type: ignore[attr-defined]
        self.server.last_auth = None  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def lock(self):
        return guard_client.GuardLock(
            host="127.0.0.1", port=self.server.server_address[1], token="tok"
        )

    def reply(self, status, body):
        self.server.reply = (status, body)  # type: ignore[attr-defined]

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


class ReadLockTests(unittest.TestCase):
    def _with_lock(self, payload):
        d = tempfile.TemporaryDirectory()
        p = Path(d.name) / "guard"
        p.mkdir(parents=True)
        if payload is not None:
            (p / "guard.json").write_text(
                payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8"
            )
        return d, {"VAIBOT_CREDS_DIR": d.name}

    def test_parses_a_real_lock(self):
        d, env = self._with_lock(
            {"host": "127.0.0.1", "port": 39116, "token": "t", "effective_mode": "observe"}
        )
        try:
            lock = guard_client.read_lock(env)
            # Port comes from the lock — the daemon does not always bind 39111,
            # and assuming the default is a silent way to govern nothing.
            self.assertEqual(lock.port, 39116)
            self.assertEqual(lock.effective_mode, "observe")
        finally:
            d.cleanup()

    def test_missing_lock_is_none(self):
        # None is the cold-start signal the degrade ladder keys off; it must be
        # distinguishable from a guard that ran and vanished.
        d, env = self._with_lock(None)
        try:
            self.assertIsNone(guard_client.read_lock(env))
        finally:
            d.cleanup()

    def test_corrupt_or_portless_lock_is_none(self):
        for payload in ("{not json", {"host": "h"}, {"port": 0}, {"port": "39111"}, "[]"):
            d, env = self._with_lock(payload)
            try:
                self.assertIsNone(guard_client.read_lock(env), payload)
            finally:
                d.cleanup()

    def test_bogus_effective_mode_is_dropped(self):
        d, env = self._with_lock({"port": 1, "effective_mode": "banana"})
        try:
            self.assertIsNone(guard_client.read_lock(env).effective_mode)
        finally:
            d.cleanup()

    def test_base_url_override_wins(self):
        d, env = self._with_lock({"port": 39116})
        try:
            env = {**env, "VAIBOT_GUARD_BASE_URL": "http://1.2.3.4:9999", "VAIBOT_GUARD_TOKEN": "x"}
            lock = guard_client.read_lock(env)
            self.assertEqual((lock.host, lock.port, lock.token), ("1.2.3.4", 9999, "x"))
        finally:
            d.cleanup()


class DecideToolTests(unittest.TestCase):
    def test_happy_path_and_auth_header(self):
        with FakeGuard() as g:
            g.reply(200, {
                "runId": "run_1",
                "risk": {"risk": "low"},
                "effective_mode": "enforce",
                "decision": {"decision": "allow", "reason": "ok"},
            })
            d, resp = guard_client.decide_tool(
                g.lock, session_id="s", tool_name="Read", params={"file_path": "/tmp/x"}
            )
            self.assertTrue(resp.ok)
            self.assertEqual(d.decision, "allow")
            self.assertEqual(d.run_id, "run_1")
            self.assertEqual(d.effective_mode, "enforce")
            self.assertEqual(g.server.last_auth, "Bearer tok")
            # Wire shape must match /v1/decide/tool exactly.
            self.assertEqual(
                set(g.server.last_body), {"sessionId", "toolName", "params", "workspaceDir"}
            )

    def test_approval_id_rides_as_approval_object(self):
        with FakeGuard() as g:
            g.reply(200, {"decision": {"decision": "allow", "reason": "ok"}})
            guard_client.decide_tool(
                g.lock, session_id="s", tool_name="Read", approval_id="appr_1"
            )
            self.assertEqual(g.server.last_body["approval"], {"approvalId": "appr_1"})

    def test_floor_flag_is_surfaced(self):
        with FakeGuard() as g:
            g.reply(200, {"decision": {"decision": "deny", "reason": "boom", "floor": True}})
            d, _ = guard_client.decide_tool(g.lock, session_id="s", tool_name="Bash")
            self.assertTrue(d.floor)

    def test_200_with_no_usable_verdict_denies(self):
        # Fail-closed: a reachable guard returning garbage must never read as allow.
        for body in ({}, {"decision": {}}, {"decision": "allow"}, {"decision": {"decision": 5}}):
            with FakeGuard() as g:
                g.reply(200, body)
                d, _ = guard_client.decide_tool(g.lock, session_id="s", tool_name="Bash")
                self.assertEqual(d.decision, "deny", body)

    def test_unparseable_body_is_treated_as_an_outage(self):
        with FakeGuard() as g:
            g.reply(200, "<html>not json</html>")
            d, resp = guard_client.decide_tool(g.lock, session_id="s", tool_name="Bash")
            self.assertIsNone(d)
            self.assertTrue(resp.unreachable)

    def test_4xx_is_a_real_answer_not_an_outage(self):
        # Conflating auth failures with outages would trip the circuit breaker on
        # a misconfiguration and mask it as a transient network problem.
        with FakeGuard() as g:
            g.reply(401, {"error": "unauthorized"})
            d, resp = guard_client.decide_tool(g.lock, session_id="s", tool_name="Bash")
            self.assertIsNone(d)
            self.assertFalse(resp.unreachable)
            self.assertEqual(resp.status, 401)

    def test_5xx_is_an_outage(self):
        with FakeGuard() as g:
            g.reply(503, {"error": "down"})
            _, resp = guard_client.decide_tool(g.lock, session_id="s", tool_name="Bash")
            self.assertTrue(resp.unreachable)

    def test_connection_refused_is_an_outage(self):
        dead = guard_client.GuardLock(host="127.0.0.1", port=9, token="")
        _, resp = guard_client.decide_tool(dead, session_id="s", tool_name="Bash", timeout_s=1.0)
        self.assertTrue(resp.unreachable)
        self.assertFalse(resp.ok)


class FinalizeTests(unittest.TestCase):
    def test_payload_shape(self):
        with FakeGuard() as g:
            guard_client.finalize_tool(
                g.lock, session_id="s", run_id="run_1", outcome="allowed", duration_ms=12.5
            )
            body = g.server.last_body
            self.assertEqual(body["runId"], "run_1")
            self.assertEqual(body["result"]["outcome"], "allowed")
            self.assertEqual(body["result"]["duration_ms"], 12.5)

    def test_error_is_clamped(self):
        with FakeGuard() as g:
            guard_client.finalize_tool(
                g.lock, session_id="s", run_id="r", outcome="blocked", error="x" * 5000
            )
            self.assertEqual(len(g.server.last_body["result"]["error"]), 2000)

    def test_omits_absent_optionals(self):
        with FakeGuard() as g:
            guard_client.finalize_tool(g.lock, session_id="s", run_id="r", outcome="allowed")
            self.assertEqual(set(g.server.last_body["result"]), {"outcome"})

    def test_denied_approval_is_sent(self):
        # Without it the guard writes an escalated run as approved.
        with FakeGuard() as g:
            guard_client.finalize_tool(
                g.lock, session_id="s", run_id="r", outcome="denied_by_reviewer", approval="denied"
            )
            self.assertEqual(
                g.server.last_body["result"], {"outcome": "denied_by_reviewer", "approval": "denied"}
            )


class HealthTests(unittest.TestCase):
    def test_health_true_and_false(self):
        with FakeGuard() as g:
            g.reply(200, {"ok": True})
            self.assertTrue(guard_client.health(g.lock))
            g.reply(503, {"ok": False})
            self.assertFalse(guard_client.health(g.lock))

    def test_health_false_when_nothing_listening(self):
        self.assertFalse(
            guard_client.health(guard_client.GuardLock(host="127.0.0.1", port=9, token=""),
                                timeout_s=1.0)
        )


class ProbeTests(unittest.TestCase):
    def test_reads_capabilities_from_the_live_daemon(self):
        with FakeGuard() as g:
            g.reply(200, {"ok": True, "version": "2.2.0", "capabilities": ["host-vocab:hermes", 7]})
            h = guard_client.probe(g.lock)
            self.assertEqual(h.capabilities, frozenset({"host-vocab:hermes"}))
            self.assertEqual(h.version, "2.2.0")

    def test_a_guard_without_the_field_has_no_capabilities(self):
        # Every guard released before the field — the case the rename shim serves.
        with FakeGuard() as g:
            g.reply(200, {"ok": True, "version": "2.1.1"})
            self.assertEqual(guard_client.probe(g.lock).capabilities, frozenset())
            g.reply(200, "not json")
            self.assertEqual(guard_client.probe(g.lock).capabilities, frozenset())

    def test_unhealthy_or_absent_is_none(self):
        with FakeGuard() as g:
            g.reply(503, {"ok": False})
            self.assertIsNone(guard_client.probe(g.lock))
        self.assertIsNone(
            guard_client.probe(guard_client.GuardLock(host="127.0.0.1", port=9, token=""), timeout_s=1.0)
        )


if __name__ == "__main__":
    unittest.main()
