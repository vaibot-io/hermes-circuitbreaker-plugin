"""Pins the tool-name shim, and checks it against a real guard classifier.

The shim only matters for guards that predate ``host-vocab:hermes``, so the
node-backed test runs each renamed tool through whatever classifier the
sibling guard checkout ships — a released vocabulary — and asserts the rename
lands on a tool it recognises.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaibot.vocab import (  # noqa: E402
    LEGACY_NAMES,
    NATIVE_VOCAB_CAPABILITY,
    classifier_tool_name,
    guard_tool_name,
)


class ShimTests(unittest.TestCase):
    def test_native_names_go_to_a_guard_that_advertises_them(self):
        self.assertEqual(guard_tool_name("terminal", {NATIVE_VOCAB_CAPABILITY}), "terminal")
        self.assertEqual(guard_tool_name("write_file", [NATIVE_VOCAB_CAPABILITY, "other"]), "write_file")

    def test_older_guards_get_a_name_they_understand(self):
        self.assertEqual(guard_tool_name("terminal", ()), "shell")
        self.assertEqual(guard_tool_name("write_file", frozenset()), "write")
        self.assertEqual(guard_tool_name("patch", None), "edit")
        self.assertEqual(guard_tool_name("read_file", ["something-else"]), "read")

    def test_unmapped_tools_pass_through(self):
        self.assertEqual(guard_tool_name("browser_click", ()), "browser_click")
        self.assertEqual(guard_tool_name("mcp__github__x", ()), "mcp__github__x")

    def test_execute_code_is_never_renamed_to_a_shell(self):
        # Python read as a shell command would pass `cat = open(...)` as `cat`.
        self.assertNotIn("execute_code", LEGACY_NAMES)
        self.assertEqual(guard_tool_name("execute_code", ()), "execute_code")

    def test_offline_classify_always_renames(self):
        # No daemon to ask; the rename is right for every guard.
        self.assertEqual(classifier_tool_name("terminal"), "shell")
        self.assertEqual(classifier_tool_name("browser_click"), "browser_click")


_PROBE = r"""
const { classify } = await import(process.argv[2])
let raw = ''
for await (const c of process.stdin) raw += c
const out = {}
for (const [name, input] of JSON.parse(raw)) out[name] = classify({ tool: name, input })
process.stdout.write(JSON.stringify(out))
"""


class ReleasedClassifierTests(unittest.TestCase):
    """Every rename target is a tool the released classifier recognises."""

    def test_each_target_is_recognised(self):
        root = Path(os.environ.get("VAIBOT_GUARD_SRC") or Path(__file__).resolve().parents[2] / "vaibot-guard")
        module = root / "scripts" / "classifier.mjs"
        node = shutil.which("node")
        if not (node and module.is_file()):
            self.skipTest("node or the guard classifier is not available")

        # Assembled from fragments: no literal destructive command in this file.
        destructive = "".join(("rm", " -rf", " /"))
        calls = [[target, {"command": destructive, "path": "src/x", "urls": ["https://example.invalid"]}]
                 for target in LEGACY_NAMES.values()]
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "probe.mjs"
            script.write_text(_PROBE, encoding="utf-8")
            proc = subprocess.run([node, str(script), module.as_uri()], input=json.dumps(calls),
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verdicts = json.loads(proc.stdout)

        for hermes, target in LEGACY_NAMES.items():
            v = verdicts[target]
            self.assertFalse(v["reasons"][0].startswith("unknown tool"), f"{hermes}→{target}: {v}")
        # The one that matters most: the renamed shell tool still hits the floor.
        self.assertEqual(verdicts[LEGACY_NAMES["terminal"]]["verdictHint"], "deny")


if __name__ == "__main__":
    unittest.main()
