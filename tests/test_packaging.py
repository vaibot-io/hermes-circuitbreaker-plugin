"""Packaging: the things that only break once, at someone else's install.

Three classes of mistake are cheap to make here and expensive to find:

* **A wrong entry point.** Hermes loads the entry point and then looks for a
  ``register`` attribute on what it gets back, so ``vaibot`` (the module) loads and
  ``vaibot:register`` (the function) silently does not. The published plugin docs
  show the second form, which is exactly why this is pinned.
* **Version drift.** The wheel, the module and ``plugin.yaml`` each used to carry a
  literal. Two of the three are now derived; this holds the last one in step.
* **A dependency creeping in.** Zero runtime dependencies is a design rule, not an
  accident of the current imports: the plugin runs in-process inside someone
  else's agent on a security path. So the imports are checked, not just the
  declaration.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vaibot  # noqa: E402
from vaibot import guard as guard_client  # noqa: E402
from vaibot import launch  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # requires-python allows 3.10, where tomllib is absent
    tomllib = None

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
PLUGIN_YAML = ROOT / "vaibot" / "plugin.yaml"
ENTRY_POINT_GROUP = "hermes_agent.plugins"


def project() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def yaml_scalar(name: str) -> str:
    """One top-level scalar out of plugin.yaml, without a YAML parser.

    The plugin has no dependencies and neither does its test suite, and the two
    values read here are plain quoted scalars.
    """
    match = re.search(rf'^{name}:\s*"?([^"\n]+)"?\s*$', PLUGIN_YAML.read_text(encoding="utf-8"), re.M)
    return match.group(1).strip() if match else ""


def yaml_list(name: str) -> list:
    items, inside = [], False
    for line in PLUGIN_YAML.read_text(encoding="utf-8").splitlines():
        if re.match(rf"^{name}:\s*$", line):
            inside = True
            continue
        if inside:
            item = re.match(r"^  - (\S+)\s*$", line)
            if item:
                items.append(item.group(1))
                continue
            if line.strip() and not line.startswith("#"):
                break
    return items


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
class TestEntryPoint(unittest.TestCase):
    def test_the_group_is_the_one_hermes_scans(self):
        self.assertIn(ENTRY_POINT_GROUP, project()["project"]["entry-points"])

    def test_the_value_is_the_module_not_the_register_function(self):
        value = project()["project"]["entry-points"][ENTRY_POINT_GROUP]["vaibot"]
        self.assertEqual(value, "vaibot")
        self.assertNotIn(":", value, "Hermes looks for `register` ON the loaded object")

    def test_the_loaded_object_satisfies_the_loader(self):
        # What Hermes does: load the entry point, then getattr(module, "register").
        self.assertTrue(callable(getattr(vaibot, "register", None)))

    def test_the_entry_point_name_matches_the_manifest(self):
        name = list(project()["project"]["entry-points"][ENTRY_POINT_GROUP])[0]
        self.assertEqual(name, yaml_scalar("name"))


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
class TestVersionIsSingleSourced(unittest.TestCase):
    def test_the_build_reads_the_module(self):
        data = project()
        self.assertIn("version", data["project"].get("dynamic", []))
        self.assertNotIn("version", data["project"], "a literal here is a third place to forget")
        self.assertEqual(data["tool"]["hatch"]["version"]["path"], "vaibot/__init__.py")

    def test_the_manifest_agrees_with_the_module(self):
        self.assertEqual(yaml_scalar("version"), vaibot.__version__)


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
class TestZeroDependencies(unittest.TestCase):
    def test_nothing_is_declared(self):
        self.assertEqual(project()["project"]["dependencies"], [])

    #: Hermes' own modules. Allowed, but only from inside a function: the plugin
    #: has to import cleanly outside Hermes (that is how every test runs, and how
    #: `hermes vaibot` runs before a session exists), so a host import belongs
    #: behind a try/except at the point of use, never at module level.
    HOST_MODULES = {"tools"}

    def test_no_third_party_import_has_crept_in(self):
        # The declaration is only half of it: an import of something not in the
        # standard library would work on the developer's machine and fail inside
        # somebody's agent.
        allowed = set(sys.stdlib_module_names) | {"vaibot"}
        offenders, top_level_host = {}, {}
        for path in sorted((ROOT / "vaibot").glob("*.py")):
            for line in path.read_text(encoding="utf-8").splitlines():
                plain = re.match(r"^(\s*)import\s+([A-Za-z_][\w.]*)", line)
                froms = re.match(r"^(\s*)from\s+([A-Za-z_][\w.]*)\s+import\b", line)
                match = plain or froms
                if not match:
                    continue
                indent, name = match.group(1), match.group(2).split(".")[0]
                if name in allowed:
                    continue
                if name in self.HOST_MODULES:
                    if not indent:
                        top_level_host.setdefault(path.name, set()).add(name)
                    continue
                offenders.setdefault(path.name, set()).add(name)
        self.assertEqual(offenders, {}, "the plugin must import nothing but the standard library")
        self.assertEqual(top_level_host, {}, "a host import at module level breaks importing outside Hermes")

    def test_the_package_imports_with_no_hermes_present(self):
        # `tools` is Hermes'. Checked in a subprocess with it blocked outright, so
        # this proves the modules import without Hermes rather than depending on
        # what some earlier test happened to leave in sys.modules.
        modules = ", ".join(
            f"vaibot.{name}" for name in (
                "breaker", "cli", "commands", "config", "containment", "creds",
                "engine", "guard", "hostbypass", "launch", "localcli", "vocab",
            )
        )
        code = (
            f"import sys; sys.modules['tools'] = None; sys.path.insert(0, {str(ROOT)!r});"
            f"import vaibot, {modules}; print('ok')"
        )
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
class TestManifestShipsAndMatches(unittest.TestCase):
    def test_the_manifest_is_carried_in_the_wheel(self):
        # It is data, so package inclusion does not pick it up — and a pip install
        # that cannot be dropped into ~/.hermes/plugins/ is half an install.
        force = project()["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
        self.assertEqual(force["vaibot/plugin.yaml"], "vaibot/plugin.yaml")

    def test_declared_hooks_are_the_hooks_registered(self):
        ctx = mock.Mock()
        with mock.patch.object(vaibot, "resolve_credentials") as rc, \
             mock.patch.object(guard_client, "read_lock", return_value=None), \
             mock.patch.object(launch, "ensure_in_background"):
            rc.return_value.key_mismatch = False
            vaibot.register(ctx)
        registered = sorted(c.args[0] for c in ctx.register_hook.call_args_list)
        self.assertEqual(registered, sorted(yaml_list("provides_hooks")))

    def test_the_manifest_uses_the_key_hermes_reads(self):
        text = PLUGIN_YAML.read_text(encoding="utf-8")
        self.assertIn("provides_hooks:", text)
        self.assertNotRegex(text, r"(?m)^hooks:", "Hermes parses `provides_hooks`, not `hooks`")


if __name__ == "__main__":
    unittest.main()
