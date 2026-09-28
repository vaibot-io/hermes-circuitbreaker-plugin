// @vaibot/guard — minimal EnvironmentFile loader.
//
// The guard reads its configuration from process.env. Under systemd that env is
// populated by `EnvironmentFile=~/.config/vaibot-guard/vaibot-guard.env`. But the
// SAME shared guard can be cold-started by a plugin (ensureGuard self-spawn), and
// that path does NOT source the file — so a self-spawned guard would miss whatever
// the CLI pinned there (notably VAIBOT_POLICY_URL + VAIBOT_POLICY_PUBKEY), and the
// single entity would behave differently depending on who launched it.
//
// Loading that same file here makes the one guard read one config no matter who
// starts it. Precedence: the real process.env ALWAYS wins — the file only fills
// keys that are unset — so systemd / launcher / shell values are never clobbered
// (the launcher's scanned port + token in particular), and under systemd this is a
// harmless no-op.
//
// The parser mirrors systemd's EnvironmentFile semantics for the subset the CLI
// emits: `KEY=value`, `#` / `;` comment lines, blank lines, and single/double-
// quoted values that MAY span multiple physical lines (newlines preserved inside
// quotes — this is how the multi-line PEM in VAIBOT_POLICY_PUBKEY is carried).
// Fail-safe: any error is a silent no-op.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** The path the CLI writes — matches `guard_env_path()` in the Rust CLI exactly
 *  (literal `~/.config`, not XDG-derived). */
export function defaultGuardEnvPath() {
  return join(homedir(), ".config", "vaibot-guard", "vaibot-guard.env");
}

/**
 * Parse EnvironmentFile-style content into a plain object. Pure; never throws.
 * @param {string} content
 * @returns {Record<string,string>}
 */
export function parseEnvFile(content) {
  const out = {};
  if (typeof content !== "string") return out;
  const s = content;
  const n = s.length;
  let i = 0;
  while (i < n) {
    // Skip blank lines / leading whitespace.
    while (i < n && (s[i] === " " || s[i] === "\t" || s[i] === "\r" || s[i] === "\n")) i++;
    if (i >= n) break;
    // Comment line → to EOL.
    if (s[i] === "#" || s[i] === ";") {
      while (i < n && s[i] !== "\n") i++;
      continue;
    }
    // KEY up to '=' (no '=' on the line → not an assignment, skip it).
    const keyStart = i;
    while (i < n && s[i] !== "=" && s[i] !== "\n") i++;
    if (i >= n || s[i] === "\n") continue;
    const key = s.slice(keyStart, i).trim();
    i++; // consume '='
    // VALUE.
    let value = "";
    if (i < n && (s[i] === '"' || s[i] === "'")) {
      const quote = s[i];
      i++; // opening quote
      let buf = "";
      while (i < n && s[i] !== quote) {
        // Inside double quotes, honor a backslash escape of the quote or of a
        // backslash. PEM bodies contain neither, so this is just correctness.
        if (quote === '"' && s[i] === "\\" && i + 1 < n && (s[i + 1] === '"' || s[i + 1] === "\\")) {
          buf += s[i + 1];
          i += 2;
          continue;
        }
        buf += s[i];
        i++;
      }
      i++; // closing quote (or EOF)
      value = buf;
      while (i < n && s[i] !== "\n") i++; // ignore trailing junk on the line
    } else {
      const valStart = i;
      while (i < n && s[i] !== "\n") i++;
      value = s.slice(valStart, i).trim();
    }
    if (key) out[key] = value;
  }
  return out;
}

/**
 * Fill `env` (default process.env) from the guard env file WITHOUT overriding any
 * key already set — real env wins. Fail-safe: a missing/unreadable file is a
 * silent no-op. Returns the keys it actually filled (for logging/tests).
 * @param {{ path?: string, env?: Record<string,string|undefined> }} [opts]
 * @returns {string[]}
 */
export function loadGuardEnvFile(opts = {}) {
  const filePath = opts.path || defaultGuardEnvPath();
  const env = opts.env || process.env;
  let content;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }
  const parsed = parseEnvFile(content);
  const filled = [];
  for (const [k, v] of Object.entries(parsed)) {
    if (env[k] === undefined) {
      env[k] = v;
      filled.push(k);
    }
  }
  return filled;
}
