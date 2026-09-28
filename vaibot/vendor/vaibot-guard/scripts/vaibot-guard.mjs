#!/usr/bin/env node
/**
 * vaibot-guard (MVP CLI)
 *
 * Implements the interface described in SKILL.md:
 * - vaibot-guard precheck --intent '<json>'
 * - vaibot-guard exec --intent '<json>' -- <command...>
 * - vaibot-guard finalize --run_id <id> --result '<json>'
 */

import http from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";

const GUARD_HOST = process.env.VAIBOT_GUARD_HOST || "127.0.0.1";

const DEFAULT_ENV_PATH = path.join(os.homedir(), ".config", "vaibot-guard", "vaibot-guard.env");

function parseEnvFile(p) {
  if (!fs.existsSync(p)) return {};
  const out = {};
  const lines = fs.readFileSync(p, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    const m = s.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) continue;
    let v = m[2];
    // strip simple quotes
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    out[m[1]] = v;
  }
  return out;
}

function sha256Hex(s) {
  return createHash("sha256").update(s).digest("hex");
}

function genGuardToken() {
  // 32 bytes -> 64 hex chars
  return sha256Hex(randomBytes(32));
}

function writeEnvFile(p, kv) {
  const dir = path.dirname(p);
  fs.mkdirSync(dir, { recursive: true });

  // Write deterministic key order for readability.
  const keys = Object.keys(kv).sort();
  const lines = ["# VAIBot Guard environment"]; 
  for (const k of keys) {
    const v = kv[k];
    if (v === undefined || v === null || v === "") continue;
    lines.push(`${k}=${String(v)}`);
  }
  lines.push("");

  fs.writeFileSync(p, lines.join("\n"), { mode: 0o600 });
  try { fs.chmodSync(p, 0o600); } catch {}
}

function ensureGuardToken(envFilePath) {
  const current = parseEnvFile(envFilePath);
  const token = process.env.VAIBOT_GUARD_TOKEN || current.VAIBOT_GUARD_TOKEN;
  if (token) return { token, created: false };

  const newToken = genGuardToken();
  // Preserve existing keys but add token.
  current.VAIBOT_GUARD_TOKEN = newToken;
  // Preserve port if present; otherwise default.
  if (!current.VAIBOT_GUARD_PORT) current.VAIBOT_GUARD_PORT = "39111";

  writeEnvFile(envFilePath, current);
  return { token: newToken, created: true };
}

const ENV_FILE = process.env.VAIBOT_GUARD_ENV_FILE || DEFAULT_ENV_PATH;
const FILE_ENV = parseEnvFile(ENV_FILE);

function getConfig(key, fallback) {
  return process.env[key] ?? FILE_ENV[key] ?? fallback;
}

const GUARD_PORT = Number(getConfig("VAIBOT_GUARD_PORT", 39111));

function die(msg, code = 2) {
  console.error(msg);
  process.exit(code);
}

function requestJson(path, payload) {
  const body = JSON.stringify(payload);
  const token = getConfig("VAIBOT_GUARD_TOKEN", "");
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  };
  if (token) headers["authorization"] = `Bearer ${token}`;

  const options = {
    hostname: GUARD_HOST,
    port: GUARD_PORT,
    path,
    method: "POST",
    headers,
    timeout: 5000,
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data || "{}"));
        } catch {
          reject(new Error(`invalid JSON from guard: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("guard request timeout")));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function parseArgs(argv) {
  // Minimal flag parsing (MVP)
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      out._.push("--");
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const v = argv[i + 1];
      if (!v || v.startsWith("--")) out[k] = true;
      else {
        out[k] = v;
        i++;
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

function parseJsonFlag(name, value) {
  if (!value) die(`Missing --${name}`);
  try {
    return JSON.parse(value);
  } catch {
    die(`--${name} must be valid JSON`);
  }
}

const [command, ...rest] = process.argv.slice(2);
if (!command || command === "-h" || command === "--help") {
  console.log(`vaibot-guard (MVP)\n\nCommands:\n  install-local\n  configure [--env_file <path>]\n  classify [--intent '<json>'] [--escalate-at <risk>]   (or intent on stdin)\n  bootstrap --agent <name> [--timeout-ms <n>]\n  precheck --intent '<json>'\n  exec --intent '<json>' -- <command...>\n  finalize --run_id <id> --result '<json>'\n  flush [--session_id <id>]\n  proof --session_id <id> --index <n> --checkpoint_seq <n>\n\nNotes:\n  - CLI reads VAIBOT_GUARD_TOKEN/PORT from env or from ${ENV_FILE}\n`);
  process.exit(0);
}

const flags = parseArgs(rest);
const sessionId = process.env.VAIBOT_SESSION_ID || process.env.OPENCLAW_SESSION_KEY || process.env.OPENCLAW_SESSION || "unknown-session";

/** Read all of stdin as a string. Returns "" when stdin is a TTY (nothing piped). */
async function readStdin() {
  if (process.stdin.isTTY) return "";
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  return raw;
}

async function maybeOnboard() {
  // `classify` is a pure, offline query used on degraded paths where the daemon
  // may be down — it must never prompt, write an env file, or restart a unit.
  // `bootstrap` is called by a breaker from inside an agent: same constraint,
  // and its only write is the credential store it exists to populate.
  if (command === "configure" || command === "classify" || command === "bootstrap") return;

  // Only prompt in interactive terminals.
  if (!process.stdin.isTTY) return;

  const envFile = ENV_FILE;

  // Ensure a guard token exists on first run (creates env file if needed).
  const tok = ensureGuardToken(envFile);
  if (tok.created) {
    console.error(`Generated VAIBOT_GUARD_TOKEN and wrote ${envFile} (chmod 600).`);

    // If systemd user unit appears installed, offer to restart it so the running service picks up the new token.
    const userUnitPath = path.join(os.homedir(), ".config", "systemd", "user", "vaibot-guard.service");
    const hasUnit = fs.existsSync(userUnitPath);

    if (hasUnit) {
      const rl2 = readline.createInterface({ input: process.stdin, output: process.stdout });
      try {
        const ans = (await rl2.question("Restart systemd user service vaibot-guard now to pick up the new token? [y/N]: ")).trim().toLowerCase();
        if (ans === "y" || ans === "yes") {
          try {
            const { execSync } = await import("node:child_process");
            execSync("systemctl --user restart vaibot-guard", { stdio: "inherit" });
          } catch (e) {
            console.error(`WARN: failed to restart vaibot-guard: ${e?.message || e}`);
            console.error("You can run manually: systemctl --user restart vaibot-guard");
          }
        }
      } finally {
        rl2.close();
      }
    }
  }

  const current = parseEnvFile(envFile);
  const proveMode = String(process.env.VAIBOT_PROVE_MODE || current.VAIBOT_PROVE_MODE || "best-effort").trim();
  const hasApiKey = !!(process.env.VAIBOT_API_KEY || current.VAIBOT_API_KEY);

  // Only prompt for VAIBOT_API_KEY if the operator explicitly configured fail-closed proving.
  if (proveMode === "required" && !hasApiKey) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      const ans = (
        await rl.question(
          `VAIBOT_PROVE_MODE=required but no VAIBOT_API_KEY found (env or ${envFile}). Run ./scripts/vaibot-guard configure now? [y/N]: `,
        )
      )
        .trim()
        .toLowerCase();
      if (ans === "y" || ans === "yes") {
        // Re-run configure in-process by setting flags for cmdConfigure.
        flags.env_file = envFile;
        await cmdConfigure();
      }
    } finally {
      rl.close();
    }
  }
}

// Poll GET /health until healthy or timeout. Used to gate a service install.
// Poll GET /health until healthy or timeout. `ownership` = { sinceMs, readLock }: when
// given, additionally require the rendezvous (guard.json) to show OUR freshly-started
// instance on this exact port — i.e. an instance that started at/after the install began.
// That distinguishes "the unit WE just started answered" from "a stale/foreign guard
// already squatting this port answered while our unit crash-loops behind it" — WITHOUT
// authenticating /health. Without `ownership`, it's a plain unauthenticated /health check.
async function pollGuardHealth(port, timeoutMs, ownership = null) {
  const token = getConfig("VAIBOT_GUARD_TOKEN", "");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://${GUARD_HOST}:${port}/health`, {
        headers: token ? { authorization: `Bearer ${token}` } : {},
        signal: AbortSignal.timeout(1000),
      });
      if (res.ok) {
        const body = await res.json().catch(() => ({}));
        const alive = !!(body && body.ok === true);
        if (alive && !ownership) return true;
        if (alive && ownership) {
          const lock = ownership.readLock();
          const owned =
            lock &&
            Number(lock.port) === Number(port) &&
            (Number(lock.startedAt) || 0) >= ownership.sinceMs;
          if (owned) return true;
        }
      }
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

// `vaibot-guard install` — non-interactive, platform-aware service install. Walks the
// root-preferred ladder (systemd / launchd / self-spawn) via installGuardService, writes
// + starts the best available tier, then health-verifies. `--system` opts into the
// root/sudo tamper-boundary tier. Exits 0 on healthy (or self-spawn), 1 on trouble.
async function cmdInstall() {
  const [{ installGuardService }, { readGuardEndpoint, writeGuardEndpoint }, { readLock }] = await Promise.all([
    import("./lib/guard-install.mjs"),
    import("./lib/creds.mjs"),
    import("./lib/guard-bootstrap.mjs"),
  ]);
  const serviceScript = path.join(path.dirname(fileURLToPath(import.meta.url)), "vaibot-guard-service.mjs");

  // Ensure a token + env file exist before the supervisor loads them.
  ensureGuardToken(ENV_FILE);

  const useSystem = flags["system"] === true || flags["system"] === "true";
  // launchd runs with CWD=/ and no stdout — set a working dir so the guard's default
  // workspace is sane, and capture stdout/stderr so a startup crash is visible.
  const guardDir = path.join(os.homedir(), ".vaibot", "guard");
  try { fs.mkdirSync(guardDir, { recursive: true }); } catch { /* best-effort */ }

  // Pin + persist the endpoint so the unit, the health-verify, and every client agree on
  // ONE port — never a bare default a foreign guard might already hold. Record the install
  // start so the health-verify can confirm OUR fresh unit (not a stale process) took over.
  const guardPort = readGuardEndpoint()?.port ?? GUARD_PORT;
  try { writeGuardEndpoint({ host: GUARD_HOST, port: guardPort }); } catch { /* best-effort */ }
  const installStart = Date.now();

  const res = await installGuardService({
    execStart: `/usr/bin/env node ${serviceScript}`,
    programArgs: [process.execPath, serviceScript],
    envFile: ENV_FILE,
    envVars: { VAIBOT_GUARD_ENV_FILE: ENV_FILE, VAIBOT_GUARD_PORT: String(guardPort) },
    workingDir: os.homedir(),
    stdout: path.join(guardDir, "launchd.out.log"),
    stderr: path.join(guardDir, "launchd.err.log"),
    uid: typeof process.getuid === "function" ? process.getuid() : undefined,
    canSudo: useSystem,
  });

  if (res.selfSpawn) {
    const { detectContainer, detectCI, commandExists } = await import("./lib/guard-supervisor.mjs");
    const why = [];
    if (detectContainer()) why.push("container detected");
    if (detectCI()) why.push("CI environment detected (a CI_* env var is set)");
    if (process.platform === "darwin" && !commandExists("launchctl")) why.push("launchctl not on PATH");
    else if (process.platform === "linux" && !commandExists("systemctl")) why.push("systemctl not on PATH");
    else if (process.platform !== "darwin" && process.platform !== "linux") why.push(`unsupported platform '${process.platform}'`);
    console.log(`[vaibot-guard] No managed service tier selected — reason: ${why.join("; ") || "unknown (platform " + process.platform + ")"}.`);
    console.log("[vaibot-guard] Self-spawning on the first agent tool call instead — governance is still enforced, just not auto-started at boot.");
    process.exit(0);
  }
  if (!res.ok) {
    console.error(`[vaibot-guard] Service install failed (${res.tier} tier): ${res.error || "unknown"}`);
    console.error("[vaibot-guard] The guard falls back to self-spawn on the next tool call. See ~/.vaibot/guard/launch.log.");
    process.exit(1);
  }
  console.log(`[vaibot-guard] Installed + started as a ${res.tier}-scope service.`);

  // Verify OUR freshly-started unit is actually serving on the pinned port — not a stale
  // guard already squatting it while our unit crash-loops behind it (no /health gating;
  // the ownership check reads the rendezvous startedAt).
  const healthy = await pollGuardHealth(guardPort, 8000, { sinceMs: installStart, readLock });
  if (healthy) {
    console.log(`[vaibot-guard] Healthy on ${GUARD_HOST}:${guardPort}.`);
    process.exit(0);
  }
  console.error(
    `[vaibot-guard] WARN: the service did not take over ${GUARD_HOST}:${guardPort} within 8s ` +
    "(crash-loop, or another guard already holds the port). Check `systemctl --user status " +
    "vaibot-guard`, ~/.vaibot/guard/launchd.err.log, and stop any stray guard, then retry.",
  );
  process.exit(1);
}

async function cmdInstallLocal() {
  if (!process.stdin.isTTY) {
    die("install-local requires a TTY");
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
    const SKILL_DIR = path.resolve(SCRIPT_DIR, "..");
    const envSrc = path.join(SKILL_DIR, "references", "systemd", "vaibot-guard.env");

    // The unit must name the code it runs by ABSOLUTE path.
    //
    // ExecStart used to be `node scripts/vaibot-guard-service.mjs`, resolved
    // against WorkingDirectory — so the unit recorded whichever directory
    // install-local happened to run from, and then executed whatever code later
    // sat there. On one machine that produced three candidate runtimes (an
    // OpenClaw skill copy, a monorepo checkout, and the npm install) with the
    // unit naming a directory that was not the one actually serving. An
    // absolute entry point makes the unit name a specific file.
    const SERVICE_ENTRY = path.join(SKILL_DIR, "scripts", "vaibot-guard-service.mjs");
    if (!fs.existsSync(SERVICE_ENTRY)) {
      die(`cannot find the service entry point at ${SERVICE_ENTRY}`);
    }

    // A source checkout is not a runtime. Installing from one means `git
    // checkout` silently changes what the service will run on its next start,
    // and the version it reports tracks whichever branch is out — which makes
    // guard_version telemetry fiction. Refuse by default, with an explicit
    // escape for anyone who knows they want it.
    const inSourceTree = (() => {
      let dir = SKILL_DIR;
      for (let i = 0; i < 6; i++) {
        if (fs.existsSync(path.join(dir, ".git"))) return dir;
        const up = path.dirname(dir);
        if (up === dir) break;
        dir = up;
      }
      return null;
    })();
    if (inSourceTree && !process.argv.includes("--allow-source-tree")) {
      die(
        `refusing to install a service that runs from a source checkout (${inSourceTree}).\n` +
          `  A checkout is not a runtime: switching branches changes what the service runs,\n` +
          `  and the version it reports follows whatever is checked out.\n` +
          `  Install the published package first:  npm install -g @vaibot/guard\n` +
          `  then re-run install-local from there. To override anyway: --allow-source-tree`,
      );
    }

    // Option A: generate the systemd unit entirely in code, so we don't depend
    // on shipping any `*.service` files. The openclaw-gateway ordering deps are
    // added only on OpenClaw hosts (detected by the `openclaw` binary on PATH);
    // the guard runs standalone for any other agent. WorkingDirectory stays for
    // relative policy/log paths, but no longer decides which code runs.
    const isOpenClawHost = (process.env.PATH || "")
      .split(path.delimiter)
      .some((dir) => {
        try {
          return fs.existsSync(path.join(dir, "openclaw"));
        } catch {
          return false;
        }
      });
    const unitDeps = isOpenClawHost
      ? "After=network-online.target openclaw-gateway.service\nWants=openclaw-gateway.service\nPartOf=openclaw-gateway.service\n"
      : "After=network-online.target\n";
    const unitTemplate = `[Unit]\nDescription=VAIBot Guard policy service (user)\n${unitDeps}\n[Service]\nType=simple\nWorkingDirectory=${SKILL_DIR}\nEnvironmentFile=%h/.config/vaibot-guard/vaibot-guard.env\nExecStart=/usr/bin/env node ${SERVICE_ENTRY}\nRestart=on-failure\nRestartSec=2\n\n# Hardening (user-scope, safe defaults)\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n`;

    const envTemplate = `# VAIBot Guard (user service) environment\n\n# Required for service auth (recommended)\n# VAIBOT_GUARD_TOKEN=\n\n# Policy file\n# VAIBOT_POLICY_PATH=references/policy.default.json\n\n# Service bind\n# VAIBOT_GUARD_HOST=127.0.0.1\n# VAIBOT_GUARD_PORT=39111\n\n# Workspace + logs\n# VAIBOT_WORKSPACE=\n# VAIBOT_GUARD_LOG_DIR=\n\n# VAIBot anchoring\n# VAIBOT_API_URL=https://provenance.vaibot.io/api\n# VAIBOT_API_KEY=\n# VAIBOT_PROVE_MODEL=vaibot-guard\n# VAIBOT_PROVE_MODE=best-effort\n\n# Checkpoint cadence\n# VAIBOT_MERKLE_CHECKPOINT_EVERY=50\n# VAIBOT_MERKLE_CHECKPOINT_EVERY_MS=600000\n`;
    const unitDstDir = path.join(os.homedir(), ".config", "systemd", "user");
    const unitDst = path.join(unitDstDir, "vaibot-guard.service");
    const envDstDir = path.join(os.homedir(), ".config", "vaibot-guard");
    const envDst = path.join(envDstDir, "vaibot-guard.env");

    const ans1 = (await rl.question("Install systemd user unit + env file for vaibot-guard? [y/N]: ")).trim().toLowerCase();
    if (!(ans1 === "y" || ans1 === "yes")) {
      console.error("Aborted.");
      process.exit(1);
    }

    fs.mkdirSync(unitDstDir, { recursive: true });
    fs.mkdirSync(envDstDir, { recursive: true });

    // Install unit file (overwrite). Generated from the embedded template so we
    // don't depend on shipping any unit files in the skill package.
    fs.writeFileSync(unitDst, unitTemplate);

    // Install env file only if it doesn't exist.
    if (!fs.existsSync(envDst)) {
      if (fs.existsSync(envSrc)) {
        fs.copyFileSync(envSrc, envDst);
      } else {
        fs.writeFileSync(envDst, envTemplate);
      }
      try { fs.chmodSync(envDst, 0o600); } catch {}
    }

    console.error(`Installed unit: ${unitDst}`);
    console.error(`Env file: ${envDst}`);

    // Run configure (prompts for API key, generates token, etc.)
    const ans2 = (await rl.question("Run interactive configure now to set VAIBOT_API_KEY and generate token? [y/N]: ")).trim().toLowerCase();
    if (ans2 === "y" || ans2 === "yes") {
      flags.env_file = envDst;
      await cmdConfigure();
      // cmdConfigure exits on success; if it doesn't, continue.
    }

    const ans3 = (await rl.question("Enable + start vaibot-guard now (systemctl --user enable --now)? [y/N]: ")).trim().toLowerCase();
    if (ans3 === "y" || ans3 === "yes") {
      const { execSync } = await import("node:child_process");
      execSync("systemctl --user daemon-reload", { stdio: "inherit" });
      execSync("systemctl --user enable --now vaibot-guard", { stdio: "inherit" });
      execSync("systemctl --user status vaibot-guard --no-pager", { stdio: "inherit" });
    } else {
      console.error("You can start later with: systemctl --user enable --now vaibot-guard");
    }

    process.stdout.write(JSON.stringify({ ok: true, unitDst, envDst }, null, 2) + "\n");
    process.exit(0);
  } finally {
    rl.close();
  }
}

async function cmdConfigure() {
  const envFile = flags.env_file || flags.envFile || ENV_FILE;
  const dir = path.dirname(envFile);
  fs.mkdirSync(dir, { recursive: true });

  if (!process.stdin.isTTY) {
    die(`configure requires a TTY. Edit ${envFile} manually or run in an interactive terminal.`);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const current = parseEnvFile(envFile);

    // Required user-defined value
    // Prove/anchoring mode. Keep defaults non-annoying: anchoring is optional.
    const proveMode = (current.VAIBOT_PROVE_MODE || (await rl.question("VAIBOT_PROVE_MODE (optional, default best-effort) [required|best-effort|off]: ")).trim()) || "best-effort";

    // VAIBot anchoring credentials are optional unless prove mode is required.
    const apiKeyPrompt = proveMode === "required" ? "VAIBOT_API_KEY (required): " : "VAIBOT_API_KEY (optional, press enter to skip): ";
    const apiKey = current.VAIBOT_API_KEY || (await rl.question(apiKeyPrompt)).trim();
    if (proveMode === "required" && !apiKey) die("VAIBOT_API_KEY is required when VAIBOT_PROVE_MODE=required");

    const portIn = (current.VAIBOT_GUARD_PORT || (await rl.question("VAIBOT_GUARD_PORT (optional, default 39111): ")).trim());
    const guardPort = portIn ? String(Number(portIn)) : "39111";

    let guardToken = current.VAIBOT_GUARD_TOKEN || (await rl.question("VAIBOT_GUARD_TOKEN (optional, press enter to auto-generate): ")).trim();
    if (!guardToken) guardToken = genGuardToken();

    const apiUrl = current.VAIBOT_API_URL || (await rl.question("VAIBOT_API_URL (optional, default https://provenance.vaibot.io/api): ")).trim() || "https://provenance.vaibot.io/api";

    const content =
      "# VAIBot Guard environment\n" +
      `VAIBOT_API_URL=${apiUrl}\n` +
      (apiKey ? `VAIBOT_API_KEY=${apiKey}\n` : "") +
      `VAIBOT_PROVE_MODE=${proveMode}\n` +
      `VAIBOT_GUARD_PORT=${guardPort}\n` +
      `VAIBOT_GUARD_TOKEN=${guardToken}\n`;

    fs.writeFileSync(envFile, content, { mode: 0o600 });
    try { fs.chmodSync(envFile, 0o600); } catch {}

    console.error(`Wrote ${envFile} (chmod 600).`);

    // If systemd user unit appears installed, offer to enable/start it.
    const userUnitPath = path.join(os.homedir(), ".config", "systemd", "user", "vaibot-guard.service");
    const hasUnit = fs.existsSync(userUnitPath);

    if (hasUnit) {
      const ans = (await rl.question("Detected systemd user unit (~/.config/systemd/user/vaibot-guard.service). Enable + start now? [y/N]: ")).trim().toLowerCase();
      if (ans === "y" || ans === "yes") {
        try {
          const { execSync } = await import("node:child_process");
          execSync("systemctl --user daemon-reload", { stdio: "inherit" });
          execSync("systemctl --user enable --now vaibot-guard", { stdio: "inherit" });
          execSync("systemctl --user status vaibot-guard --no-pager", { stdio: "inherit" });
        } catch (e) {
          console.error(`WARN: failed to enable/start vaibot-guard via systemd: ${e?.message || e}`);
          console.error("You can run manually: systemctl --user enable --now vaibot-guard");
        }
      } else {
        console.error("OK. You can start later with: systemctl --user enable --now vaibot-guard");
      }
    } else {
      console.error("To run as a service, install the systemd user unit from systemd/user/ (see references/ops-runbook.md).");
    }

    // machine-readable output
    process.stdout.write(JSON.stringify({ ok: true, envFile }, null, 2) + "\n");
    process.exit(0);
  } finally {
    rl.close();
  }
}

if (command === "install") {
  await cmdInstall();
}

if (command === "install-local") {
  await cmdInstallLocal();
}

if (command === "configure") {
  await cmdConfigure();
}

await maybeOnboard();

if (command === "bootstrap") {
  // One-shot account provisioning for a breaker that has no API key.
  //
  // WHY here: ~/.vaibot/credentials.json is shared by every breaker on the
  // machine, and creds.mjs is its single writer — merge-on-write per env, legacy
  // format migration, atomic rename. A non-Node host (the Hermes Python plugin)
  // calls this rather than growing a second writer in a second language.
  //
  //   vaibot-guard bootstrap --agent hermes
  //
  // stdout (exit 0) is one JSON line. It never carries the key: the caller
  // re-reads it from the store, so the secret doesn't cross a process boundary.
  //   {"ok":true,"env":"…","provisioned":true,"wallet_address":"0x…","wallet_network":"…"}
  //   {"ok":true,"env":"…","provisioned":false,"reason":"key-present"}     no network call made
  //   {"ok":true,"env":"…","provisioned":false,"reason":"account-exists"}  this machine has an
  //       account but the local key is gone — recover with `vaibot login`
  // Any non-zero exit prints nothing on stdout: the caller could not get an
  // answer and must fall back to its own keyless posture.
  const { migrateFileIfNeeded, resolveCredentials, saveCredsForEnv, keyPrefixMatchesEnv } = await import("./lib/creds.mjs");

  const agent = typeof flags.agent === "string" ? flags.agent.trim() : "";
  if (!/^[a-z][a-z0-9_-]{0,63}$/.test(agent)) die("bootstrap: --agent <name> is required (e.g. --agent hermes)");
  const timeoutMs = Number(flags["timeout-ms"]) > 0 ? Number(flags["timeout-ms"]) : 10000;

  migrateFileIfNeeded();
  // resolveCredentials applies the §5 gate: a production URL override is
  // ignored unless VAIBOT_ALLOW_URL_OVERRIDE is set, so an injected env var
  // can't redirect provisioning to a host of its choosing.
  const resolved = resolveCredentials();
  const answer = (fields) => {
    process.stdout.write(JSON.stringify({ ok: true, env: resolved.env, ...fields }) + "\n");
    process.exit(0);
  };

  if (resolved.apiKey) answer({ provisioned: false, reason: "key-present" });

  // The fingerprint every breaker sends: one account per user@host, whichever
  // breaker gets there first, so a machine never forks into several identities.
  const fingerprint = createHash("sha256").update(`${os.userInfo().username}@${os.hostname()}`).digest("hex");

  let res;
  try {
    res = await fetch(`${resolved.apiBaseUrl}/v2/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fingerprint, agent }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    die(`bootstrap: ${resolved.apiBaseUrl} unreachable — ${e?.message || e}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    die(`bootstrap: server returned ${res.status} ${text.slice(0, 200)}`);
  }
  let data;
  try {
    data = await res.json();
  } catch {
    die("bootstrap: server returned invalid JSON");
  }

  if (typeof data?.api_key === "string" && data.api_key) {
    // A key for the wrong env would be stored, then ignored by every reader
    // (keyMismatch), and bootstrap would run again on every call. Refuse it.
    if (!keyPrefixMatchesEnv(data.api_key, resolved.env)) {
      die(`bootstrap: server issued a key for a different environment than ${resolved.env} — not saved`);
    }
    saveCredsForEnv(resolved.env, { api_key: data.api_key, wallet_address: data.wallet_address });
    answer({
      provisioned: true,
      wallet_address: typeof data.wallet_address === "string" ? data.wallet_address : null,
      wallet_network: typeof data.wallet_network === "string" ? data.wallet_network : null,
    });
  }
  if (data?.bootstrapped === false) answer({ provisioned: false, reason: "account-exists" });
  die("bootstrap: server answered with neither a key nor an existing account");
}

if (command === "classify") {
  // One-shot, offline risk classification.
  //
  // WHY: every circuit-breaker plugin falls back to the local classifier when the
  // daemon is unreachable — that fallback IS the safety floor. The classifier is
  // Node, so a non-Node host (the Hermes Python plugin) could only reach it by
  // reimplementing it, which would mean two implementations of the floor drifting
  // apart. This exposes the real one instead. No daemon, no network, no writes —
  // "daemon down" does not imply "node missing", so this still answers.
  //
  //   echo '{"toolName":"Bash","params":{"command":"rm -rf /"}}' | vaibot-guard classify
  //   vaibot-guard classify --intent '{"tool":"Write","input":{"file_path":"/etc/hosts"}}'
  //
  // stdout: the classifier verdict. Callers read `verdictHint` (allow|ask|deny).
  // Exit 0 = classified. Exit 2 = could not classify — callers MUST treat that as
  // a failure to answer and fall back to their own fail-closed posture, never as
  // an allow.
  const { classify } = await import("./classifier.mjs");

  const raw = flags.intent ? String(flags.intent) : await readStdin();
  if (!String(raw).trim()) {
    die("classify: provide an intent on stdin or via --intent '<json>'");
  }

  let intent;
  try {
    intent = JSON.parse(raw);
  } catch (e) {
    die(`classify: invalid JSON intent — ${e?.message || e}`);
  }
  if (!intent || typeof intent !== "object") die("classify: intent must be a JSON object");

  // Accept both shapes: the classifier's native {tool,input} and the wire shape
  // {toolName,params} that /v1/decide/tool already speaks, so a caller holding a
  // decide payload can pass it straight through without reshaping.
  const tool = intent.tool ?? intent.toolName;
  const input = intent.input ?? intent.params;
  if (typeof tool !== "string" || !tool.trim()) {
    die("classify: intent requires a non-empty `tool` (or `toolName`)");
  }

  // escalateAt lets a caller reproduce a preset's ask threshold; omitted means the
  // classifier's own default. guardPort feeds the guard self-protection patterns.
  const escalateAt = flags["escalate-at"] ?? flags.escalateAt ?? intent.escalateAt;

  let verdict;
  try {
    verdict = classify(
      { tool, input },
      { ...(escalateAt ? { escalateAt: String(escalateAt) } : {}), guardPort: GUARD_PORT },
    );
  } catch (e) {
    // Never emit a partial or guessed verdict — an unusable answer must look like
    // a failure so the caller falls back to fail-closed instead of reading a
    // missing verdictHint as "allow".
    die(`classify: classifier error — ${e?.message || e}`, 2);
  }

  process.stdout.write(JSON.stringify(verdict) + "\n");
  process.exit(0);
} else if (command === "precheck") {
  const intent = parseJsonFlag("intent", flags.intent);

  // For now, we decide based on the actual command you intend to run.
  // Prefer intent.command if present; fallback to intent.command string.
  const cmd = String(intent.command || "").split(" ")[0];
  const args = Array.isArray(intent.args) ? intent.args.map(String) : [];
  if (!cmd) die("intent.command required for precheck");

  const resp = await requestJson("/v1/decide/exec", { sessionId, cmd, args, intent });
  if (!resp?.ok) die(`precheck failed: ${resp?.error || "unknown"}`, 10);

  // Pretty summary (stderr) + machine-readable JSON (stdout)
  if (resp?.risk) {
    console.error(`risk: ${resp.risk.risk} (${resp.risk.reason})`);
  }
  if (resp?.decision) {
    console.error(`decision: ${resp.decision.decision} — ${resp.decision.reason}`);
    if (resp.decision.approvalId) console.error(`approvalId: ${resp.decision.approvalId}`);
  }
  if (resp?.prove && resp.prove.ok === false) {
    console.error(`prove: failed — ${resp.prove.error || "unknown"}`);
  }

  process.stdout.write(JSON.stringify(resp, null, 2) + "\n");
  process.exit(0);
} else if (command === "exec") {
  const intent = parseJsonFlag("intent", flags.intent);

  // parse command after --
  const idx = flags._.indexOf("--");
  if (idx === -1) die("exec requires -- <command...>");

  const cmd = flags._[idx + 1];
  const args = flags._.slice(idx + 2);
  if (!cmd) die("exec missing command after --");

  const pre = await requestJson("/v1/decide/exec", { sessionId, cmd, args, intent });
  if (!pre?.ok) die(`precheck failed: ${pre?.error || "unknown"}`, 10);

  if (pre?.risk) console.error(`risk: ${pre.risk.risk} (${pre.risk.reason})`);

  const d = pre.decision;
  if (d.decision === "deny") {
    console.error(`DENY: ${d.reason}`);
    process.exit(20);
  }
  if (d.decision === "approve") {
    console.error(`REQUIRE_APPROVAL: ${d.reason}`);
    console.error(`run_id: ${pre.runId}`);
    console.error(`approval_id: ${d.approvalId}`);
    process.exit(21);
  }

  // allowed -> run
  const child = spawn(cmd, args, { stdio: "inherit", env: process.env, cwd: intent.cwd || process.cwd() });
  child.on("exit", async (code, signal) => {
    const result = { code: code ?? null, signal: signal ?? null };
    try {
      await requestJson("/v1/finalize", { sessionId, runId: pre.runId, result });
    } catch (e) {
      console.error(`WARN: finalize failed: ${e?.message || e}`);
    }
    process.exit(code ?? 1);
  });
  // keep process alive until child exits
  process.stdin.resume();
} else if (command === "finalize") {
  const runId = flags.run_id || flags.runId;
  if (!runId) die("Missing --run_id");
  const result = parseJsonFlag("result", flags.result);

  const resp = await requestJson("/v1/finalize", { sessionId, runId, result });
  if (!resp?.ok) die(`finalize failed: ${resp?.error || "unknown"}`, 10);

  process.stdout.write(JSON.stringify(resp, null, 2) + "\n");
  process.exit(0);
} else if (command === "flush") {
  const sid = flags.session_id || flags.sessionId || sessionId;
  const resp = await requestJson("/v1/flush", { sessionId: sid });
  if (!resp?.ok) die(`flush failed: ${resp?.error || "unknown"}`, 10);
  console.error(`flushed: ${sid} anchored=${resp.lastAnchoredSeq} checkpoints=${resp.lastCheckpointSeq}`);
  process.stdout.write(JSON.stringify(resp, null, 2) + "\n");
  process.exit(0);
} else if (command === "proof") {
  const sid = flags.session_id || flags.sessionId || sessionId;
  const index = Number(flags.index);
  const checkpointSeq = Number(flags.checkpoint_seq || flags.checkpointSeq);
  if (!Number.isFinite(index) || index < 0) die("Missing/invalid --index");
  if (!Number.isFinite(checkpointSeq) || checkpointSeq < 1) die("Missing/invalid --checkpoint_seq");

  const resp = await requestJson("/api/proof", { sessionId: sid, index, checkpointSeq });
  if (!resp?.ok) die(`proof failed: ${resp?.error || "unknown"}`, 10);

  console.error(`proof: session=${sid} index=${index} checkpointSeq=${checkpointSeq} rootMatches=${resp.rootMatches}`);
  process.stdout.write(JSON.stringify(resp, null, 2) + "\n");
  process.exit(0);
} else {
  die(`Unknown command: ${command}`);
}
