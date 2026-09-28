// @vaibot/shared — service-unit templates for the guard's service tier.
//
// Pure string builders, no side effects: the CLI installer writes these to disk and
// the platform supervisor loads them. systemd (Linux, user + system scope) and
// launchd (macOS, LaunchAgent + LaunchDaemon). The daemon's port/token/creds come
// from the referenced env file, so a resolved (non-default) port flows through
// without the unit hardcoding one.

// systemd unit text.
//   scope 'user'   → installed under ~/.config/systemd/user, WantedBy=default.target
//   scope 'system' → /etc/systemd/system, WantedBy=multi-user.target, runs as `user`
//                    (root-owned unit = the tamper boundary a same-user agent can't stop)
export function systemdUnit({ execStart, envFile, scope = 'user', user } = {}) {
  if (!execStart) throw new Error('systemdUnit: execStart is required')
  const wantedBy = scope === 'system' ? 'multi-user.target' : 'default.target'
  const userLine = scope === 'system' && user ? `User=${user}\n` : ''
  const envLine = envFile ? `EnvironmentFile=${envFile}\n` : ''
  return `[Unit]
Description=VAIBot Guard policy daemon (${scope})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${envLine}${userLine}ExecStart=${execStart}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=${wantedBy}
`
}

// launchd plist text (macOS).
//   scope 'user'   → LaunchAgent (~/Library/LaunchAgents), runs in the user session
//   scope 'system' → LaunchDaemon (/Library/LaunchDaemons), root-owned = tamper boundary
// RunAtLoad + KeepAlive give the same single-instance + auto-restart as systemd.
export function launchdPlist({ label, programArgs, envVars = {}, workingDir, stdout, stderr } = {}) {
  if (!label || !Array.isArray(programArgs) || programArgs.length === 0) {
    throw new Error('launchdPlist: label + non-empty programArgs[] are required')
  }
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const args = programArgs.map((a) => `    <string>${esc(a)}</string>`).join('\n')
  const envEntries = Object.entries(envVars)
  const envBlock = envEntries.length
    ? `  <key>EnvironmentVariables</key>\n  <dict>\n${envEntries
        .map(([k, v]) => `    <key>${esc(k)}</key>\n    <string>${esc(v)}</string>`)
        .join('\n')}\n  </dict>\n`
    : ''
  const wd = workingDir ? `  <key>WorkingDirectory</key>\n  <string>${esc(workingDir)}</string>\n` : ''
  // StandardOut/ErrorPath make a crash-looping job diagnosable — without them a launchd
  // service that exits on startup is completely silent (no way to see why it failed).
  const out = stdout ? `  <key>StandardOutPath</key>\n  <string>${esc(stdout)}</string>\n` : ''
  const err = stderr ? `  <key>StandardErrorPath</key>\n  <string>${esc(stderr)}</string>\n` : ''
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${esc(label)}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>
${envBlock}${wd}${out}${err}  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`
}
