# Persistence & installation notes

Security scanners and endpoint tooling may flag VAIBot-Guard as "suspicious" if it:
- writes secret-bearing env files under `~/.config/...`
- installs/creates systemd units
- modifies host-agent wiring/config

To minimize concern:

- Prefer a **manual (foreground) run** for evaluation.
- Make persistence steps (systemd + env file creation) explicitly opt-in.
- Document credentials and side-effects prominently (`README.md`).
- Keep host plugin wiring steps in `references/` rather than the top-level quick start.
