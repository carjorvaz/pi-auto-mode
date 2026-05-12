# pi-auto-mode

An auto mode extension for [Pi](https://github.com/earendil-works/pi/tree/main/packages/coding-agent), inspired by [Claude Code](https://docs.anthropic.com/en/docs/claude-code/auto-mode) and [Codex](https://github.com/openai/codex) approval policies.

When enabled, deterministic read-only tool calls are approved automatically. Mutating, sensitive, or ambiguous calls are confirmed with the user. There is no secondary LLM classifier.

## Features

- **Layered pipeline** — L0 read-only tool allowlist, L1 conservative bash heuristics, L2 user confirmation for mutating, verification, or unclear operations
- **Hardcoded safety floor** — `bash`, `write`, and `edit` can never be allowlisted
- **Sensitive read guard** — reads from `.env`, SSH keys, Pi auth, and secret paths ask first
- **Session command grants** — verification commands such as `npm test`, `cargo check`, and `nix flake check` can be approved for the current session after an explicit prompt
- **Config as source of truth** — no hidden per-session auto-mode override
- **Configurable** via `~/.pi/agent/auto-mode.json`

## Install

### Via pi package manager (recommended)

```bash
pi install git:github.com/carjorvaz/pi-auto-mode
```

Or add to your `~/.pi/agent/settings.json`:

```json
{
  "packages": ["git:github.com/carjorvaz/pi-auto-mode"]
}
```

Then run `/reload` in pi.

### Local development

For local iteration, point Pi at the checkout instead of the GitHub package:

```bash
pi install /path/to/pi-auto-mode
```

Then run `/reload` in pi. Commit and push only when the local behavior is ready to share.

## Usage

```bash
/auto         # toggle auto mode on/off
/auto-status  # show active policy and config
/auto-clear   # clear in-memory session command grants
```

When active, `auto:ro` appears in the TUI footer.

Verification/build/test commands are not auto-approved by default because package scripts and test runners can execute arbitrary code. They can be granted for the current session from the confirmation prompt; grants are exact command + cwd, in-memory only, and cleared after approved mutations or ambiguous commands.

## Dogfood Loop

For quick policy checks while tuning auto-mode:

```bash
npm run smoke
npm test
npm run typecheck
```

`npm run smoke` exercises a small corpus of representative allow/prompt decisions, including read-only pipelines, verification grants, shell execution sinks, protected path reads, and risky read-like flags. When live use produces a surprising decision, add the command to `policy-smoke.ts` first, then promote stable behavior into `heuristics.test.ts`.

## Config

Create `~/.pi/agent/auto-mode.json` to customize. Unknown keys are ignored so stale classifier settings cannot silently affect behavior.

```json
{
  "enabled": true,
  "allowTools": ["read", "grep", "find", "ls", "questionnaire"]
}
```

## Disclaimer

This extension was developed with assistance from [Kimi Code](https://www.kimi.com/code).

## License

[AGPL-3.0](LICENSE)
