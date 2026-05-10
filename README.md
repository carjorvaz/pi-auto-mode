# pi-auto-mode

An auto mode extension for [Pi](https://github.com/earendil-works/pi/tree/main/packages/coding-agent), inspired by [Claude Code](https://docs.anthropic.com/en/docs/claude-code/auto-mode) and [Codex](https://github.com/openai/codex) approval policies.

When enabled, safe tool calls are approved automatically. Destructive or ambiguous calls are classified by a secondary LLM (the session model by default) or confirmed with the user.

## Features

- **Layered pipeline** (fastest first):
  - **L0** — Tool allowlist: read-only tools pass instantly
  - **L1** — Heuristics: conservative safe/dangerous bash patterns
  - **L2** — Two-stage LLM classifier: fast conservative gate + careful review
  - **L3** — User confirmation: fallback when classifier unavailable
- **Session model as default classifier** — no extra API keys needed
- **Hardcoded safety floor** — `bash`, `write`, and `edit` can never be allowlisted
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

### Manual

Copy `auto-mode.ts` to your pi extensions directory:

```bash
mkdir -p ~/.pi/agent/extensions
cp auto-mode.ts ~/.pi/agent/extensions/
```

Then run `/reload` in pi.

## Usage

```bash
/auto         # toggle auto mode on/off
/auto-status  # show active classifier and config
```

When active, `▶▶ auto` appears in the TUI footer.

## Config

Create `~/.pi/agent/auto-mode.json` to customize. See `auto-mode.json.example` for the default configuration.

### Fallback classifier model

By default the extension uses the active session model for classification. If you want to use a different (usually cheaper/faster) model, add `provider` and `model` to the `classifier` object:

```json
{
  "classifier": {
    "provider": "anthropic",
    "model": "claude-sonnet-4-20250514",
    "temperature": 0,
    "maxTokens": 256,
    "timeout": 10,
    "twoStage": true
  }
}
```

## Disclaimer

This extension was developed with assistance from [Kimi Code](https://www.kimi.com/code).

## License

[AGPL-3.0](LICENSE)
