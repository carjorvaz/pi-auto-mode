/**
 * Auto Mode Extension for Pi
 *
 * Deterministic auto-approval. No LLM gate.
 * Read-only operations pass instantly; everything mutating asks.
 *
 * Pipeline (fastest first):
 *   L0 — Tool allowlist: read-only tools pass instantly
 *   L1 — Heuristics: conservative safe/dangerous bash patterns
 *   L2 — Confirm: mutating or ambiguous operations prompt the user
 *
 * Commands:
 *   /auto         toggle auto mode
 *   /auto-status  show state
 *   /auto-clear   clear in-memory session command grants
 *
 * Config (optional overrides): ~/.pi/agent/auto-mode.json
 */

import * as fs from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import {
	DEFAULT_ALLOW_TOOLS,
	classifyToolCall,
	truncate,
} from "./heuristics.js";

/* ═══════════════════════════════════════════════════════════════════════
   Config
   ═══════════════════════════════════════════════════════════════════════ */

interface AutoModeConfig {
	enabled?: boolean;
	allowTools?: string[];
}

const CONFIG_PATH = path.join(process.env.HOME ?? "", ".pi/agent/auto-mode.json");

function defaultConfig(): AutoModeConfig {
	return {
		enabled: true,
		allowTools: [...DEFAULT_ALLOW_TOOLS],
	};
}

function normalizeConfig(value: unknown): AutoModeConfig {
	const fallback = defaultConfig();
	if (!value || typeof value !== "object") return fallback;

	const parsed = value as { enabled?: unknown; allowTools?: unknown };
	return {
		enabled: typeof parsed.enabled === "boolean" ? parsed.enabled : fallback.enabled,
		allowTools: Array.isArray(parsed.allowTools)
			? parsed.allowTools.filter((tool): tool is string => typeof tool === "string" && tool.length > 0)
			: fallback.allowTools,
	};
}

function loadConfig(): AutoModeConfig {
	try {
		const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
		return normalizeConfig(JSON.parse(raw));
	} catch {
		return defaultConfig();
	}
}

function saveConfig(config: AutoModeConfig): void {
	try {
		fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
		fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), "utf-8");
	} catch {
		/* silent */
	}
}

/* ═══════════════════════════════════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════════════════════════════════ */

function safeStringify(value: unknown, maxLength: number): string {
	let text: string;
	try {
		text = JSON.stringify(value, null, 2);
	} catch {
		text = "[unserializable input]";
	}
	return truncate(text, maxLength);
}

export default function autoModeExtension(pi: ExtensionAPI) {
	let config = loadConfig();
	let enabled = config.enabled ?? false;
	const sessionGrants = new Set<string>();

	function updateStatus(ctx: ExtensionContext) {
		if (enabled) {
			ctx.ui.setStatus("auto-mode", ctx.ui.theme.fg("warning", "auto:ro"));
		} else {
			ctx.ui.setStatus("auto-mode", undefined);
		}
	}

	function toggle(ctx: ExtensionContext) {
		enabled = !enabled;
		config.enabled = enabled;
		if (!enabled) clearSessionGrants();
		saveConfig(config);
		updateStatus(ctx);
		ctx.ui.notify(`Auto mode ${enabled ? "enabled" : "disabled"}`, enabled ? "warning" : "info");
	}

	function clearSessionGrants(): boolean {
		if (sessionGrants.size === 0) return false;
		sessionGrants.clear();
		return true;
	}

	// ── Commands ──

	pi.registerCommand("auto", {
		description: "Toggle auto mode",
		handler: async (_args, ctx) => toggle(ctx),
	});

	pi.registerCommand("auto-status", {
		description: "Show auto mode status",
		handler: async (_args, ctx) => {
			const lines = [
				`Auto mode: ${enabled ? "ON" : "OFF"}`,
				"Policy: read-only auto, mutating prompts",
				`Allow tools: ${(config.allowTools ?? []).join(", ") || "(none)"}`,
				`Session grants: ${sessionGrants.size} exact command${sessionGrants.size === 1 ? "" : "s"}`,
				"Session override: none (config is source of truth)",
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});

	pi.registerCommand("auto-clear", {
		description: "Clear auto-mode session command grants",
		handler: async (_args, ctx) => {
			const cleared = clearSessionGrants();
			ctx.ui.notify(cleared ? "Auto-mode session grants cleared" : "No auto-mode session grants to clear", "info");
		},
	});

	// ── Events ──

	pi.on("session_start", async (_event, ctx) => {
		config = loadConfig();
		enabled = config.enabled ?? false;
		clearSessionGrants();
		updateStatus(ctx);
	});

	pi.on("before_agent_start", async (event) => {
		if (!enabled) return;
		return {
			systemPrompt:
				event.systemPrompt +
				"\n\n[Auto mode is active: read-only operations may be auto-approved. Mutating operations require confirmation. Some verification commands can be approved for the current session after explicit confirmation.]",
		};
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!enabled) return undefined;
		if (ctx.signal?.aborted) {
			return { block: true, reason: "Auto-mode: aborted by user" };
		}

		const verdict = classifyToolCall(event.toolName, event.input, {
			cwd: ctx.cwd,
			home: homedir(),
			allowTools: config.allowTools,
			sessionGrants,
		});

		if (ctx.signal?.aborted) {
			return { block: true, reason: "Auto-mode: aborted by user" };
		}
		if (verdict.decision === "allow") {
			return undefined;
		}
		if (!ctx.hasUI) {
			return { block: true, reason: `${verdict.reason} (auto-mode: no UI)` };
		}

		const details =
			event.toolName === "bash"
				? String(event.input.command ?? "")
				: safeStringify(event.input, 300);
		const grantNote = verdict.sessionGrant
			? "\n\nSession grant: this option only covers the exact command in the current cwd, and in-memory grants are cleared after approved mutations or ambiguous commands."
			: "";
		const choices = verdict.sessionGrant ? ["Allow once", "Allow for session", "Block"] : ["Allow once", "Block"];

		const choice = await ctx.ui.select(
			`Auto-mode ${verdict.layer} gate\n\n${verdict.reason}${grantNote}\n\n${event.toolName}:\n${details}\n`,
			choices,
			{ signal: ctx.signal },
		);

		if (choice === "Allow for session" && verdict.sessionGrant) {
			sessionGrants.add(verdict.sessionGrant.key);
			ctx.ui.notify(`Auto-mode session grant added: ${verdict.sessionGrant.label}`, "info");
			return undefined;
		}

		if (choice !== "Allow once") {
			return { block: true, reason: `Blocked by user (${verdict.layer})` };
		}
		if (verdict.invalidatesSessionGrants && clearSessionGrants()) {
			ctx.ui.notify("Auto-mode session grants cleared after approved mutation or ambiguous action", "info");
		}
		return undefined;
	});
}
