/**
 * Auto Mode Extension for Pi
 *
 * When enabled, safe tool calls are approved automatically.
 * Destructive or ambiguous calls are classified by a secondary LLM
 * (the session model by default) or confirmed with the user.
 *
 * Pipeline (fastest first):
 *   L0 — Tool allowlist: read-only tools pass instantly
 *   L1 — Heuristics: conservative safe/dangerous bash patterns
 *   L2 — Two-stage LLM classifier:
 *        Stage 1 (fast):  conservative yes/no, instant on ALLOW
 *        Stage 2 (careful): full reasoning, can overturn Stage 1 BLOCK
 *   L3 — User confirmation: fallback when classifier unavailable
 *
 * Commands:
 *   /auto         toggle auto mode
 *   /auto-status  show state and active classifier
 *
 * Config (optional overrides): ~/.pi/agent/auto-mode.json
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentMessage } from "@mariozechner/pi-agent-core";
import { completeSimple } from "@mariozechner/pi-ai";
import type { AssistantMessage, Model, ToolCall } from "@mariozechner/pi-ai";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import {
	NEVER_AUTO_APPROVE,
	isDangerousCommand,
	isKnownSafeCommand,
	parseClassifierResponse,
	truncate,
} from "./heuristics.js";

/* ═══════════════════════════════════════════════════════════════════════
   Config
   ═══════════════════════════════════════════════════════════════════════ */

interface ClassifierConfig {
	/** Fallback model when session model is unavailable.
	 *  Omit provider+model to use only the session model. */
	provider?: string;
	model?: string;
	temperature?: number;
	maxTokens?: number;
	/** seconds */
	timeout?: number;
	/** Use two-stage classification (fast conservative stage + careful review).
	 *  Default true. */
	twoStage?: boolean;
}

interface AutoModeConfig {
	enabled?: boolean;
	classifier?: ClassifierConfig;
	allowTools?: string[];
	allow?: string[];
	deny?: string[];
	environment?: string[];
}

const CONFIG_PATH = path.join(process.env.HOME ?? "", ".pi/agent/auto-mode.json");

function defaultConfig(): AutoModeConfig {
	return {
		enabled: true,
		classifier: { temperature: 0, maxTokens: 256, timeout: 10, twoStage: true },
		allowTools: ["read", "grep", "find", "ls", "questionnaire"],
		allow: [
			"Reading any file",
			"Git status, log, diff, show, branch (read-only queries)",
			"Nix flake show / metadata / eval / search (read-only)",
		],
		deny: [
			"rm -rf, sudo, chmod 777",
			"curl | sh / wget | sh (code from external sources)",
			"Modifying .env, auth.json, secrets, or SSH keys",
			"Git reset --hard, clean -fd, checkout -f",
			"nixos-rebuild switch or darwin-rebuild switch",
		],
		environment: [],
	};
}

function loadConfig(): AutoModeConfig {
	try {
		const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
		const parsed = JSON.parse(raw) as AutoModeConfig;
		const def = defaultConfig();
		return {
			...def,
			...parsed,
			classifier: { ...def.classifier, ...parsed.classifier },
		};
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
   Heuristics — see heuristics.ts for implementations
   ═══════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════
   Transcript builder
   ═══════════════════════════════════════════════════════════════════════ */

function buildTranscript(ctx: ExtensionContext, maxLines = 10): string {
	const entries = ctx.sessionManager.getEntries();
	const lines: string[] = [];

	for (let i = entries.length - 1; i >= 0 && lines.length < maxLines; i--) {
		const entry = entries[i];
		if (entry.type !== "message") continue;
		const compact = compactMessage((entry as { message: AgentMessage }).message);
		if (compact) lines.push(compact);
	}

	return lines.reverse().join("\n");
}

function compactMessage(msg: AgentMessage): string | null {
	const role = (msg as { role?: string }).role;
	if (!role) return null;

	if (role === "user") {
		const text = extractText((msg as { content?: unknown }).content);
		if (!text) return null;
		return `User: ${truncate(text, 200)}`;
	}

	if (role === "assistant") {
		const calls = extractToolCalls(msg as AssistantMessage);
		if (calls.length === 0) return null;
		return calls.map((c) => `Tool: ${c.name} ${JSON.stringify(c.input)}`).join("\n");
	}

	return null;
}

function isTextBlock(c: unknown): c is { type: "text"; text: string } {
	return typeof c === "object" && c !== null && (c as Record<string, unknown>).type === "text";
}

function extractText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.filter(isTextBlock)
		.map((c) => c.text)
		.join(" ")
		.trim();
}

function extractToolCalls(msg: AssistantMessage): { name: string; input: unknown }[] {
	return msg.content
		.filter((c): c is ToolCall => c.type === "toolCall")
		.map((c) => ({ name: c.name, input: c.arguments }));
}

function truncate(s: string, n: number): string {
	return s.length <= n ? s : s.slice(0, n) + "…";
}

/* ═══════════════════════════════════════════════════════════════════════
   LLM Classifier
   ═══════════════════════════════════════════════════════════════════════ */

function resolveClassifierModel(
	ctx: ExtensionContext,
	config: AutoModeConfig,
): Model<any> | null {
	if (ctx.model) return ctx.model;

	const cfg = config.classifier;
	if (cfg?.provider && cfg?.model) {
		return ctx.modelRegistry.find(cfg.provider, cfg.model) ?? null;
	}

	return null;
}

interface ClassifierParams {
	temperature: number;
	maxTokens: number;
	timeoutSec: number;
}

function getClassifierParams(config: AutoModeConfig): ClassifierParams {
	return {
		temperature: config.classifier?.temperature ?? 0,
		maxTokens: Math.max(1, config.classifier?.maxTokens ?? 256),
		timeoutSec: Math.max(1, config.classifier?.timeout ?? 10),
	};
}

/* ── Two-stage classifier ── */

async function classifyWithLLM(
	ctx: ExtensionContext,
	model: Model<any>,
	config: AutoModeConfig,
	toolName: string,
	input: Record<string, unknown>,
	signal?: AbortSignal,
): Promise<{ shouldBlock: boolean; reason: string } | null> {
	const useTwoStage = config.classifier?.twoStage !== false;
	const transcript = buildTranscript(ctx);
	const system = buildSystemPrompt(config, ctx.cwd);
	const user = buildUserPrompt(toolName, input, transcript);
	const params = getClassifierParams(config);

	if (useTwoStage) {
		// Stage 1 — fast conservative gate.
		const fastSystem = `${system}\n\nIMPORTANT: Respond with ONLY the word ALLOW or the word BLOCK. No explanation, no reasoning.`;
		const fast = await llmClassify(model, { ...params, maxTokens: 10 }, fastSystem, user, signal);
		if (signal?.aborted) return null;
		if (fast && !fast.shouldBlock) {
			return { shouldBlock: false, reason: "Allowed by fast classifier" };
		}
		// Don't proceed to stage 2 if the user already aborted.
		if (signal?.aborted) return null;
	}

	// Stage 2 (or single-stage) — full reasoning
	return await llmClassify(model, params, system, user, signal);
}

async function llmClassify(
	model: Model<any>,
	params: ClassifierParams,
	system: string,
	user: string,
	signal?: AbortSignal,
): Promise<{ shouldBlock: boolean; reason: string } | null> {
	try {
		const msg = await completeSimple(
			model,
			{
				systemPrompt: system,
				messages: [{ role: "user", content: user, timestamp: Date.now() }],
			},
			{
				temperature: params.temperature,
				maxTokens: params.maxTokens,
				timeoutMs: params.timeoutSec * 1000,
				signal,
			},
		);
		const text = msg.content.map((c) => (c.type === "text" ? c.text : "")).join("");
		return parseClassifierResponse(text);
	} catch {
		return null;
	}
}

export function parseClassifierResponse(text: string): { shouldBlock: boolean; reason: string } | null {
	// Prefer structured format: DECISION: ALLOW / BLOCK
	const structured = text.match(/DECISION:\s*(ALLOW|BLOCK)/i);
	if (structured) {
		const shouldBlock = structured[1].toUpperCase() === "BLOCK";
		const reasonMatch = text.match(/REASON:\s*(.+)/i);
		const reason = reasonMatch
			? reasonMatch[1].trim()
			: shouldBlock
				? "Blocked by classifier"
				: "Allowed by classifier";
		return { shouldBlock, reason };
	}

	// Fallback: bare word at start (Stage 1 fast gate)
	const bare = text.trim().match(/^(ALLOW|BLOCK)\b/i);
	if (bare) {
		const shouldBlock = bare[1].toUpperCase() === "BLOCK";
		return { shouldBlock, reason: shouldBlock ? "Blocked by classifier" : "Allowed by classifier" };
	}

	return null;
}

function buildSystemPrompt(config: AutoModeConfig, cwd: string): string {
	const allow = (config.allow ?? []).map((r) => `- ${r}`).join("\n") || "- (none)";
	const deny = (config.deny ?? []).map((r) => `- ${r}`).join("\n") || "- (none)";
	const env = (config.environment ?? []).map((r) => `- ${r}`).join("\n") || "- (none)";

	return `You are a safety gatekeeper for an AI coding agent.
A tool execution is being proposed. Decide whether to ALLOW it automatically or BLOCK it for user review.

Respond ONLY in this exact format:
DECISION: ALLOW
REASON: <one sentence>

Or:
DECISION: BLOCK
REASON: <one sentence>

Guidelines:
- ALLOW only when the action is clearly safe, read-only, or matches the user's explicit allow rules.
- BLOCK when the action is destructive, irreversible, could leak secrets, or matches any deny rule.
- When uncertain, BLOCK. Err on the side of caution.

Available tools:
- read / grep / find / ls — read-only file operations
- bash — arbitrary shell command execution
- write — create a new file
- edit — modify an existing file

Current working directory: ${cwd}

## Allowed patterns
${allow}

## Blocked patterns
${deny}

## Environment context
${env}`;
}

function buildUserPrompt(toolName: string, input: Record<string, unknown>, transcript: string): string {
	return `Recent conversation:
${transcript || "(no prior context)"}

PROPOSED ACTION:
Tool: ${toolName}
Arguments: ${safeStringify(input, 800)}`;
}

function safeStringify(value: unknown, maxLength: number): string {
	let text: string;
	try {
		text = JSON.stringify(value, null, 2);
	} catch {
		text = "[unserializable input]";
	}
	return truncate(text, maxLength);
}

/* ═══════════════════════════════════════════════════════════════════════
   Classification pipeline
   ═══════════════════════════════════════════════════════════════════════ */

type Decision = "allow" | "block" | "confirm";

interface Verdict {
	decision: Decision;
	reason: string;
	layer: "allowlist" | "heuristic" | "llm" | "fallback";
}

async function classify(
	toolName: string,
	input: Record<string, unknown>,
	config: AutoModeConfig,
	ctx: ExtensionContext,
	signal?: AbortSignal,
): Promise<Verdict> {
	// L0 — tool allowlist (with hardcoded safety floor)
	if (!NEVER_AUTO_APPROVE.has(toolName)) {
		const allowed = new Set(config.allowTools ?? []);
		if (allowed.has(toolName)) {
			return { decision: "allow", reason: "allowlisted read-only tool", layer: "allowlist" };
		}
	}

	// L1 — heuristics
	if (toolName === "bash") {
		const command = String(input.command ?? "");
		if (isKnownSafeCommand(command)) {
			return { decision: "allow", reason: "known-safe command", layer: "heuristic" };
		}
		if (isDangerousCommand(command)) {
			return { decision: "block", reason: `dangerous pattern: ${truncate(command, 80)}`, layer: "heuristic" };
		}
	}

	if (toolName === "write" || toolName === "edit") {
		const p = String(input.path ?? "");
		if (/(^|\/)(\.env(?:\.[^\/]+)?|\.envrc|\.ssh|\.gnupg|auth\.json|secrets?)(\/|$)/i.test(p)) {
			return { decision: "block", reason: `protected path: ${p}`, layer: "heuristic" };
		}
	}

	// L2 — two-stage LLM classifier (session model preferred)
	const resolved = resolveClassifierModel(ctx, config);
	if (resolved) {
		const result = await classifyWithLLM(ctx, resolved, config, toolName, input, signal);
		if (result) {
			return {
				decision: result.shouldBlock ? "block" : "allow",
				reason: result.reason,
				layer: "llm",
			};
		}
	}

	// L3 — fallback
	return { decision: "confirm", reason: "classifier unavailable", layer: "fallback" };
}

/* ═══════════════════════════════════════════════════════════════════════
   Extension
   ═══════════════════════════════════════════════════════════════════════ */

export default function autoModeExtension(pi: ExtensionAPI) {
	let config = loadConfig();
	let enabled = config.enabled ?? false;

	function persist() {
		pi.appendEntry("auto-mode-state", { enabled });
	}

	function updateStatus(ctx: ExtensionContext) {
		if (enabled) {
			ctx.ui.setStatus("auto-mode", ctx.ui.theme.fg("warning", "▶▶ auto"));
		} else {
			ctx.ui.setStatus("auto-mode", undefined);
		}
	}

	function toggle(ctx: ExtensionContext) {
		enabled = !enabled;
		config.enabled = enabled;
		saveConfig(config);
		persist();
		updateStatus(ctx);
		ctx.ui.notify(`Auto mode ${enabled ? "enabled" : "disabled"}`, enabled ? "warning" : "info");
	}

	// ── Commands ──

	pi.registerCommand("auto", {
		description: "Toggle auto mode",
		handler: async (_args, ctx) => toggle(ctx),
	});

	pi.registerCommand("auto-status", {
		description: "Show auto mode status",
		handler: async (_args, ctx) => {
			const resolved = resolveClassifierModel(ctx, config);
			const modelName = resolved ? `${resolved.provider}/${resolved.id}` : "unavailable";
			const twoStage = config.classifier?.twoStage !== false ? "on" : "off";
			const lines = [
				`Auto mode: ${enabled ? "ON" : "OFF"}`,
				`Classifier: ${modelName}`,
				`Two-stage: ${twoStage}`,
				`Allow tools: ${(config.allowTools ?? []).join(", ") || "(none)"}`,
				`Allow rules: ${(config.allow ?? []).length}`,
				`Deny rules: ${(config.deny ?? []).length}`,
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});

	// ── Events ──

	pi.on("session_start", async (_event, ctx) => {
		config = loadConfig();
		const entries = ctx.sessionManager.getEntries();
		const state = entries
			.filter((e) => e.type === "custom" && (e as { customType?: string }).customType === "auto-mode-state")
			.pop() as { data?: { enabled?: boolean } } | undefined;
		enabled = state?.data?.enabled ?? config.enabled ?? false;
		updateStatus(ctx);
	});

	pi.on("before_agent_start", async (event) => {
		if (!enabled) return;
		return {
			systemPrompt:
				event.systemPrompt +
				"\n\n[Auto mode is active: safe operations are auto-approved.]",
		};
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!enabled) return undefined;
		if (ctx.signal?.aborted) {
			return { block: true, reason: "Auto-mode: aborted by user" };
		}

		const verdict = await classify(event.toolName, event.input, config, ctx, ctx.signal);

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

		const choice = await ctx.ui.select(
			`Auto-mode ${verdict.layer} gate\n\n${verdict.reason}\n\n${event.toolName}:\n${details}\n`,
			["Allow once", "Block"],
			{ signal: ctx.signal },
		);

		if (choice !== "Allow once") {
			return { block: true, reason: `Blocked by user (${verdict.layer})` };
		}
		return undefined;
	});
}
