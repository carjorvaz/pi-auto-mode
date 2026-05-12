/** Tools that can never be auto-approved via allowlist, regardless of config.
 *  These always run through policy. */
export const NEVER_AUTO_APPROVE = new Set(["bash", "write", "edit"]);
export const DEFAULT_ALLOW_TOOLS = ["read", "grep", "find", "ls", "questionnaire"] as const;

export type PolicyDecision = "allow" | "prompt";
export type PolicyLayer = "allowlist" | "heuristic" | "verification" | "safety" | "fallback";

export interface PolicySessionGrant {
	key: string;
	label: string;
}

export interface PolicyVerdict {
	decision: PolicyDecision;
	reason: string;
	layer: PolicyLayer;
	sessionGrant?: PolicySessionGrant;
	invalidatesSessionGrants?: boolean;
}

export interface PolicyContext {
	cwd: string;
	home: string;
	allowTools?: readonly string[];
	sessionGrants?: ReadonlySet<string>;
}

const SAFE_COMMANDS = new Set([
	"cat", "cd", "cut", "echo", "expr", "false", "grep", "head", "id", "ls",
	"nl", "paste", "pwd", "rev", "seq", "stat", "tail", "tr", "true", "uname",
	"uniq", "wc", "which", "whoami", "find", "rg", "base64", "sed", "git", "nix",
	"dirname", "basename", "readlink", "realpath", "file", "strings", "hexdump",
	"xxd", "date", "cal", "clear", "tput", "sort", "command", "node", "npm",
	"numfmt", "tac",
]);

export const DANGEROUS_PATTERNS = [
	/\brm\b/i,
	/\brmdir\b/i,
	/\bunlink\b/i,
	/\bsudo\b/i,
	/\b(chmod|chown|chgrp)\b.*777/i,
	/\bmkfs\b/i,
	/\bdd\b/i,
	/\bshred\b/i,
	/\bcurl\s+.*\|\s*(sh|bash|zsh)/i,
	/\bwget\s+.*\|\s*(sh|bash|zsh)/i,
	/:\s*\(\s*\)\s*\{\s*:\s*\|:\s*&\s*\}\s*;\s*:/,
	/\bnixos-rebuild\s+switch\b/i,
	/\bdarwin-rebuild\s+switch\b/i,
	/\bgit\s+(commit|push)\b/i,
	/\bgit\s+(reset\s+--hard|checkout\s+-f)\b/i,
	/\bgit\s+clean(?:\s+--?(?:force|[a-z]*[fd][a-z]*))+\b/i,
	/\b(useradd|userdel|usermod|groupadd|groupdel|groupmod)\b/i,
	/\bpasswd\b/i,
	/\bvisudo\b/i,
	/\bsu\s+/i,
	/\bsg\s+/i,
	/\bnewgrp\b/i,
	/\bdoas\b/i,
	/\bpkexec\b/i,
	/\brun0\b/i,
	/\bsudoedit\b/i,
];

export const PROTECTED_PATH_PATTERNS = [
	/(^|\/)\.env[^/]*(\/|$)/i,
	/(^|\/)\.envrc$/i,
	/(^|\/)\.docker\/config\.json$/i,
	/(^|\/)\.git-credentials$/i,
	/(^|\/)\.git\/config$/i,
	/(^|\/)\.ssh(\/|$)/i,
	/(^|\/)\.gnupg(\/|$)/i,
	/(^|\/)\.netrc$/i,
	/(^|\/)\.(npmrc|pypirc)$/i,
	/(^|\/)\.aws\/credentials$/i,
	/(^|\/)\.config\/gh\/hosts\.yml$/i,
	/(^|\/)\.kube\/config$/i,
	/(^|\/)\.pi\/agent\/auth\.json$/i,
	/(^|\/)auth\.json$/i,
	/(^|\/)(credentials|credential-store)(\.[^/]*)?$/i,
	/(^|\/)dev\/(mem|kmem|port|zero|random|urandom)$/i,
	/(^|\/)etc\/(shadow|sudoers)$/i,
	/(^|\/)proc\/(self|\d+)\/(cmdline|environ|mem)$/i,
	/(^|\/)proc\/(self|\d+)\/fd(\/|$)/i,
	/(^|\/)secrets?(\/|$)/i,
	/(^|\/)[^/]*secret[^/]*(\/|$)/i,
	/(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
	/\.(pem|key|p12|pfx)$/i,
];

/** Reject any command containing shell metacharacters, quotes, backticks,
 *  variable/command substitution, or brace expansion before word-splitting.
 *  This is intentionally conservative: anything complex asks the user. */
export function isStructurallySimple(command: string): boolean {
	if (/[\r\n]/.test(command)) return false;
	if (/[;|&<>()`${}]/.test(command)) return false;
	if (/[*?[\]]/.test(command)) return false;
	if (/["'`]/.test(command)) return false;
	if (/\$\{|\$\(/.test(command)) return false;
	return true;
}

export function splitSimpleCommand(command: string): string[] | null {
	if (!isStructurallySimple(command)) return null;
	const trimmed = command.trim();
	if (!trimmed) return null;
	return trimmed.split(/\s+/);
}

function stripAllowedStderrNullRedirections(command: string): string | undefined {
	let stripped = "";
	let quote: "'" | "\"" | undefined;

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		if (quote) {
			stripped += char;
			if (char === quote) {
				quote = undefined;
				continue;
			}
			const consumed = safeQuotedCharLength(command, i, quote);
			if (consumed === 0) return undefined;
			if (consumed > 1) {
				stripped += command.slice(i + 1, i + consumed);
				i += consumed - 1;
			}
			continue;
		}

		if (char === "'" || char === "\"") {
			quote = char;
			stripped += char;
			continue;
		}

		if (char === "2" && command[i + 1] === ">" && (i === 0 || /\s/.test(command[i - 1]))) {
			let j = i + 2;
			while (/\s/.test(command[j] ?? "")) j++;
			if (!command.startsWith("/dev/null", j)) return undefined;
			j += "/dev/null".length;
			const next = command[j];
			if (next && !/\s/.test(next) && next !== "|") return undefined;
			i = j - 1;
			continue;
		}

		if (char === "<" || char === ">") return undefined;
		stripped += char;
	}

	if (quote) return undefined;
	return stripped;
}

function safeQuotedCharLength(command: string, index: number, quote: "'" | "\""): number {
	const char = command[index];
	if (/[\r\n`]/.test(char)) return 0;
	if (quote === "'") return 1;

	if (char === "\\") {
		const next = command[index + 1];
		return next && !/[\r\n$`"\\]/.test(next) ? 1 : 0;
	}
	if (char === "$") {
		const next = command[index + 1];
		if (next === "(" || next === "{") return 0;
		if (next && /[A-Za-z_]/.test(next)) {
			const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(command.slice(index + 1))?.[0] ?? "";
			return name === "HOME" ? name.length + 1 : 0;
		}
		if (next && /[0-9*@#?$!-]/.test(next)) return 0;
	}
	return 1;
}

function safeUnquotedEscapeLength(command: string, index: number): number {
	if (command[index] !== "\\") return 0;
	const next = command[index + 1];
	return next === "(" || next === ")" ? 2 : 0;
}

// Not a shell parser. This accepts only plain words plus inert quoted text,
// and rejects expansion/metacharacter behavior that should stay user-confirmed.
function splitShellWordsConservatively(command: string): string[] | null {
	const words: string[] = [];
	let current = "";
	let quote: "'" | "\"" | undefined;
	let sawToken = false;

	const pushToken = () => {
		if (!sawToken) return;
		words.push(current);
		current = "";
		sawToken = false;
	};

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		if (quote) {
			if (char === quote) {
				quote = undefined;
				continue;
			}
			const consumed = safeQuotedCharLength(command, i, quote);
			if (consumed === 0) return null;
			current += command.slice(i, i + consumed);
			i += consumed - 1;
			sawToken = true;
			continue;
		}

		if (char === "'" || char === "\"") {
			quote = char;
			sawToken = true;
			continue;
		}
		if (/\s/.test(char)) {
			pushToken();
			continue;
		}
		const escaped = safeUnquotedEscapeLength(command, i);
		if (escaped > 0) {
			current += command.slice(i, i + escaped);
			i += escaped - 1;
			sawToken = true;
			continue;
		}
		if (/[;|&<>()`${}\\*?[\]]/.test(char)) return null;
		current += char;
		sawToken = true;
	}

	if (quote) return null;
	pushToken();
	return words.length > 0 ? words : null;
}

function splitSimplePipeline(command: string): string[] | null {
	const parts: string[] = [];
	let current = "";
	let quote: "'" | "\"" | undefined;
	let sawPipe = false;

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		if (quote) {
			if (char === quote) {
				current += char;
				quote = undefined;
				continue;
			}
			const consumed = safeQuotedCharLength(command, i, quote);
			if (consumed === 0) return null;
			current += command.slice(i, i + consumed);
			i += consumed - 1;
			continue;
		}

		if (char === "'" || char === "\"") {
			quote = char;
			current += char;
			continue;
		}
		const escaped = safeUnquotedEscapeLength(command, i);
		if (escaped > 0) {
			current += command.slice(i, i + escaped);
			i += escaped - 1;
			continue;
		}
		if (char === "|") {
			if (command[i + 1] === "|") return null;
			const part = current.trim();
			if (!part) return null;
			parts.push(part);
			current = "";
			sawPipe = true;
			continue;
		}
		if (/[\r\n;&<>()`${}\\*?[\]]/.test(char)) return null;
		current += char;
	}

	if (quote) return null;
	const finalPart = current.trim();
	if (!finalPart) return null;
	parts.push(finalPart);
	return sawPipe ? parts : null;
}

function expandHome(value: string, home: string): string {
	if (value === "~") return home;
	if (value.startsWith("~/")) return `${home}/${value.slice(2)}`;
	return value;
}

function normalizePathLikeToken(token: string, cwd: string, home: string): string {
	const expanded = expandHome(token, home);
	if (expanded.startsWith("/")) return expanded.replace(/\/+/g, "/");
	if (expanded.startsWith("./") || expanded.startsWith("../") || expanded === "." || expanded === "..") {
		return `${cwd}/${expanded}`.replace(/\/+/g, "/");
	}
	return expanded.replace(/\/+/g, "/");
}

function resolveCdTarget(token: string, cwd: string, home: string): string | undefined {
	if (token.startsWith("~") && token !== "~" && !token.startsWith("~/")) return undefined;
	const expanded = expandHome(token, home);
	if (expanded.startsWith("/")) return expanded.replace(/\/+/g, "/");
	return `${cwd}/${expanded}`.replace(/\/+/g, "/");
}

export function isProtectedPath(value: string, cwd: string, home: string): boolean {
	const normalized = normalizePathLikeToken(value, cwd, home);
	if (PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(normalized))) {
		return true;
	}

	const colonIndex = value.lastIndexOf(":");
	if (colonIndex > 0 && colonIndex < value.length - 1) {
		return isProtectedPath(value.slice(colonIndex + 1), cwd, home);
	}
	return false;
}

export interface ShellCommandForPolicy {
	command: string;
	cwd: string;
	cdTarget?: string;
}

function normalizeShellCommand(command: string): string {
	return command.trim().replace(/\s+/g, " ");
}

function splitAndChain(command: string): string[] | undefined {
	if (!command.includes("&&")) return undefined;
	const parts: string[] = [];
	let current = "";
	let quote: "'" | "\"" | undefined;

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		if (quote) {
			if (char === quote) {
				current += char;
				quote = undefined;
				continue;
			}
			const consumed = safeQuotedCharLength(command, i, quote);
			if (consumed === 0) return undefined;
			current += command.slice(i, i + consumed);
			i += consumed - 1;
			continue;
		}

		if (char === "'" || char === "\"") {
			quote = char;
			current += char;
			continue;
		}
		const escaped = safeUnquotedEscapeLength(command, i);
		if (escaped > 0) {
			current += command.slice(i, i + escaped);
			i += escaped - 1;
			continue;
		}
		if (char === "&") {
			if (command[i + 1] !== "&") return undefined;
			const part = normalizeShellCommand(current);
			if (!part) return undefined;
			parts.push(part);
			current = "";
			i++;
			continue;
		}
		if (char === "|" && command[i + 1] === "|") return undefined;
		if (/[\r\n;<>()[\]`${}\\*?]/.test(char)) return undefined;
		current += char;
	}

	if (quote) return undefined;
	const finalPart = normalizeShellCommand(current);
	if (!finalPart) return undefined;
	parts.push(finalPart);
	if (parts.length < 2) return undefined;
	return parts;
}

function consumeTrueFallback(command: string, index: number): number | undefined {
	let start = index;
	while (/\s/.test(command[start] ?? "")) start++;
	if (!command.startsWith("true", start)) return undefined;

	const end = start + "true".length;
	const immediateNext = command[end];
	if (immediateNext && !/\s/.test(immediateNext) && immediateNext !== ";" && immediateNext !== "&") return undefined;

	let nextIndex = end;
	while (/\s/.test(command[nextIndex] ?? "")) nextIndex++;
	const next = command[nextIndex];
	if (!next || next === ";" || (next === "&" && command[nextIndex + 1] === "&")) return end;
	return undefined;
}

function splitCommandSequence(command: string): string[] | undefined {
	const parts: string[] = [];
	let current = "";
	let quote: "'" | "\"" | undefined;
	let sawSeparator = false;

	const pushPart = (): boolean => {
		const part = normalizeShellCommand(current);
		if (!part) return false;
		parts.push(part);
		current = "";
		return true;
	};

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		if (quote) {
			if (char === quote) {
				current += char;
				quote = undefined;
				continue;
			}
			const consumed = safeQuotedCharLength(command, i, quote);
			if (consumed === 0) return undefined;
			current += command.slice(i, i + consumed);
			i += consumed - 1;
			continue;
		}

		if (char === "'" || char === "\"") {
			quote = char;
			current += char;
			continue;
		}

		const escaped = safeUnquotedEscapeLength(command, i);
		if (escaped > 0) {
			current += command.slice(i, i + escaped);
			i += escaped - 1;
			continue;
		}

		if (char === ";") {
			if (!pushPart()) return undefined;
			sawSeparator = true;
			continue;
		}

		if (char === "&") {
			if (command[i + 1] !== "&") return undefined;
			if (!pushPart()) return undefined;
			sawSeparator = true;
			i++;
			continue;
		}

		if (char === "|") {
			if (command[i + 1] === "|") {
				const lhs = normalizeShellCommand(current);
				if (!lhs) return undefined;
				const trueEnd = consumeTrueFallback(command, i + 2);
				if (trueEnd === undefined) return undefined;
				current = lhs;
				sawSeparator = true;
				i = trueEnd - 1;
				continue;
			}
			current += char;
			continue;
		}

		if (/[\r\n()[\]`${}\\*?]/.test(char)) return undefined;
		current += char;
	}

	if (quote) return undefined;
	if (!pushPart()) return undefined;
	return sawSeparator ? parts : undefined;
}

function cdTargetFromWords(words: readonly string[]): string | undefined {
	if (words[0] !== "cd") return undefined;
	const target = words.length === 2
		? words[1]
		: words.length === 3 && words[1] === "--"
			? words[2]
			: undefined;
	if (!target || target.startsWith("-")) return undefined;
	return target;
}

function parseCdAndCommand(command: string, cwd: string, home: string): ShellCommandForPolicy | undefined {
	const parts = splitAndChain(command);
	if (!parts || parts.length !== 2) return undefined;

	const cdWords = splitSimpleCommand(parts[0]);
	const nextCommand = normalizeShellCommand(parts[1] ?? "");
	const nextWords = splitSimpleCommand(nextCommand) ?? splitSimplePipeline(nextCommand);
	if (!cdWords || !nextWords) return undefined;
	if (cdWords[0] !== "cd") return undefined;

	const cdTarget = cdTargetFromWords(cdWords);
	if (!cdTarget) return undefined;

	const nextCwd = resolveCdTarget(cdTarget, cwd, home);
	if (!nextCwd) return undefined;
	return { command: nextCommand, cwd: nextCwd, cdTarget };
}

export function shellCommandForPolicy(command: string, cwd: string, home: string): ShellCommandForPolicy {
	return parseCdAndCommand(command, cwd, home) ?? {
		command: normalizeShellCommand(command),
		cwd,
	};
}

export function shellCommandsForPolicy(command: string, cwd: string, home: string): ShellCommandForPolicy[] {
	const parts = splitCommandSequence(command);
	if (!parts) return [shellCommandForPolicy(command, cwd, home)];

	let currentCwd = cwd;
	const commands: ShellCommandForPolicy[] = [];
	for (const part of parts) {
		const words = splitShellWordsConservatively(part) ?? splitSimpleCommand(part);
		const pipeline = splitSimplePipeline(part);
		if (!words && !pipeline) return [shellCommandForPolicy(command, cwd, home)];

		const cdTarget = words ? cdTargetFromWords(words) : undefined;
		if (cdTarget) {
			const nextCwd = resolveCdTarget(cdTarget, currentCwd, home);
			if (!nextCwd) return [shellCommandForPolicy(command, cwd, home)];
			currentCwd = nextCwd;
			continue;
		}

		commands.push({ command: part, cwd: currentCwd });
	}

	return commands.length > 0 ? commands : [shellCommandForPolicy(command, cwd, home)];
}

export function commandMentionsProtectedPath(command: string, cwd: string, home: string): boolean {
	command = stripAllowedStderrNullRedirections(command) ?? command;
	const pipeline = splitSimplePipeline(command);
	if (pipeline) {
		return pipeline.some((part) => commandMentionsProtectedPath(part, cwd, home));
	}

	const words = splitShellWordsConservatively(command) ?? splitSimpleCommand(command);
	if (words) return words.some((word) => isProtectedPath(word, cwd, home));

	const parts = splitCommandSequence(command);
	if (!parts) return false;

	let currentCwd = cwd;
	for (const part of parts) {
		const partWords = splitShellWordsConservatively(part) ?? splitSimpleCommand(part);

		const cdTarget = partWords ? cdTargetFromWords(partWords) : undefined;
		if (cdTarget) {
			if (isProtectedPath(cdTarget, currentCwd, home)) return true;
			const nextCwd = resolveCdTarget(cdTarget, currentCwd, home);
			if (!nextCwd) return false;
			currentCwd = nextCwd;
			continue;
		}

		if (commandMentionsProtectedPath(part, currentCwd, home)) return true;
	}

	return false;
}

const commandName = (word: string | undefined): string => (word ?? "").replace(/^.*\//, "");

const firstNonOption = (words: readonly string[]): string => words.find((word) => !word.startsWith("-")) ?? "";

const PACKAGE_SCRIPT_NAMES = new Set([
	"build",
	"check",
	"ci",
	"clippy",
	"fmt",
	"format",
	"lint",
	"test",
	"typecheck",
	"verify",
]);

function hasFlag(words: readonly string[], flag: string): boolean {
	return words.some((word) => word === flag || word.startsWith(`${flag}=`));
}

function hasShortFlag(word: string, flags: string): boolean {
	const escapedFlags = flags.replace(/[\\\]\^-]/g, "\\$&");
	return new RegExp(`^-[A-Za-z]*[${escapedFlags}][A-Za-z]*$`).test(word);
}

function isEscaped(value: string, index: number): boolean {
	let backslashes = 0;
	for (let i = index - 1; i >= 0 && value[i] === "\\"; i--) {
		backslashes++;
	}
	return backslashes % 2 === 1;
}

function isSafeSedSubstitution(script: string): boolean {
	if (!script.startsWith("s") || script.length < 4) return false;
	const delimiter = script[1];
	if (!delimiter || /[\sA-Za-z0-9\\'"`$]/.test(delimiter)) return false;

	const delimiters: number[] = [];
	for (let i = 2; i < script.length; i++) {
		if (script[i] === delimiter && !isEscaped(script, i)) {
			delimiters.push(i);
		}
	}
	if (delimiters.length < 2) return false;

	const flags = script.slice(delimiters[1] + 1);
	return /^[gIpM0-9]*$/.test(flags);
}

export function isKnownVerificationCommand(command: string): boolean {
	const words = splitSimpleCommand(command);
	if (!words || isDangerousCommand(command)) return false;

	const first = commandName(words[0]);
	const args = words.slice(1);
	const sub = firstNonOption(args);

	switch (first) {
		case "cargo":
			return ["build", "check", "clippy", "doc", "test"].includes(sub)
				|| (sub === "fmt" && hasFlag(args, "--check"));
		case "npm":
			return sub === "test" || (sub === "run" && PACKAGE_SCRIPT_NAMES.has(firstNonOption(args.slice(args.indexOf("run") + 1))));
		case "pnpm":
		case "yarn":
			return sub === "test" || (sub === "run" && PACKAGE_SCRIPT_NAMES.has(firstNonOption(args.slice(args.indexOf("run") + 1))));
		case "bun":
			return sub === "test" || (sub === "run" && PACKAGE_SCRIPT_NAMES.has(firstNonOption(args.slice(args.indexOf("run") + 1))));
		case "go":
			return ["build", "test", "vet"].includes(sub);
		case "nix":
			if (sub === "flake") {
				return firstNonOption(args.slice(args.indexOf("flake") + 1)) === "check";
			}
			return sub === "build";
		case "make":
		case "just":
			return PACKAGE_SCRIPT_NAMES.has(sub);
		case "python":
		case "python3":
			return args[0] === "-m" && ["pytest", "unittest", "mypy"].includes(args[1] ?? "");
		case "pytest":
		case "tox":
		case "mypy":
		case "tsc":
		case "vitest":
		case "jest":
		case "mocha":
		case "ava":
			return true;
		case "ruff":
		case "eslint":
			return !hasFlag(args, "--fix");
		case "prettier":
			return hasFlag(args, "--check");
		case "dotnet":
			return ["build", "test"].includes(sub);
		case "mvn":
		case "gradle":
		case "gradlew":
			return ["build", "check", "test", "verify"].includes(sub);
		case "zig":
			return sub === "test" || (sub === "build" && args.includes("test"));
		case "swift":
		case "mix":
		case "stack":
		case "cabal":
		case "lein":
			return sub === "test";
		default:
			return false;
	}
}

export function sessionGrantKeyForToolCall(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
	home: string,
): string | undefined {
	if (toolName !== "bash") return undefined;
	const rawCommand = String(input.command ?? "");
	const effectiveCommand = shellCommandForPolicy(rawCommand, cwd, home);
	if (!effectiveCommand.command) return undefined;
	return `bash:${effectiveCommand.cwd}:${effectiveCommand.command}`;
}

function sessionGrantForToolCall(
	toolName: string,
	input: Record<string, unknown>,
	context: PolicyContext,
): PolicySessionGrant | undefined {
	const key = sessionGrantKeyForToolCall(toolName, input, context.cwd, context.home);
	if (!key) return undefined;
	const effectiveCommand = shellCommandForPolicy(String(input.command ?? ""), context.cwd, context.home);
	return { key, label: `exact command in ${effectiveCommand.cwd}: ${effectiveCommand.command}` };
}

function isSafeSshOption(value: string | undefined): boolean {
	if (!value) return false;
	const name = value.split("=")[0].toLowerCase();
	return new Set([
		"batchmode",
		"checkhostip",
		"compression",
		"connectionattempts",
		"connecttimeout",
		"globalknownhostsfile",
		"identitiesonly",
		"loglevel",
		"numberofpasswordprompts",
		"passwordauthentication",
		"preferredauthentications",
		"pubkeyauthentication",
		"serveralivecountmax",
		"serveraliveinterval",
		"stricthostkeychecking",
		"userknownhostsfile",
	]).has(name);
}

const inputPath = (input: Record<string, unknown>): string | undefined => {
	const value = input.path ?? input.file_path;
	return typeof value === "string" && value.length > 0 ? value : undefined;
};

const readLikePath = (toolName: string, input: Record<string, unknown>): string | undefined => {
	if (toolName === "read") return inputPath(input);
	if (toolName === "grep" || toolName === "find" || toolName === "ls") {
		return inputPath(input) ?? ".";
	}
	return undefined;
};

const readLikeGlob = (toolName: string, input: Record<string, unknown>): string | undefined => {
	if (toolName !== "grep" && toolName !== "find") return undefined;
	const value = input.glob;
	return typeof value === "string" && value.length > 0 ? value : undefined;
};

export function classifyToolCall(
	toolName: string,
	input: Record<string, unknown>,
	context: PolicyContext,
): PolicyVerdict {
	if (!NEVER_AUTO_APPROVE.has(toolName)) {
		const allowed = new Set(context.allowTools ?? DEFAULT_ALLOW_TOOLS);
		if (allowed.has(toolName)) {
			const targetPath = readLikePath(toolName, input);
			if (targetPath && isProtectedPath(targetPath, context.cwd, context.home)) {
				return { decision: "prompt", reason: `protected read target: ${targetPath}`, layer: "safety" };
			}

			const targetGlob = readLikeGlob(toolName, input);
			if (targetGlob && isProtectedPath(targetGlob, context.cwd, context.home)) {
				return { decision: "prompt", reason: `protected read pattern: ${targetGlob}`, layer: "safety" };
			}

			return { decision: "allow", reason: "allowlisted read-only tool", layer: "allowlist" };
		}
	}

	if (toolName === "bash") {
		const command = String(input.command ?? "");
		if (commandMentionsProtectedPath(command, context.cwd, context.home)) {
			return { decision: "prompt", reason: "command mentions a protected path", layer: "safety" };
		}
		const effectiveCommands = shellCommandsForPolicy(command, context.cwd, context.home);
		const singleEffectiveCommand = effectiveCommands.length === 1 ? effectiveCommands[0] : undefined;
		const sessionGrant = singleEffectiveCommand && isKnownVerificationCommand(singleEffectiveCommand.command)
			? sessionGrantForToolCall(toolName, input, context)
			: undefined;
		if (sessionGrant && context.sessionGrants?.has(sessionGrant.key)) {
			return { decision: "allow", reason: "verification command approved for this session", layer: "verification" };
		}
		if (effectiveCommands.every((effectiveCommand) => isKnownSafeCommand(effectiveCommand.command))) {
			return { decision: "allow", reason: "known-safe read-only command", layer: "heuristic" };
		}
		if (isDangerousCommand(command) || effectiveCommands.some((effectiveCommand) => isDangerousCommand(effectiveCommand.command))) {
			return {
				decision: "prompt",
				reason: `dangerous or mutating command: ${truncate(command, 80)}`,
				layer: "heuristic",
				invalidatesSessionGrants: true,
			};
		}
		if (sessionGrant) {
			return {
				decision: "prompt",
				reason: "verification command requires first confirmation",
				layer: "verification",
				sessionGrant,
			};
		}
		return {
			decision: "prompt",
			reason: "unknown shell command requires confirmation",
			layer: "fallback",
			invalidatesSessionGrants: true,
		};
	}

	if (toolName === "write" || toolName === "edit") {
		const targetPath = inputPath(input);
		if (targetPath && isProtectedPath(targetPath, context.cwd, context.home)) {
			return {
				decision: "prompt",
				reason: `protected write target: ${targetPath}`,
				layer: "safety",
				invalidatesSessionGrants: true,
			};
		}
		return {
			decision: "prompt",
			reason: "file mutation requires confirmation",
			layer: "fallback",
			invalidatesSessionGrants: true,
		};
	}

	return {
		decision: "prompt",
		reason: "mutating or ambiguous operation requires confirmation",
		layer: "fallback",
		invalidatesSessionGrants: true,
	};
}

/** True only for commands that are obviously simple and safe.
 *  Anything structurally complex is rejected. */
export function isKnownSafeCommand(command: string): boolean {
	const commandWithoutAllowedRedirections = stripAllowedStderrNullRedirections(command);
	if (commandWithoutAllowedRedirections === undefined) return false;
	command = commandWithoutAllowedRedirections;

	const pipeline = splitSimplePipeline(command);
	if (pipeline) {
		return pipeline.every((part) => isKnownSafeCommand(part));
	}

	const words = splitShellWordsConservatively(command) ?? splitSimpleCommand(command);
	if (!words) return false;

	const first = words[0].replace(/^.*\//, "");

	// Wrapper: bash -lc <simple-cmd>
	// Keep quoted shell strings behind confirmation even though inert quotes are
	// accepted for normal read-only command arguments.
	if (first === "bash" || first === "zsh") {
		if (/["']/.test(command)) return false;
		return words.length >= 3 && words[1] === "-lc" && isKnownSafeCommand(words.slice(2).join(" "));
	}

	// Wrapper: ssh [options] host <simple-cmd>
	// Rejects port-forwarding / backgrounding flags and interactive shells.
	if (first === "ssh") {
		const sshArgOptions = new Set(["l", "p", "i", "B", "b", "c", "J"]);
		const sshDangerous = new Set(["A", "D", "f", "L", "M", "N", "R", "S", "t", "W", "w", "X", "Y"]);
		let i = 1;
		while (i < words.length) {
			const w = words[i];
			if (w === "--") { i++; break; }
			if (!w.startsWith("-")) break; // host
			if (w.startsWith("--")) return false; // reject long options
			if (w === "-F" || w.startsWith("-F") || w === "-E" || w.startsWith("-E") || w === "-I" || w.startsWith("-I")) {
				return false;
			}
			if (w === "-o") {
				if (!isSafeSshOption(words[i + 1])) return false;
				i += 2;
				continue;
			}
			if (w.startsWith("-o")) {
				if (!isSafeSshOption(w.slice(2))) return false;
				i++;
				continue;
			}
			const chars = w.slice(1).split("");
			let consumed = false;
			for (let j = 0; j < chars.length; j++) {
				const c = chars[j];
				if (sshDangerous.has(c)) return false;
				if (sshArgOptions.has(c)) {
					i += j === chars.length - 1 ? 2 : 1;
					consumed = true;
					break;
				}
			}
			if (consumed) continue;
			i++;
		}
		const host = words[i];
		if (!host) return false;
		const remoteCommand = words.slice(i + 1).join(" ");
		if (!remoteCommand) return false;
		return isKnownSafeCommand(remoteCommand);
	}

	if (!SAFE_COMMANDS.has(first)) return false;

	switch (first) {
		case "find":
			return !words.some((w) =>
				["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls", "-fprint", "-fprint0", "-fprintf"].includes(w),
			);
		case "grep": {
			const recursiveFlags = new Set(["-r", "-R", "--recursive", "--dereference-recursive"]);
			return !words.some((w) => recursiveFlags.has(w) || hasShortFlag(w, "rR"));
		}
		case "rg":
			return !words.some(
				(w) =>
					w === "--unrestricted"
					|| w === "--follow"
					|| w === "-L"
					|| w === "--search-zip"
					|| w === "-z"
					|| /^-u+$/.test(w)
					|| w.startsWith("--no-ignore")
					|| w.startsWith("--pre")
					|| w.startsWith("--hostname-bin"),
			);
		case "base64":
			return !words.some((w) => w === "-o" || w === "--output" || w.startsWith("--output="));
		case "command":
			return words.length === 3 && words[1] === "-v" && /^[A-Za-z0-9._+-]+$/.test(words[2]);
		case "date":
			return !words.some((w, index) =>
				index > 0 && (/^\d{6,}$/.test(w) || w === "-s" || w === "--set" || w.startsWith("--set="))
			);
		case "git": {
			const args = words.slice(1);
			if (
				args.some((w) =>
					w.startsWith("-c")
					|| w.startsWith("--config-env")
					|| w === "--exec-path"
					|| w.startsWith("--exec-path=")
					|| w === "--ext-diff",
				)
			) {
				return false;
			}
			const sub = args.find((w) => !w.startsWith("-")) ?? "";
			if (sub === "branch") {
				const mutatingFlags = new Set([
					"-d", "-D", "-m", "-M", "-c", "-C",
					"--delete", "--move", "--copy", "--set-upstream-to", "--unset-upstream",
					"--edit-description", "--track", "--no-track", "--create-reflog",
				]);
				if (args.some((w) => mutatingFlags.has(w) || w.startsWith("--set-upstream-to="))) {
					return false;
				}
				const positional = args.filter((w) => !w.startsWith("-"));
				return positional.length <= 1;
			}
			if (sub === "remote") {
				const remoteSub = args.slice(args.indexOf(sub) + 1).find((w) => !w.startsWith("-")) ?? "";
				return ["", "show", "get-url"].includes(remoteSub);
			}
			return ["status", "log", "diff", "show"].includes(sub);
		}
		case "nix": {
			const args = words.slice(1);
			const sub = args.find((w) => !w.startsWith("-")) ?? "";
			if (sub === "flake") {
				const flakeSub = args.slice(args.indexOf("flake") + 1).find((w) => !w.startsWith("-")) ?? "";
				return ["show", "metadata", "info"].includes(flakeSub);
			}
			return ["eval", "search"].includes(sub);
		}
		case "node":
		case "npm":
			return words.length === 2 && ["-v", "--version"].includes(words[1]);
		case "sed":
			return (words.length <= 4 && words[1] === "-n" && /^\d+(,\d+)?p$/.test(words[2] ?? ""))
				|| (words.length === 2 && isSafeSedSubstitution(words[1]));
		case "sort":
			return !words.some((w) =>
				w === "-o"
				|| w.startsWith("-o")
				|| w === "--output"
				|| w.startsWith("--output=")
				|| w === "--compress-program"
				|| w.startsWith("--compress-program=")
				|| w === "--files0-from"
				|| w.startsWith("--files0-from=")
				|| w === "--random-source"
				|| w.startsWith("--random-source=")
			);
		case "tail":
			return !words.some((w) =>
				w === "-f" || w === "-F" || w === "--follow" || w.startsWith("--follow=") || hasShortFlag(w, "fF")
			);
		case "xxd":
			return !words.some((w) => w === "-r" || w === "-revert" || w === "--revert" || hasShortFlag(w, "r"));
		default:
			return true;
	}
}

export function isDangerousCommand(command: string): boolean {
	// git clean with -n/--dry-run is always a dry-run regardless of other flags
	if (/\bgit\s+clean\b/.test(command) && /\s(?:-[a-z]*n\b|--dry-run\b)/.test(command)) {
		return false;
	}
	return DANGEROUS_PATTERNS.some((p) => p.test(command));
}

export function truncate(s: string, n: number): string {
	return s.length <= n ? s : s.slice(0, n) + "...";
}
