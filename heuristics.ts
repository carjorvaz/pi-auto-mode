/** Tools that can never be auto-approved via allowlist, regardless of config.
 *  These always run through at least heuristics + LLM. */
export const NEVER_AUTO_APPROVE = new Set(["bash", "write", "edit"]);

const SAFE_COMMANDS = new Set([
	"cat", "cd", "cut", "echo", "expr", "false", "grep", "head", "id", "ls",
	"nl", "paste", "pwd", "rev", "seq", "stat", "tail", "tr", "true", "uname",
	"uniq", "wc", "which", "whoami", "find", "rg", "base64", "sed", "git", "nix",
	"dirname", "basename", "readlink", "realpath", "file", "strings", "hexdump",
	"xxd", "date", "cal", "clear", "history", "printenv", "tput",
	"numfmt", "tac",
]);

export const DANGEROUS_PATTERNS = [
	/\brm\b/i,
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

/** Reject any command containing shell metacharacters, quotes, backticks,
 *  variable/command substitution, or brace expansion before word-splitting.
 *  This is intentionally conservative: anything complex goes to the LLM. */
export function isStructurallySimple(command: string): boolean {
	if (/[\r\n]/.test(command)) return false;
	if (/[;|&<>()`${}]/.test(command)) return false;
	if (/["'`]/.test(command)) return false;
	if (/\$\{|\$\(/.test(command)) return false;
	return true;
}

/** True only for commands that are obviously simple and safe.
 *  Anything structurally complex is rejected. */
export function isKnownSafeCommand(command: string): boolean {
	if (!isStructurallySimple(command)) return false;

	const words = command.trim().split(/\s+/);
	if (words.length === 0) return false;

	const first = words[0].replace(/^.*\//, "");

	// Wrapper: bash -lc <simple-cmd>
	// Note: quoted wrappers (bash -lc "git status") fail isStructurallySimple
	//       due to quotes and go to the LLM — this is correct and safe.
	if (first === "bash" || first === "zsh") {
		return words.length >= 3 && words[1] === "-lc" && isKnownSafeCommand(words.slice(2).join(" "));
	}

	if (!SAFE_COMMANDS.has(first)) return false;

	switch (first) {
		case "find":
			return !words.some((w) =>
				["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fls", "-fprint", "-fprint0", "-fprintf"].includes(w),
			);
		case "rg":
			return !words.some(
				(w) => w === "--search-zip" || w === "-z" || w.startsWith("--pre") || w.startsWith("--hostname-bin"),
			);
		case "base64":
			return !words.some((w) => w === "-o" || w === "--output" || w.startsWith("--output="));
		case "git": {
			const args = words.slice(1);
			if (args.some((w) => w === "-c" || w.startsWith("-c=") || w === "--ext-diff")) {
				return false;
			}
			const sub = args.find((w) => !w.startsWith("-")) ?? "";
			if (sub === "branch") {
				// Safe only when no positional args beyond "branch" itself
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
			return ["eval", "search", "print-dev-env"].includes(sub);
		}
		case "sed":
			return words.length <= 4 && words[1] === "-n" && /^\d+(,\d+)?p$/.test(words[2] ?? "");
		default:
			return true;
	}
}

export function isDangerousCommand(command: string): boolean {
	// git clean with -n/--dry-run is always a dry-run regardless of other flags
	if (/\bgit\s+clean\b/.test(command) && /\s-(?:[a-z]*n|--dry-run)\b/.test(command)) {
		return false;
	}
	return DANGEROUS_PATTERNS.some((p) => p.test(command));
}

export function truncate(s: string, n: number): string {
	return s.length <= n ? s : s.slice(0, n) + "…";
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
