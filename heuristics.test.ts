import { describe, it } from "node:test";
import assert from "node:assert";

import {
	isStructurallySimple,
	isKnownSafeCommand,
	isDangerousCommand,
	parseClassifierResponse,
} from "./heuristics.js";

describe("isStructurallySimple", () => {
	it("accepts simple commands", () => {
		assert.strictEqual(isStructurallySimple("ls"), true);
		assert.strictEqual(isStructurallySimple("git status"), true);
	});

	it("rejects shell metacharacters", () => {
		assert.strictEqual(isStructurallySimple("ls; rm -rf /"), false);
		assert.strictEqual(isStructurallySimple("ls && cat"), false);
		assert.strictEqual(isStructurallySimple("ls | cat"), false);
		assert.strictEqual(isStructurallySimple("cat < file"), false);
		assert.strictEqual(isStructurallySimple("echo > file"), false);
	});

	it("rejects subshells and command substitution", () => {
		assert.strictEqual(isStructurallySimple("$(whoami)"), false);
		assert.strictEqual(isStructurallySimple("`whoami`"), false);
	});

	it("rejects variable expansion", () => {
		assert.strictEqual(isStructurallySimple("echo $HOME"), false);
		assert.strictEqual(isStructurallySimple("echo ${HOME}"), false);
	});

	it("rejects quotes", () => {
		assert.strictEqual(isStructurallySimple('bash -c "rm -rf /"'), false);
		assert.strictEqual(isStructurallySimple("bash -lc 'git status'"), false);
	});

	it("rejects brace expansion", () => {
		assert.strictEqual(isStructurallySimple("echo {a,b,c}"), false);
		assert.strictEqual(isStructurallySimple("touch {1..100}"), false);
	});

	it("rejects newlines", () => {
		assert.strictEqual(isStructurallySimple("ls\nrm -rf /"), false);
	});
});

describe("isKnownSafeCommand", () => {
	it("allows safe read-only commands", () => {
		assert.strictEqual(isKnownSafeCommand("ls"), true);
		assert.strictEqual(isKnownSafeCommand("pwd"), true);
		assert.strictEqual(isKnownSafeCommand("git status"), true);
		assert.strictEqual(isKnownSafeCommand("git log"), true);
		assert.strictEqual(isKnownSafeCommand("git diff"), true);
		assert.strictEqual(isKnownSafeCommand("git show"), true);
		assert.strictEqual(isKnownSafeCommand("git branch"), true);
		assert.strictEqual(isKnownSafeCommand("git remote"), true);
		assert.strictEqual(isKnownSafeCommand("git remote -v"), true);
		assert.strictEqual(isKnownSafeCommand("git remote show origin"), true);
		assert.strictEqual(isKnownSafeCommand("git remote get-url origin"), true);
	});

	it("allows bash -lc wrapper for safe commands", () => {
		assert.strictEqual(isKnownSafeCommand("bash -lc git status"), true);
		assert.strictEqual(isKnownSafeCommand("bash -lc ls"), true);
	});

	it("rejects bash without -lc wrapper", () => {
		assert.strictEqual(isKnownSafeCommand("bash -c rm -rf /"), false);
		assert.strictEqual(isKnownSafeCommand("bash rm -rf /"), false);
		assert.strictEqual(isKnownSafeCommand("bash"), false);
	});

	it("rejects zsh without -lc wrapper", () => {
		assert.strictEqual(isKnownSafeCommand("zsh -c echo hi"), false);
	});

	it("rejects git config injection", () => {
		assert.strictEqual(isKnownSafeCommand("git -c diff.external=sh diff"), false);
		assert.strictEqual(isKnownSafeCommand("git -c=alias.st=status st"), false);
		assert.strictEqual(isKnownSafeCommand("git diff --ext-diff"), false);
	});

	it("rejects destructive git subcommands", () => {
		assert.strictEqual(isKnownSafeCommand("git remote prune origin"), false);
		assert.strictEqual(isKnownSafeCommand("git remote add origin foo"), false);
		assert.strictEqual(isKnownSafeCommand("git remote remove origin"), false);
		assert.strictEqual(isKnownSafeCommand("git remote set-url origin foo"), false);
	});

	it("rejects git branch with positional args", () => {
		assert.strictEqual(isKnownSafeCommand("git branch -d main"), false);
		assert.strictEqual(isKnownSafeCommand("git branch new-branch"), false);
	});

	it("allows nix read-only commands", () => {
		assert.strictEqual(isKnownSafeCommand("nix eval"), true);
		assert.strictEqual(isKnownSafeCommand("nix search foo"), true);
		assert.strictEqual(isKnownSafeCommand("nix flake show"), true);
		assert.strictEqual(isKnownSafeCommand("nix flake metadata"), true);
	});

	it("rejects find with execution flags", () => {
		assert.strictEqual(isKnownSafeCommand("find . -exec rm {} \\;"), false);
		assert.strictEqual(isKnownSafeCommand("find . -delete"), false);
	});

	it("rejects rg with unsafe flags", () => {
		assert.strictEqual(isKnownSafeCommand("rg --search-zip foo"), false);
		assert.strictEqual(isKnownSafeCommand("rg -z foo"), false);
		assert.strictEqual(isKnownSafeCommand("rg --pre-cmd=sh foo"), false);
	});

	it("rejects base64 with output flag", () => {
		assert.strictEqual(isKnownSafeCommand("base64 -o file"), false);
		assert.strictEqual(isKnownSafeCommand("base64 --output=file"), false);
	});

	it("rejects sed outside narrow safe pattern", () => {
		assert.strictEqual(isKnownSafeCommand("sed -n 1p file"), true);
		assert.strictEqual(isKnownSafeCommand("sed -n 1,10p file"), true);
		assert.strictEqual(isKnownSafeCommand("sed 's/foo/bar/' file"), false);
		assert.strictEqual(isKnownSafeCommand("sed -i 's/foo/bar/' file"), false);
	});
});

describe("isDangerousCommand", () => {
	it("detects rm", () => {
		assert.strictEqual(isDangerousCommand("rm file.txt"), true);
		assert.strictEqual(isDangerousCommand("rm -rf /"), true);
		assert.strictEqual(isDangerousCommand("rm --recursive --force /"), true);
	});

	it("detects sudo", () => {
		assert.strictEqual(isDangerousCommand("sudo ls"), true);
	});

	it("detects privilege escalation tools", () => {
		assert.strictEqual(isDangerousCommand("doas ls"), true);
		assert.strictEqual(isDangerousCommand("pkexec ls"), true);
		assert.strictEqual(isDangerousCommand("run0 ls"), true);
		assert.strictEqual(isDangerousCommand("su -"), true);
		assert.strictEqual(isDangerousCommand("sg adm"), true);
		assert.strictEqual(isDangerousCommand("newgrp"), true);
		assert.strictEqual(isDangerousCommand("sudoedit /etc/passwd"), true);
	});

	it("detects disk destroyers", () => {
		assert.strictEqual(isDangerousCommand("dd if=/dev/zero of=/dev/sda"), true);
		assert.strictEqual(isDangerousCommand("dd"), true);
		assert.strictEqual(isDangerousCommand("mkfs.ext4 /dev/sda1"), true);
		assert.strictEqual(isDangerousCommand("shred -u file.txt"), true);
	});

	it("detects git reset --hard", () => {
		assert.strictEqual(isDangerousCommand("git reset --hard HEAD~1"), true);
	});

	it("detects git checkout -f", () => {
		assert.strictEqual(isDangerousCommand("git checkout -f main"), true);
	});

	it("detects git clean with force flags", () => {
		assert.strictEqual(isDangerousCommand("git clean -fd"), true);
		assert.strictEqual(isDangerousCommand("git clean -fdx"), true);
		assert.strictEqual(isDangerousCommand("git clean --force -d"), true);
	});

	it("does not flag git clean dry-run", () => {
		assert.strictEqual(isDangerousCommand("git clean -n"), false);
		assert.strictEqual(isDangerousCommand("git clean -dn"), false);
	});

	it("detects nixos-rebuild switch", () => {
		assert.strictEqual(isDangerousCommand("nixos-rebuild switch"), true);
	});

	it("detects darwin-rebuild switch", () => {
		assert.strictEqual(isDangerousCommand("darwin-rebuild switch"), true);
	});

	it("does not flag safe commands", () => {
		assert.strictEqual(isDangerousCommand("ls"), false);
		assert.strictEqual(isDangerousCommand("git status"), false);
	});
});

describe("parseClassifierResponse", () => {
	it("parses structured ALLOW", () => {
		const result = parseClassifierResponse("DECISION: ALLOW\nREASON: safe read-only");
		assert.deepStrictEqual(result, { shouldBlock: false, reason: "safe read-only" });
	});

	it("parses structured BLOCK", () => {
		const result = parseClassifierResponse("DECISION: BLOCK\nREASON: deletes files");
		assert.deepStrictEqual(result, { shouldBlock: true, reason: "deletes files" });
	});

	it("accepts ALLOWED as allow in structured format", () => {
		const result = parseClassifierResponse("DECISION: ALLOWED\nREASON: clearly safe");
		assert.deepStrictEqual(result, { shouldBlock: false, reason: "clearly safe" });
	});

	it("falls back to default reason when REASON missing", () => {
		const allow = parseClassifierResponse("DECISION: ALLOW");
		assert.deepStrictEqual(allow, { shouldBlock: false, reason: "Allowed by classifier" });

		const block = parseClassifierResponse("DECISION: BLOCK");
		assert.deepStrictEqual(block, { shouldBlock: true, reason: "Blocked by classifier" });
	});

	it("parses bare word ALLOW for fast gate", () => {
		const result = parseClassifierResponse("ALLOW");
		assert.deepStrictEqual(result, { shouldBlock: false, reason: "Allowed by classifier" });
	});

	it("parses bare word BLOCK for fast gate", () => {
		const result = parseClassifierResponse("BLOCK");
		assert.deepStrictEqual(result, { shouldBlock: true, reason: "Blocked by classifier" });
	});

	it("rejects ambiguous bare words", () => {
		assert.strictEqual(parseClassifierResponse("ALLOWED"), null);
		assert.strictEqual(parseClassifierResponse("BLOCKED"), null);
		assert.strictEqual(parseClassifierResponse("maybe"), null);
		assert.strictEqual(parseClassifierResponse(""), null);
	});
});
