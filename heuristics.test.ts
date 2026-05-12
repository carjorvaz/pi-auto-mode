import { describe, it } from "node:test";
import assert from "node:assert";

import {
	classifyToolCall,
	commandMentionsProtectedPath,
	isStructurallySimple,
	isKnownSafeCommand,
	isDangerousCommand,
	isKnownVerificationCommand,
	isProtectedPath,
	sessionGrantKeyForToolCall,
	shellCommandForPolicy,
} from "./heuristics.js";

const policyContext = {
	cwd: "/home/cjv/project",
	home: "/home/cjv",
	allowTools: ["read", "grep", "find", "ls", "questionnaire"],
};

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

	it("keeps quoted shell wrappers behind confirmation", () => {
		assert.strictEqual(isKnownSafeCommand("bash -lc 'git status'"), false);
		assert.strictEqual(isKnownSafeCommand('bash -lc "git status"'), false);
	});

	it("allows ssh with read-only remote commands", () => {
		assert.strictEqual(isKnownSafeCommand("ssh pius ls"), true);
		assert.strictEqual(isKnownSafeCommand("ssh pius git status"), true);
		assert.strictEqual(isKnownSafeCommand("ssh -p 2222 pius git log"), true);
		assert.strictEqual(isKnownSafeCommand("ssh -p2222 pius pwd"), true);
		assert.strictEqual(isKnownSafeCommand("ssh -o BatchMode=yes -o ConnectTimeout=5 pius true"), true);
		assert.strictEqual(isKnownSafeCommand("ssh -vv pius ls"), true);
		assert.strictEqual(isKnownSafeCommand("ssh pius bash -lc git status"), true);
	});

	it("rejects ssh without remote command or with dangerous options", () => {
		assert.strictEqual(isKnownSafeCommand("ssh pius"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -A pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -L 8080:localhost:80 pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -N pius"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -f pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -fN pius"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -tt pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -X pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -F config pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -E log pius ls"), false);
		assert.strictEqual(isKnownSafeCommand("ssh -o ProxyCommand=sh pius ls"), false);
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
		assert.strictEqual(isKnownSafeCommand("git branch -m"), false);
		assert.strictEqual(isKnownSafeCommand("git branch new-branch"), false);
		assert.strictEqual(isKnownSafeCommand("git branch --set-upstream-to=origin/main"), false);
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
		assert.strictEqual(isKnownSafeCommand("sed -n '1,10p' file"), true);
		assert.strictEqual(isKnownSafeCommand("sed 's/foo/bar/' file"), false);
		assert.strictEqual(isKnownSafeCommand("sed -i 's/foo/bar/' file"), false);
	});

	it("allows simple read-only pipelines", () => {
		assert.strictEqual(isKnownSafeCommand("ls -la ~/Documents | sed -n '1,120p'"), true);
		assert.strictEqual(isKnownSafeCommand("rg TODO . | head -20"), true);
		assert.strictEqual(isKnownSafeCommand("git status | sed -n '1,40p'"), true);
	});

	it("rejects unsafe or mutating pipelines", () => {
		assert.strictEqual(isKnownSafeCommand("cat README.md | sh"), false);
		assert.strictEqual(isKnownSafeCommand("cat evil.sh | bash"), false);
		assert.strictEqual(isKnownSafeCommand("cat evil.sh | bash -s"), false);
		assert.strictEqual(isKnownSafeCommand("head <evil.sh | bash"), false);
		assert.strictEqual(isKnownSafeCommand("ls | xargs rm"), false);
		assert.strictEqual(isKnownSafeCommand("find . -delete | head"), false);
		assert.strictEqual(isKnownSafeCommand("ls || rm file"), false);
		assert.strictEqual(isKnownSafeCommand("ls > out.txt | cat"), false);
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
		assert.strictEqual(isDangerousCommand("git clean --dry-run -fd"), false);
	});

	it("detects git commit and push", () => {
		assert.strictEqual(isDangerousCommand("git commit -m test"), true);
		assert.strictEqual(isDangerousCommand("git push"), true);
	});

	it("detects rmdir and unlink", () => {
		assert.strictEqual(isDangerousCommand("rmdir empty"), true);
		assert.strictEqual(isDangerousCommand("unlink file"), true);
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

describe("isKnownVerificationCommand", () => {
	it("recognizes common verification and build commands", () => {
		assert.strictEqual(isKnownVerificationCommand("cargo check --workspace"), true);
		assert.strictEqual(isKnownVerificationCommand("cargo test"), true);
		assert.strictEqual(isKnownVerificationCommand("cargo fmt --check"), true);
		assert.strictEqual(isKnownVerificationCommand("npm test"), true);
		assert.strictEqual(isKnownVerificationCommand("npm run typecheck"), true);
		assert.strictEqual(isKnownVerificationCommand("pnpm run lint"), true);
		assert.strictEqual(isKnownVerificationCommand("bun test"), true);
		assert.strictEqual(isKnownVerificationCommand("go test ./..."), true);
		assert.strictEqual(isKnownVerificationCommand("nix build"), true);
		assert.strictEqual(isKnownVerificationCommand("nix flake check"), true);
		assert.strictEqual(isKnownVerificationCommand("make test"), true);
		assert.strictEqual(isKnownVerificationCommand("python -m pytest"), true);
		assert.strictEqual(isKnownVerificationCommand("pytest tests"), true);
		assert.strictEqual(isKnownVerificationCommand("eslint src"), true);
		assert.strictEqual(isKnownVerificationCommand("prettier --check ."), true);
	});

	it("rejects mutating package, format, and install commands", () => {
		assert.strictEqual(isKnownVerificationCommand("cargo fmt"), false);
		assert.strictEqual(isKnownVerificationCommand("npm install"), false);
		assert.strictEqual(isKnownVerificationCommand("npm run deploy"), false);
		assert.strictEqual(isKnownVerificationCommand("eslint --fix src"), false);
		assert.strictEqual(isKnownVerificationCommand("prettier --write ."), false);
		assert.strictEqual(isKnownVerificationCommand("make install"), false);
		assert.strictEqual(isKnownVerificationCommand("git push"), false);
	});
});

describe("shellCommandForPolicy", () => {
	it("normalizes simple cd-and-command wrappers", () => {
		assert.deepStrictEqual(
			shellCommandForPolicy("cd ~/Documents/pi-auto-mode && npm   test", policyContext.cwd, policyContext.home),
			{
				command: "npm test",
				cwd: "/home/cjv/Documents/pi-auto-mode",
				cdTarget: "~/Documents/pi-auto-mode",
			},
		);
		assert.deepStrictEqual(
			shellCommandForPolicy("cd repo && git status", policyContext.cwd, policyContext.home),
			{ command: "git status", cwd: "/home/cjv/project/repo", cdTarget: "repo" },
		);
	});

	it("leaves arbitrary shell chains as the original normalized command", () => {
		assert.deepStrictEqual(
			shellCommandForPolicy("cd repo && npm test && git push", policyContext.cwd, policyContext.home),
			{ command: "cd repo && npm test && git push", cwd: policyContext.cwd },
		);
		assert.deepStrictEqual(
			shellCommandForPolicy("cd ~/repo; npm test", policyContext.cwd, policyContext.home),
			{ command: "cd ~/repo; npm test", cwd: policyContext.cwd },
		);
	});
});

describe("protected path checks", () => {
	it("detects sensitive direct paths", () => {
		assert.strictEqual(isProtectedPath(".env", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath(".env.local", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("~/.ssh/config", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("~/.pi/agent/auth.json", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("~/.netrc", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("~/.aws/credentials", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("/etc/shadow", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("secrets/foo.age", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(isProtectedPath("README.md", policyContext.cwd, policyContext.home), false);
	});

	it("detects sensitive path-like command tokens", () => {
		assert.strictEqual(commandMentionsProtectedPath("cat .env", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(commandMentionsProtectedPath("cat ~/.ssh/config", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(commandMentionsProtectedPath("cd repo && cat .env", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(commandMentionsProtectedPath("cd ~/.ssh && npm test", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(commandMentionsProtectedPath("cat .env | sed -n '1,5p'", policyContext.cwd, policyContext.home), true);
		assert.strictEqual(commandMentionsProtectedPath("cat README.md", policyContext.cwd, policyContext.home), false);
	});
});

describe("classifyToolCall", () => {
	it("allows read-only tools on non-sensitive paths", () => {
		assert.strictEqual(classifyToolCall("read", { path: "README.md" }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("grep", { pattern: "secret", path: "." }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("questionnaire", {}, policyContext).decision, "allow");
	});

	it("prompts before reading protected paths", () => {
		assert.strictEqual(classifyToolCall("read", { path: ".env" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("read", { path: "~/.ssh/config" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("read", { path: "~/.pi/agent/auth.json" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("grep", { glob: "**/.env*" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("find", { glob: "**/*.key" }, policyContext).decision, "prompt");
	});

	it("allows known-safe bash commands", () => {
		assert.strictEqual(classifyToolCall("bash", { command: "ls" }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("bash", { command: "git status" }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("bash", { command: "cd repo && git status" }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("bash", { command: "cd repo && ls | sed -n '1,20p'" }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("bash", { command: "ssh pius git status" }, policyContext).decision, "allow");
		assert.strictEqual(classifyToolCall("bash", { command: "ls -la ~/Documents | sed -n '1,120p'" }, policyContext).decision, "allow");
	});

	it("prompts for mutating or ambiguous bash commands", () => {
		assert.strictEqual(classifyToolCall("bash", { command: "git commit -m test" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "git push" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "rm -rf /" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "touch foo" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "cd repo && npm install" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "cd repo && npm test && git push" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "cat .env" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "cat .env && true" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "cat .env | sed -n '1,5p'" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "head <evil.sh | bash" }, policyContext).decision, "prompt");
		assert.strictEqual(classifyToolCall("bash", { command: "cat evil.sh | bash" }, policyContext).decision, "prompt");
	});

	it("offers explicit session grants for verification commands", () => {
		const verdict = classifyToolCall("bash", { command: "npm test" }, policyContext);
		assert.strictEqual(verdict.decision, "prompt");
		assert.strictEqual(verdict.layer, "verification");
		assert.strictEqual(verdict.sessionGrant?.key, "bash:/home/cjv/project:npm test");
		assert.strictEqual(verdict.invalidatesSessionGrants, undefined);

		const cdVerdict = classifyToolCall("bash", { command: "cd ~/Documents/pi-auto-mode && npm test" }, policyContext);
		assert.strictEqual(cdVerdict.decision, "prompt");
		assert.strictEqual(cdVerdict.layer, "verification");
		assert.strictEqual(cdVerdict.sessionGrant?.key, "bash:/home/cjv/Documents/pi-auto-mode:npm test");
	});

	it("allows exact verification commands after a session grant", () => {
		const grantKey = sessionGrantKeyForToolCall("bash", { command: "npm   test" }, policyContext.cwd, policyContext.home);
		assert.strictEqual(grantKey, "bash:/home/cjv/project:npm test");

		const grantedContext = {
			...policyContext,
			sessionGrants: new Set([grantKey!]),
		};
		assert.strictEqual(classifyToolCall("bash", { command: "npm test" }, grantedContext).decision, "allow");
		assert.strictEqual(classifyToolCall("bash", { command: "npm run typecheck" }, grantedContext).decision, "prompt");
		assert.strictEqual(
			classifyToolCall("bash", { command: "npm test" }, { ...grantedContext, cwd: "/home/cjv/other" }).decision,
			"prompt",
		);
	});

	it("allows exact cd-and-verification commands after a session grant", () => {
		const grantKey = sessionGrantKeyForToolCall(
			"bash",
			{ command: "cd ~/Documents/pi-auto-mode && npm   test" },
			policyContext.cwd,
			policyContext.home,
		);
		assert.strictEqual(grantKey, "bash:/home/cjv/Documents/pi-auto-mode:npm test");

		const grantedContext = {
			...policyContext,
			sessionGrants: new Set([grantKey!]),
		};
		assert.strictEqual(
			classifyToolCall("bash", { command: "cd ~/Documents/pi-auto-mode && npm test" }, grantedContext).decision,
			"allow",
		);
		assert.strictEqual(
			classifyToolCall("bash", { command: "cd ~/Documents/pi-auto-mode && npm run typecheck" }, grantedContext).decision,
			"prompt",
		);
	});

	it("marks mutation and unknown actions as session-grant invalidating", () => {
		assert.strictEqual(classifyToolCall("write", { path: "note.txt" }, policyContext).invalidatesSessionGrants, true);
		assert.strictEqual(classifyToolCall("bash", { command: "git push" }, policyContext).invalidatesSessionGrants, true);
		assert.strictEqual(classifyToolCall("bash", { command: "touch foo" }, policyContext).invalidatesSessionGrants, true);
		assert.strictEqual(classifyToolCall("read", { path: ".env" }, policyContext).invalidatesSessionGrants, undefined);
	});

	it("does not let config allowlist mutating tools", () => {
		const permissive = { ...policyContext, allowTools: ["bash", "write", "edit"] };
		assert.strictEqual(classifyToolCall("bash", { command: "touch foo" }, permissive).decision, "prompt");
		assert.strictEqual(classifyToolCall("write", { path: "note.txt" }, permissive).decision, "prompt");
		assert.strictEqual(classifyToolCall("edit", { path: "note.txt" }, permissive).decision, "prompt");
	});

	it("prompts for unknown tools", () => {
		assert.strictEqual(classifyToolCall("fetch", { url: "https://example.com" }, policyContext).decision, "prompt");
	});
});
