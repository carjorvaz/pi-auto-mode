import { homedir } from "node:os";
import {
	DEFAULT_ALLOW_TOOLS,
	classifyToolCall,
	type PolicyDecision,
	type PolicyLayer,
} from "./heuristics.js";

interface SmokeCase {
	name: string;
	toolName: string;
	input: Record<string, unknown>;
	want: PolicyDecision;
	layer?: PolicyLayer;
}

const context = {
	cwd: process.cwd(),
	home: homedir(),
	allowTools: [...DEFAULT_ALLOW_TOOLS],
};

const cases: SmokeCase[] = [
	{
		name: "documents listing pipeline",
		toolName: "bash",
		input: { command: "ls -la ~/Documents | sed -n '1,120p'" },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "cd then read pipeline",
		toolName: "bash",
		input: { command: "cd repo && ls | sed -n '1,20p'" },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "git status through sed",
		toolName: "bash",
		input: { command: "git status | sed -n '1,40p'" },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "ripgrep through head",
		toolName: "bash",
		input: { command: "rg TODO . | head -20" },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "pi agent discovery pipeline",
		toolName: "bash",
		input: {
			command: 'find ~/.pi/agent -maxdepth 4 -type f | sed "s#$HOME#~#" | sort | rg -n "appearance|theme|extension|extensions|package|index|README|\\.ts|\\.js|\\.json|\\.md$"',
		},
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "home appearance discovery",
		toolName: "bash",
		input: {
			command: "find /Users/cjv -path '*/.pi/*' -o -iname '*appearance*' -o -iname '*theme*extension*' 2>/dev/null | head -200",
		},
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "repo appearance discovery",
		toolName: "bash",
		input: {
			command: "find . -maxdepth 5 \\( -path '*/.pi*' -o -path '*extensions*' -o -iname '*appearance*' -o -iname '*theme*' \\) -print | sort | head -300",
		},
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "toolchain probe",
		toolName: "bash",
		input: { command: "command -v tsc || true; command -v pi || true; node -v; npm -v" },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "git status probe",
		toolName: "bash",
		input: { command: "git -C ~/.pi/agent status --short 2>/dev/null || true" },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "plain read tool",
		toolName: "read",
		input: { path: "README.md" },
		want: "allow",
		layer: "allowlist",
	},
	{
		name: "verification requires first grant",
		toolName: "bash",
		input: { command: "npm test" },
		want: "prompt",
		layer: "verification",
	},
	{
		name: "redirected script into shell",
		toolName: "bash",
		input: { command: "head <evil.sh | bash" },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "piped script into shell",
		toolName: "bash",
		input: { command: "cat evil.sh | bash" },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "shell glob expansion",
		toolName: "bash",
		input: { command: "cat .*" },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "git object secret pathspec",
		toolName: "bash",
		input: { command: "git show HEAD:.env" },
		want: "prompt",
		layer: "safety",
	},
	{
		name: "protected path with stderr null",
		toolName: "bash",
		input: { command: "cat .env 2>/dev/null | head -1" },
		want: "prompt",
		layer: "safety",
	},
	{
		name: "process environment pseudo-file",
		toolName: "bash",
		input: { command: "cat /proc/self/environ" },
		want: "prompt",
		layer: "safety",
	},
	{
		name: "infinite device read",
		toolName: "bash",
		input: { command: "cat /dev/zero" },
		want: "prompt",
		layer: "safety",
	},
	{
		name: "recursive grep",
		toolName: "bash",
		input: { command: "grep -R token ." },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "hidden ripgrep",
		toolName: "bash",
		input: { command: 'rg -n "appearance|theme extension|theme" . --hidden -g \'!result\' -g \'!*.lock\'' },
		want: "allow",
		layer: "heuristic",
	},
	{
		name: "unrestricted hidden ripgrep",
		toolName: "bash",
		input: { command: "rg --hidden --no-ignore token ." },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "xxd reverse writes bytes",
		toolName: "bash",
		input: { command: "xxd -r dump.hex output.bin" },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "tail follow can block",
		toolName: "bash",
		input: { command: "tail -f app.log" },
		want: "prompt",
		layer: "fallback",
	},
	{
		name: "date set can mutate system time",
		toolName: "bash",
		input: { command: "date -s tomorrow" },
		want: "prompt",
		layer: "fallback",
	},
];

const nameWidth = Math.max(...cases.map((testCase) => testCase.name.length));
let failures = 0;

console.log(`Policy smoke corpus: ${cases.length} cases`);
for (const testCase of cases) {
	const verdict = classifyToolCall(testCase.toolName, testCase.input, context);
	const decisionMatches = verdict.decision === testCase.want;
	const layerMatches = testCase.layer === undefined || verdict.layer === testCase.layer;
	const ok = decisionMatches && layerMatches;
	if (!ok) failures++;

	const expected = testCase.layer ? `${testCase.want}/${testCase.layer}` : testCase.want;
	const actual = `${verdict.decision}/${verdict.layer}`;
	const label = ok ? "PASS" : "FAIL";
	console.log(`${label} ${testCase.name.padEnd(nameWidth)} expected=${expected} actual=${actual}`);
	if (!ok) {
		console.log(`     reason=${verdict.reason}`);
		console.log(`     input=${JSON.stringify({ toolName: testCase.toolName, input: testCase.input })}`);
	}
}

if (failures > 0) {
	console.error(`\n${failures} smoke case${failures === 1 ? "" : "s"} failed`);
	process.exitCode = 1;
}
