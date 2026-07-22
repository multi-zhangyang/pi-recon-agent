import { createHash } from "node:crypto";
import { join } from "node:path";
import type { ExtensionAPI } from "../extensions/types.ts";
import type { EvidenceRecord } from "./evidence.ts";

type PassiveMapCommandResult = {
	code: number;
	stdout: string;
	stderr: string;
	killed?: boolean;
};

type AppendEvidence = (
	record: Omit<EvidenceRecord, "timestamp" | "priority"> & { priority?: number },
) => EvidenceRecord;

export type PassiveMapRuntimeDependencies = {
	ensureReconStorage: () => void;
	evidenceMapsDir: () => string;
	writePrivateTextFile: (path: string, text: string) => void;
	appendEvidence: AppendEvidence;
	currentMissionId: () => string | undefined;
	updateMissionCheckpoint: (name: string, status: "done", note?: string) => unknown;
	shellQuote: (value: string) => string;
	slug: (value: string) => string;
	truncateMiddle: (value: string, maxLength: number) => string;
	interestingLines: (value: string, pattern: RegExp, limit: number) => string[];
};

/** Passive target/workspace mapping with durable evidence and mission writeback. */
export function createPassiveMapRuntime(dependencies: PassiveMapRuntimeDependencies) {
	const {
		ensureReconStorage,
		evidenceMapsDir,
		writePrivateTextFile,
		appendEvidence,
		currentMissionId,
		updateMissionCheckpoint,
		shellQuote,
		slug,
		truncateMiddle,
		interestingLines,
	} = dependencies;

	function passiveMapScript(target?: string, depth?: number): string {
		const maxDepth = Math.min(Math.max(Math.floor(depth ?? 4), 1), 8);
		const targetArg = shellQuote(target?.trim() || ".");
		return [
			"set +e",
			`TARGET=${targetArg}`,
			'case "$TARGET" in http://*|https://*) ROOT="." ;; *) if [ -d "$TARGET" ]; then ROOT="$TARGET"; else ROOT="."; fi ;; esac',
			'echo "## context"',
			"pwd",
			'printf "target=%s\\n" "$TARGET"',
			'printf "root=%s\\n" "$ROOT"',
			'printf "date_utc=%s\\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"',
			"git rev-parse --show-toplevel 2>/dev/null || true",
			'echo "## target-stat"',
			'if [ -e "$TARGET" ]; then ls -la "$TARGET"; file "$TARGET" 2>/dev/null || true; if [ -f "$TARGET" ]; then sha256sum "$TARGET" 2>/dev/null || true; fi; else echo "target_missing=$TARGET"; fi',
			'echo "## file-inventory"',
			`find "$ROOT" -maxdepth ${maxDepth} -type f \\( -path '*/.git/*' -o -path '*/node_modules/*' -o -path '*/dist/*' -o -path '*/build/*' \\) -prune -o -type f -print 2>/dev/null | sort | head -300`,
			'echo "## manifests-configs"',
			`find "$ROOT" -maxdepth ${maxDepth} -type f \\( -name 'package.json' -o -name 'pyproject.toml' -o -name 'requirements*.txt' -o -name 'go.mod' -o -name 'Cargo.toml' -o -name 'pom.xml' -o -name 'build.gradle*' -o -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name '.env*' -o -name 'AndroidManifest.xml' -o -name 'Info.plist' -o -name 'openapi*.json' -o -name 'swagger*.json' \\) -print 2>/dev/null | sort | head -200`,
			'echo "## route-auth-search"',
			'if command -v rg >/dev/null 2>&1; then rg -n --glob "!node_modules" --glob "!dist" --glob "!build" "route|router|app\\.|fastify|express|auth|session|jwt|csrf|graphql|websocket|worker|queue|license|serial|flag|verify|sign|crypto|token|secret|admin|debug" "$ROOT" 2>/dev/null | head -240; else grep -RInE "route|router|auth|session|jwt|graphql|websocket|license|serial|flag|verify|sign|token|secret|admin|debug" "$ROOT" 2>/dev/null | head -160; fi',
			'echo "## binary-candidates"',
			`find "$ROOT" -maxdepth ${maxDepth} -type f -exec sh -c 'file "$1" | grep -E "ELF|PE32|Mach-O|Zip archive|Android package|Dalvik|WebAssembly" || true' _ {} \\; 2>/dev/null | head -120`,
			'case "$TARGET" in http://*|https://*) echo "## http-baseline"; curl -k -sS -I --max-time 10 "$TARGET" 2>&1 | sed -n "1,80p";; esac',
		].join("\n");
	}

	function passiveMapSignals(stdout: string, stderr: string): string[] {
		const text = `${stdout}\n${stderr}`;
		return [
			...interestingLines(text, /ELF|PE32|Mach-O|Android package|WebAssembly|Dalvik/i, 12).map(
				(line) => `binary:${truncateMiddle(line, 220)}`,
			),
			...interestingLines(text, /route|router|app\.|fastify|express|graphql|websocket|worker|queue/i, 12).map(
				(line) => `route:${truncateMiddle(line, 220)}`,
			),
			...interestingLines(text, /auth|session|jwt|csrf|oauth|token|secret|admin|debug/i, 12).map(
				(line) => `auth-state:${truncateMiddle(line, 220)}`,
			),
			...interestingLines(text, /license|serial|flag|verify|sign|crypto|encrypt|decrypt/i, 12).map(
				(line) => `logic:${truncateMiddle(line, 220)}`,
			),
			...interestingLines(text, /HTTP\/|server:|location:|set-cookie:/i, 8).map(
				(line) => `http:${truncateMiddle(line, 220)}`,
			),
		].slice(0, 40);
	}

	function writePassiveMapArtifact(params: {
		target?: string;
		depth: number;
		script: string;
		result: PassiveMapCommandResult;
		signals: string[];
	}): string {
		ensureReconStorage();
		const timestamp = new Date().toISOString();
		const path = join(
			evidenceMapsDir(),
			`${timestamp.replace(/[:.]/g, "-")}-${slug(params.target ?? "workspace")}.md`,
		);
		writePrivateTextFile(
			path,
			[
				"# REPI Passive Map Artifact",
				"",
				`timestamp: ${timestamp}`,
				`mission_id: ${currentMissionId() ?? "none"}`,
				`target: ${params.target ?? "."}`,
				`depth: ${params.depth}`,
				`exit: ${params.result.code}`,
				`killed: ${params.result.killed ? "true" : "false"}`,
				"",
				"## Signals",
				"",
				...(params.signals.length > 0
					? params.signals.map((signal) => `- ${signal}`)
					: ["- no high-signal anchors parsed"]),
				"",
				"## Script",
				"",
				"```bash",
				params.script,
				"```",
				"",
				"## stdout",
				"",
				"```",
				params.result.stdout,
				"```",
				"",
				"## stderr",
				"",
				"```",
				params.result.stderr,
				"```",
				"",
			].join("\n"),
		);
		return path;
	}

	async function runPassiveMap(pi: ExtensionAPI, params: { target?: string; depth?: number }): Promise<string> {
		const depth = Math.min(Math.max(Math.floor(params.depth ?? 4), 1), 8);
		const script = passiveMapScript(params.target, depth);
		const result = await pi.exec("bash", ["-lc", script], { timeout: 60000 });
		const signals = passiveMapSignals(result.stdout, result.stderr);
		const artifactPath = writePassiveMapArtifact({ target: params.target, depth, script, result, signals });
		const evidence = appendEvidence({
			kind: "artifact",
			title: `passive-map ${params.target ?? "workspace"} exit ${result.code}`,
			fact: [
				`Captured passive target/workspace map with ${signals.length} parsed signal(s)`,
				`stdout=${result.stdout.length}B`,
				`stderr=${result.stderr.length}B`,
				result.killed ? "killed=true" : "killed=false",
				signals.length ? `signals=${signals.slice(0, 10).join(" | ")}` : undefined,
			]
				.filter(Boolean)
				.join("; "),
			command: `re_map${params.target ? ` ${params.target}` : ""}`,
			path: artifactPath,
			verify: `cat ${artifactPath}`,
			confidence: "auto-captured passive map",
		});
		updateMissionCheckpoint("passive_map_done", "done", artifactPath);
		return [
			"passive_map_result:",
			`exit: ${result.code}`,
			`killed: ${result.killed ? "true" : "false"}`,
			`stdout_bytes: ${Buffer.byteLength(result.stdout, "utf8")}`,
			`stderr_bytes: ${Buffer.byteLength(result.stderr, "utf8")}`,
			`stdout_sha256: ${createHash("sha256").update(result.stdout).digest("hex")}`,
			`stderr_sha256: ${createHash("sha256").update(result.stderr).digest("hex")}`,
			`map_artifact: ${artifactPath}`,
			`evidence_ledger: ${evidence.timestamp} ${evidence.title}`,
			`signals: ${signals.length}`,
			"",
			"top_signals:",
			...(signals.length > 0 ? signals.slice(0, 8).map((signal) => `- ${signal}`) : ["- none"]),
			`verify: cat ${artifactPath}`,
		]
			.filter(Boolean)
			.join("\n");
	}

	return { runPassiveMap };
}
