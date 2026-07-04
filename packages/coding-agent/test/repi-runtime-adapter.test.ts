import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
	buildRuntimeAdapterExecutionGate,
	detectRuntimeAdapterIds,
	formatRuntimeAdapterExecutionGate,
	inspectRuntimeAdapterTarget,
	materializeRuntimeAdapterCommand,
	parseRuntimeAdapterSignals,
	summarizeRuntimeAdapterSignals,
} from "../src/core/repi/runtime-adapter.ts";

describe("REPI runtime adapter pure contracts", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = join(tmpdir(), `repi-runtime-adapter-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	test("detects adapters from local file magic without relying on extensions", () => {
		const elf = join(tempDir, "renamed-native.payload");
		writeFileSync(elf, Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(128)]));
		expect(detectRuntimeAdapterIds(elf)).toEqual(
			expect.arrayContaining(["gdb-native-trace-adapter", "r2-native-xref-adapter"]),
		);

		const pcapng = join(tempDir, "traffic-flow.fixture");
		writeFileSync(pcapng, Buffer.from([0x0a, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x1c]));
		expect(detectRuntimeAdapterIds(pcapng)).toContain("tshark-pcap-flow-adapter");

		const apk = join(tempDir, "mobile.unknown");
		writeFileSync(apk, Buffer.from("PK\x03\x04 AndroidManifest.xml classes.dex", "latin1"));
		expect(detectRuntimeAdapterIds(apk)).toContain("frida-mobile-hook-adapter");

		const firmware = join(tempDir, "firmware.payload");
		writeFileSync(firmware, Buffer.from("hsqs\x00\x00OpenWrt BusyBox", "latin1"));
		expect(detectRuntimeAdapterIds(firmware)).toContain("binwalk-firmware-extract-adapter");

		const dex = join(tempDir, "payload.bin");
		writeFileSync(dex, Buffer.concat([Buffer.from("dex\n035\0", "latin1"), Buffer.alloc(128)]));
		expect(detectRuntimeAdapterIds(dex)).toContain("frida-mobile-hook-adapter");

		const wasm = join(tempDir, "module.payload");
		writeFileSync(wasm, Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d]), Buffer.alloc(128)]));
		expect(detectRuntimeAdapterIds(wasm)).toEqual(
			expect.arrayContaining(["gdb-native-trace-adapter", "r2-native-xref-adapter"]),
		);
	});

	test("profiles CDP/HAR/mobile/native targets with ranked reasons", () => {
		expect(detectRuntimeAdapterIds("ws://127.0.0.1:9222/devtools/browser/abc")).toContain("web-cdp-network-adapter");

		const har = join(tempDir, "capture.har");
		writeFileSync(har, JSON.stringify({ log: { entries: [{ request: { url: "https://example.test/api" } }] } }));
		const harProfile = inspectRuntimeAdapterTarget(har);
		expect(harProfile.magic).toBe("har-json");
		expect(harProfile.adapterIds).toContain("web-cdp-network-adapter");
		expect(harProfile.signals.some((signal) => signal.evidenceRank === "network")).toBe(true);

		const mobileProfile = inspectRuntimeAdapterTarget("com.example.target.app");
		expect(mobileProfile.targetKinds).toContain("mobile-package");
		expect(mobileProfile.reasons.join("\n")).toContain("mobile package/runtime lexical signal");
	});

	test("prioritizes rootfs directory markers over misleading flow-like path names", () => {
		const rootfs = join(tempDir, "flow-rootfs");
		mkdirSync(join(rootfs, "etc", "init.d"), { recursive: true });
		mkdirSync(join(rootfs, "bin"), { recursive: true });
		writeFileSync(join(rootfs, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\n");
		writeFileSync(join(rootfs, "bin", "busybox"), "busybox\n");

		expect(detectRuntimeAdapterIds(rootfs)[0]).toBe("firmware-rootfs-service-map-adapter");
		expect(detectRuntimeAdapterIds(rootfs)).not.toContain("tshark-pcap-flow-adapter");
	});

	test("builds gate rows and parses runner proof signals", () => {
		const report = buildRuntimeAdapterExecutionGate("firmware-rootfs-service-map-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "find" || tool === "grep",
		});
		expect(report.closure.allHaveParserRules).toBe(true);
		const rootfsAdapter = report.adapters.find((row) => row.adapterId === "firmware-rootfs-service-map-adapter");
		expect(rootfsAdapter?.status).toBe("native-ready");

		const command = materializeRuntimeAdapterCommand(rootfsAdapter!.commandTemplate, "/tmp/root fs");
		expect(command).toContain("'/tmp/root fs'");

		const signals = parseRuntimeAdapterSignals(
			rootfsAdapter!,
			"[adapter-rootfs-target] /etc/passwd\nroot:x:0:0:root:/root:/bin/sh\n/etc/init.d/httpd\npassword=admin\n",
		);
		expect(signals.map((row) => row.ruleId)).toEqual(
			expect.arrayContaining(["parser-rootfs-passwd", "parser-rootfs-service-init", "parser-rootfs-config-secret"]),
		);
		expect(signals.every((row) => row.evidenceRank)).toBe(true);
		expect(summarizeRuntimeAdapterSignals(rootfsAdapter!, signals)).toMatchObject({
			matchedRules: 3,
			totalRules: 3,
			missingProofExitSignals: [],
		});
		expect(formatRuntimeAdapterExecutionGate(report)).toContain("target_profile:");
	});

	test("executes real rootfs and web adapter commands against local fixtures", () => {
		const rootfs = join(tempDir, "squashfs-root");
		mkdirSync(join(rootfs, "etc", "init.d"), { recursive: true });
		mkdirSync(join(rootfs, "bin"), { recursive: true });
		writeFileSync(join(rootfs, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\n");
		writeFileSync(join(rootfs, "etc", "config"), "config service httpd\n\toption password 'admin'\n");
		writeFileSync(join(rootfs, "etc", "init.d", "httpd"), "#!/bin/sh\nbusybox httpd -f\n");
		writeFileSync(join(rootfs, "bin", "busybox"), "busybox\n");

		const rootfsReport = buildRuntimeAdapterExecutionGate("firmware-rootfs-service-map-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "find" || tool === "grep",
		});
		const rootfsAdapter = rootfsReport.adapters.find(
			(row) => row.adapterId === "firmware-rootfs-service-map-adapter",
		)!;
		const rootfsOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(rootfsAdapter.commandTemplate, rootfs)],
			{
				encoding: "utf8",
				timeout: 10_000,
			},
		);
		const rootfsSummary = summarizeRuntimeAdapterSignals(
			rootfsAdapter,
			parseRuntimeAdapterSignals(rootfsAdapter, rootfsOutput),
		);
		expect(rootfsOutput).toContain("/etc/passwd");
		expect(rootfsSummary.missingProofExitSignals).toEqual([]);

		const html = [
			"<script>",
			"fetch('/api/orders?nonce=123&timestamp=456', {headers: {'x-signature': 'abc'}});",
			"const ws = new WebSocket('wss://example.test/socket');",
			"const signature = 'abc';",
			"</script>",
		].join("\n");
		const url = `data:text/html;charset=utf-8,${encodeURIComponent(html)}`;
		const webReport = buildRuntimeAdapterExecutionGate("web-cdp-network-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "node" || tool === "curl",
		});
		const webAdapter = webReport.adapters.find((row) => row.adapterId === "web-cdp-network-adapter")!;
		const webOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(webAdapter.commandTemplate, url)],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_ADAPTER_TARGET: url },
				timeout: 10_000,
			},
		);
		expect(webOutput).toContain("[http-response] status=200");
		expect(webOutput).not.toMatch(/replay diff pending|manual-confirm|fallback=portable/i);
		const webSummary = summarizeRuntimeAdapterSignals(webAdapter, parseRuntimeAdapterSignals(webAdapter, webOutput));
		expect(webSummary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["HTTP/CDP response capture", "XHR/WS route extraction", "signed request replay"]),
		);
		expect(webSummary.missingProofExitSignals).toContain("request order proof");
	});

	test("keeps pwn verifier evidence tied to real runs instead of synthetic success markers", () => {
		const report = buildRuntimeAdapterExecutionGate("pwntools-local-verifier-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "python3" || tool === "gdb",
		});
		const adapter = report.adapters.find((row) => row.adapterId === "pwntools-local-verifier-adapter")!;
		expect(materializeRuntimeAdapterCommand(adapter.commandTemplate, "/tmp/vuln")).not.toMatch(
			/manual-confirm|replay diff pending|fallback=portable/i,
		);

		const signals = parseRuntimeAdapterSignals(
			adapter,
			[
				"[pwn-exec-run] run=1 exit=0 signal=NONE stdout_sha256=abc stderr_sha256=def",
				"[pwn-primitive-candidate] symbols=read,write,puts",
				"[pwn-multirun-summary] runs=1 crash_runs=0",
			].join("\n"),
		);
		const summary = summarizeRuntimeAdapterSignals(adapter, signals);
		expect(summary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["primitive control evidence", "multi-run verifier", "stdout/stderr hash"]),
		);
		expect(summary.missingProofExitSignals).toContain("crash-to-offset proof");
	});
});
