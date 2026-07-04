import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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

function be16(value: number): Buffer {
	const buffer = Buffer.alloc(2);
	buffer.writeUInt16BE(value, 0);
	return buffer;
}

function be24(value: number): Buffer {
	return Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}

function dnsQueryPayload(name: string): Buffer {
	const header = Buffer.alloc(12);
	header.writeUInt16BE(0x1234, 0);
	header.writeUInt16BE(0x0100, 2);
	header.writeUInt16BE(1, 4);
	const labels = name
		.split(".")
		.flatMap((label) => [Buffer.from([Buffer.byteLength(label, "ascii")]), Buffer.from(label, "ascii")]);
	return Buffer.concat([header, ...labels, Buffer.from([0]), be16(1), be16(1)]);
}

function tlsClientHelloSniPayload(hostname: string): Buffer {
	const host = Buffer.from(hostname, "ascii");
	const serverName = Buffer.concat([Buffer.from([0]), be16(host.length), host]);
	const sniList = Buffer.concat([be16(serverName.length), serverName]);
	const sniExtension = Buffer.concat([be16(0), be16(sniList.length), sniList]);
	const clientHello = Buffer.concat([
		Buffer.from([0x03, 0x03]),
		Buffer.alloc(32, 0x42),
		Buffer.from([0]),
		be16(2),
		Buffer.from([0x13, 0x01]),
		Buffer.from([1, 0]),
		be16(sniExtension.length),
		sniExtension,
	]);
	const handshake = Buffer.concat([Buffer.from([1]), be24(clientHello.length), clientHello]);
	return Buffer.concat([Buffer.from([22, 3, 3]), be16(handshake.length), handshake]);
}

function ethernetIpv4TcpFrame(payload: Buffer, sourcePort: number, destPort: number): Buffer {
	const ethernet = Buffer.concat([Buffer.alloc(6, 0xaa), Buffer.alloc(6, 0xbb), Buffer.from([0x08, 0x00])]);
	const ip = Buffer.alloc(20);
	ip[0] = 0x45;
	ip.writeUInt16BE(20 + 20 + payload.length, 2);
	ip[8] = 64;
	ip[9] = 6;
	Buffer.from([10, 1, 0, 2]).copy(ip, 12);
	Buffer.from([93, 184, 216, 34]).copy(ip, 16);
	const tcp = Buffer.alloc(20);
	tcp.writeUInt16BE(sourcePort, 0);
	tcp.writeUInt16BE(destPort, 2);
	tcp.writeUInt32BE(1, 4);
	tcp[12] = 0x50;
	tcp[13] = 0x18;
	tcp.writeUInt16BE(8192, 14);
	return Buffer.concat([ethernet, ip, tcp, payload]);
}

function ethernetIpv4UdpFrame(payload: Buffer, sourcePort: number, destPort: number): Buffer {
	const ethernet = Buffer.concat([Buffer.alloc(6, 0xcc), Buffer.alloc(6, 0xdd), Buffer.from([0x08, 0x00])]);
	const ip = Buffer.alloc(20);
	ip[0] = 0x45;
	ip.writeUInt16BE(20 + 8 + payload.length, 2);
	ip[8] = 64;
	ip[9] = 17;
	Buffer.from([10, 1, 0, 2]).copy(ip, 12);
	Buffer.from([8, 8, 8, 8]).copy(ip, 16);
	const udp = Buffer.alloc(8);
	udp.writeUInt16BE(sourcePort, 0);
	udp.writeUInt16BE(destPort, 2);
	udp.writeUInt16BE(8 + payload.length, 4);
	return Buffer.concat([ethernet, ip, udp, payload]);
}

function pcapngBlock(type: number, body: Buffer): Buffer {
	const padding = Buffer.alloc((4 - (body.length % 4)) % 4);
	const totalLength = 12 + body.length + padding.length;
	const header = Buffer.alloc(8);
	header.writeUInt32LE(type, 0);
	header.writeUInt32LE(totalLength, 4);
	const trailer = Buffer.alloc(4);
	trailer.writeUInt32LE(totalLength, 0);
	return Buffer.concat([header, body, padding, trailer]);
}

function pcapngSectionHeader(): Buffer {
	const body = Buffer.alloc(16);
	body.writeUInt32LE(0x1a2b3c4d, 0);
	body.writeUInt16LE(1, 4);
	body.writeUInt16LE(0, 6);
	body.writeBigInt64LE(-1n, 8);
	return pcapngBlock(0x0a0d0d0a, body);
}

function pcapngInterfaceDescription(): Buffer {
	const body = Buffer.alloc(8);
	body.writeUInt16LE(1, 0);
	body.writeUInt32LE(65535, 4);
	return pcapngBlock(1, body);
}

function pcapngEnhancedPacket(frame: Buffer): Buffer {
	const header = Buffer.alloc(20);
	header.writeUInt32LE(0, 0);
	header.writeUInt32LE(frame.length, 12);
	header.writeUInt32LE(frame.length, 16);
	return pcapngBlock(6, Buffer.concat([header, frame]));
}

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
			expect.arrayContaining([
				"HTTP/CDP response capture",
				"XHR/WS route extraction",
				"request order proof",
				"signed request replay",
			]),
		);
		expect(webSummary.missingProofExitSignals).toEqual([]);

		const har = join(tempDir, "signed-flow.har");
		writeFileSync(
			har,
			JSON.stringify({
				log: {
					entries: [
						{
							request: {
								method: "POST",
								url: "https://example.test/api/orders?nonce=123&timestamp=456",
								headers: [{ name: "x-signature", value: "abc" }],
								postData: { text: '{"signature":"abc","timestamp":456}' },
							},
							response: {
								status: 200,
								headers: [{ name: "etag", value: "signed-response" }],
								content: { mimeType: "application/json", text: '{"ok":true}' },
							},
						},
					],
				},
			}),
		);
		const harOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(webAdapter.commandTemplate, har)],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_ADAPTER_TARGET: har },
				timeout: 10_000,
			},
		);
		const harSummary = summarizeRuntimeAdapterSignals(webAdapter, parseRuntimeAdapterSignals(webAdapter, harOutput));
		expect(harOutput).toContain("[har-file]");
		expect(harOutput).toContain("[request-order] index=1");
		expect(harSummary.matchedProofExitSignals).toEqual(
			expect.arrayContaining([
				"HTTP/CDP response capture",
				"XHR/WS route extraction",
				"request order proof",
				"signed request replay",
			]),
		);
		expect(harSummary.missingProofExitSignals).toEqual([]);
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

	test("executes real fallback commands for PCAP, mobile package, and pwn fixtures", () => {
		const pcap = join(tempDir, "capture.pcap");
		const pcapPayload = Buffer.from(
			"GET /login HTTP/1.1\r\nHost: target.local\r\nCookie: sid=abc\r\npassword=demo\r\n\r\n",
			"latin1",
		);
		const ethernet = Buffer.concat([Buffer.alloc(6, 0x00), Buffer.alloc(6, 0x11), Buffer.from([0x08, 0x00])]);
		const ip = Buffer.alloc(20);
		ip[0] = 0x45;
		ip.writeUInt16BE(20 + 20 + pcapPayload.length, 2);
		ip[8] = 64;
		ip[9] = 6;
		Buffer.from([10, 0, 0, 1]).copy(ip, 12);
		Buffer.from([10, 0, 0, 2]).copy(ip, 16);
		const tcp = Buffer.alloc(20);
		tcp.writeUInt16BE(12345, 0);
		tcp.writeUInt16BE(80, 2);
		tcp[12] = 0x50;
		tcp[13] = 0x18;
		tcp.writeUInt16BE(8192, 14);
		const frame = Buffer.concat([ethernet, ip, tcp, pcapPayload]);
		const packetHeader = Buffer.alloc(16);
		packetHeader.writeUInt32LE(1, 0);
		packetHeader.writeUInt32LE(0, 4);
		packetHeader.writeUInt32LE(frame.length, 8);
		packetHeader.writeUInt32LE(frame.length, 12);
		writeFileSync(
			pcap,
			Buffer.concat([Buffer.from("d4c3b2a1020004000000000000000000ffff000001000000", "hex"), packetHeader, frame]),
		);
		const pcapReport = buildRuntimeAdapterExecutionGate("tshark-pcap-flow-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "python3",
		});
		const pcapAdapter = pcapReport.adapters.find((row) => row.adapterId === "tshark-pcap-flow-adapter")!;
		const pcapOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(pcapAdapter.fallbackCommandTemplate, pcap)],
			{ encoding: "utf8", timeout: 10_000 },
		);
		const pcapSummary = summarizeRuntimeAdapterSignals(
			pcapAdapter,
			parseRuntimeAdapterSignals(pcapAdapter, pcapOutput),
		);
		expect(pcapOutput).toContain("[pcap-file]");
		expect(pcapOutput).toContain("[flow-conversation]");
		expect(pcapOutput).toContain("[http-object]");
		expect(pcapOutput).toContain("GET /login HTTP/1.1");
		expect(pcapOutput).toContain("[credential-timeline]");
		expect(pcapSummary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["flow conversation", "follow-stream", "timeline evidence"]),
		);

		const apk = join(tempDir, "target.apk");
		execFileSync(
			"python3",
			[
				"-c",
				[
					"import sys, zipfile",
					"path = sys.argv[1]",
					"with zipfile.ZipFile(path, 'w') as z:",
					"    z.writestr('AndroidManifest.xml', '<manifest package=\"com.repi.fixture\"/>')",
					"    z.writestr('classes.dex', 'OkHttp CertificatePinner TrustManager Cipher MessageDigest pinning X509')",
				].join("\n"),
				apk,
			],
			{ encoding: "utf8", timeout: 10_000 },
		);
		const mobileReport = buildRuntimeAdapterExecutionGate("frida-mobile-hook-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "bash",
		});
		const mobileAdapter = mobileReport.adapters.find((row) => row.adapterId === "frida-mobile-hook-adapter")!;
		const mobileOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(mobileAdapter.fallbackCommandTemplate, apk)],
			{ encoding: "utf8", timeout: 10_000 },
		);
		const mobileSummary = summarizeRuntimeAdapterSignals(
			mobileAdapter,
			parseRuntimeAdapterSignals(mobileAdapter, mobileOutput),
		);
		expect(mobileOutput).toMatch(/classes\.dex|OkHttp|CertificatePinner/);
		expect(mobileSummary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["runtime attach env checkpoint", "hook output artifact contract"]),
		);

		const pwnTarget = join(tempDir, "pwn-fixture.sh");
		writeFileSync(pwnTarget, "#!/usr/bin/env bash\nprintf 'read write puts system /bin/sh flag token\\n'\n", "utf8");
		chmodSync(pwnTarget, 0o700);
		const pwnReport = buildRuntimeAdapterExecutionGate("pwntools-local-verifier-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "python3",
		});
		const pwnAdapter = pwnReport.adapters.find((row) => row.adapterId === "pwntools-local-verifier-adapter")!;
		const pwnOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(pwnAdapter.commandTemplate, pwnTarget)],
			{
				encoding: "utf8",
				env: { ...process.env, REPI_ADAPTER_TARGET: pwnTarget, REPI_EXPLOIT_VERIFY_RUNS: "2" },
				timeout: 15_000,
			},
		);
		const pwnSummary = summarizeRuntimeAdapterSignals(pwnAdapter, parseRuntimeAdapterSignals(pwnAdapter, pwnOutput));
		expect(pwnOutput).toContain("[pwn-exec-run] run=1");
		expect(pwnOutput).toContain("stdout_sha256=");
		expect(pwnSummary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["primitive control evidence", "multi-run verifier", "stdout/stderr hash"]),
		);
		expect(pwnOutput).not.toMatch(/manual-confirm|replay diff pending|fallback=portable/i);
	});

	test("executes the PCAP fallback against pcapng DNS and TLS-SNI fixtures", () => {
		const pcapng = join(tempDir, "dns-tls.fixture");
		const hostname = "api.target.local";
		writeFileSync(
			pcapng,
			Buffer.concat([
				pcapngSectionHeader(),
				pcapngInterfaceDescription(),
				pcapngEnhancedPacket(ethernetIpv4UdpFrame(dnsQueryPayload(hostname), 53000, 53)),
				pcapngEnhancedPacket(ethernetIpv4TcpFrame(tlsClientHelloSniPayload(hostname), 44321, 443)),
			]),
		);

		const pcapReport = buildRuntimeAdapterExecutionGate("tshark-pcap-flow-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "python3",
		});
		const pcapAdapter = pcapReport.adapters.find((row) => row.adapterId === "tshark-pcap-flow-adapter")!;
		const output = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(pcapAdapter.fallbackCommandTemplate, pcapng)],
			{ encoding: "utf8", timeout: 10_000 },
		);
		const summary = summarizeRuntimeAdapterSignals(pcapAdapter, parseRuntimeAdapterSignals(pcapAdapter, output));

		expect(output).toContain("format=pcapng");
		expect(output).toContain("[dns-query]");
		expect(output).toContain(`qname=${hostname}`);
		expect(output).toContain("[tls-sni]");
		expect(output).toContain(`server_name=${hostname}`);
		expect(output).toContain("[flow-conversation]");
		expect(summary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["flow conversation", "dns timeline", "tls sni proof"]),
		);
	});

	test("executes real native fallback commands for r2, GDB, and Ghidra-style adapters", () => {
		const compiler = execFileSync("bash", ["-lc", "command -v cc || command -v gcc || command -v clang || true"], {
			encoding: "utf8",
			timeout: 5_000,
		})
			.trim()
			.split(/\r?\n/)[0];
		expect(compiler).toBeTruthy();

		const source = join(tempDir, "native-fixture.c");
		const binary = join(tempDir, "native-fixture");
		writeFileSync(
			source,
			[
				"#include <stdio.h>",
				"#include <string.h>",
				"int main(int argc, char **argv) {",
				'  const char *secret = "license password token flag";',
				'  if (argc > 1 && strcmp(argv[1], "open-sesame") == 0) puts(secret);',
				"  return 0;",
				"}",
			].join("\n"),
			"utf8",
		);
		execFileSync(compiler, [source, "-O0", "-g", "-o", binary], { encoding: "utf8", timeout: 20_000 });

		const r2Report = buildRuntimeAdapterExecutionGate("r2-native-xref-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "objdump",
		});
		const r2Adapter = r2Report.adapters.find((row) => row.adapterId === "r2-native-xref-adapter")!;
		const r2Output = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(r2Adapter.fallbackCommandTemplate, binary)],
			{
				encoding: "utf8",
				timeout: 20_000,
			},
		);
		const r2Summary = summarizeRuntimeAdapterSignals(r2Adapter, parseRuntimeAdapterSignals(r2Adapter, r2Output));
		expect(r2Output).toContain("license password token flag");
		expect(r2Summary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["symbol/import map", "control-flow xref", "runtime adapter transcript"]),
		);

		const gdbReport = buildRuntimeAdapterExecutionGate("gdb-native-trace-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "objdump",
		});
		const gdbAdapter = gdbReport.adapters.find((row) => row.adapterId === "gdb-native-trace-adapter")!;
		const gdbOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(gdbAdapter.fallbackCommandTemplate, binary)],
			{
				encoding: "utf8",
				timeout: 20_000,
			},
		);
		const gdbSummary = summarizeRuntimeAdapterSignals(gdbAdapter, parseRuntimeAdapterSignals(gdbAdapter, gdbOutput));
		expect(gdbOutput).toMatch(/Entry point|\\.text|<main>/);
		expect(gdbSummary.matchedProofExitSignals).toEqual(expect.arrayContaining(["function/runtime entry map"]));

		const ghidraReport = buildRuntimeAdapterExecutionGate("ghidra-headless-summary-adapter", {
			toolIndexPath: "/tmp/tool-index.md",
			isToolPresent: (tool) => tool === "readelf",
		});
		const ghidraAdapter = ghidraReport.adapters.find((row) => row.adapterId === "ghidra-headless-summary-adapter")!;
		const ghidraOutput = execFileSync(
			"bash",
			["-lc", materializeRuntimeAdapterCommand(ghidraAdapter.fallbackCommandTemplate, binary)],
			{
				encoding: "utf8",
				timeout: 20_000,
			},
		);
		const ghidraSummary = summarizeRuntimeAdapterSignals(
			ghidraAdapter,
			parseRuntimeAdapterSignals(ghidraAdapter, ghidraOutput),
		);
		expect(ghidraOutput).toMatch(/Symbol table|Entry point|GLOBAL/);
		expect(ghidraSummary.matchedProofExitSignals).toEqual(
			expect.arrayContaining(["function inventory", "import table proof"]),
		);
		expect(`${r2Output}\n${gdbOutput}\n${ghidraOutput}`).not.toMatch(
			/manual-confirm|replay diff pending|fallback=portable/i,
		);
	});
});
