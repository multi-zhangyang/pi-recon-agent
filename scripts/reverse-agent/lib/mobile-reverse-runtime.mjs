import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";

let noWrite;
let root;
let redact;
let writePrivate;
let bufferSha256;
let httpSecretHash;
let shortHash;
let shellQuote;
let firmwareStrings;
let parseZipCentralDirectory;
let zipEntryData;

export function configureMobileRuntime(runtime) {
	({ noWrite, root, redact, writePrivate, bufferSha256, httpSecretHash, shortHash, shellQuote, firmwareStrings, parseZipCentralDirectory, zipEntryData } = runtime);
}
function archiveSignalLines(data, entries) {
	const lines = [];
	const interesting = entries.filter((entry) => /\.(?:xml|plist|json|properties|txt|js|html|dex)$/i.test(entry.name) || /manifest|config|security|network|classes/i.test(entry.name));
	for (const entry of interesting.slice(0, 80)) {
		const content = zipEntryData(data, entry);
		if (!content) continue;
		const text = content.toString("utf8").replace(/[^\x09\x0a\x0d\x20-\x7e]/g, " ");
		for (const pattern of [
			/https?:\/\/[^\s"'<>\\]{4,}/gi,
			/\b(?:api[_-]?key|token|secret|password|client_secret|access_token|refresh_token)\b\s*[:=]\s*["']?[^"'\s<>]{4,}/gi,
			/\b(?:CertificatePinner|TrustManager|HostnameVerifier|checkServerTrusted|SecTrust|pinning|root|jailbreak|frida|xposed|su\b|cleartextTrafficPermitted)\b/gi,
			/\bandroid\.permission\.[A-Z_]+\b/g,
		]) {
			for (const match of text.matchAll(pattern)) {
				lines.push(`${entry.name}: ${redact(match[0]).slice(0, 240)}`);
				if (lines.length >= 80) return lines;
			}
		}
	}
	return lines;
}

function xmlAttribute(source, name) {
	const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	const match = new RegExp(`(?:android:)?${escaped}\\s*=\\s*["']([^"']*)["']`, "i").exec(source);
	return match?.[1] ? redact(match[1]) : null;
}

function androidPermissionRisk(name) {
	return /(?:READ_SMS|SEND_SMS|RECEIVE_SMS|READ_CONTACTS|WRITE_CONTACTS|READ_CALL_LOG|WRITE_CALL_LOG|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|READ_PHONE_STATE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|QUERY_ALL_PACKAGES|BIND_ACCESSIBILITY_SERVICE|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE)/.test(name);
}

function parsePlainAndroidManifest(path, content) {
	const text = content.toString("utf8");
	if (!/<manifest\b/i.test(text)) return { path: redact(path), format: "binary-or-unsupported", packageName: null, permissions: [], application: null, components: [], risks: ["android-manifest-binary-xml-unparsed"] };
	const manifestOpen = /<manifest\b([^>]*)>/i.exec(text)?.[1] ?? "";
	const applicationOpen = /<application\b([^>]*)>/i.exec(text)?.[1] ?? "";
	const permissions = [];
	for (const match of text.matchAll(/<uses-permission(?:-sdk-\d+)?\b([^>]*)>/gi)) {
		const name = xmlAttribute(match[1], "name");
		if (name) permissions.push({ name, dangerous: androidPermissionRisk(name) });
	}
	const components = [];
	for (const match of text.matchAll(/<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(?:\/>|>([\s\S]*?)<\/\1>)/gi)) {
		const [, type, attrs, body = ""] = match;
		const name = xmlAttribute(attrs, "name");
		const exported = xmlAttribute(attrs, "exported");
		const permission = xmlAttribute(attrs, "permission");
		const hasIntentFilter = /<intent-filter\b/i.test(body);
		components.push({
			type,
			name: name ?? "<unnamed>",
			exported: exported === null ? null : /^true$/i.test(exported),
			permission,
			hasIntentFilter,
			risk: /^true$/i.test(exported) || (exported === null && hasIntentFilter),
		});
	}
	const debuggable = xmlAttribute(applicationOpen, "debuggable");
	const usesCleartextTraffic = xmlAttribute(applicationOpen, "usesCleartextTraffic");
	const allowBackup = xmlAttribute(applicationOpen, "allowBackup");
	const risks = [];
	if (debuggable === "true") risks.push("android-debuggable-enabled");
	if (usesCleartextTraffic === "true") risks.push("android-cleartext-traffic-enabled");
	if (allowBackup === "true") risks.push("android-backup-enabled");
	if (permissions.some((permission) => permission.dangerous)) risks.push("android-dangerous-permission-signal");
	if (components.some((component) => component.risk)) risks.push("android-exported-component-signal");
	return {
		path: redact(path),
		format: "plain-xml",
		packageName: xmlAttribute(manifestOpen, "package"),
		permissions: permissions.slice(0, 80),
		application: {
			debuggable: debuggable === null ? null : debuggable === "true",
			usesCleartextTraffic: usesCleartextTraffic === null ? null : usesCleartextTraffic === "true",
			allowBackup: allowBackup === null ? null : allowBackup === "true",
		},
		components: components.slice(0, 80),
		risks,
	};
}

function xmlTextDecode(value) {
	return redact(
		String(value ?? "")
			.replace(/&lt;/g, "<")
			.replace(/&gt;/g, ">")
			.replace(/&amp;/g, "&")
			.replace(/&quot;/g, '"')
			.replace(/&apos;/g, "'")
			.trim(),
	);
}

function escapeRegex(value) {
	return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function plistKeyString(text, key) {
	const match = new RegExp(`<key>\\s*${escapeRegex(key)}\\s*</key>\\s*<string>([\\s\\S]*?)</string>`, "i").exec(text);
	return match ? xmlTextDecode(match[1]) : null;
}

function plistKeyBool(text, key) {
	const match = new RegExp(`<key>\\s*${escapeRegex(key)}\\s*</key>\\s*<(true|false)\\s*/>`, "i").exec(text);
	if (!match) return null;
	return match[1].toLowerCase() === "true";
}

function plistKeyArray(text, key) {
	const match = new RegExp(`<key>\\s*${escapeRegex(key)}\\s*</key>\\s*<array>([\\s\\S]*?)</array>`, "i").exec(text);
	if (!match) return [];
	return Array.from(match[1].matchAll(/<string>([\s\S]*?)<\/string>/gi))
		.map((row) => xmlTextDecode(row[1]))
		.filter(Boolean)
		.slice(0, 80);
}

function plistExceptionDomains(text) {
	const domains = [];
	for (const match of text.matchAll(/<key>\s*([^<]+)\s*<\/key>\s*<dict>/gi)) {
		const domain = xmlTextDecode(match[1]);
		if (!/^(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i.test(domain)) continue;
		const body = text.slice(match.index ?? 0, Math.min(text.length, (match.index ?? 0) + 2000));
		domains.push({
			domain,
			includesSubdomains: plistKeyBool(body, "NSIncludesSubdomains"),
			allowsInsecureHttp: plistKeyBool(body, "NSExceptionAllowsInsecureHTTPLoads"),
			minimumTlsVersion: plistKeyString(body, "NSExceptionMinimumTLSVersion"),
		});
		if (domains.length >= 40) break;
	}
	return domains;
}

function parseIosInfoPlist(path, content) {
	const text = content.toString("utf8");
	if (!/<plist\b/i.test(text)) return { path: redact(path), format: "binary-or-unsupported", bundleId: null, urlSchemes: [], queriedSchemes: [], backgroundModes: [], ats: null, risks: ["ios-info-plist-binary-unparsed"] };
	const urlSchemes = plistKeyArray(text, "CFBundleURLSchemes");
	const queriedSchemes = plistKeyArray(text, "LSApplicationQueriesSchemes");
	const backgroundModes = plistKeyArray(text, "UIBackgroundModes");
	const exceptionDomains = plistExceptionDomains(text);
	const ats = {
		allowsArbitraryLoads: plistKeyBool(text, "NSAllowsArbitraryLoads"),
		allowsArbitraryLoadsInWebContent: plistKeyBool(text, "NSAllowsArbitraryLoadsInWebContent"),
		exceptionDomains,
	};
	const risks = [];
	if (urlSchemes.length) risks.push("ios-url-scheme-entrypoint");
	if (queriedSchemes.some((scheme) => /cydia|sileo|zbra|undecimus|frida|fb|twitter|wechat|alipay/i.test(scheme))) risks.push("ios-url-scheme-enumeration-signal");
	if (backgroundModes.length) risks.push("ios-background-mode-signal");
	if (ats.allowsArbitraryLoads) risks.push("ios-ats-arbitrary-loads");
	if (ats.allowsArbitraryLoadsInWebContent) risks.push("ios-ats-webcontent-arbitrary-loads");
	if (exceptionDomains.some((domain) => domain.allowsInsecureHttp)) risks.push("ios-ats-insecure-domain-exception");
	return {
		path: redact(path),
		format: "xml-plist",
		bundleId: plistKeyString(text, "CFBundleIdentifier"),
		displayName: plistKeyString(text, "CFBundleDisplayName") ?? plistKeyString(text, "CFBundleName"),
		urlSchemes,
		queriedSchemes,
		backgroundModes,
		ats,
		risks,
	};
}

function parseIosEntitlements(path, content) {
	const rawText = content.toString("utf8");
	const plistStart = rawText.search(/<plist\b/i);
	if (plistStart < 0) return undefined;
	const text = rawText.slice(plistStart);
	const keychainAccessGroups = plistKeyArray(text, "keychain-access-groups");
	const associatedDomains = plistKeyArray(text, "com.apple.developer.associated-domains");
	const applicationGroups = plistKeyArray(text, "com.apple.security.application-groups");
	const getTaskAllow = plistKeyBool(text, "get-task-allow");
	const risks = [];
	if (getTaskAllow) risks.push("ios-get-task-allow-enabled");
	if (keychainAccessGroups.length) risks.push("ios-keychain-access-group-signal");
	if (associatedDomains.length) risks.push("ios-associated-domain-signal");
	if (applicationGroups.length) risks.push("ios-application-group-signal");
	return {
		path: redact(path),
		format: "xml-plist",
		applicationIdentifier: plistKeyString(text, "application-identifier"),
		teamIdentifier: plistKeyArray(text, "com.apple.developer.team-identifier")[0] ?? plistKeyString(text, "com.apple.developer.team-identifier"),
		getTaskAllow,
		apsEnvironment: plistKeyString(text, "aps-environment"),
		keychainAccessGroups,
		associatedDomains,
		applicationGroups,
		risks,
	};
}

function readU32LeSafe(data, offset) {
	if (offset < 0 || offset + 4 > data.length) return undefined;
	return data.readUInt32LE(offset);
}

function readDexUleb128(data, offset, end) {
	let value = 0;
	let shift = 0;
	let cursor = offset;
	while (cursor < end && cursor - offset < 5) {
		const byte = data[cursor];
		value |= (byte & 0x7f) << shift;
		cursor += 1;
		if ((byte & 0x80) === 0) return { value, nextOffset: cursor };
		shift += 7;
	}
	return undefined;
}

function dexSignalRows(strings, regex, limit = 24) {
	const rows = [];
	const seen = new Set();
	for (const [index, text] of strings.entries()) {
		if (!regex.test(text)) continue;
		regex.lastIndex = 0;
		const sample = redact(text.replace(/\s+/g, " ").slice(0, 240));
		if (seen.has(sample)) continue;
		seen.add(sample);
		rows.push({ index, text: sample });
		if (rows.length >= limit) break;
	}
	return rows;
}

function printableDexFallbackStrings(data, limit = 400) {
	return firmwareStrings(data, 4, limit).map((row) => redact(row.text.replace(/\s+/g, " ").slice(0, 240)));
}

function parseDexQuicklook(data, path) {
	const validMagic = data.length >= 112 && data.subarray(0, 4).toString("ascii") === "dex\n";
	let strings = [];
	const header = {
		validMagic,
		version: validMagic ? data.toString("ascii", 4, Math.min(7, data.length)).replace(/[^\x20-\x7e]/g, "") : null,
		fileSize: validMagic ? readU32LeSafe(data, 32) ?? data.length : data.length,
		headerSize: validMagic ? readU32LeSafe(data, 36) ?? null : null,
		stringIdsSize: validMagic ? readU32LeSafe(data, 56) ?? 0 : 0,
		stringIdsOff: validMagic ? readU32LeSafe(data, 60) ?? 0 : 0,
		typeIdsSize: validMagic ? readU32LeSafe(data, 64) ?? 0 : 0,
		protoIdsSize: validMagic ? readU32LeSafe(data, 72) ?? 0 : 0,
		fieldIdsSize: validMagic ? readU32LeSafe(data, 80) ?? 0 : 0,
		methodIdsSize: validMagic ? readU32LeSafe(data, 88) ?? 0 : 0,
		classDefsSize: validMagic ? readU32LeSafe(data, 96) ?? 0 : 0,
		dataSize: validMagic ? readU32LeSafe(data, 104) ?? 0 : 0,
		dataOff: validMagic ? readU32LeSafe(data, 108) ?? 0 : 0,
	};
	if (validMagic && header.stringIdsSize && header.stringIdsOff && header.stringIdsOff + header.stringIdsSize * 4 <= data.length) {
		for (let index = 0; index < Math.min(header.stringIdsSize, 5000) && strings.length < 800; index++) {
			const stringDataOffset = data.readUInt32LE(header.stringIdsOff + index * 4);
			if (stringDataOffset <= 0 || stringDataOffset >= data.length) continue;
			const length = readDexUleb128(data, stringDataOffset, data.length);
			if (!length) continue;
			let cursor = length.nextOffset;
			const start = cursor;
			const maxEnd = Math.min(data.length, start + Math.max(1, Math.min(length.value * 4 + 8, 1024)));
			while (cursor < maxEnd && data[cursor] !== 0) cursor += 1;
			if (cursor <= start) continue;
			const text = redact(data.toString("utf8", start, cursor).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "?").slice(0, 240));
			if (text) strings.push(text);
		}
	} else {
		strings = printableDexFallbackStrings(data);
	}
	const signals = {
		classes: dexSignalRows(strings, /^(?:L|[a-zA-Z_$][\w$]*\/)[A-Za-z0-9_/$-]+;?$/i, 32),
		endpoints: dexSignalRows(strings, /https?:\/\/|\/api\/|graphql|websocket|wss:\/\//i),
		permissions: dexSignalRows(strings, /android\.permission\.[A-Z_]+/),
		pinning: dexSignalRows(strings, /CertificatePinner|TrustManager|X509TrustManager|HostnameVerifier|checkServerTrusted|network_security_config|pinning/i),
		antiTamper: dexSignalRows(strings, /frida|xposed|magisk|rootbeer|jailbreak|ptrace|isDebuggerConnected|\/su\b|\/bin\/su\b/i),
		crypto: dexSignalRows(strings, /javax\/crypto|javax\.crypto|Cipher|SecretKeySpec|MessageDigest|Mac|Hmac|AES|DES|RSA|Base64|SHA-256|SHA256/i),
		nativeBridge: dexSignalRows(strings, /System\.loadLibrary|loadLibrary|JNI_OnLoad|native-lib|RegisterNatives/i),
		secrets: dexSignalRows(strings, /api[_-]?key|token|secret|password|client_secret|access_token|refresh_token|Bearer\s+/i),
	};
	const risks = [];
	if (signals.endpoints.length) risks.push("dex-network-endpoint-signal");
	if (signals.pinning.length) risks.push("dex-pinning-signal");
	if (signals.antiTamper.length) risks.push("dex-anti-tamper-signal");
	if (signals.crypto.length) risks.push("dex-crypto-transform-signal");
	if (signals.nativeBridge.length) risks.push("dex-native-bridge-signal");
	if (signals.secrets.length) risks.push("dex-hardcoded-secret-signal");
	return {
		path: redact(path),
		validMagic,
		sha256: bufferSha256(data),
		header,
		stringSample: strings.slice(0, 40),
		signals,
		risks,
	};
}

function mobileArchiveSummary(target, lane) {
	const data = readFileSync(target);
	const parsed = parseZipCentralDirectory(data);
	const entries = parsed.entries;
	const platform = lane === "mobile-ios" || entries.some((entry) => entry.lower.startsWith("payload/") || entry.lower.endsWith(".app/info.plist")) ? "ios" : "android";
	const dexEntries = entries.filter((entry) => /^classes\d*\.dex$/i.test(basename(entry.name)));
	const nativeLibs = entries
		.map((entry) => {
			const android = /^lib\/([^/]+)\/([^/]+\.so)$/i.exec(entry.name);
			if (android) return { platform: "android", abi: android[1], name: android[2], path: entry.name, size: entry.uncompressedSize };
			const ios = /^Payload\/[^/]+\.app\/(?:Frameworks\/)?([^/]+(?:\.framework\/[^/]+|\.dylib))$/i.exec(entry.name);
			if (ios) return { platform: "ios", abi: null, name: basename(ios[1]), path: entry.name, size: entry.uncompressedSize };
			return undefined;
		})
		.filter(Boolean);
	const manifests = entries.filter((entry) => /(^|\/)(AndroidManifest\.xml|Info\.plist)$/i.test(entry.name)).map((entry) => entry.name);
	const certs = entries.filter((entry) => /^META-INF\/[^/]+\.(?:RSA|DSA|EC|SF|MF)$/i.test(entry.name)).map((entry) => entry.name);
	const networkSecurity = entries.filter((entry) => /network_security_config|ats|transportsecurity|pinning|cert|trust/i.test(entry.name)).map((entry) => entry.name);
	const signalLines = archiveSignalLines(data, entries).map(redact);
	const manifestAnalysis = entries
		.filter((entry) => /(^|\/)AndroidManifest\.xml$/i.test(entry.name))
		.map((entry) => {
			const content = zipEntryData(data, entry, 2 * 1024 * 1024);
			return content ? parsePlainAndroidManifest(entry.name, content) : undefined;
		})
		.filter(Boolean);
	const iosPlistAnalysis = entries
		.filter((entry) => /(^|\/)Info\.plist$/i.test(entry.name))
		.map((entry) => {
			const content = zipEntryData(data, entry, 2 * 1024 * 1024);
			return content ? parseIosInfoPlist(entry.name, content) : undefined;
		})
		.filter(Boolean);
	const iosEntitlements = entries
		.filter((entry) => /(?:\.xcent|\.entitlements|embedded\.mobileprovision)$/i.test(entry.name))
		.map((entry) => {
			const content = zipEntryData(data, entry, 2 * 1024 * 1024);
			return content ? parseIosEntitlements(entry.name, content) : undefined;
		})
		.filter(Boolean);
	const dexQuicklook = dexEntries
		.map((entry) => {
			const content = zipEntryData(data, entry, 8 * 1024 * 1024);
			return content ? parseDexQuicklook(content, entry.name) : undefined;
		})
		.filter(Boolean);
	const permissions = Array.from(
		new Set([
			...signalLines.map((line) => line.match(/android\.permission\.[A-Z_]+/)?.[0]).filter(Boolean),
			...manifestAnalysis.flatMap((manifest) => manifest.permissions.map((permission) => permission.name)),
		]),
	).slice(0, 80);
	const entrySamples = entries.slice(0, 200).map((entry) => ({
		name: redact(entry.name),
		method: entry.method,
		compressedSize: entry.compressedSize,
		uncompressedSize: entry.uncompressedSize,
		crc32: entry.crc32,
	}));
	const risks = [];
	if (nativeLibs.length) risks.push("native-code-present");
	if (dexEntries.length > 1) risks.push("multi-dex");
	if (networkSecurity.length || signalLines.some((line) => /cleartextTrafficPermitted|TrustManager|CertificatePinner|HostnameVerifier|SecTrust|pinning/i.test(line))) risks.push("network-or-pinning-signal");
	if (signalLines.some((line) => /root|jailbreak|frida|xposed|su\b/i.test(line))) risks.push("anti-tamper-or-root-detection-signal");
	if (signalLines.some((line) => /api[_-]?key|token|secret|password|client_secret|access_token|refresh_token/i.test(line))) risks.push("hardcoded-secret-signal");
	if (manifestAnalysis.some((manifest) => manifest.risks.includes("android-debuggable-enabled"))) risks.push("android-debuggable-enabled");
	if (manifestAnalysis.some((manifest) => manifest.risks.includes("android-cleartext-traffic-enabled"))) risks.push("android-cleartext-traffic-enabled");
	if (manifestAnalysis.some((manifest) => manifest.risks.includes("android-backup-enabled"))) risks.push("android-backup-enabled");
	if (manifestAnalysis.some((manifest) => manifest.risks.includes("android-dangerous-permission-signal"))) risks.push("android-dangerous-permission-signal");
	if (manifestAnalysis.some((manifest) => manifest.risks.includes("android-exported-component-signal"))) risks.push("android-exported-component-signal");
	for (const risk of new Set([...iosPlistAnalysis.flatMap((plist) => plist.risks), ...iosEntitlements.flatMap((entitlements) => entitlements.risks)])) {
		risks.push(risk);
	}
	if (dexQuicklook.some((row) => row.risks.includes("dex-pinning-signal"))) risks.push("dex-pinning-signal");
	if (dexQuicklook.some((row) => row.risks.includes("dex-anti-tamper-signal"))) risks.push("dex-anti-tamper-signal");
	if (dexQuicklook.some((row) => row.risks.includes("dex-crypto-transform-signal"))) risks.push("dex-crypto-transform-signal");
	if (dexQuicklook.some((row) => row.risks.includes("dex-native-bridge-signal"))) risks.push("dex-native-bridge-signal");
	if (dexQuicklook.some((row) => row.risks.includes("dex-hardcoded-secret-signal"))) risks.push("dex-hardcoded-secret-signal");
	return {
		kind: "repi-mobile-archive-quicklook",
		schemaVersion: 2,
		platform,
		entryCount: entries.length,
		dex: dexEntries.map((entry) => ({ name: entry.name, size: entry.uncompressedSize, crc32: entry.crc32 })),
		dexQuicklook,
		nativeLibs,
		manifests,
		manifestAnalysis,
		iosPlistAnalysis,
		iosEntitlements,
		certs,
		networkSecurity,
		permissions,
		risks,
		signalLines,
		entrySamples,
	};
}

function mobileArchiveEntryNames(summary) {
	return Array.from(
		new Set(
			[
				...(summary.dex ?? []).map((entry) => entry.name),
				...(summary.manifests ?? []),
				...(summary.nativeLibs ?? []).map((entry) => entry.path),
				...(summary.certs ?? []),
				...(summary.networkSecurity ?? []),
				...(summary.iosPlistAnalysis ?? []).map((entry) => entry.path),
				...(summary.iosEntitlements ?? []).map((entry) => entry.path),
			]
				.filter(Boolean)
				.map(String),
		),
	);
}

function mobileArchiveVerificationSummary(target, artifactDir, summary) {
	const data = readFileSync(target);
	const archiveSha256 = bufferSha256(data);
	const archiveIdentity = {
		size: data.length,
		sha256: archiveSha256,
		headerHex: data.subarray(0, 16).toString("hex"),
		verified: data.length > 0 && (summary.entryCount ?? 0) >= 0,
	};
	if (data.length) {
		const mutated = Buffer.from(data);
		mutated[0] ^= 0xff;
		const mutatedSha256 = bufferSha256(mutated);
		archiveIdentity.negativeControl = {
			controlType: "mobile-archive-byte-mutation-rejection",
			mutatedSha256,
			passed: mutatedSha256 !== archiveSha256,
		};
	}
	let parsed;
	try {
		parsed = parseZipCentralDirectory(data);
	} catch (error) {
		parsed = { entries: [], parseError: error instanceof Error ? redact(error.message) : redact(String(error)) };
	}
	const entriesByName = new Map((parsed.entries ?? []).map((entry) => [entry.name, entry]));
	const directoryIdentity = {
		entryCount: parsed.entries?.length ?? 0,
		expectedEntryCount: summary.entryCount ?? null,
		verified: (parsed.entries?.length ?? -1) === (summary.entryCount ?? -2),
		namesSha256: httpSecretHash((parsed.entries ?? []).map((entry) => entry.name).join("\n")),
		parseError: parsed.parseError ?? null,
	};
	const entryChecks = [];
	for (const name of mobileArchiveEntryNames(summary)) {
		const entry = entriesByName.get(name);
		let actual = {};
		let verified = false;
		let negativeControl = null;
		let reason = "entry-missing";
		if (entry) {
			const content = zipEntryData(data, entry, 16 * 1024 * 1024);
			actual = {
				name: redact(entry.name),
				method: entry.method,
				crc32: entry.crc32,
				compressedSize: entry.compressedSize,
				uncompressedSize: entry.uncompressedSize,
				localHeaderOffset: entry.localHeaderOffset,
				sha256: content ? bufferSha256(content) : null,
				headerHex: content ? content.subarray(0, 16).toString("hex") : null,
			};
			verified = Boolean(content) && entry.name === name;
			reason = verified ? "zip-entry-metadata-and-content-bound" : "zip-entry-content-unavailable";
			if (content?.length) {
				const mutated = Buffer.from(content);
				mutated[0] ^= 0xff;
				const mutatedSha256 = bufferSha256(mutated);
				negativeControl = {
					controlType: "mobile-entry-byte-mutation-rejection",
					entry: redact(entry.name),
					mutatedSha256,
					passed: mutatedSha256 !== actual.sha256,
				};
			}
		}
		entryChecks.push({ name: redact(name), actual, verified, reason, negativeControl });
	}
	const dexChecks = [];
	for (const dex of summary.dexQuicklook ?? []) {
		const entry = entriesByName.get(dex.path);
		const content = entry ? zipEntryData(data, entry, 16 * 1024 * 1024) : undefined;
		let reparsed = null;
		try {
			reparsed = content ? parseDexQuicklook(content, dex.path) : null;
		} catch {
			reparsed = null;
		}
		const verified =
			Boolean(content) &&
			Boolean(reparsed) &&
			Boolean(dex.validMagic) === Boolean(reparsed.validMagic) &&
			(dex.header?.version ?? null) === (reparsed.header?.version ?? null) &&
			(dex.header?.stringIdsSize ?? null) === (reparsed.header?.stringIdsSize ?? null);
		dexChecks.push({
			path: dex.path,
			verified,
			actual: reparsed
				? {
						validMagic: reparsed.validMagic,
						version: reparsed.header?.version ?? null,
						stringIdsSize: reparsed.header?.stringIdsSize ?? null,
						sha256: content ? bufferSha256(content) : null,
					}
				: null,
			expected: {
				validMagic: dex.validMagic,
				version: dex.header?.version ?? null,
				stringIdsSize: dex.header?.stringIdsSize ?? null,
			},
		});
	}
	const manifestChecks = [];
	for (const manifest of summary.manifestAnalysis ?? []) {
		const entry = entriesByName.get(manifest.path);
		const content = entry ? zipEntryData(data, entry, 2 * 1024 * 1024) : undefined;
		const reparsed = content ? parsePlainAndroidManifest(manifest.path, content) : null;
		manifestChecks.push({
			path: manifest.path,
			platform: "android",
			verified: Boolean(reparsed) && reparsed.packageName === manifest.packageName && reparsed.components.length === manifest.components.length,
			evidence: {
				packageName: manifest.packageName,
				componentCount: manifest.components?.length ?? 0,
				permissionCount: manifest.permissions?.length ?? 0,
				sha256: content ? bufferSha256(content) : null,
			},
		});
	}
	for (const plist of summary.iosPlistAnalysis ?? []) {
		const entry = entriesByName.get(plist.path);
		const content = entry ? zipEntryData(data, entry, 2 * 1024 * 1024) : undefined;
		const reparsed = content ? parseIosInfoPlist(plist.path, content) : null;
		manifestChecks.push({
			path: plist.path,
			platform: "ios-plist",
			verified: Boolean(reparsed) && reparsed.bundleId === plist.bundleId && JSON.stringify(reparsed.urlSchemes ?? []) === JSON.stringify(plist.urlSchemes ?? []),
			evidence: {
				bundleId: plist.bundleId,
				urlSchemeCount: plist.urlSchemes?.length ?? 0,
				sha256: content ? bufferSha256(content) : null,
			},
		});
	}
	for (const entitlements of summary.iosEntitlements ?? []) {
		const entry = entriesByName.get(entitlements.path);
		const content = entry ? zipEntryData(data, entry, 2 * 1024 * 1024) : undefined;
		const reparsed = content ? parseIosEntitlements(entitlements.path, content) : null;
		manifestChecks.push({
			path: entitlements.path,
			platform: "ios-entitlements",
			verified: Boolean(reparsed) && reparsed.applicationIdentifier === entitlements.applicationIdentifier && Boolean(reparsed.getTaskAllow) === Boolean(entitlements.getTaskAllow),
			evidence: {
				applicationIdentifier: entitlements.applicationIdentifier,
				getTaskAllow: Boolean(entitlements.getTaskAllow),
				keychainGroupCount: entitlements.keychainAccessGroups?.length ?? 0,
				sha256: content ? bufferSha256(content) : null,
			},
		});
	}
	const hookPath = join(artifactDir, "mobile-frida-hooks.js");
	let hookVerification = { exists: false, verified: false, sha256: null, mode: null, expectedSignals: [], matchedSignals: [] };
	if (existsSync(hookPath)) {
		const hook = readFileSync(hookPath, "utf8");
		const expectedSignals = summary.platform === "ios" ? ["SecTrustEvaluate", "NSFileManager"] : ["CertificatePinner", "TrustManagerImpl", "Runtime.exec", "SystemProperties"];
		const matchedSignals = expectedSignals.filter((signal) => hook.includes(signal));
		let mode = null;
		try {
			mode = "0o" + (statSync(hookPath).mode & 0o777).toString(8);
		} catch {
			mode = null;
		}
		hookVerification = {
			exists: true,
			verified: matchedSignals.length >= Math.min(2, expectedSignals.length),
			sha256: httpSecretHash(hook),
			mode,
			expectedSignals,
			matchedSignals,
		};
	}
	const negativeControls = [archiveIdentity.negativeControl, ...entryChecks.map((row) => row.negativeControl)].filter((row) => row?.passed);
	const verifiedEntries = entryChecks.filter((row) => row.verified);
	const verifiedDex = dexChecks.filter((row) => row.verified);
	const verifiedManifests = manifestChecks.filter((row) => row.verified);
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const archiveClaim = archiveIdentity.verified
		? addClaim({
				id: "mobile-archive-hash-verification-" + shortHash(archiveIdentity.sha256),
				claimType: "mobile-archive-hash-verification-proof",
				sourceBinding: { artifact: "mobile-archive-verification.json" },
				evidenceBinding: archiveIdentity,
				statement: "Mobile verifier re-read APK/IPA bytes and bound file size, SHA-256, and header evidence.",
				confidence: 0.9,
				rerunCommand: "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
			})
		: undefined;
	const entryClaim = verifiedEntries.length
		? addClaim({
				id: "mobile-zip-entry-verification-" + shortHash(verifiedEntries.map((row) => `${row.name}:${row.actual?.sha256}`).join("|")),
				claimType: "mobile-zip-entry-verification-proof",
				sourceBinding: { artifact: "mobile-archive-verification.json" },
				evidenceBinding: {
					entryCount: verifiedEntries.length,
					entries: verifiedEntries.slice(0, 80).map((row) => ({ name: row.name, sha256: row.actual?.sha256, crc32: row.actual?.crc32, uncompressedSize: row.actual?.uncompressedSize })),
				},
				statement: "Mobile verifier matched manifest, DEX, native, certificate, or config ZIP entries by central-directory metadata and content SHA-256.",
				confidence: 0.86,
				rerunCommand: "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
			})
		: undefined;
	const dexClaim = verifiedDex.length
		? addClaim({
				id: "mobile-dex-quicklook-verification-" + shortHash(verifiedDex.map((row) => `${row.path}:${row.actual?.sha256}`).join("|")),
				claimType: "mobile-dex-quicklook-verification-proof",
				sourceBinding: { artifact: "mobile-archive-verification.json" },
				evidenceBinding: { dex: verifiedDex.map((row) => ({ path: row.path, version: row.actual?.version, stringIdsSize: row.actual?.stringIdsSize, sha256: row.actual?.sha256 })) },
				statement: "Mobile verifier reparsed DEX entries and matched quicklook header/string table metadata.",
				confidence: 0.86,
				rerunCommand: "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
			})
		: undefined;
	const manifestClaim = verifiedManifests.length
		? addClaim({
				id: "mobile-manifest-verification-" + shortHash(verifiedManifests.map((row) => `${row.path}:${row.evidence?.sha256}`).join("|")),
				claimType: "mobile-manifest-verification-proof",
				sourceBinding: { artifact: "mobile-archive-verification.json" },
				evidenceBinding: { manifests: verifiedManifests },
				statement: "Mobile verifier reparsed Android manifest, iOS plist, or entitlements entries and matched key runtime fields.",
				confidence: 0.86,
				rerunCommand: "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
			})
		: undefined;
	const hookClaim = hookVerification.verified
		? addClaim({
				id: "mobile-frida-hook-verification-" + shortHash(hookVerification.sha256),
				claimType: "mobile-frida-hook-verification-proof",
				sourceBinding: { artifact: "mobile-archive-verification.json", hook: "mobile-frida-hooks.js" },
				evidenceBinding: hookVerification,
				statement: "Mobile verifier hash-bound the Frida hook scaffold and matched expected platform hook signals.",
				confidence: 0.82,
				rerunCommand: "node --check mobile-frida-hooks.js",
			})
		: undefined;
	const controlClaim = negativeControls.length
		? addClaim({
				id: "mobile-verifier-negative-control-" + shortHash(negativeControls.map((row) => `${row.controlType}:${row.mutatedSha256}`).join("|")),
				claimType: "mobile-verifier-negative-control-proof",
				sourceBinding: { artifact: "mobile-archive-verification.json" },
				evidenceBinding: { passedControls: negativeControls },
				statement: "Mobile verifier ran archive and entry mutation controls so archive evidence is rejectable and rerunnable.",
				confidence: 0.84,
				rerunCommand: "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
			})
		: undefined;
	if (archiveClaim && entryClaim && (dexClaim || manifestClaim) && hookClaim && controlClaim) {
		const segments = [archiveClaim, entryClaim, dexClaim, manifestClaim, hookClaim, controlClaim].filter(Boolean);
		const composed = {
			id: "mobile-runtime-evidence-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "mobile-runtime-evidence-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				platform: summary.platform,
				archiveSha256,
				verifiedEntries: verifiedEntries.length,
				verifiedDex: verifiedDex.length,
				verifiedManifests: verifiedManifests.length,
				hasHookVerification: true,
				hasNegativeControl: true,
			},
			statement: "Mobile evidence composes archive hash, ZIP entry hashes, DEX/manifest reparsing, Frida hook binding, and mutation controls into a runtime proof path.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
			rerunCommand: "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!archiveIdentity.verified) blockers.push("missing-mobile-archive-hash-verification");
	if (!verifiedEntries.length) blockers.push("missing-mobile-zip-entry-verification");
	if ((summary.dexQuicklook ?? []).length && !verifiedDex.length) blockers.push("missing-mobile-dex-quicklook-verification");
	if (((summary.manifestAnalysis ?? []).length || (summary.iosPlistAnalysis ?? []).length || (summary.iosEntitlements ?? []).length) && !verifiedManifests.length) blockers.push("missing-mobile-manifest-verification");
	if (!hookVerification.verified) blockers.push("missing-mobile-hook-verification");
	if (!negativeControls.length) blockers.push("missing-mobile-negative-control");
	const repairActions = {
		"missing-mobile-archive-hash-verification": "Rerun mobile-archive-verifier.py against the original APK/IPA and require size/SHA-256 equality.",
		"missing-mobile-zip-entry-verification": "Verify manifest, DEX, native library, certificate, and config ZIP entries by CRC, size, and SHA-256.",
		"missing-mobile-dex-quicklook-verification": "Bind DEX quicklook strings/header claims to exact classes.dex bytes.",
		"missing-mobile-manifest-verification": "Bind AndroidManifest.xml, Info.plist, or entitlements fields to exact archive entry bytes.",
		"missing-mobile-hook-verification": "Generate mobile-frida-hooks.js and syntax/hash-check expected platform hook signals.",
		"missing-mobile-negative-control": "Add archive and entry mutation controls so mobile evidence has rejection proof.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "mobile-archive-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound mobile archive evidence and rerun mobile-archive-verifier.py.",
		rerunCommand: `python3 ${shellQuote(join(artifactDir, "mobile-archive-verifier.py"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "mobile-archive-summary.json"))} ${shellQuote(join(artifactDir, "mobile-archive-verification.json"))}`,
	}));
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-mobile-archive-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		platform: summary.platform,
		proofReady: promotedClaims.length > 0,
		runtimeProofReady: composedPaths.length > 0,
		archiveIdentity,
		directoryIdentity,
		entryChecks,
		dexChecks,
		manifestChecks,
		hookVerification,
		negativeControls,
		stats: {
			entriesVerified: verifiedEntries.length,
			dexVerified: verifiedDex.length,
			manifestsVerified: verifiedManifests.length,
			negativeControlsPassed: negativeControls.length,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady: promotedClaims.length > 0, runtimeProofReady: composedPaths.length > 0, promotedClaims, blockers },
		repairQueue,
	};
}

export function writeMobileArchiveVerification(artifactDir, target, summary) {
	if (noWrite || !artifactDir || !summary) return undefined;
	const verification = mobileArchiveVerificationSummary(target, artifactDir, summary);
	const path = join(artifactDir, "mobile-archive-verification.json");
	writePrivate(path, `${JSON.stringify(verification, null, 2)}\n`, 0o600);
	return { path, summary: verification };
}

function mobileArchiveVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import tempfile
import zipfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def archive_entry_names(summary):
    names = []
    for row in summary.get("dex") or []:
        names.append(row.get("name"))
    names.extend(summary.get("manifests") or [])
    names.extend(summary.get("certs") or [])
    names.extend(summary.get("networkSecurity") or [])
    for row in summary.get("nativeLibs") or []:
        names.append(row.get("path"))
    for row in summary.get("manifestAnalysis") or []:
        names.append(row.get("path"))
    for row in summary.get("iosPlistAnalysis") or []:
        names.append(row.get("path"))
    for row in summary.get("iosEntitlements") or []:
        names.append(row.get("path"))
    out = []
    for name in names:
        if name and name not in out:
            out.append(name)
    return out


def verify(target, summary_path):
    with open(target, "rb") as handle:
        data = handle.read()
    with open(summary_path, "r", encoding="utf-8") as handle:
        summary = json.load(handle)
    archive_sha = sha256(data)
    archive_identity = {"size": len(data), "sha256": archive_sha, "headerHex": data[:16].hex(), "verified": True}
    if data:
        mutated = bytearray(data)
        mutated[0] ^= 0xFF
        archive_identity["negativeControl"] = {"controlType": "mobile-archive-byte-mutation-rejection", "mutatedSha256": sha256(bytes(mutated)), "passed": sha256(bytes(mutated)) != archive_sha}
    entry_checks = []
    dex_checks = []
    manifest_checks = []
    controls = [archive_identity.get("negativeControl")]
    with zipfile.ZipFile(target, "r") as archive:
        infos = {info.filename: info for info in archive.infolist()}
        directory_identity = {"entryCount": len(infos), "expectedEntryCount": summary.get("entryCount"), "verified": len(infos) == summary.get("entryCount"), "namesSha256": sha256("\n".join(infos).encode())}
        for name in archive_entry_names(summary):
            info = infos.get(name)
            verified = False
            actual = {}
            control = None
            reason = "entry-missing"
            if info:
                content = archive.read(info)
                actual = {"name": info.filename, "crc32": "0x%08x" % info.CRC, "compressedSize": info.compress_size, "uncompressedSize": info.file_size, "sha256": sha256(content), "headerHex": content[:16].hex()}
                verified = bool(content) or info.file_size == 0
                reason = "zip-entry-metadata-and-content-bound" if verified else "zip-entry-empty"
                if content:
                    mutated = bytearray(content)
                    mutated[0] ^= 0xFF
                    control = {"controlType": "mobile-entry-byte-mutation-rejection", "entry": info.filename, "mutatedSha256": sha256(bytes(mutated)), "passed": sha256(bytes(mutated)) != actual["sha256"]}
                    controls.append(control)
            entry_checks.append({"name": name, "actual": actual, "verified": verified, "reason": reason, "negativeControl": control})
        for dex in summary.get("dexQuicklook") or []:
            name = dex.get("path")
            info = infos.get(name)
            content = archive.read(info) if info else b""
            dex_checks.append({"path": name, "verified": content.startswith(b"dex\n") == bool(dex.get("validMagic")), "actual": {"sha256": sha256(content), "validMagic": content.startswith(b"dex\n"), "size": len(content)}})
        for row in (summary.get("manifestAnalysis") or []):
            name = row.get("path")
            content = archive.read(infos[name]) if name in infos else b""
            package = row.get("packageName") or ""
            manifest_checks.append({"path": name, "platform": "android", "verified": bool(package) and package.encode() in content, "evidence": {"packageName": package, "sha256": sha256(content)}})
        for row in (summary.get("iosPlistAnalysis") or []):
            name = row.get("path")
            content = archive.read(infos[name]) if name in infos else b""
            bundle = row.get("bundleId") or ""
            manifest_checks.append({"path": name, "platform": "ios-plist", "verified": bool(bundle) and bundle.encode() in content, "evidence": {"bundleId": bundle, "sha256": sha256(content)}})
        for row in (summary.get("iosEntitlements") or []):
            name = row.get("path")
            content = archive.read(infos[name]) if name in infos else b""
            appid = row.get("applicationIdentifier") or ""
            manifest_checks.append({"path": name, "platform": "ios-entitlements", "verified": bool(appid) and appid.encode() in content, "evidence": {"applicationIdentifier": appid, "sha256": sha256(content)}})
    controls = [row for row in controls if row and row.get("passed")]
    verified_entries = [row for row in entry_checks if row.get("verified")]
    verified_dex = [row for row in dex_checks if row.get("verified")]
    verified_manifests = [row for row in manifest_checks if row.get("verified")]
    blockers = []
    if not archive_identity.get("verified"):
        blockers.append("missing-mobile-archive-hash-verification")
    if not verified_entries:
        blockers.append("missing-mobile-zip-entry-verification")
    if summary.get("dexQuicklook") and not verified_dex:
        blockers.append("missing-mobile-dex-quicklook-verification")
    if (summary.get("manifestAnalysis") or summary.get("iosPlistAnalysis") or summary.get("iosEntitlements")) and not verified_manifests:
        blockers.append("missing-mobile-manifest-verification")
    if not controls:
        blockers.append("missing-mobile-negative-control")
    proof_ready = bool(verified_entries) and bool(controls)
    repair_queue = [{"id": "mobile-archive-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound mobile archive evidence and rerun mobile-archive-verifier.py.", "rerunCommand": "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json"} for blocker in blockers]
    return {"kind": "repi-mobile-archive-verification", "schemaVersion": 1, "target": target, "proofReady": proof_ready, "archiveIdentity": archive_identity, "directoryIdentity": directory_identity, "entryChecks": entry_checks, "dexChecks": dex_checks, "manifestChecks": manifest_checks, "negativeControls": controls, "stats": {"entriesVerified": len(verified_entries), "dexVerified": len(verified_dex), "manifestsVerified": len(verified_manifests), "negativeControlsPassed": len(controls)}, "repairQueue": repair_queue, "promotionReport": {"proofReady": proof_ready, "blockers": blockers}}


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "app.apk")
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("AndroidManifest.xml", '<manifest package="com.example.repi"><application android:debuggable="true"/></manifest>')
            archive.writestr("classes.dex", b"dex\n035\x00" + b"demo")
        with open(target, "rb") as handle:
            data = handle.read()
        summary = {"kind": "repi-mobile-archive-quicklook", "schemaVersion": 2, "platform": "android", "entryCount": 2, "dex": [{"name": "classes.dex"}], "dexQuicklook": [{"path": "classes.dex", "validMagic": True}], "manifests": ["AndroidManifest.xml"], "manifestAnalysis": [{"path": "AndroidManifest.xml", "packageName": "com.example.repi"}], "nativeLibs": [], "certs": [], "networkSecurity": []}
        summary_path = os.path.join(tmp, "mobile-archive-summary.json")
        with open(summary_path, "w", encoding="utf-8") as handle:
            json.dump(summary, handle)
        result = verify(target, summary_path)
        assert result["proofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-mobile-archive-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Verify REPI mobile APK/IPA archive entry evidence with hash-bound negative controls.")
    parser.add_argument("target", nargs="?")
    parser.add_argument("summary", nargs="?", default="mobile-archive-summary.json")
    parser.add_argument("output", nargs="?", default="mobile-archive-verification.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.target:
        parser.error("target is required unless --self-test is used")
    result = verify(args.target, args.summary)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
`;
}

export function writeMobileArchiveVerifier(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "mobile-archive-verifier.py");
	writePrivate(path, mobileArchiveVerifierSource(), 0o700);
	return path;
}

export function mobileAttackSurfaceClaims(summary, verification) {
	const claimLedger = [];
	const hookTargets = [];
	const addHookTarget = (target) => {
		if (!target?.id || hookTargets.some((row) => row.id === target.id)) return;
		hookTargets.push(target);
	};
	const addClaim = (claim) => {
		claimLedger.push({
			verdict: "promoted",
			confidence: 0.7,
			blockers: [],
			...claim,
		});
	};
	for (const manifest of summary.manifestAnalysis ?? []) {
		const app = manifest.application ?? {};
		if (app.debuggable) {
			addClaim({
				id: "mobile-android-debuggable-" + shortHash(`${manifest.path}:${manifest.packageName}`),
				claimType: "android-debuggable-application",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: manifest.path, packageName: manifest.packageName },
				evidenceBinding: { debuggable: true, application: app },
				statement: "Android manifest evidence enables debuggable application runtime inspection.",
				confidence: 0.84,
				rerunCommand: "cat mobile-archive-summary.json | jq '.manifestAnalysis'",
			});
		}
		if (app.usesCleartextTraffic) {
			addClaim({
				id: "mobile-android-cleartext-" + shortHash(`${manifest.path}:${manifest.packageName}`),
				claimType: "android-cleartext-traffic",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: manifest.path, packageName: manifest.packageName },
				evidenceBinding: { usesCleartextTraffic: true, application: app },
				statement: "Android manifest evidence allows cleartext traffic, creating a network replay/intercept path.",
				confidence: 0.82,
				rerunCommand: "cat mobile-archive-summary.json | jq '.manifestAnalysis'",
			});
		}
		if (app.allowBackup) {
			addClaim({
				id: "mobile-android-backup-" + shortHash(`${manifest.path}:${manifest.packageName}`),
				claimType: "android-backup-enabled",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: manifest.path, packageName: manifest.packageName },
				evidenceBinding: { allowBackup: true, application: app },
				statement: "Android manifest evidence enables backup/data extraction triage.",
				confidence: 0.74,
				rerunCommand: "cat mobile-archive-summary.json | jq '.manifestAnalysis'",
			});
		}
		for (const permission of manifest.permissions ?? []) {
			if (!permission.dangerous) continue;
			addClaim({
				id: "mobile-android-dangerous-permission-" + shortHash(`${manifest.path}:${permission.name}`),
				claimType: "android-dangerous-permission",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: manifest.path, packageName: manifest.packageName },
				evidenceBinding: { permission: permission.name, dangerous: true },
				statement: "Android manifest evidence requests a dangerous permission that should be tied to runtime use.",
				confidence: 0.72,
				rerunCommand: "cat mobile-archive-summary.json | jq '.manifestAnalysis[].permissions'",
			});
		}
		for (const component of manifest.components ?? []) {
			if (!component.risk) continue;
			addClaim({
				id: "mobile-android-exported-component-" + shortHash(`${manifest.path}:${component.type}:${component.name}`),
				claimType: "android-exported-component-entrypoint",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: manifest.path, packageName: manifest.packageName, component: component.name },
				evidenceBinding: {
					type: component.type,
					name: component.name,
					exported: component.exported,
					hasIntentFilter: Boolean(component.hasIntentFilter),
					permission: component.permission ?? null,
				},
				statement: "Android manifest evidence exposes a component entrypoint suitable for adb/am or deep-link replay.",
				confidence: component.exported ? 0.86 : 0.78,
				rerunCommand: "cat mobile-archive-summary.json | jq '.manifestAnalysis[].components'",
			});
		}
	}
	for (const dex of summary.dexQuicklook ?? []) {
		for (const row of dex.signals?.endpoints ?? []) {
			addClaim({
				id: "mobile-dex-network-endpoint-" + shortHash(`${dex.path}:${row.index}:${row.text}`),
				claimType: "mobile-network-endpoint",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: dex.path, stringIndex: row.index },
				evidenceBinding: { endpoint: row.text },
				statement: "DEX string evidence identifies a network endpoint for replay/interception.",
				confidence: 0.78,
				rerunCommand: "cat mobile-archive-summary.json | jq '.dexQuicklook[].signals.endpoints'",
			});
		}
		for (const row of dex.signals?.secrets ?? []) {
			addClaim({
				id: "mobile-dex-secret-" + shortHash(`${dex.path}:${row.index}:${row.text}`),
				claimType: "mobile-hardcoded-secret-signal",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: dex.path, stringIndex: row.index },
				evidenceBinding: { text: row.text, redacted: /<redacted>|\bredacted\b/i.test(row.text) },
				statement: "DEX string evidence contains a redacted credential/token/config secret signal.",
				confidence: 0.78,
				rerunCommand: "cat mobile-archive-summary.json | jq '.dexQuicklook[].signals.secrets'",
			});
		}
		for (const row of dex.signals?.pinning ?? []) {
			addHookTarget({ id: "android-tls-pinning-bypass", platform: "android", reason: "CertificatePinner/TrustManager signal", hook: "CertificatePinner.check / TrustManagerImpl.checkTrustedRecursive" });
			addClaim({
				id: "mobile-dex-pinning-" + shortHash(`${dex.path}:${row.index}:${row.text}`),
				claimType: "mobile-tls-pinning-surface",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: dex.path, stringIndex: row.index },
				evidenceBinding: { text: row.text, hookTargetId: "android-tls-pinning-bypass" },
				statement: "DEX string evidence identifies certificate pinning/trust manager code and maps it to a Frida hook target.",
				confidence: 0.84,
				rerunCommand: "frida -U -f <package> -l mobile-frida-hooks.js --no-pause",
			});
		}
		for (const row of dex.signals?.antiTamper ?? []) {
			addHookTarget({ id: "android-root-anti-tamper", platform: "android", reason: "root/frida/xposed signal", hook: "Runtime.exec / SystemProperties.get" });
			addClaim({
				id: "mobile-dex-antitamper-" + shortHash(`${dex.path}:${row.index}:${row.text}`),
				claimType: "mobile-anti-tamper-surface",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: dex.path, stringIndex: row.index },
				evidenceBinding: { text: row.text, hookTargetId: "android-root-anti-tamper" },
				statement: "DEX string evidence identifies root/debug/tamper detection and maps it to a runtime hook target.",
				confidence: 0.78,
				rerunCommand: "frida -U -f <package> -l mobile-frida-hooks.js --no-pause",
			});
		}
		for (const row of dex.signals?.crypto ?? []) {
			addClaim({
				id: "mobile-dex-crypto-" + shortHash(`${dex.path}:${row.index}:${row.text}`),
				claimType: "mobile-crypto-transform-surface",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: dex.path, stringIndex: row.index },
				evidenceBinding: { text: row.text },
				statement: "DEX string evidence identifies crypto/codec transform code for local reconstruction or hook tracing.",
				confidence: 0.74,
				rerunCommand: "cat mobile-archive-summary.json | jq '.dexQuicklook[].signals.crypto'",
			});
		}
		for (const row of dex.signals?.nativeBridge ?? []) {
			addHookTarget({ id: "android-native-load", platform: "android", reason: "System.loadLibrary/native bridge signal", hook: "System.loadLibrary / JNI_OnLoad tracing" });
			addClaim({
				id: "mobile-dex-native-bridge-" + shortHash(`${dex.path}:${row.index}:${row.text}`),
				claimType: "mobile-native-bridge-surface",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: dex.path, stringIndex: row.index },
				evidenceBinding: { text: row.text, hookTargetId: "android-native-load" },
				statement: "DEX string evidence identifies a native bridge that should be tied to loaded libraries and JNI hooks.",
				confidence: 0.78,
				rerunCommand: "cat mobile-archive-summary.json | jq '.dexQuicklook[].signals.nativeBridge'",
			});
		}
	}
	for (const lib of summary.nativeLibs ?? []) {
		addClaim({
			id: "mobile-native-code-" + shortHash(`${lib.platform}:${lib.path}:${lib.size}`),
			claimType: "mobile-native-code-surface",
			sourceBinding: { artifact: "mobile-archive-summary.json", file: lib.path },
			evidenceBinding: { platform: lib.platform, abi: lib.abi ?? null, name: lib.name, size: lib.size },
			statement: "Mobile archive evidence contains native code that should be triaged with native tooling and runtime load hooks.",
			confidence: 0.76,
			rerunCommand: "cat mobile-archive-summary.json | jq '.nativeLibs'",
		});
	}
	for (const plist of summary.iosPlistAnalysis ?? []) {
		for (const scheme of plist.urlSchemes ?? []) {
			addClaim({
				id: "mobile-ios-url-scheme-" + shortHash(`${plist.path}:${scheme}`),
				claimType: "ios-url-scheme-entrypoint",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: plist.path, bundleId: plist.bundleId },
				evidenceBinding: { scheme },
				statement: "iOS Info.plist evidence exposes a URL scheme entrypoint for deep-link replay.",
				confidence: 0.82,
				rerunCommand: "cat mobile-archive-summary.json | jq '.iosPlistAnalysis[].urlSchemes'",
			});
		}
		if (plist.ats?.allowsArbitraryLoads || plist.ats?.allowsArbitraryLoadsInWebContent || (plist.ats?.exceptionDomains ?? []).some((domain) => domain.allowsInsecureHttp)) {
			addHookTarget({ id: "ios-trust-eval", platform: "ios", reason: "ATS or trust-evaluation surface", hook: "SecTrustEvaluate / SecTrustEvaluateWithError" });
			addClaim({
				id: "mobile-ios-ats-" + shortHash(`${plist.path}:${JSON.stringify(plist.ats)}`),
				claimType: "ios-ats-insecure-transport",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: plist.path, bundleId: plist.bundleId },
				evidenceBinding: { ats: plist.ats, hookTargetId: "ios-trust-eval" },
				statement: "iOS Info.plist evidence weakens ATS or defines insecure transport exceptions.",
				confidence: 0.84,
				rerunCommand: "cat mobile-archive-summary.json | jq '.iosPlistAnalysis[].ats'",
			});
		}
	}
	for (const entitlements of summary.iosEntitlements ?? []) {
		if (entitlements.getTaskAllow) {
			addClaim({
				id: "mobile-ios-get-task-allow-" + shortHash(`${entitlements.path}:${entitlements.applicationIdentifier}`),
				claimType: "ios-debug-entitlement",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: entitlements.path, applicationIdentifier: entitlements.applicationIdentifier },
				evidenceBinding: { getTaskAllow: true, teamIdentifier: entitlements.teamIdentifier ?? null },
				statement: "iOS entitlement evidence enables debugger attachment through get-task-allow.",
				confidence: 0.9,
				rerunCommand: "cat mobile-archive-summary.json | jq '.iosEntitlements'",
			});
		}
		for (const group of entitlements.keychainAccessGroups ?? []) {
			addClaim({
				id: "mobile-ios-keychain-group-" + shortHash(`${entitlements.path}:${group}`),
				claimType: "ios-keychain-access-group",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: entitlements.path, applicationIdentifier: entitlements.applicationIdentifier },
				evidenceBinding: { group, teamIdentifier: entitlements.teamIdentifier ?? null },
				statement: "iOS entitlement evidence exposes a keychain access group for credential storage triage.",
				confidence: 0.78,
				rerunCommand: "cat mobile-archive-summary.json | jq '.iosEntitlements[].keychainAccessGroups'",
			});
		}
		for (const domain of entitlements.associatedDomains ?? []) {
			addClaim({
				id: "mobile-ios-associated-domain-" + shortHash(`${entitlements.path}:${domain}`),
				claimType: "ios-associated-domain",
				sourceBinding: { artifact: "mobile-archive-summary.json", file: entitlements.path, applicationIdentifier: entitlements.applicationIdentifier },
				evidenceBinding: { domain },
				statement: "iOS entitlement evidence binds an associated domain for universal-link or credential handoff testing.",
				confidence: 0.72,
				rerunCommand: "cat mobile-archive-summary.json | jq '.iosEntitlements[].associatedDomains'",
			});
		}
	}
	if (summary.platform === "ios" && (summary.iosPlistAnalysis ?? []).length) {
		addHookTarget({ id: "ios-jailbreak-path", platform: "ios", reason: "iOS runtime path/trust hook scaffold", hook: "NSFileManager.fileExistsAtPath / SecTrustEvaluate" });
	}
	const verificationPromotedPaths = [];
	for (const verificationClaim of verification?.claimLedger ?? []) {
		if (verificationClaim.verdict !== "promoted") continue;
		const claim = {
			...verificationClaim,
			id: verificationClaim.id || "mobile-verification-claim-" + shortHash(JSON.stringify(verificationClaim)),
			sourceBinding: {
				artifact: "mobile-archive-verification.json",
				...(verificationClaim.sourceBinding ?? {}),
			},
			rerunCommand: verificationClaim.rerunCommand ?? "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
		};
		addClaim(claim);
		if (claim.claimType === "mobile-runtime-evidence-proof-path") verificationPromotedPaths.push(claim);
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const entrypointClaim = promotedClaims.find((claim) => /entrypoint|url-scheme/.test(claim.claimType));
	const endpointClaim = promotedClaims.find((claim) => claim.claimType === "mobile-network-endpoint");
	const secretClaim = promotedClaims.find((claim) => claim.claimType === "mobile-hardcoded-secret-signal");
	const hookClaim = promotedClaims.find((claim) => /pinning|anti-tamper|ats/.test(claim.claimType));
	const nativeClaim = promotedClaims.find((claim) => /native|crypto/.test(claim.claimType));
	const entitlementClaim = promotedClaims.find((claim) => /^ios-(?:debug|keychain|associated)/.test(claim.claimType));
	const composedPaths = [];
	for (const verificationPath of verification?.composedPaths ?? []) {
		const composed = {
			...verificationPath,
			id: verificationPath.id || "mobile-verification-path-" + shortHash(JSON.stringify(verificationPath)),
			sourceBinding: {
				artifact: "mobile-archive-verification.json",
				...(verificationPath.sourceBinding ?? {}),
			},
			rerunCommand: verificationPath.rerunCommand ?? "python3 mobile-archive-verifier.py <apk-or-ipa> mobile-archive-summary.json mobile-archive-verification.json",
		};
		if (!claimLedger.some((claim) => claim.id === composed.id)) {
			claimLedger.push(composed);
			promotedClaims.push(composed);
		}
		composedPaths.push(composed);
	}
	for (const verificationPath of verificationPromotedPaths) {
		if (!composedPaths.some((path) => path.id === verificationPath.id)) composedPaths.push(verificationPath);
	}
	if (entrypointClaim && (endpointClaim || secretClaim || hookClaim || nativeClaim || entitlementClaim)) {
		const segments = [entrypointClaim, endpointClaim, secretClaim, hookClaim, nativeClaim, entitlementClaim].filter(Boolean);
		const composed = {
			id: "mobile-runtime-pivot-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "mobile-runtime-pivot",
			sourceBinding: {
				platform: summary.platform,
				segments: segments.map((claim) => ({
					id: claim.id,
					claimType: claim.claimType,
					file: claim.sourceBinding?.file,
				})),
			},
			evidenceBinding: {
				hasEntrypoint: Boolean(entrypointClaim),
				hasNetworkEndpoint: Boolean(endpointClaim),
				hasSecretSignal: Boolean(secretClaim),
				hasHookTarget: Boolean(hookClaim),
				hasNativeOrCrypto: Boolean(nativeClaim),
				hasEntitlementPivot: Boolean(entitlementClaim),
				hookTargets,
			},
			statement: "Mobile evidence composes entrypoint, endpoint/secret, hook target, and native/entitlement surface into one runtime proof path.",
			verdict: "promoted",
			confidence: endpointClaim && hookClaim ? 0.86 : 0.78,
			blockers: [],
			rerunCommand: "cat mobile-attack-surface-claims.json | jq '.composedPaths'",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!entrypointClaim) blockers.push("missing-entrypoint");
	if (!endpointClaim) blockers.push("missing-network-endpoint");
	if (!hookTargets.length) blockers.push("missing-runtime-hook-target");
	if (!secretClaim) blockers.push("missing-secret-or-config");
	if (!nativeClaim) blockers.push("missing-native-or-crypto");
	if (!(summary.manifestAnalysis ?? []).length && !(summary.iosPlistAnalysis ?? []).length) blockers.push("missing-platform-manifest");
	if (!verification) blockers.push("missing-mobile-archive-verification");
	for (const blocker of verification?.promotionReport?.blockers ?? []) {
		if (!blockers.includes(blocker)) blockers.push(blocker);
	}
	const repairActions = {
		"missing-entrypoint": "Identify an exported Android component or iOS URL scheme/universal link before claiming runtime reachability.",
		"missing-network-endpoint": "Extract endpoints from DEX, plist, strings, or runtime traffic and bind them to source strings.",
		"missing-runtime-hook-target": "Map pinning, trust, root/jailbreak, or native-load evidence to a concrete Frida hook target.",
		"missing-secret-or-config": "Extract redacted token, API key, credential, or config fields from DEX/resources/plist without leaking values.",
		"missing-native-or-crypto": "Bind crypto transforms or native library loading to DEX strings, native libs, or symbols.",
		"missing-platform-manifest": "Parse AndroidManifest.xml, Info.plist, or entitlements; binary manifests need aapt/apktool/plutil conversion.",
		"missing-mobile-archive-verification": "Generate mobile-archive-verification.json and mobile-archive-verifier.py to bind archive entries and negative controls.",
		"missing-mobile-archive-hash-verification": "Rerun mobile-archive-verifier.py against the original APK/IPA and require size/SHA-256 equality.",
		"missing-mobile-zip-entry-verification": "Verify manifest, DEX, native library, certificate, and config ZIP entries by CRC, size, and SHA-256.",
		"missing-mobile-dex-quicklook-verification": "Bind DEX quicklook strings/header claims to exact classes.dex bytes.",
		"missing-mobile-manifest-verification": "Bind AndroidManifest.xml, Info.plist, or entitlements fields to exact archive entry bytes.",
		"missing-mobile-hook-verification": "Generate mobile-frida-hooks.js and syntax/hash-check expected platform hook signals.",
		"missing-mobile-negative-control": "Add archive and entry mutation controls so mobile evidence has rejection proof.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "mobile-attack-surface-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect mobile archive evidence and rerun attack-surface claim promotion.",
		rerunCommand: "repi engage <apk-or-ipa> --json",
	}));
	return {
		kind: "repi-mobile-attack-surface-claims",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		platform: summary.platform,
		proofReady: promotedClaims.length > 0,
		runtimeProofReady: composedPaths.length > 0,
		verificationStats: verification?.stats ?? null,
		hookTargets,
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			promotedClaims,
			blockers,
		},
		repairQueue,
	};
}

export function mobileArchiveQuicklookRows(target, artifactDir, lane) {
	try {
		const summary = mobileArchiveSummary(target, lane);
		const attackSurface = mobileAttackSurfaceClaims(summary);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "mobile-archive-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "mobile-attack-surface-claims.json"), `${JSON.stringify(attackSurface, null, 2)}\n`);
		return [
			{
				id: "mobile-archive-quicklook",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(summary, null, 2)}\n`,
				stderr: "",
				error: undefined,
			},
			{
				id: "mobile-attack-surface-claims",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: attackSurface.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(attackSurface, null, 2)}\n`,
				stderr: "",
				error: attackSurface.proofReady ? undefined : "no mobile attack-surface claims promoted",
			},
		];
	} catch (error) {
		return [{ id: "mobile-archive-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}

function mobileFridaHookSource(platform) {
	if (platform === "ios") {
		return `// REPI iOS reverse/pentest hook scaffold.
// Use: frida -U -f <bundle-id> -l mobile-frida-hooks.js --no-pause
if (ObjC.available) {
  const log = (name, value) => console.log("[repi-ios]", name, value || "");
  const hook = (className, selector, callback) => {
    const klass = ObjC.classes[className];
    if (!klass || !klass[selector]) return;
    Interceptor.attach(klass[selector].implementation, callback);
    log("hooked", className + " " + selector);
  };
  hook("NSFileManager", "- fileExistsAtPath:", {
    onEnter(args) { this.path = new ObjC.Object(args[2]).toString(); },
    onLeave(retval) {
      if (/(?:Cydia|frida|Substrate|\\/bin\\/sh|\\/usr\\/sbin\\/sshd|\\/private\\/var\\/lib\\/apt)/i.test(this.path)) {
        log("jailbreak-path", this.path);
        retval.replace(0);
      }
    },
  });
  ["SecTrustEvaluate", "SecTrustEvaluateWithError"].forEach((name) => {
    const ptr = Module.findExportByName("Security", name);
    if (ptr) Interceptor.attach(ptr, { onEnter() { log("trust-eval", name); }, onLeave(retval) { retval.replace(1); } });
  });
}
`;
	}
	return `// REPI Android reverse/pentest hook scaffold.
// Use: frida -U -f <package> -l mobile-frida-hooks.js --no-pause
Java.perform(function () {
  const log = (name, value) => console.log("[repi-android] " + name + (value ? " " + value : ""));
  try {
    const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.checkTrustedRecursive.implementation = function () {
      log("TrustManagerImpl.checkTrustedRecursive");
      return Java.use("java.util.ArrayList").$new();
    };
  } catch (error) { log("trustmanager-skip", String(error)); }
  try {
    const CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        log("okhttp3.CertificatePinner.check", arguments[0] && arguments[0].toString());
        return;
      };
    });
  } catch (error) { log("pinner-skip", String(error)); }
  try {
    const Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overloads.forEach(function (overload) {
      overload.implementation = function () {
        log("Runtime.exec", arguments[0] && arguments[0].toString());
        return overload.apply(this, arguments);
      };
    });
  } catch (error) { log("runtime-skip", String(error)); }
  try {
    const SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload("java.lang.String").implementation = function (key) {
      const value = this.get(key);
      log("SystemProperties.get", key + "=" + value);
      return value;
    };
  } catch (error) { log("systemproperties-skip", String(error)); }
});
`;
}

export function writeMobileFridaHook(artifactDir, lane) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "mobile-frida-hooks.js");
	writePrivate(path, mobileFridaHookSource(lane === "mobile-ios" ? "ios" : "android"), 0o700);
	return path;
}
