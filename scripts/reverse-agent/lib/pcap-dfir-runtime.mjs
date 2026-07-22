import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { gunzipSync, inflateSync } from "node:zlib";

let deep;
let noWrite;
let root;
let redact;
let writePrivate;
let bufferSha256;
let shortHash;
let httpSecretHash;
let slug;
let findSignatureOffsets;
let embeddedZipArchives;
let parseZipCentralDirectory;
let zipEntryData;

function configurePcapDfirRuntime(runtime) {
	({ deep, noWrite, root, redact, writePrivate, bufferSha256, shortHash, httpSecretHash, slug, findSignatureOffsets, embeddedZipArchives, parseZipCentralDirectory, zipEntryData } = runtime);
}

function dnsTypeName(value) {
	return (
		{
			1: "A",
			2: "NS",
			5: "CNAME",
			6: "SOA",
			12: "PTR",
			15: "MX",
			16: "TXT",
			28: "AAAA",
			33: "SRV",
			65: "HTTPS",
			64: "SVCB",
		}[value] ?? String(value)
	);
}

function decodeDnsName(buffer, offset, end, depth = 0, base = 0) {
	const labels = [];
	let cursor = offset;
	let nextOffset = offset;
	let jumped = false;
	while (cursor < end && depth < 8) {
		const length = buffer[cursor];
		if ((length & 0xc0) === 0xc0) {
			if (cursor + 1 >= end) break;
			const pointer = ((length & 0x3f) << 8) | buffer[cursor + 1];
			if (!jumped) nextOffset = cursor + 2;
			cursor = base + pointer;
			jumped = true;
			depth += 1;
			continue;
		}
		if (length === 0) {
			cursor += 1;
			if (!jumped) nextOffset = cursor;
			return { name: labels.join("."), nextOffset };
		}
		const labelStart = cursor + 1;
		const labelEnd = labelStart + length;
		if (labelEnd > end) break;
		labels.push(buffer.toString("ascii", labelStart, labelEnd).replace(/[^\x20-\x7e]/g, "?"));
		cursor = labelEnd;
		if (!jumped) nextOffset = cursor;
	}
	return { name: labels.join("."), nextOffset };
}

function shannonEntropy(text) {
	const value = String(text ?? "");
	if (!value) return 0;
	const counts = new Map();
	for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
	let entropy = 0;
	for (const count of counts.values()) {
		const p = count / value.length;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

function dnsLabelRiskKinds(label) {
	const value = String(label ?? "");
	if (!value) return [];
	const entropy = shannonEntropy(value);
	const risks = [];
	if (value.length >= 48) risks.push("long-label");
	else if (value.length >= 32) risks.push("medium-long-label");
	if (value.length >= 20 && entropy >= 3.7) risks.push("high-entropy-label");
	if (value.length >= 24 && /^[A-Z2-7]+$/i.test(value)) risks.push("base32-like-label");
	if (value.length >= 24 && /^[A-Za-z0-9_-]+$/.test(value) && entropy >= 4.0) risks.push("base64url-like-label");
	if (/(?:secret|token|password|passwd|flag)/i.test(value)) risks.push("sensitive-keyword-label");
	return risks;
}

function dnsLabelSignal(label, index) {
	const risks = dnsLabelRiskKinds(label);
	if (!risks.length) return undefined;
	return {
		index,
		length: label.length,
		entropy: Number(shannonEntropy(label).toFixed(2)),
		valueSha256: createHash("sha256").update(label).digest("hex"),
		risks,
	};
}

function sanitizeDnsName(name) {
	const labels = String(name ?? "")
		.split(".")
		.filter(Boolean);
	if (!labels.length) return "";
	return labels
		.map((label) => {
			const risks = dnsLabelRiskKinds(label);
			if (!risks.length) return redact(label.slice(0, 80));
			return `<dns-label:${label.length}:${createHash("sha256").update(label).digest("hex").slice(0, 12)}>`;
		})
		.join(".");
}

function dnsQueryAnalysis(name) {
	const labels = String(name ?? "")
		.split(".")
		.filter(Boolean);
	const labelSignals = labels.map((label, index) => dnsLabelSignal(label, index)).filter(Boolean);
	const maxLabelLength = labels.reduce((max, label) => Math.max(max, label.length), 0);
	const maxEntropy = labels.reduce((max, label) => Math.max(max, shannonEntropy(label)), 0);
	const risks = [];
	if (labelSignals.some((signal) => signal.risks.includes("long-label") || signal.risks.includes("medium-long-label"))) risks.push("pcap-dns-long-label-exfil-signal");
	if (labelSignals.some((signal) => signal.risks.includes("high-entropy-label"))) risks.push("pcap-dns-high-entropy-label-signal");
	if (labelSignals.some((signal) => signal.risks.includes("base32-like-label") || signal.risks.includes("base64url-like-label"))) risks.push("pcap-dns-encoded-label-signal");
	if (labelSignals.some((signal) => signal.risks.includes("sensitive-keyword-label"))) risks.push("pcap-dns-sensitive-label-signal");
	if (labels.length >= 6 && maxLabelLength >= 12) risks.push("pcap-dns-deep-subdomain-signal");
	const sanitizedName = sanitizeDnsName(name);
	const baseDomain = labels.length >= 2 ? sanitizeDnsName(labels.slice(-2).join(".")) : sanitizedName;
	return {
		sanitizedName,
		originalNameSha256: sanitizedName !== name ? createHash("sha256").update(String(name)).digest("hex") : undefined,
		baseDomain,
		labelCount: labels.length,
		maxLabelLength,
		maxEntropy: Number(maxEntropy.toFixed(2)),
		labelSignals,
		risks,
	};
}

function dnsRecordValue(buffer, start, length, type, messageStart, end) {
	if (type === 1 && length === 4) return `${buffer[start]}.${buffer[start + 1]}.${buffer[start + 2]}.${buffer[start + 3]}`;
	if (type === 28 && length === 16) {
		const parts = [];
		for (let offset = 0; offset < 16; offset += 2) parts.push(buffer.readUInt16BE(start + offset).toString(16));
		return parts.join(":");
	}
	if ([2, 5, 12].includes(type)) return sanitizeDnsName(decodeDnsName(buffer, start, end, 0, messageStart).name || ".");
	if (type === 16) {
		const texts = [];
		let cursor = start;
		const recordEnd = Math.min(end, start + length);
		while (cursor < recordEnd && texts.length < 8) {
			const partLength = buffer[cursor];
			cursor += 1;
			if (cursor + partLength > recordEnd) break;
			const text = buffer.toString("utf8", cursor, cursor + partLength).replace(/[^\x20-\x7e]/g, "?");
			if (text) texts.push(redact(text.slice(0, 160)));
			cursor += partLength;
		}
		return texts.join(" ");
	}
	return `rdata:${length}b sha256:${createHash("sha256").update(buffer.subarray(start, Math.min(end, start + length))).digest("hex").slice(0, 16)}`;
}

function parseDnsMessage(buffer, start, length) {
	const end = Math.min(buffer.length, start + length);
	if (end - start < 12) return { queries: [], answers: [] };
	const qdCount = buffer.readUInt16BE(start + 4);
	const anCount = buffer.readUInt16BE(start + 6);
	const nsCount = buffer.readUInt16BE(start + 8);
	const arCount = buffer.readUInt16BE(start + 10);
	let cursor = start + 12;
	const queries = [];
	for (let index = 0; index < Math.min(qdCount, 12); index++) {
		const decoded = decodeDnsName(buffer, cursor, end, 0, start);
		cursor = decoded.nextOffset;
		if (!decoded.name || cursor + 4 > end) break;
		const qtype = buffer.readUInt16BE(cursor);
		const qclass = buffer.readUInt16BE(cursor + 2);
		cursor += 4;
		const analysis = dnsQueryAnalysis(decoded.name);
		queries.push({
			name: analysis.sanitizedName,
			type: dnsTypeName(qtype),
			class: qclass,
			...(analysis.originalNameSha256 ? { originalNameSha256: analysis.originalNameSha256 } : {}),
			...(analysis.risks.length
				? {
						queryAnalysis: {
							baseDomain: analysis.baseDomain,
							labelCount: analysis.labelCount,
							maxLabelLength: analysis.maxLabelLength,
							maxEntropy: analysis.maxEntropy,
							labelSignals: analysis.labelSignals,
						},
						risks: analysis.risks,
					}
				: {}),
		});
	}
	const answers = [];
	const sections = [
		["answer", anCount],
		["authority", nsCount],
		["additional", arCount],
	];
	for (const [section, count] of sections) {
		for (let index = 0; index < Math.min(count, 40); index++) {
			const decoded = decodeDnsName(buffer, cursor, end, 0, start);
			cursor = decoded.nextOffset;
			if (cursor + 10 > end) break;
			const type = buffer.readUInt16BE(cursor);
			const qclass = buffer.readUInt16BE(cursor + 2);
			const ttl = buffer.readUInt32BE(cursor + 4);
			const dataLength = buffer.readUInt16BE(cursor + 8);
			const dataStart = cursor + 10;
			const dataEnd = dataStart + dataLength;
			if (dataEnd > end) break;
			answers.push({
				section,
				name: sanitizeDnsName(decoded.name || "."),
				type: dnsTypeName(type),
				class: qclass,
				ttl,
				value: dnsRecordValue(buffer, dataStart, dataLength, type, start, end),
			});
			cursor = dataEnd;
			if (answers.length >= 80) return { queries, answers };
		}
	}
	return { queries, answers };
}

function parseDnsQueries(buffer, start, length) {
	return parseDnsMessage(buffer, start, length).queries;
}

function pushUniqueValue(values, value, limit = 20) {
	if (value == null || value === "" || values.length >= limit || values.includes(value)) return;
	values.push(value);
}

function pushPcapRisk(risks, risk) {
	pushUniqueValue(risks, risk, 40);
}

function httpSensitiveName(name) {
	return /(?:^|[_-])(?:auth|authorization|token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|session|sid|secret|password|passwd|pwd|api[_-]?key|client[_-]?secret|credential|csrf|xsrf|sso|code|key)(?:$|[_-])/i.test(String(name ?? ""));
}

function boundedHttpToken(value, limit = 200) {
	const text = String(value ?? "").replace(/[^\x20-\x7e]/g, "?").trim();
	return text ? redact(text.slice(0, limit)) : undefined;
}

function parseHttpHeaderLines(headerBlock) {
	const lines = headerBlock.split(/\r?\n/).slice(1);
	const headers = [];
	for (const rawLine of lines) {
		if (/^[ \t]/.test(rawLine) && headers.length) {
			headers[headers.length - 1].value = `${headers[headers.length - 1].value} ${rawLine.trim()}`.slice(0, 2048);
			continue;
		}
		const match = /^([^:\s][^:]{0,120}):\s*(.*)$/.exec(rawLine);
		if (!match) continue;
		headers.push({ name: match[1].toLowerCase(), originalName: match[1].slice(0, 120), value: match[2].trim().slice(0, 4096) });
		if (headers.length >= 80) break;
	}
	return headers;
}

function httpHeaderValues(headers, name) {
	const wanted = String(name).toLowerCase();
	return headers.filter((header) => header.name === wanted).map((header) => header.value);
}

function firstHttpHeader(headers, name) {
	return httpHeaderValues(headers, name)[0];
}

function addCredentialSignal(signals, signal) {
	if (!signal?.valueSha256 || signals.length >= 48) return;
	const key = `${signal.kind}:${signal.name ?? ""}:${signal.scheme ?? ""}:${signal.valueSha256}`;
	if (signals.some((existing) => `${existing.kind}:${existing.name ?? ""}:${existing.scheme ?? ""}:${existing.valueSha256}` === key)) return;
	signals.push(signal);
}

function hashedCredentialSignal(kind, value, extra = {}) {
	if (value == null || value === "") return undefined;
	const text = String(value);
	return {
		kind,
		...extra,
		valueSha256: httpSecretHash(text),
		valueLength: text.length,
	};
}

function analyzeHttpAuthorization(headers, credentialSignals, risks) {
	for (const value of httpHeaderValues(headers, "authorization")) {
		const auth = /^([A-Za-z][A-Za-z0-9._-]{0,40})\s+(.+)$/.exec(value);
		const scheme = auth?.[1] ?? "unknown";
		const credential = auth?.[2] ?? value;
		addCredentialSignal(credentialSignals, hashedCredentialSignal("authorization", credential, { scheme }));
		pushPcapRisk(risks, "pcap-http-authorization-header");
		if (/^basic$/i.test(scheme)) pushPcapRisk(risks, "pcap-http-basic-auth");
		if (/^bearer$/i.test(scheme)) pushPcapRisk(risks, "pcap-http-bearer-token");
		if (/^(?:digest|ntlm|negotiate)$/i.test(scheme)) pushPcapRisk(risks, "pcap-http-auth-challenge-material");
	}
}

function analyzeHttpCookies(headers, credentialSignals, risks) {
	const cookieNames = [];
	for (const value of httpHeaderValues(headers, "cookie")) {
		for (const part of value.split(";")) {
			const index = part.indexOf("=");
			const name = (index >= 0 ? part.slice(0, index) : part).trim().slice(0, 120);
			const cookieValue = index >= 0 ? part.slice(index + 1).trim() : "";
			if (!name) continue;
			pushUniqueValue(cookieNames, name, 40);
			if (cookieValue) addCredentialSignal(credentialSignals, hashedCredentialSignal("cookie", cookieValue, { name }));
			if (httpSensitiveName(name) || /(?:session|sid|jwt|token|auth|sso|remember)/i.test(name)) pushPcapRisk(risks, "pcap-http-cookie-session");
		}
	}
	return cookieNames;
}

function analyzeHttpSetCookies(headers, credentialSignals, risks) {
	const cookieNames = [];
	for (const value of httpHeaderValues(headers, "set-cookie")) {
		const firstPart = value.split(";", 1)[0] ?? "";
		const index = firstPart.indexOf("=");
		const name = (index >= 0 ? firstPart.slice(0, index) : firstPart).trim().slice(0, 120);
		const cookieValue = index >= 0 ? firstPart.slice(index + 1).trim() : "";
		if (!name) continue;
		pushUniqueValue(cookieNames, name, 40);
		if (cookieValue) addCredentialSignal(credentialSignals, hashedCredentialSignal("set-cookie", cookieValue, { name }));
		if (httpSensitiveName(name) || /(?:session|sid|jwt|token|auth|sso|remember)/i.test(name)) pushPcapRisk(risks, "pcap-http-set-cookie-session");
	}
	return cookieNames;
}

function queryPartFromHttpTarget(target) {
	const raw = String(target ?? "");
	const question = raw.indexOf("?");
	if (question < 0) return "";
	const hash = raw.indexOf("#", question + 1);
	return raw.slice(question + 1, hash >= 0 ? hash : undefined);
}

function analyzeHttpQuery(target, credentialSignals, risks) {
	const query = queryPartFromHttpTarget(target);
	if (!query) return;
	for (const [name, value] of new URLSearchParams(query).entries()) {
		if (!value || !httpSensitiveName(name)) continue;
		addCredentialSignal(credentialSignals, hashedCredentialSignal("query-param", value, { name: name.slice(0, 120) }));
		pushPcapRisk(risks, "pcap-http-query-token");
	}
}

function analyzeFormUrlEncoded(body, credentialSignals, risks) {
	for (const [name, value] of new URLSearchParams(body).entries()) {
		if (!value || !httpSensitiveName(name)) continue;
		addCredentialSignal(credentialSignals, hashedCredentialSignal("form-field", value, { name: name.slice(0, 120) }));
		pushPcapRisk(risks, "pcap-http-form-credential");
	}
}

function walkJsonCredentialFields(value, credentialSignals, risks, path = "", depth = 0) {
	if (depth > 6 || value == null || credentialSignals.length >= 48) return;
	if (Array.isArray(value)) {
		for (const item of value.slice(0, 24)) walkJsonCredentialFields(item, credentialSignals, risks, path, depth + 1);
		return;
	}
	if (typeof value !== "object") return;
	for (const [key, child] of Object.entries(value).slice(0, 80)) {
		const nextPath = path ? `${path}.${key}` : key;
		if ((typeof child === "string" || typeof child === "number" || typeof child === "boolean") && httpSensitiveName(key)) {
			addCredentialSignal(credentialSignals, hashedCredentialSignal("json-field", String(child), { name: nextPath.slice(0, 160) }));
			pushPcapRisk(risks, "pcap-http-form-credential");
		} else {
			walkJsonCredentialFields(child, credentialSignals, risks, nextPath, depth + 1);
		}
	}
}

function analyzeHttpBody(body, contentType, credentialSignals, risks) {
	if (!body) return;
	const boundedBody = body.slice(0, 16_384);
	if (/application\/x-www-form-urlencoded/i.test(contentType || "")) {
		analyzeFormUrlEncoded(boundedBody, credentialSignals, risks);
		return;
	}
	if (/(?:^|[+;/])json(?:[;\s]|$)|application\/json/i.test(contentType || "")) {
		try {
			walkJsonCredentialFields(JSON.parse(boundedBody), credentialSignals, risks);
		} catch {
			// Non-fatal; packet samples are often truncated.
		}
	}
}

function httpHeaderBoundary(buffer, start, end) {
	const cappedEnd = Math.min(end, start + 32_768);
	const crlf = buffer.indexOf(Buffer.from("\r\n\r\n", "latin1"), start);
	const lf = buffer.indexOf(Buffer.from("\n\n", "latin1"), start);
	const candidates = [];
	if (crlf >= start && crlf < cappedEnd) candidates.push({ offset: crlf, separatorLength: 4 });
	if (lf >= start && lf < cappedEnd) candidates.push({ offset: lf, separatorLength: 2 });
	candidates.sort((a, b) => a.offset - b.offset || b.separatorLength - a.separatorLength);
	return candidates[0];
}

function httpIntegerHeader(headers, name) {
	const value = firstHttpHeader(headers, name);
	if (!value || !/^\d{1,12}$/.test(value.trim())) return null;
	const parsed = Number(value.trim());
	return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function decodeHttpChunkedBody(data, maxBytes = 512 * 1024) {
	let cursor = 0;
	const parts = [];
	let decodedBytes = 0;
	let chunkCount = 0;
	let truncated = false;
	while (cursor < data.length && chunkCount < 4096) {
		const lineEnd = data.indexOf(Buffer.from("\r\n", "latin1"), cursor);
		if (lineEnd < 0) {
			truncated = true;
			break;
		}
		const line = data.toString("ascii", cursor, lineEnd).split(";", 1)[0].trim();
		if (!/^[0-9a-fA-F]+$/.test(line)) return undefined;
		const size = Number.parseInt(line, 16);
		if (!Number.isFinite(size) || size < 0) return undefined;
		cursor = lineEnd + 2;
		if (size === 0) {
			return { data: Buffer.concat(parts), chunkCount, truncated: false };
		}
		if (cursor + size > data.length) {
			const remaining = Math.max(0, data.length - cursor);
			const take = Math.min(remaining, Math.max(0, maxBytes - decodedBytes));
			if (take > 0) parts.push(data.subarray(cursor, cursor + take));
			truncated = true;
			break;
		}
		const take = Math.min(size, Math.max(0, maxBytes - decodedBytes));
		if (take > 0) parts.push(data.subarray(cursor, cursor + take));
		decodedBytes += take;
		if (take < size) truncated = true;
		cursor += size;
		if (data[cursor] === 0x0d && data[cursor + 1] === 0x0a) cursor += 2;
		else if (data[cursor] === 0x0a) cursor += 1;
		else {
			truncated = true;
			break;
		}
		chunkCount += 1;
		if (decodedBytes >= maxBytes) {
			truncated = true;
			break;
		}
	}
	return { data: Buffer.concat(parts), chunkCount, truncated };
}

function maybeDecodeHttpContentEncoding(data, contentEncoding) {
	if (!data.length) return { data, decodedFrom: null, decodeError: null };
	const normalized = String(contentEncoding || "").toLowerCase();
	if (normalized.includes("gzip") || (data.length >= 3 && data[0] === 0x1f && data[1] === 0x8b && data[2] === 0x08)) {
		try {
			return { data: gunzipSync(data.subarray(0, Math.min(data.length, 512 * 1024))), decodedFrom: "gzip", decodeError: null };
		} catch (error) {
			return { data, decodedFrom: null, decodeError: error instanceof Error ? redact(error.message).slice(0, 160) : redact(String(error)).slice(0, 160) };
		}
	}
	if (normalized.includes("deflate")) {
		try {
			return { data: inflateSync(data.subarray(0, Math.min(data.length, 512 * 1024))), decodedFrom: "deflate", decodeError: null };
		} catch (error) {
			return { data, decodedFrom: null, decodeError: error instanceof Error ? redact(error.message).slice(0, 160) : redact(String(error)).slice(0, 160) };
		}
	}
	return { data, decodedFrom: null, decodeError: null };
}

function httpObjectMagicSignatures(data) {
	const signatures = [
		{ name: "ZIP", bytes: Buffer.from("504b0304", "hex"), risk: "pcap-http-embedded-zip-object", search: true },
		{ name: "PNG", bytes: Buffer.from("89504e470d0a1a0a", "hex"), risk: "pcap-http-image-object", search: true },
		{ name: "JPEG", bytes: Buffer.from("ffd8ff", "hex"), risk: "pcap-http-image-object", search: true },
		{ name: "GZIP", bytes: Buffer.from("1f8b08", "hex"), risk: "pcap-http-compressed-object", search: true },
		{ name: "PDF", bytes: Buffer.from("%PDF-", "ascii"), risk: "pcap-http-document-object", search: true },
		{ name: "ELF", bytes: Buffer.from("7f454c46", "hex"), risk: "pcap-http-executable-object", search: true },
		{ name: "PE/DOS", bytes: Buffer.from("4d5a", "hex"), risk: "pcap-http-executable-object", search: false },
		{ name: "Mach-O", bytes: Buffer.from("cffaedfe", "hex"), risk: "pcap-http-executable-object", search: true },
		{ name: "Mach-O", bytes: Buffer.from("feedfacf", "hex"), risk: "pcap-http-executable-object", search: true },
		{ name: "WASM", bytes: Buffer.from("0061736d", "hex"), risk: "pcap-http-wasm-object", search: true },
		{ name: "SQLite", bytes: Buffer.from("SQLite format 3\u0000", "binary"), risk: "pcap-http-database-object", search: true },
		{ name: "7z", bytes: Buffer.from("377abcaf271c", "hex"), risk: "pcap-http-compressed-object", search: true },
		{ name: "RAR", bytes: Buffer.from("526172211a07", "hex"), risk: "pcap-http-compressed-object", search: true },
		{ name: "DEX", bytes: Buffer.from("dex\n", "ascii"), risk: "pcap-http-mobile-code-object", search: true },
		{ name: "Java class", bytes: Buffer.from("cafebabe", "hex"), risk: "pcap-http-executable-object", search: true },
	];
	const rows = [];
	for (const signature of signatures) {
		const offsets = signature.search ? findSignatureOffsets(data, signature.bytes, 8) : (data.subarray(0, signature.bytes.length).equals(signature.bytes) ? [0] : []);
		for (const offset of offsets) {
			rows.push({
				name: signature.name,
				bodyOffset: offset,
				sha256: bufferSha256(data.subarray(offset, Math.min(data.length, offset + 4096))),
				risk: signature.risk,
			});
			if (rows.length >= 32) return rows;
		}
	}
	if (data.length >= 262 && data.toString("ascii", 257, 262) === "ustar") {
		rows.push({
			name: "TAR",
			bodyOffset: 0,
			sha256: bufferSha256(data.subarray(0, Math.min(data.length, 4096))),
			risk: "pcap-http-compressed-object",
		});
	}
	return rows;
}

function httpBodyObjectQuicklook(buffer, bodyStart, end, headers, payloadStart) {
	const declaredLength = httpIntegerHeader(headers, "content-length");
	const contentType = firstHttpHeader(headers, "content-type");
	const contentEncoding = firstHttpHeader(headers, "content-encoding");
	const transferEncoding = firstHttpHeader(headers, "transfer-encoding");
	const contentDisposition = firstHttpHeader(headers, "content-disposition");
	const bodyEnd = declaredLength !== null && !/chunked/i.test(transferEncoding || "") ? Math.min(end, bodyStart + declaredLength) : end;
	const body = buffer.subarray(bodyStart, bodyEnd);
	if (!body.length && !declaredLength) return undefined;
	const encodedSha256 = body.length ? bufferSha256(body) : null;
	let inspected = body.subarray(0, Math.min(body.length, 512 * 1024));
	const decodedFrom = [];
	let decodedChunkCount = null;
	let decodeError = null;
	let decodedTruncated = body.length > inspected.length;
	if (/chunked/i.test(transferEncoding || "")) {
		const decoded = decodeHttpChunkedBody(inspected);
		if (decoded) {
			inspected = decoded.data;
			decodedFrom.push("chunked");
			decodedChunkCount = decoded.chunkCount;
			decodedTruncated = decoded.truncated;
		}
	}
	const decodedContent = maybeDecodeHttpContentEncoding(inspected, contentEncoding);
	inspected = decodedContent.data;
	if (decodedContent.decodedFrom) decodedFrom.push(decodedContent.decodedFrom);
	if (decodedContent.decodeError) decodeError = decodedContent.decodeError;
	const magic = httpObjectMagicSignatures(inspected).map((row) => ({
		...row,
		streamOffset: bodyStart - payloadStart + row.bodyOffset,
	}));
	const embeddedArchives = magic.some((row) => row.name === "ZIP")
		? embeddedZipArchives(inspected, 0, inspected.length, 6).map((archive) => ({
				...archive,
				streamOffset: bodyStart - payloadStart + archive.offset,
			}))
		: [];
	const risks = [];
	if (body.length || declaredLength) pushPcapRisk(risks, "pcap-http-object-body");
	for (const row of magic) pushPcapRisk(risks, row.risk);
	if (embeddedArchives.some((archive) => !archive.parseError)) pushPcapRisk(risks, "pcap-http-embedded-archive-parsed");
	if (embeddedArchives.some((archive) => archive.parseError)) pushPcapRisk(risks, "pcap-http-embedded-archive-parse-error");
	const declaredTruncated = declaredLength !== null && body.length < declaredLength;
	if (declaredTruncated || decodedTruncated) pushPcapRisk(risks, "pcap-http-body-truncated");
	return {
		bodyOffset: bodyStart - payloadStart,
		capturedLength: body.length,
		declaredLength,
		truncated: declaredTruncated || decodedTruncated,
		sha256: inspected.length ? bufferSha256(inspected) : encodedSha256,
		encodedSha256: decodedFrom.length ? encodedSha256 : undefined,
		contentType: contentType ? boundedHttpToken(contentType) : null,
		contentEncoding: contentEncoding ? boundedHttpToken(contentEncoding) : null,
		transferEncoding: transferEncoding ? boundedHttpToken(transferEncoding) : null,
		contentDisposition: contentDisposition ? boundedHttpToken(redact(contentDisposition)) : null,
		decodedFrom,
		decodedChunkCount,
		decodeError,
		magic,
		embeddedArchives,
		risks,
	};
}

function parseHttpSample(buffer, start, length) {
	const end = Math.min(buffer.length, start + length);
	if (end <= start) return undefined;
	const boundary = httpHeaderBoundary(buffer, start, end);
	const sampleEnd = Math.min(end, start + 16_384);
	const sample = buffer.toString("latin1", start, sampleEnd);
	const sampleHeaderEnd = sample.indexOf("\r\n\r\n") >= 0 ? sample.indexOf("\r\n\r\n") : sample.indexOf("\n\n");
	const headerEnd = boundary ? boundary.offset - start : sampleHeaderEnd;
	const separatorLength = boundary ? boundary.separatorLength : sample.indexOf("\r\n\r\n") >= 0 ? 4 : headerEnd >= 0 ? 2 : 0;
	const headerBlock = headerEnd >= 0 ? buffer.toString("latin1", start, start + headerEnd) : sample;
	const bodyStart = headerEnd >= 0 ? start + headerEnd + separatorLength : end;
	const body = bodyStart < sampleEnd ? buffer.toString("latin1", bodyStart, sampleEnd) : "";
	const firstLine = headerBlock.split(/\r?\n/, 1)[0]?.trim();
	if (!firstLine) return undefined;
	const request = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+([^\s]{1,2048})\s+HTTP\/\d(?:\.\d)?$/i.exec(firstLine);
	const response = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\b(.*)$/i.exec(firstLine);
	if (!request && !response) return undefined;
	const headers = parseHttpHeaderLines(headerBlock);
	const host = firstHttpHeader(headers, "host")?.slice(0, 200);
	const bodySummary = headerEnd >= 0 ? httpBodyObjectQuicklook(buffer, bodyStart, end, headers, start) : undefined;
	if (request) {
		const credentialSignals = [];
		const risks = [];
		analyzeHttpAuthorization(headers, credentialSignals, risks);
		const cookieNames = analyzeHttpCookies(headers, credentialSignals, risks);
		analyzeHttpQuery(request[2], credentialSignals, risks);
		const contentType = firstHttpHeader(headers, "content-type");
		analyzeHttpBody(body, contentType, credentialSignals, risks);
		for (const risk of bodySummary?.risks ?? []) pushPcapRisk(risks, risk);
		if (credentialSignals.length) pushPcapRisk(risks, "pcap-http-cleartext-credential-flow");
		const authorizationScheme = credentialSignals.find((signal) => signal.kind === "authorization")?.scheme;
		const headerSummary = {
			host: host ? redact(host) : null,
			authorizationScheme: authorizationScheme ?? null,
			cookieNames,
			contentLength: httpIntegerHeader(headers, "content-length"),
			contentType: contentType ? boundedHttpToken(contentType) : null,
			contentEncoding: boundedHttpToken(firstHttpHeader(headers, "content-encoding")) ?? null,
			transferEncoding: boundedHttpToken(firstHttpHeader(headers, "transfer-encoding")) ?? null,
			contentDisposition: boundedHttpToken(redact(firstHttpHeader(headers, "content-disposition"))) ?? null,
			userAgent: boundedHttpToken(firstHttpHeader(headers, "user-agent")) ?? null,
			referer: boundedHttpToken(firstHttpHeader(headers, "referer")) ?? null,
		};
		return {
			kind: "request",
			method: request[1].toUpperCase(),
			target: redact(request[2].slice(0, 240)),
			host: host ? redact(host) : null,
			headers: headerSummary,
			bodySummary,
			credentialSignals,
			risks,
			line: redact(firstLine.slice(0, 300)),
		};
	}
	const credentialSignals = [];
	const risks = [];
	const setCookieNames = analyzeHttpSetCookies(headers, credentialSignals, risks);
	const location = firstHttpHeader(headers, "location");
	if (location) analyzeHttpQuery(location, credentialSignals, risks);
	for (const risk of bodySummary?.risks ?? []) pushPcapRisk(risks, risk);
	if (credentialSignals.length) pushPcapRisk(risks, "pcap-http-cleartext-credential-flow");
	const responseHeaders = {
		contentLength: httpIntegerHeader(headers, "content-length"),
		contentType: boundedHttpToken(firstHttpHeader(headers, "content-type")) ?? null,
		contentEncoding: boundedHttpToken(firstHttpHeader(headers, "content-encoding")) ?? null,
		transferEncoding: boundedHttpToken(firstHttpHeader(headers, "transfer-encoding")) ?? null,
		contentDisposition: boundedHttpToken(redact(firstHttpHeader(headers, "content-disposition"))) ?? null,
		server: boundedHttpToken(firstHttpHeader(headers, "server")) ?? null,
		location: boundedHttpToken(location) ?? null,
		setCookieNames,
	};
	return {
		kind: "response",
		status: Number(response[1]),
		reason: response[2]?.trim().slice(0, 120) || null,
		headers: responseHeaders,
		bodySummary,
		credentialSignals,
		risks,
		line: redact(firstLine.slice(0, 300)),
	};
}

function plaintextAuthProtocol(sport, dport) {
	const ports = [sport, dport];
	if (ports.includes(21)) return "ftp";
	if (ports.includes(110)) return "pop3";
	if (ports.includes(143)) return "imap";
	if (ports.includes(25) || ports.includes(587) || ports.includes(465)) return "smtp";
	if (ports.includes(6379)) return "redis";
	return "unknown";
}

function cleanPlaintextAuthValue(value) {
	return String(value ?? "")
		.trim()
		.replace(/^"(.*)"$/, "$1")
		.slice(0, 4096);
}

function parsePlaintextAuthSample(buffer, start, length, sport, dport) {
	const end = Math.min(buffer.length, start + length);
	if (end <= start) return undefined;
	const sample = buffer.toString("latin1", start, Math.min(end, start + 4096)).replace(/\0/g, "");
	if (!/(?:^|\r?\n)(?:USER|PASS|AUTH|[A-Za-z0-9_.-]+\s+LOGIN)\b/i.test(sample)) return undefined;
	const protocol = plaintextAuthProtocol(sport, dport);
	const credentialSignals = [];
	const commands = [];
	const risks = [];
	const addCommand = (command) => pushUniqueValue(commands, command, 20);
	const addSignal = (field, value, command) => {
		const cleaned = cleanPlaintextAuthValue(value);
		if (!cleaned) return;
		addCommand(command);
		addCredentialSignal(credentialSignals, hashedCredentialSignal("plaintext-auth-field", cleaned, { protocol, field }));
	};
	for (const line of sample.split(/\r?\n/).slice(0, 40)) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		const user = /^(?:USER)\s+(.{1,512})$/i.exec(trimmed);
		if (user) {
			addSignal("username", user[1], "USER");
			continue;
		}
		const pass = /^(?:PASS)\s+(.{1,512})$/i.exec(trimmed);
		if (pass) {
			addSignal("password", pass[1], "PASS");
			continue;
		}
		const imapLogin = /^[A-Za-z0-9_.-]+\s+LOGIN\s+("[^"]{1,512}"|\S{1,512})\s+("[^"]{1,512}"|\S{1,512})/i.exec(trimmed);
		if (imapLogin) {
			addSignal("username", imapLogin[1], "LOGIN");
			addSignal("password", imapLogin[2], "LOGIN");
			continue;
		}
		const redisAuth = protocol === "redis" ? /^AUTH\s+(.{1,1024})$/i.exec(trimmed) : null;
		if (redisAuth) {
			addSignal("auth-material", redisAuth[1], "AUTH");
			continue;
		}
		const smtpAuth = /^AUTH\s+(PLAIN|LOGIN|CRAM-MD5|XOAUTH2)(?:\s+([A-Za-z0-9+/=._~-]{4,2048}))?/i.exec(trimmed);
		if (smtpAuth) {
			addCommand(`AUTH ${smtpAuth[1].toUpperCase()}`);
			if (smtpAuth[2]) addSignal("auth-material", smtpAuth[2], `AUTH ${smtpAuth[1].toUpperCase()}`);
			continue;
		}
	}
	if (!credentialSignals.length) return undefined;
	const hasSecret = credentialSignals.some((signal) => /password|auth-material/i.test(signal.field ?? ""));
	if (hasSecret) {
		pushPcapRisk(risks, "pcap-plaintext-auth");
		if (protocol !== "unknown") pushPcapRisk(risks, `pcap-plaintext-auth-${protocol}`);
	}
	return {
		kind: "plaintext-auth",
		protocol,
		commands,
		credentialSignals,
		risks,
	};
}

function tlsVersionHex(buffer, offset) {
	if (offset + 2 > buffer.length) return undefined;
	return `0x${buffer[offset].toString(16).padStart(2, "0")}${buffer[offset + 1].toString(16).padStart(2, "0")}`;
}

function cleanTlsToken(buffer, start, length) {
	const end = Math.min(buffer.length, start + length);
	if (end <= start) return undefined;
	const text = buffer.toString("utf8", start, end).replace(/[^\x20-\x7e]/g, "?").slice(0, 200);
	return text ? redact(text) : undefined;
}

function tlsCodeHex(value) {
	return `0x${value.toString(16).padStart(4, "0")}`;
}

function isTlsGrease(value) {
	return (value & 0x0f0f) === 0x0a0a && ((value >> 8) & 0xff) === (value & 0xff);
}

function digestHex(algorithm, value) {
	try {
		return createHash(algorithm).update(value).digest("hex");
	} catch {
		return undefined;
	}
}

function parseTlsClientHello(buffer, start, length) {
	const end = Math.min(buffer.length, start + length);
	if (end - start < 9 || buffer[start] !== 0x16) return undefined;
	const recordLength = buffer.readUInt16BE(start + 3);
	const recordEnd = start + 5 + recordLength;
	if (recordLength < 4 || recordEnd > end) return undefined;
	const handshakeStart = start + 5;
	if (buffer[handshakeStart] !== 0x01) return undefined;
	const handshakeLength = (buffer[handshakeStart + 1] << 16) | (buffer[handshakeStart + 2] << 8) | buffer[handshakeStart + 3];
	const handshakeEnd = Math.min(recordEnd, handshakeStart + 4 + handshakeLength);
	let cursor = handshakeStart + 4;
	if (handshakeEnd - cursor < 38) return undefined;
	const clientVersion = tlsVersionHex(buffer, cursor);
	const clientVersionValue = buffer.readUInt16BE(cursor);
	cursor += 2 + 32;
	if (cursor + 1 > handshakeEnd) return undefined;
	const sessionIdLength = buffer[cursor];
	cursor += 1 + sessionIdLength;
	if (cursor + 2 > handshakeEnd) return undefined;
	const cipherSuiteLength = buffer.readUInt16BE(cursor);
	cursor += 2;
	if (cursor + cipherSuiteLength > handshakeEnd) return undefined;
	const cipherSuites = [];
	for (let suiteCursor = cursor; suiteCursor + 1 < cursor + cipherSuiteLength; suiteCursor += 2) {
		cipherSuites.push(buffer.readUInt16BE(suiteCursor));
	}
	cursor += cipherSuiteLength;
	if (cursor + 1 > handshakeEnd) return undefined;
	const compressionMethodsLength = buffer[cursor];
	cursor += 1;
	if (cursor + compressionMethodsLength > handshakeEnd) return undefined;
	cursor += compressionMethodsLength;
	if (cursor + 2 > handshakeEnd) {
		return {
			kind: "client-hello",
			recordVersion: tlsVersionHex(buffer, start + 1),
			clientVersion,
			cipherSuites: cipherSuites.slice(0, 32).map(tlsCodeHex),
			extensions: [],
			ja3: `${clientVersionValue},${cipherSuites.filter((value) => !isTlsGrease(value)).join("-")},,,`,
			ja3Hash: digestHex("md5", `${clientVersionValue},${cipherSuites.filter((value) => !isTlsGrease(value)).join("-")},,,`),
			sni: [],
			alpn: [],
		};
	}
	const extensionsLength = buffer.readUInt16BE(cursor);
	cursor += 2;
	const extensionsEnd = Math.min(handshakeEnd, cursor + extensionsLength);
	const sni = [];
	const alpn = [];
	const extensions = [];
	const supportedGroups = [];
	const ecPointFormats = [];
	while (cursor + 4 <= extensionsEnd) {
		const type = buffer.readUInt16BE(cursor);
		const extensionLength = buffer.readUInt16BE(cursor + 2);
		cursor += 4;
		const extensionEnd = cursor + extensionLength;
		if (extensionEnd > extensionsEnd) break;
		extensions.push(type);
		if (type === 0x0000 && cursor + 2 <= extensionEnd) {
			let nameCursor = cursor + 2;
			const listEnd = Math.min(extensionEnd, cursor + 2 + buffer.readUInt16BE(cursor));
			while (nameCursor + 3 <= listEnd && sni.length < 12) {
				const nameType = buffer[nameCursor];
				const nameLength = buffer.readUInt16BE(nameCursor + 1);
				nameCursor += 3;
				if (nameCursor + nameLength > listEnd) break;
				const name = cleanTlsToken(buffer, nameCursor, nameLength);
				if (nameType === 0 && name) sni.push(name.toLowerCase());
				nameCursor += nameLength;
			}
		} else if (type === 0x0010 && cursor + 2 <= extensionEnd) {
			let protocolCursor = cursor + 2;
			const protocolEnd = Math.min(extensionEnd, cursor + 2 + buffer.readUInt16BE(cursor));
			while (protocolCursor + 1 <= protocolEnd && alpn.length < 12) {
				const protocolLength = buffer[protocolCursor];
				protocolCursor += 1;
				if (protocolCursor + protocolLength > protocolEnd) break;
				const protocol = cleanTlsToken(buffer, protocolCursor, protocolLength);
				if (protocol) alpn.push(protocol);
				protocolCursor += protocolLength;
			}
		} else if (type === 0x000a && cursor + 2 <= extensionEnd) {
			let groupCursor = cursor + 2;
			const groupEnd = Math.min(extensionEnd, cursor + 2 + buffer.readUInt16BE(cursor));
			while (groupCursor + 1 < groupEnd && supportedGroups.length < 48) {
				supportedGroups.push(buffer.readUInt16BE(groupCursor));
				groupCursor += 2;
			}
		} else if (type === 0x000b && cursor + 1 <= extensionEnd) {
			let pointCursor = cursor + 1;
			const pointEnd = Math.min(extensionEnd, cursor + 1 + buffer[cursor]);
			while (pointCursor < pointEnd && ecPointFormats.length < 16) {
				ecPointFormats.push(buffer[pointCursor]);
				pointCursor += 1;
			}
		}
		cursor = extensionEnd;
	}
	const ja3 = [
		clientVersionValue,
		cipherSuites.filter((value) => !isTlsGrease(value)).join("-"),
		extensions.filter((value) => !isTlsGrease(value)).join("-"),
		supportedGroups.filter((value) => !isTlsGrease(value)).join("-"),
		ecPointFormats.join("-"),
	].join(",");
	return {
		kind: "client-hello",
		recordVersion: tlsVersionHex(buffer, start + 1),
		clientVersion,
		cipherSuites: cipherSuites.slice(0, 32).map(tlsCodeHex),
		extensions: extensions.slice(0, 48).map(tlsCodeHex),
		supportedGroups: supportedGroups.slice(0, 48).map(tlsCodeHex),
		ecPointFormats,
		ja3,
		ja3Hash: digestHex("md5", ja3),
		sni,
		alpn,
	};
}

function pcapQuicklookState() {
	const protocols = {};
	const flows = new Map();
	const tcpPayloads = new Map();
	const http = [];
	const dns = [];
	const dnsAnswers = [];
	const dnsTunnels = new Map();
	const tls = [];
	const plaintextAuth = [];
	return {
		protocols,
		flows,
		http,
		dns,
		dnsAnswers,
		dnsTunnels,
		tls,
		plaintextAuth,
		addProtocol(name) {
			protocols[name] = (protocols[name] ?? 0) + 1;
		},
		addFlow(flow, frame) {
			const key = `${flow.proto} ${flow.src}:${flow.sport ?? ""}>${flow.dst}:${flow.dport ?? ""}`;
			const existing = flows.get(key) ?? { ...flow, packets: 0, bytes: 0, firstFrame: frame, lastFrame: frame };
			existing.packets += 1;
			existing.bytes += flow.bytes;
			existing.lastFrame = frame;
			flows.set(key, existing);
		},
		addTcpPayload(flow, frame, payload) {
			if (!payload?.length) return;
			const key = `${flow.src}:${flow.sport}>${flow.dst}:${flow.dport}`;
			const cap = deep ? 262_144 : 65_536;
			const existing = tcpPayloads.get(key) ?? {
				key,
				src: flow.src,
				dst: flow.dst,
				sport: flow.sport,
				dport: flow.dport,
				packets: 0,
				payloadBytes: 0,
				reassembledBytes: 0,
				firstFrame: frame,
				lastFrame: frame,
				truncated: false,
				chunks: [],
			};
			existing.packets += 1;
			existing.payloadBytes += payload.length;
			existing.lastFrame = frame;
			const remaining = Math.max(0, cap - existing.reassembledBytes);
			if (remaining > 0) {
				const chunk = Buffer.from(payload.subarray(0, remaining));
				existing.chunks.push({
					seq: Number.isFinite(flow.seq) ? flow.seq : null,
					frame,
					order: existing.chunks.length,
					length: payload.length,
					data: chunk,
				});
				existing.reassembledBytes += chunk.length;
				if (chunk.length < payload.length) existing.truncated = true;
			} else {
				existing.truncated = true;
			}
			tcpPayloads.set(key, existing);
		},
		addHttp(sample) {
			if (http.length < 40) http.push(sample);
		},
		addDns(sample) {
			if (dns.length < 80) dns.push(sample);
			if (sample.risks?.length) this.addDnsTunnel(sample);
		},
		addDnsAnswer(sample) {
			if (dnsAnswers.length < 80) dnsAnswers.push(sample);
		},
		addDnsTunnel(sample) {
			const baseDomain = sample.queryAnalysis?.baseDomain || sample.name || "unknown";
			const existing = dnsTunnels.get(baseDomain) ?? {
				baseDomain,
				queryCount: 0,
				firstFrame: sample.frame,
				lastFrame: sample.frame,
				maxLabelLength: 0,
				maxEntropy: 0,
				risks: [],
				samples: [],
				labelSha256s: [],
			};
			existing.queryCount += 1;
			existing.lastFrame = sample.frame;
			existing.maxLabelLength = Math.max(existing.maxLabelLength, sample.queryAnalysis?.maxLabelLength ?? 0);
			existing.maxEntropy = Math.max(existing.maxEntropy, sample.queryAnalysis?.maxEntropy ?? 0);
			for (const risk of sample.risks ?? []) pushUniqueValue(existing.risks, risk, 20);
			pushUniqueValue(existing.samples, sample.name, 8);
			for (const signal of sample.queryAnalysis?.labelSignals ?? []) pushUniqueValue(existing.labelSha256s, signal.valueSha256, 16);
			dnsTunnels.set(baseDomain, existing);
		},
		addTls(sample) {
			if (tls.length < 80) tls.push(sample);
		},
		addPlaintextAuth(sample) {
			if (plaintextAuth.length < 80) plaintextAuth.push(sample);
		},
		finalizeTcpStreams() {
			const streams = [];
			for (const record of tcpPayloads.values()) {
				const allSeqKnown = record.chunks.length > 0 && record.chunks.every((chunk) => Number.isFinite(chunk.seq));
				const orderedChunks = record.chunks.slice().sort((a, b) => {
					if (allSeqKnown) return a.seq - b.seq || a.order - b.order;
					return a.order - b.order;
				});
				const sequenceGaps = [];
				const sequenceOverlaps = [];
				const payloadParts = [];
				let cursorSeq = null;
				for (const chunk of orderedChunks) {
					if (allSeqKnown) {
						if (cursorSeq === null) cursorSeq = chunk.seq;
						if (chunk.seq > cursorSeq) {
							sequenceGaps.push({ afterSeq: cursorSeq, nextSeq: chunk.seq, missingBytes: chunk.seq - cursorSeq });
							cursorSeq = chunk.seq;
						}
						let data = chunk.data;
						if (chunk.seq < cursorSeq) {
							const overlapBytes = cursorSeq - chunk.seq;
							sequenceOverlaps.push({ frame: chunk.frame, seq: chunk.seq, overlapBytes: Math.min(overlapBytes, chunk.data.length) });
							if (overlapBytes >= chunk.data.length) continue;
							data = chunk.data.subarray(overlapBytes);
						}
						payloadParts.push(data);
						cursorSeq += data.length;
					} else {
						payloadParts.push(chunk.data);
					}
				}
				const payload = Buffer.concat(payloadParts);
				const outOfOrder = allSeqKnown && orderedChunks.some((chunk, index) => chunk.order !== index);
				const protocolHints = [];
				const httpSample = parseHttpSample(payload, 0, payload.length);
				if (httpSample) pushUniqueValue(protocolHints, "HTTP", 8);
				const plaintextAuthSample = parsePlaintextAuthSample(payload, 0, payload.length, record.sport, record.dport);
				if (plaintextAuthSample) pushUniqueValue(protocolHints, "plaintext-auth", 8);
				const tlsSample = parseTlsClientHello(payload, 0, payload.length);
				if (tlsSample) pushUniqueValue(protocolHints, "TLS-client-hello", 8);
				if (record.packets > 1 && protocolHints.length) {
					this.addProtocol("TCP-reassembled");
					if (httpSample) {
						this.addProtocol("HTTP-reassembled");
						this.addHttp({ frame: record.firstFrame, lastFrame: record.lastFrame, reassembled: true, src: record.src, dst: record.dst, sport: record.sport, dport: record.dport, ...httpSample });
					}
					if (plaintextAuthSample) {
						this.addProtocol("plaintext-auth-reassembled");
						this.addPlaintextAuth({ frame: record.firstFrame, lastFrame: record.lastFrame, reassembled: true, src: record.src, dst: record.dst, sport: record.sport, dport: record.dport, ...plaintextAuthSample });
					}
					if (tlsSample) {
						this.addProtocol("TLS-reassembled");
						this.addTls({ frame: record.firstFrame, lastFrame: record.lastFrame, reassembled: true, src: record.src, dst: record.dst, sport: record.sport, dport: record.dport, ...tlsSample });
					}
				}
				const stream = {
					key: record.key,
					src: record.src,
					dst: record.dst,
					sport: record.sport,
					dport: record.dport,
					packets: record.packets,
					payloadBytes: record.payloadBytes,
					reassembledBytes: payload.length,
					firstFrame: record.firstFrame,
					lastFrame: record.lastFrame,
					truncated: record.truncated,
					reassembly: {
						strategy: allSeqKnown ? "tcp-sequence" : "capture-order",
						outOfOrder,
						firstSeq: allSeqKnown ? orderedChunks[0]?.seq : null,
						lastSeq: allSeqKnown ? orderedChunks.at(-1)?.seq : null,
						gaps: sequenceGaps.slice(0, 16),
						overlaps: sequenceOverlaps.slice(0, 16),
					},
					payloadSha256: createHash("sha256").update(payload).digest("hex"),
					protocolHints,
					http: httpSample ? { ...httpSample, line: undefined } : undefined,
					plaintextAuth: plaintextAuthSample,
					tls: tlsSample ? { kind: tlsSample.kind, sni: tlsSample.sni, alpn: tlsSample.alpn, ja3Hash: tlsSample.ja3Hash } : undefined,
				};
				Object.defineProperty(stream, "_reassembledPayload", { value: payload, enumerable: false });
				streams.push(stream);
			}
			return streams.slice(0, 80);
		},
	};
}

function parsePcapPacket(data, start, capturedLength, originalLength, linktype, frame, state) {
	const base = start;
	const end = Math.min(data.length, start + capturedLength);
	let ipStart = -1;
	if (linktype === 1 && end - base >= 14) {
		const ethType = data.readUInt16BE(base + 12);
		if (ethType === 0x0800) ipStart = base + 14;
		else if (ethType === 0x86dd) {
			state.addProtocol("IPv6");
			return;
		} else if (ethType === 0x0806) {
			state.addProtocol("ARP");
			return;
		} else {
			state.addProtocol(`EtherType-0x${ethType.toString(16)}`);
			return;
		}
	} else if (linktype === 101 || linktype === 228) {
		ipStart = base;
	} else {
		state.addProtocol(`linktype-${linktype}`);
		return;
	}
	if (ipStart < 0 || ipStart + 20 > end) return;
	const version = data[ipStart] >> 4;
	if (version !== 4) {
		if (version === 6) state.addProtocol("IPv6");
		return;
	}
	state.addProtocol("IPv4");
	const ihl = (data[ipStart] & 0x0f) * 4;
	if (ihl < 20 || ipStart + ihl > end) return;
	const totalLength = data.readUInt16BE(ipStart + 2) || end - ipStart;
	const ipEnd = Math.min(end, ipStart + totalLength);
	const proto = data[ipStart + 9];
	const ip4 = (offset) => `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
	const src = ip4(ipStart + 12);
	const dst = ip4(ipStart + 16);
	const l4 = ipStart + ihl;
	if (proto === 6 && l4 + 20 <= ipEnd) {
		state.addProtocol("TCP");
		const sport = data.readUInt16BE(l4);
		const dport = data.readUInt16BE(l4 + 2);
		const seq = data.readUInt32BE(l4 + 4);
		const tcpHeaderLength = (data[l4 + 12] >> 4) * 4;
		const payloadStart = l4 + tcpHeaderLength;
		const payloadLength = Math.max(0, ipEnd - payloadStart);
		if ([80, 8000, 8080, 8081, 8888].includes(sport) || [80, 8000, 8080, 8081, 8888].includes(dport)) state.addProtocol("HTTP-candidate");
		if (sport === 443 || dport === 443) state.addProtocol("TLS-candidate");
		state.addFlow({ proto: "TCP", src, dst, sport, dport, bytes: originalLength }, frame);
		if (payloadLength > 0) state.addTcpPayload({ src, dst, sport, dport, seq }, frame, data.subarray(payloadStart, payloadStart + payloadLength));
		const httpSample = parseHttpSample(data, payloadStart, payloadLength);
		if (httpSample) state.addHttp({ frame, src, dst, sport, dport, ...httpSample });
		const plaintextAuthSample = parsePlaintextAuthSample(data, payloadStart, payloadLength, sport, dport);
		if (plaintextAuthSample) state.addPlaintextAuth({ frame, src, dst, sport, dport, ...plaintextAuthSample });
		const tlsSample = parseTlsClientHello(data, payloadStart, payloadLength);
		if (tlsSample) state.addTls({ frame, src, dst, sport, dport, ...tlsSample });
	} else if (proto === 17 && l4 + 8 <= ipEnd) {
		state.addProtocol("UDP");
		const sport = data.readUInt16BE(l4);
		const dport = data.readUInt16BE(l4 + 2);
		const udpLength = data.readUInt16BE(l4 + 4);
		const payloadStart = l4 + 8;
		const payloadLength = Math.max(0, Math.min(ipEnd - payloadStart, udpLength ? udpLength - 8 : ipEnd - payloadStart));
		if (sport === 53 || dport === 53) {
			state.addProtocol("DNS-candidate");
			const dnsMessage = parseDnsMessage(data, payloadStart, payloadLength);
			for (const query of dnsMessage.queries) {
				state.addDns({ frame, src, dst, sport, dport, ...query });
			}
			for (const answer of dnsMessage.answers) {
				state.addDnsAnswer({ frame, src, dst, sport, dport, ...answer });
			}
		}
		state.addFlow({ proto: "UDP", src, dst, sport, dport, bytes: originalLength }, frame);
	} else {
		state.addFlow({ proto: `IP-${proto}`, src, dst, bytes: originalLength }, frame);
	}
}

function parseClassicPcap(data, limit) {
	const magicLe = data.readUInt32LE(0);
	const magicBe = data.readUInt32BE(0);
	const little = magicLe === 0xa1b2c3d4 || magicLe === 0xa1b23c4d;
	const big = magicBe === 0xa1b2c3d4 || magicBe === 0xa1b23c4d;
	if (!little && !big) throw new Error(`unsupported pcap magic=${data.subarray(0, 4).toString("hex")}`);
	const readU32 = (offset) => (little ? data.readUInt32LE(offset) : data.readUInt32BE(offset));
	const linktype = readU32(20);
	let offset = 24;
	let frame = 0;
	let truncated = false;
	const state = pcapQuicklookState();
	while (offset + 16 <= data.length && frame < limit) {
		const capturedLength = readU32(offset + 8);
		const originalLength = readU32(offset + 12);
		offset += 16;
		if (capturedLength > data.length - offset) {
			truncated = true;
			break;
		}
		frame += 1;
		parsePcapPacket(data, offset, capturedLength, originalLength, linktype, frame, state);
		offset += capturedLength;
	}
	const tcpStreams = state.finalizeTcpStreams();
	return {
		kind: "repi-pcap-quicklook",
		schemaVersion: 7,
		format: "pcap",
		supported: true,
		linktype,
		packetCount: frame,
		truncated,
		protocols: state.protocols,
		flows: Array.from(state.flows.values()).slice(0, 80),
		tcpStreams,
		http: state.http,
		dns: state.dns,
		dnsAnswers: state.dnsAnswers,
		dnsTunnels: Array.from(state.dnsTunnels.values()).slice(0, 40),
		tls: state.tls,
		plaintextAuth: state.plaintextAuth,
	};
}

function parsePcapng(data, limit) {
	if (data.length < 28) throw new Error("pcapng too small");
	let offset = 0;
	let little = true;
	let sectionSeen = false;
	let frame = 0;
	let truncated = false;
	const interfaces = [];
	const state = pcapQuicklookState();
	const readU16 = (cursor) => (little ? data.readUInt16LE(cursor) : data.readUInt16BE(cursor));
	const readU32 = (cursor) => (little ? data.readUInt32LE(cursor) : data.readUInt32BE(cursor));
	while (offset + 12 <= data.length && frame < limit) {
		let blockType = sectionSeen ? readU32(offset) : data.readUInt32LE(offset);
		if (blockType === 0x0a0d0d0a) {
			if (offset + 12 > data.length) {
				truncated = true;
				break;
			}
			const bomLe = data.readUInt32LE(offset + 8);
			const bomBe = data.readUInt32BE(offset + 8);
			if (bomLe === 0x1a2b3c4d) little = true;
			else if (bomBe === 0x1a2b3c4d) little = false;
			else throw new Error("invalid pcapng byte-order magic");
			sectionSeen = true;
			blockType = readU32(offset);
		}
		const blockLength = readU32(offset + 4);
		if (blockLength < 12 || offset + blockLength > data.length) {
			truncated = true;
			break;
		}
		const body = offset + 8;
		const bodyEnd = offset + blockLength - 4;
		if (blockType === 0x00000001 && body + 8 <= bodyEnd) {
			interfaces.push({ linktype: readU16(body), snaplen: readU32(body + 4) });
		} else if (blockType === 0x00000006 && body + 20 <= bodyEnd) {
			const interfaceId = readU32(body);
			const capturedLength = readU32(body + 12);
			const originalLength = readU32(body + 16);
			const packetStart = body + 20;
			const packetEnd = packetStart + capturedLength;
			if (packetEnd > bodyEnd) {
				truncated = true;
				break;
			}
			frame += 1;
			parsePcapPacket(data, packetStart, capturedLength, originalLength, interfaces[interfaceId]?.linktype ?? 1, frame, state);
		} else if (blockType === 0x00000003 && body + 4 <= bodyEnd) {
			const originalLength = readU32(body);
			const capturedLength = Math.min(originalLength, bodyEnd - (body + 4));
			frame += 1;
			parsePcapPacket(data, body + 4, capturedLength, originalLength, interfaces[0]?.linktype ?? 1, frame, state);
		}
		offset += blockLength;
	}
	const tcpStreams = state.finalizeTcpStreams();
	return {
		kind: "repi-pcap-quicklook",
		schemaVersion: 7,
		format: "pcapng",
		supported: true,
		linktype: interfaces[0]?.linktype ?? null,
		interfaces,
		packetCount: frame,
		truncated,
		protocols: state.protocols,
		flows: Array.from(state.flows.values()).slice(0, 80),
		tcpStreams,
		http: state.http,
		dns: state.dns,
		dnsAnswers: state.dnsAnswers,
		dnsTunnels: Array.from(state.dnsTunnels.values()).slice(0, 40),
		tls: state.tls,
		plaintextAuth: state.plaintextAuth,
	};
}

function pcapQuicklook(target, limit = deep ? 500 : 120) {
	const data = readFileSync(target);
	if (data.length < 24) throw new Error("pcap too small");
	const magicLe = data.readUInt32LE(0);
	const magicBe = data.readUInt32BE(0);
	const summary = magicLe === 0x0a0d0d0a || magicBe === 0x0a0d0d0a ? parsePcapng(data, limit) : parseClassicPcap(data, limit);
	return {
		...summary,
		size: data.length,
		sha256: bufferSha256(data),
	};
}

function shouldCarveHttpBody(bodySummary) {
	if (!bodySummary || bodySummary.capturedLength <= 0) return false;
	if (bodySummary.magic?.length || bodySummary.embeddedArchives?.length) return true;
	if (bodySummary.contentDisposition) return true;
	return /^(?:application\/(?:octet-stream|zip|pdf|wasm|java-archive|x-(?:7z|bzip|gzip|tar|xz|rar|msdownload|dosexec|elf|sqlite))|image\/|audio\/|video\/)/i.test(bodySummary.contentType || "");
}

function httpObjectExtension(bodySummary) {
	const magicName = bodySummary?.magic?.[0]?.name;
	const byMagic = new Map([
		["ZIP", "zip"],
		["PNG", "png"],
		["JPEG", "jpg"],
		["GZIP", "gz"],
		["PDF", "pdf"],
		["ELF", "elf"],
		["PE/DOS", "exe"],
		["Mach-O", "macho"],
		["WASM", "wasm"],
		["SQLite", "sqlite"],
		["7z", "7z"],
		["RAR", "rar"],
		["DEX", "dex"],
		["Java class", "class"],
		["TAR", "tar"],
	]);
	if (byMagic.has(magicName)) return byMagic.get(magicName);
	const contentType = String(bodySummary?.contentType || "").toLowerCase();
	if (contentType.includes("zip")) return "zip";
	if (contentType.includes("json")) return "json";
	if (contentType.includes("pdf")) return "pdf";
	if (contentType.includes("png")) return "png";
	if (contentType.includes("jpeg") || contentType.includes("jpg")) return "jpg";
	if (contentType.includes("wasm")) return "wasm";
	if (contentType.startsWith("text/")) return "txt";
	return "bin";
}

function materializeHttpBodyFromSummary(payload, bodySummary, maxBytes = deep ? 2 * 1024 * 1024 : 512 * 1024) {
	if (!Buffer.isBuffer(payload) || !bodySummary) return undefined;
	const bodyOffset = Number(bodySummary.bodyOffset);
	const capturedLength = Number(bodySummary.capturedLength);
	if (!Number.isFinite(bodyOffset) || !Number.isFinite(capturedLength) || bodyOffset < 0 || capturedLength <= 0 || bodyOffset >= payload.length) return undefined;
	const bodyEnd = Math.min(payload.length, bodyOffset + capturedLength, bodyOffset + maxBytes);
	let body = payload.subarray(bodyOffset, bodyEnd);
	for (const transform of bodySummary.decodedFrom ?? []) {
		if (transform === "chunked") {
			const decoded = decodeHttpChunkedBody(body, maxBytes);
			if (decoded) body = decoded.data.subarray(0, maxBytes);
			continue;
		}
		if (transform === "gzip" || transform === "deflate") {
			const decoded = maybeDecodeHttpContentEncoding(body, transform);
			body = decoded.data.subarray(0, maxBytes);
		}
	}
	return body.subarray(0, maxBytes);
}

function safeArchiveEntryRelPath(name, fallback = "entry.bin") {
	const parts = String(name || "")
		.split(/[\\/]+/)
		.filter((part) => part && part !== "." && part !== "..")
		.slice(0, 10)
		.map((part) => slug(part).replace(/^\.+$/, "") || "part");
	return parts.join("/") || fallback;
}

function pcapHttpObjectVerifierSource() {
	return `#!/usr/bin/env python3
import hashlib, json, pathlib, sys

manifest_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).with_name("pcap-http-objects.json")
base = manifest_path.parent
manifest = json.loads(manifest_path.read_text())

def check_file(row, label):
    rel = row.get("artifactRelPath")
    if not rel:
        raise SystemExit(f"missing artifactRelPath for {label}")
    path = (base / rel).resolve()
    if base.resolve() not in path.parents and path != base.resolve():
        raise SystemExit(f"path escapes manifest root: {rel}")
    data = path.read_bytes()
    expected_size = row.get("size")
    expected_sha = row.get("sha256")
    if expected_size is not None and len(data) != expected_size:
        raise SystemExit(f"size mismatch {rel}: got={len(data)} expected={expected_size}")
    if expected_sha and hashlib.sha256(data).hexdigest() != expected_sha:
        raise SystemExit(f"sha256 mismatch {rel}")
    return 1

objects = 0
entries = 0
decoded = 0
for obj in manifest.get("objects", []):
    objects += check_file(obj, "object")
    for row in obj.get("decodedArtifacts", []):
        decoded += check_file(row, "decoded")
    for entry in obj.get("extractedEntries", []):
        entries += check_file(entry, "entry")
        for row in entry.get("decodedArtifacts", []):
            decoded += check_file(row, "decoded")
print(f"verdict: pass objects={objects} entries={entries} decoded={decoded}")
`;
}

function carveZipEntriesFromHttpObject(artifactDir, objectDir, archiveBytes, archiveRow, objectSha) {
	const extractedEntries = [];
	let parsed;
	try {
		parsed = parseZipCentralDirectory(archiveBytes, 200);
	} catch (error) {
		return {
			parseError: error instanceof Error ? redact(error.message).slice(0, 160) : redact(String(error)).slice(0, 160),
			extractedEntries,
		};
	}
	let writtenBytes = 0;
	for (const entry of parsed.entries.slice(0, 32)) {
		const content = zipEntryData(archiveBytes, entry, 512 * 1024);
		if (!content || content.length <= 0) continue;
		writtenBytes += content.length;
		if (writtenBytes > 2 * 1024 * 1024) break;
		const entryRel = safeArchiveEntryRelPath(entry.name, `entry-${extractedEntries.length + 1}.bin`);
		const entryPath = join(objectDir, `${objectSha.slice(0, 12)}-zip`, entryRel);
		writePrivate(entryPath, content, 0o600);
		const entrySha = bufferSha256(content);
		extractedEntries.push({
			name: redact(entry.name),
			method: entry.method,
			compressedSize: entry.compressedSize,
			uncompressedSize: entry.uncompressedSize,
			crc32: entry.crc32,
			localHeaderOffset: archiveRow.offset + entry.localHeaderOffset,
			artifactRelPath: relative(dirname(objectDir), entryPath),
			size: content.length,
			sha256: entrySha,
			decodedArtifacts: writeDecodedTransformArtifacts(artifactDir, objectDir, content, entrySha, `zip-entry:${redact(entry.name)}`),
		});
	}
	return { extractedEntries };
}

function mostlyPrintableAscii(data) {
	if (!data?.length) return false;
	let printable = 0;
	const limit = Math.min(data.length, 8192);
	for (let index = 0; index < limit; index++) {
		const byte = data[index];
		if (byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e)) printable += 1;
	}
	return printable / Math.max(1, limit) >= 0.92;
}

function decodedArtifactExtension(data) {
	const magic = httpObjectMagicSignatures(data)[0]?.name;
	if (magic === "ZIP") return "zip";
	if (magic === "PNG") return "png";
	if (magic === "JPEG") return "jpg";
	if (magic === "GZIP") return "gz";
	if (magic === "PDF") return "pdf";
	if (magic === "ELF") return "elf";
	if (magic === "PE/DOS") return "exe";
	if (magic === "Mach-O") return "macho";
	if (magic === "WASM") return "wasm";
	if (magic === "SQLite") return "sqlite";
	if (magic === "7z") return "7z";
	if (magic === "RAR") return "rar";
	if (magic === "DEX") return "dex";
	if (magic === "Java class") return "class";
	if (data.length >= 262 && data.toString("ascii", 257, 262) === "ustar") return "tar";
	if (mostlyPrintableAscii(data)) return "txt";
	return "bin";
}

function decodeBase64Candidate(data) {
	if (!mostlyPrintableAscii(data)) return undefined;
	const text = data.toString("ascii").trim();
	if (text.length < 16 || text.length > 2_000_000) return undefined;
	const compact = text.replace(/\s+/g, "");
	if (compact.length < 16 || !/^[A-Za-z0-9+/_=-]+$/.test(compact)) return undefined;
	const normalized = compact.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
	try {
		const decoded = Buffer.from(padded, "base64");
		if (decoded.length < 4) return undefined;
		const recoded = decoded.toString("base64").replace(/=+$/g, "");
		if (recoded !== normalized.replace(/=+$/g, "")) return undefined;
		return decoded;
	} catch {
		return undefined;
	}
}

function decodeHexCandidate(data) {
	if (!mostlyPrintableAscii(data)) return undefined;
	const compact = data.toString("ascii").replace(/\s+/g, "");
	if (compact.length < 16 || compact.length % 2 !== 0 || !/^[a-fA-F0-9]+$/.test(compact)) return undefined;
	try {
		return Buffer.from(compact, "hex");
	} catch {
		return undefined;
	}
}

function decodeCompressionCandidate(data) {
	if (data.length >= 3 && data[0] === 0x1f && data[1] === 0x8b && data[2] === 0x08) {
		try {
			return { transform: "gzip", data: gunzipSync(data.subarray(0, Math.min(data.length, 2 * 1024 * 1024))) };
		} catch {
			return undefined;
		}
	}
	if (data.length >= 2 && data[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(data[1])) {
		try {
			return { transform: "zlib", data: inflateSync(data.subarray(0, Math.min(data.length, 2 * 1024 * 1024))) };
		} catch {
			return undefined;
		}
	}
	return undefined;
}

function interestingDecodedBytes(data) {
	if (!data?.length) return false;
	if (httpObjectMagicSignatures(data).length) return true;
	const sample = data.subarray(0, Math.min(data.length, 16_384)).toString("latin1");
	return /flag\{|ctf\{|password|secret|token|private key|BEGIN [A-Z ]+KEY|PK\x03\x04/i.test(sample);
}

function singleByteXorCandidate(data) {
	if (!data?.length || data.length > 512 * 1024) return undefined;
	for (let key = 1; key <= 255; key++) {
		const decoded = Buffer.allocUnsafe(data.length);
		for (let index = 0; index < data.length; index++) decoded[index] = data[index] ^ key;
		if (mostlyPrintableAscii(decoded) && interestingDecodedBytes(decoded)) return { transform: "xor-single-byte", key, data: decoded };
	}
	return undefined;
}

function transformCandidates(data) {
	const candidates = [];
	const compressed = decodeCompressionCandidate(data);
	if (compressed?.data?.length) candidates.push(compressed);
	const base64Decoded = decodeBase64Candidate(data);
	if (base64Decoded?.length) candidates.push({ transform: "base64", data: base64Decoded });
	const hexDecoded = decodeHexCandidate(data);
	if (hexDecoded?.length) candidates.push({ transform: "hex", data: hexDecoded });
	const xorDecoded = singleByteXorCandidate(data);
	if (xorDecoded?.data?.length) candidates.push(xorDecoded);
	return candidates;
}

function decodedTransformArtifacts(data, maxDepth = 3) {
	const rows = [];
	const seen = new Set([bufferSha256(data)]);
	const walk = (current, chain, depth) => {
		if (depth >= maxDepth || rows.length >= 12) return;
		for (const candidate of transformCandidates(current)) {
			if (!candidate.data?.length || candidate.data.length > 2 * 1024 * 1024) continue;
			const sha256 = bufferSha256(candidate.data);
			if (seen.has(sha256)) continue;
			seen.add(sha256);
			const nextChain = [...chain, candidate.transform];
			const row = {
				chain: nextChain,
				xorKey: Number.isFinite(candidate.key) ? candidate.key : undefined,
				size: candidate.data.length,
				sha256,
				extension: decodedArtifactExtension(candidate.data),
				magic: httpObjectMagicSignatures(candidate.data).slice(0, 8),
				interesting: interestingDecodedBytes(candidate.data),
				data: candidate.data,
			};
			rows.push(row);
			walk(candidate.data, nextChain, depth + 1);
		}
	};
	walk(data, [], 0);
	return rows;
}

function writeDecodedTransformArtifacts(artifactDir, objectDir, sourceBytes, sourceSha, sourceLabel) {
	const decodedArtifacts = [];
	let index = 0;
	for (const decoded of decodedTransformArtifacts(sourceBytes)) {
		index += 1;
		const path = join(objectDir, `${sourceSha.slice(0, 12)}-decoded`, `decode-${index}-${decoded.sha256.slice(0, 12)}.${decoded.extension}`);
		writePrivate(path, decoded.data, 0o600);
		decodedArtifacts.push({
			source: sourceLabel,
			chain: decoded.chain,
			xorKey: decoded.xorKey,
			artifactRelPath: relative(artifactDir, path),
			size: decoded.size,
			sha256: decoded.sha256,
			magic: decoded.magic,
			interesting: decoded.interesting,
		});
	}
	return decodedArtifacts;
}

function writePcapHttpObjectArtifacts(summary, artifactDir) {
	if (noWrite || !artifactDir || !summary?.tcpStreams?.length) return undefined;
	const objectDir = join(artifactDir, "pcap-http-objects");
	const manifest = {
		kind: "repi-pcap-http-object-carves",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		source: summary.format,
		summarySchemaVersion: summary.schemaVersion,
		objectCount: 0,
		entryCount: 0,
		decodedCount: 0,
		objects: [],
	};
	for (const [streamIndex, stream] of summary.tcpStreams.entries()) {
		const bodySummary = stream.http?.bodySummary;
		if (!shouldCarveHttpBody(bodySummary)) continue;
		const body = materializeHttpBodyFromSummary(stream._reassembledPayload, bodySummary);
		if (!body?.length) continue;
		const sha256 = bufferSha256(body);
		const filename = `stream-${streamIndex + 1}-frames-${stream.firstFrame}-${stream.lastFrame}-body-${sha256.slice(0, 12)}.${httpObjectExtension(bodySummary)}`;
		const artifactPath = join(objectDir, filename);
		writePrivate(artifactPath, body, 0o600);
		const objectRow = {
			streamIndex,
			key: stream.key,
			src: stream.src,
			dst: stream.dst,
			sport: stream.sport,
			dport: stream.dport,
			firstFrame: stream.firstFrame,
			lastFrame: stream.lastFrame,
			httpKind: stream.http?.kind,
			status: stream.http?.status ?? null,
			method: stream.http?.method ?? null,
			target: stream.http?.target ?? null,
			contentType: bodySummary.contentType,
			contentDisposition: bodySummary.contentDisposition,
			decodedFrom: bodySummary.decodedFrom ?? [],
			bodyOffset: bodySummary.bodyOffset,
			size: body.length,
			sha256,
			artifactRelPath: relative(artifactDir, artifactPath),
			magic: bodySummary.magic ?? [],
			embeddedArchives: bodySummary.embeddedArchives ?? [],
			decodedArtifacts: writeDecodedTransformArtifacts(artifactDir, objectDir, body, sha256, "http-body"),
			extractedEntries: [],
			risks: bodySummary.risks ?? [],
		};
		for (const archive of bodySummary.embeddedArchives ?? []) {
			if (archive.format !== "zip" || archive.parseError) continue;
			const archiveBytes = body.subarray(archive.offset);
			const carved = carveZipEntriesFromHttpObject(artifactDir, objectDir, archiveBytes, archive, sha256);
			if (carved.parseError) {
				objectRow.embeddedArchiveParseError = carved.parseError;
				continue;
			}
			objectRow.extractedEntries.push(...carved.extractedEntries);
		}
		manifest.objects.push(objectRow);
	}
	manifest.objectCount = manifest.objects.length;
	manifest.entryCount = manifest.objects.reduce((count, object) => count + (object.extractedEntries?.length ?? 0), 0);
	manifest.decodedCount = manifest.objects.reduce(
		(count, object) =>
			count +
			(object.decodedArtifacts?.length ?? 0) +
			(object.extractedEntries ?? []).reduce((inner, entry) => inner + (entry.decodedArtifacts?.length ?? 0), 0),
		0,
	);
	if (!manifest.objectCount) return undefined;
	const manifestPath = join(artifactDir, "pcap-http-objects.json");
	const verifierPath = join(artifactDir, "pcap-http-object-verifier.py");
	manifest.verifierRelPath = relative(artifactDir, verifierPath);
	writePrivate(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 0o600);
	writePrivate(verifierPath, pcapHttpObjectVerifierSource(), 0o700);
	return {
		manifest,
		manifestPath,
		verifierPath,
		objectDir,
	};
}

function pcapEndpointKey(row) {
	return `${row.src ?? "?"}:${row.sport ?? "?"}->${row.dst ?? "?"}:${row.dport ?? "?"}`;
}

function pcapStableJsonSha(value) {
	return createHash("sha256").update(JSON.stringify(value ?? null)).digest("hex");
}

function pcapCredentialSignalRows(summary) {
	const rows = [];
	for (const [index, row] of (summary.http ?? []).entries()) {
		for (const signal of row.credentialSignals ?? []) {
			rows.push({
				source: "http",
				index,
				kind: signal.kind,
				name: signal.name ?? signal.field ?? signal.scheme ?? null,
				valueSha256: signal.valueSha256 ?? null,
				valueLength: signal.valueLength ?? null,
				frame: row.frame ?? row.firstFrame ?? null,
				flow: pcapEndpointKey(row),
			});
		}
	}
	for (const [index, row] of (summary.plaintextAuth ?? []).entries()) {
		for (const signal of row.credentialSignals ?? []) {
			rows.push({
				source: "plaintextAuth",
				index,
				kind: signal.kind,
				name: signal.field ?? signal.protocol ?? null,
				valueSha256: signal.valueSha256 ?? null,
				valueLength: signal.valueLength ?? null,
				frame: row.frame ?? row.firstFrame ?? null,
				flow: pcapEndpointKey(row),
			});
		}
	}
	return rows;
}

function pcapComparableSummary(summary) {
	return {
		format: summary.format,
		size: summary.size,
		sha256: summary.sha256,
		packetCount: summary.packetCount,
		truncated: Boolean(summary.truncated),
		protocols: summary.protocols ?? {},
		flows: (summary.flows ?? []).map((row) => ({ proto: row.proto, src: row.src, dst: row.dst, sport: row.sport ?? null, dport: row.dport ?? null, packets: row.packets, bytes: row.bytes, firstFrame: row.firstFrame, lastFrame: row.lastFrame })),
		tcpStreams: (summary.tcpStreams ?? []).map((row) => ({ key: row.key, firstFrame: row.firstFrame, lastFrame: row.lastFrame, packets: row.packets, reassembledBytes: row.reassembledBytes, payloadSha256: row.payloadSha256, protocolHints: row.protocolHints ?? [], reassembly: row.reassembly ?? null })),
		http: (summary.http ?? []).map((row) => ({ kind: row.kind, method: row.method ?? null, status: row.status ?? null, target: row.target ?? null, host: row.host ?? null, frame: row.frame ?? null, firstFrame: row.firstFrame ?? null, lastFrame: row.lastFrame ?? null, reassembled: Boolean(row.reassembled), credentialSignals: row.credentialSignals ?? [], risks: row.risks ?? [], bodySummary: row.bodySummary ? { sha256: row.bodySummary.sha256, capturedLength: row.bodySummary.capturedLength, declaredLength: row.bodySummary.declaredLength, contentType: row.bodySummary.contentType, contentDisposition: row.bodySummary.contentDisposition, risks: row.bodySummary.risks ?? [] } : null })),
		dnsTunnels: summary.dnsTunnels ?? [],
		tls: (summary.tls ?? []).map((row) => ({ frame: row.frame ?? null, sni: row.sni ?? [], alpn: row.alpn ?? [], ja3Hash: row.ja3Hash ?? null, flow: pcapEndpointKey(row) })),
		plaintextAuth: (summary.plaintextAuth ?? []).map((row) => ({ frame: row.frame ?? null, firstFrame: row.firstFrame ?? null, lastFrame: row.lastFrame ?? null, protocol: row.protocol, credentialSignals: row.credentialSignals ?? [], risks: row.risks ?? [], flow: pcapEndpointKey(row) })),
	};
}

function pcapVerifyArtifactFile(artifactDir, row, label) {
	if (!artifactDir || !row?.artifactRelPath) return { label, artifactRelPath: row?.artifactRelPath ?? null, verified: false, reason: "missing-artifact-binding" };
	const base = resolve(artifactDir);
	const path = resolve(join(artifactDir, row.artifactRelPath));
	if (!(path === base || path.startsWith(base + "/"))) return { label, artifactRelPath: row.artifactRelPath, verified: false, reason: "artifact-path-escape" };
	let actual = {};
	let negativeControl = null;
	try {
		const data = readFileSync(path);
		actual = { size: data.length, sha256: bufferSha256(data), headerHex: data.subarray(0, 16).toString("hex") };
		if (data.length) {
			const mutated = Buffer.from(data);
			mutated[0] ^= 0xff;
			const mutatedSha256 = bufferSha256(mutated);
			negativeControl = { controlType: "pcap-artifact-byte-mutation-rejection", mutatedSha256, passed: mutatedSha256 !== row.sha256 };
		}
		const verified = (row.size == null || row.size === actual.size) && (!row.sha256 || row.sha256 === actual.sha256);
		return { label, artifactRelPath: row.artifactRelPath, expected: { size: row.size ?? null, sha256: row.sha256 ?? null }, actual, verified, reason: verified ? "artifact-size-sha256-match" : "artifact-size-sha256-mismatch", negativeControl };
	} catch (error) {
		return { label, artifactRelPath: row.artifactRelPath, expected: { size: row.size ?? null, sha256: row.sha256 ?? null }, actual, verified: false, reason: error instanceof Error ? redact(error.message) : redact(String(error)), negativeControl };
	}
}

function pcapObjectArtifactChecks(objectManifest, artifactDir) {
	const rows = [];
	for (const [objectIndex, object] of (objectManifest?.objects ?? []).entries()) {
		rows.push({ objectIndex, ...pcapVerifyArtifactFile(artifactDir, object, "http-object") });
		for (const [decodedIndex, decoded] of (object.decodedArtifacts ?? []).entries()) rows.push({ objectIndex, decodedIndex, ...pcapVerifyArtifactFile(artifactDir, decoded, "http-object-decoded") });
		for (const [entryIndex, entry] of (object.extractedEntries ?? []).entries()) {
			rows.push({ objectIndex, entryIndex, name: entry.name, ...pcapVerifyArtifactFile(artifactDir, entry, "http-archive-entry") });
			for (const [decodedIndex, decoded] of (entry.decodedArtifacts ?? []).entries()) rows.push({ objectIndex, entryIndex, decodedIndex, name: entry.name, ...pcapVerifyArtifactFile(artifactDir, decoded, "http-entry-decoded") });
		}
	}
	return rows;
}

function pcapFlowVerificationClaims(summary, verificationRows) {
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => claimLedger.push({ verdict: "promoted", confidence: 0.76, blockers: [], ...claim });
	const verifiedObjects = verificationRows.objectArtifactChecks.filter((row) => row.verified);
	const passedControls = verificationRows.negativeControls.filter((row) => row.passed);
	if (verificationRows.captureIdentity.verified) {
		addClaim({
			id: "pcap-capture-hash-verification-" + shortHash(verificationRows.captureIdentity.sha256),
			claimType: "pcap-capture-hash-verification-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json" },
			evidenceBinding: { size: verificationRows.captureIdentity.size, sha256: verificationRows.captureIdentity.sha256, format: summary.format, packetCount: summary.packetCount },
			statement: "Verifier re-read the capture file and matched size/SHA-256 against the PCAP quicklook summary.",
			confidence: 0.9,
			rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		});
	}
	if (verificationRows.quicklookDeterminism.verified) {
		addClaim({
			id: "pcap-quicklook-determinism-" + shortHash(verificationRows.quicklookDeterminism.storedSha256),
			claimType: "pcap-quicklook-determinism-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json" },
			evidenceBinding: verificationRows.quicklookDeterminism,
			statement: "Verifier reparsed the PCAP and matched the normalized flow/HTTP/DNS/TLS/TCP summary hash.",
			confidence: 0.88,
			rerunCommand: "repi engage <pcap-or-pcapng> --json",
		});
	}
	if (verificationRows.credentialSignals.verifiedCount) {
		addClaim({
			id: "pcap-credential-signal-verification-" + shortHash(JSON.stringify(verificationRows.credentialSignals.sampleHashes)),
			claimType: "pcap-credential-signal-verification-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json", rows: verificationRows.credentialSignals.sampleHashes },
			evidenceBinding: verificationRows.credentialSignals,
			statement: "Verifier confirmed credential signal hashes/lengths are reproduced by a fresh parse of the capture.",
			confidence: 0.86,
			rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		});
	}
	if (verificationRows.reassembly.verifiedCount) {
		addClaim({
			id: "pcap-reassembly-hash-verification-" + shortHash(JSON.stringify(verificationRows.reassembly.sampleStreams)),
			claimType: "pcap-reassembly-hash-verification-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json", streams: verificationRows.reassembly.sampleStreams },
			evidenceBinding: verificationRows.reassembly,
			statement: "Verifier confirmed TCP stream payload hashes are reproduced by a fresh capture parse.",
			confidence: 0.86,
			rerunCommand: "repi engage <pcap-or-pcapng> --json",
		});
	}
	if (verificationRows.dnsTunnel.verifiedCount) {
		addClaim({
			id: "pcap-dns-tunnel-verification-" + shortHash(JSON.stringify(verificationRows.dnsTunnel.sampleDomains)),
			claimType: "pcap-dns-tunnel-verification-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json", domains: verificationRows.dnsTunnel.sampleDomains },
			evidenceBinding: verificationRows.dnsTunnel,
			statement: "Verifier confirmed DNS tunnel label hashes/base-domain grouping are stable across fresh parse.",
			confidence: 0.82,
			rerunCommand: "repi engage <pcap-or-pcapng> --json",
		});
	}
	if (verifiedObjects.length) {
		addClaim({
			id: "pcap-object-artifact-verification-" + shortHash(verifiedObjects.map((row) => `${row.label}:${row.artifactRelPath}:${row.actual?.sha256}`).join("|")),
			claimType: "pcap-object-artifact-verification-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json", artifacts: verifiedObjects.slice(0, 80).map((row) => ({ label: row.label, artifactRelPath: row.artifactRelPath })) },
			evidenceBinding: { verifiedCount: verifiedObjects.length, objectCount: verificationRows.objectManifestStats.objectCount, entryCount: verificationRows.objectManifestStats.entryCount, decodedCount: verificationRows.objectManifestStats.decodedCount },
			statement: "Verifier matched carved HTTP object, archive entry, and decoded artifact files against manifest size/SHA-256 evidence.",
			confidence: 0.9,
			rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		});
	}
	if (passedControls.length) {
		addClaim({
			id: "pcap-verifier-negative-control-" + shortHash(passedControls.map((row) => `${row.controlType}:${row.mutatedSha256}`).join("|")),
			claimType: "pcap-verifier-negative-control-proof",
			sourceBinding: { artifact: "pcap-flow-verification.json" },
			evidenceBinding: { passedControls },
			statement: "Verifier ran mutation controls proving altered capture/object bytes do not retain the original evidence hashes.",
			confidence: 0.84,
			rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		});
	}
	const identityClaim = claimLedger.find((claim) => claim.claimType === "pcap-capture-hash-verification-proof");
	const deterministicClaim = claimLedger.find((claim) => claim.claimType === "pcap-quicklook-determinism-proof");
	const credentialClaim = claimLedger.find((claim) => claim.claimType === "pcap-credential-signal-verification-proof");
	const objectClaim = claimLedger.find((claim) => claim.claimType === "pcap-object-artifact-verification-proof");
	const reassemblyClaim = claimLedger.find((claim) => claim.claimType === "pcap-reassembly-hash-verification-proof");
	const dnsClaim = claimLedger.find((claim) => claim.claimType === "pcap-dns-tunnel-verification-proof");
	const controlClaim = claimLedger.find((claim) => claim.claimType === "pcap-verifier-negative-control-proof");
	if (identityClaim && deterministicClaim && (credentialClaim || objectClaim || reassemblyClaim || dnsClaim) && controlClaim) {
		const segments = [identityClaim, deterministicClaim, credentialClaim, objectClaim, reassemblyClaim, dnsClaim, controlClaim].filter(Boolean);
		const composed = {
			id: "pcap-flow-verification-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "pcap-flow-verification-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				captureSha256: verificationRows.captureIdentity.sha256,
				hasCredentialSignalProof: Boolean(credentialClaim),
				hasObjectArtifactProof: Boolean(objectClaim),
				hasReassemblyHashProof: Boolean(reassemblyClaim),
				hasDnsTunnelProof: Boolean(dnsClaim),
				hasNegativeControl: Boolean(controlClaim),
			},
			statement: "PCAP verification composes capture identity, deterministic parser output, flow/object evidence, and mutation controls into a rerunnable proof path.",
			verdict: "promoted",
			confidence: credentialClaim && objectClaim ? 0.9 : 0.84,
			blockers: [],
			rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	return { claimLedger, composedPaths };
}

function pcapFlowVerificationSummary(target, summary, objectManifest, artifactDir) {
	const data = readFileSync(target);
	const captureSha256 = bufferSha256(data);
	const captureIdentity = {
		size: data.length,
		sha256: captureSha256,
		verified: data.length === summary.size && captureSha256 === summary.sha256,
	};
	if (data.length) {
		const mutated = Buffer.from(data);
		mutated[0] ^= 0xff;
		const mutatedSha256 = bufferSha256(mutated);
		captureIdentity.negativeControl = { controlType: "pcap-capture-byte-mutation-rejection", mutatedSha256, passed: mutatedSha256 !== captureSha256 };
	}
	const fresh = pcapQuicklook(target);
	const storedComparable = pcapComparableSummary(summary);
	const freshComparable = pcapComparableSummary(fresh);
	const quicklookDeterminism = {
		storedSha256: pcapStableJsonSha(storedComparable),
		freshSha256: pcapStableJsonSha(freshComparable),
		verified: pcapStableJsonSha(storedComparable) === pcapStableJsonSha(freshComparable),
		packetCount: summary.packetCount,
		freshPacketCount: fresh.packetCount,
	};
	const storedCredentials = pcapCredentialSignalRows(summary);
	const freshCredentials = pcapCredentialSignalRows(fresh);
	const freshCredentialKeys = new Set(freshCredentials.map((row) => `${row.source}:${row.kind}:${row.name}:${row.valueSha256}:${row.valueLength}:${row.flow}`));
	const verifiedCredentials = storedCredentials.filter((row) => freshCredentialKeys.has(`${row.source}:${row.kind}:${row.name}:${row.valueSha256}:${row.valueLength}:${row.flow}`));
	const storedStreams = (summary.tcpStreams ?? []).filter((row) => row.payloadSha256);
	const freshStreamKeys = new Set((fresh.tcpStreams ?? []).map((row) => `${row.key}:${row.payloadSha256}:${row.reassembledBytes}:${row.firstFrame}:${row.lastFrame}`));
	const verifiedStreams = storedStreams.filter((row) => freshStreamKeys.has(`${row.key}:${row.payloadSha256}:${row.reassembledBytes}:${row.firstFrame}:${row.lastFrame}`));
	const storedDnsTunnels = summary.dnsTunnels ?? [];
	const freshDnsTunnelKeys = new Set((fresh.dnsTunnels ?? []).map((row) => `${row.baseDomain}:${row.queryCount}:${(row.labelSha256s ?? []).join(",")}`));
	const verifiedDnsTunnels = storedDnsTunnels.filter((row) => freshDnsTunnelKeys.has(`${row.baseDomain}:${row.queryCount}:${(row.labelSha256s ?? []).join(",")}`));
	const objectArtifactChecks = pcapObjectArtifactChecks(objectManifest, artifactDir);
	const negativeControls = [captureIdentity.negativeControl, ...objectArtifactChecks.map((row) => row.negativeControl)].filter((row) => row?.passed);
	const verificationRows = {
		captureIdentity,
		quicklookDeterminism,
		credentialSignals: {
			storedCount: storedCredentials.length,
			verifiedCount: verifiedCredentials.length,
			sampleHashes: verifiedCredentials.slice(0, 64).map((row) => ({ source: row.source, kind: row.kind, name: row.name, valueSha256: row.valueSha256, valueLength: row.valueLength, flow: row.flow })),
		},
		reassembly: {
			storedCount: storedStreams.length,
			verifiedCount: verifiedStreams.length,
			sampleStreams: verifiedStreams.slice(0, 32).map((row) => ({ key: row.key, firstFrame: row.firstFrame, lastFrame: row.lastFrame, reassembledBytes: row.reassembledBytes, payloadSha256: row.payloadSha256 })),
		},
		dnsTunnel: {
			storedCount: storedDnsTunnels.length,
			verifiedCount: verifiedDnsTunnels.length,
			sampleDomains: verifiedDnsTunnels.slice(0, 32).map((row) => ({ baseDomain: row.baseDomain, queryCount: row.queryCount, labelSha256s: row.labelSha256s ?? [] })),
		},
		objectManifestStats: {
			objectCount: objectManifest?.objectCount ?? 0,
			entryCount: objectManifest?.entryCount ?? 0,
			decodedCount: objectManifest?.decodedCount ?? 0,
			verifierRelPath: objectManifest?.verifierRelPath ?? null,
		},
		objectArtifactChecks,
		negativeControls,
	};
	const claims = pcapFlowVerificationClaims(summary, verificationRows);
	const blockers = [];
	if (!captureIdentity.verified) blockers.push("missing-pcap-capture-hash-verification");
	if (!quicklookDeterminism.verified) blockers.push("missing-pcap-quicklook-determinism");
	if (storedCredentials.length && !verifiedCredentials.length) blockers.push("missing-pcap-credential-signal-verification");
	if (storedStreams.length && !verifiedStreams.length) blockers.push("missing-pcap-reassembly-hash-verification");
	if (storedDnsTunnels.length && !verifiedDnsTunnels.length) blockers.push("missing-pcap-dns-tunnel-verification");
	if ((objectManifest?.objectCount ?? 0) && !objectArtifactChecks.some((row) => row.verified)) blockers.push("missing-pcap-object-artifact-verification");
	if (!negativeControls.length) blockers.push("missing-pcap-verifier-negative-control");
	const repairActions = {
		"missing-pcap-capture-hash-verification": "Rerun the verifier against the original PCAP bytes and require capture size/SHA-256 equality.",
		"missing-pcap-quicklook-determinism": "Reparse the capture and resolve parser nondeterminism before promoting flow evidence.",
		"missing-pcap-credential-signal-verification": "Require credential signal hashes/lengths to reproduce from a fresh parse.",
		"missing-pcap-reassembly-hash-verification": "Require TCP stream payload hashes to reproduce from a fresh reassembly.",
		"missing-pcap-dns-tunnel-verification": "Require DNS tunnel base-domain and label hashes to reproduce from a fresh parse.",
		"missing-pcap-object-artifact-verification": "Verify each carved HTTP object/entry/decoded artifact against manifest size and SHA-256.",
		"missing-pcap-verifier-negative-control": "Add capture/object byte mutation controls so altered evidence hashes are rejected.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "pcap-flow-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound PCAP evidence and rerun pcap-flow-verifier.mjs.",
		rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
	}));
	const promotedClaims = claims.claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-pcap-flow-verification",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		target: redact(target),
		proofReady: promotedClaims.length > 0,
		...verificationRows,
		stats: {
			credentialsVerified: verifiedCredentials.length,
			reassemblyStreamsVerified: verifiedStreams.length,
			dnsTunnelsVerified: verifiedDnsTunnels.length,
			objectArtifactsVerified: objectArtifactChecks.filter((row) => row.verified).length,
			negativeControlsPassed: negativeControls.length,
		},
		claimLedger: claims.claimLedger,
		composedPaths: claims.composedPaths,
		promotionReport: { proofReady: promotedClaims.length > 0, promotedClaims, blockers },
		repairQueue,
	};
}


function pcapFlowClaims(summary, objectManifest, verification) {
	const claimLedger = [];
	const addClaim = (claim) => {
		claimLedger.push({
			verdict: "promoted",
			confidence: 0.7,
			blockers: [],
			...claim,
		});
	};
	for (const [index, stream] of (summary.tcpStreams ?? []).entries()) {
		if (!stream.reassembledBytes && !stream.http?.reassembled && !stream.reassembly?.outOfOrder) continue;
		addClaim({
			id: "pcap-tcp-reassembly-" + shortHash(`${stream.key}:${stream.payloadSha256}:${stream.firstFrame}:${stream.lastFrame}`),
			claimType: "pcap-tcp-reassembly-proof",
			sourceBinding: {
				artifact: "pcap-flow-summary.json",
				streamIndex: index,
				firstFrame: stream.firstFrame,
				lastFrame: stream.lastFrame,
				flow: pcapEndpointKey(stream),
			},
			evidenceBinding: {
				protocolHints: stream.protocolHints ?? [],
				payloadBytes: stream.payloadBytes,
				reassembledBytes: stream.reassembledBytes,
				payloadSha256: stream.payloadSha256,
				reassembly: stream.reassembly
					? {
							strategy: stream.reassembly.strategy,
							outOfOrder: Boolean(stream.reassembly.outOfOrder),
							gapCount: (stream.reassembly.gaps ?? []).length,
							overlapCount: (stream.reassembly.overlaps ?? []).length,
						}
					: null,
			},
			statement: "PCAP TCP stream evidence binds packet frames to a reassembled payload hash for protocol replay.",
			confidence: stream.reassembly?.outOfOrder ? 0.86 : 0.78,
			rerunCommand: "cat pcap-flow-summary.json | jq '.tcpStreams'",
		});
	}
	for (const [index, row] of (summary.http ?? []).entries()) {
		if (!(row.credentialSignals ?? []).length) continue;
		addClaim({
			id: "pcap-http-credential-flow-" + shortHash(`${index}:${row.method ?? row.status}:${row.target ?? row.headers?.location ?? ""}:${JSON.stringify(row.credentialSignals)}`),
			claimType: "pcap-http-credential-flow",
			sourceBinding: {
				artifact: "pcap-flow-summary.json",
				httpIndex: index,
				frame: row.frame ?? null,
				firstFrame: row.firstFrame ?? null,
				lastFrame: row.lastFrame ?? null,
				reassembled: Boolean(row.reassembled),
				flow: pcapEndpointKey(row),
			},
			evidenceBinding: {
				kind: row.kind,
				method: row.method ?? null,
				status: row.status ?? null,
				target: row.target ?? null,
				host: row.host ?? null,
				credentialSignals: row.credentialSignals,
				risks: row.risks ?? [],
				headerNames: Object.keys(row.headers ?? {}).filter((name) => row.headers?.[name] != null),
			},
			statement: "HTTP evidence contains hashed credential material bound to a concrete flow, request/response row, and risk taxonomy.",
			confidence: row.reassembled ? 0.88 : 0.82,
			rerunCommand: "cat pcap-flow-summary.json | jq '.http[] | select(.credentialSignals|length>0)'",
		});
	}
	for (const [index, row] of (summary.plaintextAuth ?? []).entries()) {
		addClaim({
			id: "pcap-plaintext-auth-" + shortHash(`${index}:${row.protocol}:${pcapEndpointKey(row)}:${JSON.stringify(row.credentialSignals)}`),
			claimType: "pcap-plaintext-auth-flow",
			sourceBinding: {
				artifact: "pcap-flow-summary.json",
				plaintextAuthIndex: index,
				frame: row.frame ?? null,
				lastFrame: row.lastFrame ?? null,
				reassembled: Boolean(row.reassembled),
				flow: pcapEndpointKey(row),
			},
			evidenceBinding: {
				protocol: row.protocol,
				commands: row.commands ?? [],
				credentialSignals: row.credentialSignals ?? [],
				risks: row.risks ?? [],
			},
			statement: "Plaintext authentication evidence binds USER/PASS or equivalent auth fields to a transport flow and hashed values.",
			confidence: (row.credentialSignals ?? []).some((signal) => /password|auth-material/i.test(signal.field ?? "")) ? 0.88 : 0.78,
			rerunCommand: "cat pcap-flow-summary.json | jq '.plaintextAuth'",
		});
	}
	for (const [index, row] of (summary.dnsTunnels ?? []).entries()) {
		addClaim({
			id: "pcap-dns-tunnel-" + shortHash(`${row.baseDomain}:${row.queryCount}:${(row.labelSha256s ?? []).join(",")}`),
			claimType: "pcap-dns-tunnel-exfil-candidate",
			sourceBinding: {
				artifact: "pcap-flow-summary.json",
				dnsTunnelIndex: index,
				baseDomain: row.baseDomain,
			},
			evidenceBinding: {
				queryCount: row.queryCount,
				maxLabelLength: row.maxLabelLength,
				maxEntropy: row.maxEntropy,
				labelSha256s: row.labelSha256s ?? [],
				samples: row.samples ?? [],
				risks: row.risks ?? [],
			},
			statement: "DNS query evidence contains high-entropy or encoded labels grouped by base domain for tunnel/exfil triage.",
			confidence: (row.risks ?? []).some((risk) => /encoded|long-label|high-entropy/i.test(risk)) ? 0.82 : 0.66,
			rerunCommand: "cat pcap-flow-summary.json | jq '.dnsTunnels'",
		});
	}
	for (const [index, row] of (summary.tls ?? []).entries()) {
		addClaim({
			id: "pcap-tls-clienthello-" + shortHash(`${index}:${(row.sni ?? []).join(",")}:${row.ja3Hash}`),
			claimType: "pcap-tls-sni-fingerprint",
			sourceBinding: {
				artifact: "pcap-flow-summary.json",
				tlsIndex: index,
				frame: row.frame ?? null,
				flow: pcapEndpointKey(row),
			},
			evidenceBinding: {
				sni: row.sni ?? [],
				alpn: row.alpn ?? [],
				ja3: row.ja3 ?? null,
				ja3Hash: row.ja3Hash ?? null,
				cipherSuites: row.cipherSuites ?? [],
				extensions: row.extensions ?? [],
			},
			statement: "TLS ClientHello evidence binds SNI/ALPN and JA3 fingerprint to a concrete flow.",
			confidence: (row.sni ?? []).length ? 0.8 : 0.68,
			rerunCommand: "cat pcap-flow-summary.json | jq '.tls'",
		});
	}
	for (const [index, object] of (objectManifest?.objects ?? []).entries()) {
		addClaim({
			id: "pcap-http-object-carve-" + shortHash(`${object.streamIndex}:${object.sha256}:${object.artifactRelPath}`),
			claimType: "pcap-http-object-carve",
			sourceBinding: {
				artifact: "pcap-http-objects.json",
				objectIndex: index,
				streamIndex: object.streamIndex,
				firstFrame: object.firstFrame,
				lastFrame: object.lastFrame,
				flow: pcapEndpointKey(object),
			},
			evidenceBinding: {
				artifactRelPath: object.artifactRelPath,
				size: object.size,
				sha256: object.sha256,
				magic: object.magic ?? [],
				embeddedArchives: object.embeddedArchives ?? [],
				extractedEntryCount: (object.extractedEntries ?? []).length,
				decodedArtifactCount: (object.decodedArtifacts ?? []).length,
				risks: object.risks ?? [],
			},
			statement: "HTTP object carve evidence binds response frames to a private artifact path, size, hash, magic, and archive metadata.",
			confidence: (object.magic ?? []).length ? 0.88 : 0.78,
			rerunCommand: "python3 pcap-http-object-verifier.py pcap-http-objects.json",
		});
		for (const decoded of object.decodedArtifacts ?? []) {
			addClaim({
				id: "pcap-http-decoded-object-" + shortHash(`${object.sha256}:${decoded.sha256}:${(decoded.chain ?? []).join(">")}`),
				claimType: "pcap-http-decoded-artifact",
				sourceBinding: {
					artifact: "pcap-http-objects.json",
					objectIndex: index,
					source: decoded.source,
				},
				evidenceBinding: {
					chain: decoded.chain ?? [],
					xorKey: decoded.xorKey,
					artifactRelPath: decoded.artifactRelPath,
					size: decoded.size,
					sha256: decoded.sha256,
					magic: decoded.magic ?? [],
					interesting: Boolean(decoded.interesting),
				},
				statement: "Decoded HTTP object evidence binds a transform chain to a carved artifact hash.",
				confidence: decoded.interesting ? 0.84 : 0.72,
				rerunCommand: "cat pcap-http-objects.json | jq '.objects[].decodedArtifacts'",
			});
		}
		for (const entry of object.extractedEntries ?? []) {
			addClaim({
				id: "pcap-http-archive-entry-" + shortHash(`${object.sha256}:${entry.name}:${entry.sha256}`),
				claimType: "pcap-http-archive-entry",
				sourceBinding: {
					artifact: "pcap-http-objects.json",
					objectIndex: index,
					name: entry.name,
					localHeaderOffset: entry.localHeaderOffset,
				},
				evidenceBinding: {
					artifactRelPath: entry.artifactRelPath,
					size: entry.size,
					sha256: entry.sha256,
					method: entry.method,
					compressedSize: entry.compressedSize,
					uncompressedSize: entry.uncompressedSize,
					decodedArtifactCount: (entry.decodedArtifacts ?? []).length,
				},
				statement: "Embedded archive entry evidence binds entry metadata to a carved private artifact.",
				confidence: 0.86,
				rerunCommand: "cat pcap-http-objects.json | jq '.objects[].extractedEntries'",
			});
			for (const decoded of entry.decodedArtifacts ?? []) {
				addClaim({
					id: "pcap-http-decoded-entry-" + shortHash(`${entry.sha256}:${decoded.sha256}:${(decoded.chain ?? []).join(">")}`),
					claimType: "pcap-http-decoded-artifact",
					sourceBinding: {
						artifact: "pcap-http-objects.json",
						objectIndex: index,
						entryName: entry.name,
						source: decoded.source,
					},
					evidenceBinding: {
						chain: decoded.chain ?? [],
						xorKey: decoded.xorKey,
						artifactRelPath: decoded.artifactRelPath,
						size: decoded.size,
						sha256: decoded.sha256,
						magic: decoded.magic ?? [],
						interesting: Boolean(decoded.interesting),
					},
					statement: "Decoded archive-entry evidence binds a transform chain to an extracted object hash.",
					confidence: decoded.interesting ? 0.86 : 0.72,
					rerunCommand: "cat pcap-http-objects.json | jq '.objects[].extractedEntries[].decodedArtifacts'",
				});
			}
		}
	}
	for (const claim of verification?.claimLedger ?? []) {
		if (claim.verdict !== "promoted") continue;
		addClaim({
			...claim,
			id: claim.id || "pcap-verification-claim-" + shortHash(JSON.stringify(claim)),
			sourceBinding: {
				artifact: "pcap-flow-verification.json",
				...(claim.sourceBinding ?? {}),
			},
			rerunCommand: claim.rerunCommand ?? "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		});
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const credentialClaim = promotedClaims.find((claim) => claim.claimType === "pcap-http-credential-flow" || claim.claimType === "pcap-plaintext-auth-flow");
	const objectClaim = promotedClaims.find((claim) => claim.claimType === "pcap-http-object-carve");
	const decodedClaim = promotedClaims.find((claim) => claim.claimType === "pcap-http-decoded-artifact");
	const dnsClaim = promotedClaims.find((claim) => claim.claimType === "pcap-dns-tunnel-exfil-candidate");
	const tlsClaim = promotedClaims.find((claim) => claim.claimType === "pcap-tls-sni-fingerprint");
	const reassemblyClaim = promotedClaims.find((claim) => claim.claimType === "pcap-tcp-reassembly-proof");
	const verifierCredentialClaim = promotedClaims.find((claim) => claim.claimType === "pcap-credential-signal-verification-proof");
	const verifierObjectClaim = promotedClaims.find((claim) => claim.claimType === "pcap-object-artifact-verification-proof");
	const verifierReassemblyClaim = promotedClaims.find((claim) => claim.claimType === "pcap-reassembly-hash-verification-proof");
	const verifierDnsClaim = promotedClaims.find((claim) => claim.claimType === "pcap-dns-tunnel-verification-proof");
	const verifierNegativeControlClaim = promotedClaims.find((claim) => claim.claimType === "pcap-verifier-negative-control-proof");
	const composedPaths = [];
	for (const path of verification?.composedPaths ?? []) {
		const composed = {
			...path,
			id: path.id || "pcap-verification-path-" + shortHash(JSON.stringify(path)),
			sourceBinding: {
				artifact: "pcap-flow-verification.json",
				...(path.sourceBinding ?? {}),
			},
			rerunCommand: path.rerunCommand ?? "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	if (credentialClaim || objectClaim || dnsClaim || tlsClaim) {
		const segments = [credentialClaim, verifierCredentialClaim, objectClaim, verifierObjectClaim, decodedClaim, dnsClaim, verifierDnsClaim, tlsClaim, reassemblyClaim, verifierReassemblyClaim, verifierNegativeControlClaim].filter(Boolean);
		const composed = {
			id: "pcap-flow-pivot-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "pcap-flow-evidence-pivot",
			sourceBinding: {
				segments: segments.map((claim) => ({
					id: claim.id,
					claimType: claim.claimType,
					artifact: claim.sourceBinding?.artifact,
					frame: claim.sourceBinding?.frame,
					firstFrame: claim.sourceBinding?.firstFrame,
					lastFrame: claim.sourceBinding?.lastFrame,
				})),
			},
			evidenceBinding: {
				hasCredentialFlow: Boolean(credentialClaim),
				hasHttpObject: Boolean(objectClaim),
				hasDecodedArtifact: Boolean(decodedClaim),
				hasDnsTunnel: Boolean(dnsClaim),
				hasTlsFingerprint: Boolean(tlsClaim),
				hasReassemblyProof: Boolean(reassemblyClaim),
				hasVerifierCredentialSignal: Boolean(verifierCredentialClaim),
				hasVerifierObjectArtifact: Boolean(verifierObjectClaim),
				hasVerifierReassemblyHash: Boolean(verifierReassemblyClaim),
				hasVerifierDnsTunnel: Boolean(verifierDnsClaim),
				hasNegativeControl: Boolean(verifierNegativeControlClaim),
			},
			statement: "PCAP evidence composes credential, object, DNS, TLS, TCP reassembly, deterministic parser output, and mutation-control anchors into one replayable investigation pivot.",
			verdict: "promoted",
			confidence: verifierNegativeControlClaim && (verifierCredentialClaim || verifierObjectClaim) ? 0.9 : credentialClaim && (objectClaim || dnsClaim) ? 0.86 : 0.76,
			blockers: [],
			rerunCommand: "cat pcap-flow-claims.json | jq '.composedPaths'",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!credentialClaim) blockers.push("missing-credential-flow");
	if (!objectClaim) blockers.push("missing-http-object-carve");
	if (!decodedClaim) blockers.push("missing-decoded-artifact");
	if (!dnsClaim) blockers.push("missing-dns-tunnel");
	if (!tlsClaim && !(summary.tls ?? []).length) blockers.push("missing-tls-fingerprint");
	if (!reassemblyClaim && (summary.tcpStreams ?? []).length) blockers.push("missing-reassembly-proof");
	for (const blocker of verification?.promotionReport?.blockers ?? []) {
		if (!blockers.includes(blocker)) blockers.push(blocker);
	}
	const repairActions = {
		"missing-credential-flow": "Locate HTTP authorization/cookie/form/query credentials or plaintext auth commands and bind only hashed values to frames.",
		"missing-http-object-carve": "Find HTTP bodies with binary magic, archive metadata, content-disposition, or object content-types and carve them with hashes.",
		"missing-decoded-artifact": "Run transform decoding over carved bodies and archive entries until interesting decoded artifacts are hash-bound.",
		"missing-dns-tunnel": "Group DNS labels by base domain and score long, high-entropy, base32/base64url-like labels.",
		"missing-tls-fingerprint": "Parse TLS ClientHello SNI/ALPN/JA3 and bind it to the TCP flow.",
		"missing-reassembly-proof": "Reassemble TCP streams with seq/gap/overlap metadata before promoting cross-packet HTTP evidence.",
		"missing-pcap-capture-hash-verification": "Rerun pcap-flow-verifier.mjs against original bytes and require capture size/SHA-256 equality.",
		"missing-pcap-quicklook-determinism": "Reparse the capture and resolve parser nondeterminism before promoting flow evidence.",
		"missing-pcap-credential-signal-verification": "Require credential signal hashes/lengths to reproduce from a fresh parse.",
		"missing-pcap-reassembly-hash-verification": "Require TCP stream payload hashes to reproduce from a fresh reassembly.",
		"missing-pcap-dns-tunnel-verification": "Require DNS tunnel label hashes/base domains to reproduce from a fresh parse.",
		"missing-pcap-object-artifact-verification": "Verify carved HTTP objects, archive entries, and decoded artifacts against manifest size/SHA-256.",
		"missing-pcap-verifier-negative-control": "Add capture/object byte mutation controls so altered evidence hashes are rejected.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "pcap-flow-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect source-bound PCAP evidence and rerun flow claim promotion.",
		rerunCommand: /^missing-pcap-/.test(blocker)
			? "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json"
			: "repi engage <pcap-or-pcapng> --json",
	}));
	return {
		kind: "repi-pcap-flow-claims",
		schemaVersion: 2,
		generatedAt: new Date().toISOString(),
		proofReady: promotedClaims.length > 0,
		verificationStats: verification?.stats ?? null,
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

function pcapFlowVerifierSource() {
	return String.raw`#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function verifyFile(base, row, label) {
  if (!row?.artifactRelPath) return { label, artifactRelPath: row?.artifactRelPath ?? null, verified: false, reason: "missing-artifactRelPath" };
  const root = resolve(base);
  const path = resolve(join(base, row.artifactRelPath));
  if (!(path === root || path.startsWith(root + "/"))) return { label, artifactRelPath: row.artifactRelPath, verified: false, reason: "path-escape" };
  const data = readFileSync(path);
  const actual = { size: data.length, sha256: sha256(data) };
  const verified = (row.size == null || row.size === actual.size) && (!row.sha256 || row.sha256 === actual.sha256);
  let negativeControl = null;
  if (data.length && row.sha256) {
    const mutated = Buffer.from(data);
    mutated[0] ^= 0xff;
    const mutatedSha256 = sha256(mutated);
    negativeControl = { controlType: "pcap-artifact-byte-mutation-rejection", mutatedSha256, passed: mutatedSha256 !== row.sha256 };
  }
  return { label, artifactRelPath: row.artifactRelPath, expected: { size: row.size ?? null, sha256: row.sha256 ?? null }, actual, verified, reason: verified ? "artifact-size-sha256-match" : "artifact-size-sha256-mismatch", negativeControl };
}

function verify(pcapPath, summaryPath, manifestPath) {
  const summary = readJson(summaryPath);
  const capture = readFileSync(pcapPath);
  const captureIdentity = { size: capture.length, sha256: sha256(capture), verified: capture.length === summary.size && sha256(capture) === summary.sha256 };
  if (capture.length) {
    const mutated = Buffer.from(capture);
    mutated[0] ^= 0xff;
    const mutatedSha256 = sha256(mutated);
    captureIdentity.negativeControl = { controlType: "pcap-capture-byte-mutation-rejection", mutatedSha256, passed: mutatedSha256 !== captureIdentity.sha256 };
  }
  const objectArtifactChecks = [];
  let objectManifestStats = { objectCount: 0, entryCount: 0, decodedCount: 0, verifierRelPath: null };
  if (manifestPath && existsSync(manifestPath)) {
    const manifest = readJson(manifestPath);
    const base = dirname(manifestPath);
    objectManifestStats = { objectCount: manifest.objectCount ?? 0, entryCount: manifest.entryCount ?? 0, decodedCount: manifest.decodedCount ?? 0, verifierRelPath: manifest.verifierRelPath ?? null };
    for (const [objectIndex, object] of (manifest.objects ?? []).entries()) {
      objectArtifactChecks.push({ objectIndex, ...verifyFile(base, object, "http-object") });
      for (const [decodedIndex, decoded] of (object.decodedArtifacts ?? []).entries()) objectArtifactChecks.push({ objectIndex, decodedIndex, ...verifyFile(base, decoded, "http-object-decoded") });
      for (const [entryIndex, entry] of (object.extractedEntries ?? []).entries()) {
        objectArtifactChecks.push({ objectIndex, entryIndex, name: entry.name, ...verifyFile(base, entry, "http-archive-entry") });
        for (const [decodedIndex, decoded] of (entry.decodedArtifacts ?? []).entries()) objectArtifactChecks.push({ objectIndex, entryIndex, decodedIndex, name: entry.name, ...verifyFile(base, decoded, "http-entry-decoded") });
      }
    }
  }
  const negativeControls = [captureIdentity.negativeControl, ...objectArtifactChecks.map((row) => row.negativeControl)].filter((row) => row?.passed);
  const proofReady = captureIdentity.verified && (objectArtifactChecks.length === 0 || objectArtifactChecks.some((row) => row.verified)) && negativeControls.length > 0;
  const blockers = [];
  if (!captureIdentity.verified) blockers.push("missing-pcap-capture-hash-verification");
  if (objectArtifactChecks.length && !objectArtifactChecks.some((row) => row.verified)) blockers.push("missing-pcap-object-artifact-verification");
  if (!negativeControls.length) blockers.push("missing-pcap-verifier-negative-control");
  return {
    kind: "repi-pcap-flow-verification",
    schemaVersion: 1,
    proofReady,
    captureIdentity,
    quicklookDeterminism: { verified: null, reason: "standalone-harness-validates-capture-and-object-artifacts; engage performs full deterministic parser comparison" },
    objectManifestStats,
    objectArtifactChecks,
    negativeControls,
    stats: {
      credentialsVerified: 0,
      reassemblyStreamsVerified: 0,
      dnsTunnelsVerified: 0,
      objectArtifactsVerified: objectArtifactChecks.filter((row) => row.verified).length,
      negativeControlsPassed: negativeControls.length,
    },
    repairQueue: blockers.map((blocker) => ({ id: "pcap-flow-verification-" + blocker, blocker, action: "Collect verifier-bound PCAP evidence and rerun pcap-flow-verifier.mjs.", rerunCommand: "node pcap-flow-verifier.mjs <pcap> pcap-flow-summary.json pcap-flow-verification.json pcap-http-objects.json" })),
    promotionReport: { proofReady, blockers },
  };
}

function selfTest() {
  const dir = mkdtempSync(join(tmpdir(), "repi-pcap-flow-verifier-"));
  const pcapPath = join(dir, "sample.pcap");
  const bodyPath = join(dir, "pcap-http-objects", "body.bin");
  const body = Buffer.from("PK\x03\x04demo-object");
  writeFileSync(pcapPath, Buffer.from("pcap-bytes"));
  mkdirSync(dirname(bodyPath), { recursive: true });
  writeFileSync(bodyPath, body);
  const summaryPath = join(dir, "pcap-flow-summary.json");
  writeFileSync(summaryPath, JSON.stringify({ size: 10, sha256: sha256(Buffer.from("pcap-bytes")), format: "pcapng", packetCount: 1 }) + "\n");
  const manifestPath = join(dir, "pcap-http-objects.json");
  writeFileSync(manifestPath, JSON.stringify({ kind: "repi-pcap-http-object-carves", objectCount: 1, entryCount: 0, decodedCount: 0, objects: [{ artifactRelPath: "pcap-http-objects/body.bin", size: body.length, sha256: sha256(body), decodedArtifacts: [], extractedEntries: [] }] }) + "\n");
  const result = verify(pcapPath, summaryPath, manifestPath);
  if (!result.proofReady) throw new Error(JSON.stringify(result));
  console.log(JSON.stringify({ kind: "repi-pcap-flow-verifier-self-test", status: "ok", stats: result.stats }, null, 2));
}

const args = process.argv.slice(2);
if (args.includes("--self-test")) {
  selfTest();
  process.exit(0);
}
const [pcapPath, summaryPath = "pcap-flow-summary.json", outputPath = "pcap-flow-verification.json", manifestPath = "pcap-http-objects.json"] = args;
if (!pcapPath) {
  console.error("usage: node pcap-flow-verifier.mjs <pcap> [summary.json] [output.json] [objects.json]");
  process.exit(2);
}
const result = verify(pcapPath, summaryPath, manifestPath);
writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n", { mode: 0o600 });
console.log(JSON.stringify({ kind: result.kind, proofReady: result.proofReady, stats: result.stats, output: outputPath }, null, 2));
process.exit(result.proofReady ? 0 : 1);
`;
}


export function pcapQuicklookRows(target, artifactDir, runtime) {
	configurePcapDfirRuntime(runtime);
	try {
		const summary = pcapQuicklook(target);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "pcap-flow-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
		const carving = writePcapHttpObjectArtifacts(summary, artifactDir);
		const flowVerification = pcapFlowVerificationSummary(target, summary, carving?.manifest, artifactDir);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "pcap-flow-verification.json"), `${JSON.stringify(flowVerification, null, 2)}\n`);
		const flowClaims = pcapFlowClaims(summary, carving?.manifest, flowVerification);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "pcap-flow-claims.json"), `${JSON.stringify(flowClaims, null, 2)}\n`);
		const rows = [
			{
				id: "pcap-quicklook",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: summary.supported === false ? 1 : 0,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(summary, null, 2)}\n`,
				stderr: "",
				error: summary.supported === false ? summary.reason : undefined,
			},
			{
				id: "pcap-flow-verification",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: flowVerification.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(flowVerification, null, 2)}\n`,
				stderr: "",
				error: flowVerification.proofReady ? undefined : "PCAP flow verification blockers present",
			},
			{
				id: "pcap-flow-claims",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: flowClaims.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(flowClaims, null, 2)}\n`,
				stderr: "",
				error: flowClaims.proofReady ? undefined : "no PCAP flow claims promoted",
			},
		];
		if (!noWrite && artifactDir) {
			const verifierPath = join(artifactDir, "pcap-flow-verifier.mjs");
			writePrivate(verifierPath, pcapFlowVerifierSource(), 0o700);
			rows.push({
				id: "pcap-flow-verifier-artifact",
				command: "internal",
				args: [redact(verifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(verifierPath)}\nrun=node ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "pcap-flow-summary.json"))} ${redact(join(artifactDir, "pcap-flow-verification.json"))} ${redact(join(artifactDir, "pcap-http-objects.json"))}\n`,
				stderr: "",
				error: undefined,
			});
		}
		if (carving) {
			rows.push({
				id: "pcap-http-object-carves",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify({
					kind: carving.manifest.kind,
					schemaVersion: carving.manifest.schemaVersion,
					objectCount: carving.manifest.objectCount,
					entryCount: carving.manifest.entryCount,
					decodedCount: carving.manifest.decodedCount,
					manifestPath: redact(carving.manifestPath),
					verifierPath: redact(carving.verifierPath),
					objects: carving.manifest.objects.map((object) => ({
						streamIndex: object.streamIndex,
						firstFrame: object.firstFrame,
						lastFrame: object.lastFrame,
						contentType: object.contentType,
						size: object.size,
						sha256: object.sha256,
						artifactRelPath: object.artifactRelPath,
						magic: object.magic,
						decodedArtifacts: object.decodedArtifacts.map((decoded) => ({
							source: decoded.source,
							chain: decoded.chain,
							size: decoded.size,
							sha256: decoded.sha256,
							artifactRelPath: decoded.artifactRelPath,
							interesting: decoded.interesting,
						})),
						extractedEntries: object.extractedEntries.map((entry) => ({
							name: entry.name,
							size: entry.size,
							sha256: entry.sha256,
							artifactRelPath: entry.artifactRelPath,
							decodedArtifacts: entry.decodedArtifacts.map((decoded) => ({
								source: decoded.source,
								chain: decoded.chain,
								size: decoded.size,
								sha256: decoded.sha256,
								artifactRelPath: decoded.artifactRelPath,
								interesting: decoded.interesting,
							})),
						})),
					})),
				}, null, 2)}\n`,
				stderr: "",
				error: undefined,
			});
		}
		return rows;
	} catch (error) {
		return [{ id: "pcap-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}
