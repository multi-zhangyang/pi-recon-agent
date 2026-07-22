import { readFileSync } from "node:fs";
import { join } from "node:path";

let root;
let redact;
let shortHash;
let bufferSha256;
let writePrivate;
let noWrite;
let shellQuote;
let findSignatureOffsets;
let firmwareStrings;
let firmwareEntropySamples;

export function configureFirmwareRuntime(runtime) {
	({ root, redact, shortHash, bufferSha256, writePrivate, noWrite, shellQuote, findSignatureOffsets, firmwareStrings, firmwareEntropySamples } = runtime);
}
function firmwareSignatureSummary(data) {
	const signatures = [
		{ name: "uImage", magic: Buffer.from([0x27, 0x05, 0x19, 0x56]), next: "Parse U-Boot header, then carve payload at header+64." },
		{ name: "TRX", magic: Buffer.from("HDR0", "ascii"), next: "Parse TRX length/CRC and carve partitions." },
		{ name: "UBI", magic: Buffer.from("UBI#", "ascii"), next: "Use ubireader/unblob to extract UBI volumes." },
		{ name: "SquashFS-little", magic: Buffer.from("hsqs", "ascii"), next: "Use unsquashfs from this offset." },
		{ name: "SquashFS-big", magic: Buffer.from("sqsh", "ascii"), next: "Use unsquashfs with endian awareness from this offset." },
		{ name: "CramFS", magic: Buffer.from([0x45, 0x3d, 0xcd, 0x28]), next: "Use cramfsck/extract from this offset." },
		{ name: "gzip", magic: Buffer.from([0x1f, 0x8b, 0x08]), next: "Try gzip/zcat from this offset." },
		{ name: "xz", magic: Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), next: "Try xzcat from this offset." },
		{ name: "ZIP", magic: Buffer.from("PK\u0003\u0004", "binary"), next: "Use unzip/7z from this offset." },
		{ name: "ELF", magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]), next: "Extract binary and run native hardening/reverse probes." },
	];
	return signatures
		.map((signature) => ({ name: signature.name, offsets: findSignatureOffsets(data, signature.magic), next: signature.next }))
		.filter((signature) => signature.offsets.length);
}

function safeNumberFromBigInt(value) {
	return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
}

function firmwareCompressionName(value) {
	return (
		{
			1: "gzip",
			2: "lzma",
			3: "lzo",
			4: "xz",
			5: "lz4",
			6: "zstd",
		}[value] ?? `unknown-${value}`
	);
}

function parseFirmwareTrx(data, offset) {
	if (offset + 28 > data.length) return { offset, error: "truncated-trx-header" };
	const length = data.readUInt32LE(offset + 4);
	const partitionOffsets = [data.readUInt32LE(offset + 16), data.readUInt32LE(offset + 20), data.readUInt32LE(offset + 24)];
	const validOffsets = partitionOffsets
		.map((partOffset, index) => ({ index, offset: partOffset, absoluteOffset: offset + partOffset }))
		.filter((row) => row.offset > 0 && row.absoluteOffset < data.length && (!length || row.offset < length));
	return {
		offset,
		length,
		crc32: `0x${data.readUInt32LE(offset + 8).toString(16).padStart(8, "0")}`,
		flags: data.readUInt16LE(offset + 12),
		version: data.readUInt16LE(offset + 14),
		partitionOffsets,
		partitions: validOffsets.map((row, index) => {
			const next = validOffsets[index + 1]?.absoluteOffset ?? (length ? Math.min(data.length, offset + length) : data.length);
			return { ...row, size: Math.max(0, next - row.absoluteOffset) };
		}),
	};
}

function uImageOsName(value) {
	return (
		{
			5: "Linux",
			13: "FreeBSD",
			17: "OpenBSD",
			21: "VxWorks",
		}[value] ?? `unknown-${value}`
	);
}

function uImageArchName(value) {
	return (
		{
			2: "ARM",
			3: "x86",
			5: "MIPS",
			8: "PowerPC",
			21: "AArch64",
		}[value] ?? `unknown-${value}`
	);
}

function uImageTypeName(value) {
	return (
		{
			2: "kernel",
			3: "ramdisk",
			4: "multi",
			5: "firmware",
			7: "script",
			11: "flatdt",
		}[value] ?? `unknown-${value}`
	);
}

function uImageCompressionName(value) {
	return (
		{
			0: "none",
			1: "gzip",
			2: "bzip2",
			3: "lzma",
			5: "lz4",
			6: "zstd",
		}[value] ?? `unknown-${value}`
	);
}

function parseFirmwareUImage(data, offset) {
	if (offset + 64 > data.length) return { offset, error: "truncated-uimage-header" };
	return {
		offset,
		headerCrc32: `0x${data.readUInt32BE(offset + 4).toString(16).padStart(8, "0")}`,
		timestamp: data.readUInt32BE(offset + 8),
		size: data.readUInt32BE(offset + 12),
		loadAddress: `0x${data.readUInt32BE(offset + 16).toString(16)}`,
		entryPoint: `0x${data.readUInt32BE(offset + 20).toString(16)}`,
		dataCrc32: `0x${data.readUInt32BE(offset + 24).toString(16).padStart(8, "0")}`,
		os: uImageOsName(data[offset + 28]),
		arch: uImageArchName(data[offset + 29]),
		type: uImageTypeName(data[offset + 30]),
		compression: uImageCompressionName(data[offset + 31]),
		name: redact(data.toString("ascii", offset + 32, offset + 64).replace(/\0.*$/s, "").replace(/[^\x20-\x7e]/g, "?")),
	};
}

function parseFirmwareSquashfs(data, offset, endian) {
	if (offset + 96 > data.length) return { offset, endian, error: "truncated-squashfs-superblock" };
	const readU16 = endian === "little" ? data.readUInt16LE.bind(data) : data.readUInt16BE.bind(data);
	const readU32 = endian === "little" ? data.readUInt32LE.bind(data) : data.readUInt32BE.bind(data);
	const readU64 = endian === "little" ? data.readBigUInt64LE.bind(data) : data.readBigUInt64BE.bind(data);
	const compression = readU16(offset + 20);
	return {
		offset,
		endian,
		inodes: readU32(offset + 4),
		mkfsTime: readU32(offset + 8),
		blockSize: readU32(offset + 12),
		fragments: readU32(offset + 16),
		compression,
		compressionName: firmwareCompressionName(compression),
		blockLog: readU16(offset + 22),
		flags: readU16(offset + 24),
		idCount: readU16(offset + 26),
		version: `${readU16(offset + 28)}.${readU16(offset + 30)}`,
		rootInode: safeNumberFromBigInt(readU64(offset + 32)),
		bytesUsed: safeNumberFromBigInt(readU64(offset + 40)),
	};
}

function parseFirmwareUbi(data, offset) {
	if (offset + 64 > data.length) return { offset, error: "truncated-ubi-ec-header" };
	return {
		offset,
		version: data[offset + 4],
		eraseCount: safeNumberFromBigInt(data.readBigUInt64BE(offset + 8)),
		vidHeaderOffset: data.readUInt32BE(offset + 16),
		dataOffset: data.readUInt32BE(offset + 20),
		imageSequence: data.readUInt32BE(offset + 24),
		headerCrc32: `0x${data.readUInt32BE(offset + 60).toString(16).padStart(8, "0")}`,
	};
}

function firmwareStructureSummary(data, signatures) {
	const offsetRows = (name) => signatures.find((signature) => signature.name === name)?.offsets ?? [];
	const trx = offsetRows("TRX").slice(0, 12).map((offset) => parseFirmwareTrx(data, offset));
	const uImage = offsetRows("uImage").slice(0, 12).map((offset) => parseFirmwareUImage(data, offset));
	const squashfs = [
		...offsetRows("SquashFS-little").slice(0, 12).map((offset) => parseFirmwareSquashfs(data, offset, "little")),
		...offsetRows("SquashFS-big").slice(0, 12).map((offset) => parseFirmwareSquashfs(data, offset, "big")),
	];
	const ubi = offsetRows("UBI").slice(0, 12).map((offset) => parseFirmwareUbi(data, offset));
	return {
		trx,
		uImage,
		squashfs,
		ubi,
	};
}

function firmwareSignals(strings) {
	const urls = [];
	const credentials = [];
	const services = [];
	const paths = [];
	const addUnique = (list, value, offset) => {
		const text = redact(String(value).slice(0, 260));
		if (!text || list.some((row) => row.text === text)) return;
		list.push({ offset, text });
	};
	for (const row of strings) {
		for (const match of row.text.matchAll(/https?:\/\/[^\s"'<>\\]{4,}/gi)) addUnique(urls, match[0], row.offset + match.index);
		for (const match of row.text.matchAll(/\b(?:password|passwd|pwd|token|secret|api[_-]?key|auth|client_secret|access_token|refresh_token)\b[\w ._-]{0,24}[:=]\s*["']?[^"'\s<>]{4,}/gi)) addUnique(credentials, match[0], row.offset + match.index);
		for (const match of row.text.matchAll(/\b(?:busybox|dropbear|telnetd|uhttpd|lighttpd|boa|dnsmasq|iptables|nvram|cgi-bin|login\.cgi|admin\.cgi|system\.ini|rcS)\b/gi)) addUnique(services, match[0], row.offset + match.index);
		for (const match of row.text.matchAll(/\/(?:etc|bin|sbin|usr|www|var)\/[A-Za-z0-9._/-]{2,}/g)) addUnique(paths, match[0], row.offset + match.index);
		if (urls.length + credentials.length + services.length + paths.length >= 180) break;
	}
	return {
		urls: urls.slice(0, 40),
		credentials: credentials.slice(0, 40),
		services: services.slice(0, 60),
		paths: paths.slice(0, 60),
	};
}

function firmwareQuicklookSummary(target) {
	const data = readFileSync(target);
	const signatures = firmwareSignatureSummary(data);
	const structures = firmwareStructureSummary(data, signatures);
	const strings = firmwareStrings(data);
	const signals = firmwareSignals(strings);
	const risks = [];
	if (signals.credentials.length) risks.push("hardcoded-credential-signal");
	if (signals.urls.length) risks.push("network-endpoint-signal");
	if (signals.services.some((row) => /telnetd|dropbear|uhttpd|lighttpd|boa|login\.cgi|admin\.cgi/i.test(row.text))) risks.push("exposed-service-or-web-admin-signal");
	if (signals.paths.some((row) => /\/etc\/passwd|\/etc\/shadow|\/etc\/init\.d|rcS/i.test(row.text))) risks.push("filesystem-init-credential-surface");
	if (signatures.some((signature) => /SquashFS|CramFS|UBI/i.test(signature.name))) risks.push("rootfs-signature-present");
	if (structures.trx.length || structures.uImage.length) risks.push("firmware-container-header-parsed");
	if (structures.squashfs.length) risks.push("filesystem-superblock-parsed");
	if (structures.ubi.length) risks.push("ubi-header-parsed");
	return {
		kind: "repi-firmware-quicklook",
		schemaVersion: 2,
		size: data.length,
		sha256: bufferSha256(data),
		signatures,
		structures,
		entropy: firmwareEntropySamples(data),
		stringScan: {
			count: strings.length,
			scannedBytes: Math.min(data.length, 32 * 1024 * 1024),
			signals,
		},
		risks,
	};
}

function firmwareExtractionTargetsFromSummary(summary) {
	const structures = summary.structures ?? {};
	const extractionTargets = [];
	const push = (target) => {
		const key = `${target.type}:${target.offset}:${target.size ?? ""}`;
		if (extractionTargets.some((row) => `${row.type}:${row.offset}:${row.size ?? ""}` === key)) return;
		extractionTargets.push({ ...target });
	};
	for (const row of structures.trx ?? []) {
		for (const partition of row.partitions ?? []) {
			push({ type: "trx-partition", offset: partition.absoluteOffset, size: partition.size, containerOffset: row.offset });
		}
	}
	for (const row of structures.squashfs ?? []) {
		push({ type: "squashfs-rootfs", offset: row.offset, size: row.bytesUsed, endian: row.endian, compressionName: row.compressionName });
	}
	for (const row of structures.ubi ?? []) {
		push({ type: "ubi-volume", offset: row.offset, vidHeaderOffset: row.vidHeaderOffset, dataOffset: row.dataOffset });
	}
	for (const row of structures.uImage ?? []) {
		push({ type: "uimage-payload", offset: row.offset + 64, size: row.size, containerOffset: row.offset, arch: row.arch, compression: row.compression });
	}
	return extractionTargets;
}

function firmwareSignatureMagic(name) {
	const map = {
		uImage: Buffer.from([0x27, 0x05, 0x19, 0x56]),
		TRX: Buffer.from("HDR0", "ascii"),
		UBI: Buffer.from("UBI#", "ascii"),
		"SquashFS-little": Buffer.from("hsqs", "ascii"),
		"SquashFS-big": Buffer.from("sqsh", "ascii"),
		CramFS: Buffer.from([0x45, 0x3d, 0xcd, 0x28]),
		gzip: Buffer.from([0x1f, 0x8b, 0x08]),
		xz: Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
		ZIP: Buffer.from("PK\u0003\u0004", "binary"),
		ELF: Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
	};
	return map[name] ?? null;
}

function firmwareExpectedMagicForTarget(target) {
	if (target.type === "squashfs-rootfs") return target.endian === "big" ? firmwareSignatureMagic("SquashFS-big") : firmwareSignatureMagic("SquashFS-little");
	if (target.type === "ubi-volume") return firmwareSignatureMagic("UBI");
	if (target.type === "trx-partition" || target.type === "uimage-payload") return null;
	return null;
}

function firmwareMagicAt(data, offset) {
	for (const name of ["SquashFS-little", "SquashFS-big", "UBI", "uImage", "TRX", "CramFS", "gzip", "xz", "ZIP", "ELF"]) {
		const magic = firmwareSignatureMagic(name);
		if (magic && offset >= 0 && offset + magic.length <= data.length && data.subarray(offset, offset + magic.length).equals(magic)) return name;
	}
	return null;
}

function firmwareExtractionVerificationSummary(target, summary) {
	const data = readFileSync(target);
	const imageIdentity = {
		size: data.length,
		sha256: bufferSha256(data),
		headerHex: data.subarray(0, 16).toString("hex"),
		verified: data.length === summary.size && bufferSha256(data) === summary.sha256,
	};
	if (data.length) {
		const mutated = Buffer.from(data);
		mutated[0] ^= 0xff;
		const mutatedSha256 = bufferSha256(mutated);
		imageIdentity.negativeControl = {
			controlType: "firmware-image-byte-mutation-rejection",
			mutatedSha256,
			passed: mutatedSha256 !== summary.sha256,
		};
	}
	const signatureChecks = [];
	for (const signature of summary.signatures ?? []) {
		const magic = firmwareSignatureMagic(signature.name);
		for (const offset of signature.offsets ?? []) {
			let verified = false;
			let reason = "missing-magic";
			let actual = {};
			let negativeControl = null;
			if (magic && offset >= 0 && offset + magic.length <= data.length) {
				const chunk = data.subarray(offset, offset + magic.length);
				actual = { magicHex: chunk.toString("hex"), length: chunk.length, sha256: bufferSha256(chunk) };
				verified = chunk.equals(magic);
				reason = verified ? "signature-magic-match" : "signature-magic-mismatch";
				const mutatedOffset = offset + 1 + magic.length <= data.length ? offset + 1 : offset > 0 ? offset - 1 : null;
				if (mutatedOffset != null) {
					const mutated = data.subarray(mutatedOffset, mutatedOffset + magic.length);
					negativeControl = {
						controlType: "signature-mutated-offset-rejection",
						mutatedOffset,
						mutatedSha256: bufferSha256(mutated),
						passed: !mutated.equals(magic),
					};
				}
			} else if (magic) {
				reason = "signature-offset-out-of-range";
			}
			signatureChecks.push({ name: signature.name, offset, expectedMagicHex: magic?.toString("hex") ?? null, actual, verified, reason, negativeControl });
		}
	}
	const extractionTargets = firmwareExtractionTargetsFromSummary(summary);
	const carveChecks = [];
	for (const extractionTarget of extractionTargets) {
		const offset = Number(extractionTarget.offset);
		const requestedSize = Number(extractionTarget.size ?? (data.length - offset));
		let verified = false;
		let complete = false;
		let reason = "target-out-of-range";
		let actual = {};
		let negativeControl = null;
		if (Number.isFinite(offset) && offset >= 0 && offset < data.length) {
			const boundedSize = Number.isFinite(requestedSize) && requestedSize > 0 ? Math.min(requestedSize, data.length - offset) : data.length - offset;
			const carved = data.subarray(offset, offset + boundedSize);
			const expectedMagic = firmwareExpectedMagicForTarget(extractionTarget);
			const observedMagic = firmwareMagicAt(data, offset);
			complete = Number.isFinite(requestedSize) && requestedSize > 0 ? offset + requestedSize <= data.length : true;
			actual = {
				offset,
				requestedSize: Number.isFinite(requestedSize) && requestedSize > 0 ? requestedSize : null,
				carvedSize: carved.length,
				sha256: bufferSha256(carved),
				headerHex: carved.subarray(0, 16).toString("hex"),
				observedMagic,
				complete,
			};
			verified = expectedMagic ? carved.subarray(0, expectedMagic.length).equals(expectedMagic) : carved.length > 0;
			reason = verified ? (complete ? "carve-offset-size-hash-match" : "carve-header-match-but-truncated") : "carve-header-mismatch";
			const mutatedOffset = offset + 1 + Math.min(carved.length, 16) <= data.length ? offset + 1 : offset > 0 ? offset - 1 : null;
			if (mutatedOffset != null) {
				const mutated = data.subarray(mutatedOffset, mutatedOffset + Math.min(carved.length, 64));
				negativeControl = {
					controlType: "carve-mutated-offset-rejection",
					mutatedOffset,
					mutatedSha256: bufferSha256(mutated),
					passed: bufferSha256(mutated) !== actual.sha256,
				};
			}
		}
		carveChecks.push({ target: extractionTarget, actual, verified, complete, reason, negativeControl });
	}
	const passedControls = [imageIdentity.negativeControl, ...signatureChecks.map((row) => row.negativeControl), ...carveChecks.map((row) => row.negativeControl)].filter((row) => row?.passed);
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => claimLedger.push({ verdict: "promoted", confidence: 0.76, blockers: [], ...claim });
	if (imageIdentity.verified) {
		addClaim({
			id: "firmware-image-hash-verification-" + shortHash(summary.sha256),
			claimType: "firmware-image-hash-verification-proof",
			sourceBinding: { artifact: "firmware-extraction-verification.json" },
			evidenceBinding: { size: imageIdentity.size, sha256: imageIdentity.sha256, headerHex: imageIdentity.headerHex },
			statement: "Verifier re-read the firmware image and matched size/SHA-256 against firmware quicklook.",
			confidence: 0.9,
			rerunCommand: "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		});
	}
	const verifiedSignatures = signatureChecks.filter((row) => row.verified);
	if (verifiedSignatures.length) {
		addClaim({
			id: "firmware-signature-offset-verification-" + shortHash(verifiedSignatures.map((row) => `${row.name}:${row.offset}`).join("|")),
			claimType: "firmware-signature-offset-verification-proof",
			sourceBinding: { artifact: "firmware-extraction-verification.json", offsets: verifiedSignatures.map((row) => ({ name: row.name, offset: row.offset })) },
			evidenceBinding: { verifiedSignatures: verifiedSignatures.map((row) => ({ name: row.name, offset: row.offset, magicHex: row.expectedMagicHex })) },
			statement: "Verifier matched firmware container/rootfs signatures at exact offsets.",
			confidence: 0.86,
			rerunCommand: "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		});
	}
	const verifiedRootfsCarves = carveChecks.filter((row) => row.verified && /squashfs-rootfs|ubi-volume/.test(row.target?.type));
	if (verifiedRootfsCarves.length) {
		addClaim({
			id: "firmware-rootfs-carve-proof-" + shortHash(verifiedRootfsCarves.map((row) => `${row.target.type}:${row.target.offset}:${row.actual.sha256}`).join("|")),
			claimType: "firmware-rootfs-carve-proof",
			sourceBinding: { artifact: "firmware-extraction-verification.json", carves: verifiedRootfsCarves.map((row) => ({ type: row.target.type, offset: row.target.offset, size: row.target.size ?? null })) },
			evidenceBinding: { carves: verifiedRootfsCarves.map((row) => ({ type: row.target.type, offset: row.target.offset, requestedSize: row.actual.requestedSize, carvedSize: row.actual.carvedSize, sha256: row.actual.sha256, observedMagic: row.actual.observedMagic, complete: row.complete })) },
			statement: "Verifier carved rootfs candidates by offset and bound each carve to a header, bounded size, SHA-256, and completeness flag.",
			confidence: verifiedRootfsCarves.some((row) => row.complete) ? 0.9 : 0.76,
			rerunCommand: "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		});
	}
	if (passedControls.length) {
		addClaim({
			id: "firmware-extraction-negative-control-" + shortHash(passedControls.map((row) => `${row.controlType}:${row.mutatedSha256}`).join("|")),
			claimType: "firmware-extraction-negative-control-proof",
			sourceBinding: { artifact: "firmware-extraction-verification.json" },
			evidenceBinding: { passedControls },
			statement: "Verifier ran mutation controls proving shifted offsets or mutated images do not share source hashes/magic.",
			confidence: 0.84,
			rerunCommand: "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		});
	}
	const imageClaim = claimLedger.find((claim) => claim.claimType === "firmware-image-hash-verification-proof");
	const signatureClaim = claimLedger.find((claim) => claim.claimType === "firmware-signature-offset-verification-proof");
	const rootfsClaim = claimLedger.find((claim) => claim.claimType === "firmware-rootfs-carve-proof");
	const controlClaim = claimLedger.find((claim) => claim.claimType === "firmware-extraction-negative-control-proof");
	if (imageClaim && signatureClaim && rootfsClaim && controlClaim) {
		const segments = [imageClaim, signatureClaim, rootfsClaim, controlClaim];
		const composed = {
			id: "firmware-rootfs-carve-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "firmware-rootfs-carve-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				imageSha256: summary.sha256,
				rootfsCarves: verifiedRootfsCarves.map((row) => ({ type: row.target.type, offset: row.target.offset, complete: row.complete, sha256: row.actual.sha256 })),
				hasCompleteRootfsCarve: verifiedRootfsCarves.some((row) => row.complete),
				hasNegativeControl: true,
			},
			statement: "Firmware verification composes image identity, signature offsets, rootfs carve hashes, and mutation controls into a rerunnable extraction proof path.",
			verdict: "promoted",
			confidence: verifiedRootfsCarves.some((row) => row.complete) ? 0.88 : 0.78,
			blockers: verifiedRootfsCarves.some((row) => !row.complete) ? ["rootfs-carve-truncated"] : [],
			rerunCommand: "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!imageIdentity.verified) blockers.push("missing-firmware-image-hash-verification");
	if (!verifiedSignatures.length) blockers.push("missing-signature-offset-verification");
	if (!verifiedRootfsCarves.length) blockers.push("missing-rootfs-carve-verifier");
	if (verifiedRootfsCarves.some((row) => !row.complete)) blockers.push("rootfs-carve-truncated");
	if (!passedControls.length) blockers.push("missing-firmware-extraction-negative-control");
	const repairActions = {
		"missing-firmware-image-hash-verification": "Rerun the verifier against the original firmware image and require size/SHA-256 equality.",
		"missing-signature-offset-verification": "Verify each TRX/uImage/SquashFS/UBI signature by exact offset and magic bytes before carving.",
		"missing-rootfs-carve-verifier": "Create at least one source-bound rootfs carve with offset, bounded size, header, and SHA-256.",
		"rootfs-carve-truncated": "Acquire the complete firmware/rootfs bytes or adjust the carve size before claiming a full filesystem extraction.",
		"missing-firmware-extraction-negative-control": "Add mutated image/offset controls so incorrect offsets or bytes are rejected by the verifier.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "firmware-extraction-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound firmware extraction evidence and rerun the verifier.",
		rerunCommand: "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
	}));
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-firmware-extraction-verification",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		target: redact(target),
		proofReady: promotedClaims.length > 0,
		imageIdentity,
		signatureChecks,
		extractionTargets,
		carveChecks,
		negativeControls: passedControls,
		stats: {
			signaturesVerified: verifiedSignatures.length,
			rootfsCarvesVerified: verifiedRootfsCarves.length,
			completeRootfsCarves: verifiedRootfsCarves.filter((row) => row.complete).length,
			negativeControlsPassed: passedControls.length,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady: promotedClaims.length > 0, promotedClaims, blockers },
		repairQueue,
	};
}


function firmwareAttackSurfaceClaims(summary, verification) {
	const structures = summary.structures ?? {};
	const signals = summary.stringScan?.signals ?? {};
	const claimLedger = [];
	const extractionTargets = [];
	const addClaim = (claim) => {
		claimLedger.push({
			verdict: "promoted",
			confidence: 0.72,
			blockers: [],
			...claim,
		});
	};
	const pushExtractionTarget = (target) => {
		const key = `${target.type}:${target.offset}:${target.size ?? ""}`;
		if (extractionTargets.some((row) => `${row.type}:${row.offset}:${row.size ?? ""}` === key)) return;
		extractionTargets.push({
			...target,
			command: target.size
				? `dd if="$FW" of="$OUT/carves/${String(target.offset).padStart(8, "0")}-${target.type}.bin" bs=1 skip=${target.offset} count=${target.size} status=none`
				: `dd if="$FW" of="$OUT/carves/${String(target.offset).padStart(8, "0")}-${target.type}.bin" bs=1 skip=${target.offset} status=none`,
		});
	};
	for (const row of structures.trx ?? []) {
		for (const partition of row.partitions ?? []) {
			pushExtractionTarget({
				type: "trx-partition",
				offset: partition.absoluteOffset,
				size: partition.size,
				containerOffset: row.offset,
			});
		}
		addClaim({
			id: "firmware-container-partition-map-" + shortHash(`${row.offset}:${row.length}:${(row.partitionOffsets ?? []).join(",")}`),
			claimType: "firmware-container-partition-map",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				structure: "TRX",
				offset: row.offset,
			},
			evidenceBinding: {
				length: row.length,
				version: row.version,
				partitionOffsets: row.partitionOffsets ?? [],
				partitions: row.partitions ?? [],
			},
			statement: "Firmware container header was parsed into concrete partition offsets suitable for carving.",
			confidence: 0.86,
			rerunCommand: "cat firmware-quicklook.json | jq '.structures.trx'",
		});
	}
	for (const row of structures.uImage ?? []) {
		addClaim({
			id: "firmware-uimage-entrypoint-" + shortHash(`${row.offset}:${row.arch}:${row.type}:${row.compression}:${row.entryPoint}`),
			claimType: "firmware-uimage-entrypoint",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				structure: "uImage",
				offset: row.offset,
			},
			evidenceBinding: {
				arch: row.arch,
				os: row.os,
				type: row.type,
				compression: row.compression,
				loadAddress: row.loadAddress,
				entryPoint: row.entryPoint,
				size: row.size,
			},
			statement: "uImage header evidence binds architecture, compression, and entrypoint for an emulation or unpack path.",
			confidence: 0.84,
			rerunCommand: "cat firmware-quicklook.json | jq '.structures.uImage'",
		});
	}
	for (const row of structures.squashfs ?? []) {
		pushExtractionTarget({
			type: "squashfs-rootfs",
			offset: row.offset,
			size: row.bytesUsed,
			endian: row.endian,
			compressionName: row.compressionName,
		});
		addClaim({
			id: "firmware-rootfs-squashfs-" + shortHash(`${row.offset}:${row.bytesUsed}:${row.endian}:${row.compressionName}`),
			claimType: "firmware-rootfs-extraction-target",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				structure: "SquashFS",
				offset: row.offset,
			},
			evidenceBinding: {
				endian: row.endian,
				version: row.version,
				blockSize: row.blockSize,
				compressionName: row.compressionName,
				bytesUsed: row.bytesUsed,
				inodes: row.inodes,
			},
			statement: "SquashFS superblock evidence identifies a concrete root filesystem carve target.",
			confidence: 0.9,
			rerunCommand: "cat firmware-quicklook.json | jq '.structures.squashfs'",
		});
	}
	for (const row of structures.ubi ?? []) {
		pushExtractionTarget({
			type: "ubi-volume",
			offset: row.offset,
			vidHeaderOffset: row.vidHeaderOffset,
			dataOffset: row.dataOffset,
		});
		addClaim({
			id: "firmware-rootfs-ubi-" + shortHash(`${row.offset}:${row.vidHeaderOffset}:${row.dataOffset}:${row.imageSequence}`),
			claimType: "firmware-rootfs-extraction-target",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				structure: "UBI",
				offset: row.offset,
			},
			evidenceBinding: {
				version: row.version,
				eraseCount: row.eraseCount,
				vidHeaderOffset: row.vidHeaderOffset,
				dataOffset: row.dataOffset,
				imageSequence: row.imageSequence,
			},
			statement: "UBI EC header evidence identifies a concrete flash-volume extraction target.",
			confidence: 0.86,
			rerunCommand: "cat firmware-quicklook.json | jq '.structures.ubi'",
		});
	}
	for (const row of (signals.credentials ?? []).slice(0, 24)) {
		addClaim({
			id: "firmware-hardcoded-credential-" + shortHash(`${row.offset}:${row.text}`),
			claimType: "firmware-hardcoded-credential",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				offset: row.offset,
			},
			evidenceBinding: {
				text: row.text,
				redacted: /<redacted>|\bredacted\b/i.test(row.text),
			},
			statement: "Firmware string evidence contains a redacted hardcoded credential or token assignment.",
			confidence: 0.78,
			rerunCommand: "cat firmware-quicklook.json | jq '.stringScan.signals.credentials'",
		});
	}
	for (const row of (signals.services ?? []).slice(0, 32)) {
		const exposed = /telnetd|dropbear|uhttpd|lighttpd|boa|login\.cgi|admin\.cgi/i.test(row.text);
		addClaim({
			id: "firmware-service-surface-" + shortHash(`${row.offset}:${row.text}`),
			claimType: exposed ? "firmware-exposed-management-surface" : "firmware-service-or-init-signal",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				offset: row.offset,
			},
			evidenceBinding: {
				text: row.text,
				exposed,
			},
			statement: exposed
				? "Firmware string evidence identifies a management service or web-admin handler."
				: "Firmware string evidence identifies a service/init component for runtime mapping.",
			confidence: exposed ? 0.76 : 0.62,
			rerunCommand: "cat firmware-quicklook.json | jq '.stringScan.signals.services'",
		});
	}
	for (const row of (signals.paths ?? []).slice(0, 32)) {
		const sensitive = /\/etc\/passwd|\/etc\/shadow|\/etc\/init\.d|rcS|\/www\/|cgi-bin/i.test(row.text);
		addClaim({
			id: "firmware-filesystem-path-" + shortHash(`${row.offset}:${row.text}`),
			claimType: sensitive ? "firmware-sensitive-filesystem-path" : "firmware-filesystem-path",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				offset: row.offset,
			},
			evidenceBinding: {
				text: row.text,
				sensitive,
			},
			statement: sensitive
				? "Firmware string evidence identifies a sensitive filesystem, init, or web handler path."
				: "Firmware string evidence identifies a filesystem path for rootfs mapping.",
			confidence: sensitive ? 0.72 : 0.58,
			rerunCommand: "cat firmware-quicklook.json | jq '.stringScan.signals.paths'",
		});
	}
	for (const row of (signals.urls ?? []).slice(0, 16)) {
		addClaim({
			id: "firmware-network-endpoint-" + shortHash(`${row.offset}:${row.text}`),
			claimType: "firmware-network-endpoint",
			sourceBinding: {
				artifact: "firmware-quicklook.json",
				offset: row.offset,
			},
			evidenceBinding: {
				text: row.text,
			},
			statement: "Firmware string evidence identifies a network endpoint for traffic or update-flow replay.",
			confidence: 0.68,
			rerunCommand: "cat firmware-quicklook.json | jq '.stringScan.signals.urls'",
		});
	}
	for (const claim of verification?.claimLedger ?? []) {
		if (claim.verdict !== "promoted") continue;
		addClaim({
			...claim,
			id: claim.id || "firmware-verification-claim-" + shortHash(JSON.stringify(claim)),
			sourceBinding: {
				artifact: "firmware-extraction-verification.json",
				...(claim.sourceBinding ?? {}),
			},
			rerunCommand: claim.rerunCommand ?? "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		});
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const credentialClaim = promotedClaims.find((claim) => claim.claimType === "firmware-hardcoded-credential");
	const serviceClaim = promotedClaims.find((claim) => claim.claimType === "firmware-exposed-management-surface");
	const sensitivePathClaim = promotedClaims.find((claim) => claim.claimType === "firmware-sensitive-filesystem-path");
	const rootfsClaim = promotedClaims.find((claim) => claim.claimType === "firmware-rootfs-extraction-target");
	const rootfsVerifierClaim = promotedClaims.find((claim) => claim.claimType === "firmware-rootfs-carve-proof");
	const extractionNegativeControlClaim = promotedClaims.find((claim) => claim.claimType === "firmware-extraction-negative-control-proof");
	const composedPaths = [];
	for (const path of verification?.composedPaths ?? []) {
		const composed = {
			...path,
			id: path.id || "firmware-verification-path-" + shortHash(JSON.stringify(path)),
			sourceBinding: {
				artifact: "firmware-extraction-verification.json",
				...(path.sourceBinding ?? {}),
			},
			rerunCommand: path.rerunCommand ?? "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	if (credentialClaim && (serviceClaim || sensitivePathClaim)) {
		const segments = [rootfsClaim, rootfsVerifierClaim, credentialClaim, serviceClaim, sensitivePathClaim, extractionNegativeControlClaim].filter(Boolean);
		const composed = {
			id: "firmware-management-credential-pivot-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "firmware-management-credential-pivot",
			sourceBinding: {
				segments: segments.map((claim) => ({
					id: claim.id,
					claimType: claim.claimType,
					offset: claim.sourceBinding?.offset,
				})),
			},
			evidenceBinding: {
				hasRootfsTarget: Boolean(rootfsClaim),
				hasRootfsVerifier: Boolean(rootfsVerifierClaim),
				hasCredential: true,
				hasManagementService: Boolean(serviceClaim),
				hasSensitivePath: Boolean(sensitivePathClaim),
				hasNegativeControl: Boolean(extractionNegativeControlClaim),
			},
			statement: "Firmware evidence composes credential material, management service/path, rootfs carve verifier output, and extraction negative controls into a concrete triage pivot.",
			verdict: "promoted",
			confidence: rootfsVerifierClaim && extractionNegativeControlClaim ? 0.86 : rootfsClaim ? 0.82 : 0.74,
			blockers: [],
			rerunCommand: "cat firmware-attack-surface.json | jq '.composedPaths'",
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!rootfsClaim) blockers.push("missing-rootfs-signature");
	if (!credentialClaim) blockers.push("missing-credential-signal");
	if (!serviceClaim) blockers.push("missing-management-service");
	if (!(structures.uImage ?? []).length) blockers.push("missing-emulation-entrypoint");
	if (!extractionTargets.length) blockers.push("missing-extraction-target");
	for (const blocker of verification?.promotionReport?.blockers ?? []) {
		if (!blockers.includes(blocker)) blockers.push(blocker);
	}
	const repairActions = {
		"missing-rootfs-signature": "Run binwalk/unblob/deeper magic scans or carve nested containers until a root filesystem header is source-bound.",
		"missing-credential-signal": "Scan extracted rootfs configs, NVRAM defaults, web assets, and init scripts for credential assignments.",
		"missing-management-service": "Map init scripts and web roots to management daemons or CGI handlers before exploitation.",
		"missing-emulation-entrypoint": "Bind architecture, kernel/uImage header, or init entrypoint before QEMU/chroot smoke testing.",
		"missing-extraction-target": "Collect at least one carve target with offset/size before claiming rootfs extraction readiness.",
		"missing-firmware-image-hash-verification": "Rerun firmware-extraction-verifier.py against original bytes and require size/SHA-256 equality.",
		"missing-signature-offset-verification": "Bind TRX/uImage/SquashFS/UBI signature claims to exact offset and magic-byte checks.",
		"missing-rootfs-carve-verifier": "Produce a rootfs carve record with offset, bounded size, header/magic, and SHA-256.",
		"rootfs-carve-truncated": "Acquire complete firmware/rootfs bytes or correct the carve size before claiming a full filesystem extraction.",
		"missing-firmware-extraction-negative-control": "Add mutated image/offset controls so bad offsets and byte changes are rejected.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "firmware-attack-surface-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect source-bound firmware evidence and rerun attack-surface claim promotion.",
		rerunCommand: /^missing-(?:firmware-image-hash|signature-offset|rootfs-carve|firmware-extraction-negative-control)|rootfs-carve-truncated/.test(blocker)
			? "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json"
			: "repi engage <firmware-image> --json",
	}));
	return {
		kind: "repi-firmware-attack-surface",
		schemaVersion: 2,
		generatedAt: new Date().toISOString(),
		proofReady: promotedClaims.length > 0,
		extractionTargets,
		extractionVerificationStats: verification?.stats ?? null,
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

function firmwareExtractionVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import tempfile

MAGICS = {
    "uImage": bytes([0x27, 0x05, 0x19, 0x56]),
    "TRX": b"HDR0",
    "UBI": b"UBI#",
    "SquashFS-little": b"hsqs",
    "SquashFS-big": b"sqsh",
    "CramFS": bytes([0x45, 0x3d, 0xcd, 0x28]),
    "gzip": bytes([0x1F, 0x8B, 0x08]),
    "xz": bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
    "ZIP": b"PK\x03\x04",
    "ELF": bytes([0x7F, 0x45, 0x4C, 0x46]),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def expected_magic(target):
    if target.get("type") == "squashfs-rootfs":
        return MAGICS["SquashFS-big" if target.get("endian") == "big" else "SquashFS-little"]
    if target.get("type") == "ubi-volume":
        return MAGICS["UBI"]
    return None


def magic_at(data, offset):
    for name in ("SquashFS-little", "SquashFS-big", "UBI", "uImage", "TRX", "CramFS", "gzip", "xz", "ZIP", "ELF"):
        magic = MAGICS[name]
        if offset >= 0 and offset + len(magic) <= len(data) and data[offset:offset + len(magic)] == magic:
            return name
    return None


def extraction_targets(summary):
    structures = summary.get("structures") or {}
    rows = []
    seen = set()
    def push(row):
        key = (row.get("type"), row.get("offset"), row.get("size"))
        if key not in seen:
            seen.add(key)
            rows.append(row)
    for trx in structures.get("trx") or []:
        for part in trx.get("partitions") or []:
            push({"type": "trx-partition", "offset": part.get("absoluteOffset"), "size": part.get("size"), "containerOffset": trx.get("offset")})
    for sq in structures.get("squashfs") or []:
        push({"type": "squashfs-rootfs", "offset": sq.get("offset"), "size": sq.get("bytesUsed"), "endian": sq.get("endian"), "compressionName": sq.get("compressionName")})
    for ubi in structures.get("ubi") or []:
        push({"type": "ubi-volume", "offset": ubi.get("offset"), "vidHeaderOffset": ubi.get("vidHeaderOffset"), "dataOffset": ubi.get("dataOffset")})
    for ui in structures.get("uImage") or []:
        push({"type": "uimage-payload", "offset": int(ui.get("offset", 0)) + 64, "size": ui.get("size"), "containerOffset": ui.get("offset"), "arch": ui.get("arch"), "compression": ui.get("compression")})
    return rows


def verify(firmware_path, quicklook_path):
    with open(firmware_path, "rb") as handle:
        data = handle.read()
    with open(quicklook_path, "r", encoding="utf-8") as handle:
        summary = json.load(handle)
    image_identity = {"size": len(data), "sha256": sha256(data), "headerHex": data[:16].hex(), "verified": len(data) == summary.get("size") and sha256(data) == summary.get("sha256")}
    if data:
        mutated = bytearray(data)
        mutated[0] ^= 0xFF
        mutated_sha = sha256(bytes(mutated))
        image_identity["negativeControl"] = {"controlType": "firmware-image-byte-mutation-rejection", "mutatedSha256": mutated_sha, "passed": mutated_sha != summary.get("sha256")}
    signature_checks = []
    for sig in summary.get("signatures") or []:
        magic = MAGICS.get(sig.get("name"))
        for offset in sig.get("offsets") or []:
            verified = False
            reason = "missing-magic"
            actual = {}
            control = None
            if magic and offset >= 0 and offset + len(magic) <= len(data):
                chunk = data[offset:offset + len(magic)]
                actual = {"magicHex": chunk.hex(), "length": len(chunk), "sha256": sha256(chunk)}
                verified = chunk == magic
                reason = "signature-magic-match" if verified else "signature-magic-mismatch"
                mutated_offset = offset + 1 if offset + 1 + len(magic) <= len(data) else (offset - 1 if offset > 0 else None)
                if mutated_offset is not None:
                    mutated = data[mutated_offset:mutated_offset + len(magic)]
                    control = {"controlType": "signature-mutated-offset-rejection", "mutatedOffset": mutated_offset, "mutatedSha256": sha256(mutated), "passed": mutated != magic}
            elif magic:
                reason = "signature-offset-out-of-range"
            signature_checks.append({"name": sig.get("name"), "offset": offset, "expectedMagicHex": magic.hex() if magic else None, "actual": actual, "verified": verified, "reason": reason, "negativeControl": control})
    carve_checks = []
    targets = extraction_targets(summary)
    for target in targets:
        try:
            offset = int(target.get("offset"))
        except Exception:
            offset = -1
        try:
            requested = int(target.get("size", len(data) - offset))
        except Exception:
            requested = len(data) - offset
        verified = False
        complete = False
        reason = "target-out-of-range"
        actual = {}
        control = None
        if offset >= 0 and offset < len(data):
            bounded = min(requested, len(data) - offset) if requested > 0 else len(data) - offset
            carved = data[offset:offset + bounded]
            exp = expected_magic(target)
            complete = (offset + requested <= len(data)) if requested > 0 else True
            actual = {"offset": offset, "requestedSize": requested if requested > 0 else None, "carvedSize": len(carved), "sha256": sha256(carved), "headerHex": carved[:16].hex(), "observedMagic": magic_at(data, offset), "complete": complete}
            verified = carved.startswith(exp) if exp else len(carved) > 0
            reason = "carve-offset-size-hash-match" if verified and complete else ("carve-header-match-but-truncated" if verified else "carve-header-mismatch")
            mutated_offset = offset + 1 if offset + 1 + min(len(carved), 16) <= len(data) else (offset - 1 if offset > 0 else None)
            if mutated_offset is not None:
                mutated = data[mutated_offset:mutated_offset + min(len(carved), 64)]
                control = {"controlType": "carve-mutated-offset-rejection", "mutatedOffset": mutated_offset, "mutatedSha256": sha256(mutated), "passed": sha256(mutated) != actual["sha256"]}
        carve_checks.append({"target": target, "actual": actual, "verified": verified, "complete": complete, "reason": reason, "negativeControl": control})
    controls = [image_identity.get("negativeControl")] + [row.get("negativeControl") for row in signature_checks] + [row.get("negativeControl") for row in carve_checks]
    controls = [row for row in controls if row and row.get("passed")]
    verified_sigs = [row for row in signature_checks if row.get("verified")]
    rootfs = [row for row in carve_checks if row.get("verified") and row.get("target", {}).get("type") in {"squashfs-rootfs", "ubi-volume"}]
    blockers = []
    if not image_identity.get("verified"):
        blockers.append("missing-firmware-image-hash-verification")
    if not verified_sigs:
        blockers.append("missing-signature-offset-verification")
    if not rootfs:
        blockers.append("missing-rootfs-carve-verifier")
    if any(not row.get("complete") for row in rootfs):
        blockers.append("rootfs-carve-truncated")
    if not controls:
        blockers.append("missing-firmware-extraction-negative-control")
    repair_queue = [{"id": "firmware-extraction-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound firmware extraction evidence and rerun firmware-extraction-verifier.py.", "rerunCommand": "python3 firmware-extraction-verifier.py <firmware> firmware-quicklook.json firmware-extraction-verification.json"} for blocker in blockers]
    proof_ready = image_identity.get("verified") and bool(verified_sigs) and bool(rootfs) and bool(controls)
    return {"kind": "repi-firmware-extraction-verification", "schemaVersion": 1, "target": firmware_path, "proofReady": proof_ready, "imageIdentity": image_identity, "signatureChecks": signature_checks, "extractionTargets": targets, "carveChecks": carve_checks, "negativeControls": controls, "stats": {"signaturesVerified": len(verified_sigs), "rootfsCarvesVerified": len(rootfs), "completeRootfsCarves": sum(1 for row in rootfs if row.get("complete")), "negativeControlsPassed": len(controls)}, "repairQueue": repair_queue, "promotionReport": {"proofReady": proof_ready, "blockers": blockers}}


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        fw = bytearray(0x200)
        fw[0:4] = b"HDR0"
        fw[4:8] = (0x180).to_bytes(4, "little")
        fw[16:20] = (0x40).to_bytes(4, "little")
        fw[0x40:0x44] = b"hsqs"
        fw[0x68:0x70] = (0x80).to_bytes(8, "little")
        path = os.path.join(tmp, "fw.bin")
        with open(path, "wb") as handle:
            handle.write(fw)
        summary = {"size": len(fw), "sha256": sha256(bytes(fw)), "signatures": [{"name": "TRX", "offsets": [0]}, {"name": "SquashFS-little", "offsets": [0x40]}], "structures": {"trx": [{"offset": 0, "partitions": [{"absoluteOffset": 0x40, "size": 0x140}]}], "squashfs": [{"offset": 0x40, "bytesUsed": 0x80, "endian": "little", "compressionName": "xz"}], "ubi": [], "uImage": []}}
        quicklook = os.path.join(tmp, "firmware-quicklook.json")
        with open(quicklook, "w", encoding="utf-8") as handle:
            json.dump(summary, handle)
        result = verify(path, quicklook)
        assert result["proofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-firmware-extraction-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Verify REPI firmware signature/rootfs carve evidence without extracting or executing firmware.")
    parser.add_argument("firmware", nargs="?")
    parser.add_argument("quicklook", nargs="?", default="firmware-quicklook.json")
    parser.add_argument("output", nargs="?", default="firmware-extraction-verification.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.firmware:
        parser.error("firmware is required unless --self-test is used")
    result = verify(args.firmware, args.quicklook)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
`;
}


function firmwareExtractPlanSource(target, summary) {
	const signatureRows = summary.signatures.flatMap((signature) => signature.offsets.map((offset) => ({ name: signature.name, offset })));
	return `#!/usr/bin/env bash
set -euo pipefail

FW=\${1:-${shellQuote(target)}}
OUT=\${2:-firmware-extract-\$(basename "$FW")}
mkdir -p "$OUT"/{binwalk,unblob,carves,logs}
printf '[repi-firmware] input=%s out=%s\\n' "$FW" "$OUT" | tee "$OUT/logs/plan.log"

if command -v binwalk >/dev/null 2>&1; then
  binwalk -Me "$FW" -C "$OUT/binwalk" | tee "$OUT/logs/binwalk.log" || true
else
  printf '[repi-firmware] binwalk=missing\\n' | tee -a "$OUT/logs/plan.log"
fi

if command -v unblob >/dev/null 2>&1; then
  unblob "$FW" "$OUT/unblob" | tee "$OUT/logs/unblob.log" || true
else
  printf '[repi-firmware] unblob=missing\\n' | tee -a "$OUT/logs/plan.log"
fi

python3 - "$FW" "$OUT/carves" <<'PY'
import json
import os
import re
import sys

fw, out = sys.argv[1], sys.argv[2]
rows = ${JSON.stringify(signatureRows)}
with open(fw, "rb") as handle:
    data = handle.read()
for row in rows:
    offset = int(row["offset"])
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", row["name"])
    path = os.path.join(out, f"{offset:08x}-{name}.bin")
    with open(path, "wb") as handle:
        handle.write(data[offset:])
    print("[repi-firmware-carve]", json.dumps({"offset": offset, "name": row["name"], "path": path}, sort_keys=True))
PY

cat > "$OUT/next.txt" <<'EOF'
1. Run file/find/strings over carves and extracted rootfs.
2. Prioritize /etc/passwd, /etc/shadow, /etc/init.d, rcS, nvram defaults, www/cgi-bin.
3. Map exposed services and web CGI handlers to credentials/config sinks.
4. Rerun firmware-extraction-verifier.py when present; require signature/carve hashes and mutation controls before proof promotion.
5. If rootfs is valid and complete, build chroot/qemu smoke only after binding the entrypoint and architecture.
EOF
`;
}

export function firmwareQuicklookRows(target, artifactDir) {
	try {
		const summary = firmwareQuicklookSummary(target);
		const extractionVerification = firmwareExtractionVerificationSummary(target, summary);
		const attackSurface = firmwareAttackSurfaceClaims(summary, extractionVerification);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "firmware-quicklook.json"), `${JSON.stringify(summary, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "firmware-extraction-verification.json"), `${JSON.stringify(extractionVerification, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "firmware-attack-surface.json"), `${JSON.stringify(attackSurface, null, 2)}\n`);
		const rows = [
			{
				id: "firmware-quicklook",
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
				id: "firmware-extraction-verification",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: extractionVerification.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(extractionVerification, null, 2)}\n`,
				stderr: "",
				error: extractionVerification.proofReady ? undefined : "firmware extraction verification blockers present",
			},
			{
				id: "firmware-attack-surface",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: attackSurface.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(attackSurface, null, 2)}\n`,
				stderr: "",
				error: attackSurface.proofReady ? undefined : "no firmware attack-surface claims promoted",
			},
		];
		if (!noWrite && artifactDir) {
			const verifierPath = join(artifactDir, "firmware-extraction-verifier.py");
			writePrivate(verifierPath, firmwareExtractionVerifierSource(), 0o700);
			rows.push({
				id: "firmware-extraction-verifier-artifact",
				command: "internal",
				args: [redact(verifierPath)],
				cwd: root,
				exit: 0,
				signal: null,
				durationMs: 0,
				stdout: `verifier=${redact(verifierPath)}\nrun=python3 ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "firmware-quicklook.json"))} ${redact(join(artifactDir, "firmware-extraction-verification.json"))}\n`,
				stderr: "",
				error: undefined,
			});
			const planPath = join(artifactDir, "firmware-extract-plan.sh");
			writePrivate(planPath, firmwareExtractPlanSource(target, summary), 0o700);
			rows.push({
				id: "firmware-extract-plan-artifact",
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
		return [{ id: "firmware-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}
