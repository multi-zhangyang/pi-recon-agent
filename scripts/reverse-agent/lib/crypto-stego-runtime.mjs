import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";

let noWrite;
let root;
let redact;
let writePrivate;
let bufferSha256;
let httpSecretHash;
let shortHash;
let shellQuote;
let readJsonArtifact;
let byteEntropy;
let parseZipCentralDirectory;

export function configureCryptoStegoRuntime(runtime) {
	({ noWrite, root, redact, writePrivate, bufferSha256, httpSecretHash, shortHash, shellQuote, readJsonArtifact, byteEntropy, parseZipCentralDirectory } = runtime);
}
function cryptoStegoSolverSource(target) {
	return `#!/usr/bin/env python3
import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import string
import sys
import zlib

TARGET = sys.argv[1] if len(sys.argv) > 1 else ${JSON.stringify(target)}
MAX_STRINGS = int(os.getenv("REPI_CRYPTO_STEGO_MAX_STRINGS", "120"))
PRINTABLE = set(bytes(string.printable, "ascii"))

def is_printable(blob):
    return bool(blob) and sum(ch in PRINTABLE for ch in blob) / max(1, len(blob)) >= 0.85

def redact_text(text):
    text = re.sub(r"(?i)(secret|token|password|passwd|api[_-]?key|client[_-]?secret)=([^\\s&;,'\\\"]+)", r"\\1=<redacted>", text)
    text = re.sub(r"(?i)Bearer\\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer <redacted>", text)
    text = re.sub(r"sk-[A-Za-z0-9._-]{8,}", "<redacted:api-key>", text)
    return text

def safe_text(blob, limit=240):
    return redact_text(blob[:limit].decode("utf-8", "replace"))

def rows(label, values):
    for value in values:
        print("[crypto-stego]", json.dumps({"label": label, **value}, sort_keys=True))

def printable_strings(data):
    return [match.group(0) for match in re.finditer(rb"[ -~]{4,}", data)][:MAX_STRINGS]

def try_base64(strings):
    out = []
    for item in strings:
        if len(item) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/=_-]+", item):
            continue
        normalized = item.replace(b"-", b"+").replace(b"_", b"/")
        normalized += b"=" * ((4 - len(normalized) % 4) % 4)
        try:
            decoded = base64.b64decode(normalized, validate=False)
        except (binascii.Error, ValueError):
            continue
        if decoded and (is_printable(decoded) or re.search(rb"flag\\{|ctf\\{|key|password|secret", decoded, re.I)):
            out.append({"source": safe_text(item, 120), "decodedSha256": hashlib.sha256(decoded).hexdigest(), "decoded": safe_text(decoded)})
            if len(out) >= 20:
                break
    return out

def try_base64_blob(blob):
    if len(blob) < 8 or len(blob) > 2_000_000:
        return None
    compact = re.sub(rb"\\s+", b"", blob.strip())
    if len(compact) < 8 or not re.fullmatch(rb"[A-Za-z0-9+/=_-]+", compact):
        return None
    normalized = compact.replace(b"-", b"+").replace(b"_", b"/")
    normalized += b"=" * ((4 - len(normalized) % 4) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=False)
    except (binascii.Error, ValueError):
        return None
    return decoded if decoded and decoded != blob else None

def try_hex_blob(blob):
    compact = re.sub(rb"\\s+", b"", blob.strip())
    if len(compact) < 8 or len(compact) % 2 or not re.fullmatch(rb"[0-9A-Fa-f]+", compact):
        return None
    try:
        decoded = binascii.unhexlify(compact)
    except (binascii.Error, ValueError):
        return None
    return decoded if decoded and decoded != blob else None

def try_compression_blob(blob):
    if blob.startswith(b"\\x1f\\x8b\\x08"):
        try:
            return ("gzip", gzip.decompress(blob[:2_000_000]))
        except (OSError, EOFError, zlib.error):
            return None
    if len(blob) >= 2 and blob[0] == 0x78 and blob[1] in (0x01, 0x5e, 0x9c, 0xda):
        try:
            return ("zlib", zlib.decompress(blob[:2_000_000]))
        except zlib.error:
            return None
    return None

def interesting(blob):
    return bool(blob) and (is_printable(blob[:4096]) or re.search(rb"flag\\{|ctf\\{|key|password|secret|token|PK\\x03\\x04|BEGIN [A-Z ]+KEY", blob[:4096], re.I))

def transform_candidates(blob):
    out = []
    decoded = try_base64_blob(blob)
    if decoded:
        out.append(("base64", decoded))
    decoded = try_hex_blob(blob)
    if decoded:
        out.append(("hex", decoded))
    compressed = try_compression_blob(blob)
    if compressed:
        out.append(compressed)
    if 4 <= len(blob) <= 512 * 1024:
        for key in range(1, 256):
            xored = bytes(ch ^ key for ch in blob)
            if interesting(xored):
                out.append((f"xor-single-byte:{key}", xored))
                break
    return out

def transform_chain(seed_rows, max_depth=3, limit=24):
    queue = [(label, blob, []) for label, blob in seed_rows if blob]
    seen = {hashlib.sha256(blob).hexdigest() for _, blob, _ in queue}
    out = []
    while queue and len(out) < limit:
        label, blob, chain = queue.pop(0)
        if len(chain) >= max_depth:
            continue
        for transform, decoded in transform_candidates(blob):
            if not decoded or len(decoded) > 2_000_000:
                continue
            digest = hashlib.sha256(decoded).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            next_chain = chain + [transform]
            row = {
                "source": label,
                "chain": next_chain,
                "decodedSha256": digest,
                "decodedLength": len(decoded),
                "interesting": interesting(decoded),
                "sample": safe_text(decoded) if interesting(decoded) else "",
            }
            out.append(row)
            queue.append((label, decoded, next_chain))
    return out

def try_single_byte_xor(data):
    needles = [b"flag{", b"ctf{", b"FLAG{", b"CTF{"]
    out = []
    for key in range(1, 256):
        xored = bytes(ch ^ key for ch in data[:2_000_000])
        for needle in needles:
            offset = xored.find(needle)
            if offset >= 0:
                start = max(0, offset - 48)
                end = min(len(xored), offset + 160)
                out.append({"key": key, "offset": offset, "sample": safe_text(xored[start:end])})
                break
        if len(out) >= 20:
            break
    return out

def main():
    with open(TARGET, "rb") as handle:
        data = handle.read()
    print("[crypto-stego]", json.dumps({"label": "file", "target": TARGET, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "headerHex": data[:32].hex()}, sort_keys=True))
    strings_found = printable_strings(data)
    signal_strings = [value for value in strings_found if re.search(rb"flag|ctf|key|password|secret|salt|nonce|iv|base64|xor|cipher", value, re.I)]
    rows("signal-string", [{"text": safe_text(value)} for value in signal_strings[:40]])
    rows("base64-decode", try_base64(strings_found))
    rows("single-byte-xor", try_single_byte_xor(data))
    token_rows = []
    for index, value in enumerate(strings_found[:80]):
        for token_index, token in enumerate(re.findall(rb"[A-Za-z0-9+/=_-]{8,}", value)):
            token_rows.append((f"string-{index}-token-{token_index}", token))
            if len(token_rows) >= 120:
                break
        if len(token_rows) >= 120:
            break
    seed_rows = [("file", data[:2_000_000]), *[(f"string-{index}", value) for index, value in enumerate(strings_found[:80])], *token_rows]
    rows("transform-chain", transform_chain(seed_rows))
    print("[crypto-stego]", json.dumps({"label": "next", "message": "If no direct hit, inspect metadata/binwalk/zsteg output, then model the transform chain with this script as the verifier harness."}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
`;
}

export function writeCryptoStegoSolver(artifactDir, target) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "crypto-stego-solver.py");
	writePrivate(path, cryptoStegoSolverSource(target), 0o700);
	return path;
}

function cryptoStegoVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import stat
import tempfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(path, media):
    with open(path, "rb") as handle:
        data = handle.read()
    st = os.stat(path)
    identity = {
        "size": len(data),
        "sha256": sha256(data),
        "headerHex": data[:16].hex(),
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "verified": len(data) == media.get("size") and sha256(data) == media.get("sha256") if media else True,
    }
    if data:
        mutated = bytearray(data)
        mutated[0] ^= 0xFF
        identity["negativeControl"] = {
            "controlType": "crypto-file-byte-mutation-rejection",
            "mutatedSha256": sha256(bytes(mutated)),
            "passed": sha256(bytes(mutated)) != identity["sha256"],
        }
    return data, identity


def check_png_chunk(data, chunk):
    offset = int(chunk.get("offset", -1))
    length = int(chunk.get("length", -1))
    expected_type = chunk.get("type")
    verified = False
    reason = "chunk-out-of-range"
    actual = {}
    control = None
    if offset >= 0 and length >= 0 and offset + 12 + length <= len(data):
        actual_type = data[offset + 4:offset + 8].decode("latin1", "replace")
        payload = data[offset + 8:offset + 8 + length]
        actual = {"offset": offset, "type": actual_type, "length": length, "sha256": sha256(payload)}
        verified = actual_type == expected_type and actual["sha256"] == chunk.get("sha256")
        reason = "chunk-offset-hash-match" if verified else "chunk-offset-hash-mismatch"
        shifted = offset + 1 if offset + 1 + min(length, 16) <= len(data) else (offset - 1 if offset > 0 else None)
        if shifted is not None:
            shifted_payload = data[shifted + 8:shifted + 8 + min(length, 64)] if shifted + 8 < len(data) else b""
            control = {"controlType": "crypto-chunk-shifted-offset-rejection", "offset": shifted, "mutatedSha256": sha256(shifted_payload), "passed": sha256(shifted_payload) != chunk.get("sha256")}
    return {"kind": "chunk", "type": expected_type, "offset": offset, "length": length, "actual": actual, "verified": verified, "reason": reason, "negativeControl": control}


def check_slice(data, row, kind):
    if not row:
        return None
    offset = int(row.get("offset", -1))
    length = int(row.get("length", -1))
    expected_sha = row.get("sha256")
    verified = False
    actual = {}
    control = None
    reason = "slice-out-of-range"
    if offset >= 0 and length >= 0 and offset + length <= len(data):
        payload = data[offset:offset + length]
        actual = {"offset": offset, "length": length, "sha256": sha256(payload), "headerHex": payload[:16].hex()}
        verified = sha256(payload) == expected_sha
        reason = "slice-offset-hash-match" if verified else "slice-offset-hash-mismatch"
        shifted = offset + 1 if offset + 1 + min(length, 16) <= len(data) else (offset - 1 if offset > 0 else None)
        if shifted is not None:
            shifted_payload = data[shifted:shifted + min(length, 64)]
            control = {"controlType": "crypto-slice-shifted-offset-rejection", "kind": kind, "offset": shifted, "mutatedSha256": sha256(shifted_payload), "passed": sha256(shifted_payload) != expected_sha}
    return {"kind": kind, "offset": offset, "length": length, "expectedSha256": expected_sha, "actual": actual, "verified": verified, "reason": reason, "negativeControl": control}


def verify(target, media_path):
    media = None
    if media_path and os.path.exists(media_path):
        with open(media_path, "r", encoding="utf-8") as handle:
            media = json.load(handle)
    data, identity = file_identity(target, media or {})
    structure_checks = []
    if media:
        if media.get("format") == "png":
            structure_checks.extend(check_png_chunk(data, chunk) for chunk in media.get("chunks") or [])
        else:
            for chunk in media.get("chunks") or []:
                structure_checks.append(check_slice(data, {"offset": int(chunk.get("offset", 0)) + 8, "length": chunk.get("length"), "sha256": chunk.get("sha256")}, "chunk:" + str(chunk.get("type"))))
        if media.get("trailing"):
            structure_checks.append(check_slice(data, media.get("trailing"), "trailing"))
        if media.get("audioData"):
            structure_checks.append(check_slice(data, media.get("audioData"), "audio-data"))
        for archive in media.get("embeddedArchives") or []:
            if archive.get("length") and archive.get("sha256"):
                structure_checks.append(check_slice(data, archive, "embedded-archive"))
    structure_checks = [row for row in structure_checks if row]
    controls = [identity.get("negativeControl")] + [row.get("negativeControl") for row in structure_checks]
    controls = [row for row in controls if row and row.get("passed")]
    verified_structures = [row for row in structure_checks if row.get("verified")]
    blockers = []
    if not identity.get("verified"):
        blockers.append("missing-crypto-file-hash-verification")
    if media and not verified_structures:
        blockers.append("missing-crypto-structure-offset-verification")
    if not controls:
        blockers.append("missing-crypto-negative-control")
    proof_ready = identity.get("verified") and (not media or bool(verified_structures)) and bool(controls)
    repair_queue = [{"id": "crypto-stego-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound crypto/stego offsets and rerun crypto-stego-verifier.py.", "rerunCommand": "python3 crypto-stego-verifier.py <target> crypto-stego-media-quicklook.json crypto-stego-verification.json"} for blocker in blockers]
    return {
        "kind": "repi-crypto-stego-verification",
        "schemaVersion": 1,
        "target": target,
        "proofReady": proof_ready,
        "fileIdentity": identity,
        "mediaQuicklook": {"present": bool(media), "format": media.get("format") if media else None, "sha256": sha256(json.dumps(media, sort_keys=True).encode()) if media else None},
        "structureChecks": structure_checks,
        "negativeControls": controls,
        "stats": {"structuresVerified": len(verified_structures), "negativeControlsPassed": len(controls)},
        "repairQueue": repair_queue,
        "promotionReport": {"proofReady": proof_ready, "blockers": blockers},
    }


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        payload = b"hide"
        data = b"\x89PNG\r\n\x1a\n" + len(payload).to_bytes(4, "big") + b"tEXt" + payload + b"\x00\x00\x00\x00" + b"TRAIL"
        target = os.path.join(tmp, "sample.png")
        with open(target, "wb") as handle:
            handle.write(data)
        media = {
            "kind": "repi-crypto-stego-media-quicklook",
            "schemaVersion": 1,
            "format": "png",
            "size": len(data),
            "sha256": sha256(data),
            "chunks": [{"offset": 8, "type": "tEXt", "length": len(payload), "sha256": sha256(payload)}],
            "trailing": {"offset": len(data) - 5, "length": 5, "sha256": sha256(b"TRAIL")},
            "embeddedArchives": [],
        }
        media_path = os.path.join(tmp, "crypto-stego-media-quicklook.json")
        with open(media_path, "w", encoding="utf-8") as handle:
            json.dump(media, handle)
        result = verify(target, media_path)
        assert result["proofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-crypto-stego-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Verify REPI crypto/stego file, media offsets, carves, and negative controls.")
    parser.add_argument("target", nargs="?")
    parser.add_argument("media", nargs="?", default="crypto-stego-media-quicklook.json")
    parser.add_argument("output", nargs="?", default="crypto-stego-verification.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.target:
        parser.error("target is required unless --self-test is used")
    result = verify(args.target, args.media)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
`;
}

export function writeCryptoStegoVerifier(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "crypto-stego-verifier.py");
	writePrivate(path, cryptoStegoVerifierSource(), 0o700);
	return path;
}

function dataLooksLikePng(target) {
	try {
		const data = readFileSync(target);
		return data.length >= 8 && data.subarray(0, 8).toString("hex") === "89504e470d0a1a0a";
	} catch {
		return false;
	}
}

function dataLooksLikeWav(target) {
	try {
		const data = readFileSync(target);
		return data.length >= 12 && data.subarray(0, 4).toString("ascii") === "RIFF" && data.subarray(8, 12).toString("ascii") === "WAVE";
	} catch {
		return false;
	}
}

export function dataLooksLikeCryptoStegoMedia(target) {
	return dataLooksLikePng(target) || dataLooksLikeWav(target);
}

function pngTypeFlags(type) {
	const bytes = Buffer.from(type, "ascii");
	return {
		ancillary: Boolean(bytes[0] & 0x20),
		private: Boolean(bytes[1] & 0x20),
		reservedLowercase: Boolean(bytes[2] & 0x20),
		safeToCopy: Boolean(bytes[3] & 0x20),
	};
}

function pngTextValue(type, chunkData) {
	const firstNull = chunkData.indexOf(0);
	if (firstNull < 0) return undefined;
	const keyword = redact(chunkData.toString("latin1", 0, firstNull).replace(/[^\x20-\x7e]/g, "?").slice(0, 80));
	try {
		if (type === "tEXt") {
			return { keyword, text: redact(chunkData.toString("utf8", firstNull + 1).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "?").slice(0, 400)) };
		}
		if (type === "zTXt" && firstNull + 2 <= chunkData.length) {
			const compressionMethod = chunkData[firstNull + 1];
			const compressed = chunkData.subarray(firstNull + 2);
			const text = compressionMethod === 0 ? inflateSync(compressed).toString("utf8") : "";
			return { keyword, compressed: true, compressionMethod, text: redact(text.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "?").slice(0, 400)) };
		}
		if (type === "iTXt" && firstNull + 3 <= chunkData.length) {
			const compressionFlag = chunkData[firstNull + 1];
			const compressionMethod = chunkData[firstNull + 2];
			let cursor = firstNull + 3;
			const languageEnd = chunkData.indexOf(0, cursor);
			if (languageEnd < 0) return { keyword, text: "" };
			cursor = languageEnd + 1;
			const translatedEnd = chunkData.indexOf(0, cursor);
			if (translatedEnd < 0) return { keyword, text: "" };
			cursor = translatedEnd + 1;
			const payload = chunkData.subarray(cursor);
			const text = compressionFlag && compressionMethod === 0 ? inflateSync(payload).toString("utf8") : payload.toString("utf8");
			return { keyword, compressed: Boolean(compressionFlag), compressionMethod, text: redact(text.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "?").slice(0, 400)) };
		}
	} catch (error) {
		return { keyword, error: error instanceof Error ? redact(error.message) : redact(String(error)) };
	}
	return undefined;
}

function pngTrailingSample(data, offset) {
	const sample = data.subarray(offset, Math.min(data.length, offset + 160));
	return redact(sample.toString("latin1").replace(/[^\x09\x0a\x0d\x20-\x7e]/g, ".").slice(0, 160));
}

export function embeddedZipArchives(data, searchOffset, searchLength, limit = 8) {
	const archives = [];
	if (!Number.isFinite(searchOffset) || !Number.isFinite(searchLength) || searchOffset < 0 || searchLength <= 0 || searchOffset >= data.length) return archives;
	const searchEnd = Math.min(data.length, searchOffset + searchLength);
	let cursor = searchOffset;
	while (archives.length < limit && cursor + 4 <= searchEnd) {
		const offset = data.indexOf(Buffer.from("PK\u0003\u0004", "binary"), cursor);
		if (offset < 0 || offset >= searchEnd) break;
		try {
			const slice = data.subarray(offset);
			const parsed = parseZipCentralDirectory(slice, 200);
			const eocdEnd = parsed.eocd.offset + 22 + parsed.eocd.commentLength;
			archives.push({
				format: "zip",
				offset,
				length: eocdEnd,
				sha256: bufferSha256(slice.subarray(0, Math.min(slice.length, eocdEnd))),
				entryCount: parsed.entries.length,
				entries: parsed.entries.slice(0, 80).map((entry) => ({
					name: redact(entry.name),
					method: entry.method,
					compressedSize: entry.compressedSize,
					uncompressedSize: entry.uncompressedSize,
					crc32: entry.crc32,
					localHeaderOffset: offset + entry.localHeaderOffset,
				})),
			});
			cursor = offset + Math.max(4, eocdEnd);
		} catch (error) {
			archives.push({
				format: "zip",
				offset,
				parseError: error instanceof Error ? redact(error.message) : redact(String(error)),
			});
			cursor = offset + 4;
		}
	}
	return archives;
}

function pngStegoQuicklook(data) {
	const chunks = [];
	const text = [];
	const risks = [];
	let cursor = 8;
	let truncated = false;
	let ihdr = null;
	let idatCount = 0;
	let idatBytes = 0;
	let iendOffset = null;
	while (cursor + 12 <= data.length && chunks.length < 512) {
		const offset = cursor;
		const length = data.readUInt32BE(cursor);
		const type = data.toString("ascii", cursor + 4, cursor + 8).replace(/[^\x20-\x7e]/g, "?");
		const chunkStart = cursor + 8;
		const chunkEnd = chunkStart + length;
		const crcEnd = chunkEnd + 4;
		if (crcEnd > data.length) {
			truncated = true;
			risks.push("malformed-png-chunk");
			break;
		}
		const chunkData = data.subarray(chunkStart, chunkEnd);
		const flags = pngTypeFlags(type);
		if (type === "IHDR" && length >= 13) {
			ihdr = {
				width: chunkData.readUInt32BE(0),
				height: chunkData.readUInt32BE(4),
				bitDepth: chunkData[8],
				colorType: chunkData[9],
				compression: chunkData[10],
				filter: chunkData[11],
				interlace: chunkData[12],
			};
		}
		if (type === "IDAT") {
			idatCount += 1;
			idatBytes += length;
		}
		if (["tEXt", "zTXt", "iTXt"].includes(type)) {
			const row = pngTextValue(type, chunkData);
			if (row) text.push({ offset, type, ...row });
		}
		chunks.push({
			index: chunks.length,
			offset,
			type,
			length,
			crc32: `0x${data.readUInt32BE(chunkEnd).toString(16).padStart(8, "0")}`,
			sha256: bufferSha256(chunkData),
			...flags,
		});
		cursor = crcEnd;
		if (flags.private || flags.reservedLowercase) risks.push("private-or-nonstandard-png-chunk");
		if (type === "IEND") {
			iendOffset = offset;
			break;
		}
	}
	const trailingOffset = cursor;
	const trailingLength = Math.max(0, data.length - trailingOffset);
	if (!ihdr) risks.push("missing-ihdr");
	if (!idatCount) risks.push("missing-idat");
	if (iendOffset === null) risks.push("missing-iend");
	if (truncated) risks.push("truncated-png-structure");
	if (text.length) risks.push("png-text-metadata-signal");
	if (text.some((row) => /flag|ctf|key|password|secret|token|nonce|salt|base64|xor|cipher/i.test(row.text ?? ""))) risks.push("png-text-stego-signal");
	if (trailingLength > 0) risks.push("appended-data-after-iend");
	const embeddedArchives = embeddedZipArchives(data, trailingOffset, trailingLength);
	if (trailingLength > 0 && (embeddedArchives.length || data.subarray(trailingOffset, Math.min(data.length, trailingOffset + 8)).includes(Buffer.from("PK")))) risks.push("appended-zip-after-iend");
	if (embeddedArchives.some((archive) => !archive.parseError)) risks.push("embedded-zip-archive-parsed");
	const trailing = trailingLength
		? {
				offset: trailingOffset,
				length: trailingLength,
				sha256: bufferSha256(data.subarray(trailingOffset)),
				sample: pngTrailingSample(data, trailingOffset),
			}
		: null;
	return {
		kind: "repi-crypto-stego-media-quicklook",
		schemaVersion: 1,
		format: "png",
		supported: true,
		size: data.length,
		sha256: bufferSha256(data),
		ihdr,
		chunkCount: chunks.length,
		chunks,
		idat: { count: idatCount, bytes: idatBytes },
		text,
		trailing,
		embeddedArchives,
		risks: Array.from(new Set(risks)),
		next: [
			"Inspect text/private chunks and appended data before brute-forcing LSB paths.",
			"If trailing data starts with PK, carve from the trailing offset and unzip/test passwords.",
			"Bind any decoded flag or key to chunk offset, hash, and transform chain.",
		],
	};
}

function wavInfoMetadata(chunkData, chunkOffset) {
	const rows = [];
	let cursor = 4;
	while (cursor + 8 <= chunkData.length && rows.length < 80) {
		const id = chunkData.toString("ascii", cursor, cursor + 4).replace(/[^\x20-\x7e]/g, "?");
		const size = chunkData.readUInt32LE(cursor + 4);
		const start = cursor + 8;
		const end = start + size;
		if (end > chunkData.length) break;
		const value = redact(chunkData.toString("utf8", start, end).replace(/\0+$/g, "").replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "?").slice(0, 400));
		rows.push({ id, offset: chunkOffset + cursor, size, value });
		cursor = end + (size % 2);
	}
	return rows;
}

function packedLsbBytes(data, bit = 0, limitBytes = 512) {
	const outputLength = Math.min(limitBytes, Math.floor(data.length / 8));
	const out = Buffer.alloc(outputLength);
	for (let index = 0; index < outputLength; index++) {
		let value = 0;
		for (let bitIndex = 0; bitIndex < 8; bitIndex++) {
			value |= ((data[index * 8 + bitIndex] >> bit) & 1) << bitIndex;
		}
		out[index] = value;
	}
	return out;
}

function printableRuns(buffer, limit = 12) {
	const runs = [];
	for (const match of buffer.toString("latin1").matchAll(/[ -~]{4,}/g)) {
		runs.push({
			offset: match.index ?? 0,
			text: redact(match[0].slice(0, 240)),
		});
		if (runs.length >= limit) break;
	}
	return runs;
}

function wavStegoQuicklook(data) {
	if (data.length < 12 || data.subarray(0, 4).toString("ascii") !== "RIFF" || data.subarray(8, 12).toString("ascii") !== "WAVE") {
		return { kind: "repi-crypto-stego-media-quicklook", schemaVersion: 1, format: "unknown", supported: false, reason: "not-wav-signature" };
	}
	const declaredSize = data.readUInt32LE(4);
	const declaredEnd = Math.min(data.length, declaredSize + 8);
	const chunks = [];
	const metadata = [];
	const risks = [];
	let fmt = null;
	let audioData = null;
	let cursor = 12;
	while (cursor + 8 <= declaredEnd && chunks.length < 512) {
		const offset = cursor;
		const type = data.toString("ascii", cursor, cursor + 4).replace(/[^\x20-\x7e]/g, "?");
		const length = data.readUInt32LE(cursor + 4);
		const chunkStart = cursor + 8;
		const chunkEnd = chunkStart + length;
		if (chunkEnd > data.length) {
			risks.push("truncated-wav-chunk");
			break;
		}
		const chunkData = data.subarray(chunkStart, chunkEnd);
		const row = {
			index: chunks.length,
			offset,
			type,
			length,
			sha256: bufferSha256(chunkData),
			entropy: byteEntropy(chunkData),
		};
		if (type === "fmt " && length >= 16) {
			fmt = {
				audioFormat: chunkData.readUInt16LE(0),
				channels: chunkData.readUInt16LE(2),
				sampleRate: chunkData.readUInt32LE(4),
				byteRate: chunkData.readUInt32LE(8),
				blockAlign: chunkData.readUInt16LE(12),
				bitsPerSample: chunkData.readUInt16LE(14),
			};
		}
		if (type === "LIST" && chunkData.length >= 4 && chunkData.subarray(0, 4).toString("ascii") === "INFO") {
			metadata.push(...wavInfoMetadata(chunkData, chunkStart));
		}
		if (type === "data" && !audioData) {
			const lsbBytes = packedLsbBytes(chunkData, 0, 768);
			const lsbRuns = printableRuns(lsbBytes, 24);
			audioData = {
				offset: chunkStart,
				length,
				sha256: bufferSha256(chunkData),
				entropy: byteEntropy(chunkData),
				lsb: {
					bit: 0,
					sampledBytes: Math.min(chunkData.length, 768 * 8),
					ones: chunkData.subarray(0, Math.min(chunkData.length, 768 * 8)).reduce((count, byte) => count + (byte & 1), 0),
					printableRuns: lsbRuns,
				},
			};
		}
		chunks.push(row);
		cursor = chunkEnd + (length % 2);
	}
	const trailingOffset = Math.max(cursor, declaredEnd);
	const trailingLength = Math.max(0, data.length - trailingOffset);
	if (!fmt) risks.push("missing-wav-fmt-chunk");
	if (!audioData) risks.push("missing-wav-data-chunk");
	if (metadata.length) risks.push("wav-info-metadata-signal");
	if (metadata.some((row) => /flag|ctf|key|password|secret|token|nonce|salt|base64|xor|cipher/i.test(row.value ?? ""))) risks.push("wav-text-stego-signal");
	if (audioData?.lsb.printableRuns.some((row) => /flag|ctf|key|password|secret|token|nonce|salt|base64|xor|cipher/i.test(row.text ?? ""))) risks.push("wav-lsb-printable-signal");
	if (trailingLength > 0) risks.push("appended-data-after-riff");
	const embeddedArchives = embeddedZipArchives(data, trailingOffset, trailingLength);
	if (trailingLength > 0 && (embeddedArchives.length || data.subarray(trailingOffset, Math.min(data.length, trailingOffset + 8)).includes(Buffer.from("PK")))) risks.push("appended-zip-after-riff");
	if (embeddedArchives.some((archive) => !archive.parseError)) risks.push("embedded-zip-archive-parsed");
	return {
		kind: "repi-crypto-stego-media-quicklook",
		schemaVersion: 1,
		format: "wav",
		supported: true,
		size: data.length,
		sha256: bufferSha256(data),
		riff: {
			declaredSize,
			declaredEnd,
		},
		fmt,
		chunkCount: chunks.length,
		chunks,
		metadata,
		audioData,
		embeddedArchives,
		trailing: trailingLength
			? {
					offset: trailingOffset,
					length: trailingLength,
					sha256: bufferSha256(data.subarray(trailingOffset)),
					sample: pngTrailingSample(data, trailingOffset),
				}
			: null,
		risks: Array.from(new Set(risks)),
		next: [
			"Inspect LIST/INFO metadata and appended RIFF trailing bytes before brute-forcing audio transforms.",
			"Use audioData.lsb.printableRuns to prioritize bit-plane extraction, then verify recovered text with hashes and offsets.",
			"If trailing data starts with PK, carve from the trailing offset and unzip/test passwords.",
		],
	};
}

function cryptoStegoMediaQuicklook(target) {
	const data = readFileSync(target);
	if (data.length >= 8 && data.subarray(0, 8).toString("hex") === "89504e470d0a1a0a") return pngStegoQuicklook(data);
	if (data.length >= 12 && data.subarray(0, 4).toString("ascii") === "RIFF" && data.subarray(8, 12).toString("ascii") === "WAVE") return wavStegoQuicklook(data);
	return { kind: "repi-crypto-stego-media-quicklook", schemaVersion: 1, format: "unknown", supported: false, reason: "unsupported-media-signature" };
}

export function cryptoStegoMediaQuicklookRows(target, artifactDir) {
	try {
		const summary = cryptoStegoMediaQuicklook(target);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "crypto-stego-media-quicklook.json"), `${JSON.stringify(summary, null, 2)}\n`);
		return [
			{
				id: "crypto-stego-media-quicklook",
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
		];
	} catch (error) {
		return [{ id: "crypto-stego-media-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}

function cryptoStegoEvidenceRows(rows, valueKey = "text", limit = 24) {
	return (rows ?? []).slice(0, limit).map((row) => {
		const value = row?.[valueKey] ?? "";
		return {
			offset: row?.offset ?? null,
			type: row?.type ?? row?.id ?? null,
			length: row?.length ?? row?.size ?? String(value).length,
			valueSha256: httpSecretHash(value),
			valueLength: String(value).length,
		};
	});
}

function cryptoStegoVerificationSummary(target, artifactDir) {
	const data = readFileSync(target);
	const media = readJsonArtifact(join(artifactDir, "crypto-stego-media-quicklook.json"));
	const fileSha256 = bufferSha256(data);
	const fileIdentity = {
		size: data.length,
		sha256: fileSha256,
		headerHex: data.subarray(0, 16).toString("hex"),
		verified: media ? media.size === data.length && media.sha256 === fileSha256 : true,
	};
	if (data.length) {
		const mutated = Buffer.from(data);
		mutated[0] ^= 0xff;
		const mutatedSha256 = bufferSha256(mutated);
		fileIdentity.negativeControl = {
			controlType: "crypto-file-byte-mutation-rejection",
			mutatedSha256,
			passed: mutatedSha256 !== fileSha256,
		};
	}
	let mediaQuicklookDeterminism = { present: Boolean(media), verified: false, format: media?.format ?? null, quicklookSha256: null, reparseSha256: null, reason: media ? "not-run" : "missing-media-quicklook" };
	if (media) {
		try {
			const reparsed = cryptoStegoMediaQuicklook(target);
			const quicklookSha256 = httpSecretHash(JSON.stringify(media));
			const reparseSha256 = httpSecretHash(JSON.stringify(reparsed));
			mediaQuicklookDeterminism = {
				present: true,
				verified: quicklookSha256 === reparseSha256,
				format: media.format ?? null,
				quicklookSha256,
				reparseSha256,
				reparseRisks: reparsed.risks ?? [],
			};
		} catch (error) {
			mediaQuicklookDeterminism = { present: true, verified: false, format: media.format ?? null, quicklookSha256: httpSecretHash(JSON.stringify(media)), reparseSha256: null, reason: error instanceof Error ? redact(error.message) : redact(String(error)) };
		}
	}
	const structureChecks = [];
	const addSliceCheck = (kind, row) => {
		if (!row || !Number.isFinite(Number(row.offset)) || !Number.isFinite(Number(row.length))) return;
		const offset = Number(row.offset);
		const length = Number(row.length);
		let verified = false;
		let actual = {};
		let reason = "slice-out-of-range";
		let negativeControl = null;
		if (offset >= 0 && length >= 0 && offset + length <= data.length) {
			const slice = data.subarray(offset, offset + length);
			const actualSha256 = bufferSha256(slice);
			actual = { offset, length, sha256: actualSha256, headerHex: slice.subarray(0, 16).toString("hex") };
			verified = actualSha256 === row.sha256;
			reason = verified ? "slice-offset-hash-match" : "slice-offset-hash-mismatch";
			const shiftedOffset = offset + 1 + Math.min(length, 16) <= data.length ? offset + 1 : offset > 0 ? offset - 1 : null;
			if (shiftedOffset != null) {
				const shifted = data.subarray(shiftedOffset, shiftedOffset + Math.min(length, 64));
				negativeControl = {
					controlType: "crypto-slice-shifted-offset-rejection",
					kind,
					mutatedOffset: shiftedOffset,
					mutatedSha256: bufferSha256(shifted),
					passed: bufferSha256(shifted) !== row.sha256,
				};
			}
		}
		structureChecks.push({ kind, offset, length, expectedSha256: row.sha256 ?? null, actual, verified, reason, negativeControl });
	};
	if (media?.format === "png") {
		for (const chunk of media.chunks ?? []) {
			const offset = Number(chunk.offset);
			const length = Number(chunk.length);
			let verified = false;
			let actual = {};
			let reason = "chunk-out-of-range";
			let negativeControl = null;
			if (Number.isFinite(offset) && Number.isFinite(length) && offset >= 0 && length >= 0 && offset + 12 + length <= data.length) {
				const type = data.toString("ascii", offset + 4, offset + 8).replace(/[^\x20-\x7e]/g, "?");
				const payload = data.subarray(offset + 8, offset + 8 + length);
				const actualSha256 = bufferSha256(payload);
				actual = { type, length, sha256: actualSha256 };
				verified = type === chunk.type && actualSha256 === chunk.sha256;
				reason = verified ? "png-chunk-offset-hash-match" : "png-chunk-offset-hash-mismatch";
				const shiftedOffset = offset + 1 + Math.min(length, 16) <= data.length ? offset + 1 : offset > 0 ? offset - 1 : null;
				if (shiftedOffset != null) {
					const shifted = data.subarray(shiftedOffset + 8, shiftedOffset + 8 + Math.min(length, 64));
					negativeControl = {
						controlType: "crypto-chunk-shifted-offset-rejection",
						type: chunk.type,
						mutatedOffset: shiftedOffset,
						mutatedSha256: bufferSha256(shifted),
						passed: bufferSha256(shifted) !== chunk.sha256,
					};
				}
			}
			structureChecks.push({ kind: "png-chunk", type: chunk.type, offset, length, expectedSha256: chunk.sha256, actual, verified, reason, negativeControl });
		}
	}
	if (media?.format === "wav") {
		for (const chunk of media.chunks ?? []) addSliceCheck(`wav-chunk:${chunk.type}`, { offset: Number(chunk.offset) + 8, length: chunk.length, sha256: chunk.sha256 });
	}
	if (media?.trailing) addSliceCheck("trailing", media.trailing);
	if (media?.audioData) addSliceCheck("audio-data", media.audioData);
	for (const archive of media?.embeddedArchives ?? []) {
		if (archive.sha256 && archive.length) addSliceCheck("embedded-archive", archive);
	}
	const verifiedStructures = structureChecks.filter((row) => row.verified);
	const negativeControls = [fileIdentity.negativeControl, ...structureChecks.map((row) => row.negativeControl)].filter((row) => row?.passed);
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const fileClaim = fileIdentity.verified
		? addClaim({
				id: "crypto-file-hash-verification-" + shortHash(fileIdentity.sha256),
				claimType: "crypto-file-hash-verification-proof",
				sourceBinding: { artifact: "crypto-stego-verification.json" },
				evidenceBinding: fileIdentity,
				statement: "Crypto/stego verifier re-read the target and matched file size/SHA-256/header evidence.",
				confidence: 0.9,
				rerunCommand: "python3 crypto-stego-verifier.py <target> crypto-stego-media-quicklook.json crypto-stego-verification.json",
			})
		: undefined;
	const determinismClaim = mediaQuicklookDeterminism.verified
		? addClaim({
				id: "crypto-media-quicklook-determinism-" + shortHash(`${mediaQuicklookDeterminism.quicklookSha256}:${mediaQuicklookDeterminism.reparseSha256}`),
				claimType: "crypto-media-quicklook-determinism-proof",
				sourceBinding: { artifact: "crypto-stego-verification.json", quicklook: "crypto-stego-media-quicklook.json" },
				evidenceBinding: mediaQuicklookDeterminism,
				statement: "Crypto/stego verifier reparsed media structure and matched the quicklook hash deterministically.",
				confidence: 0.86,
				rerunCommand: "python3 crypto-stego-verifier.py <target> crypto-stego-media-quicklook.json crypto-stego-verification.json",
			})
		: undefined;
	const structureClaim = verifiedStructures.length
		? addClaim({
				id: "crypto-structure-offset-verification-" + shortHash(verifiedStructures.map((row) => `${row.kind}:${row.offset}:${row.actual?.sha256}`).join("|")),
				claimType: "crypto-structure-offset-verification-proof",
				sourceBinding: { artifact: "crypto-stego-verification.json" },
				evidenceBinding: {
					verifiedStructures: verifiedStructures.slice(0, 80).map((row) => ({ kind: row.kind, type: row.type ?? null, offset: row.offset, length: row.length, sha256: row.actual?.sha256 })),
				},
				statement: "Crypto/stego verifier matched media chunks, trailing data, embedded archive, or audio slices by exact offset and SHA-256.",
				confidence: 0.86,
				rerunCommand: "python3 crypto-stego-verifier.py <target> crypto-stego-media-quicklook.json crypto-stego-verification.json",
			})
		: undefined;
	const controlClaim = negativeControls.length
		? addClaim({
				id: "crypto-hidden-channel-negative-control-" + shortHash(negativeControls.map((row) => `${row.controlType}:${row.mutatedSha256}`).join("|")),
				claimType: "crypto-hidden-channel-negative-control-proof",
				sourceBinding: { artifact: "crypto-stego-verification.json" },
				evidenceBinding: { passedControls: negativeControls },
				statement: "Crypto/stego verifier ran byte and shifted-offset controls so structure matches are not source-only assertions.",
				confidence: 0.84,
				rerunCommand: "python3 crypto-stego-verifier.py <target> crypto-stego-media-quicklook.json crypto-stego-verification.json",
			})
		: undefined;
	if (fileClaim && determinismClaim && structureClaim && controlClaim) {
		const segments = [fileClaim, determinismClaim, structureClaim, controlClaim];
		const composed = {
			id: "crypto-stego-verification-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "crypto-stego-verification-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				fileSha256,
				format: media?.format ?? "unknown",
				verifiedStructures: verifiedStructures.length,
				hasNegativeControl: true,
			},
			statement: "Crypto/stego proof path composes file hash, deterministic media quicklook, exact offset/hash structure checks, and negative controls.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
			rerunCommand: "python3 crypto-stego-verifier.py <target> crypto-stego-media-quicklook.json crypto-stego-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!fileIdentity.verified) blockers.push("missing-crypto-file-hash-verification");
	if (media && !mediaQuicklookDeterminism.verified) blockers.push("missing-crypto-media-determinism");
	if (media && !verifiedStructures.length) blockers.push("missing-crypto-structure-offset-verification");
	if (!negativeControls.length) blockers.push("missing-crypto-negative-control");
	const repairActions = {
		"missing-crypto-file-hash-verification": "Rerun crypto-stego-verifier.py against the original file and require size/SHA-256 equality.",
		"missing-crypto-media-determinism": "Reparse PNG/WAV media quicklook and resolve nondeterminism before promoting structure evidence.",
		"missing-crypto-structure-offset-verification": "Bind chunks, trailing bytes, embedded archives, or audio data to exact offsets and SHA-256 hashes.",
		"missing-crypto-negative-control": "Add byte mutation and shifted-offset controls so hidden-channel evidence has a rejection oracle.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "crypto-stego-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound crypto/stego evidence and rerun crypto-stego-verifier.py.",
		rerunCommand: `python3 ${shellQuote(join(artifactDir, "crypto-stego-verifier.py"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "crypto-stego-media-quicklook.json"))} ${shellQuote(join(artifactDir, "crypto-stego-verification.json"))}`,
	}));
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-crypto-stego-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		proofReady: promotedClaims.length > 0,
		transformProofReady: composedPaths.length > 0,
		fileIdentity,
		mediaQuicklookDeterminism,
		structureChecks,
		negativeControls,
		stats: {
			structuresVerified: verifiedStructures.length,
			negativeControlsPassed: negativeControls.length,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady: promotedClaims.length > 0, transformProofReady: composedPaths.length > 0, promotedClaims, blockers },
		repairQueue,
	};
}

export function writeCryptoStegoVerification(artifactDir, target) {
	if (noWrite || !artifactDir) return undefined;
	const summary = cryptoStegoVerificationSummary(target, artifactDir);
	const path = join(artifactDir, "crypto-stego-verification.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}

function cryptoStegoTransformClaims(target, artifactDir, verificationSummary) {
	const media = readJsonArtifact(join(artifactDir, "crypto-stego-media-quicklook.json"));
	const verification = verificationSummary ?? readJsonArtifact(join(artifactDir, "crypto-stego-verification.json"));
	const solverPath = join(artifactDir, "crypto-stego-solver.py");
	const solverExists = existsSync(solverPath);
	const claimLedger = [];
	const addClaim = (claim) => {
		if (!claim?.id || claimLedger.some((row) => row.id === claim.id)) return undefined;
		const normalized = {
			verdict: "promoted",
			confidence: 0.7,
			blockers: [],
			...claim,
		};
		claimLedger.push(normalized);
		return normalized;
	};
	const mediaRisks = new Set(media?.risks ?? []);
	const structureClaims = [];
	if (solverExists) {
		addClaim({
			id: "crypto-transform-solver-harness-" + shortHash(target),
			claimType: "crypto-transform-solver-harness",
			sourceBinding: { artifact: "crypto-stego-solver.py" },
			evidenceBinding: {
				supportedTransforms: ["base64", "hex", "gzip", "zlib", "xor-single-byte", "signal-strings", "transform-chain"],
				requiresExecute: true,
			},
			statement: "Crypto/stego solver harness can replay printable strings, base64/hex, compression, XOR, and chained transform candidates.",
			confidence: 0.78,
			rerunCommand: `python3 ${shellQuote(solverPath)} ${shellQuote(target)}`,
		});
	}
	if (media?.format === "png" && (mediaRisks.has("png-text-stego-signal") || mediaRisks.has("png-text-metadata-signal"))) {
		const claim = addClaim({
			id: "crypto-png-text-signal-" + shortHash(`${target}:${JSON.stringify(media.text ?? [])}`),
			claimType: "crypto-png-text-stego-signal",
			sourceBinding: { artifact: "crypto-stego-media-quicklook.json", field: "text" },
			evidenceBinding: {
				chunks: (media.text ?? []).slice(0, 24).map((row) => ({ offset: row.offset, type: row.type, keyword: row.keyword, textSha256: httpSecretHash(row.text ?? ""), textLength: String(row.text ?? "").length })),
				risks: media.risks ?? [],
			},
			statement: "PNG text chunk evidence contains metadata or stego keywords and is hash-bound for transform-chain replay.",
			confidence: mediaRisks.has("png-text-stego-signal") ? 0.84 : 0.74,
			rerunCommand: "cat crypto-stego-media-quicklook.json | jq '.text'",
		});
		if (claim) structureClaims.push(claim);
	}
	if (media?.format === "png" && media?.trailing) {
		const claim = addClaim({
			id: "crypto-png-trailing-data-" + shortHash(`${target}:${media.trailing.offset}:${media.trailing.sha256}`),
			claimType: "crypto-png-trailing-data",
			sourceBinding: { artifact: "crypto-stego-media-quicklook.json", field: "trailing" },
			evidenceBinding: {
				offset: media.trailing.offset,
				length: media.trailing.length,
				sha256: media.trailing.sha256,
				risks: media.risks ?? [],
			},
			statement: "PNG structure evidence contains bytes after IEND; carve and decode from the exact trailing offset.",
			confidence: 0.84,
			rerunCommand: "cat crypto-stego-media-quicklook.json | jq '.trailing'",
		});
		if (claim) structureClaims.push(claim);
	}
	if (media?.format === "wav" && (mediaRisks.has("wav-text-stego-signal") || mediaRisks.has("wav-info-metadata-signal"))) {
		const claim = addClaim({
			id: "crypto-wav-metadata-signal-" + shortHash(`${target}:${JSON.stringify(media.metadata ?? [])}`),
			claimType: "crypto-wav-metadata-stego-signal",
			sourceBinding: { artifact: "crypto-stego-media-quicklook.json", field: "metadata" },
			evidenceBinding: {
				metadata: cryptoStegoEvidenceRows(media.metadata, "value"),
				risks: media.risks ?? [],
			},
			statement: "WAV LIST/INFO metadata evidence contains stego keywords and is hash-bound for solver replay.",
			confidence: mediaRisks.has("wav-text-stego-signal") ? 0.84 : 0.74,
			rerunCommand: "cat crypto-stego-media-quicklook.json | jq '.metadata'",
		});
		if (claim) structureClaims.push(claim);
	}
	if (media?.format === "wav" && mediaRisks.has("wav-lsb-printable-signal")) {
		const claim = addClaim({
			id: "crypto-wav-lsb-printable-" + shortHash(`${target}:${JSON.stringify(media.audioData?.lsb?.printableRuns ?? [])}`),
			claimType: "crypto-wav-lsb-printable-signal",
			sourceBinding: { artifact: "crypto-stego-media-quicklook.json", field: "audioData.lsb.printableRuns" },
			evidenceBinding: {
				audioOffset: media.audioData?.offset ?? null,
				audioLength: media.audioData?.length ?? null,
				audioSha256: media.audioData?.sha256 ?? null,
				lsbBit: media.audioData?.lsb?.bit ?? 0,
				printableRuns: cryptoStegoEvidenceRows(media.audioData?.lsb?.printableRuns, "text"),
			},
			statement: "WAV LSB bit-plane evidence contains printable stego text candidates tied to audio offsets and hashes.",
			confidence: 0.86,
			rerunCommand: "cat crypto-stego-media-quicklook.json | jq '.audioData.lsb.printableRuns'",
		});
		if (claim) structureClaims.push(claim);
	}
	if ((media?.embeddedArchives ?? []).length) {
		const claim = addClaim({
			id: "crypto-embedded-archive-carve-" + shortHash(`${target}:${JSON.stringify(media.embeddedArchives ?? [])}`),
			claimType: "crypto-embedded-archive-carve",
			sourceBinding: { artifact: "crypto-stego-media-quicklook.json", field: "embeddedArchives" },
			evidenceBinding: {
				archives: (media.embeddedArchives ?? []).slice(0, 16).map((archive) => ({
					format: archive.format,
					offset: archive.offset,
					length: archive.length ?? null,
					sha256: archive.sha256 ?? null,
					entryCount: archive.entryCount ?? archive.entries?.length ?? 0,
					entries: (archive.entries ?? []).slice(0, 40).map((entry) => ({
						name: entry.name,
						method: entry.method,
						compressedSize: entry.compressedSize,
						uncompressedSize: entry.uncompressedSize,
						crc32: entry.crc32,
					})),
				})),
			},
			statement: "Crypto/stego media evidence contains an embedded archive carve with entry metadata and hashes.",
			confidence: 0.88,
			rerunCommand: "cat crypto-stego-media-quicklook.json | jq '.embeddedArchives'",
		});
		if (claim) structureClaims.push(claim);
	}
	const solverClaim = claimLedger.find((claim) => claim.claimType === "crypto-transform-solver-harness");
	const composedPaths = [];
	if (solverClaim && structureClaims.length) {
		const segments = [structureClaims[0], solverClaim];
		const composed = {
			id: "crypto-transform-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "crypto-transform-proof-path",
			sourceBinding: {
				target: redact(target),
				segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })),
			},
			evidenceBinding: {
				format: media?.format ?? "unknown",
				risks: media?.risks ?? [],
				hasArchiveCarve: structureClaims.some((claim) => claim.claimType === "crypto-embedded-archive-carve"),
				hasLsbSignal: structureClaims.some((claim) => claim.claimType === "crypto-wav-lsb-printable-signal"),
				hasTextSignal: structureClaims.some((claim) => /text|metadata/.test(claim.claimType)),
			},
			statement: "Crypto/stego evidence composes a media hidden-channel signal with an executable transform-chain solver harness.",
			verdict: "promoted",
			confidence: 0.86,
			blockers: [],
			rerunCommand: `python3 ${shellQuote(solverPath)} ${shellQuote(target)}`,
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	for (const verificationClaim of verification?.claimLedger ?? []) {
		if (verificationClaim.verdict !== "promoted") continue;
		const claim = addClaim({
			...verificationClaim,
			id: verificationClaim.id || "crypto-stego-verification-claim-" + shortHash(JSON.stringify(verificationClaim)),
			sourceBinding: {
				artifact: "crypto-stego-verification.json",
				...(verificationClaim.sourceBinding ?? {}),
			},
			rerunCommand:
				verificationClaim.rerunCommand ??
				`python3 ${shellQuote(join(artifactDir, "crypto-stego-verifier.py"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "crypto-stego-media-quicklook.json"))} ${shellQuote(join(artifactDir, "crypto-stego-verification.json"))}`,
		});
		if (claim?.claimType === "crypto-stego-verification-proof-path" && !composedPaths.some((path) => path.id === claim.id)) composedPaths.push(claim);
	}
	for (const verificationPath of verification?.composedPaths ?? []) {
		const composed = {
			...verificationPath,
			id: verificationPath.id || "crypto-stego-verification-path-" + shortHash(JSON.stringify(verificationPath)),
			sourceBinding: {
				artifact: "crypto-stego-verification.json",
				...(verificationPath.sourceBinding ?? {}),
			},
			rerunCommand:
				verificationPath.rerunCommand ??
				`python3 ${shellQuote(join(artifactDir, "crypto-stego-verifier.py"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "crypto-stego-media-quicklook.json"))} ${shellQuote(join(artifactDir, "crypto-stego-verification.json"))}`,
		};
		if (!claimLedger.some((claim) => claim.id === composed.id)) claimLedger.push(composed);
		if (!composedPaths.some((path) => path.id === composed.id)) composedPaths.push(composed);
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const blockers = [];
	if (!media) blockers.push("missing-media-quicklook");
	if (!solverExists) blockers.push("missing-transform-solver");
	if (media && !structureClaims.length) blockers.push("missing-hidden-channel-signal");
	if (media && !(media.embeddedArchives ?? []).length && !mediaRisks.has("wav-lsb-printable-signal") && !media?.trailing) blockers.push("missing-carve-or-bitplane-target");
	if (!verification) blockers.push("missing-crypto-stego-verification");
	for (const blocker of verification?.promotionReport?.blockers ?? []) {
		if (!blockers.includes(blocker)) blockers.push(blocker);
	}
	const repairActions = {
		"missing-media-quicklook": "Parse PNG/WAV structure or run file-specific metadata/binwalk probes before claiming a hidden channel.",
		"missing-transform-solver": "Generate crypto-stego-solver.py so each transform candidate is rerunnable with hashes.",
		"missing-hidden-channel-signal": "Find text/private chunks, trailing bytes, embedded archives, metadata, LSB runs, or encoded strings before promotion.",
		"missing-carve-or-bitplane-target": "Carve appended archives/data or extract prioritized bit-planes before brute forcing unrelated transforms.",
		"missing-crypto-stego-verification": "Generate crypto-stego-verification.json and crypto-stego-verifier.py to bind file/media offsets and negative controls.",
		"missing-crypto-file-hash-verification": "Rerun crypto-stego-verifier.py against the original file and require size/SHA-256 equality.",
		"missing-crypto-media-determinism": "Reparse media quicklook deterministically before treating chunks or LSB runs as proof.",
		"missing-crypto-structure-offset-verification": "Verify chunks, trailing data, embedded archives, or audio slices by exact offset and SHA-256.",
		"missing-crypto-negative-control": "Add byte mutation and shifted-offset controls for hidden-channel rejection proof.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "crypto-stego-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect crypto/stego structure evidence and rerun transform claim promotion.",
		rerunCommand: `repi engage ${shellQuote(target)} --json`,
	}));
	return {
		kind: "repi-crypto-stego-transform-claims",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		format: media?.format ?? "unknown",
		verificationStats: verification?.stats ?? null,
		proofReady: promotedClaims.length > 0,
		transformProofReady: composedPaths.length > 0,
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			transformProofReady: composedPaths.length > 0,
			promotedClaims,
			blockers,
		},
		repairQueue,
	};
}

export function writeCryptoStegoTransformClaims(artifactDir, target, verificationSummary) {
	if (noWrite || !artifactDir) return undefined;
	const summary = cryptoStegoTransformClaims(target, artifactDir, verificationSummary);
	const path = join(artifactDir, "crypto-stego-transform-claims.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}
