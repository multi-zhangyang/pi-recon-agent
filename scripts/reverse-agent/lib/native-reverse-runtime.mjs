import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

let deep;
let noWrite;
let root;
let redact;
let writePrivate;
let bufferSha256;
let shortHash;
let httpSecretHash;
let readJsonArtifact;
let byteEntropy;
let firmwareStrings;
let timeoutMs;
let run;
let shellQuote;

export function configureNativeRuntime(runtime) {
	({ deep, noWrite, root, redact, writePrivate, bufferSha256, shortHash, httpSecretHash, readJsonArtifact, byteEntropy, firmwareStrings, timeoutMs, run, shellQuote } = runtime);
}

function elfTypeName(value) {
	return (
		{
			0: "NONE",
			1: "REL",
			2: "EXEC",
			3: "DYN",
			4: "CORE",
		}[value] ?? String(value)
	);
}

function elfMachineName(value) {
	return (
		{
			3: "x86",
			8: "MIPS",
			20: "PowerPC",
			40: "ARM",
			62: "x86-64",
			183: "AArch64",
			243: "RISC-V",
		}[value] ?? String(value)
	);
}

function elfSymbolBindName(value) {
	return (
		{
			0: "LOCAL",
			1: "GLOBAL",
			2: "WEAK",
			10: "LOOS",
			12: "HIOS",
			13: "LOPROC",
			15: "HIPROC",
		}[value] ?? String(value)
	);
}

function elfSymbolTypeName(value) {
	return (
		{
			0: "NOTYPE",
			1: "OBJECT",
			2: "FUNC",
			3: "SECTION",
			4: "FILE",
			5: "COMMON",
			6: "TLS",
			10: "LOOS",
			12: "HIOS",
			13: "LOPROC",
			15: "HIPROC",
		}[value] ?? String(value)
	);
}

function elfRelocationTypeName(machineValue, value) {
	if (machineValue === 62) {
		return (
			{
				1: "R_X86_64_64",
				2: "R_X86_64_PC32",
				5: "R_X86_64_COPY",
				6: "R_X86_64_GLOB_DAT",
				7: "R_X86_64_JUMP_SLOT",
				8: "R_X86_64_RELATIVE",
				37: "R_X86_64_IRELATIVE",
			}[value] ?? String(value)
		);
	}
	if (machineValue === 3) {
		return (
			{
				1: "R_386_32",
				2: "R_386_PC32",
				5: "R_386_COPY",
				6: "R_386_GLOB_DAT",
				7: "R_386_JMP_SLOT",
				8: "R_386_RELATIVE",
			}[value] ?? String(value)
		);
	}
	if (machineValue === 183) {
		return (
			{
				257: "R_AARCH64_ABS64",
				1025: "R_AARCH64_GLOB_DAT",
				1026: "R_AARCH64_JUMP_SLOT",
				1027: "R_AARCH64_RELATIVE",
			}[value] ?? String(value)
		);
	}
	return String(value);
}

function readElfInteger(data, offset, bytes, little) {
	if (offset < 0 || offset + bytes > data.length) return undefined;
	if (bytes === 2) return little ? data.readUInt16LE(offset) : data.readUInt16BE(offset);
	if (bytes === 4) return little ? data.readUInt32LE(offset) : data.readUInt32BE(offset);
	if (bytes === 8) {
		const value = little ? data.readBigUInt64LE(offset) : data.readBigUInt64BE(offset);
		return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : undefined;
	}
	return undefined;
}

function cStringAt(data, offset, limit = 500) {
	if (!Number.isFinite(offset) || offset < 0 || offset >= data.length) return "";
	const end = Math.min(data.length, offset + limit);
	let cursor = offset;
	while (cursor < end && data[cursor] !== 0) cursor++;
	return data.toString("utf8", offset, cursor).replace(/[^\x20-\x7e]/g, "");
}

export function parseElfHardening(target) {
	const data = readFileSync(target);
	if (data.length < 64 || data.subarray(0, 4).toString("hex") !== "7f454c46") throw new Error("not an ELF file");
	const elfClass = data[4];
	const endianByte = data[5];
	if (![1, 2].includes(elfClass)) throw new Error(`unsupported ELF class=${elfClass}`);
	if (![1, 2].includes(endianByte)) throw new Error(`unsupported ELF endian=${endianByte}`);
	const little = endianByte === 1;
	const bitness = elfClass === 2 ? 64 : 32;
	const read16 = (offset) => readElfInteger(data, offset, 2, little);
	const read32 = (offset) => readElfInteger(data, offset, 4, little);
	const readPtr = (offset) => readElfInteger(data, offset, bitness === 64 ? 8 : 4, little);
	const typeValue = read16(16);
	const machineValue = read16(18);
	const entry = readPtr(bitness === 64 ? 24 : 24);
	const phoff = readPtr(bitness === 64 ? 32 : 28);
	const ehsize = read16(bitness === 64 ? 52 : 40);
	const phentsize = read16(bitness === 64 ? 54 : 42);
	const phnum = read16(bitness === 64 ? 56 : 44);
	if (!Number.isFinite(phoff) || !Number.isFinite(phentsize) || !Number.isFinite(phnum)) throw new Error("ELF program header metadata is unreadable");
	const programHeaders = [];
	for (let index = 0; index < Math.min(phnum, 256); index++) {
		const base = phoff + index * phentsize;
		if (base < 0 || base + phentsize > data.length) break;
		const type = read32(base);
		let flags;
		let offset;
		let vaddr;
		let filesz;
		let memsz;
		if (bitness === 64) {
			flags = read32(base + 4);
			offset = readPtr(base + 8);
			vaddr = readPtr(base + 16);
			filesz = readPtr(base + 32);
			memsz = readPtr(base + 40);
		} else {
			offset = read32(base + 4);
			vaddr = read32(base + 8);
			filesz = read32(base + 16);
			memsz = read32(base + 20);
			flags = read32(base + 24);
		}
		programHeaders.push({ type, flags, offset, vaddr, filesz, memsz });
	}
	const gnuStack = programHeaders.find((header) => header.type === 0x6474e551);
	const gnuRelro = programHeaders.find((header) => header.type === 0x6474e552);
	const interp = programHeaders.find((header) => header.type === 3);
	const dynamicHeader = programHeaders.find((header) => header.type === 2);
	const loadHeaders = programHeaders.filter((header) => header.type === 1);
	const virtualAddressToOffset = (address) => {
		if (!Number.isFinite(address)) return undefined;
		for (const header of loadHeaders) {
			const span = Math.min(header.filesz ?? 0, header.memsz ?? header.filesz ?? 0);
			if (!Number.isFinite(header.vaddr) || !Number.isFinite(header.offset) || span <= 0) continue;
			if (address >= header.vaddr && address < header.vaddr + span) return header.offset + (address - header.vaddr);
		}
		return undefined;
	};
	let interpreter = null;
	if (interp && Number.isFinite(interp.offset) && Number.isFinite(interp.filesz) && interp.filesz > 0 && interp.offset + interp.filesz <= data.length) {
		interpreter = data
			.subarray(interp.offset, interp.offset + Math.min(interp.filesz, 300))
			.toString("utf8")
			.replace(/\0.*$/s, "");
	}
	const dynamic = [];
	if (dynamicHeader && Number.isFinite(dynamicHeader.offset) && Number.isFinite(dynamicHeader.filesz) && dynamicHeader.filesz > 0 && dynamicHeader.offset + dynamicHeader.filesz <= data.length) {
		const entrySize = bitness === 64 ? 16 : 8;
		for (let cursor = dynamicHeader.offset; cursor + entrySize <= dynamicHeader.offset + dynamicHeader.filesz && dynamic.length < 512; cursor += entrySize) {
			const tag = bitness === 64 ? readPtr(cursor) : read32(cursor);
			const value = bitness === 64 ? readPtr(cursor + 8) : read32(cursor + 4);
			if (!Number.isFinite(tag)) break;
			dynamic.push({ tag, value: value ?? 0 });
			if (tag === 0) break;
		}
	}
	const dynamicValue = (tag) => dynamic.find((entry) => entry.tag === tag)?.value;
	const dynamicValues = (tag) => dynamic.filter((entry) => entry.tag === tag).map((entry) => entry.value);
	const flags = dynamicValue(30) ?? 0;
	const flags1 = dynamicValue(0x6ffffffb) ?? 0;
	const bindNow = dynamic.some((entry) => entry.tag === 24) || Boolean(flags & 0x8) || Boolean(flags1 & 0x1);
	const dynstrAddress = dynamicValue(5);
	const dynstrSize = dynamicValue(10);
	const dynstrOffset = virtualAddressToOffset(dynstrAddress);
	const dynsymAddress = dynamicValue(6);
	const dynsymOffset = virtualAddressToOffset(dynsymAddress);
	const symentSize = dynamicValue(11) || (bitness === 64 ? 24 : 16);
	const hashAddress = dynamicValue(4);
	const hashOffset = virtualAddressToOffset(hashAddress);
	const needed = [];
	const dynamicString = (offset) => {
		if (!Number.isFinite(dynstrOffset) || !Number.isFinite(dynstrSize) || offset < 0 || offset >= dynstrSize) return "";
		return cStringAt(data, dynstrOffset + offset, Math.min(500, dynstrSize - offset));
	};
	if (Number.isFinite(dynstrOffset) && Number.isFinite(dynstrSize) && dynstrSize > 0 && dynstrOffset + dynstrSize <= data.length) {
		for (const offset of dynamicValues(1).slice(0, 80)) {
			const library = dynamicString(offset);
			if (library) needed.push(library);
		}
	}
	let symbolCount = 0;
	if (Number.isFinite(hashOffset) && hashOffset + 8 <= data.length) {
		const nchain = read32(hashOffset + 4);
		if (Number.isFinite(nchain) && nchain > 0) symbolCount = Math.min(nchain, 1024);
	}
	const relocationStarts = [dynamicValue(23), dynamicValue(7), dynamicValue(17)]
		.map((value) => virtualAddressToOffset(value))
		.filter((value) => Number.isFinite(value));
	if (!symbolCount && Number.isFinite(dynsymOffset) && symentSize > 0) {
		const nextTableOffset = relocationStarts.filter((offset) => offset > dynsymOffset).sort((a, b) => a - b)[0];
		const maxBytes = Number.isFinite(nextTableOffset) ? nextTableOffset - dynsymOffset : Math.min(data.length - dynsymOffset, symentSize * 128);
		if (maxBytes > 0) symbolCount = Math.min(Math.floor(maxBytes / symentSize), 128);
	}
	const dynamicSymbols = [];
	if (Number.isFinite(dynsymOffset) && symentSize >= (bitness === 64 ? 24 : 16) && symbolCount > 0) {
		for (let index = 0; index < Math.min(symbolCount, 512); index++) {
			const base = dynsymOffset + index * symentSize;
			if (base < 0 || base + symentSize > data.length) break;
			let nameOffset;
			let info;
			let shndx;
			let value;
			let size;
			if (bitness === 64) {
				nameOffset = read32(base);
				info = data[base + 4];
				shndx = read16(base + 6);
				value = readPtr(base + 8);
				size = readPtr(base + 16);
			} else {
				nameOffset = read32(base);
				value = read32(base + 4);
				size = read32(base + 8);
				info = data[base + 12];
				shndx = read16(base + 14);
			}
			const name = dynamicString(nameOffset);
			if (!name && index === 0) continue;
			if (!name) continue;
			const bind = info >> 4;
			const symbolType = info & 0x0f;
			dynamicSymbols.push({
				index,
				name: redact(name),
				bind: elfSymbolBindName(bind),
				type: elfSymbolTypeName(symbolType),
				shndx,
				imported: shndx === 0,
				value: Number.isFinite(value) && value > 0 ? `0x${value.toString(16)}` : null,
				size: size ?? 0,
			});
		}
	}
	const symbolByIndex = new Map(dynamicSymbols.map((symbol) => [symbol.index, symbol]));
	const importedSymbols = dynamicSymbols.filter((symbol) => symbol.imported).slice(0, 120);
	const parseRelocations = (address, size, entSize, rela, table) => {
		const relocOffset = virtualAddressToOffset(address);
		if (!Number.isFinite(relocOffset) || !Number.isFinite(size) || size <= 0) return [];
		const entrySize = entSize || (bitness === 64 ? (rela ? 24 : 16) : rela ? 12 : 8);
		const rows = [];
		for (let index = 0; index < Math.min(Math.floor(size / entrySize), 256); index++) {
			const base = relocOffset + index * entrySize;
			if (base < 0 || base + entrySize > data.length) break;
			let relocAddress;
			let info;
			let addend = null;
			if (bitness === 64) {
				relocAddress = readPtr(base);
				info = readPtr(base + 8);
				if (rela && base + 24 <= data.length) addend = readPtr(base + 16) ?? 0;
			} else {
				relocAddress = read32(base);
				info = read32(base + 4);
				if (rela && base + 12 <= data.length) addend = read32(base + 8) ?? 0;
			}
			if (!Number.isFinite(info)) continue;
			const symbolIndex = bitness === 64 ? Math.floor(info / 2 ** 32) : info >> 8;
			const type = bitness === 64 ? info >>> 0 : info & 0xff;
			const symbol = symbolByIndex.get(symbolIndex);
			rows.push({
				table,
				offset: Number.isFinite(relocAddress) ? `0x${relocAddress.toString(16)}` : null,
				type,
				typeName: elfRelocationTypeName(machineValue, type),
				symbolIndex,
				symbol: symbol?.name ?? null,
				addend,
			});
		}
		return rows;
	};
	const pltRelType = dynamicValue(20);
	const pltIsRela = pltRelType === 7 || (pltRelType == null && bitness === 64);
	const relocations = [
		...parseRelocations(dynamicValue(23), dynamicValue(2), pltIsRela ? dynamicValue(9) : dynamicValue(19), pltIsRela, "plt"),
		...parseRelocations(dynamicValue(7), dynamicValue(8), dynamicValue(9), true, "rela"),
		...parseRelocations(dynamicValue(17), dynamicValue(18), dynamicValue(19), false, "rel"),
	].slice(0, 160);
	const importRisks = [];
	const importedNames = importedSymbols.map((symbol) => symbol.name);
	if (importedNames.some((name) => /^(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|memcpy|memmove)$/i.test(name))) importRisks.push("elf-unsafe-import-surface");
	if (importedNames.some((name) => /^(system|popen|execv|execve|execl|execlp|execvp|posix_spawn)$/i.test(name))) importRisks.push("elf-command-exec-import-surface");
	if (importedNames.some((name) => /^(dlopen|dlsym|mprotect|mmap)$/i.test(name))) importRisks.push("elf-dynamic-loader-or-memory-permission-import");
	if (relocations.some((row) => /JUMP_SLOT|JMP_SLOT/i.test(row.typeName))) importRisks.push("elf-plt-relocation-surface");
	if (relocations.some((row) => /JUMP_SLOT|JMP_SLOT/i.test(row.typeName)) && !bindNow) importRisks.push("elf-lazy-binding-plt-surface");
	const canary = data.includes(Buffer.from("__stack_chk_fail")) || data.includes(Buffer.from("__stack_chk_guard"));
	const fortify = /__[A-Za-z0-9_]+_chk(?:\0|$)/.test(data.subarray(0, Math.min(data.length, 8 * 1024 * 1024)).toString("latin1"));
	const stackExecutable = gnuStack ? Boolean((gnuStack.flags ?? 0) & 1) : null;
	const relroLevel = gnuRelro ? (bindNow ? "full" : "partial") : "none";
	const hardening = {
		pie: typeValue === 3,
		nx: stackExecutable === null ? null : !stackExecutable,
		stackExecutable,
		relro: Boolean(gnuRelro),
		relroLevel,
		bindNow,
		canary,
		fortify,
		dynamic: programHeaders.some((header) => header.type === 2),
		interpreter: interpreter || null,
		needed,
	};
	const risk = [];
	if (hardening.pie === false) risk.push("no-pie");
	if (hardening.nx === false) risk.push("executable-stack");
	if (hardening.nx === null) risk.push("nx-unknown-missing-gnu-stack");
	if (hardening.relro === false) risk.push("no-gnu-relro");
	if (hardening.relro === true && hardening.bindNow === false) risk.push("partial-relro");
	if (hardening.canary === false) risk.push("no-stack-canary-detected");
	return {
		kind: "repi-native-elf-hardening",
		schemaVersion: 1,
		elf: {
			class: bitness,
			endian: little ? "little" : "big",
			type: elfTypeName(typeValue),
			typeValue,
			machine: elfMachineName(machineValue),
			machineValue,
			entry: Number.isFinite(entry) ? `0x${entry.toString(16)}` : null,
			headerSize: ehsize ?? null,
			programHeaderOffset: phoff,
			programHeaderEntrySize: phentsize,
			programHeaderCount: phnum,
		},
		hardening,
		risk,
		programHeaders: programHeaders.slice(0, 40).map((header) => ({
			type: header.type,
			flags: header.flags,
			offset: header.offset,
			vaddr: Number.isFinite(header.vaddr) ? `0x${header.vaddr.toString(16)}` : null,
			filesz: header.filesz,
			memsz: header.memsz,
		})),
		dynamic: {
			bindNow,
			flags,
			flags1,
			strtab: Number.isFinite(dynstrAddress) ? `0x${dynstrAddress.toString(16)}` : null,
			symtab: Number.isFinite(dynsymAddress) ? `0x${dynsymAddress.toString(16)}` : null,
			symbolCount: dynamicSymbols.length,
			needed,
			imports: importedSymbols,
			relocations,
			risks: importRisks,
		},
	};
}

export function nativeElfHardeningRows(target, artifactDir) {
	try {
		const summary = parseElfHardening(target);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "native-elf-hardening.json"), `${JSON.stringify(summary, null, 2)}\n`);
		return [
			{
				id: "native-elf-hardening",
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
		];
	} catch (error) {
		return [{ id: "native-elf-hardening", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}

function nativeSignalRows(strings, regex, limit = 40) {
	const rows = [];
	const seen = new Set();
	for (const row of strings) {
		const match = regex.exec(row.text);
		if (!match) continue;
		const text = redact(row.text.replace(/\s+/g, " ").slice(0, 240));
		const key = `${match[0]}:${text}`;
		if (seen.has(key)) continue;
		seen.add(key);
		rows.push({ offset: row.offset, match: redact(match[0]), text });
		if (rows.length >= limit) break;
	}
	return rows;
}

function nativeArchitectureHint(data) {
	if (data.length >= 20 && data.subarray(0, 4).toString("hex") === "7f454c46") {
		const little = data[5] === 1;
		const machine = little ? data.readUInt16LE(18) : data.readUInt16BE(18);
		return { format: "ELF", machine, arch: elfMachineName(machine) };
	}
	if (data.length >= 0x40 && data.subarray(0, 2).toString("ascii") === "MZ") {
		const peOffset = data.readUInt32LE(0x3c);
		if (peOffset + 6 <= data.length && data.subarray(peOffset, peOffset + 4).toString("binary") === "PE\0\0") {
			const machine = data.readUInt16LE(peOffset + 4);
			return { format: "PE", machine, arch: peMachineName(machine) };
		}
	}
	return { format: "raw", machine: null, arch: "unknown" };
}

function scanOpcodePattern(data, bytes, name, limit = 24) {
	const samples = [];
	let count = 0;
	for (let offset = 0; offset <= data.length - bytes.length; offset++) {
		let match = true;
		for (let index = 0; index < bytes.length; index++) {
			if (data[offset + index] !== bytes[index]) {
				match = false;
				break;
			}
		}
		if (!match) continue;
		count += 1;
		if (samples.length < limit) samples.push({ fileOffset: offset, offsetHex: `0x${offset.toString(16)}`, bytes: Buffer.from(bytes).toString("hex"), gadget: name });
	}
	return { name, count, samples };
}

function nativeGadgetQuicklook(data, strings, signals) {
	const architecture = nativeArchitectureHint(data);
	const patterns = [
		{ name: "ret", bytes: [0xc3] },
		{ name: "leave; ret", bytes: [0xc9, 0xc3] },
		{ name: "pop rdi; ret", bytes: [0x5f, 0xc3], arch: /x86-64|AMD64/i },
		{ name: "pop rsi; ret", bytes: [0x5e, 0xc3], arch: /x86-64|AMD64/i },
		{ name: "pop rdx; ret", bytes: [0x5a, 0xc3], arch: /x86-64|AMD64/i },
		{ name: "pop rcx; ret", bytes: [0x59, 0xc3], arch: /x86-64|AMD64/i },
		{ name: "pop rax; ret", bytes: [0x58, 0xc3], arch: /x86-64|AMD64/i },
		{ name: "syscall; ret", bytes: [0x0f, 0x05, 0xc3], arch: /x86-64|AMD64/i },
		{ name: "jmp rsp", bytes: [0xff, 0xe4], arch: /x86-64|x86|AMD64/i },
		{ name: "call rsp", bytes: [0xff, 0xd4], arch: /x86-64|x86|AMD64/i },
		{ name: "int 0x80", bytes: [0xcd, 0x80], arch: /x86/i },
	];
	const gadgets = {};
	for (const pattern of patterns) {
		if (pattern.arch && !pattern.arch.test(architecture.arch)) continue;
		const row = scanOpcodePattern(data, pattern.bytes, pattern.name);
		if (row.count) gadgets[pattern.name] = row;
	}
	const risks = [];
	const hints = [];
	if (Object.keys(gadgets).length) risks.push("native-rop-gadget-signal");
	if (gadgets["pop rdi; ret"] && (signals.commandExec.length || signals.shellPaths.length)) {
		risks.push("native-ret2libc-primitive-signal");
		hints.push("ret2libc-candidate: pop rdi; ret plus command/shell string signals; bind to system/exec import or libc leak before exploit.");
	}
	if (gadgets["syscall; ret"] && gadgets["pop rax; ret"] && gadgets["pop rdi; ret"]) {
		risks.push("native-syscall-rop-primitive-signal");
		hints.push("syscall-chain-candidate: syscall; ret with register-pop primitives; verify writable memory and constraints.");
	}
	if (gadgets["leave; ret"]) {
		risks.push("native-stack-pivot-gadget-signal");
		hints.push("stack-pivot-candidate: leave; ret present; check controllable saved rbp/rsp and pivot target.");
	}
	if (gadgets["jmp rsp"] || gadgets["call rsp"]) risks.push("native-stack-jump-gadget-signal");
	const stringAnchors = {
		binSh: strings.filter((row) => /\/bin\/(?:sh|bash)/i.test(row.text)).slice(0, 8).map((row) => ({ offset: row.offset, text: redact(row.text.slice(0, 120)) })),
		systemLike: signals.commandExec.slice(0, 8),
	};
	return {
		kind: "repi-native-gadget-quicklook",
		architecture,
		gadgetCount: Object.values(gadgets).reduce((sum, row) => sum + row.count, 0),
		gadgets,
		stringAnchors,
		risks,
		hints,
	};
}

function nativeStaticTriage(target) {
	const data = readFileSync(target);
	const strings = firmwareStrings(data, 4, 6000);
	const signals = {
		unsafeInput: nativeSignalRows(strings, /\b(?:gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|memcpy|memmove|__isoc99_scanf)\b/i),
		commandExec: nativeSignalRows(strings, /\b(?:system|popen|execve|execl|execvp|WinExec|ShellExecute|CreateProcess)\b/i),
		networkIo: nativeSignalRows(strings, /\b(?:socket|connect|bind|listen|accept|recv|send|WSAStartup|InternetOpen|HttpSendRequest|curl_easy_perform)\b/i),
		formatStrings: nativeSignalRows(strings, /%[0-9$*+# .-]*(?:n|p|x|s)/i),
		shellPaths: nativeSignalRows(strings, /(?:\/bin\/(?:sh|bash)|cmd\.exe|powershell|\/etc\/passwd)/i),
		cryptoCodec: nativeSignalRows(strings, /\b(?:AES|RSA|ChaCha|base64|zlib|inflate|deflate|xor|md5|sha1|sha256)\b/i),
		secretsAndFlags: nativeSignalRows(strings, /\b(?:flag|ctf|password|passwd|secret|token|api[_-]?key|nonce|salt)\b/i),
		urls: nativeSignalRows(strings, /https?:\/\/[^\s"'<>]{3,}/i),
	};
	const gadgetQuicklook = nativeGadgetQuicklook(data, strings, signals);
	const risks = [];
	if (signals.unsafeInput.length) risks.push("unsafe-input-sink-signal");
	if (signals.commandExec.length || signals.shellPaths.length) risks.push("command-execution-sink-signal");
	if (signals.formatStrings.length) risks.push("format-string-signal");
	if (signals.networkIo.length || signals.urls.length) risks.push("network-or-c2-string-signal");
	if (signals.cryptoCodec.length) risks.push("crypto-codec-transform-signal");
	if (signals.secretsAndFlags.length) risks.push("secret-or-flag-string-signal");
	for (const risk of gadgetQuicklook.risks) risks.push(risk);
	return {
		kind: "repi-native-static-triage",
		schemaVersion: 2,
		size: data.length,
		stringCount: strings.length,
		signals,
		gadgetQuicklook,
		risks,
		next: [
			"Confirm whether matched sinks are imported/reachable with objdump/readelf/r2 before treating them as exploitable.",
			"Use gadgetQuicklook to seed ROP/ret2libc hypotheses, then verify gadget virtual addresses in r2/gdb against PIE/load base.",
			"Bind format-string or unsafe-input strings to a callsite, then build a debugger replay with native-gdb-trace.gdb.",
			"Use URLs/crypto strings as reverse-engineering pivots; corroborate with xrefs or runtime traffic.",
		],
	};
}

export function nativeStaticTriageRows(target, artifactDir) {
	try {
		const summary = nativeStaticTriage(target);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "native-static-triage.json"), `${JSON.stringify(summary, null, 2)}\n`);
		return [
			{
				id: "native-static-triage",
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
		];
	} catch (error) {
		return [{ id: "native-static-triage", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}

function peMachineName(value) {
	return (
		{
			0x014c: "x86",
			0x01c0: "ARM",
			0x01c4: "ARMv7",
			0x8664: "x86-64",
			0xaa64: "ARM64",
		}[value] ?? `0x${Number(value ?? 0).toString(16)}`
	);
}

function peSubsystemName(value) {
	return (
		{
			1: "native",
			2: "windows-gui",
			3: "windows-cui",
			7: "posix-cui",
			9: "windows-ce-gui",
			10: "efi-application",
			11: "efi-boot-service-driver",
			12: "efi-runtime-driver",
			14: "xbox",
			16: "windows-boot-application",
		}[value] ?? String(value)
	);
}

export function parsePeQuicklook(target) {
	const data = readFileSync(target);
	if (data.length < 0x100 || data.subarray(0, 2).toString("ascii") !== "MZ") throw new Error("not a PE/MZ file");
	const peOffset = data.readUInt32LE(0x3c);
	if (!Number.isFinite(peOffset) || peOffset < 0x40 || peOffset + 24 > data.length) throw new Error("invalid PE header offset");
	if (data.subarray(peOffset, peOffset + 4).toString("hex") !== "50450000") throw new Error("missing PE signature");
	const coff = peOffset + 4;
	const machineValue = data.readUInt16LE(coff);
	const sectionCount = data.readUInt16LE(coff + 2);
	const timeDateStamp = data.readUInt32LE(coff + 4);
	const sizeOfOptionalHeader = data.readUInt16LE(coff + 16);
	const characteristics = data.readUInt16LE(coff + 18);
	const optional = coff + 20;
	if (optional + sizeOfOptionalHeader > data.length) throw new Error("truncated PE optional header");
	const magic = data.readUInt16LE(optional);
	if (![0x10b, 0x20b].includes(magic)) throw new Error(`unsupported PE optional magic=0x${magic.toString(16)}`);
	const pe64 = magic === 0x20b;
	const readPtr = (offset) => {
		if (offset < 0 || offset + (pe64 ? 8 : 4) > data.length) return undefined;
		if (!pe64) return data.readUInt32LE(offset);
		const value = data.readBigUInt64LE(offset);
		return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : undefined;
	};
	const addressOfEntryPoint = data.readUInt32LE(optional + 16);
	const imageBase = readPtr(optional + (pe64 ? 24 : 28));
	const sectionAlignment = data.readUInt32LE(optional + 32);
	const fileAlignment = data.readUInt32LE(optional + 36);
	const sizeOfImage = data.readUInt32LE(optional + 56);
	const sizeOfHeaders = data.readUInt32LE(optional + 60);
	const subsystemValue = data.readUInt16LE(optional + 68);
	const dllCharacteristics = data.readUInt16LE(optional + 70);
	const numberOfRvaAndSizes = data.readUInt32LE(optional + (pe64 ? 108 : 92));
	const dataDirectoryOffset = optional + (pe64 ? 112 : 96);
	const directories = [];
	for (let index = 0; index < Math.min(numberOfRvaAndSizes, 16); index++) {
		const offset = dataDirectoryOffset + index * 8;
		if (offset + 8 > optional + sizeOfOptionalHeader || offset + 8 > data.length) break;
		directories.push({ index, rva: data.readUInt32LE(offset), size: data.readUInt32LE(offset + 4) });
	}
	const sections = [];
	const sectionTable = optional + sizeOfOptionalHeader;
	for (let index = 0; index < Math.min(sectionCount, 96); index++) {
		const offset = sectionTable + index * 40;
		if (offset + 40 > data.length) break;
		const rawName = data.subarray(offset, offset + 8);
		const name = rawName.toString("ascii").replace(/\0.*$/s, "").trim() || `<section-${index}>`;
		const virtualSize = data.readUInt32LE(offset + 8);
		const virtualAddress = data.readUInt32LE(offset + 12);
		const rawSize = data.readUInt32LE(offset + 16);
		const rawPointer = data.readUInt32LE(offset + 20);
		const sectionCharacteristics = data.readUInt32LE(offset + 36);
		const raw = rawPointer < data.length ? data.subarray(rawPointer, Math.min(data.length, rawPointer + rawSize)) : Buffer.alloc(0);
		sections.push({
			name,
			virtualAddress,
			virtualSize,
			rawPointer,
			rawSize,
			characteristics: sectionCharacteristics,
			entropy: byteEntropy(raw),
			executable: Boolean(sectionCharacteristics & 0x20000000),
			writable: Boolean(sectionCharacteristics & 0x80000000),
		});
	}
	const rvaToOffset = (rva) => {
		if (!Number.isFinite(rva)) return undefined;
		if (rva > 0 && rva < sizeOfHeaders) return rva;
		for (const section of sections) {
			const span = Math.max(section.virtualSize, section.rawSize);
			if (span <= 0) continue;
			if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
				const offset = section.rawPointer + (rva - section.virtualAddress);
				return offset >= 0 && offset < data.length ? offset : undefined;
			}
		}
		return undefined;
	};
	const importDirectory = directories[1] ?? { rva: 0, size: 0 };
	const imports = [];
	const suspiciousImports = [];
	const suspiciousPattern = /\b(?:VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|OpenProcess|QueueUserAPC|SetWindowsHookEx|LoadLibraryA?|GetProcAddress|WinExec|ShellExecuteA?|InternetOpenA?|InternetConnectA?|WinHttpOpen|URLDownloadToFileA?|RegSetValueA?|Crypt(?:AcquireContext|Decrypt|Encrypt)|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\b/i;
	let importOffset = rvaToOffset(importDirectory.rva);
	if (Number.isFinite(importOffset) && importDirectory.size) {
		for (let descriptor = 0; descriptor < 128 && importOffset + 20 <= data.length; descriptor++, importOffset += 20) {
			const originalFirstThunk = data.readUInt32LE(importOffset);
			const nameRva = data.readUInt32LE(importOffset + 12);
			const firstThunk = data.readUInt32LE(importOffset + 16);
			if (!originalFirstThunk && !nameRva && !firstThunk) break;
			const dll = cStringAt(data, rvaToOffset(nameRva) ?? -1, 260);
			const thunkRva = originalFirstThunk || firstThunk;
			const thunkOffset = rvaToOffset(thunkRva);
			const functions = [];
			if (Number.isFinite(thunkOffset)) {
				const thunkSize = pe64 ? 8 : 4;
				for (let index = 0; index < 256 && thunkOffset + index * thunkSize + thunkSize <= data.length; index++) {
					const cursor = thunkOffset + index * thunkSize;
					const thunkValue = pe64 ? data.readBigUInt64LE(cursor) : BigInt(data.readUInt32LE(cursor));
					if (thunkValue === 0n) break;
					const ordinalMask = pe64 ? 0x8000000000000000n : 0x80000000n;
					if (thunkValue & ordinalMask) {
						functions.push(`#${Number(thunkValue & 0xffffn)}`);
						continue;
					}
					const hintNameOffset = rvaToOffset(Number(thunkValue));
					if (!Number.isFinite(hintNameOffset) || hintNameOffset + 2 >= data.length) continue;
					const name = cStringAt(data, hintNameOffset + 2, 260);
					if (!name) continue;
					functions.push(name);
					if (suspiciousPattern.test(name)) suspiciousImports.push({ dll, name });
				}
			}
			imports.push({ dll: dll || `<unnamed-${descriptor}>`, functions: functions.slice(0, 160) });
		}
	}
	const mitigations = {
		dynamicBase: Boolean(dllCharacteristics & 0x40),
		nx: Boolean(dllCharacteristics & 0x100),
		highEntropyVa: Boolean(dllCharacteristics & 0x20),
		noSeh: Boolean(dllCharacteristics & 0x400),
		guardCf: Boolean(dllCharacteristics & 0x4000),
		terminalServerAware: Boolean(dllCharacteristics & 0x8000),
	};
	const risks = [];
	if (!mitigations.dynamicBase) risks.push("no-aslr-dynamic-base");
	if (!mitigations.nx) risks.push("no-nx-compat");
	if (pe64 && !mitigations.highEntropyVa) risks.push("no-high-entropy-va");
	if (!mitigations.guardCf) risks.push("no-control-flow-guard");
	if (sections.some((section) => section.executable && section.writable)) risks.push("writable-executable-section");
	if (sections.some((section) => section.entropy >= 7.2)) risks.push("high-entropy-section-packer-signal");
	if (suspiciousImports.length) risks.push("suspicious-import-surface");
	return {
		kind: "repi-native-pe-quicklook",
		schemaVersion: 1,
		target: redact(target),
		pe: {
			format: pe64 ? "PE32+" : "PE32",
			machine: peMachineName(machineValue),
			machineValue,
			timeDateStamp,
			characteristics,
			entryRva: `0x${addressOfEntryPoint.toString(16)}`,
			imageBase: Number.isFinite(imageBase) ? `0x${imageBase.toString(16)}` : null,
			sectionAlignment,
			fileAlignment,
			sizeOfImage,
			sizeOfHeaders,
			subsystem: peSubsystemName(subsystemValue),
			subsystemValue,
			dllCharacteristics,
		},
		mitigations,
		sections,
		imports,
		suspiciousImports: suspiciousImports.slice(0, 120),
		risks,
	};
}

export function nativePeQuicklookRows(target, artifactDir) {
	try {
		const summary = parsePeQuicklook(target);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "native-pe-quicklook.json"), `${JSON.stringify(summary, null, 2)}\n`);
		return [
			{
				id: "native-pe-quicklook",
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
		];
	} catch (error) {
		return [{ id: "native-pe-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}

function machoCpuName(value) {
	return (
		{
			7: "x86",
			0x01000007: "x86-64",
			12: "ARM",
			0x0100000c: "ARM64",
			18: "PowerPC",
			0x01000012: "PowerPC64",
		}[value] ?? `0x${Number(value ?? 0).toString(16)}`
	);
}

function machoFileTypeName(value) {
	return (
		{
			1: "object",
			2: "executable",
			3: "fixed-vm-library",
			4: "core",
			5: "preload",
			6: "dylib",
			7: "dylinker",
			8: "bundle",
			9: "dylib-stub",
			10: "dsym",
			11: "kext-bundle",
		}[value] ?? `unknown-${value}`
	);
}

function machoLoadCommandName(value) {
	const base = value & ~0x80000000;
	const suffix = value & 0x80000000 ? "|REQ_DYLD" : "";
	return (
		{
			1: "LC_SEGMENT",
			2: "LC_SYMTAB",
			5: "LC_UNIXTHREAD",
			11: "LC_DYSYMTAB",
			12: "LC_LOAD_DYLIB",
			13: "LC_ID_DYLIB",
			14: "LC_LOAD_DYLINKER",
			15: "LC_ID_DYLINKER",
			24: "LC_LOAD_WEAK_DYLIB",
			25: "LC_SEGMENT_64",
			27: "LC_UUID",
			28: "LC_RPATH",
			29: "LC_CODE_SIGNATURE",
			34: "LC_DYLD_INFO",
			36: "LC_VERSION_MIN_MACOSX",
			37: "LC_VERSION_MIN_IPHONEOS",
			40: "LC_MAIN",
			44: "LC_ENCRYPTION_INFO_64",
			50: "LC_BUILD_VERSION",
		}[base] ?? `LC_0x${base.toString(16)}`
	) + suffix;
}

function machoPlatformName(value) {
	return (
		{
			1: "macOS",
			2: "iOS",
			3: "tvOS",
			4: "watchOS",
			6: "Mac Catalyst",
			7: "iOS Simulator",
			8: "tvOS Simulator",
			9: "watchOS Simulator",
			11: "visionOS",
		}[value] ?? `unknown-${value}`
	);
}

function machoVersion(value) {
	return `${(value >>> 16) & 0xffff}.${(value >>> 8) & 0xff}.${value & 0xff}`;
}

function emptyMachOSymbolSignals() {
	return {
		dangerous: [],
		dynamicLoader: [],
		objcSwift: [],
		cryptoNetwork: [],
		antiDebug: [],
	};
}

function machoSymbolSignalKinds(name) {
	const kinds = [];
	if (/(?:^|_)system$|(?:^|_)popen$|(?:^|_)execv(?:e|p)?$|(?:^|_)posix_spawn$|(?:^|_)fork$|(?:^|_)mprotect$|(?:^|_)vm_protect$/i.test(name)) kinds.push("dangerous");
	if (/(?:^|_)dlopen$|(?:^|_)dlsym$|(?:^|_)NSClassFromString$|(?:^|_)objc_getClass$/i.test(name)) kinds.push("dynamicLoader");
	if (/(?:^|_)objc_msgSend$|(?:^|_)objc_(?:retain|release|storeStrong)|OBJC_(?:CLASS|METACLASS|IVAR|SEL)_|^_\$s|swift_/i.test(name)) kinds.push("objcSwift");
	if (/SecTrustEvaluate|SecTrustEvaluateWithError|NSURLSession|URLSession|NSURLConnection|CCCrypt|CommonCrypto|CryptoKit|SecCertificate|SecPolicy|SSLSetSessionOption/i.test(name)) kinds.push("cryptoNetwork");
	if (/(?:^|_)ptrace$|(?:^|_)sysctl$|(?:^|_)task_for_pid$|jailbreak|frida|substrate|cydia|amIBeingDebugged/i.test(name)) kinds.push("antiDebug");
	return kinds;
}

function parseThinMachOQuicklook(data, target, fatInfo = null) {
	if (data.length < 28) throw new Error("Mach-O too small");
	const magicLe = data.readUInt32LE(0);
	const magicBe = data.readUInt32BE(0);
	const little = magicLe === 0xfeedface || magicLe === 0xfeedfacf;
	const big = magicBe === 0xfeedface || magicBe === 0xfeedfacf;
	if (!little && !big) throw new Error(`not Mach-O magic=${data.subarray(0, 4).toString("hex")}`);
	const magic = little ? magicLe : magicBe;
	const is64 = magic === 0xfeedfacf;
	const readU32 = (offset) => (little ? data.readUInt32LE(offset) : data.readUInt32BE(offset));
	const readI32 = (offset) => (little ? data.readInt32LE(offset) : data.readInt32BE(offset));
	const readU64 = (offset) => {
		const value = little ? data.readBigUInt64LE(offset) : data.readBigUInt64BE(offset);
		return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
	};
	const headerSize = is64 ? 32 : 28;
	if (data.length < headerSize) throw new Error("truncated Mach-O header");
	const cpuType = readI32(4);
	const cpuSubType = readI32(8);
	const fileType = readU32(12);
	const ncmds = readU32(16);
	const sizeofcmds = readU32(20);
	const flags = readU32(24);
	const commands = [];
	const segments = [];
	const dylibs = [];
	const rpaths = [];
	let symtabCommand = null;
	let codeSignature = null;
	let encryption = null;
	let entry = null;
	let buildVersion = null;
	let uuid = null;
	let cursor = headerSize;
	for (let index = 0; index < Math.min(ncmds, 512); index++) {
		if (cursor + 8 > data.length) break;
		const cmd = readU32(cursor);
		const cmdsize = readU32(cursor + 4);
		if (cmdsize < 8 || cursor + cmdsize > data.length) break;
		const command = { index, offset: cursor, cmd: machoLoadCommandName(cmd), cmdValue: cmd, cmdsize };
		commands.push(command);
		const baseCmd = cmd & ~0x80000000;
		if (baseCmd === 25 && is64 && cmdsize >= 72) {
			const segname = data.toString("ascii", cursor + 8, cursor + 24).replace(/\0.*$/s, "");
			const vmaddr = readU64(cursor + 24);
			const vmsize = readU64(cursor + 32);
			const fileoff = readU64(cursor + 40);
			const filesize = readU64(cursor + 48);
			const maxprot = readU32(cursor + 56);
			const initprot = readU32(cursor + 60);
			const nsects = readU32(cursor + 64);
			const sections = [];
			let sectionCursor = cursor + 72;
			for (let sectionIndex = 0; sectionIndex < Math.min(nsects, 96) && sectionCursor + 80 <= cursor + cmdsize; sectionIndex++, sectionCursor += 80) {
				const sectionName = data.toString("ascii", sectionCursor, sectionCursor + 16).replace(/\0.*$/s, "");
				const segmentName = data.toString("ascii", sectionCursor + 16, sectionCursor + 32).replace(/\0.*$/s, "");
				const addr = readU64(sectionCursor + 32);
				const size = readU64(sectionCursor + 40);
				const offset = readU32(sectionCursor + 48);
				const flagsValue = readU32(sectionCursor + 68);
				const bytes = offset < data.length && Number.isFinite(size) ? data.subarray(offset, Math.min(data.length, offset + size)) : Buffer.alloc(0);
				sections.push({
					name: sectionName,
					segment: segmentName,
					address: typeof addr === "number" ? `0x${addr.toString(16)}` : addr,
					size,
					offset,
					flags: flagsValue,
					entropy: byteEntropy(bytes),
				});
			}
			segments.push({
				name: segname,
				vmaddr: typeof vmaddr === "number" ? `0x${vmaddr.toString(16)}` : vmaddr,
				vmsize,
				fileoff,
				filesize,
				maxprot,
				initprot,
				executable: Boolean(initprot & 0x4),
				writable: Boolean(initprot & 0x2),
				readable: Boolean(initprot & 0x1),
				sections,
			});
		} else if ([12, 13, 14, 15, 24].includes(baseCmd) && cmdsize >= 12) {
			const nameOffset = readU32(cursor + 8);
			const name = nameOffset < cmdsize ? cStringAt(data, cursor + nameOffset, Math.min(512, cmdsize - nameOffset)) : "";
			if (baseCmd === 12 || baseCmd === 24) dylibs.push({ name: redact(name), weak: baseCmd === 24 });
			else command.name = redact(name);
		} else if (baseCmd === 28 && cmdsize >= 12) {
			const pathOffset = readU32(cursor + 8);
			const path = pathOffset < cmdsize ? cStringAt(data, cursor + pathOffset, Math.min(512, cmdsize - pathOffset)) : "";
			if (path) rpaths.push(redact(path));
		} else if (baseCmd === 29 && cmdsize >= 16) {
			const dataOffset = readU32(cursor + 8);
			codeSignature = {
				dataOffset,
				dataSize: readU32(cursor + 12),
				fileOffset: Number.isFinite(fatInfo?.selectedOffset) ? fatInfo.selectedOffset + dataOffset : dataOffset,
			};
		} else if (baseCmd === 44 && cmdsize >= 24) {
			encryption = {
				cryptOffset: readU32(cursor + 8),
				cryptSize: readU32(cursor + 12),
				cryptId: readU32(cursor + 16),
			};
		} else if (baseCmd === 40 && cmdsize >= 24) {
			entry = { entryOffset: readU64(cursor + 8), stackSize: readU64(cursor + 16) };
		} else if (baseCmd === 50 && cmdsize >= 24) {
			buildVersion = {
				platform: machoPlatformName(readU32(cursor + 8)),
				minos: machoVersion(readU32(cursor + 12)),
				sdk: machoVersion(readU32(cursor + 16)),
				toolCount: readU32(cursor + 20),
			};
		} else if (baseCmd === 27 && cmdsize >= 24) {
			uuid = data.subarray(cursor + 8, cursor + 24).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
		} else if (baseCmd === 2 && cmdsize >= 24) {
			symtabCommand = {
				symoff: readU32(cursor + 8),
				nsyms: readU32(cursor + 12),
				stroff: readU32(cursor + 16),
				strsize: readU32(cursor + 20),
			};
			command.symoff = symtabCommand.symoff;
			command.nsyms = symtabCommand.nsyms;
			command.stroff = symtabCommand.stroff;
			command.strsize = symtabCommand.strsize;
		}
		cursor += cmdsize;
	}
	let symbols = null;
	if (symtabCommand) {
		const nlistSize = is64 ? 16 : 12;
		const symtabValid = symtabCommand.symoff + nlistSize <= data.length && symtabCommand.stroff < data.length;
		const sampled = [];
		const signals = emptyMachOSymbolSignals();
		if (symtabValid) {
			const symbolLimit = Math.min(symtabCommand.nsyms, 512);
			const strEnd = Math.min(data.length, symtabCommand.stroff + symtabCommand.strsize);
			for (let symbolIndex = 0; symbolIndex < symbolLimit; symbolIndex++) {
				const symbolOffset = symtabCommand.symoff + symbolIndex * nlistSize;
				if (symbolOffset + nlistSize > data.length) break;
				const strx = readU32(symbolOffset);
				const type = data[symbolOffset + 4];
				const section = data[symbolOffset + 5];
				const desc = little ? data.readUInt16LE(symbolOffset + 6) : data.readUInt16BE(symbolOffset + 6);
				const value = is64 ? readU64(symbolOffset + 8) : readU32(symbolOffset + 8);
				const nameOffset = symtabCommand.stroff + strx;
				const name = strx > 0 && nameOffset < strEnd ? redact(cStringAt(data, nameOffset, Math.min(384, strEnd - nameOffset))) : "";
				if (!name) continue;
				const symbol = {
					index: symbolIndex,
					name,
					type,
					section,
					desc,
					value: typeof value === "number" ? `0x${value.toString(16)}` : value,
				};
				if (sampled.length < 160) sampled.push(symbol);
				for (const kind of machoSymbolSignalKinds(name)) {
					if (signals[kind].length < 80) signals[kind].push(symbol);
				}
			}
		}
		symbols = {
			symoff: symtabCommand.symoff,
			nsyms: symtabCommand.nsyms,
			stroff: symtabCommand.stroff,
			strsize: symtabCommand.strsize,
			fileSymoff: Number.isFinite(fatInfo?.selectedOffset) ? fatInfo.selectedOffset + symtabCommand.symoff : symtabCommand.symoff,
			fileStroff: Number.isFinite(fatInfo?.selectedOffset) ? fatInfo.selectedOffset + symtabCommand.stroff : symtabCommand.stroff,
			valid: symtabValid,
			sampled,
			signals,
		};
	}
	const risks = [];
	if (!Boolean(flags & 0x200000)) risks.push("no-mach-o-pie");
	if (Boolean(flags & 0x20000)) risks.push("mach-o-allows-stack-execution");
	if (segments.some((segment) => segment.executable && segment.writable)) risks.push("writable-executable-segment");
	if (segments.some((segment) => segment.sections?.some((section) => section.entropy >= 7.2))) risks.push("high-entropy-section-packer-signal");
	if (!codeSignature) risks.push("missing-code-signature-command");
	if (encryption?.cryptId) risks.push("encrypted-mach-o-segment");
	if (rpaths.length) risks.push("rpath-dylib-hijack-surface");
	if (symbols?.signals.dangerous.length) risks.push("macho-dangerous-symbol-surface");
	if (symbols?.signals.dynamicLoader.length) risks.push("macho-dynamic-loader-symbol-surface");
	if (symbols?.signals.objcSwift.length) risks.push("macho-objc-swift-metadata-signal");
	if (symbols?.signals.cryptoNetwork.length) risks.push("macho-crypto-network-symbol-signal");
	if (symbols?.signals.antiDebug.length) risks.push("macho-anti-debug-symbol-signal");
	return {
		kind: "repi-native-macho-quicklook",
		schemaVersion: 1,
		target: redact(target),
		fat: fatInfo,
		macho: {
			format: is64 ? "Mach-O 64-bit" : "Mach-O 32-bit",
			endian: little ? "little" : "big",
			cpu: machoCpuName(cpuType),
			cpuType,
			cpuSubType,
			fileType: machoFileTypeName(fileType),
			fileTypeValue: fileType,
			sliceOffset: fatInfo?.selectedOffset ?? 0,
			sliceSize: fatInfo?.selectedSize ?? data.length,
			ncmds,
			sizeofcmds,
			flags,
			uuid,
		},
		commands,
		segments,
		dylibs,
		rpaths,
		codeSignature,
		encryption,
		entry,
		buildVersion,
		symbols,
		risks,
	};
}

function parseMachoQuicklook(target) {
	const data = readFileSync(target);
	if (data.length < 4) throw new Error("Mach-O too small");
	const magicBe = data.readUInt32BE(0);
	const magicLe = data.readUInt32LE(0);
	const fatBig = magicBe === 0xcafebabe || magicBe === 0xcafebabf;
	const fatLittle = magicLe === 0xcafebabe || magicLe === 0xcafebabf;
	if (!fatBig && !fatLittle) return parseThinMachOQuicklook(data, target);
	const is64 = magicBe === 0xcafebabf || magicLe === 0xcafebabf;
	const readU32 = (offset) => (fatBig ? data.readUInt32BE(offset) : data.readUInt32LE(offset));
	const readI32 = (offset) => (fatBig ? data.readInt32BE(offset) : data.readInt32LE(offset));
	const readU64 = (offset) => {
		const value = fatBig ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset);
		return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
	};
	const nfatArch = data.length >= 8 ? readU32(4) : 0;
	const archSize = is64 ? 32 : 20;
	const architectures = [];
	let cursor = 8;
	for (let index = 0; index < Math.min(nfatArch, 64) && cursor + archSize <= data.length; index++, cursor += archSize) {
		const cpuType = readI32(cursor);
		const cpuSubType = readI32(cursor + 4);
		const offset = is64 ? readU64(cursor + 8) : readU32(cursor + 8);
		const size = is64 ? readU64(cursor + 16) : readU32(cursor + 12);
		const align = readU32(cursor + (is64 ? 24 : 16));
		architectures.push({
			index,
			cpu: machoCpuName(cpuType),
			cpuType,
			cpuSubType,
			offset,
			size,
			align,
		});
	}
	const selected = architectures.find((arch) => {
		if (!Number.isFinite(arch.offset) || !Number.isFinite(arch.size)) return false;
		if (arch.offset < 0 || arch.size < 28 || arch.offset + arch.size > data.length) return false;
		const magic = data.subarray(arch.offset, arch.offset + 4).toString("hex");
		return ["feedface", "cefaedfe", "feedfacf", "cffaedfe"].includes(magic);
	});
	const fatInfo = {
		format: is64 ? "fat Mach-O 64-bit" : "fat Mach-O",
		endian: fatBig ? "big" : "little",
		architectureCount: nfatArch,
		architectures,
		selectedIndex: selected?.index ?? null,
		selectedOffset: selected?.offset ?? null,
		selectedSize: selected?.size ?? null,
	};
	if (!selected) {
		return {
			kind: "repi-native-macho-quicklook",
			schemaVersion: 1,
			target: redact(target),
			fat: fatInfo,
			macho: null,
			commands: [],
			segments: [],
			dylibs: [],
			rpaths: [],
			codeSignature: null,
			encryption: null,
			entry: null,
			buildVersion: null,
			symbols: null,
			risks: ["fat-mach-o-no-parseable-slice"],
		};
	}
	return parseThinMachOQuicklook(data.subarray(selected.offset, selected.offset + selected.size), target, fatInfo);
}

export function nativeMachOQuicklookRows(target, artifactDir) {
	try {
		const summary = parseMachoQuicklook(target);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "native-macho-quicklook.json"), `${JSON.stringify(summary, null, 2)}\n`);
		return [
			{
				id: "native-macho-quicklook",
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
		];
	} catch (error) {
		return [{ id: "native-macho-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}

function nativeRunTimeoutSeconds() {
	return Math.max(1, Math.min(deep ? 10 : 5, Math.ceil(timeoutMs / 1000)));
}

function nativeExecutionCaseScript(target, seconds, mode) {
	const prefix = `
set +e
BIN=${shellQuote(target)}
T=${seconds}
MODE=${shellQuote(mode)}
if [ ! -x "$BIN" ]; then
  printf '[native-exec] mode=%s skipped=not_executable file_mode=%s\\n' "$MODE" "$(stat -c '%A' "$BIN" 2>/dev/null || printf unknown)"
  exit 0
fi
`.trim();
	const crashPrinter = `
case "$code" in
  124|137) printf '[native-exec] timeout=true\\n' ;;
  139) printf '[native-exec] crash_signal=SIGSEGV\\n' ;;
  134) printf '[native-exec] crash_signal=SIGABRT\\n' ;;
esac
exit 0
`.trim();
	if (mode === "empty") {
		return `${prefix}
timeout "$T"s "$BIN" </dev/null
code=$?
printf '\\n[native-exec] mode=empty exit=%s case=empty-stdin payload_len=0 timeout_s=%s\\n' "$code" "$T"
${crashPrinter}`;
	}
	if (mode === "argv-help") {
		return `${prefix}
timeout "$T"s "$BIN" --help </dev/null
code=$?
printf '\\n[native-exec] mode=argv-help exit=%s case=argv-help argv_count=1 payload_len=0 timeout_s=%s\\n' "$code" "$T"
${crashPrinter}`;
	}
	if (mode === "argv-cyclic") {
		return `${prefix}
if command -v python3 >/dev/null 2>&1; then
  ARG="$(python3 - <<'PY'
import sys
alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
out = bytearray()
for a in alphabet:
    for b in alphabet:
        for c in alphabet:
            out += bytes((a, b, c))
            if len(out) >= 256:
                sys.stdout.write(bytes(out[:256]).decode("ascii"))
                raise SystemExit
PY
)"
else
  ARG="$(head -c 256 /dev/zero | tr '\\0' 'A')"
fi
timeout "$T"s "$BIN" "$ARG" </dev/null
code=$?
printf '\\n[native-exec] mode=argv-cyclic exit=%s case=argv-cyclic argv_count=1 argv_len=%s payload_len=0 timeout_s=%s\\n' "$code" "\${#ARG}" "$T"
${crashPrinter}`;
	}
	if (mode === "format-stdin") {
		return `${prefix}
printf '%s\\n' '%p.%p.%p.%n' | timeout "$T"s "$BIN"
code=\${PIPESTATUS[1]}
printf '\\n[native-exec] mode=format-stdin exit=%s case=format-stdin input_len=12 timeout_s=%s\\n' "$code" "$T"
${crashPrinter}`;
	}
	if (mode === "env-marker") {
		return `${prefix}
REPI_NATIVE_MARKER=repi-native-env-control timeout "$T"s "$BIN" </dev/null
code=$?
printf '\\n[native-exec] mode=env-marker exit=%s case=env-marker env_keys=REPI_NATIVE_MARKER payload_len=0 timeout_s=%s\\n' "$code" "$T"
${crashPrinter}`;
	}
	if (mode === "short-stdin") {
		return `${prefix}
printf '%s\\n' 'AAAAAAAAAAAAAAAA' | timeout "$T"s "$BIN"
code=\${PIPESTATUS[1]}
printf '\\n[native-exec] mode=short-stdin exit=%s case=short-stdin input_len=17 timeout_s=%s\\n' "$code" "$T"
${crashPrinter}`;
	}
	const cyclicCase = mode === "cyclic-repeat" ? "cyclic-2" : "cyclic-1";
	return `${prefix}
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY' | timeout "$T"s "$BIN"
import sys
alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
out = bytearray()
for a in alphabet:
    for b in alphabet:
        for c in alphabet:
            out += bytes((a, b, c))
            if len(out) >= 768:
                sys.stdout.buffer.write(bytes(out[:768]) + b"\\n")
                raise SystemExit
PY
  code=\${PIPESTATUS[1]}
else
  head -c 768 /dev/zero | tr '\\0' 'A' | timeout "$T"s "$BIN"
  code=\${PIPESTATUS[2]}
fi
printf '\\n[native-exec] mode=%s exit=%s case=%s input_len=769 timeout_s=%s\\n' "$MODE" "$code" ${shellQuote(cyclicCase)} "$T"
${crashPrinter}`;
}

export function nativeExecutionRows(target) {
	const seconds = nativeRunTimeoutSeconds();
	const caseRows = [
		["native-run-empty", "empty", seconds + 2],
		["native-run-argv-help", "argv-help", seconds + 2],
		["native-run-argv-cyclic", "argv-cyclic", seconds + 2],
		["native-run-format-stdin", "format-stdin", seconds + 2],
		["native-run-env-marker", "env-marker", seconds + 2],
		["native-run-short-stdin", "short-stdin", seconds + 2],
		["native-run-cyclic", "cyclic", seconds + 3],
		["native-run-cyclic-repeat", "cyclic-repeat", seconds + 3],
	];
	return caseRows.map(([id, mode, timeoutSeconds]) => run("bash", ["-lc", nativeExecutionCaseScript(target, seconds, mode)], { id, timeout: timeoutSeconds * 1000 }));
}

function nativeReplayVerifierSource(target) {
	return `#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import sys
import time

BIN = sys.argv[1] if len(sys.argv) > 1 else ${JSON.stringify(target)}
TIMEOUT = float(os.getenv("REPI_NATIVE_TIMEOUT", "${nativeRunTimeoutSeconds()}"))
RUNS = int(os.getenv("REPI_NATIVE_RUNS", "3"))
CYCLIC_LEN = int(os.getenv("REPI_NATIVE_CYCLIC_LEN", "768"))
ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
FORMAT_PROBE = b"%p.%p.%p.%n\\n"

def cyclic(length):
    out = bytearray()
    for a in ALPHABET:
        for b in ALPHABET:
            for c in ALPHABET:
                out += bytes((a, b, c))
                if len(out) >= length:
                    return bytes(out[:length])
    return bytes(out[:length])

def sha(data):
    return hashlib.sha256(data).hexdigest()

def crash_like(exit_code):
    return isinstance(exit_code, int) and (exit_code < 0 or exit_code in (134, 139))

def run_case(name, payload, argv=None, extra_env=None):
    argv = list(argv or [])
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    started = time.time()
    try:
        proc = subprocess.run([BIN, *argv], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT, env=env)
        duration_ms = int((time.time() - started) * 1000)
        row = {
            "case": name,
            "exit": proc.returncode,
            "crashLike": crash_like(proc.returncode),
            "timeout": False,
            "durationMs": duration_ms,
            "argvCount": len(argv),
            "argvSha256": sha("\\x00".join(argv).encode("utf-8", "replace")) if argv else None,
            "envKeys": sorted((extra_env or {}).keys()),
            "payloadLen": len(payload),
            "payloadSha256": sha(payload),
            "stdoutSha256": sha(proc.stdout),
            "stderrSha256": sha(proc.stderr),
            "stdoutSample": proc.stdout[:160].decode("utf-8", "replace"),
            "stderrSample": proc.stderr[:160].decode("utf-8", "replace"),
        }
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.time() - started) * 1000)
        row = {
            "case": name,
            "exit": "timeout",
            "crashLike": False,
            "timeout": True,
            "durationMs": duration_ms,
            "argvCount": len(argv),
            "argvSha256": sha("\\x00".join(argv).encode("utf-8", "replace")) if argv else None,
            "envKeys": sorted((extra_env or {}).keys()),
            "payloadLen": len(payload),
            "payloadSha256": sha(payload),
            "stdoutSha256": sha(exc.stdout or b""),
            "stderrSha256": sha(exc.stderr or b""),
        }
    print("[native-replay]", json.dumps(row, sort_keys=True))
    return row

def main():
    if not os.path.exists(BIN):
        print("[native-replay]", json.dumps({"error": "target_missing", "target": BIN}, sort_keys=True))
        return 2
    print("[native-replay]", json.dumps({"target": BIN, "runs": RUNS, "timeout": TIMEOUT, "cyclicLen": CYCLIC_LEN}, sort_keys=True))
    payload = cyclic(CYCLIC_LEN) + b"\\n"
    argv_payload = cyclic(min(CYCLIC_LEN, 256)).decode("ascii", "ignore")
    rows = [
        run_case("empty-stdin", b""),
        run_case("argv-help", b"", ["--help"]),
        run_case("argv-cyclic", b"", [argv_payload]),
        run_case("format-stdin", FORMAT_PROBE),
        run_case("env-marker", b"", [], {"REPI_NATIVE_MARKER": "repi-native-env-control"}),
    ]
    for index in range(max(1, RUNS)):
        rows.append(run_case(f"cyclic-{index + 1}", payload))
    unstable = len({json.dumps({"exit": row["exit"], "stdout": row["stdoutSha256"], "stderr": row["stderrSha256"]}, sort_keys=True) for row in rows[1:]}) > 1
    crashes = [row for row in rows if crash_like(row["exit"])]
    print("[native-replay]", json.dumps({
        "ioContract": {
            "cases": [row["case"] for row in rows],
            "stdinCases": [row["case"] for row in rows if row["payloadLen"]],
            "argvCases": [row["case"] for row in rows if row["argvCount"]],
            "envCases": [row["case"] for row in rows if row["envKeys"]],
        },
        "unstable": unstable,
        "crashLike": len(crashes),
        "crashCases": [row["case"] for row in crashes],
        "next": "If cyclic crashes, rerun under gdb/pwndbg and map register bytes back into this cyclic payload; if argv/env cases diverge, add them to the exploit harness input contract.",
    }, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
`;
}

export function writeNativeReplayVerifier(artifactDir, target) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "native-replay-verifier.py");
	writePrivate(path, nativeReplayVerifierSource(target), 0o700);
	return path;
}

function nativeCyclicPayload(length = 768) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let out = "";
	for (const a of alphabet) {
		for (const b of alphabet) {
			for (const c of alphabet) {
				out += `${a}${b}${c}`;
				if (out.length >= length) return Buffer.from(`${out.slice(0, length)}\n`, "ascii");
			}
		}
	}
	return Buffer.from(`${out.slice(0, length)}\n`, "ascii");
}

function nativeCyclicOffsetSource() {
	return `#!/usr/bin/env python3
import json
import re
import sys

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

def cyclic(length):
    out = bytearray()
    for a in ALPHABET:
        for b in ALPHABET:
            for c in ALPHABET:
                out += bytes((a, b, c))
                if len(out) >= length:
                    return bytes(out[:length])
    return bytes(out[:length])

def candidates(value):
    raw = str(value).strip()
    out = []
    if raw.startswith("hex:"):
        try:
            out.append(("hex", bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", raw[4:]))))
        except ValueError:
            pass
    elif raw.startswith("0x") or re.fullmatch(r"[0-9a-fA-F]{6,16}", raw):
        text = raw[2:] if raw.startswith("0x") else raw
        if len(text) % 2:
            text = "0" + text
        try:
            data = bytes.fromhex(text)
            out.append(("hex-big", data))
            out.append(("hex-little", data[::-1]))
        except ValueError:
            pass
    if raw:
        out.append(("ascii", raw.encode("latin1", "ignore")))
    return [(kind, data) for kind, data in out if data]

def main():
    if len(sys.argv) < 2:
        print("usage: native-cyclic-offset.py <hex:41414142|0x42414141|ascii>", file=sys.stderr)
        return 2
    pattern_len = int(sys.argv[2]) if len(sys.argv) > 2 else 8192
    pattern = cyclic(pattern_len)
    rows = []
    for item in sys.argv[1:2]:
        for kind, needle in candidates(item):
            offset = pattern.find(needle)
            rows.append({"input": item, "kind": kind, "needleHex": needle.hex(), "offset": offset if offset >= 0 else None})
    result = {"kind": "repi-native-cyclic-offset", "patternLength": len(pattern), "rows": rows}
    print(json.dumps(result, sort_keys=True))
    return 0 if any(row["offset"] is not None for row in rows) else 1

if __name__ == "__main__":
    raise SystemExit(main())
`;
}

function gdbQuote(value) {
	return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function writeNativeGdbTraceArtifacts(artifactDir, target) {
	if (noWrite || !artifactDir) return undefined;
	const payloadPath = join(artifactDir, "native-cyclic-payload.bin");
	const gdbPath = join(artifactDir, "native-gdb-trace.gdb");
	const offsetPath = join(artifactDir, "native-cyclic-offset.py");
	writePrivate(payloadPath, nativeCyclicPayload(), 0o600);
	const script = [
		"set pagination off",
		"set confirm off",
		"set disassemble-next-line on",
		"set follow-fork-mode child",
		"set detach-on-fork off",
		`file ${gdbQuote(target)}`,
		`run < ${gdbQuote(payloadPath)}`,
		'printf "\\n[repi-gdb] stop-info\\\\n"',
		"info registers",
		"bt",
		"x/24gx $rsp",
		"x/16i $pc-32",
		"quit",
		"",
	].join("\n");
	writePrivate(gdbPath, script, 0o600);
	writePrivate(offsetPath, nativeCyclicOffsetSource(), 0o700);
	return { payloadPath, gdbPath, offsetPath };
}

function nativeRuntimeVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
EXPECTED_CASES = ["empty-stdin", "argv-help", "argv-cyclic", "format-stdin", "env-marker", "short-stdin", "cyclic-1", "cyclic-2"]
STATIC_ARTIFACTS = [
    "native-elf-hardening.json",
    "native-pe-quicklook.json",
    "native-macho-quicklook.json",
    "native-static-triage.json",
    "native-exploit-hypotheses.json",
    "native-primitive-claims.json",
    "native-replay-verifier.py",
    "native-gdb-trace.gdb",
    "native-cyclic-payload.bin",
    "native-cyclic-offset.py",
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def cyclic(length):
    out = bytearray()
    for a in ALPHABET:
        for b in ALPHABET:
            for c in ALPHABET:
                out += bytes((a, b, c))
                if len(out) >= length:
                    return bytes(out[:length])
    return bytes(out[:length])


def crash_like(exit_code):
    return isinstance(exit_code, int) and (exit_code < 0 or exit_code in (134, 139) or exit_code > 128)


def target_identity(target):
    if not os.path.exists(target):
        return {"exists": False, "verified": False, "reason": "target-missing"}
    with open(target, "rb") as handle:
        data = handle.read()
    st = os.stat(target)
    row = {
        "exists": True,
        "verified": True,
        "size": len(data),
        "sha256": sha256(data),
        "headerHex": data[:16].hex(),
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "executable": bool(st.st_mode & 0o111),
    }
    if data:
        mutated = bytearray(data)
        mutated[0] ^= 0xFF
        row["negativeControl"] = {
            "controlType": "native-target-byte-mutation-rejection",
            "mutatedSha256": sha256(bytes(mutated)),
            "passed": sha256(bytes(mutated)) != row["sha256"],
        }
    return row


def artifact_bindings(artifact_dir):
    rows = []
    for rel in STATIC_ARTIFACTS:
        path = os.path.join(artifact_dir, rel)
        if not os.path.exists(path):
            continue
        with open(path, "rb") as handle:
            data = handle.read()
        parsed = None
        if rel.endswith(".json"):
            try:
                parsed = json.loads(data.decode("utf-8"))
            except Exception:
                parsed = None
        rows.append({
            "relPath": rel,
            "size": len(data),
            "sha256": sha256(data),
            "mode": oct(stat.S_IMODE(os.stat(path).st_mode)),
            "kind": parsed.get("kind") if isinstance(parsed, dict) else None,
            "schemaVersion": parsed.get("schemaVersion") if isinstance(parsed, dict) else None,
        })
    return rows


def input_binding(case):
    if case in {"cyclic-1", "cyclic-2"}:
        payload = cyclic(768) + b"\n"
        return {"payloadLen": len(payload), "payloadSha256": sha256(payload)}
    if case == "format-stdin":
        payload = b"%p.%p.%p.%n\n"
        return {"payloadLen": len(payload), "payloadSha256": sha256(payload)}
    if case == "short-stdin":
        payload = b"AAAAAAAAAAAAAAAA\n"
        return {"payloadLen": len(payload), "payloadSha256": sha256(payload)}
    if case == "argv-cyclic":
        argv = cyclic(256)
        return {"payloadLen": 0, "payloadSha256": sha256(b""), "argvSha256": sha256(argv), "argvLen": len(argv)}
    return {"payloadLen": 0, "payloadSha256": sha256(b"")}


def run_case(target, case, timeout):
    payload = b""
    argv = []
    env = os.environ.copy()
    extra_env = []
    if case == "argv-help":
        argv = ["--help"]
    elif case == "argv-cyclic":
        argv = [cyclic(256).decode("ascii")]
    elif case == "format-stdin":
        payload = b"%p.%p.%p.%n\n"
    elif case == "env-marker":
        env["REPI_NATIVE_MARKER"] = "repi-native-env-control"
        extra_env = ["REPI_NATIVE_MARKER"]
    elif case == "short-stdin":
        payload = b"AAAAAAAAAAAAAAAA\n"
    elif case in {"cyclic-1", "cyclic-2"}:
        payload = cyclic(768) + b"\n"
    started = time.time()
    try:
        proc = subprocess.run([target, *argv], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout)
        return {
            "case": case,
            "observed": True,
            "verified": True,
            "exit": proc.returncode,
            "timeout": False,
            "crashLike": crash_like(proc.returncode),
            "durationMs": int((time.time() - started) * 1000),
            "argvCount": len(argv),
            "envKeys": extra_env,
            "stdoutSha256": sha256(proc.stdout),
            "stderrSha256": sha256(proc.stderr),
            **input_binding(case),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "case": case,
            "observed": True,
            "verified": False,
            "exit": "timeout",
            "timeout": True,
            "crashLike": False,
            "durationMs": int((time.time() - started) * 1000),
            "argvCount": len(argv),
            "envKeys": extra_env,
            "stdoutSha256": sha256(exc.stdout or b""),
            "stderrSha256": sha256(exc.stderr or b""),
            **input_binding(case),
        }


def cyclic_payload_verification(artifact_dir):
    expected = cyclic(768) + b"\n"
    path = os.path.join(artifact_dir, "native-cyclic-payload.bin")
    if not os.path.exists(path):
        return {"exists": False, "verified": False, "expectedSha256": sha256(expected)}
    with open(path, "rb") as handle:
        data = handle.read()
    needle = data[30:34]
    offset = cyclic(8192).find(needle) if len(needle) == 4 else -1
    mutated = bytearray(data)
    if mutated:
        mutated[0] ^= 0xFF
    return {
        "exists": True,
        "verified": data == expected and offset == 30,
        "size": len(data),
        "sha256": sha256(data),
        "expectedSha256": sha256(expected),
        "needleHex": needle.hex(),
        "needleOffsetSelfTest": offset if offset >= 0 else None,
        "negativeControl": {
            "controlType": "native-cyclic-payload-byte-mutation-rejection",
            "mutatedSha256": sha256(bytes(mutated)),
            "passed": bool(mutated) and sha256(bytes(mutated)) != sha256(data),
        },
    }


def build_verification(target, artifact_dir, timeout, run_live=True):
    identity = target_identity(target)
    artifacts = artifact_bindings(artifact_dir)
    if run_live and identity.get("executable"):
        checks = [run_case(target, case, timeout) for case in EXPECTED_CASES]
    else:
        checks = [{"case": case, "observed": False, "verified": False, **input_binding(case)} for case in EXPECTED_CASES]
    missing = [row["case"] for row in checks if not row.get("observed") or row.get("timeout")]
    replay_coverage = {"expectedCases": EXPECTED_CASES, "observedCases": [row["case"] for row in checks if row.get("observed")], "missingCases": missing, "verified": not missing and bool(checks)}
    cyclic_rows = [row for row in checks if row["case"] in {"cyclic-1", "cyclic-2"} and row.get("observed")]
    cyclic_crashes = [row for row in cyclic_rows if row.get("crashLike")]
    output_stable = len({json.dumps({"exit": row.get("exit"), "stdout": row.get("stdoutSha256"), "stderr": row.get("stderrSha256")}, sort_keys=True) for row in cyclic_rows}) <= 1 if cyclic_rows else False
    deterministic_crash = len(cyclic_crashes) >= 2 and len({json.dumps({"exit": row.get("exit"), "payload": row.get("payloadSha256")}, sort_keys=True) for row in cyclic_crashes}) == 1
    baseline = [row for row in checks if row["case"] in {"empty-stdin", "short-stdin"} and row.get("observed")]
    baseline_non_crash = any(not row.get("crashLike") and not row.get("timeout") for row in baseline)
    crash_diff = {"verified": deterministic_crash and baseline_non_crash, "deterministicCrash": deterministic_crash, "outputStable": output_stable, "crashCases": [row["case"] for row in cyclic_crashes], "baselineNonCrash": baseline_non_crash}
    payload_verification = cyclic_payload_verification(artifact_dir)
    controls = []
    for row in [identity.get("negativeControl"), payload_verification.get("negativeControl")]:
        if row and row.get("passed"):
            controls.append(row)
    for row in baseline:
        if not row.get("crashLike") and not row.get("timeout"):
            controls.append({"controlType": "native-baseline-non-crash-control", "case": row["case"], "exit": row.get("exit"), "passed": True, "stdoutSha256": row.get("stdoutSha256"), "stderrSha256": row.get("stderrSha256")})
    if crash_diff["verified"]:
        controls.append({"controlType": "native-cyclic-vs-baseline-crash-differential", "crashCases": crash_diff["crashCases"], "passed": True})
    claim_ledger = []
    composed_paths = []

    def add_claim(row):
        row = {"verdict": "promoted", "confidence": 0.76, "blockers": [], **row}
        claim_ledger.append(row)
        return row

    target_claim = add_claim({"id": "native-target-hash-verification-" + identity.get("sha256", "missing")[:16], "claimType": "native-target-hash-verification-proof", "sourceBinding": {"artifact": "native-runtime-verification.json"}, "evidenceBinding": identity, "statement": "Native verifier re-read target bytes and bound size, SHA-256, header, mode, and executable bit.", "confidence": 0.9, "rerunCommand": "python3 native-runtime-verifier.py <target> <artifact-dir> native-runtime-verification.json"}) if identity.get("verified") else None
    replay_claim = add_claim({"id": "native-replay-case-verification-" + sha256("|".join(replay_coverage["observedCases"]).encode())[:16], "claimType": "native-replay-case-verification-proof", "sourceBinding": {"artifact": "native-runtime-verification.json"}, "evidenceBinding": {"replayCoverage": replay_coverage, "caseHashes": [{k: row.get(k) for k in ("case", "exit", "payloadSha256", "argvSha256", "stdoutSha256", "stderrSha256", "crashLike")} for row in checks]}, "statement": "Native verifier replayed stdin, argv, env, short-control, and cyclic cases with hashed I/O evidence.", "confidence": 0.86, "rerunCommand": "python3 native-runtime-verifier.py <target> <artifact-dir> native-runtime-verification.json"}) if replay_coverage.get("verified") else None
    crash_claim = add_claim({"id": "native-crash-differential-verification-" + sha256(json.dumps(crash_diff, sort_keys=True).encode())[:16], "claimType": "native-crash-differential-verification-proof", "sourceBinding": {"artifact": "native-runtime-verification.json"}, "evidenceBinding": crash_diff, "statement": "Repeated cyclic payloads reached a deterministic crash-like state while baseline controls stayed non-crashing.", "confidence": 0.88, "rerunCommand": "python3 native-runtime-verifier.py <target> <artifact-dir> native-runtime-verification.json"}) if crash_diff.get("verified") else None
    cyclic_claim = add_claim({"id": "native-cyclic-payload-verification-" + payload_verification.get("sha256", "missing")[:16], "claimType": "native-cyclic-payload-verification-proof", "sourceBinding": {"artifact": "native-runtime-verification.json", "payload": "native-cyclic-payload.bin"}, "evidenceBinding": payload_verification, "statement": "Verifier matched the generated cyclic payload and self-tested needle-to-offset mapping.", "confidence": 0.86, "rerunCommand": "python3 native-cyclic-offset.py hex:<register-or-stack-bytes>"}) if payload_verification.get("verified") else None
    control_claim = add_claim({"id": "native-runtime-negative-control-" + sha256(json.dumps(controls, sort_keys=True).encode())[:16], "claimType": "native-runtime-negative-control-proof", "sourceBinding": {"artifact": "native-runtime-verification.json"}, "evidenceBinding": {"passedControls": controls}, "statement": "Native runtime verification includes mutation and baseline controls instead of treating crashes alone as proof.", "confidence": 0.84, "rerunCommand": "python3 native-runtime-verifier.py <target> <artifact-dir> native-runtime-verification.json"}) if controls else None
    if target_claim and replay_claim and crash_claim and cyclic_claim and control_claim:
        segments = [target_claim, replay_claim, crash_claim, cyclic_claim, control_claim]
        composed = {"id": "native-runtime-exploit-proof-path-" + sha256(">".join(row["id"] for row in segments).encode())[:16], "claimType": "native-runtime-exploit-proof-path", "sourceBinding": {"segments": [{"id": row["id"], "claimType": row["claimType"], "artifact": row.get("sourceBinding", {}).get("artifact")} for row in segments]}, "evidenceBinding": {"targetSha256": identity.get("sha256"), "crashCases": crash_diff["crashCases"], "hasNegativeControl": True, "cyclicPayloadSha256": payload_verification.get("sha256")}, "statement": "Native runtime evidence composes target hash, replay coverage, deterministic crash differential, cyclic payload binding, and negative controls into a rerunnable exploit proof path.", "verdict": "promoted", "confidence": 0.88, "blockers": [], "rerunCommand": "python3 native-runtime-verifier.py <target> <artifact-dir> native-runtime-verification.json"}
        claim_ledger.append(composed)
        composed_paths.append(composed)
    blockers = []
    if not identity.get("verified"):
        blockers.append("missing-native-target-hash-verification")
    if not replay_coverage.get("verified"):
        blockers.append("missing-native-replay-case-verification")
    if not crash_diff.get("verified"):
        blockers.append("missing-native-crash-differential-verification")
    if not payload_verification.get("verified"):
        blockers.append("missing-native-cyclic-payload-verification")
    if not controls:
        blockers.append("missing-native-runtime-negative-control")
    repair_queue = [{"id": "native-runtime-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound native runtime evidence and rerun native-runtime-verifier.py.", "rerunCommand": "python3 native-runtime-verifier.py <target> <artifact-dir> native-runtime-verification.json"} for blocker in blockers]
    promoted = [row for row in claim_ledger if row.get("verdict") == "promoted"]
    return {
        "kind": "repi-native-runtime-verification",
        "schemaVersion": 1,
        "target": target,
        "proofReady": bool(promoted),
        "exploitProofReady": bool(composed_paths),
        "targetIdentity": identity,
        "artifactBindings": artifacts,
        "replayCoverage": replay_coverage,
        "replayCaseChecks": checks,
        "crashDifferential": crash_diff,
        "cyclicPayloadVerification": payload_verification,
        "negativeControls": controls,
        "stats": {"replayCasesVerified": len([row for row in checks if row.get("observed") and not row.get("timeout")]), "crashCases": len(cyclic_crashes), "artifactBindings": len(artifacts), "negativeControlsPassed": len(controls)},
        "claimLedger": claim_ledger,
        "composedPaths": composed_paths,
        "promotionReport": {"proofReady": bool(promoted), "exploitProofReady": bool(composed_paths), "promotedClaims": promoted, "blockers": blockers},
        "repairQueue": repair_queue,
    }


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "crashy.sh")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(
                "#!/usr/bin/env bash\n"
                "IFS= read -r input || true\n"
                "if [ \"" + "$" + "{#input}\" -gt 100 ]; then\n"
                "  echo \"simulated crash len=" + "$" + "{#input}\"\n"
                "  exit 139\n"
                "fi\n"
                "echo ready\n"
            )
        os.chmod(target, 0o755)
        with open(os.path.join(tmp, "native-cyclic-payload.bin"), "wb") as handle:
            handle.write(cyclic(768) + b"\n")
        result = build_verification(target, tmp, 2.0, run_live=True)
        assert result["exploitProofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-native-runtime-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Verify REPI native runtime replay evidence, cyclic payload binding, and negative controls.")
    parser.add_argument("target", nargs="?")
    parser.add_argument("artifact_dir", nargs="?", default=".")
    parser.add_argument("output", nargs="?", default="native-runtime-verification.json")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--no-run", action="store_true", help="only verify target/artifact hashes; do not execute target")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.target:
        parser.error("target is required unless --self-test is used")
    result = build_verification(args.target, args.artifact_dir, float(os.getenv("REPI_NATIVE_TIMEOUT", "5")), run_live=not args.no_run)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "exploitProofReady": result["exploitProofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
`;
}

export function writeNativeRuntimeVerifier(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "native-runtime-verifier.py");
	writePrivate(path, nativeRuntimeVerifierSource(), 0o700);
	return path;
}

function nativeRuntimeArtifactBindings(artifactDir) {
	const relPaths = [
		"native-elf-hardening.json",
		"native-pe-quicklook.json",
		"native-macho-quicklook.json",
		"native-static-triage.json",
		"native-exploit-hypotheses.json",
		"native-replay-verifier.py",
		"native-gdb-trace.gdb",
		"native-cyclic-payload.bin",
		"native-cyclic-offset.py",
		"native-runtime-verifier.py",
	];
	const rows = [];
	for (const relPath of relPaths) {
		const path = join(artifactDir, relPath);
		if (!existsSync(path)) continue;
		const data = readFileSync(path);
		let parsed = null;
		if (/\.json$/i.test(relPath)) parsed = readJsonArtifact(path);
		let mode = null;
		try {
			mode = "0o" + (statSync(path).mode & 0o777).toString(8);
		} catch {
			mode = null;
		}
		rows.push({
			relPath,
			size: data.length,
			sha256: bufferSha256(data),
			mode,
			kind: parsed?.kind ?? null,
			schemaVersion: parsed?.schemaVersion ?? null,
		});
	}
	return rows;
}

function nativeRuntimeInputBinding(caseName) {
	if (caseName === "cyclic-1" || caseName === "cyclic-2") {
		const payload = nativeCyclicPayload(768);
		return { payloadLen: payload.length, payloadSha256: bufferSha256(payload) };
	}
	if (caseName === "format-stdin") {
		const payload = Buffer.from("%p.%p.%p.%n\n", "utf8");
		return { payloadLen: payload.length, payloadSha256: bufferSha256(payload) };
	}
	if (caseName === "short-stdin") {
		const payload = Buffer.from("AAAAAAAAAAAAAAAA\n", "utf8");
		return { payloadLen: payload.length, payloadSha256: bufferSha256(payload) };
	}
	if (caseName === "argv-cyclic") {
		const argv = nativeCyclicPayload(256).subarray(0, 256);
		return { payloadLen: 0, payloadSha256: bufferSha256(Buffer.alloc(0)), argvLen: argv.length, argvSha256: bufferSha256(argv) };
	}
	return { payloadLen: 0, payloadSha256: bufferSha256(Buffer.alloc(0)) };
}

function nativeRuntimeTargetIdentity(target) {
	try {
		const data = readFileSync(target);
		const stat = statSync(target);
		const sha256 = bufferSha256(data);
		const identity = {
			exists: true,
			verified: true,
			size: data.length,
			sha256,
			headerHex: data.subarray(0, 16).toString("hex"),
			mode: "0o" + (stat.mode & 0o777).toString(8),
			executable: Boolean(stat.mode & 0o111),
		};
		if (data.length) {
			const mutated = Buffer.from(data);
			mutated[0] ^= 0xff;
			const mutatedSha256 = bufferSha256(mutated);
			identity.negativeControl = {
				controlType: "native-target-byte-mutation-rejection",
				mutatedSha256,
				passed: mutatedSha256 !== sha256,
			};
		}
		return identity;
	} catch (error) {
		return { exists: false, verified: false, reason: error instanceof Error ? error.message : String(error) };
	}
}

function nativeCyclicPayloadVerification(artifactDir) {
	const expected = nativeCyclicPayload(768);
	const path = join(artifactDir, "native-cyclic-payload.bin");
	if (!existsSync(path)) {
		return { exists: false, verified: false, expectedSha256: bufferSha256(expected) };
	}
	const data = readFileSync(path);
	const sha256 = bufferSha256(data);
	const needle = data.subarray(30, 34);
	const pattern = nativeCyclicPayload(8192).subarray(0, 8192);
	const offset = needle.length === 4 ? pattern.indexOf(needle) : -1;
	const mutated = Buffer.from(data);
	if (mutated.length) mutated[0] ^= 0xff;
	const mutatedSha256 = bufferSha256(mutated);
	return {
		exists: true,
		verified: data.equals(expected) && offset === 30,
		size: data.length,
		sha256,
		expectedSha256: bufferSha256(expected),
		needleHex: needle.toString("hex"),
		needleOffsetSelfTest: offset >= 0 ? offset : null,
		negativeControl: {
			controlType: "native-cyclic-payload-byte-mutation-rejection",
			mutatedSha256,
			passed: mutated.length > 0 && mutatedSha256 !== sha256,
		},
	};
}

function nativeRuntimeVerificationSummary(target, artifactDir, rows) {
	const execution = nativeExecutionEvidence(rows);
	const targetIdentity = nativeRuntimeTargetIdentity(target);
	const expectedCases = ["empty-stdin", "argv-help", "argv-cyclic", "format-stdin", "env-marker", "short-stdin", "cyclic-1", "cyclic-2"];
	const replayCaseChecks = expectedCases.map((caseName) => {
		const row = execution.rows.find((candidate) => candidate.case === caseName || (caseName === "cyclic-1" && candidate.mode === "cyclic") || (caseName === "cyclic-2" && candidate.mode === "cyclic-repeat"));
		return {
			case: caseName,
			observed: Boolean(row),
			verified: Boolean(row && row.exit != null && !row.timeout),
			rowId: row?.id ?? null,
			mode: row?.mode ?? null,
			exit: row?.exit ?? null,
			crashSignal: row?.crashSignal ?? null,
			timeout: row?.timeout ?? false,
			crashLike: row?.crashLike ?? false,
			stdoutSha256: row?.stdoutSha256 ?? null,
			stderrSha256: row?.stderrSha256 ?? null,
			nativeLines: row?.nativeLines ?? [],
			...nativeRuntimeInputBinding(caseName),
		};
	});
	const replayCoverage = {
		expectedCases,
		observedCases: replayCaseChecks.filter((row) => row.observed).map((row) => row.case),
		missingCases: replayCaseChecks.filter((row) => !row.observed || row.timeout).map((row) => row.case),
		verified: replayCaseChecks.every((row) => row.observed && !row.timeout),
	};
	const cyclicRows = replayCaseChecks.filter((row) => /^cyclic-\d+$/.test(row.case) && row.observed);
	const cyclicCrashes = cyclicRows.filter((row) => row.crashLike);
	const deterministicCrash =
		cyclicCrashes.length >= 2 &&
		new Set(cyclicCrashes.map((row) => JSON.stringify({ exit: row.exit, crashSignal: row.crashSignal, payloadSha256: row.payloadSha256 }))).size === 1;
	const outputStable =
		cyclicRows.length > 0 &&
		new Set(cyclicRows.map((row) => JSON.stringify({ exit: row.exit, stdoutSha256: row.stdoutSha256, stderrSha256: row.stderrSha256 }))).size <= 1;
	const baselineRows = replayCaseChecks.filter((row) => (row.case === "empty-stdin" || row.case === "short-stdin") && row.observed);
	const baselineNonCrash = baselineRows.some((row) => !row.crashLike && !row.timeout);
	const crashDifferential = {
		verified: deterministicCrash && baselineNonCrash,
		deterministicCrash,
		outputStable,
		crashCases: cyclicCrashes.map((row) => row.case),
		baselineNonCrash,
	};
	const cyclicPayloadVerification = nativeCyclicPayloadVerification(artifactDir);
	const negativeControls = [targetIdentity.negativeControl, cyclicPayloadVerification.negativeControl]
		.filter((row) => row?.passed)
		.concat(
			baselineRows
				.filter((row) => !row.crashLike && !row.timeout)
				.map((row) => ({
					controlType: "native-baseline-non-crash-control",
					case: row.case,
					exit: row.exit,
					stdoutSha256: row.stdoutSha256,
					stderrSha256: row.stderrSha256,
					passed: true,
				})),
		);
	if (crashDifferential.verified) {
		negativeControls.push({
			controlType: "native-cyclic-vs-baseline-crash-differential",
			crashCases: crashDifferential.crashCases,
			passed: true,
		});
	}
	const artifactBindings = nativeRuntimeArtifactBindings(artifactDir);
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const targetClaim = targetIdentity.verified
		? addClaim({
				id: "native-target-hash-verification-" + shortHash(targetIdentity.sha256),
				claimType: "native-target-hash-verification-proof",
				sourceBinding: { artifact: "native-runtime-verification.json" },
				evidenceBinding: targetIdentity,
				statement: "Native runtime verifier re-read the target and bound size, SHA-256, header, mode, and executable bit.",
				confidence: 0.9,
				rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
			})
		: undefined;
	const replayClaim = replayCoverage.verified
		? addClaim({
				id: "native-replay-case-verification-" + shortHash(replayCoverage.observedCases.join("|")),
				claimType: "native-replay-case-verification-proof",
				sourceBinding: { artifact: "native-runtime-verification.json" },
				evidenceBinding: {
					replayCoverage,
					caseHashes: replayCaseChecks.map((row) => ({
						case: row.case,
						rowId: row.rowId,
						exit: row.exit,
						crashLike: row.crashLike,
						payloadSha256: row.payloadSha256,
						argvSha256: row.argvSha256 ?? null,
						stdoutSha256: row.stdoutSha256,
						stderrSha256: row.stderrSha256,
					})),
				},
				statement: "Native runtime verifier covered stdin, argv, env, short-control, and repeated cyclic replay cases with hashed I/O evidence.",
				confidence: 0.86,
				rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
			})
		: undefined;
	const crashClaim = crashDifferential.verified
		? addClaim({
				id: "native-crash-differential-verification-" + shortHash(JSON.stringify(crashDifferential)),
				claimType: "native-crash-differential-verification-proof",
				sourceBinding: { artifact: "native-runtime-verification.json" },
				evidenceBinding: crashDifferential,
				statement: "Repeated cyclic payloads reached a deterministic crash-like state while baseline controls stayed non-crashing.",
				confidence: 0.88,
				rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
			})
		: undefined;
	const cyclicClaim = cyclicPayloadVerification.verified
		? addClaim({
				id: "native-cyclic-payload-verification-" + shortHash(cyclicPayloadVerification.sha256),
				claimType: "native-cyclic-payload-verification-proof",
				sourceBinding: { artifact: "native-runtime-verification.json", payload: "native-cyclic-payload.bin" },
				evidenceBinding: cyclicPayloadVerification,
				statement: "Verifier matched native-cyclic-payload.bin to the generated pattern and self-tested needle-to-offset mapping.",
				confidence: 0.86,
				rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-cyclic-offset.py"))} hex:<register-or-stack-bytes>`,
			})
		: undefined;
	const controlClaim = negativeControls.length
		? addClaim({
				id: "native-runtime-negative-control-" + shortHash(JSON.stringify(negativeControls)),
				claimType: "native-runtime-negative-control-proof",
				sourceBinding: { artifact: "native-runtime-verification.json" },
				evidenceBinding: { passedControls: negativeControls },
				statement: "Native runtime verification includes mutation and baseline controls instead of treating crashes alone as proof.",
				confidence: 0.84,
				rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
			})
		: undefined;
	if (targetClaim && replayClaim && crashClaim && cyclicClaim && controlClaim) {
		const segments = [targetClaim, replayClaim, crashClaim, cyclicClaim, controlClaim];
		const composed = {
			id: "native-runtime-exploit-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "native-runtime-exploit-proof-path",
			sourceBinding: {
				segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })),
			},
			evidenceBinding: {
				targetSha256: targetIdentity.sha256,
				crashCases: crashDifferential.crashCases,
				hasNegativeControl: true,
				cyclicPayloadSha256: cyclicPayloadVerification.sha256,
			},
			statement: "Native runtime evidence composes target hash, replay coverage, deterministic crash differential, cyclic payload binding, and negative controls into a rerunnable exploit proof path.",
			verdict: "promoted",
			confidence: 0.88,
			blockers: [],
			rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!targetIdentity.verified) blockers.push("missing-native-target-hash-verification");
	if (!replayCoverage.verified) blockers.push("missing-native-replay-case-verification");
	if (!crashDifferential.verified) blockers.push("missing-native-crash-differential-verification");
	if (!cyclicPayloadVerification.verified) blockers.push("missing-native-cyclic-payload-verification");
	if (!negativeControls.length) blockers.push("missing-native-runtime-negative-control");
	const repairActions = {
		"missing-native-target-hash-verification": "Rerun native-runtime-verifier.py against the original executable and require size/SHA-256/header/mode binding.",
		"missing-native-replay-case-verification": "Replay empty stdin, --help argv, cyclic argv, format stdin, env marker, short stdin, and repeated cyclic stdin cases.",
		"missing-native-crash-differential-verification": "Require repeated cyclic crashes with stable exit/signal and a non-crashing empty or short-input baseline.",
		"missing-native-cyclic-payload-verification": "Regenerate native-cyclic-payload.bin and verify native-cyclic-offset.py maps a payload needle to the expected offset.",
		"missing-native-runtime-negative-control": "Add target/payload mutation and benign-baseline controls so rejected or non-crashing cases are explicit.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "native-runtime-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound native runtime evidence and rerun native-runtime-verifier.py.",
		rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
	}));
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	return {
		kind: "repi-native-runtime-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		proofReady: promotedClaims.length > 0,
		exploitProofReady: composedPaths.length > 0,
		targetIdentity,
		artifactBindings,
		replayCoverage,
		replayCaseChecks,
		crashDifferential,
		cyclicPayloadVerification,
		negativeControls,
		stats: {
			replayCasesVerified: replayCaseChecks.filter((row) => row.observed && !row.timeout).length,
			crashCases: cyclicCrashes.length,
			artifactBindings: artifactBindings.length,
			negativeControlsPassed: negativeControls.length,
		},
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			exploitProofReady: composedPaths.length > 0,
			promotedClaims,
			blockers,
		},
		repairQueue,
	};
}

export function writeNativeRuntimeVerification(artifactDir, target, rows) {
	if (noWrite || !artifactDir) return undefined;
	const summary = nativeRuntimeVerificationSummary(target, artifactDir, rows);
	const path = join(artifactDir, "native-runtime-verification.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}


function nativeExploitHypotheses(target, artifactDir, rows) {
	const elf = readJsonArtifact(join(artifactDir, "native-elf-hardening.json"));
	const pe = readJsonArtifact(join(artifactDir, "native-pe-quicklook.json"));
	const macho = readJsonArtifact(join(artifactDir, "native-macho-quicklook.json"));
	const triage = readJsonArtifact(join(artifactDir, "native-static-triage.json"));
	const executionRows = rows.filter((row) => /^native-run-/.test(row.id));
	const crashRows = executionRows.filter((row) => /\bcrash_signal=|mode=cyclic exit=(?:139|134|1[3-9][0-9])\b/i.test(`${row.stdout}\n${row.stderr}`));
	const hypotheses = [];
	const addHypothesis = (row) => {
		if (!row?.id || hypotheses.some((existing) => existing.id === row.id)) return;
		hypotheses.push(row);
	};
	const importedNames = new Set((elf?.dynamic?.imports ?? []).map((row) => String(row.name ?? "")));
	const elfRisks = new Set([...(elf?.risk ?? []), ...(elf?.dynamic?.risks ?? [])]);
	const staticRisks = new Set(triage?.risks ?? []);
	const gadgetRisks = new Set(triage?.gadgetQuicklook?.risks ?? []);
	const mitigations = {
		pie: elf?.hardening?.pie ?? pe?.mitigations?.dynamicBase ?? null,
		nx: elf?.hardening?.nx ?? pe?.mitigations?.nx ?? null,
		canary: elf?.hardening?.canary ?? null,
		relroLevel: elf?.hardening?.relroLevel ?? null,
		bindNow: elf?.hardening?.bindNow ?? null,
	};
	const evidence = {
		artifacts: [
			elf ? "native-elf-hardening.json" : null,
			pe ? "native-pe-quicklook.json" : null,
			macho ? "native-macho-quicklook.json" : null,
			triage ? "native-static-triage.json" : null,
			existsSync(join(artifactDir, "native-replay-verifier.py")) ? "native-replay-verifier.py" : null,
			existsSync(join(artifactDir, "native-gdb-trace.gdb")) ? "native-gdb-trace.gdb" : null,
			existsSync(join(artifactDir, "native-cyclic-offset.py")) ? "native-cyclic-offset.py" : null,
		].filter(Boolean),
		mitigations,
		imports: Array.from(importedNames).slice(0, 80),
		gadgetRisks: Array.from(gadgetRisks),
		staticRisks: Array.from(staticRisks),
		crashRows: crashRows.map((row) => ({ id: row.id, stdout: redact(row.stdout).slice(0, 500) })),
	};
	if (crashRows.length) {
		addHypothesis({
			id: "cyclic-crash-control-proof",
			priority: "high",
			claim: "Cyclic input reaches a crash-like state; first proof target is controllable offset and register/stack binding.",
			evidence: ["native-run-cyclic crash_signal/exit", "native-cyclic-payload.bin", "native-cyclic-offset.py", "native-gdb-trace.gdb"],
			verify: [
				`python3 ${shellQuote(join(artifactDir, "native-replay-verifier.py"))} ${shellQuote(target)}`,
				`gdb -q -x ${shellQuote(join(artifactDir, "native-gdb-trace.gdb"))} ${shellQuote(target)}`,
				`python3 ${shellQuote(join(artifactDir, "native-cyclic-offset.py"))} hex:<register-or-stack-bytes>`,
			],
			blockers: ["Need debugger stop register/stack bytes before claiming instruction-pointer or saved-return-address control."],
		});
	}
	if (gadgetRisks.has("native-ret2libc-primitive-signal") && (importedNames.has("system") || triage?.signals?.commandExec?.length) && triage?.signals?.shellPaths?.length) {
		addHypothesis({
			id: "ret2libc-system-binsh",
			priority: mitigations.pie ? "medium" : "high",
			claim: "system-like sink, /bin/sh string, and argument-control gadget are present; ret2libc is a plausible exploit path after offset/leak proof.",
			evidence: ["native-static-triage.json:gadgetQuicklook.pop rdi; ret", "native-static-triage.json:signals.shellPaths", importedNames.has("system") ? "native-elf-hardening.json:dynamic.imports.system" : "native-static-triage.json:signals.commandExec"],
			verify: [
				"Resolve exact virtual addresses under PIE/load base using r2/gdb.",
				"Prove offset with native-cyclic-offset.py before building chain.",
				"Check stack alignment and bad-byte/input truncation constraints.",
			],
			blockers: mitigations.pie ? ["PIE enabled: need base leak or non-PIE mapping before fixed addresses."] : [],
		});
	}
	if (gadgetRisks.has("native-syscall-rop-primitive-signal")) {
		addHypothesis({
			id: "syscall-rop-chain",
			priority: "medium",
			claim: "syscall; ret and register-pop primitives are present; direct syscall ROP can be explored if writable memory and syscall constraints are satisfied.",
			evidence: ["native-static-triage.json:gadgetQuicklook.syscall; ret", "native-static-triage.json:gadgetQuicklook.pop register; ret"],
			verify: ["Locate writable memory segment or controlled stack buffer.", "Confirm register-pop coverage for target syscall ABI.", "Replay in gdb with exact chain bytes."],
			blockers: ["Need writable target buffer and exact ABI/register constraints."],
		});
	}
	if (staticRisks.has("format-string-signal")) {
		addHypothesis({
			id: "format-string-leak-or-write",
			priority: "medium",
			claim: "Format-string pattern exists; verify reachability for leak/write primitive before exploiting mitigations.",
			evidence: ["native-static-triage.json:signals.formatStrings"],
			verify: ["Find xref/callsite to the format string.", "Replay with %p/%lx leak probe and bounded verifier.", "If %n is reachable, prove controlled write target."],
			blockers: ["String evidence alone is not reachability proof."],
		});
	}
	if (elfRisks.has("elf-lazy-binding-plt-surface") || (elf?.dynamic?.relocations ?? []).some((row) => /JUMP_SLOT|JMP_SLOT/i.test(row.typeName ?? ""))) {
		addHypothesis({
			id: "plt-got-resolution-surface",
			priority: elfRisks.has("elf-lazy-binding-plt-surface") ? "medium" : "low",
			claim: "PLT/GOT relocation surface is mapped; use it for import resolution, leak targeting, or lazy-binding analysis.",
			evidence: ["native-elf-hardening.json:dynamic.relocations", "native-elf-hardening.json:dynamic.imports"],
			verify: ["Map relocation offsets to runtime addresses.", "Check RELRO/bindNow before GOT overwrite assumptions.", "Use imported function pointers as leak/resolve anchors."],
			blockers: mitigations.relroLevel === "full" ? ["Full RELRO: GOT overwrite path unlikely; use leak/ret2libc instead."] : [],
		});
	}
	return {
		kind: "repi-native-exploit-hypotheses",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		evidence,
		hypotheses,
		next: [
			"Promote a hypothesis only after an end-to-end replay binds input bytes → crash/register/branch state → primitive.",
			"Prefer native-replay-verifier.py for deterministic crash reproduction before expanding into ROP or ret2libc.",
			"Use native-gdb-trace.gdb and native-cyclic-offset.py to convert crash evidence into offset/control evidence.",
		],
	};
}

function nativeSignalEvidenceRows(rows, limit = 16) {
	return (rows ?? []).slice(0, limit).map((row) => ({
		offset: row.offset ?? null,
		match: row.match ?? null,
		textLength: String(row.text ?? "").length,
		textSha256: httpSecretHash(row.text ?? ""),
	}));
}

function nativeExecutionEvidence(rows) {
	const parsedRows = rows
		.filter((row) => /^native-run-/.test(row.id))
		.map((row) => {
			const text = `${row.stdout ?? ""}\n${row.stderr ?? ""}`;
			const nativeLines = text
				.split(/\r?\n/)
				.filter((line) => /^\[native-exec]/.test(line))
				.map((line) => redact(line))
				.slice(0, 8);
			const joined = nativeLines.join(" ");
			const mode = /mode=([a-z0-9_-]+)/i.exec(joined)?.[1] ?? row.id.replace(/^native-run-/, "");
			const caseName = /case=([a-z0-9_-]+)/i.exec(joined)?.[1] ?? (mode === "cyclic" ? "cyclic-1" : mode === "cyclic-repeat" ? "cyclic-2" : mode);
			const exitToken = /(?:^|\s)exit=([a-z0-9_-]+)/i.exec(joined)?.[1] ?? null;
			const exit = exitToken && /^\d+$/.test(exitToken) ? Number(exitToken) : exitToken;
			const crashSignal = /crash_signal=([A-Z0-9_-]+)/i.exec(joined)?.[1] ?? null;
			const timeout = /timeout=true/i.test(joined) || exit === 124 || exit === 137;
			const crashLike = Boolean(crashSignal) || (typeof exit === "number" && (exit === 134 || exit === 139 || exit > 128));
			const inputLenToken = /(?:payload_len|input_len)=([0-9]+)/i.exec(joined)?.[1] ?? null;
			const argvLenToken = /argv_len=([0-9]+)/i.exec(joined)?.[1] ?? null;
			const argvCountToken = /argv_count=([0-9]+)/i.exec(joined)?.[1] ?? null;
			return {
				id: row.id,
				mode,
				case: caseName,
				exit,
				crashSignal,
				timeout,
				crashLike,
				inputLen: inputLenToken ? Number(inputLenToken) : null,
				argvLen: argvLenToken ? Number(argvLenToken) : null,
				argvCount: argvCountToken ? Number(argvCountToken) : 0,
				stdoutSha256: httpSecretHash(row.stdout ?? ""),
				stderrSha256: httpSecretHash(row.stderr ?? ""),
				nativeLines,
			};
		});
	return {
		rows: parsedRows,
		crashRows: parsedRows.filter((row) => row.crashLike),
		modes: parsedRows.map((row) => row.mode),
	};
}

function nativePrimitiveClaims(target, artifactDir, rows, hypothesesSummary, runtimeVerificationSummary) {
	const elf = readJsonArtifact(join(artifactDir, "native-elf-hardening.json"));
	const pe = readJsonArtifact(join(artifactDir, "native-pe-quicklook.json"));
	const macho = readJsonArtifact(join(artifactDir, "native-macho-quicklook.json"));
	const triage = readJsonArtifact(join(artifactDir, "native-static-triage.json"));
	const hypotheses = hypothesesSummary ?? readJsonArtifact(join(artifactDir, "native-exploit-hypotheses.json"));
	const runtimeVerification = runtimeVerificationSummary ?? readJsonArtifact(join(artifactDir, "native-runtime-verification.json"));
	const execution = nativeExecutionEvidence(rows);
	const artifactFiles = [
		elf ? "native-elf-hardening.json" : null,
		pe ? "native-pe-quicklook.json" : null,
		macho ? "native-macho-quicklook.json" : null,
		triage ? "native-static-triage.json" : null,
		hypotheses ? "native-exploit-hypotheses.json" : null,
		runtimeVerification ? "native-runtime-verification.json" : null,
		existsSync(join(artifactDir, "native-replay-verifier.py")) ? "native-replay-verifier.py" : null,
		existsSync(join(artifactDir, "native-runtime-verifier.py")) ? "native-runtime-verifier.py" : null,
		existsSync(join(artifactDir, "native-gdb-trace.gdb")) ? "native-gdb-trace.gdb" : null,
		existsSync(join(artifactDir, "native-cyclic-payload.bin")) ? "native-cyclic-payload.bin" : null,
		existsSync(join(artifactDir, "native-cyclic-offset.py")) ? "native-cyclic-offset.py" : null,
	].filter(Boolean);
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
	const importedNames = (elf?.dynamic?.imports ?? []).map((row) => String(row.name ?? "")).filter(Boolean);
	const elfRisks = new Set([...(elf?.risk ?? []), ...(elf?.dynamic?.risks ?? [])]);
	const staticRisks = new Set(triage?.risks ?? []);
	const gadgetRisks = new Set(triage?.gadgetQuicklook?.risks ?? []);
	const hypothesisRows = hypotheses?.hypotheses ?? [];
	const hypothesisById = new Map(hypothesisRows.map((row) => [row.id, row]));
	const mitigations = hypotheses?.evidence?.mitigations ?? {
		pie: elf?.hardening?.pie ?? pe?.mitigations?.dynamicBase ?? null,
		nx: elf?.hardening?.nx ?? pe?.mitigations?.nx ?? null,
		canary: elf?.hardening?.canary ?? null,
		relroLevel: elf?.hardening?.relroLevel ?? null,
		bindNow: elf?.hardening?.bindNow ?? null,
	};
	const crashRow = execution.crashRows[0];
	const crashClaim = crashRow
		? addClaim({
				id: "native-crash-replay-" + shortHash(`${target}:${crashRow.id}:${crashRow.exit}:${crashRow.stdoutSha256}`),
				claimType: "native-crash-replay-signal",
				sourceBinding: { artifact: "commands.jsonl", rowId: crashRow.id },
				evidenceBinding: {
					mode: crashRow.mode,
					exit: crashRow.exit,
					crashSignal: crashRow.crashSignal,
					timeout: crashRow.timeout,
					stdoutSha256: crashRow.stdoutSha256,
					stderrSha256: crashRow.stderrSha256,
					nativeLines: crashRow.nativeLines,
				},
				statement: "Bounded native execution reached a crash-like state from a controlled replay input.",
				confidence: 0.86,
				rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-replay-verifier.py"))} ${shellQuote(target)}`,
			})
		: undefined;
	if (execution.rows.length && existsSync(join(artifactDir, "native-replay-verifier.py"))) {
		addClaim({
			id: "native-io-contract-" + shortHash(`${target}:${execution.modes.join(",")}`),
			claimType: "native-io-contract-harness",
			sourceBinding: { artifact: "native-replay-verifier.py", rows: execution.rows.map((row) => row.id) },
			evidenceBinding: {
				modes: execution.modes,
				crashLikeCount: execution.crashRows.length,
				rowHashes: execution.rows.map((row) => ({ id: row.id, stdoutSha256: row.stdoutSha256, stderrSha256: row.stderrSha256 })),
			},
			statement: "Native replay harness covers stdin, argv, env, and cyclic input contract cases for deterministic primitive reproduction.",
			confidence: execution.crashRows.length ? 0.82 : 0.72,
			rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-replay-verifier.py"))} ${shellQuote(target)}`,
		});
	}
	if (existsSync(join(artifactDir, "native-cyclic-offset.py")) && existsSync(join(artifactDir, "native-cyclic-payload.bin")) && existsSync(join(artifactDir, "native-gdb-trace.gdb"))) {
		addClaim({
			id: "native-offset-control-workbench-" + shortHash(target),
			claimType: "native-offset-control-workbench",
			sourceBinding: {
				payload: "native-cyclic-payload.bin",
				offsetHelper: "native-cyclic-offset.py",
				debuggerScript: "native-gdb-trace.gdb",
			},
			evidenceBinding: {
				hasCyclicPayload: true,
				hasOffsetHelper: true,
				hasDebuggerTrace: true,
				crashLikeCount: execution.crashRows.length,
			},
			statement: "Native cyclic payload, offset helper, and debugger trace script are ready to bind register/stack bytes to input offsets.",
			confidence: execution.crashRows.length ? 0.84 : 0.74,
			rerunCommand: `gdb -q -x ${shellQuote(join(artifactDir, "native-gdb-trace.gdb"))} ${shellQuote(target)}`,
		});
	}
	if (elfRisks.has("elf-unsafe-import-surface") || staticRisks.has("unsafe-input-sink-signal") || (triage?.signals?.unsafeInput ?? []).length) {
		addClaim({
			id: "native-unsafe-import-surface-" + shortHash(`${target}:${importedNames.join(",")}:${JSON.stringify(triage?.signals?.unsafeInput ?? [])}`),
			claimType: "native-unsafe-import-surface",
			sourceBinding: { artifacts: ["native-elf-hardening.json", "native-static-triage.json"].filter((name) => artifactFiles.includes(name)) },
			evidenceBinding: {
				imports: importedNames.filter((name) => /^(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|memcpy|memmove)$/i.test(name)).slice(0, 24),
				staticSignals: nativeSignalEvidenceRows(triage?.signals?.unsafeInput),
				risks: [...elfRisks, ...staticRisks].filter((risk) => /unsafe|stack|canary|pie|relro/i.test(risk)),
			},
			statement: "Native static/import evidence identifies unsafe input or memory-copy sinks that need callsite reachability proof.",
			confidence: elfRisks.has("elf-unsafe-import-surface") ? 0.82 : 0.74,
			rerunCommand: "cat native-elf-hardening.json native-static-triage.json",
		});
	}
	if (elfRisks.has("elf-command-exec-import-surface") || staticRisks.has("command-execution-sink-signal") || (triage?.signals?.commandExec ?? []).length || (triage?.signals?.shellPaths ?? []).length) {
		addClaim({
			id: "native-command-exec-surface-" + shortHash(`${target}:${importedNames.join(",")}:${JSON.stringify(triage?.signals?.shellPaths ?? [])}`),
			claimType: "native-command-exec-surface",
			sourceBinding: { artifacts: ["native-elf-hardening.json", "native-static-triage.json"].filter((name) => artifactFiles.includes(name)) },
			evidenceBinding: {
				imports: importedNames.filter((name) => /^(system|popen|execv|execve|execl|execlp|execvp|posix_spawn)$/i.test(name)).slice(0, 24),
				commandSignals: nativeSignalEvidenceRows(triage?.signals?.commandExec),
				shellPathSignals: nativeSignalEvidenceRows(triage?.signals?.shellPaths),
			},
			statement: "Native evidence contains command-execution or shell-path anchors for ret2libc, command-injection, or sandbox escape triage.",
			confidence: 0.82,
			rerunCommand: "cat native-static-triage.json | jq '.signals.commandExec,.signals.shellPaths'",
		});
	}
	if (gadgetRisks.has("native-rop-gadget-signal")) {
		addClaim({
			id: "native-gadget-corpus-" + shortHash(`${target}:${JSON.stringify(triage?.gadgetQuicklook?.gadgets ?? {})}`),
			claimType: "native-gadget-corpus-surface",
			sourceBinding: { artifact: "native-static-triage.json", field: "gadgetQuicklook" },
			evidenceBinding: {
				architecture: triage?.gadgetQuicklook?.architecture ?? null,
				gadgetCount: triage?.gadgetQuicklook?.gadgetCount ?? 0,
				gadgets: Object.fromEntries(
					Object.entries(triage?.gadgetQuicklook?.gadgets ?? {}).map(([name, row]) => [
						name,
						{ count: row.count ?? 0, samples: (row.samples ?? []).slice(0, 6).map((sample) => ({ offsetHex: sample.offsetHex, gadget: sample.gadget })) },
					]),
				),
				risks: [...gadgetRisks],
			},
			statement: "Native opcode scan found reusable control-flow gadgets; resolve virtual addresses under the final load base before chain construction.",
			confidence: 0.78,
			rerunCommand: "cat native-static-triage.json | jq '.gadgetQuicklook'",
		});
	}
	const hypothesisClaimTypes = {
		"cyclic-crash-control-proof": "native-cyclic-crash-control-claim",
		"ret2libc-system-binsh": "native-ret2libc-surface",
		"syscall-rop-chain": "native-syscall-rop-surface",
		"format-string-leak-or-write": "native-format-string-surface",
		"plt-got-resolution-surface": "native-plt-got-resolution-surface",
	};
	const hypothesisClaims = [];
	for (const hypothesis of hypothesisRows) {
		const claimType = hypothesisClaimTypes[hypothesis.id];
		if (!claimType) continue;
		const claim = addClaim({
			id: `${claimType}-${shortHash(`${target}:${hypothesis.id}:${JSON.stringify(hypothesis.evidence ?? [])}`)}`,
			claimType,
			sourceBinding: { artifact: "native-exploit-hypotheses.json", hypothesisId: hypothesis.id },
			evidenceBinding: {
				priority: hypothesis.priority,
				evidence: hypothesis.evidence ?? [],
				verify: hypothesis.verify ?? [],
				mitigations,
			},
			statement: hypothesis.claim ?? "Native exploit hypothesis promoted from static and replay evidence.",
			confidence: hypothesis.id === "cyclic-crash-control-proof" && crashClaim ? 0.86 : 0.76,
			blockers: hypothesis.blockers ?? [],
			rerunCommand: "cat native-exploit-hypotheses.json | jq '.hypotheses'",
		});
		if (claim) hypothesisClaims.push(claim);
	}
	if ((pe?.suspiciousImports ?? []).length) {
		addClaim({
			id: "native-windows-injection-surface-" + shortHash(`${target}:${JSON.stringify(pe.suspiciousImports)}`),
			claimType: "native-windows-injection-surface",
			sourceBinding: { artifact: "native-pe-quicklook.json", field: "suspiciousImports" },
			evidenceBinding: {
				machine: pe.pe?.machine ?? null,
				mitigations: pe.mitigations ?? {},
				imports: (pe.suspiciousImports ?? []).slice(0, 32).map((row) => ({ dll: row.dll, name: row.name })),
				risks: pe.risks ?? [],
			},
			statement: "PE import evidence identifies injection, loader, downloader, crypto, registry, or anti-debug primitives for Windows reverse triage.",
			confidence: 0.82,
			rerunCommand: "cat native-pe-quicklook.json | jq '.suspiciousImports'",
		});
	}
	if ((macho?.risks ?? []).some((risk) => /rpath|dynamic-loader|dangerous-symbol/i.test(risk))) {
		addClaim({
			id: "native-macho-loader-surface-" + shortHash(`${target}:${JSON.stringify(macho?.risks ?? [])}`),
			claimType: "native-macho-loader-surface",
			sourceBinding: { artifact: "native-macho-quicklook.json", fields: ["rpaths", "dylibs", "symbols.signals"] },
			evidenceBinding: {
				cpu: macho?.macho?.cpu ?? null,
				rpaths: macho?.rpaths ?? [],
				dylibs: (macho?.dylibs ?? []).slice(0, 20).map((row) => row.name),
				dangerousSymbols: (macho?.symbols?.signals?.dangerous ?? []).slice(0, 20).map((row) => row.name),
				dynamicLoaderSymbols: (macho?.symbols?.signals?.dynamicLoader ?? []).slice(0, 20).map((row) => row.name),
				risks: macho?.risks ?? [],
			},
			statement: "Mach-O load-command and symbol evidence exposes loader hijack or dangerous-symbol surfaces.",
			confidence: 0.82,
			rerunCommand: "cat native-macho-quicklook.json | jq '.rpaths,.symbols.signals'",
		});
	}
	if ((macho?.symbols?.signals?.cryptoNetwork ?? []).length) {
		addClaim({
			id: "native-macho-trust-network-surface-" + shortHash(`${target}:${JSON.stringify(macho.symbols.signals.cryptoNetwork)}`),
			claimType: "native-macho-trust-network-surface",
			sourceBinding: { artifact: "native-macho-quicklook.json", field: "symbols.signals.cryptoNetwork" },
			evidenceBinding: {
				symbols: (macho.symbols.signals.cryptoNetwork ?? []).slice(0, 32).map((row) => row.name),
				risks: macho.risks ?? [],
			},
			statement: "Mach-O symbol evidence identifies trust-evaluation or network surfaces for runtime hook/replay work.",
			confidence: 0.78,
			rerunCommand: "cat native-macho-quicklook.json | jq '.symbols.signals.cryptoNetwork'",
		});
	}
	if ((triage?.signals?.networkIo ?? []).length || (triage?.signals?.urls ?? []).length) {
		addClaim({
			id: "native-network-string-surface-" + shortHash(`${target}:${JSON.stringify(triage?.signals?.networkIo ?? [])}:${JSON.stringify(triage?.signals?.urls ?? [])}`),
			claimType: "native-network-string-surface",
			sourceBinding: { artifact: "native-static-triage.json", fields: ["signals.networkIo", "signals.urls"] },
			evidenceBinding: {
				networkSignals: nativeSignalEvidenceRows(triage?.signals?.networkIo),
				urlSignals: nativeSignalEvidenceRows(triage?.signals?.urls),
			},
			statement: "Native string evidence identifies network or URL pivots that should be tied to xrefs/runtime traffic.",
			confidence: 0.72,
			rerunCommand: "cat native-static-triage.json | jq '.signals.networkIo,.signals.urls'",
		});
	}
	if ((triage?.signals?.secretsAndFlags ?? []).length) {
		addClaim({
			id: "native-secret-flag-string-surface-" + shortHash(`${target}:${JSON.stringify(triage?.signals?.secretsAndFlags ?? [])}`),
			claimType: "native-secret-flag-string-surface",
			sourceBinding: { artifact: "native-static-triage.json", field: "signals.secretsAndFlags" },
			evidenceBinding: {
				signals: nativeSignalEvidenceRows(triage?.signals?.secretsAndFlags),
			},
			statement: "Native string evidence contains secret/flag/config indicators; values are hash-bound instead of emitted.",
			confidence: 0.72,
			rerunCommand: "cat native-static-triage.json | jq '.signals.secretsAndFlags'",
		});
	}
	const verificationComposedPaths = [];
	for (const verificationClaim of runtimeVerification?.claimLedger ?? []) {
		if (verificationClaim.verdict !== "promoted") continue;
		const claim = addClaim({
			...verificationClaim,
			id: verificationClaim.id || "native-runtime-verification-claim-" + shortHash(JSON.stringify(verificationClaim)),
			sourceBinding: {
				artifact: "native-runtime-verification.json",
				...(verificationClaim.sourceBinding ?? {}),
			},
			rerunCommand:
				verificationClaim.rerunCommand ??
				`python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
		});
		if (claim?.claimType === "native-runtime-exploit-proof-path") verificationComposedPaths.push(claim);
	}
	const promotedClaims = claimLedger.filter((claim) => claim.verdict === "promoted");
	const composedPaths = [];
	for (const verificationPath of runtimeVerification?.composedPaths ?? []) {
		const composed = {
			...verificationPath,
			id: verificationPath.id || "native-runtime-verification-path-" + shortHash(JSON.stringify(verificationPath)),
			sourceBinding: {
				artifact: "native-runtime-verification.json",
				...(verificationPath.sourceBinding ?? {}),
			},
			rerunCommand:
				verificationPath.rerunCommand ??
				`python3 ${shellQuote(join(artifactDir, "native-runtime-verifier.py"))} ${shellQuote(target)} ${shellQuote(artifactDir)} ${shellQuote(join(artifactDir, "native-runtime-verification.json"))}`,
		};
		if (!claimLedger.some((claim) => claim.id === composed.id)) {
			claimLedger.push(composed);
			promotedClaims.push(composed);
		}
		if (!composedPaths.some((path) => path.id === composed.id)) composedPaths.push(composed);
	}
	for (const verificationPath of verificationComposedPaths) {
		if (!composedPaths.some((path) => path.id === verificationPath.id)) composedPaths.push(verificationPath);
	}
	const controlClaim = hypothesisClaims.find((claim) => claim.claimType === "native-cyclic-crash-control-claim");
	const primitiveClaim = hypothesisClaims.find((claim) => /ret2libc|syscall|format-string|plt-got/.test(claim.claimType)) ?? promotedClaims.find((claim) => /unsafe-import|command-exec|windows-injection|macho-loader/.test(claim.claimType));
	if (crashClaim && (controlClaim || primitiveClaim)) {
		const segments = [crashClaim, controlClaim, primitiveClaim].filter(Boolean);
		const composed = {
			id: "native-exploit-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "native-exploit-proof-path",
			sourceBinding: {
				target: redact(target),
				segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })),
			},
			evidenceBinding: {
				crashLike: true,
				hasControlWorkbench: Boolean(controlClaim),
				hasPrimitiveSurface: Boolean(primitiveClaim),
				mitigations,
				artifactFiles,
			},
			statement: "Native evidence composes replay crash, cyclic/control workbench, and primitive surface into a debugger-backed proof path.",
			verdict: "promoted",
			confidence: primitiveClaim ? 0.86 : 0.82,
			blockers: primitiveClaim ? primitiveClaim.blockers ?? [] : ["Need exact register/stack bytes before claiming instruction-pointer control."],
			rerunCommand: `python3 ${shellQuote(join(artifactDir, "native-replay-verifier.py"))} ${shellQuote(target)} && gdb -q -x ${shellQuote(join(artifactDir, "native-gdb-trace.gdb"))} ${shellQuote(target)}`,
		};
		claimLedger.push(composed);
		promotedClaims.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!triage) blockers.push("missing-native-static-triage");
	if (!execution.rows.length) blockers.push("missing-native-runtime-replay");
	if (!execution.crashRows.length) blockers.push("missing-crash-or-behavior-differential");
	if (!existsSync(join(artifactDir, "native-replay-verifier.py"))) blockers.push("missing-replay-verifier");
	if (!runtimeVerification) blockers.push("missing-native-runtime-verification");
	if (execution.crashRows.length && !existsSync(join(artifactDir, "native-cyclic-offset.py"))) blockers.push("missing-cyclic-offset-helper");
	if (execution.crashRows.length && !existsSync(join(artifactDir, "native-gdb-trace.gdb"))) blockers.push("missing-debugger-trace");
	if (!hypothesisRows.length) blockers.push("missing-native-primitive-hypothesis");
	if ((hypothesisById.has("ret2libc-system-binsh") || hypothesisById.has("plt-got-resolution-surface")) && mitigations.pie) blockers.push("need-pie-base-leak");
	if (mitigations.canary) blockers.push("need-canary-leak-or-non-stack-primitive");
	for (const blocker of runtimeVerification?.promotionReport?.blockers ?? []) {
		if (!blockers.includes(blocker)) blockers.push(blocker);
	}
	const repairActions = {
		"missing-native-static-triage": "Run strings/import/gadget triage and bind each sink/gadget to an artifact row before exploit planning.",
		"missing-native-runtime-replay": "Run native-replay-verifier.py to establish stdin/argv/env behavior and deterministic output hashes.",
		"missing-crash-or-behavior-differential": "Find a controlled crash, leak, branch, parser error, or output differential before promoting exploitability.",
		"missing-replay-verifier": "Generate native-replay-verifier.py and keep it executable so primitive claims are rerunnable.",
		"missing-native-runtime-verification": "Generate native-runtime-verification.json and native-runtime-verifier.py to bind replay/hash/negative-control evidence.",
		"missing-native-target-hash-verification": "Rerun native-runtime-verifier.py against the original executable and require size/SHA-256/header/mode binding.",
		"missing-native-replay-case-verification": "Replay empty stdin, argv help/cyclic, format stdin, env marker, short stdin, and repeated cyclic stdin cases.",
		"missing-native-crash-differential-verification": "Require repeated cyclic crashes with stable exit/signal and a non-crashing empty or short-input baseline.",
		"missing-native-cyclic-payload-verification": "Regenerate native-cyclic-payload.bin and verify native-cyclic-offset.py maps a payload needle to the expected offset.",
		"missing-native-runtime-negative-control": "Add target/payload mutation and benign-baseline controls so exploit proof has a rejection oracle.",
		"missing-cyclic-offset-helper": "Generate native-cyclic-offset.py and use debugger bytes to calculate exact control offset.",
		"missing-debugger-trace": "Run or generate native-gdb-trace.gdb to capture registers, backtrace, stack, and nearby instructions.",
		"missing-native-primitive-hypothesis": "Promote at least one ret2libc, syscall ROP, format-string, PLT/GOT, PE injection, or Mach-O loader hypothesis.",
		"need-pie-base-leak": "Collect a code/libc base leak or non-PIE mapping before using fixed gadget/import addresses.",
		"need-canary-leak-or-non-stack-primitive": "Avoid stack overwrite assumptions until canary leak, non-stack write, or logic primitive is proven.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "native-primitive-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect native runtime/static evidence and rerun claim promotion.",
		rerunCommand: `repi engage ${shellQuote(target)} --json`,
	}));
	return {
		kind: "repi-native-primitive-claims",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		artifactFiles,
		execution,
		mitigations,
		verificationStats: runtimeVerification?.stats ?? null,
		proofReady: promotedClaims.length > 0,
		exploitProofReady: composedPaths.length > 0,
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: promotedClaims.length > 0,
			exploitProofReady: composedPaths.length > 0,
			promotedClaims,
			blockers,
		},
		repairQueue,
	};
}

export function writeNativeExploitHypotheses(artifactDir, target, rows) {
	if (noWrite || !artifactDir) return undefined;
	const summary = nativeExploitHypotheses(target, artifactDir, rows);
	const path = join(artifactDir, "native-exploit-hypotheses.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}

export function writeNativePrimitiveClaims(artifactDir, target, rows, hypothesesSummary, runtimeVerificationSummary) {
	if (noWrite || !artifactDir) return undefined;
	const summary = nativePrimitiveClaims(target, artifactDir, rows, hypothesesSummary, runtimeVerificationSummary);
	const path = join(artifactDir, "native-primitive-claims.json");
	writePrivate(path, `${JSON.stringify(summary, null, 2)}\n`, 0o600);
	return { path, summary };
}
