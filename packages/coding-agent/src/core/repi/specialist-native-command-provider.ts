import { type MissionState, missionOperatorDirective } from "./mission.ts";

export type NativeSpecialistCommandProviderDependencies = {
	mission: MissionState;
	target?: string;
	domain: string;
	laneName: string;
	context: string;
	targetArg: string;
	targetPython: string;
	specialists: string[];
	add(
		label: string,
		command: string,
		evidence: string,
		runtimeAdapter?: {
			adapter: string;
			target?: string;
			timeoutMs?: number;
			specialist?: string;
		},
	): void;
};

const ADAPTERS = {
	nativeXref: "r2-native-xref-adapter",
	nativeTrace: "gdb-native-trace-adapter",
	decompiler: "ghidra-headless-summary-adapter",
	mobile: "frida-mobile-hook-adapter",
	pwn: "pwntools-local-verifier-adapter",
	exploitReliability: "exploit-reliability-adapter",
} as const;

const NATIVE_ALIASES = [
	"native-deep-symbol-map-scaffold",
	"native-deep-decompiler-project-scaffold",
	"native-deep-compare-trace-scaffold",
	"native-deep-patch-hypothesis-scaffold",
	"native-deep-symbolic-fuzz-scaffold",
	"/tmp/repi-native-symbolic-fuzz.py",
];

const PWN_ALIASES = [
	"native-deep-symbol-map-scaffold",
	"pwn-primitive-cyclic-crash",
	"pwn-primitive-offset-analyzer",
	"pwn-primitive-rop-libc-scaffold",
	"pwn-primitive-local-verifier",
	"pwn-advanced-heap-tcache-scaffold",
	"pwn-advanced-format-string-scaffold",
	"pwn-advanced-srop-ret2dlresolve-scaffold",
	"pwn-advanced-one-gadget-constraints",
	"pwn-advanced-seccomp-sandbox-scaffold",
	"ROPgadget",
	"pwntools",
];

const IOS_ALIASES = [
	"ios-ipa-inventory-scaffold",
	"ios-macho-class-map-scaffold",
	"ios-frida-objection-hook-scaffold",
	"ios-network-replay-scaffold",
];

const MOBILE_ALIASES = ["frida-gdb-trace-hook-template", "Java.perform", "Module.findExportByName"];

const EXPLOIT_RELIABILITY_ALIASES = [
	"exploit-poc-normalizer-scaffold",
	"exploit-replay-matrix-scaffold",
	"exploit-environment-pin-scaffold",
	"exploit-flake-triage-scaffold",
	"exploit-artifact-bundle-scaffold",
];

export function createNativeSpecialistCommandProvider(dependencies: NativeSpecialistCommandProviderDependencies) {
	const { mission, target, domain, laneName, context, targetArg, specialists, add } = dependencies;
	const directive = (missionOperatorDirective(mission) || mission.task).toLowerCase();
	const laneAllowsRuntime =
		/headers|triage|map|control|flow|primitive|runtime|proof|poc|verify|patch|fuzz|report|inventory|replay|bundle/.test(
			laneName,
		);
	const pwnContext =
		/\bpwn\b|\bexploit\b|\brop\b|ret2libc|\bheap\b|tcache|fastbin|format[-_ ]?string|fmtstr|srop|ret2dlresolve|one_gadget|seccomp|pwntools|\bprimitive\b|cyclic|栈|堆/.test(
			context,
		);
	const exploitReliability =
		((domain === "Exploit reliability" &&
			/replay|normalize|flake|bundle|reliab|stability|inventory/.test(laneName)) ||
			/autopwn|exploit reliability|reliable exploit|poc replay|replay matrix|payload stability|crash flake|稳定.*poc|复现矩阵/.test(
				context,
			)) &&
		/primitive/.test(laneName) === false;
	const iosContext =
		domain === "Mobile / iOS" ||
		Boolean(target && /\.ipa$/i.test(target)) ||
		/\bios\b|\bipa\b|objective-c|objc|swift|mach-o|keychain|jailbreak|越狱/.test(context);
	const mobileContext =
		iosContext || domain === "Mobile / Android" || /mobile|android|apk|frida|jadx|apktool|adb|smali/.test(context);
	const nativeContext =
		/Native reverse|Pwn \/ exploit|CTF \/ sandbox/.test(domain) ||
		/native|reverse|binary|elf|pe32|mach-o|wasm|crackme|license|serial|keygen|patch|symbolic|fuzz|二进制|逆向|反编译|反汇编/.test(
			`${context}\n${directive}`,
		);

	function addAdapter(
		label: string,
		adapter: string,
		aliases: readonly string[],
		evidence: string,
		specialist: string,
	): void {
		add(label, `re_runtime_adapter run ${adapter} ${targetArg} # ${aliases.join(" ")}`, evidence, {
			adapter,
			target,
			specialist,
		});
	}

	function appendMobileAndNative(): void {
		if (!laneAllowsRuntime) return;
		if (mobileContext) {
			specialists.push(iosContext ? "iOS IPA/mobile runtime" : "Frida/GDB trace");
			if (!target) {
				add(
					"mobile-target-discovery",
					"find . -maxdepth 6 -type f \\( -iname '*.apk' -o -iname '*.ipa' -o -iname '*.so' -o -iname '*.dylib' \\) -print | head -160",
					"discover a concrete mobile package or native module",
				);
				return;
			}
			addAdapter(
				"mobile-domain-adapter",
				ADAPTERS.mobile,
				iosContext ? IOS_ALIASES : MOBILE_ALIASES,
				"single mobile DomainAdapter for Frida hooks, process/package state, pinning and crypto anchors",
				iosContext ? "ios-ipa frida-gdb-trace" : "frida-gdb-trace frida-gdb-trace-mobile-environment",
			);
			return;
		}
		if (!nativeContext || pwnContext || exploitReliability) return;
		specialists.push("native deep reverse/pwn");
		if (!target) {
			add(
				"native-target-discovery",
				'find . -maxdepth 5 -type f -exec sh -c \'file "$1" | grep -Eq "ELF|PE32|Mach-O|WebAssembly" && printf "%s\\n" "$1"\' _ {} \\; | head -80',
				"discover a concrete native target before adapter execution",
			);
			return;
		}
		const selection = /runtime|trace|debug|crash|compare|fuzz/.test(laneName)
			? ([
					"native-domain-adapter-trace",
					ADAPTERS.nativeTrace,
					"GDB MI registers, breakpoints, crash and mitigation evidence",
				] as const)
			: /decomp|control|flow/.test(laneName)
				? ([
						"native-domain-adapter-decompile",
						ADAPTERS.decompiler,
						"Ghidra headless control-flow and function summary evidence",
					] as const)
				: ([
						"native-domain-adapter-xref",
						ADAPTERS.nativeXref,
						"radare2/rizin symbol, import, string and xref evidence",
					] as const);
		addAdapter(selection[0], selection[1], NATIVE_ALIASES, selection[2], "native-deep-symbol-map");
	}

	function appendPwnAndExploit(): void {
		if (!laneAllowsRuntime || (!pwnContext && !exploitReliability)) return;
		if (!target) {
			add(
				"pwn-target-discovery",
				"find . -maxdepth 5 -type f -perm -111 -exec file {} \\; 2>/dev/null | grep -E 'ELF|Mach-O|PE32' | head -100",
				"discover a concrete executable for exploit verification",
			);
			return;
		}
		if (exploitReliability) {
			specialists.push("exploit reliability/autopwn");
			addAdapter(
				"exploit-reliability-domain-adapter",
				ADAPTERS.exploitReliability,
				EXPLOIT_RELIABILITY_ALIASES,
				"bounded multi-run verifier with stdout/stderr hashes and stable replay evidence",
				"exploit-poc-normalizer exploit-replay-matrix",
			);
			return;
		}
		specialists.push("pwn primitive");
		addAdapter(
			"pwn-domain-adapter",
			ADAPTERS.pwn,
			PWN_ALIASES,
			"pwntools primitive, cyclic crash, mitigation and bounded multi-run evidence",
			"pwn-primitive",
		);
	}

	return {
		appendMobileAndNative,
		appendPwnAndExploit,
		// Kept as a compatibility hook for the planner; mobile/native execution
		// is already emitted by appendMobileAndNative through the adapter.
		appendFridaTrace() {},
	};
}
