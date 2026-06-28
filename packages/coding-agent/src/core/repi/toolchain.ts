export const REPI_TOOL_BOOTSTRAP_CATALOG = [
	{
		tool: "checksec",
		install: "sudo apt-get update && sudo apt-get install -y checksec",
		verify: "command -v checksec && checksec --version || true",
	},
	{
		tool: "gdb",
		install: "sudo apt-get update && sudo apt-get install -y gdb",
		verify: "command -v gdb && gdb --version | head -1",
	},
	{
		tool: "strace",
		install: "sudo apt-get update && sudo apt-get install -y strace",
		verify: "command -v strace && strace --version | head -1",
	},
	{
		tool: "ltrace",
		install: "sudo apt-get update && sudo apt-get install -y ltrace",
		verify: "command -v ltrace && ltrace --version | head -1",
	},
	{
		tool: "radare2",
		install: "sudo apt-get update && sudo apt-get install -y radare2",
		verify: "command -v r2 && r2 -v | head -1",
	},
	{
		tool: "r2",
		install: "sudo apt-get update && sudo apt-get install -y radare2",
		verify: "command -v r2 && r2 -v | head -1",
	},
	{
		tool: "ghidra",
		install:
			"(sudo apt-get update && sudo apt-get install -y default-jdk unzip curl) || true; echo 'manual_tool_review ghidra: ensure JDK 21+, then download the latest ghidra_PUBLIC_<ver>.zip from https://github.com/NationalSecurityAgency/ghidra/releases, unzip to /opt, sudo ln -sf /opt/ghidra_*/ghidraRun /usr/local/bin/ghidra'",
		verify: "command -v ghidra || test -x /opt/ghidra_*/ghidraRun || true",
	},
	{
		tool: "binwalk",
		install: "sudo apt-get update && sudo apt-get install -y binwalk",
		verify: "command -v binwalk && binwalk --version | head -1",
	},
	{
		tool: "unblob",
		install: "python3 -m pip install --user unblob",
		verify: "command -v unblob && unblob --version | head -1",
	},
	{
		tool: "unsquashfs",
		install: "sudo apt-get update && sudo apt-get install -y squashfs-tools",
		verify: "command -v unsquashfs && unsquashfs -version | head -1",
	},
	{
		tool: "ubireader_extract_files",
		install: "python3 -m pip install --user ubi_reader",
		verify: "command -v ubireader_extract_files && ubireader_extract_files --help | head -1",
	},
	{
		tool: "qemu-mips",
		install: "sudo apt-get update && sudo apt-get install -y qemu-user-static qemu-system-mips",
		verify: "command -v qemu-mips || command -v qemu-mips-static",
	},
	{
		tool: "qemu-arm",
		install: "sudo apt-get update && sudo apt-get install -y qemu-user-static qemu-system-arm",
		verify: "command -v qemu-arm || command -v qemu-arm-static",
	},
	{
		tool: "nmap",
		install: "sudo apt-get update && sudo apt-get install -y nmap",
		verify: "command -v nmap && nmap --version | head -1",
	},
	{
		tool: "masscan",
		install: "sudo apt-get update && sudo apt-get install -y masscan",
		verify: "command -v masscan && masscan --version | head -1",
	},
	{
		tool: "ffuf",
		install: "sudo apt-get update && sudo apt-get install -y ffuf",
		verify: "command -v ffuf && ffuf -V | head -1",
	},
	{
		tool: "gobuster",
		install: "sudo apt-get update && sudo apt-get install -y gobuster",
		verify: "command -v gobuster && gobuster version",
	},
	{
		tool: "sqlmap",
		install: "sudo apt-get update && sudo apt-get install -y sqlmap",
		verify: "command -v sqlmap && sqlmap --version",
	},
	{
		tool: "wfuzz",
		install: "sudo apt-get update && sudo apt-get install -y wfuzz",
		verify: "command -v wfuzz && wfuzz --version | head -1",
	},
	{
		tool: "tshark",
		install:
			"sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark",
		verify: "command -v tshark && tshark --version | head -1",
	},
	{
		tool: "capinfos",
		install:
			"sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark",
		verify: "command -v capinfos && capinfos -h | head -1",
	},
	{
		tool: "tcpdump",
		install: "sudo apt-get update && sudo apt-get install -y tcpdump",
		verify: "command -v tcpdump && tcpdump --version | head -1",
	},
	{
		tool: "wireshark",
		install: "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wireshark",
		verify: "command -v wireshark && wireshark --version | head -1 || true",
	},
	{
		tool: "exiftool",
		install: "sudo apt-get update && sudo apt-get install -y libimage-exiftool-perl",
		verify: "command -v exiftool && exiftool -ver",
	},
	{
		tool: "foremost",
		install: "sudo apt-get update && sudo apt-get install -y foremost",
		verify: "command -v foremost && foremost -V 2>&1 | head -1",
	},
	{
		tool: "yara",
		install: "sudo apt-get update && sudo apt-get install -y yara",
		verify: "command -v yara && yara --version",
	},
	{
		tool: "capa",
		install: "python3 -m pip install --user flare-capa",
		verify: "command -v capa && capa --version | head -1",
	},
	{
		tool: "floss",
		install: "python3 -m pip install --user flare-floss",
		verify: "command -v floss && floss --version | head -1",
	},
	{
		tool: "clamscan",
		install: "sudo apt-get update && sudo apt-get install -y clamav",
		verify: "command -v clamscan && clamscan --version | head -1",
	},
	{
		tool: "upx",
		install: "sudo apt-get update && sudo apt-get install -y upx-ucl",
		verify: "command -v upx && upx --version | head -1",
	},
	{
		tool: "hashcat",
		install: "sudo apt-get update && sudo apt-get install -y hashcat",
		verify: "command -v hashcat && hashcat --version",
	},
	{
		tool: "john",
		install: "sudo apt-get update && sudo apt-get install -y john",
		verify: "command -v john && john --list=build-info | head -1",
	},
	{
		tool: "hydra",
		install: "sudo apt-get update && sudo apt-get install -y hydra",
		verify: "command -v hydra && hydra -h | head -1",
	},
	{
		tool: "msfconsole",
		install:
			"sudo apt-get update && sudo apt-get install -y metasploit-framework || echo 'manual_tool_review metasploit-framework: if apt unavailable, use the official Metasploit installer (https://www.metasploit.com) or snap install metasploit-framework'",
		verify: "command -v msfconsole && msfconsole -v | head -1 || true",
	},
	{
		tool: "ROPgadget",
		install: "python3 -m pip install --user ROPGadget",
		verify: "command -v ROPgadget && ROPgadget --help | head -1",
	},
	{ tool: "ropper", install: "python3 -m pip install --user ropper", verify: "command -v ropper && ropper --version" },
	{
		tool: "angr",
		install:
			"python3 -m pip install --user angr || echo 'manual_tool_review angr: pip install failed (heavy native deps) — use the Phase 0 manual constraint-modeling fallback (objdump -d + python3 predicates/z3)'",
		verify: "command -v python3 && python3 -c 'import angr' >/dev/null 2>&1 && echo angr-ok || true",
	},
	{
		tool: "one_gadget",
		install: "gem install --user-install one_gadget",
		verify: "command -v one_gadget && one_gadget --version",
	},
	{
		tool: "seccomp-tools",
		install: "gem install --user-install seccomp-tools",
		verify: "command -v seccomp-tools && seccomp-tools --version",
	},
	{
		tool: "patchelf",
		install: "sudo apt-get update && sudo apt-get install -y patchelf",
		verify: "command -v patchelf && patchelf --version",
	},
	{
		tool: "jadx",
		install: "sudo apt-get update && sudo apt-get install -y jadx",
		verify: "command -v jadx && jadx --version",
	},
	{
		tool: "apktool",
		install: "sudo apt-get update && sudo apt-get install -y apktool",
		verify: "command -v apktool && apktool --version",
	},
	{
		tool: "adb",
		install: "sudo apt-get update && sudo apt-get install -y adb",
		verify: "command -v adb && adb version | head -1",
	},
	{
		tool: "frida",
		install: "python3 -m pip install --user frida-tools",
		verify: "command -v frida && frida --version",
	},
	{ tool: "aws", install: "python3 -m pip install --user awscli", verify: "command -v aws && aws --version" },
	{
		tool: "kubectl",
		install: "sudo apt-get update && sudo apt-get install -y kubernetes-client",
		verify: "command -v kubectl && (kubectl version --client --short 2>/dev/null || kubectl version --client)",
	},
	{
		tool: "docker",
		install: "sudo apt-get update && sudo apt-get install -y docker.io",
		verify: "command -v docker && docker --version",
	},
	{
		tool: "az",
		install: "python3 -m pip install --user azure-cli",
		verify: "command -v az && az version | head -20",
	},
	{
		tool: "impacket-secretsdump",
		install: "python3 -m pip install --user impacket",
		verify: "command -v impacket-secretsdump && impacket-secretsdump -h | head -1",
	},
	{
		tool: "nxc",
		install: "python3 -m pip install --user netexec",
		verify: "command -v nxc && nxc --version",
	},
	{
		tool: "crackmapexec",
		install: "python3 -m pip install --user crackmapexec",
		verify: "command -v crackmapexec && crackmapexec --version",
	},
	{
		tool: "bloodhound-python",
		install: "python3 -m pip install --user bloodhound",
		verify: "command -v bloodhound-python && bloodhound-python -h | head -1",
	},
	{
		tool: "certipy",
		install: "python3 -m pip install --user certipy-ad",
		verify: "command -v certipy && certipy -h | head -1",
	},
	{
		tool: "ldapsearch",
		install: "sudo apt-get update && sudo apt-get install -y ldap-utils",
		verify: "command -v ldapsearch && ldapsearch -VV 2>&1 | head -2",
	},
	{
		tool: "curl",
		install: "sudo apt-get update && sudo apt-get install -y curl",
		verify: "command -v curl && curl --version | head -1",
	},
	{
		tool: "rg",
		install: "sudo apt-get update && sudo apt-get install -y ripgrep",
		verify: "command -v rg && rg --version | head -1",
	},
	{
		tool: "jq",
		install: "sudo apt-get update && sudo apt-get install -y jq",
		verify: "command -v jq && jq --version",
	},
	{
		tool: "unzip",
		install: "sudo apt-get update && sudo apt-get install -y unzip",
		verify: "command -v unzip && unzip -v | head -1",
	},
	{
		tool: "python3",
		install: "sudo apt-get update && sudo apt-get install -y python3 python3-pip",
		verify: "command -v python3 && python3 --version",
	},
	{
		tool: "node",
		install: "sudo apt-get update && sudo apt-get install -y nodejs npm",
		verify: "command -v node && node --version",
	},
	{
		tool: "npm",
		install: "sudo apt-get update && sudo apt-get install -y npm",
		verify: "command -v npm && npm --version",
	},
	{
		tool: "httpx",
		install:
			"command -v go >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y golang-go); go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
		verify: "command -v httpx && httpx -version | head -1",
	},
	{
		tool: "nuclei",
		install:
			"command -v go >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y golang-go); go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		verify: "command -v nuclei && nuclei -version | head -1",
	},
	{
		tool: "katana",
		install:
			"command -v go >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y golang-go); go install github.com/projectdiscovery/katana/cmd/katana@latest",
		verify: "command -v katana && katana -version | head -1",
	},
	{
		tool: "feroxbuster",
		install: "sudo apt-get update && sudo apt-get install -y feroxbuster",
		verify: "command -v feroxbuster && feroxbuster --version | head -1",
	},
	{
		tool: "nikto",
		install: "sudo apt-get update && sudo apt-get install -y nikto",
		verify: "command -v nikto && nikto -Version 2>&1 | head -1",
	},
	{
		tool: "dalfox",
		install:
			"command -v go >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y golang-go); go install github.com/hahwul/dalfox/v2@latest",
		verify: "command -v dalfox && dalfox version | head -1",
	},
	{
		tool: "arjun",
		install: "python3 -m pip install --user arjun",
		verify: "command -v arjun && arjun --version | head -1",
	},
	{
		tool: "volatility3",
		install: "python3 -m pip install --user volatility3",
		verify: "command -v volatility3 && volatility3 -h | head -1",
	},
	{
		tool: "objection",
		install: "python3 -m pip install --user objection",
		verify: "command -v objection && objection version | head -1",
	},
	{
		tool: "ios-deploy",
		install: "npm install -g ios-deploy",
		verify: "command -v ios-deploy && ios-deploy --version",
	},
	{
		tool: "class-dump",
		install:
			"echo 'manual_tool_review class-dump: macOS only; install via brew install class-dump or build class-dump-swift from source (https://github.com/nygard/class-dump)'",
		verify: "command -v class-dump || command -v class-dump-swift || true",
	},
	{
		tool: "otool",
		install:
			"echo 'manual_tool_review otool: macOS only; install Xcode Command Line Tools via xcode-select --install'",
		verify: "command -v otool && otool -h 2>&1 | head -1 || true",
	},
	{
		tool: "nm",
		install: "sudo apt-get update && sudo apt-get install -y binutils",
		verify: "command -v nm && nm --version | head -1",
	},
	{
		tool: "codesign",
		install:
			"echo 'manual_tool_review codesign: macOS only; install Xcode Command Line Tools via xcode-select --install'",
		verify: "command -v codesign && codesign -h 2>&1 | head -1 || true",
	},
	{
		tool: "plutil",
		install:
			"sudo apt-get update && sudo apt-get install -y libplist-utils || echo 'manual_tool_review plutil: on macOS plutil ships with Xcode CLT; on Linux libplist-utils provides plutil'",
		verify: "command -v plutil && plutil -help 2>&1 | head -1 || true",
	},
	{
		tool: "openssl",
		install: "sudo apt-get update && sudo apt-get install -y openssl",
		verify: "command -v openssl && openssl version",
	},
	{
		tool: "z3",
		install: "python3 -m pip install --user z3-solver",
		verify: "python3 - <<'PYZ3'\nimport z3; print(z3.get_version_string())\nPYZ3",
	},
	{
		tool: "sage",
		install: "sudo apt-get update && sudo apt-get install -y sagemath",
		verify: "command -v sage && sage --version | head -1",
	},
	{
		tool: "7z",
		install: "sudo apt-get update && sudo apt-get install -y p7zip-full",
		verify: "command -v 7z && 7z | head -2",
	},
	{
		tool: "zeek",
		install: "sudo apt-get update && sudo apt-get install -y zeek",
		verify: "command -v zeek && zeek --version",
	},
	{
		tool: "pwn",
		install: "python3 -m pip install --user pwntools",
		verify: "command -v pwn && pwn version || python3 - <<'PYPWN'\nimport pwn; print(pwn.__version__)\nPYPWN",
	},
	{
		tool: "burpsuite",
		install:
			"(sudo apt-get update && sudo apt-get install -y default-jdk curl) || true; echo 'manual_tool_review burpsuite: ensure JDK 17+, then download burpsuite_community_<ver>.jar from https://portswigger.net/burp/communitydownload and run java -jar burpsuite_community.jar; optionally alias burpsuite=java -jar /opt/burpsuite_community.jar'",
		verify: "command -v burpsuite || test -f /opt/burpsuite_community*.jar || true",
	},
	{
		tool: "mitmproxy",
		install: "python3 -m pip install --user mitmproxy",
		verify: "command -v mitmproxy && mitmproxy --version | head -1",
	},
	{
		tool: "playwright",
		install: "npm install -g playwright && playwright install",
		verify: "command -v playwright && playwright --version",
	},
] as const;

export type RepiToolBootstrapCatalogEntry = (typeof REPI_TOOL_BOOTSTRAP_CATALOG)[number];
