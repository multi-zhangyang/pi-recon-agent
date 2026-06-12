#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(pwd)}"
PI_DIR="$ROOT/repi-profile"
OUT="$PI_DIR/tools/tool-index.md"
mkdir -p "$PI_DIR/tools"
TOOLS=(
  file sha256sum unzip bash sh strings readelf objdump checksec gdb strace ltrace radare2 r2 rabin2 ghidra yara capa floss clamscan upx python3 python pwn sage z3 openssl curl rg jq pip node npm go rustc cargo java
  jadx apktool adb frida frida-ps objection ios-deploy class-dump otool nm codesign plutil binwalk unblob unsquashfs ubireader_extract_files qemu-system-x86_64 qemu-aarch64 qemu-mips qemu-arm 7z nmap masscan naabu httpx subfinder amass
  nuclei katana ffuf feroxbuster gobuster nikto dalfox arjun sqlmap wfuzz tshark zeek capinfos tcpdump editcap wireshark exiftool zsteg foremost volatility3 hashcat john hydra msfconsole ruby
  one_gadget ROPgadget ropper patchelf docker kubectl aws az gcloud impacket-secretsdump nxc crackmapexec bloodhound-python certipy
  burpsuite mitmproxy playwright
)
{
  echo '# REPI Tool Index'
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo '| Tool | Present | Path | Version probe |'
  echo '|---|---:|---|---|'
  for t in "${TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      p="$(command -v "$t")"
      v="$($t --version 2>&1 | head -1 | tr '\n' ' ' || true)"
      printf '| %s | yes | %s | %s |\n' "$t" "$p" "$v"
    else
      printf '| %s | no |  |  |\n' "$t"
    fi
  done
} > "$OUT"
echo "$OUT"
