/**
 * MITRE ATT&CK + CWE taxonomy reference for REPI.
 *
 * Progressive-disclosure: the thin kernel only keeps a compact index; technique
 * playbooks ({@link repi/techniques}) pull the concrete ATT&CK/CWE tags from
 * here so findings can be mapped to a standard taxonomy on demand. This module
 * holds only the tactic/technique/CWE identifiers actually referenced by the
 * REPI technique catalog plus the most common offensive-security classes — it is
 * a lookup, not an exhaustive ATT&CK export.
 */

export interface MitreTechnique {
	/** ATT&CK Technique ID, e.g. "T1059.004". */
	id: string;
	/** Technique name, e.g. "Command and Scripting Interpreter: Unix Shell". */
	name: string;
	/** Parent tactic name(s), e.g. "Execution". */
	tactics: string[];
}

export interface CweEntry {
	/** CWE ID, e.g. "CWE-78". */
	id: string;
	/** Short title, e.g. "Improper Neutralization of OS Command". */
	title: string;
}

/**
 * ATT&CK techniques referenced by the REPI technique catalog. IDs follow
 * Enterprise ATT&CK (sub-techniques where relevant). Keep entries accurate to
 * the public matrix; do not invent IDs.
 */
export const MITRE_TECHNIQUES: readonly MitreTechnique[] = [
	{ id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell", tactics: ["Execution"] },
	{ id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactics: ["Execution"] },
	{ id: "T1059", name: "Command and Scripting Interpreter", tactics: ["Execution"] },
	{ id: "T1203", name: "Exploitation for Client Execution", tactics: ["Execution"] },
	{ id: "T1068", name: "Exploitation for Privilege Escalation", tactics: ["Privilege Escalation"] },
	{ id: "T1211", name: "Exploitation for Defense Evasion", tactics: ["Defense Evasion"] },
	{ id: "T1055", name: "Process Injection", tactics: ["Defense Evasion", "Privilege Escalation"] },
	{ id: "T1055.001", name: "Process Injection: DLL Injection", tactics: ["Defense Evasion", "Privilege Escalation"] },
	{ id: "T1496", name: "Resource Hijacking", tactics: ["Impact"] },
	{ id: "T1053.003", name: "Scheduled Task/Job: Cron", tactics: ["Execution", "Persistence", "Privilege Escalation"] },
	{
		id: "T1543.002",
		name: "Create or Modify System Process: Systemd Service",
		tactics: ["Persistence", "Privilege Escalation"],
	},
	{
		id: "T1547.001",
		name: "Boot or Logon Autostart: Registry Run Keys",
		tactics: ["Persistence", "Privilege Escalation"],
	},
	{ id: "T1003", name: "OS Credential Dumping", tactics: ["Credential Access"] },
	{ id: "T1003.002", name: "OS Credential Dumping: Security Account Manager", tactics: ["Credential Access"] },
	{ id: "T1003.006", name: "OS Credential Dumping: DCSync", tactics: ["Credential Access"] },
	{ id: "T1558", name: "Steal or Forge Kerberos Tickets", tactics: ["Credential Access", "Defense Evasion"] },
	{ id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactics: ["Credential Access"] },
	{ id: "T1558.004", name: "Steal or Forge Kerberos Tickets: AS-REP Roasting", tactics: ["Credential Access"] },
	{
		id: "T1550.002",
		name: "Use Alternate Authentication Material: Pass the Hash",
		tactics: ["Defense Evasion", "Lateral Movement"],
	},
	{
		id: "T1550.001",
		name: "Use Alternate Authentication Material: Application Access Token",
		tactics: ["Defense Evasion", "Lateral Movement"],
	},
	{ id: "T1210", name: "Exploitation of Remote Services", tactics: ["Lateral Movement"] },
	{ id: "T1046", name: "Network Service Discovery", tactics: ["Discovery"] },
	{ id: "T1087", name: "Account Discovery", tactics: ["Discovery"] },
	{ id: "T1087.002", name: "Account Discovery: Domain Account", tactics: ["Discovery"] },
	{ id: "T1018", name: "Remote System Discovery", tactics: ["Discovery"] },
	{ id: "T1525", name: "Implant Internal Image", tactics: ["Persistence", "Lateral Movement"] },
	{ id: "T1611", name: "Escape to Host", tactics: ["Privilege Escalation"] },
	{ id: "T1613", name: "Container and Resource Discovery", tactics: ["Discovery"] },
	{ id: "T1602", name: "Data from Configuration Repository", tactics: ["Collection"] },
	{
		id: "T1552.007",
		name: "Unsecured Credentials: Container and Cloud Instance Metadata API",
		tactics: ["Credential Access"],
	},
	{ id: "T1528", name: "Steal Application Access Token", tactics: ["Credential Access"] },
	{ id: "T1190", name: "Exploit Public-Facing Application", tactics: ["Initial Access"] },
	{ id: "T1539", name: "Steal Web Session Cookie", tactics: ["Credential Access"] },
	{ id: "T1505.003", name: "Server Software Component: Web Shell", tactics: ["Persistence"] },
	{ id: "T1027.002", name: "Obfuscated Files or Information: Software Packing", tactics: ["Defense Evasion"] },
	{ id: "T1027.009", name: "Obfuscated Files or Information: Embedded Payloads", tactics: ["Defense Evasion"] },
	{ id: "T1497.001", name: "Virtualization/Sandbox Evasion: System Checks", tactics: ["Defense Evasion"] },
	{ id: "T1056", name: "Input Capture", tactics: ["Collection"] },
	{ id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactics: ["Command and Control"] },
	{ id: "T1105", name: "Ingress Tool Transfer", tactics: ["Command and Control"] },
];

/**
 * CWE classes referenced by the REPI technique catalog. Titles match the MITRE
 * CWE glossary short forms.
 */
export const CWE_ENTRIES: readonly CweEntry[] = [
	{ id: "CWE-22", title: "Path Traversal" },
	{ id: "CWE-78", title: "OS Command Injection" },
	{ id: "CWE-79", title: "Cross-site Scripting" },
	{ id: "CWE-89", title: "SQL Injection" },
	{ id: "CWE-94", title: "Improper Control of Code Generation (Code Injection)" },
	{ id: "CWE-98", title: "PHP File Inclusion (RFI/LFI)" },
	{ id: "CWE-121", title: "Stack-based Buffer Overflow" },
	{ id: "CWE-122", title: "Heap-based Buffer Overflow" },
	{ id: "CWE-125", title: "Out-of-bounds Read" },
	{ id: "CWE-190", title: "Integer Overflow/Wrap-around" },
	{ id: "CWE-200", title: "Exposure of Sensitive Information" },
	{ id: "CWE-209", title: "Generation of Error Message Containing Sensitive Information" },
	{ id: "CWE-20", title: "Improper Input Validation" },
	{ id: "CWE-134", title: "Uncontrolled Format String" },
	{ id: "CWE-250", title: "Execution with Unnecessary Privileges" },
	{ id: "CWE-295", title: "Improper Certificate Validation" },
	{ id: "CWE-319", title: "Cleartext Transmission of Sensitive Information" },
	{ id: "CWE-287", title: "Improper Authentication" },
	{ id: "CWE-285", title: "Improper Authorization" },
	{ id: "CWE-306", title: "Missing Authentication for Critical Function" },
	{ id: "CWE-326", title: "Inadequate Encryption Strength" },
	{ id: "CWE-327", title: "Use of a Broken or Risky Cryptographic Algorithm" },
	{ id: "CWE-338", title: "Use of Cryptographically Weak Pseudo-Random Number Generator" },
	{ id: "CWE-347", title: "Improper Verification of Cryptographic Signature" },
	{ id: "CWE-384", title: "Session Fixation" },
	{ id: "CWE-416", title: "Use After Free" },
	{ id: "CWE-434", title: "Unrestricted Upload of File with Dangerous Type" },
	{ id: "CWE-444", title: "HTTP Request Smuggling" },
	{ id: "CWE-451", title: "User Interface (UI) Misrepresentation of Critical Information" },
	{ id: "CWE-502", title: "Deserialization of Untrusted Data" },
	{ id: "CWE-522", title: "Insufficiently Protected Credentials" },
	{ id: "CWE-601", title: "Open Redirect" },
	{ id: "CWE-611", title: "XXE (XML External Entity)" },
	{ id: "CWE-639", title: "Authorization Bypass Through User-Controlled Key (IDOR/BOLA)" },
	{ id: "CWE-693", title: "Protection Mechanism Failure" },
	{ id: "CWE-732", title: "Incorrect Permission Assignment for Critical Resource" },
	{ id: "CWE-74", title: "Injection (general)" },
	{ id: "CWE-77", title: "Command Injection (generic)" },
	{ id: "CWE-1333", title: "Inadequate Neutralization of Script-Related HTML Tags (Prototype Pollution adjacent)" },
	{ id: "CWE-918", title: "Server-Side Request Forgery (SSRF)" },
	{ id: "CWE-1021", title: "Improper Restriction of Rendered UI Layers/Page (Clickjacking)" },
	{ id: "CWE-1321", title: "Prototype Pollution" },
	{ id: "CWE-1336", title: "Improper Neutralization of Special Elements Used in a Template Engine (SSTI)" },
];

const mitreById = new Map<string, MitreTechnique>(MITRE_TECHNIQUES.map((entry) => [entry.id, entry]));
const cweById = new Map<string, CweEntry>(CWE_ENTRIES.map((entry) => [entry.id, entry]));

/** Resolve an ATT&CK technique id to its entry, or undefined if unknown. */
export function mitreTechnique(id: string): MitreTechnique | undefined {
	return mitreById.get(id);
}

/** Resolve a CWE id to its entry, or undefined if unknown. */
export function cweEntry(id: string): CweEntry | undefined {
	return cweById.get(id);
}

/** Format an ATT&CK tag line, e.g. `MITRE ATT&CK T1059.004 — Unix Shell (Execution)`. */
export function formatMitreTag(id: string): string {
	const entry = mitreTechnique(id);
	if (!entry) return `MITRE ATT&CK ${id}`;
	return `MITRE ATT&CK ${id} — ${entry.name} (${entry.tactics.join(", ")})`;
}

/** Format a CWE tag line, e.g. `CWE-78 — OS Command Injection`. */
export function formatCweTags(ids: readonly string[]): string {
	if (ids.length === 0) return "";
	return ids
		.map((id) => {
			const entry = cweEntry(id);
			return entry ? `${id} — ${entry.title}` : id;
		})
		.join(" | ");
}

/** Validate that every id in a list resolves to a known taxonomy entry. */
export function unresolvedTaxonomyIds(
	mitreIds: readonly string[],
	cweIds: readonly string[],
): { mitre: string[]; cwe: string[] } {
	return {
		mitre: mitreIds.filter((id) => !mitreById.has(id)),
		cwe: cweIds.filter((id) => !cweById.has(id)),
	};
}
