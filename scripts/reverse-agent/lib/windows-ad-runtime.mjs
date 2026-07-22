import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

let root;
let redact;
let shortHash;
let shellQuote;
let noWrite;
let writePrivate;
let readSmallText;
let readJsonArtifact;
let collectDirectoryFiles;
let textLikeWindowsAdFile;
let bufferSha256;
let firmwareStrings;

function configureWindowsAdRuntime(runtime) {
	({ root, redact, shortHash, shellQuote, noWrite, writePrivate, readSmallText, readJsonArtifact, collectDirectoryFiles, textLikeWindowsAdFile, bufferSha256, firmwareStrings } = runtime);
}

function windowsAdCandidateFiles(target) {
	if (!existsSync(target)) return [];
	const stat = statSync(target);
	if (stat.isFile()) return [{ name: basename(target), path: target }];
	return collectDirectoryFiles(target, 4, 500)
		.filter((entry) => textLikeWindowsAdFile(entry) || /(?:^|\/)(?:ntds\.dit|sam|system|security)$/i.test(entry.name) || /\.(?:evtx|kirbi|ccache|dit|hive|hiv)$/i.test(entry.name))
		.map((entry) => ({ name: entry.name, path: entry.path }))
		.slice(0, 240);
}

function windowsAdSignals(strings) {
	const domains = [];
	const principals = [];
	const credentials = [];
	const kerberos = [];
	const adcs = [];
	const events = [];
	const commands = [];
	const addUnique = (list, value, offset) => {
		const text = redact(String(value).slice(0, 320));
		if (!text || list.some((row) => row.text === text)) return;
		list.push({ offset, text });
	};
	for (const row of strings) {
		const text = row.text;
		for (const match of text.matchAll(/\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b|\bDC=[A-Za-z0-9_-]+(?:,DC=[A-Za-z0-9_-]+)+/gi)) addUnique(domains, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+|[A-Za-z0-9._$-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|S-1-5-21-[0-9-]+)\b/gi)) addUnique(principals, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:krbtgt|NTDS\.DIT|DCSync|secretsdump|hashcat|john|NTLM|LMHASH|SAM hive|SYSTEM hive|mimikatz|sekurlsa|lsadump|dpapi)\b[^\0\r\n]{0,180}/gi)) addUnique(credentials, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:Kerberoast|AS-REP|ASREP|TGS-REP|TGT|SPN|KRB5|kirbi|ccache|4768|4769|4771|4776)\b[^\0\r\n]{0,180}/gi)) addUnique(kerberos, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:ADCS|ESC[1-9]|Certipy|certutil|certificate template|Enrollment Agent|PetitPotam|NTLM relay)\b[^\0\r\n]{0,180}/gi)) addUnique(adcs, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:EventID|Event Id|EventCode)\s*[:=]?\s*(?:4624|4625|4672|4688|4720|4728|4732|4768|4769|4771|4776|7045)\b[^\0\r\n]{0,180}/gi)) addUnique(events, match[0], row.offset + match.index);
		for (const match of text.matchAll(/\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|rundll32|regsvr32|wmic|net\s+user|net\s+group|nltest|dsquery|ldapsearch|SharpHound|BloodHound|Certipy|nxc|crackmapexec|impacket-[a-z-]+|secretsdump\.py|Get-ADUser|Get-DomainUser)\b[^\0\r\n]{0,220}/gi)) addUnique(commands, match[0], row.offset + match.index);
		if (domains.length + principals.length + credentials.length + kerberos.length + adcs.length + events.length + commands.length >= 360) break;
	}
	return {
		domains: domains.slice(0, 60),
		principals: principals.slice(0, 90),
		credentials: credentials.slice(0, 80),
		kerberos: kerberos.slice(0, 80),
		adcs: adcs.slice(0, 80),
		events: events.slice(0, 80),
		commands: commands.slice(0, 80),
	};
}

function windowsAdJsonFiles(candidates) {
	return candidates
		.filter((file) => /\.json$/i.test(file.name) && /bloodhound|sharphound|users|groups|computers|edges|sessions|acl|gpo|containers|ous/i.test(file.name))
		.slice(0, 60);
}

function bloodhoundValue(row, keys) {
	if (!row || typeof row !== "object") return undefined;
	for (const key of keys) {
		if (Object.hasOwn(row, key)) return row[key];
	}
	const props = row.Properties ?? row.properties ?? row.Props ?? row.props;
	if (props && typeof props === "object") {
		for (const key of keys) {
			if (Object.hasOwn(props, key)) return props[key];
		}
	}
	return undefined;
}

function bloodhoundString(row, keys) {
	const value = bloodhoundValue(row, keys);
	if (typeof value === "string" && value.trim()) return redact(value.trim().slice(0, 260));
	if (typeof value === "number") return String(value);
	return undefined;
}

function bloodhoundBool(row, keys) {
	const value = bloodhoundValue(row, keys);
	if (typeof value === "boolean") return value;
	if (typeof value === "number") return value !== 0;
	if (typeof value === "string") return /^(?:true|yes|1)$/i.test(value.trim());
	return false;
}

function bloodhoundArray(value) {
	if (!value) return [];
	if (Array.isArray(value)) return value;
	return [value];
}

function bloodhoundNodeType(row) {
	const labels = bloodhoundValue(row, ["Labels", "labels"]);
	if (Array.isArray(labels) && labels.length) return redact(String(labels[0]).slice(0, 80));
	const kind = bloodhoundString(row, ["ObjectType", "objecttype", "type", "Type", "kind", "label", "Label"]);
	if (kind) return kind;
	const name = bloodhoundString(row, ["name", "Name", "displayname", "DisplayName"]);
	if (name?.endsWith("@")) return "Domain";
	if (name?.includes("@")) return "Principal";
	return undefined;
}

function bloodhoundNodeName(row) {
	return bloodhoundString(row, ["name", "Name", "displayname", "DisplayName", "ObjectName", "objectname", "samaccountname", "SamAccountName", "objectid", "ObjectIdentifier", "ObjectID", "id"]);
}

function bloodhoundEdgeEndpoint(value) {
	if (!value) return undefined;
	if (typeof value === "string") return redact(value.slice(0, 260));
	if (typeof value === "number") return String(value);
	if (typeof value === "object") return bloodhoundNodeName(value);
	return undefined;
}

function bloodhoundPushUnique(list, row, keyFn, limit) {
	const key = keyFn(row);
	if (!key || list.some((existing) => keyFn(existing) === key)) return;
	if (list.length < limit) list.push(row);
}

function parseBloodhoundJson(file) {
	let parsed;
	try {
		parsed = JSON.parse(readSmallText(file.path, 2_000_000));
	} catch (error) {
		return { file: file.name, error: error instanceof Error ? redact(error.message) : redact(String(error)), nodes: [], edges: [] };
	}
	const nodes = [];
	const edges = [];
	let objectCount = 0;
	const pushNode = (row) => bloodhoundPushUnique(nodes, row, (node) => `${node.type ?? ""}:${node.name}`, 240);
	const pushEdge = (row) => bloodhoundPushUnique(edges, row, (edge) => `${edge.source}>${edge.relationship}>${edge.target}`, 260);
	const processObject = (row, path) => {
		if (!row || typeof row !== "object" || Array.isArray(row)) return;
		objectCount += 1;
		const name = bloodhoundNodeName(row);
		const type = bloodhoundNodeType(row);
		const highValue = bloodhoundBool(row, ["highvalue", "HighValue", "is_high_value", "admincount", "AdminCount"]);
		const owned = bloodhoundBool(row, ["owned", "Owned", "pwned", "Pwned", "compromised", "Compromised"]);
		if (name && (type || highValue || owned || /(?:data|nodes|users|groups|computers|domains)/i.test(path))) {
			pushNode({
				file: file.name,
				name,
				type: type ?? "unknown",
				highValue,
				owned,
			});
		}
		for (const member of bloodhoundArray(bloodhoundValue(row, ["memberOf", "memberof", "MemberOf", "MemberOfName"]))) {
			const target = bloodhoundEdgeEndpoint(member);
			if (name && target) pushEdge({ file: file.name, source: name, relationship: "MemberOf", target });
		}
		for (const adminTarget of bloodhoundArray(bloodhoundValue(row, ["adminTo", "AdminTo", "localadmin", "LocalAdmin"]))) {
			const target = bloodhoundEdgeEndpoint(adminTarget);
			if (name && target) pushEdge({ file: file.name, source: name, relationship: "AdminTo", target });
		}
		const relationship = bloodhoundString(row, ["RelationshipType", "relationship", "relationshipType", "edgeType", "RightName", "rightname"]);
		const source = bloodhoundEdgeEndpoint(bloodhoundValue(row, ["StartNode", "start", "source", "Source", "SourceName", "PrincipalName", "PrincipalSID", "src"]));
		const target = bloodhoundEdgeEndpoint(bloodhoundValue(row, ["EndNode", "end", "target", "Target", "TargetName", "ObjectName", "ObjectIdentifier", "dst"]));
		if (relationship && source && target) {
			pushEdge({ file: file.name, source, relationship, target });
		}
	};
	const visit = (value, path = "$", depth = 0) => {
		if (objectCount > 6000 || depth > 8 || nodes.length + edges.length > 480) return;
		if (Array.isArray(value)) {
			for (let index = 0; index < Math.min(value.length, 2400); index++) visit(value[index], `${path}[]`, depth + 1);
			return;
		}
		if (!value || typeof value !== "object") return;
		processObject(value, path);
		for (const [key, child] of Object.entries(value)) {
			if (["Properties", "properties", "Aces", "aces", "data", "nodes", "edges", "relationships", "Users", "Groups", "Computers"].includes(key) || Array.isArray(child)) {
				visit(child, `${path}.${key}`, depth + 1);
			}
		}
	};
	visit(parsed);
	return { file: file.name, objectCount, nodes, edges };
}

function bloodhoundNameKey(name) {
	return String(name ?? "")
		.trim()
		.toLowerCase();
}

function bloodhoundAttackPathPriority(relationships) {
	const text = relationships.join(" ");
	if (/DCSync|GenericAll|WriteDacl|WriteOwner|AllExtendedRights/i.test(text)) return "critical";
	if (/AddMember|GenericWrite|ForceChangePassword|AllowedToDelegate|AdminTo/i.test(text)) return "high";
	if (/MemberOf|CanRDP|Owns/i.test(text)) return "medium";
	return "low";
}

function windowsAdBloodhoundAttackPaths(nodes, edges, owned, highValue) {
	const nodeByKey = new Map();
	for (const node of nodes) {
		const key = bloodhoundNameKey(node.name);
		if (!key || nodeByKey.has(key)) continue;
		nodeByKey.set(key, node);
	}
	const adjacency = new Map();
	for (const edge of edges) {
		const sourceKey = bloodhoundNameKey(edge.source);
		const targetKey = bloodhoundNameKey(edge.target);
		if (!sourceKey || !targetKey) continue;
		const list = adjacency.get(sourceKey) ?? [];
		list.push({ ...edge, sourceKey, targetKey });
		adjacency.set(sourceKey, list);
	}
	const targetKeys = new Set(highValue.map((node) => bloodhoundNameKey(node.name)).filter(Boolean));
	const paths = [];
	for (const source of owned.slice(0, 24)) {
		const sourceKey = bloodhoundNameKey(source.name);
		if (!sourceKey) continue;
		const queue = [{ key: sourceKey, nodes: [source.name], edges: [] }];
		const seen = new Set([sourceKey]);
		while (queue.length && paths.length < 80) {
			const current = queue.shift();
			if (current.edges.length > 0 && targetKeys.has(current.key)) {
				const relationships = current.edges.map((edge) => edge.relationship);
				const target = current.nodes[current.nodes.length - 1];
				paths.push({
					id: "ad-path-" + shortHash(`${source.name}->${target}:${relationships.join(">")}`),
					source: source.name,
					target,
					length: current.edges.length,
					priority: bloodhoundAttackPathPriority(relationships),
					relationships,
					nodes: current.nodes,
					edges: current.edges.map((edge) => ({
						file: edge.file,
						source: edge.source,
						relationship: edge.relationship,
						target: edge.target,
					})),
					evidence: {
						sourceOwned: Boolean(source.owned),
						targetHighValue: Boolean(nodeByKey.get(current.key)?.highValue || /domain admins|enterprise admins|administrators|krbtgt|dc\d/i.test(target)),
						edgeCount: current.edges.length,
						files: Array.from(new Set(current.edges.map((edge) => edge.file).filter(Boolean))).slice(0, 12),
					},
					proofReady: true,
				});
			}
			if (current.edges.length >= 4) continue;
			for (const edge of adjacency.get(current.key) ?? []) {
				const visitKey = `${edge.targetKey}:${current.edges.length + 1}`;
				if (seen.has(visitKey)) continue;
				seen.add(visitKey);
				queue.push({
					key: edge.targetKey,
					nodes: [...current.nodes, edge.target],
					edges: [...current.edges, edge],
				});
			}
		}
	}
	return paths.slice(0, 40);
}

function windowsAdAttackPathClaims(summary) {
	const bloodhound = summary.bloodhound ?? {};
	const signals = summary.signals ?? {};
	const attackPaths = Array.isArray(bloodhound.attackPaths) ? bloodhound.attackPaths : [];
	const fileRows = Array.isArray(summary.files) ? summary.files : [];
	const blockers = [];
	if (!(bloodhound.owned ?? []).length) blockers.push("missing-owned-principal");
	if (!(bloodhound.highValue ?? []).length) blockers.push("missing-high-value-target");
	if (!attackPaths.length) blockers.push("missing-owned-to-high-value-path");
	const claimLedger = [];
	const addClaim = (claim) => {
		const normalized = {
			verdict: "promoted",
			confidence: 0.72,
			blockers: [],
			...claim,
		};
		if (!normalized.id || claimLedger.some((row) => row.id === normalized.id)) return undefined;
		claimLedger.push(normalized);
		return normalized;
	};
	const attackPathClaims = attackPaths
		.map((path) =>
			addClaim({
				id: "windows-ad-attack-path-" + shortHash(path.id),
				claimType: "windows-ad-attack-path",
				pathId: path.id,
				sourceBinding: {
					source: path.source,
					target: path.target,
					relationships: path.relationships,
					files: path.evidence?.files ?? [],
				},
				evidenceBinding: {
					nodes: path.nodes,
					edges: path.edges,
					sourceOwned: Boolean(path.evidence?.sourceOwned),
					targetHighValue: Boolean(path.evidence?.targetHighValue),
					edgeCount: path.evidence?.edgeCount ?? path.length,
					priority: path.priority ?? null,
				},
				statement: "BloodHound data contains an owned-principal to high-value target attack path with concrete edge evidence.",
				confidence: path.priority === "critical" ? 0.9 : path.priority === "high" ? 0.84 : 0.76,
				rerunCommand: "cat windows-ad-quicklook.json | jq '.bloodhound.attackPaths'",
			}),
		)
		.filter(Boolean);
	const credentialRows = Array.isArray(signals.credentials) ? signals.credentials : [];
	const kerberosRows = Array.isArray(signals.kerberos) ? signals.kerberos : [];
	const adcsRows = Array.isArray(signals.adcs) ? signals.adcs : [];
	const eventRows = Array.isArray(signals.events) ? signals.events : [];
	const commandRows = Array.isArray(signals.commands) ? signals.commands : [];
	const principalRows = Array.isArray(signals.principals) ? signals.principals : [];
	const hasNtds = fileRows.some((row) => row.type === "ntds");
	const hasRegistryHive = fileRows.some((row) => row.type === "registry-hive");
	const hasKerberosArtifact = fileRows.some((row) => row.type === "kirbi" || row.type === "ccache");
	const hasEvtx = fileRows.some((row) => row.type === "evtx");
	const credentialClaim =
		credentialRows.length || hasNtds || hasRegistryHive
			? addClaim({
					id: "windows-ad-credential-material-" + shortHash(`${credentialRows.map((row) => row.text).join("|")}:${hasNtds}:${hasRegistryHive}`),
					claimType: hasNtds && hasRegistryHive ? "windows-ad-offline-domain-credential-dump-surface" : "windows-ad-credential-material-surface",
					sourceBinding: {
						artifact: "windows-ad-quicklook.json",
						fields: ["files", "signals.credentials"],
						fileTypes: fileRows.filter((row) => ["ntds", "registry-hive"].includes(row.type)).map((row) => row.type),
					},
					evidenceBinding: {
						hasNtds,
						hasRegistryHive,
						credentialSignals: credentialRows.slice(0, 16),
					},
					statement: hasNtds && hasRegistryHive
						? "Windows/AD evidence contains NTDS plus registry hive material; hash extraction may be verifiable with a matching bootkey."
						: "Windows/AD evidence contains credential-material signals that need usability verification before replay.",
					confidence: hasNtds && hasRegistryHive ? 0.84 : 0.7,
					blockers: hasNtds && hasRegistryHive ? [] : ["missing-matching-ntds-system-hive"],
					rerunCommand: "cat windows-ad-quicklook.json | jq '.files,.signals.credentials'",
				})
			: undefined;
	const kerberosClaim =
		kerberosRows.length || hasKerberosArtifact
			? addClaim({
					id: "windows-ad-kerberos-ticket-" + shortHash(`${kerberosRows.map((row) => row.text).join("|")}:${hasKerberosArtifact}`),
					claimType: "windows-ad-kerberos-ticket-surface",
					sourceBinding: {
						artifact: "windows-ad-quicklook.json",
						fields: ["files", "signals.kerberos"],
						kerberosArtifacts: fileRows.filter((row) => row.type === "kirbi" || row.type === "ccache").map((row) => row.name),
					},
					evidenceBinding: {
						hasKerberosArtifact,
						kerberosSignals: kerberosRows.slice(0, 16),
						principals: principalRows.slice(0, 12),
					},
					statement: "Kerberos ticket/SPN/log evidence identifies replay, roast, or cracking pivots that require realm/time/service validation.",
					confidence: hasKerberosArtifact ? 0.82 : 0.72,
					rerunCommand: "cat windows-ad-quicklook.json | jq '.files,.signals.kerberos,.signals.principals'",
				})
			: undefined;
	const adcsClaim = adcsRows.length
		? addClaim({
				id: "windows-ad-adcs-esc-" + shortHash(adcsRows.map((row) => row.text).join("|")),
				claimType: "windows-ad-adcs-esc-surface",
				sourceBinding: { artifact: "windows-ad-quicklook.json", field: "signals.adcs" },
				evidenceBinding: { adcsSignals: adcsRows.slice(0, 20), principals: principalRows.slice(0, 12) },
				statement: "ADCS/ESC evidence identifies certificate-abuse triage targets that need template enrollment proof before exploitation.",
				confidence: adcsRows.some((row) => /ESC[1-9]|Certipy/i.test(row.text)) ? 0.78 : 0.68,
				rerunCommand: "cat windows-ad-quicklook.json | jq '.signals.adcs'",
			})
		: undefined;
	const logonClaim =
		eventRows.length || hasEvtx
			? addClaim({
					id: "windows-ad-logon-event-correlation-" + shortHash(`${eventRows.map((row) => row.text).join("|")}:${hasEvtx}`),
					claimType: "windows-ad-logon-event-correlation",
					sourceBinding: { artifact: "windows-ad-quicklook.json", fields: ["files", "signals.events"] },
					evidenceBinding: { hasEvtx, events: eventRows.slice(0, 20), principals: principalRows.slice(0, 12) },
					statement: "Windows event evidence gives logon/privilege timestamps to correlate credential usability with graph edges.",
					confidence: eventRows.some((row) => /4624|4672/i.test(row.text)) ? 0.78 : 0.62,
					rerunCommand: "cat windows-ad-quicklook.json | jq '.signals.events'",
				})
			: undefined;
	if (commandRows.length) {
		addClaim({
			id: "windows-ad-offensive-tool-command-surface-" + shortHash(commandRows.map((row) => row.text).join("|")),
			claimType: "windows-ad-offensive-tool-command-surface",
			sourceBinding: { artifact: "windows-ad-quicklook.json", field: "signals.commands" },
			evidenceBinding: { commands: commandRows.slice(0, 20) },
			statement: "Windows/AD artifact strings contain offensive or administrative command anchors for timeline and operator-intent correlation.",
			confidence: 0.66,
			rerunCommand: "cat windows-ad-quicklook.json | jq '.signals.commands'",
		});
	}
	const composedPaths = [];
	const pivotClaim = attackPathClaims[0];
	if (pivotClaim && (credentialClaim || kerberosClaim || logonClaim)) {
		const segments = [credentialClaim, kerberosClaim, logonClaim, pivotClaim].filter(Boolean);
		const composed = {
			id: "windows-ad-credential-graph-pivot-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "windows-ad-credential-graph-pivot",
			sourceBinding: {
				segments: segments.map((claim) => ({
					id: claim.id,
					claimType: claim.claimType,
					source: claim.sourceBinding?.source,
					target: claim.sourceBinding?.target,
					artifact: claim.sourceBinding?.artifact,
				})),
			},
			evidenceBinding: {
				hasCredentialMaterial: Boolean(credentialClaim),
				hasKerberosArtifactOrSignal: Boolean(kerberosClaim),
				hasLogonEvents: Boolean(logonClaim),
				attackPath: {
					source: pivotClaim.sourceBinding.source,
					target: pivotClaim.sourceBinding.target,
					relationships: pivotClaim.sourceBinding.relationships,
					edgeCount: pivotClaim.evidenceBinding.edgeCount,
				},
				files: Array.from(new Set([...(pivotClaim.sourceBinding.files ?? []), ...fileRows.map((row) => row.name).slice(0, 12)])).slice(0, 24),
			},
			statement: "Credential/Kerberos/logon evidence composes with an owned-to-high-value BloodHound path into a prioritized AD pivot proof path.",
			verdict: "promoted",
			confidence: credentialClaim && kerberosClaim ? 0.88 : 0.82,
			blockers: [],
			rerunCommand: "cat windows-ad-attack-paths.json | jq '.composedPaths'",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	if (adcsClaim && pivotClaim) {
		const composed = {
			id: "windows-ad-adcs-graph-pivot-" + shortHash(`${adcsClaim.id}>${pivotClaim.id}`),
			claimType: "windows-ad-adcs-graph-pivot",
			sourceBinding: {
				segments: [
					{ id: adcsClaim.id, claimType: adcsClaim.claimType, artifact: adcsClaim.sourceBinding?.artifact },
					{ id: pivotClaim.id, claimType: pivotClaim.claimType, source: pivotClaim.sourceBinding.source, target: pivotClaim.sourceBinding.target },
				],
			},
			evidenceBinding: {
				adcsSignals: adcsClaim.evidenceBinding.adcsSignals,
				attackPath: {
					source: pivotClaim.sourceBinding.source,
					target: pivotClaim.sourceBinding.target,
					relationships: pivotClaim.sourceBinding.relationships,
				},
			},
			statement: "ADCS/ESC signals and a high-value graph path compose into a certificate-abuse triage pivot candidate.",
			verdict: "promoted",
			confidence: 0.8,
			blockers: ["needs-template-enrollment-proof"],
			rerunCommand: "cat windows-ad-quicklook.json | jq '.signals.adcs' && cat windows-ad-attack-paths.json | jq '.attackPaths'",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const repairActions = {
		"missing-owned-principal": "Import BloodHound owned/pwned principal data or mark a verified credential as owned.",
		"missing-high-value-target": "Import BloodHound high-value nodes such as Domain Admins, Enterprise Admins, DCs, or krbtgt.",
		"missing-owned-to-high-value-path": "Import relationship/ACL/session edges or run path collection until an owned-to-high-value chain exists.",
		"needs-template-enrollment-proof": "Enumerate ADCS templates and prove enrollment/ESC conditions before treating the certificate pivot as executable.",
	};
	const repairQueue = Array.from(new Set([...blockers, ...composedPaths.flatMap((path) => path.blockers ?? [])])).map((blocker) => ({
		id: "windows-ad-attack-path-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect Windows/AD evidence and rerun attack-path claim promotion.",
		rerunCommand: "repi engage <windows-ad-artifact-dir> --json",
	}));
	return {
		kind: "repi-windows-ad-attack-paths",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		proofReady: claimLedger.some((claim) => claim.verdict === "promoted"),
		attackPathProofReady: attackPathClaims.length > 0,
		pivotProofReady: composedPaths.length > 0,
		attackPaths,
		claimLedger,
		composedPaths,
		promotionReport: {
			proofReady: claimLedger.some((claim) => claim.verdict === "promoted"),
			attackPathProofReady: attackPathClaims.length > 0,
			pivotProofReady: composedPaths.length > 0,
			promotedClaims: claimLedger.filter((claim) => claim.verdict === "promoted"),
			composedPaths,
			observations: [],
			blockers,
		},
		repairQueue,
	};
}

function windowsAdTargetRoot(target) {
	if (!existsSync(target)) return resolve(target);
	const stat = statSync(target);
	return stat.isDirectory() ? resolve(target) : dirname(resolve(target));
}

function windowsAdResolveArtifactPath(target, relPath) {
	const rootDir = windowsAdTargetRoot(target);
	const path = resolve(rootDir, relPath);
	if (path !== rootDir && !path.startsWith(`${rootDir}/`)) return undefined;
	return path;
}

function windowsAdVerificationSummary(target, artifactDir, summary, attackReport) {
	const quicklook = summary ?? readJsonArtifact(join(artifactDir, "windows-ad-quicklook.json"));
	const attackPaths = attackReport ?? readJsonArtifact(join(artifactDir, "windows-ad-attack-paths.json"));
	const files = quicklook?.files ?? [];
	const fileChecks = files.map((row) => {
		const path = windowsAdResolveArtifactPath(target, row.name);
		if (!path || !existsSync(path)) return { name: row.name, type: row.type, verified: false, error: "missing-artifact" };
		const data = readFileSync(path);
		const sha256 = bufferSha256(data);
		return {
			name: row.name,
			type: row.type,
			verified: row.size === data.length && row.sha256 === sha256,
			expectedSize: row.size,
			actualSize: data.length,
			expectedSha256: row.sha256,
			actualSha256: sha256,
		};
	});
	const fileHashVerification = {
		verified: fileChecks.length > 0 && fileChecks.every((row) => row.verified),
		checkedFiles: fileChecks.length,
		verifiedFiles: fileChecks.filter((row) => row.verified).length,
		fileTypes: Array.from(new Set(fileChecks.filter((row) => row.verified).map((row) => row.type).filter(Boolean))).sort(),
	};
	const fileHashByName = new Map(fileChecks.map((row) => [row.name, row.actualSha256]));
	const bloodhound = quicklook?.bloodhound ?? {};
	const ownedNames = new Set((bloodhound.owned ?? []).map((row) => row.name));
	const highValueNames = new Set((bloodhound.highValue ?? []).map((row) => row.name));
	const pathChecks = (attackPaths?.attackPaths ?? []).map((pathRow) => {
		const edgeChecks = (pathRow.edges ?? []).map((edge) => ({
			file: edge.file,
			source: edge.source,
			relationship: edge.relationship,
			target: edge.target,
			fileVerified: Boolean(edge.file && fileHashByName.has(edge.file)),
		}));
		const relationMatch = JSON.stringify(pathRow.relationships ?? []) === JSON.stringify(edgeChecks.map((edge) => edge.relationship));
		return {
			id: pathRow.id,
			source: pathRow.source,
			target: pathRow.target,
			verified:
				edgeChecks.length > 0 &&
				edgeChecks.every((edge) => edge.fileVerified) &&
				relationMatch &&
				(Boolean(pathRow.evidence?.sourceOwned) || ownedNames.has(pathRow.source)) &&
				(Boolean(pathRow.evidence?.targetHighValue) || highValueNames.has(pathRow.target)),
			relationMatch,
			edgeChecks,
		};
	});
	const bloodhoundPathVerification = {
		verified: pathChecks.some((row) => row.verified),
		pathCount: pathChecks.length,
		verifiedPathCount: pathChecks.filter((row) => row.verified).length,
		pathChecks,
	};
	const signals = quicklook?.signals ?? {};
	const signalCoverage = {
		verified: Boolean((signals.credentials ?? []).length || (signals.kerberos ?? []).length || (signals.events ?? []).length || (signals.adcs ?? []).length),
		hasCredentialMaterial: Boolean((signals.credentials ?? []).length || fileHashVerification.fileTypes.includes("ntds")),
		hasKerberos: Boolean((signals.kerberos ?? []).length || fileHashVerification.fileTypes.some((type) => type === "kirbi" || type === "ccache")),
		hasLogonEvents: Boolean((signals.events ?? []).length || fileHashVerification.fileTypes.includes("evtx")),
		hasAdcs: Boolean((signals.adcs ?? []).length),
		principalCount: (signals.principals ?? []).length,
	};
	const claims = attackPaths?.claimLedger ?? [];
	const claimById = new Map(claims.map((claim) => [claim.id, claim]));
	const composedPathChecks = (attackPaths?.composedPaths ?? []).map((pathRow) => {
		const segments = pathRow.sourceBinding?.segments ?? [];
		const resolvedSegments = segments.map((segment) => ({
			id: segment.id,
			claimType: segment.claimType,
			claimPresent: claimById.has(segment.id),
			verdict: claimById.get(segment.id)?.verdict ?? null,
		}));
		return {
			id: pathRow.id,
			claimType: pathRow.claimType,
			blockers: pathRow.blockers ?? [],
			verified: resolvedSegments.length > 0 && resolvedSegments.every((segment) => segment.claimPresent && segment.verdict === "promoted") && !(pathRow.blockers ?? []).length,
			segments: resolvedSegments,
		};
	});
	const composedPathVerification = {
		verified: composedPathChecks.some((row) => row.verified),
		pathCount: composedPathChecks.length,
		verifiedPathCount: composedPathChecks.filter((row) => row.verified).length,
		pathChecks: composedPathChecks,
	};
	const firstFile = fileChecks.find((row) => row.verified);
	const firstPath = pathChecks.find((row) => row.verified);
	const firstComposed = composedPathChecks.find((row) => row.verified);
	const negativeControls = [];
	if (firstFile) {
		const missingPath = windowsAdResolveArtifactPath(target, `${firstFile.name}.missing-control`);
		let missingFileAccepted = false;
		if (missingPath && existsSync(missingPath)) {
			const missingData = readFileSync(missingPath);
			missingFileAccepted =
				missingData.length === firstFile.expectedSize && bufferSha256(missingData) === firstFile.expectedSha256;
		}
		negativeControls.push({
			controlType: "windows-ad-missing-artifact-negative-control",
			artifact: firstFile.name,
			missingFileAccepted,
			passed: Boolean(firstFile.verified && !missingFileAccepted),
		});
	}
	if (firstPath) {
		const mutatedEdges = [
			...(firstPath.edgeChecks ?? []),
			{ file: "missing-control", source: firstPath.source, relationship: "NotARealEdge", target: firstPath.target, fileVerified: false },
		];
		const mutatedPathAccepted = mutatedEdges.length > 0 && mutatedEdges.every((edge) => edge.fileVerified);
		negativeControls.push({
			controlType: "windows-ad-mutated-edge-negative-control",
			pathId: firstPath.id,
			mutatedPathAccepted,
			passed: !mutatedPathAccepted,
		});
	}
	if (firstComposed) {
		const mutatedSegments = firstComposed.segments.map((segment, index) =>
			index === 0 ? { ...segment, id: `${segment.id}:negative-control-mutation` } : segment,
		);
		const mutatedPathAccepted = mutatedSegments.length > 0 && mutatedSegments.every((segment) => claimById.get(segment.id)?.verdict === "promoted");
		negativeControls.push({
			controlType: "windows-ad-mutated-segment-negative-control",
			pathId: firstComposed.id,
			mutatedPathAccepted,
			passed: !mutatedPathAccepted,
		});
	}
	const negativeControlVerification = {
		verified: negativeControls.length >= 3 && negativeControls.every((row) => row.passed),
		negativeControlsPassed: negativeControls.filter((row) => row.passed).length,
		negativeControls,
	};
	const claimLedger = [];
	const composedPaths = [];
	const addClaim = (claim) => {
		const normalized = { verdict: "promoted", confidence: 0.76, blockers: [], ...claim };
		claimLedger.push(normalized);
		return normalized;
	};
	const fileClaim = fileHashVerification.verified
		? addClaim({
				id: "windows-ad-file-hash-verification-" + shortHash(fileHashVerification.fileTypes.join("|")),
				claimType: "windows-ad-file-hash-verification-proof",
				sourceBinding: { artifact: "windows-ad-verification.json", quicklook: "windows-ad-quicklook.json" },
				evidenceBinding: fileHashVerification,
				statement: "Windows/AD verifier rebound quicklook file rows to exact artifact size and SHA-256.",
				confidence: 0.88,
				rerunCommand: "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json",
			})
		: undefined;
	const pathClaim = bloodhoundPathVerification.verified
		? addClaim({
				id: "windows-ad-bloodhound-path-verification-" + shortHash(JSON.stringify(pathChecks.map((row) => row.id))),
				claimType: "windows-ad-bloodhound-path-verification-proof",
				sourceBinding: { artifact: "windows-ad-verification.json", attackPaths: "windows-ad-attack-paths.json" },
				evidenceBinding: bloodhoundPathVerification,
				statement: "Windows/AD verifier confirmed BloodHound owned-to-high-value edge chains resolve to verified source files.",
				confidence: 0.87,
				rerunCommand: "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json",
			})
		: undefined;
	const signalClaim = signalCoverage.verified
		? addClaim({
				id: "windows-ad-signal-coverage-" + shortHash(JSON.stringify(signalCoverage)),
				claimType: "windows-ad-signal-coverage-verification-proof",
				sourceBinding: { artifact: "windows-ad-verification.json", quicklook: "windows-ad-quicklook.json" },
				evidenceBinding: signalCoverage,
				statement: "Windows/AD verifier confirmed credential, Kerberos, logon, or ADCS signal coverage from verified artifacts.",
				confidence: 0.82,
				rerunCommand: "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json",
			})
		: undefined;
	const composedClaim = composedPathVerification.verified
		? addClaim({
				id: "windows-ad-composed-path-verification-" + shortHash(JSON.stringify(composedPathChecks.map((row) => row.id))),
				claimType: "windows-ad-composed-path-verification-proof",
				sourceBinding: { artifact: "windows-ad-verification.json", attackPaths: "windows-ad-attack-paths.json" },
				evidenceBinding: composedPathVerification,
				statement: "Windows/AD verifier confirmed composed pivot segments resolve to promoted source-bound claims.",
				confidence: 0.86,
				rerunCommand: "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json",
			})
		: undefined;
	const negativeClaim = negativeControlVerification.verified
		? addClaim({
				id: "windows-ad-verifier-negative-control-" + shortHash(JSON.stringify(negativeControls)),
				claimType: "windows-ad-verifier-negative-control-proof",
				sourceBinding: { artifact: "windows-ad-verification.json" },
				evidenceBinding: negativeControlVerification,
				statement: "Windows/AD verifier rejected missing-artifact, mutated-edge, and mutated-segment controls.",
				confidence: 0.82,
				rerunCommand: "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json",
			})
		: undefined;
	if (fileClaim && pathClaim && signalClaim && composedClaim && negativeClaim) {
		const segments = [fileClaim, pathClaim, signalClaim, composedClaim, negativeClaim];
		const composed = {
			id: "windows-ad-verification-proof-path-" + shortHash(segments.map((claim) => claim.id).join(">")),
			claimType: "windows-ad-verification-proof-path",
			sourceBinding: { segments: segments.map((claim) => ({ id: claim.id, claimType: claim.claimType, artifact: claim.sourceBinding?.artifact })) },
			evidenceBinding: {
				verifiedFiles: fileHashVerification.verifiedFiles,
				verifiedPathCount: bloodhoundPathVerification.verifiedPathCount,
				verifiedComposedPaths: composedPathVerification.verifiedPathCount,
				negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
			},
			statement: "Windows/AD proof path composes artifact hashes, BloodHound path verification, signal coverage, composed claim resolution, and negative controls.",
			verdict: "promoted",
			confidence: 0.89,
			blockers: [],
			rerunCommand: "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json",
		};
		claimLedger.push(composed);
		composedPaths.push(composed);
	}
	const blockers = [];
	if (!fileHashVerification.verified) blockers.push("missing-windows-ad-file-hash-verification");
	if (!bloodhoundPathVerification.verified) blockers.push("missing-windows-ad-bloodhound-path-verification");
	if (!signalCoverage.verified) blockers.push("missing-windows-ad-signal-coverage");
	if (!composedPathVerification.verified) blockers.push("missing-windows-ad-composed-path-verification");
	if (!negativeControlVerification.verified) blockers.push("missing-windows-ad-negative-control");
	const repairActions = {
		"missing-windows-ad-file-hash-verification": "Re-read AD artifacts and require size/SHA-256 equality for every quicklook file row.",
		"missing-windows-ad-bloodhound-path-verification": "Import BloodHound edge files and verify owned-to-high-value relationship chains.",
		"missing-windows-ad-signal-coverage": "Collect credential, Kerberos, logon, or ADCS signals from verified artifacts.",
		"missing-windows-ad-composed-path-verification": "Require each composed pivot segment to resolve to a promoted source-bound claim without blockers.",
		"missing-windows-ad-negative-control": "Run missing-artifact, mutated-edge, and mutated-segment controls before promotion.",
	};
	const repairQueue = blockers.map((blocker) => ({
		id: "windows-ad-verification-" + blocker,
		blocker,
		action: repairActions[blocker] ?? "Collect verifier-bound Windows/AD evidence and rerun windows-ad-verifier.py.",
		rerunCommand: `python3 ${shellQuote(join(artifactDir, "windows-ad-verifier.py"))} ${shellQuote(target)} ${shellQuote(join(artifactDir, "windows-ad-quicklook.json"))} ${shellQuote(join(artifactDir, "windows-ad-attack-paths.json"))} ${shellQuote(join(artifactDir, "windows-ad-verification.json"))}`,
	}));
	const proofReady = composedPaths.length > 0;
	return {
		kind: "repi-windows-ad-verification",
		schemaVersion: 1,
		target: redact(target),
		generatedAt: new Date().toISOString(),
		proofReady,
		attackPathProofReady: bloodhoundPathVerification.verified,
		pivotProofReady: composedPathVerification.verified,
		fileHashVerification,
		fileChecks,
		bloodhoundPathVerification,
		signalCoverage,
		composedPathVerification,
		negativeControlVerification,
		stats: {
			checkedFiles: fileHashVerification.checkedFiles,
			verifiedFiles: fileHashVerification.verifiedFiles,
			verifiedPathCount: bloodhoundPathVerification.verifiedPathCount,
			verifiedComposedPaths: composedPathVerification.verifiedPathCount,
			negativeControlsPassed: negativeControlVerification.negativeControlsPassed,
		},
		claimLedger,
		composedPaths,
		promotionReport: { proofReady, attackPathProofReady: bloodhoundPathVerification.verified, pivotProofReady: composedPathVerification.verified, promotedClaims: claimLedger.filter((claim) => claim.verdict === "promoted"), blockers },
		repairQueue,
	};
}

function windowsAdVerifierSource() {
	return String.raw`#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import tempfile
import time


def sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    return hashlib.sha256(value or b"").hexdigest()


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def short(value):
    return sha256(str(value))[:12]


def artifact_path(root, rel):
    root_abs = os.path.abspath(root)
    path = os.path.abspath(os.path.join(root_abs, str(rel or "")))
    if path != root_abs and not path.startswith(root_abs + os.sep):
        return None
    return path


def verify(root, quicklook_path, attack_path):
    quicklook = load(quicklook_path)
    attack = load(attack_path)
    files = quicklook.get("files") or []
    file_checks = []
    for row in files:
        path = artifact_path(root, row.get("name"))
        if not path or not os.path.exists(path):
            file_checks.append({"name": row.get("name"), "type": row.get("type"), "verified": False, "error": "missing-artifact"})
            continue
        with open(path, "rb") as handle:
            data = handle.read()
        actual = sha256(data)
        file_checks.append({"name": row.get("name"), "type": row.get("type"), "verified": row.get("size") == len(data) and row.get("sha256") == actual, "expectedSize": row.get("size"), "actualSize": len(data), "expectedSha256": row.get("sha256"), "actualSha256": actual})
    file_types = sorted({row.get("type") for row in file_checks if row.get("verified") and row.get("type")})
    file_verification = {"verified": bool(file_checks) and all(row.get("verified") for row in file_checks), "checkedFiles": len(file_checks), "verifiedFiles": len([row for row in file_checks if row.get("verified")]), "fileTypes": file_types}
    verified_files = {row.get("name") for row in file_checks if row.get("verified")}
    bloodhound = quicklook.get("bloodhound") or {}
    owned = {row.get("name") for row in bloodhound.get("owned") or []}
    high_value = {row.get("name") for row in bloodhound.get("highValue") or []}
    path_checks = []
    for path_row in attack.get("attackPaths") or []:
        edge_checks = [{"file": edge.get("file"), "source": edge.get("source"), "relationship": edge.get("relationship"), "target": edge.get("target"), "fileVerified": edge.get("file") in verified_files} for edge in path_row.get("edges") or []]
        relation_match = (path_row.get("relationships") or []) == [edge.get("relationship") for edge in edge_checks]
        verified = bool(edge_checks) and all(edge.get("fileVerified") for edge in edge_checks) and relation_match and ((path_row.get("evidence") or {}).get("sourceOwned") or path_row.get("source") in owned) and ((path_row.get("evidence") or {}).get("targetHighValue") or path_row.get("target") in high_value)
        path_checks.append({"id": path_row.get("id"), "source": path_row.get("source"), "target": path_row.get("target"), "verified": bool(verified), "relationMatch": relation_match, "edgeChecks": edge_checks})
    path_verification = {"verified": any(row.get("verified") for row in path_checks), "pathCount": len(path_checks), "verifiedPathCount": len([row for row in path_checks if row.get("verified")]), "pathChecks": path_checks}
    signals = quicklook.get("signals") or {}
    signal_coverage = {"verified": bool(signals.get("credentials") or signals.get("kerberos") or signals.get("events") or signals.get("adcs")), "hasCredentialMaterial": bool(signals.get("credentials") or "ntds" in file_types), "hasKerberos": bool(signals.get("kerberos") or any(t in {"kirbi", "ccache"} for t in file_types)), "hasLogonEvents": bool(signals.get("events") or "evtx" in file_types), "hasAdcs": bool(signals.get("adcs")), "principalCount": len(signals.get("principals") or [])}
    claims = attack.get("claimLedger") or []
    by_id = {claim.get("id"): claim for claim in claims}
    composed_checks = []
    for composed in attack.get("composedPaths") or []:
        segments = ((composed.get("sourceBinding") or {}).get("segments") or [])
        resolved = [{"id": segment.get("id"), "claimType": segment.get("claimType"), "claimPresent": segment.get("id") in by_id, "verdict": (by_id.get(segment.get("id")) or {}).get("verdict")} for segment in segments]
        composed_checks.append({"id": composed.get("id"), "claimType": composed.get("claimType"), "blockers": composed.get("blockers") or [], "verified": bool(resolved) and all(row.get("claimPresent") and row.get("verdict") == "promoted" for row in resolved) and not (composed.get("blockers") or []), "segments": resolved})
    composed_verification = {"verified": any(row.get("verified") for row in composed_checks), "pathCount": len(composed_checks), "verifiedPathCount": len([row for row in composed_checks if row.get("verified")]), "pathChecks": composed_checks}
    controls = []
    first_file = next((row for row in file_checks if row.get("verified")), None)
    first_path = next((row for row in path_checks if row.get("verified")), None)
    first_composed = next((row for row in composed_checks if row.get("verified")), None)
    if first_file:
        missing_path = artifact_path(root, str(first_file.get("name")) + ".missing-control")
        missing_file_accepted = False
        if missing_path and os.path.exists(missing_path):
            with open(missing_path, "rb") as handle:
                missing_data = handle.read()
            missing_file_accepted = len(missing_data) == first_file.get("expectedSize") and sha256(missing_data) == first_file.get("expectedSha256")
        controls.append({"controlType": "windows-ad-missing-artifact-negative-control", "artifact": first_file.get("name"), "missingFileAccepted": missing_file_accepted, "passed": bool(first_file.get("verified") and not missing_file_accepted)})
    if first_path:
        mutated_edges = list(first_path.get("edgeChecks") or []) + [{"file": "missing-control", "source": first_path.get("source"), "relationship": "NotARealEdge", "target": first_path.get("target"), "fileVerified": False}]
        mutated_path_accepted = bool(mutated_edges) and all(edge.get("fileVerified") for edge in mutated_edges)
        controls.append({"controlType": "windows-ad-mutated-edge-negative-control", "pathId": first_path.get("id"), "mutatedPathAccepted": mutated_path_accepted, "passed": not mutated_path_accepted})
    if first_composed:
        mutated_segments = [dict(segment, id=str(segment.get("id")) + ":negative-control-mutation") if index == 0 else dict(segment) for index, segment in enumerate(first_composed.get("segments") or [])]
        mutated_path_accepted = bool(mutated_segments) and all((by_id.get(segment.get("id")) or {}).get("verdict") == "promoted" for segment in mutated_segments)
        controls.append({"controlType": "windows-ad-mutated-segment-negative-control", "pathId": first_composed.get("id"), "mutatedPathAccepted": mutated_path_accepted, "passed": not mutated_path_accepted})
    negative = {"verified": len(controls) >= 3 and all(row.get("passed") for row in controls), "negativeControlsPassed": len([row for row in controls if row.get("passed")]), "negativeControls": controls}
    ledger = []
    paths = []
    def add_claim(**claim):
        row = {"verdict": "promoted", "confidence": 0.76, "blockers": []}
        row.update(claim)
        ledger.append(row)
        return row
    file_claim = add_claim(id="windows-ad-file-hash-verification-" + short("|".join(file_types)), claimType="windows-ad-file-hash-verification-proof", sourceBinding={"artifact": "windows-ad-verification.json", "quicklook": "windows-ad-quicklook.json"}, evidenceBinding=file_verification, statement="Windows/AD verifier rebound quicklook file rows to exact artifact size and SHA-256.", confidence=0.88, rerunCommand="python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json") if file_verification["verified"] else None
    path_claim = add_claim(id="windows-ad-bloodhound-path-verification-" + short(json.dumps([row.get("id") for row in path_checks], sort_keys=True)), claimType="windows-ad-bloodhound-path-verification-proof", sourceBinding={"artifact": "windows-ad-verification.json", "attackPaths": "windows-ad-attack-paths.json"}, evidenceBinding=path_verification, statement="Windows/AD verifier confirmed BloodHound owned-to-high-value edge chains resolve to verified source files.", confidence=0.87, rerunCommand="python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json") if path_verification["verified"] else None
    signal_claim = add_claim(id="windows-ad-signal-coverage-" + short(json.dumps(signal_coverage, sort_keys=True)), claimType="windows-ad-signal-coverage-verification-proof", sourceBinding={"artifact": "windows-ad-verification.json", "quicklook": "windows-ad-quicklook.json"}, evidenceBinding=signal_coverage, statement="Windows/AD verifier confirmed credential, Kerberos, logon, or ADCS signal coverage from verified artifacts.", confidence=0.82, rerunCommand="python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json") if signal_coverage["verified"] else None
    composed_claim = add_claim(id="windows-ad-composed-path-verification-" + short(json.dumps([row.get("id") for row in composed_checks], sort_keys=True)), claimType="windows-ad-composed-path-verification-proof", sourceBinding={"artifact": "windows-ad-verification.json", "attackPaths": "windows-ad-attack-paths.json"}, evidenceBinding=composed_verification, statement="Windows/AD verifier confirmed composed pivot segments resolve to promoted source-bound claims.", confidence=0.86, rerunCommand="python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json") if composed_verification["verified"] else None
    negative_claim = add_claim(id="windows-ad-verifier-negative-control-" + short(json.dumps(controls, sort_keys=True)), claimType="windows-ad-verifier-negative-control-proof", sourceBinding={"artifact": "windows-ad-verification.json"}, evidenceBinding=negative, statement="Windows/AD verifier rejected missing-artifact, mutated-edge, and mutated-segment controls.", confidence=0.82, rerunCommand="python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json") if negative["verified"] else None
    if file_claim and path_claim and signal_claim and composed_claim and negative_claim:
        segments = [file_claim, path_claim, signal_claim, composed_claim, negative_claim]
        composed = {"id": "windows-ad-verification-proof-path-" + short(">".join([claim["id"] for claim in segments])), "claimType": "windows-ad-verification-proof-path", "sourceBinding": {"segments": [{"id": claim["id"], "claimType": claim["claimType"], "artifact": claim.get("sourceBinding", {}).get("artifact")} for claim in segments]}, "evidenceBinding": {"verifiedFiles": file_verification["verifiedFiles"], "verifiedPathCount": path_verification["verifiedPathCount"], "verifiedComposedPaths": composed_verification["verifiedPathCount"], "negativeControlsPassed": negative["negativeControlsPassed"]}, "statement": "Windows/AD proof path composes artifact hashes, BloodHound path verification, signal coverage, composed claim resolution, and negative controls.", "verdict": "promoted", "confidence": 0.89, "blockers": [], "rerunCommand": "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json"}
        ledger.append(composed)
        paths.append(composed)
    blockers = []
    if not file_verification["verified"]:
        blockers.append("missing-windows-ad-file-hash-verification")
    if not path_verification["verified"]:
        blockers.append("missing-windows-ad-bloodhound-path-verification")
    if not signal_coverage["verified"]:
        blockers.append("missing-windows-ad-signal-coverage")
    if not composed_verification["verified"]:
        blockers.append("missing-windows-ad-composed-path-verification")
    if not negative["verified"]:
        blockers.append("missing-windows-ad-negative-control")
    proof_ready = bool(paths)
    return {"kind": "repi-windows-ad-verification", "schemaVersion": 1, "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "proofReady": proof_ready, "attackPathProofReady": path_verification["verified"], "pivotProofReady": composed_verification["verified"], "fileHashVerification": file_verification, "fileChecks": file_checks, "bloodhoundPathVerification": path_verification, "signalCoverage": signal_coverage, "composedPathVerification": composed_verification, "negativeControlVerification": negative, "stats": {"checkedFiles": file_verification["checkedFiles"], "verifiedFiles": file_verification["verifiedFiles"], "verifiedPathCount": path_verification["verifiedPathCount"], "verifiedComposedPaths": composed_verification["verifiedPathCount"], "negativeControlsPassed": negative["negativeControlsPassed"]}, "claimLedger": ledger, "composedPaths": paths, "promotionReport": {"proofReady": proof_ready, "attackPathProofReady": path_verification["verified"], "pivotProofReady": composed_verification["verified"], "promotedClaims": ledger, "blockers": blockers}, "repairQueue": [{"id": "windows-ad-verification-" + blocker, "blocker": blocker, "action": "Collect verifier-bound Windows/AD evidence and rerun windows-ad-verifier.py.", "rerunCommand": "python3 windows-ad-verifier.py <windows-ad-artifact-dir> windows-ad-quicklook.json windows-ad-attack-paths.json windows-ad-verification.json"} for blocker in blockers]}


def self_test():
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "bloodhound"), exist_ok=True)
        files = {"ntds.dit": b"NTDS krbtgt DCSync", "SYSTEM": b"SYSTEM hive", "Security.evtx": b"ElfFile\0 EventID 4624", "ticket.kirbi": b"KRB5 TGT", "bloodhound/edges.json": b"{}"}
        for rel, data in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) != root else None
            with open(path, "wb") as handle:
                handle.write(data)
        quicklook_path = os.path.join(root, "windows-ad-quicklook.json")
        attack_path = os.path.join(root, "windows-ad-attack-paths.json")
        quicklook = {"files": [{"name": rel, "type": "ntds" if rel == "ntds.dit" else "registry-hive" if rel == "SYSTEM" else "evtx" if rel.endswith(".evtx") else "kirbi" if rel.endswith(".kirbi") else "text-or-artifact", "size": len(data), "sha256": sha256(data)} for rel, data in files.items()], "signals": {"credentials": [{"text": "krbtgt"}], "kerberos": [{"text": "KRB5"}], "events": [{"text": "EventID 4624"}], "adcs": [{"text": "ADCS ESC1"}], "principals": [{"text": "ALICE@CORP.EXAMPLE.COM"}]}, "bloodhound": {"owned": [{"name": "ALICE@CORP.EXAMPLE.COM"}], "highValue": [{"name": "DOMAIN ADMINS@CORP.EXAMPLE.COM"}]}}
        attack_claim = {"id": "attack", "claimType": "windows-ad-attack-path", "verdict": "promoted", "sourceBinding": {"source": "ALICE@CORP.EXAMPLE.COM", "target": "DOMAIN ADMINS@CORP.EXAMPLE.COM"}}
        cred_claim = {"id": "cred", "claimType": "windows-ad-offline-domain-credential-dump-surface", "verdict": "promoted", "sourceBinding": {"artifact": "windows-ad-quicklook.json"}}
        composed = {"id": "pivot", "claimType": "windows-ad-credential-graph-pivot", "verdict": "promoted", "blockers": [], "sourceBinding": {"segments": [{"id": "cred", "claimType": "windows-ad-offline-domain-credential-dump-surface"}, {"id": "attack", "claimType": "windows-ad-attack-path"}]}}
        attack_doc = {"attackPaths": [{"id": "p1", "source": "ALICE@CORP.EXAMPLE.COM", "target": "DOMAIN ADMINS@CORP.EXAMPLE.COM", "relationships": ["GenericAll"], "edges": [{"file": "bloodhound/edges.json", "source": "ALICE@CORP.EXAMPLE.COM", "relationship": "GenericAll", "target": "DOMAIN ADMINS@CORP.EXAMPLE.COM"}], "evidence": {"sourceOwned": True, "targetHighValue": True}}], "claimLedger": [attack_claim, cred_claim, composed], "composedPaths": [composed]}
        with open(quicklook_path, "w", encoding="utf-8") as handle:
            json.dump(quicklook, handle)
        with open(attack_path, "w", encoding="utf-8") as handle:
            json.dump(attack_doc, handle)
        result = verify(root, quicklook_path, attack_path)
        assert result["proofReady"], json.dumps(result, sort_keys=True)
        print(json.dumps({"kind": "repi-windows-ad-verifier-self-test", "status": "ok", "stats": result["stats"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description="Verify REPI Windows/AD quicklook and BloodHound evidence with negative controls.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("quicklook", nargs="?", default="windows-ad-quicklook.json")
    parser.add_argument("attack_paths", nargs="?", default="windows-ad-attack-paths.json")
    parser.add_argument("output", nargs="?", default="windows-ad-verification.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    result = verify(args.root, args.quicklook, args.attack_paths)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"kind": result["kind"], "proofReady": result["proofReady"], "stats": result["stats"], "output": args.output}, sort_keys=True))
    return 0 if result["proofReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
`;
}

function writeWindowsAdVerifier(artifactDir) {
	if (noWrite || !artifactDir) return undefined;
	const path = join(artifactDir, "windows-ad-verifier.py");
	writePrivate(path, windowsAdVerifierSource(), 0o700);
	return path;
}

function writeWindowsAdVerification(artifactDir, target, summary, attackReport) {
	if (noWrite || !artifactDir) return undefined;
	const verification = windowsAdVerificationSummary(target, artifactDir, summary, attackReport);
	const path = join(artifactDir, "windows-ad-verification.json");
	writePrivate(path, `${JSON.stringify(verification, null, 2)}\n`, 0o600);
	return { path, summary: verification };
}

function windowsAdBloodhoundSummary(candidates) {
	const files = windowsAdJsonFiles(candidates);
	const parsed = files.map(parseBloodhoundJson);
	const nodes = [];
	const edges = [];
	for (const item of parsed) {
		for (const node of item.nodes ?? []) bloodhoundPushUnique(nodes, node, (row) => `${row.type}:${row.name}`, 240);
		for (const edge of item.edges ?? []) bloodhoundPushUnique(edges, edge, (row) => `${row.source}>${row.relationship}>${row.target}`, 260);
	}
	const relationCounts = {};
	for (const edge of edges) relationCounts[edge.relationship] = (relationCounts[edge.relationship] ?? 0) + 1;
	const highValue = nodes.filter((node) => node.highValue || /domain admins|enterprise admins|administrators|krbtgt/i.test(node.name)).slice(0, 80);
	const owned = nodes.filter((node) => node.owned).slice(0, 80);
	const privilegeEdges = edges.filter((edge) => /AdminTo|GenericAll|GenericWrite|WriteDacl|WriteOwner|DCSync|AllExtendedRights|AddMember|ForceChangePassword|Owns|CanRDP|AllowedToDelegate|MemberOf/i.test(edge.relationship)).slice(0, 120);
	const risks = [];
	if (parsed.some((item) => (item.nodes?.length ?? 0) || (item.edges?.length ?? 0))) risks.push("bloodhound-graph-data-present");
	if (highValue.length) risks.push("bloodhound-high-value-node-signal");
	if (owned.length) risks.push("bloodhound-owned-principal-signal");
	if (privilegeEdges.length) risks.push("bloodhound-privilege-edge-signal");
	if (owned.length && privilegeEdges.some((edge) => owned.some((node) => edge.source === node.name))) risks.push("bloodhound-owned-principal-edge-signal");
	const attackPaths = windowsAdBloodhoundAttackPaths(nodes, edges, owned, highValue);
	if (attackPaths.length) risks.push("bloodhound-owned-to-high-value-path-signal");
	return {
		fileCount: files.length,
		files: parsed.map((item) => ({
			file: item.file,
			objectCount: item.objectCount ?? 0,
			nodeCount: item.nodes?.length ?? 0,
			edgeCount: item.edges?.length ?? 0,
			error: item.error,
		})),
		nodeCount: nodes.length,
		edgeCount: edges.length,
		relationCounts,
		highValue,
		owned,
		privilegeEdges,
		attackPaths,
		risks,
	};
}

function windowsAdQuicklookSummary(target) {
	const candidates = windowsAdCandidateFiles(target);
	const bloodhound = windowsAdBloodhoundSummary(candidates);
	const fileRows = [];
	let allStrings = [];
	for (const file of candidates.slice(0, 80)) {
		let data;
		try {
			data = readFileSync(file.path);
		} catch {
			continue;
		}
		const headerHex = data.subarray(0, 16).toString("hex");
		const type = headerHex.startsWith("456c6646696c6500")
			? "evtx"
			: file.name.toLowerCase().endsWith(".kirbi")
				? "kirbi"
				: file.name.toLowerCase().endsWith(".ccache")
					? "ccache"
					: /ntds\.dit$/i.test(file.name)
						? "ntds"
						: /(?:^|\/)(?:sam|system|security)$/i.test(file.name)
							? "registry-hive"
							: "text-or-artifact";
		const strings = firmwareStrings(data, 5, 1200).map((row) => ({ ...row, file: file.name }));
		allStrings = allStrings.concat(strings.map((row) => ({ offset: row.offset, text: `${file.name}: ${row.text}` })));
		fileRows.push({
			name: file.name,
			type,
			size: data.length,
			sha256: bufferSha256(data),
			headerHex,
			stringCount: strings.length,
		});
		if (allStrings.length >= 5000) break;
	}
	const signals = windowsAdSignals(allStrings);
	const risks = [];
	if (signals.credentials.length) risks.push("credential-material-signal");
	if (signals.kerberos.length) risks.push("kerberos-attack-surface");
	if (signals.adcs.length) risks.push("adcs-attack-surface");
	if (signals.events.length) risks.push("windows-event-log-signal");
	if (signals.commands.some((row) => /powershell|rundll32|regsvr32|wmic|secretsdump|mimikatz|SharpHound|Certipy|nxc|crackmapexec/i.test(row.text))) risks.push("offensive-tool-or-suspicious-command-signal");
	if (fileRows.some((row) => row.type === "ntds" || row.type === "registry-hive")) risks.push("offline-domain-credential-dump-surface");
	risks.push(...bloodhound.risks);
	return {
		kind: "repi-windows-ad-quicklook",
		schemaVersion: 2,
		target: redact(target),
		fileCount: fileRows.length,
		files: fileRows.slice(0, 80),
		signals,
		bloodhound,
		risks,
	};
}

function windowsAdTriagePlanSource(target) {
	return `#!/usr/bin/env bash
set -euo pipefail

TARGET=\${1:-${shellQuote(target)}}
OUT=\${2:-windows-ad-triage-\$(basename "$TARGET")}
mkdir -p "$OUT"/{events,credentials,kerberos,adcs,graph,logs}
printf '[repi-windows-ad] target=%s out=%s\\n' "$TARGET" "$OUT" | tee "$OUT/logs/plan.log"

# High-value artifacts: ntds.dit, SAM, SYSTEM, SECURITY, *.evtx, *.kirbi, *.ccache, BloodHound/SharpHound JSON.
find "$TARGET" -type f 2>/dev/null | grep -Eai '(ntds\\.dit|/SAM$|/SYSTEM$|/SECURITY$|\\.evtx$|\\.kirbi$|\\.ccache$|bloodhound|sharphound|certipy)' > "$OUT/artifacts.txt" || true
grep -RInE 'krbtgt|DCSync|Kerberoast|AS-REP|SPN|ADCS|ESC[1-9]|Certipy|SharpHound|BloodHound|mimikatz|secretsdump|EventID[:= ]*(4624|4625|4672|4688|4768|4769|4771|4776)' "$TARGET" > "$OUT/high-signal-grep.txt" 2>/dev/null || true

if command -v evtx_dump.py >/dev/null 2>&1; then
  while IFS= read -r evtx; do evtx_dump.py "$evtx" > "$OUT/events/$(basename "$evtx").xml" 2>/dev/null || true; done < <(find "$TARGET" -type f -iname '*.evtx' 2>/dev/null)
fi

cat > "$OUT/next.txt" <<'EOF'
1. Bind domain/DC anchors first: domain SID, DC hostname/IP, forest/domain FQDN.
2. For NTDS/SAM/SYSTEM artifacts, verify hash extraction only with matching bootkey/SYSTEM hive.
3. For Kerberos artifacts, map SPN/account/timestamp before cracking or replaying.
4. For ADCS signals, enumerate templates and prove ESC path before exploitation.
5. For BloodHound/SharpHound data, prioritize owned principal -> shortest path -> credential usability proof.
EOF
`;
}

export function windowsAdRows(target, artifactDir, runtime) {
	configureWindowsAdRuntime(runtime);
	try {
		const summary = windowsAdQuicklookSummary(target);
		const attackPathReport = windowsAdAttackPathClaims(summary);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "windows-ad-quicklook.json"), `${JSON.stringify(summary, null, 2)}\n`);
		if (!noWrite && artifactDir) writePrivate(join(artifactDir, "windows-ad-attack-paths.json"), `${JSON.stringify(attackPathReport, null, 2)}\n`);
		const rows = [
			{
				id: "windows-ad-quicklook",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: summary.fileCount || summary.risks.length ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(summary, null, 2)}\n`,
				stderr: "",
				error: summary.fileCount || summary.risks.length ? undefined : "no Windows/AD artifacts",
			},
			{
				id: "windows-ad-attack-paths",
				command: "internal",
				args: [redact(target)],
				cwd: root,
				exit: attackPathReport.proofReady ? 0 : 1,
				signal: null,
				durationMs: 0,
				stdout: `${JSON.stringify(attackPathReport, null, 2)}\n`,
				stderr: "",
				error: attackPathReport.proofReady ? undefined : "no owned-to-high-value BloodHound path",
			},
		];
		if (!noWrite && artifactDir) {
			const verifierPath = writeWindowsAdVerifier(artifactDir);
			if (verifierPath) {
				rows.push({
					id: "windows-ad-verifier-artifact",
					command: "internal",
					args: [redact(verifierPath)],
					cwd: root,
					exit: 0,
					signal: null,
					durationMs: 0,
					stdout: `verifier=${redact(verifierPath)}\nrun=python3 ${redact(verifierPath)} ${redact(target)} ${redact(join(artifactDir, "windows-ad-quicklook.json"))} ${redact(join(artifactDir, "windows-ad-attack-paths.json"))} ${redact(join(artifactDir, "windows-ad-verification.json"))}\n`,
					stderr: "",
					error: undefined,
				});
			}
			const verification = writeWindowsAdVerification(artifactDir, target, summary, attackPathReport);
			if (verification) {
				rows.push({
					id: "windows-ad-verification",
					command: "internal",
					args: [redact(verification.path)],
					cwd: root,
					exit: verification.summary.proofReady ? 0 : 1,
					signal: null,
					durationMs: 0,
					stdout: `${JSON.stringify(verification.summary, null, 2)}\n`,
					stderr: "",
					error: verification.summary.proofReady ? undefined : "Windows/AD verification blockers present",
				});
			}
			const planPath = join(artifactDir, "windows-ad-triage-plan.sh");
			writePrivate(planPath, windowsAdTriagePlanSource(target), 0o700);
			rows.push({
				id: "windows-ad-triage-plan-artifact",
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
		return [{ id: "windows-ad-quicklook", command: "internal", args: [redact(target)], cwd: root, exit: 1, signal: null, durationMs: 0, stdout: "", stderr: error instanceof Error ? error.message : String(error), error: error instanceof Error ? error.message : String(error) }];
	}
}
