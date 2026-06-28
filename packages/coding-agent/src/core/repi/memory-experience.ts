import { type MemoryDepositionRuntimeEventV7, readMemoryDepositionEvents } from "./memory-deposition.ts";
import type { MemoryArtifactHash, MemoryEventV1, MemoryOutcome, MemoryQuality } from "./memory-event.ts";
import { readMemoryEvents } from "./memory-search.ts";
import { writeFileAtomic } from "./memory-store.ts";
import {
	ensureRepiStorage,
	memoryDepositionEventBusPath,
	memoryEventsPath,
	memoryExperienceClaimsPath,
	memoryExperienceEpisodesPath,
	memoryExperienceLessonBookPath,
	memoryExperiencePromotionLedgerPath,
	memoryExperienceReportPath,
} from "./storage.ts";
import { clamp01, sha256Text, truncateMiddle, uniqueNonEmpty } from "./text.ts";

export type MemoryExperienceClaimTypeV8 =
	| "command_strategy"
	| "failure_signature"
	| "verifier_rule"
	| "artifact_pattern"
	| "scope_constraint"
	| "repair_playbook";

export type MemoryExperienceClaimStatusV8 =
	| "candidate"
	| "promoted"
	| "retained"
	| "demoted"
	| "quarantined"
	| "conflicted";
export type MemoryExperienceLessonActionV8 = "reuse" | "avoid" | "repair" | "verify" | "scope-limit";
export type MemoryExperiencePromotionDecisionV8 = "promote" | "retain" | "demote" | "quarantine" | "merge";

export type MemoryExperienceEpisodeV8 = {
	kind: "repi-memory-experience-episode";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryExperienceEngineV8: true;
	eventId: string;
	depositionEventIds: string[];
	caseSignature: string;
	route: string;
	target?: string;
	targetScope: string;
	intent: string;
	outcome: MemoryOutcome;
	observation: string;
	commands: string[];
	evidenceRefs: MemoryArtifactHash[];
	failureSignature?: string;
	quality: MemoryQuality;
	claimIds: string[];
	lessonIds: string[];
	entryHash: string;
};

export type MemoryExperienceClaimV8 = {
	kind: "repi-memory-experience-claim";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryExperienceEngineV8: true;
	episodeId: string;
	eventId: string;
	claimType: MemoryExperienceClaimTypeV8;
	status: MemoryExperienceClaimStatusV8;
	statement: string;
	caseSignature: string;
	route: string;
	targetScope: string;
	commandFingerprint?: string;
	supportEventIds: string[];
	contradictionEventIds: string[];
	evidenceRefs: MemoryArtifactHash[];
	confidence: number;
	reuseScore: number;
	promotionReady: boolean;
	blockers: string[];
	entryHash: string;
};

export type MemoryExperienceLessonV8 = {
	kind: "repi-memory-experience-lesson";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryExperienceEngineV8: true;
	claimId: string;
	episodeId: string;
	action: MemoryExperienceLessonActionV8;
	lesson: string;
	appliesWhen: string[];
	commands: string[];
	confidence: number;
	backprop: { reuseCount: number; failureCount: number; decay: number; lastUsefulAt: string; source: string };
	evidenceRefs: MemoryArtifactHash[];
};

export type MemoryExperiencePromotionRowV8 = {
	kind: "repi-memory-experience-promotion";
	schemaVersion: 1;
	id: string;
	ts: string;
	MemoryExperienceEngineV8: true;
	claimId: string;
	decision: MemoryExperiencePromotionDecisionV8;
	reason: string;
	check: "artifact_sha256" | "replay_or_verifier" | "feedback" | "contradiction" | "confidence" | "scope";
	evidenceRefs: MemoryArtifactHash[];
	entryHash: string;
};

export type MemoryExperienceReportV8 = {
	kind: "repi-memory-experience-report";
	schemaVersion: 1;
	generatedAt: string;
	MemoryExperienceEngineV8: true;
	episode_model_v8: true;
	structured_claim_extraction: true;
	lesson_promotion_check: true;
	contradiction_resolution: true;
	usefulness_backprop: true;
	reportPath: string;
	episodesPath: string;
	claimsPath: string;
	lessonBookPath: string;
	promotionLedgerPath: string;
	memoryEventsPath: string;
	depositionEventBusPath: string;
	episodeCount: number;
	claimCount: number;
	lessonCount: number;
	promotionDecisionCount: number;
	promotedClaimIds: string[];
	retainedClaimIds: string[];
	demotedClaimIds: string[];
	quarantinedClaimIds: string[];
	conflictedClaimIds: string[];
	operatorInjectionCommands: string[];
	avoidCommands: string[];
	verifyCommands: string[];
	promotionCoverage: number;
	status: "pass" | "warn" | "blocked" | "empty";
	recentEpisodes: MemoryExperienceEpisodeV8[];
	recentClaims: MemoryExperienceClaimV8[];
	recentLessons: MemoryExperienceLessonV8[];
	requiredChecks: string[];
	policy: {
		MemoryExperienceEngineV8: true;
		episodeModel: true;
		structuredClaimExtraction: true;
		lessonPromotionCheck: true;
		contradictionResolution: true;
		usefulnessBackprop: true;
		scopeSafeInjectionOnly: true;
	};
	nextCommands: string[];
};

export function memoryExperienceTargetScope(event: MemoryEventV1): string {
	return [event.memoryScope?.workspaceRoot ?? process.cwd(), event.route, event.target ?? "workspace"]
		.map((item) => item.replace(/\s+/g, " ").trim())
		.filter(Boolean)
		.join("::");
}

export function memoryExperienceIntent(event: MemoryEventV1): string {
	const text = [event.task, event.route, ...event.domainTags, ...event.lessons, ...event.reuseRules].join(" ");
	if (/authz|idor|bola|jwt|oauth|session/i.test(text)) return "web-authz";
	if (/pwn|rop|heap|crash|libc|gdb|overflow/i.test(text)) return "pwn-exploit";
	if (/android|apk|frida|mobile|jadx/i.test(text)) return "mobile-runtime";
	if (/firmware|iot|binwalk|squashfs|mips|arm/i.test(text)) return "firmware-dfir";
	if (/pcap|dfir|forensic|tshark|wireshark/i.test(text)) return "dfir";
	if (/cloud|k8s|aws|azure|gcp|identity|ldap|kerberos/i.test(text)) return "cloud-identity";
	return event.route || "general";
}

export function memoryExperienceObservation(event: MemoryEventV1): string {
	return truncateMiddle(
		uniqueNonEmpty([event.task, ...event.lessons, ...event.reuseRules, ...event.failurePatterns], 12).join(" | "),
		720,
	);
}

export function memoryExperienceFailureSignature(event: MemoryEventV1): string | undefined {
	if (event.outcome !== "failure" && event.outcome !== "blocked" && event.outcome !== "repair") return undefined;
	const text = uniqueNonEmpty([...event.failurePatterns, ...event.lessons, event.task], 8)
		.join("\n")
		.toLowerCase();
	return sha256Text(text).slice(0, 20);
}

export function memoryExperienceCommandFingerprint(command?: string): string | undefined {
	const normalized = String(command ?? "")
		.trim()
		.replace(/\s+/g, " ")
		.replace(/https?:\/\/[^\s/'"`]+/gi, "https://<host>")
		.replace(/\b\d+\b/g, "<n>");
	return normalized ? sha256Text(normalized).slice(0, 20) : undefined;
}

export function memoryExperienceEvidenceReady(event: MemoryEventV1): boolean {
	return (
		event.quality.replayVerified ||
		event.promotion.verifierRuleCandidate ||
		event.artifactHashes.some((artifact) => Boolean(artifact.sha256))
	);
}

export function memoryExperienceEpisodeHash(row: MemoryExperienceEpisodeV8): string {
	const { entryHash: _entryHash, ...withoutHash } = row;
	return sha256Text(JSON.stringify(withoutHash));
}

export function memoryExperienceClaimHash(row: MemoryExperienceClaimV8): string {
	const { entryHash: _entryHash, ...withoutHash } = row;
	return sha256Text(JSON.stringify(withoutHash));
}

export function memoryExperiencePromotionHash(row: MemoryExperiencePromotionRowV8): string {
	const { entryHash: _entryHash, ...withoutHash } = row;
	return sha256Text(JSON.stringify(withoutHash));
}

export function memoryExperienceClaimBaseStatus(
	event: MemoryEventV1,
	claimType: MemoryExperienceClaimTypeV8,
): MemoryExperienceClaimStatusV8 {
	const evidenceReady = memoryExperienceEvidenceReady(event);
	const confidence = event.quality.confidence;
	if (claimType === "scope_constraint") return "promoted";
	if (event.outcome === "failure" || event.outcome === "blocked" || event.outcome === "repair") {
		return confidence >= 0.55 ? "demoted" : "retained";
	}
	if (claimType === "verifier_rule" && event.promotion.verifierRuleCandidate && confidence >= 0.6) return "promoted";
	if (evidenceReady && confidence >= 0.68) return "promoted";
	return confidence >= 0.45 ? "retained" : "candidate";
}

export function isMemoryExperienceClaimRowV8(value: unknown): value is MemoryExperienceClaimV8 {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as MemoryExperienceClaimV8;
	return (
		row.kind === "repi-memory-experience-claim" &&
		row.schemaVersion === 1 &&
		row.MemoryExperienceEngineV8 === true &&
		typeof row.id === "string" &&
		typeof row.episodeId === "string" &&
		typeof row.eventId === "string" &&
		typeof row.claimType === "string" &&
		typeof row.status === "string" &&
		typeof row.statement === "string" &&
		typeof row.caseSignature === "string" &&
		typeof row.route === "string" &&
		typeof row.targetScope === "string" &&
		Array.isArray(row.supportEventIds) &&
		Array.isArray(row.contradictionEventIds) &&
		Array.isArray(row.evidenceRefs) &&
		typeof row.confidence === "number" &&
		typeof row.reuseScore === "number" &&
		typeof row.promotionReady === "boolean" &&
		Array.isArray(row.blockers) &&
		typeof row.entryHash === "string"
	);
}

export function buildMemoryExperienceReport(
	options: { write?: boolean; route?: string; target?: string } = {},
): MemoryExperienceReportV8 {
	ensureRepiStorage();
	const events = readMemoryEvents().filter((event) => {
		const requestedRoute = options.route?.toLowerCase();
		const eventRoute = event.route.toLowerCase();
		if (
			requestedRoute &&
			eventRoute &&
			eventRoute !== requestedRoute &&
			!requestedRoute.includes(eventRoute) &&
			!eventRoute.includes(requestedRoute)
		)
			return false;
		if (options.target && event.target && event.target !== options.target) return false;
		return true;
	});
	const depositionByMemoryEvent = new Map<string, MemoryDepositionRuntimeEventV7[]>();
	for (const event of readMemoryDepositionEvents()) {
		if (!event.memoryEventId) continue;
		const rows = depositionByMemoryEvent.get(event.memoryEventId) ?? [];
		rows.push(event);
		depositionByMemoryEvent.set(event.memoryEventId, rows);
	}
	const episodes: MemoryExperienceEpisodeV8[] = events.map((event) => {
		const depositionRows = depositionByMemoryEvent.get(event.id) ?? [];
		const base: Omit<MemoryExperienceEpisodeV8, "entryHash"> = {
			kind: "repi-memory-experience-episode",
			schemaVersion: 1,
			id: `mexp-episode:${sha256Text(event.id).slice(0, 20)}`,
			ts: event.ts,
			MemoryExperienceEngineV8: true,
			eventId: event.id,
			depositionEventIds: depositionRows.map((row) => row.id),
			caseSignature: event.caseSignature,
			route: event.route,
			target: event.target,
			targetScope: memoryExperienceTargetScope(event),
			intent: memoryExperienceIntent(event),
			outcome: event.outcome,
			observation: memoryExperienceObservation(event),
			commands: uniqueNonEmpty(event.commands, 32),
			evidenceRefs: event.artifactHashes,
			failureSignature: memoryExperienceFailureSignature(event),
			quality: event.quality,
			claimIds: [],
			lessonIds: [],
		};
		const row: MemoryExperienceEpisodeV8 = {
			...base,
			entryHash: memoryExperienceEpisodeHash({ ...base, entryHash: "" }),
		};
		return row;
	});
	const episodeByEvent = new Map(episodes.map((episode) => [episode.eventId, episode]));
	const claimRows: MemoryExperienceClaimV8[] = [];
	const addClaim = (
		event: MemoryEventV1,
		claimType: MemoryExperienceClaimTypeV8,
		statement: string,
		command?: string,
		blockers: string[] = [],
	) => {
		const episode = episodeByEvent.get(event.id);
		if (!episode) return;
		const commandFingerprint = memoryExperienceCommandFingerprint(command);
		const id = `mexp-claim:${sha256Text(`${event.id}\n${claimType}\n${statement}\n${commandFingerprint ?? ""}`).slice(0, 24)}`;
		const confidence = clamp01(event.quality.confidence, 0.5);
		const reuseScore = Number(
			Math.max(
				0,
				confidence * 100 +
					(event.quality.replayVerified ? 12 : 0) +
					event.quality.reuseCount * 5 -
					event.quality.failureCount * 9 -
					event.quality.decay * 10,
			).toFixed(2),
		);
		const baseStatus = memoryExperienceClaimBaseStatus(event, claimType);
		const base: Omit<MemoryExperienceClaimV8, "entryHash"> = {
			kind: "repi-memory-experience-claim",
			schemaVersion: 1,
			id,
			ts: event.ts,
			MemoryExperienceEngineV8: true,
			episodeId: episode.id,
			eventId: event.id,
			claimType,
			status: baseStatus,
			statement: truncateMiddle(statement, 640),
			caseSignature: event.caseSignature,
			route: event.route,
			targetScope: episode.targetScope,
			commandFingerprint,
			supportEventIds: [event.id],
			contradictionEventIds: [],
			evidenceRefs: event.artifactHashes,
			confidence,
			reuseScore,
			promotionReady: baseStatus === "promoted",
			blockers,
		};
		claimRows.push({ ...base, entryHash: memoryExperienceClaimHash({ ...base, entryHash: "" }) });
	};
	for (const event of events) {
		const evidenceReady = memoryExperienceEvidenceReady(event);
		for (const command of event.commands.slice(0, 8)) {
			if (event.outcome === "success" || event.outcome === "partial") {
				addClaim(
					event,
					"command_strategy",
					`Reuse command strategy when intent=${memoryExperienceIntent(event)} route=${event.route}: ${command}`,
					command,
					evidenceReady ? [] : ["artifact_or_replay_evidence_required"],
				);
			} else {
				addClaim(
					event,
					"failure_signature",
					`Avoid or repair command after ${event.outcome} signature=${memoryExperienceFailureSignature(event) ?? "unknown"}: ${command}`,
					command,
					[],
				);
			}
		}
		for (const rule of event.reuseRules.slice(0, 6)) {
			addClaim(
				event,
				"repair_playbook",
				`Reusable rule for ${event.route}: ${rule}`,
				event.commands[0],
				evidenceReady ? [] : ["evidence_hash_missing"],
			);
		}
		for (const pattern of event.failurePatterns.slice(0, 6)) {
			addClaim(event, "failure_signature", `Failure pattern for ${event.route}: ${pattern}`, event.commands[0], []);
		}
		if (event.promotion.verifierRuleCandidate || event.quality.replayVerified) {
			addClaim(
				event,
				"verifier_rule",
				`Verifier/replay rule candidate: ${event.lessons[0] ?? event.task}`,
				event.commands[0],
				[],
			);
		}
		if (event.artifactHashes.some((artifact) => artifact.sha256)) {
			addClaim(
				event,
				"artifact_pattern",
				`Artifact-backed pattern: ${event.artifactHashes
					.map((artifact) => artifact.path)
					.slice(0, 4)
					.join(", ")}`,
				event.commands[0],
				[],
			);
		}
		if (event.memoryScope) {
			addClaim(
				event,
				"scope_constraint",
				`Scope-safe reuse only within ${memoryExperienceTargetScope(event)}`,
				undefined,
				[],
			);
		}
	}
	const byFingerprint = new Map<string, MemoryExperienceClaimV8[]>();
	for (const claim of claimRows) {
		if (!claim.commandFingerprint) continue;
		const key = `${claim.route}:${claim.targetScope}:${claim.commandFingerprint}`;
		const rows = byFingerprint.get(key) ?? [];
		rows.push(claim);
		byFingerprint.set(key, rows);
	}
	const contradictionMap = new Map<string, string[]>();
	for (const rows of byFingerprint.values()) {
		const positive = rows.filter(
			(row) => row.claimType === "command_strategy" || row.claimType === "repair_playbook",
		);
		const negative = rows.filter((row) => row.claimType === "failure_signature");
		if (!positive.length || !negative.length) continue;
		const ids = rows.map((row) => row.eventId);
		for (const row of rows)
			contradictionMap.set(
				row.id,
				ids.filter((id) => id !== row.eventId),
			);
	}
	const claims = claimRows.map((claim) => {
		const contradictionEventIds = uniqueNonEmpty(contradictionMap.get(claim.id) ?? [], 24);
		const status: MemoryExperienceClaimStatusV8 = contradictionEventIds.length
			? "conflicted"
			: claim.blockers.length && claim.status === "promoted"
				? "retained"
				: claim.status;
		const updated = {
			...claim,
			status,
			contradictionEventIds,
			promotionReady: status === "promoted" && claim.blockers.length === 0,
			blockers: uniqueNonEmpty(
				[...claim.blockers, ...(contradictionEventIds.length ? ["contradiction_resolution_required"] : [])],
				16,
			),
		};
		return { ...updated, entryHash: memoryExperienceClaimHash({ ...updated, entryHash: "" }) };
	});
	const lessons: MemoryExperienceLessonV8[] = claims
		.filter((claim) => claim.status === "promoted" || claim.status === "demoted" || claim.status === "retained")
		.slice(0, 240)
		.map((claim) => {
			const episode = episodes.find((item) => item.id === claim.episodeId);
			const event = events.find((item) => item.id === claim.eventId);
			const action: MemoryExperienceLessonActionV8 =
				claim.claimType === "failure_signature"
					? "avoid"
					: claim.claimType === "verifier_rule"
						? "verify"
						: claim.claimType === "scope_constraint"
							? "scope-limit"
							: claim.status === "demoted"
								? "repair"
								: "reuse";
			return {
				kind: "repi-memory-experience-lesson",
				schemaVersion: 1,
				id: `mexp-lesson:${sha256Text(`${claim.id}\n${action}`).slice(0, 20)}`,
				ts: claim.ts,
				MemoryExperienceEngineV8: true,
				claimId: claim.id,
				episodeId: claim.episodeId,
				action,
				lesson: claim.statement,
				appliesWhen: uniqueNonEmpty([episode?.intent, claim.route, episode?.targetScope, claim.caseSignature], 12),
				commands: action === "avoid" ? [] : uniqueNonEmpty(event?.commands ?? [], 10),
				confidence: claim.confidence,
				backprop: {
					reuseCount: event?.quality.reuseCount ?? 0,
					failureCount: event?.quality.failureCount ?? 0,
					decay: event?.quality.decay ?? 0,
					lastUsefulAt: event?.quality.lastUsefulAt ?? claim.ts,
					source: "MemoryExperienceEngineV8 usefulness_backprop",
				},
				evidenceRefs: claim.evidenceRefs,
			};
		});
	const promotionRows: MemoryExperiencePromotionRowV8[] = claims.map((claim) => {
		const decision: MemoryExperiencePromotionDecisionV8 =
			claim.status === "promoted"
				? "promote"
				: claim.status === "demoted"
					? "demote"
					: claim.status === "quarantined" || claim.status === "conflicted"
						? "quarantine"
						: "retain";
		const check: MemoryExperiencePromotionRowV8["check"] = claim.contradictionEventIds.length
			? "contradiction"
			: claim.evidenceRefs.some((artifact) => artifact.sha256)
				? "artifact_sha256"
				: claim.claimType === "verifier_rule"
					? "replay_or_verifier"
					: claim.confidence >= 0.68
						? "confidence"
						: "feedback";
		const base: Omit<MemoryExperiencePromotionRowV8, "entryHash"> = {
			kind: "repi-memory-experience-promotion",
			schemaVersion: 1,
			id: `mexp-promotion:${sha256Text(`${claim.id}\n${decision}`).slice(0, 20)}`,
			ts: new Date().toISOString(),
			MemoryExperienceEngineV8: true,
			claimId: claim.id,
			decision,
			reason: claim.blockers.length
				? claim.blockers.join(";")
				: `status=${claim.status} confidence=${claim.confidence}`,
			check,
			evidenceRefs: claim.evidenceRefs,
		};
		return { ...base, entryHash: memoryExperiencePromotionHash({ ...base, entryHash: "" }) };
	});
	const byStatus = (status: MemoryExperienceClaimStatusV8) =>
		claims
			.filter((claim) => claim.status === status)
			.map((claim) => claim.id)
			.slice(0, 120);
	const operatorInjectionCommands = uniqueNonEmpty(
		lessons
			.filter((lesson) => lesson.action === "reuse" || lesson.action === "repair")
			.flatMap((lesson) => lesson.commands),
		24,
	);
	const avoidCommands = uniqueNonEmpty(
		claims
			.filter((claim) => claim.status === "demoted" || claim.claimType === "failure_signature")
			.flatMap((claim) => {
				const event = events.find((item) => item.id === claim.eventId);
				return event?.commands ?? [];
			}),
		24,
	);
	const verifyCommands = uniqueNonEmpty(
		lessons.filter((lesson) => lesson.action === "verify").flatMap((lesson) => lesson.commands),
		24,
	);
	const decided = promotionRows.filter((row) => row.decision !== "retain").length;
	const status: MemoryExperienceReportV8["status"] =
		events.length === 0
			? "empty"
			: claims.some((claim) => claim.status === "conflicted")
				? "warn"
				: claims.length && lessons.length
					? "pass"
					: "warn";
	const report: MemoryExperienceReportV8 = {
		kind: "repi-memory-experience-report",
		schemaVersion: 1,
		generatedAt: new Date().toISOString(),
		MemoryExperienceEngineV8: true,
		episode_model_v8: true,
		structured_claim_extraction: true,
		lesson_promotion_check: true,
		contradiction_resolution: true,
		usefulness_backprop: true,
		reportPath: memoryExperienceReportPath(),
		episodesPath: memoryExperienceEpisodesPath(),
		claimsPath: memoryExperienceClaimsPath(),
		lessonBookPath: memoryExperienceLessonBookPath(),
		promotionLedgerPath: memoryExperiencePromotionLedgerPath(),
		memoryEventsPath: memoryEventsPath(),
		depositionEventBusPath: memoryDepositionEventBusPath(),
		episodeCount: episodes.length,
		claimCount: claims.length,
		lessonCount: lessons.length,
		promotionDecisionCount: promotionRows.length,
		promotedClaimIds: byStatus("promoted"),
		retainedClaimIds: byStatus("retained"),
		demotedClaimIds: byStatus("demoted"),
		quarantinedClaimIds: byStatus("quarantined"),
		conflictedClaimIds: byStatus("conflicted"),
		operatorInjectionCommands,
		avoidCommands,
		verifyCommands,
		promotionCoverage: claims.length ? Number((decided / claims.length).toFixed(4)) : 0,
		status,
		recentEpisodes: episodes.slice(-12),
		recentClaims: claims.slice(-12),
		recentLessons: lessons.slice(-12),
		requiredChecks: [
			"MemoryExperienceEngineV8",
			"episode_model_v8",
			"structured_claim_extraction",
			"lesson_promotion_check",
			"contradiction_resolution",
			"usefulness_backprop",
			"experience_report_in_context_pack",
			"operator_memory_injection_commands",
		],
		policy: {
			MemoryExperienceEngineV8: true,
			episodeModel: true,
			structuredClaimExtraction: true,
			lessonPromotionCheck: true,
			contradictionResolution: true,
			usefulnessBackprop: true,
			scopeSafeInjectionOnly: true,
		},
		nextCommands: uniqueNonEmpty(
			[
				"re_memory experience",
				operatorInjectionCommands.length
					? "re_operator plan # consumes MemoryExperienceEngineV8 operatorInjectionCommands"
					: undefined,
				avoidCommands.length ? "re_autofix plan # avoidCommands include demoted failure signatures" : undefined,
				verifyCommands.length ? "re_verifier matrix # verifyCommands include promoted verifier rules" : undefined,
				"re_memory supervise",
				"re_context pack",
			].filter(Boolean) as string[],
			12,
		),
	};
	if (options.write !== false) {
		writeFileAtomic(
			memoryExperienceEpisodesPath(),
			episodes.map((row) => JSON.stringify(row)).join("\n") + (episodes.length ? "\n" : ""),
		);
		writeFileAtomic(
			memoryExperienceClaimsPath(),
			claims.map((row) => JSON.stringify(row)).join("\n") + (claims.length ? "\n" : ""),
		);
		writeFileAtomic(
			memoryExperiencePromotionLedgerPath(),
			promotionRows.map((row) => JSON.stringify(row)).join("\n") + (promotionRows.length ? "\n" : ""),
		);
		writeFileAtomic(
			memoryExperienceLessonBookPath(),
			[
				"# REPI Memory Experience Lesson Book",
				"",
				"MemoryExperienceEngineV8: true",
				`generated_at: ${report.generatedAt}`,
				`report: ${report.reportPath}`,
				"",
				"## Reuse / Repair / Verify Lessons",
				...(lessons.length
					? lessons
							.slice(0, 160)
							.map(
								(lesson) =>
									`- ${lesson.action} confidence=${lesson.confidence.toFixed(2)} claim=${lesson.claimId} :: ${lesson.lesson}`,
							)
					: ["- none"]),
				"",
				"## Operator Injection Commands",
				...(operatorInjectionCommands.length
					? operatorInjectionCommands.map((command) => `- ${command}`)
					: ["- none"]),
				"",
				"## Avoid Commands / Failure Signatures",
				...(avoidCommands.length ? avoidCommands.map((command) => `- ${command}`) : ["- none"]),
				"",
				"## Required Checks",
				...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
				"",
			].join("\n"),
		);
		writeFileAtomic(memoryExperienceReportPath(), `${JSON.stringify(report, null, 2)}\n`);
	}
	return report;
}

export function formatMemoryExperienceReport(report = buildMemoryExperienceReport()): string {
	return [
		"memory_experience_engine_v8:",
		`MemoryExperienceEngineV8=${report.MemoryExperienceEngineV8}`,
		`episode_model_v8=${report.episode_model_v8}`,
		`structured_claim_extraction=${report.structured_claim_extraction}`,
		`lesson_promotion_check=${report.lesson_promotion_check}`,
		`contradiction_resolution=${report.contradiction_resolution}`,
		`usefulness_backprop=${report.usefulness_backprop}`,
		`status=${report.status}`,
		`episodes=${report.episodeCount}`,
		`claims=${report.claimCount}`,
		`lessons=${report.lessonCount}`,
		`promotion_coverage=${report.promotionCoverage}`,
		`promoted=${report.promotedClaimIds.length}`,
		`demoted=${report.demotedClaimIds.length}`,
		`conflicted=${report.conflictedClaimIds.length}`,
		`report=${report.reportPath}`,
		`lesson_book=${report.lessonBookPath}`,
		"operator_injection_commands:",
		...(report.operatorInjectionCommands.length
			? report.operatorInjectionCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"avoid_commands:",
		...(report.avoidCommands.length
			? report.avoidCommands.slice(0, 12).map((command) => `- ${command}`)
			: ["- none"]),
		"recent_lessons:",
		...(report.recentLessons.length
			? report.recentLessons.map(
					(lesson) => `- ${lesson.action} claim=${lesson.claimId} ${truncateMiddle(lesson.lesson, 180)}`,
				)
			: ["- none"]),
		"next_commands:",
		...report.nextCommands.map((command) => `- ${command}`),
		"required_checks:",
		...report.requiredChecks.map((checkpoint) => `- ${checkpoint}`),
	].join("\n");
}
