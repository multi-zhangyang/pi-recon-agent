import type { ImageContent, TextContent } from "@pi-recon/repi-ai";
import type { AgentMessage } from "../../types.ts";
import { createBranchSummaryMessage, createCompactionSummaryMessage, createCustomMessage } from "../messages.ts";
import type {
	ActiveToolsChangeEntry,
	BranchSummaryEntry,
	CompactionEntry,
	CustomEntry,
	CustomMessageEntry,
	LabelEntry,
	MessageEntry,
	ModelChangeEntry,
	SessionContext,
	SessionInfoEntry,
	SessionMetadata,
	SessionStorage,
	SessionTreeEntry,
	ThinkingLevelChangeEntry,
} from "../types.ts";
import { SessionError } from "../types.ts";

export type ContextEntryTransform = (entries: readonly SessionTreeEntry[]) => readonly SessionTreeEntry[];

export type CustomEntryContextMessageProjector = (
	entry: CustomEntry,
	index: number,
	entries: readonly SessionTreeEntry[],
) => readonly AgentMessage[] | undefined;

export interface SessionContextBuildOptions {
	/** Additional entry transforms applied after compaction selects the active context. */
	entryTransforms?: readonly ContextEntryTransform[];
	/** Custom persisted entries are omitted unless their type has an explicit projector. */
	entryProjectors?: Readonly<Record<string, CustomEntryContextMessageProjector>>;
}

function deriveSessionContextState(pathEntries: readonly SessionTreeEntry[]): Omit<SessionContext, "messages"> {
	let thinkingLevel = "off";
	let model: { provider: string; modelId: string } | null = null;
	let activeToolNames: string[] | null = null;

	for (const entry of pathEntries) {
		if (entry.type === "thinking_level_change") {
			thinkingLevel = entry.thinkingLevel;
		} else if (entry.type === "model_change") {
			model = { provider: entry.provider, modelId: entry.modelId };
		} else if (entry.type === "message" && entry.message.role === "assistant") {
			model = { provider: entry.message.provider, modelId: entry.message.model };
		} else if (entry.type === "active_tools_change") {
			activeToolNames = [...entry.activeToolNames];
		}
	}

	return { thinkingLevel, model, activeToolNames };
}

export function defaultContextEntryTransform(pathEntries: readonly SessionTreeEntry[]): SessionTreeEntry[] {
	let compaction: CompactionEntry | null = null;
	let compactionIndex = -1;
	for (let index = 0; index < pathEntries.length; index++) {
		const entry = pathEntries[index]!;
		if (entry.type === "compaction") {
			compaction = entry;
			compactionIndex = index;
		}
	}
	if (!compaction) return [...pathEntries];

	const entries: SessionTreeEntry[] = [compaction];
	let foundFirstKept = false;
	for (let index = 0; index < compactionIndex; index++) {
		const entry = pathEntries[index]!;
		if (entry.id === compaction.firstKeptEntryId) foundFirstKept = true;
		// Older compaction entries are already represented by the latest summary.
		// Including them again duplicates history after repeated compaction.
		if (foundFirstKept && entry.type !== "compaction") entries.push(entry);
	}
	if (!foundFirstKept) {
		// Preserve context from corrupt/legacy boundaries instead of silently
		// returning only the latest summary.
		for (let index = 0; index < compactionIndex; index++) {
			const entry = pathEntries[index]!;
			if (entry.type !== "compaction") entries.push(entry);
		}
	}
	for (let index = compactionIndex + 1; index < pathEntries.length; index++) {
		entries.push(pathEntries[index]!);
	}
	return entries;
}

export function buildContextEntries(
	pathEntries: readonly SessionTreeEntry[],
	options: SessionContextBuildOptions = {},
): SessionTreeEntry[] {
	let entries = defaultContextEntryTransform(pathEntries);
	for (const transform of options.entryTransforms ?? []) entries = [...transform(entries)];
	return entries;
}

export function sessionEntryToContextMessages(
	entry: SessionTreeEntry,
	index: number,
	entries: readonly SessionTreeEntry[],
	options: SessionContextBuildOptions = {},
): AgentMessage[] {
	if (entry.type === "message") return [entry.message as AgentMessage];
	if (entry.type === "custom_message") {
		return [
			createCustomMessage(
				entry.customType,
				entry.content as string | (TextContent | ImageContent)[],
				entry.display,
				entry.details,
				entry.timestamp,
			),
		];
	}
	if (entry.type === "compaction") {
		return [createCompactionSummaryMessage(entry.summary, entry.tokensBefore, entry.timestamp)];
	}
	if (entry.type === "branch_summary" && entry.summary) {
		return [createBranchSummaryMessage(entry.summary, entry.fromId, entry.timestamp)];
	}
	if (entry.type === "custom") {
		return [...(options.entryProjectors?.[entry.customType]?.(entry, index, entries) ?? [])];
	}
	return [];
}

export function buildSessionContext(
	pathEntries: readonly SessionTreeEntry[],
	options: SessionContextBuildOptions = {},
): SessionContext {
	const state = deriveSessionContextState(pathEntries);
	const contextEntries = buildContextEntries(pathEntries, options);
	const messages = contextEntries.flatMap((entry, index) =>
		sessionEntryToContextMessages(entry, index, contextEntries, options),
	);
	return { ...state, messages };
}

export class Session<TMetadata extends SessionMetadata = SessionMetadata> {
	private storage: SessionStorage<TMetadata>;
	private contextBuildOptions: SessionContextBuildOptions;
	private mutationQueue: Promise<void> = Promise.resolve();

	constructor(storage: SessionStorage<TMetadata>, contextBuildOptions: SessionContextBuildOptions = {}) {
		this.storage = storage;
		this.contextBuildOptions = contextBuildOptions;
	}

	getMetadata(): Promise<TMetadata> {
		return this.storage.getMetadata();
	}

	getStorage(): SessionStorage<TMetadata> {
		return this.storage;
	}

	getLeafId(): Promise<string | null> {
		return this.storage.getLeafId();
	}

	getEntry(id: string): Promise<SessionTreeEntry | undefined> {
		return this.storage.getEntry(id);
	}

	getEntries(): Promise<SessionTreeEntry[]> {
		return this.storage.getEntries();
	}

	async getBranch(fromId?: string): Promise<SessionTreeEntry[]> {
		const leafId = fromId ?? (await this.storage.getLeafId());
		return this.storage.getPathToRoot(leafId);
	}

	async buildContextEntries(options: SessionContextBuildOptions = {}): Promise<SessionTreeEntry[]> {
		return buildContextEntries(await this.getBranch(), this.mergeContextBuildOptions(options));
	}

	async buildContext(options: SessionContextBuildOptions = {}): Promise<SessionContext> {
		return buildSessionContext(await this.getBranch(), this.mergeContextBuildOptions(options));
	}

	private mergeContextBuildOptions(options: SessionContextBuildOptions): SessionContextBuildOptions {
		return {
			entryTransforms: [...(this.contextBuildOptions.entryTransforms ?? []), ...(options.entryTransforms ?? [])],
			entryProjectors: {
				...(this.contextBuildOptions.entryProjectors ?? {}),
				...(options.entryProjectors ?? {}),
			},
		};
	}

	getLabel(id: string): Promise<string | undefined> {
		return this.storage.getLabel(id);
	}

	async getSessionName(): Promise<string | undefined> {
		const entries = await this.storage.findEntries("session_info");
		return entries[entries.length - 1]?.name?.trim() || undefined;
	}

	private enqueueMutation<TResult>(mutation: () => Promise<TResult>): Promise<TResult> {
		const result = this.mutationQueue.then(mutation);
		// A failed write rejects its caller but must not poison later mutations.
		this.mutationQueue = result.then(
			() => undefined,
			() => undefined,
		);
		return result;
	}

	// Queue-owning compound mutations call this directly; it must not enqueue itself.
	private async appendEntryWithinMutation<TEntry extends SessionTreeEntry>(
		createEntry: (id: string, parentId: string | null, timestamp: string) => TEntry,
	): Promise<string> {
		const id = await this.storage.createEntryId();
		const parentId = await this.storage.getLeafId();
		const entry = createEntry(id, parentId, new Date().toISOString());
		await this.storage.appendEntry(entry);
		return entry.id;
	}

	private appendEntry<TEntry extends SessionTreeEntry>(
		createEntry: (id: string, parentId: string | null, timestamp: string) => TEntry,
	): Promise<string> {
		return this.enqueueMutation(() => this.appendEntryWithinMutation(createEntry));
	}

	async appendMessage(message: AgentMessage): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) => ({ type: "message", id, parentId, timestamp, message }) satisfies MessageEntry,
		);
	}

	async appendThinkingLevelChange(thinkingLevel: string): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({
					type: "thinking_level_change",
					id,
					parentId,
					timestamp,
					thinkingLevel,
				}) satisfies ThinkingLevelChangeEntry,
		);
	}

	async appendModelChange(provider: string, modelId: string): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({ type: "model_change", id, parentId, timestamp, provider, modelId }) satisfies ModelChangeEntry,
		);
	}

	async appendActiveToolsChange(activeToolNames: string[]): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({
					type: "active_tools_change",
					id,
					parentId,
					timestamp,
					activeToolNames: [...activeToolNames],
				}) satisfies ActiveToolsChangeEntry,
		);
	}

	async appendCompaction<T = unknown>(
		summary: string,
		firstKeptEntryId: string,
		tokensBefore: number,
		details?: T,
		fromHook?: boolean,
	): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({
					type: "compaction",
					id,
					parentId,
					timestamp,
					summary,
					firstKeptEntryId,
					tokensBefore,
					details,
					fromHook,
				}) satisfies CompactionEntry<T>,
		);
	}

	async appendCustomEntry(customType: string, data?: unknown): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({ type: "custom", id, parentId, timestamp, customType, data }) satisfies CustomEntry,
		);
	}

	async appendCustomMessageEntry<T = unknown>(
		customType: string,
		content: string | (TextContent | ImageContent)[],
		display: boolean,
		details?: T,
	): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({
					type: "custom_message",
					id,
					parentId,
					timestamp,
					customType,
					content,
					display,
					details,
				}) satisfies CustomMessageEntry<T>,
		);
	}

	async appendLabel(targetId: string, label: string | undefined): Promise<string> {
		return this.enqueueMutation(async () => {
			if (!(await this.storage.getEntry(targetId))) {
				throw new SessionError("not_found", `Entry ${targetId} not found`);
			}
			return this.appendEntryWithinMutation(
				(id, parentId, timestamp) =>
					({ type: "label", id, parentId, timestamp, targetId, label }) satisfies LabelEntry,
			);
		});
	}

	async appendSessionName(name: string): Promise<string> {
		return this.appendEntry(
			(id, parentId, timestamp) =>
				({ type: "session_info", id, parentId, timestamp, name: name.trim() }) satisfies SessionInfoEntry,
		);
	}

	async moveTo(
		entryId: string | null,
		summary?: { summary: string; details?: unknown; fromHook?: boolean },
	): Promise<string | undefined> {
		return this.enqueueMutation(async () => {
			if (entryId !== null && !(await this.storage.getEntry(entryId))) {
				throw new SessionError("not_found", `Entry ${entryId} not found`);
			}
			await this.storage.setLeafId(entryId);
			if (!summary) return undefined;
			return this.appendEntryWithinMutation(
				(id, parentId, timestamp) =>
					({
						type: "branch_summary",
						id,
						parentId,
						timestamp,
						fromId: entryId ?? "root",
						summary: summary.summary,
						details: summary.details,
						fromHook: summary.fromHook,
					}) satisfies BranchSummaryEntry,
			);
		});
	}
}
