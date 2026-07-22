import { basename, dirname } from "node:path";
import type { Agent, ThinkingLevel } from "@pi-recon/repi-agent-core";
import type { ImageContent, Model, TextContent } from "@pi-recon/repi-ai";
import type { CompactionResult } from "./compaction/index.ts";
import type {
	ContextUsage,
	ExtensionCommandContextActions,
	ExtensionErrorListener,
	ExtensionMode,
	ExtensionRunner,
	ExtensionUIContext,
	SessionStartEvent,
	ShutdownHandler,
	ToolInfo,
} from "./extensions/index.ts";
import { emitSessionShutdownEvent } from "./extensions/runner.ts";
import type { CustomMessage } from "./messages.ts";
import type { ModelRegistry } from "./model-registry.ts";
import type { ModelRuntime } from "./model-runtime.ts";
import type { PromptTemplate } from "./prompt-templates.ts";
import type { ResourceExtensionPaths, ResourceLoader } from "./resource-loader.ts";
import type { SessionManager } from "./session-manager.ts";
import type { SettingsManager } from "./settings-manager.ts";
import type { SlashCommandInfo } from "./slash-commands.ts";
import type { BuildSystemPromptOptions } from "./system-prompt.ts";

export const STALE_EXTENSION_CONTEXT_MESSAGE =
	"This extension ctx is stale after session replacement or reload. Do not use a captured pi or command ctx after ctx.newSession(), ctx.fork(), ctx.switchSession(), or ctx.reload(). For newSession, fork, and switchSession, move post-replacement work into withSession and use the ctx passed to withSession. For reload, do not use the old ctx after await ctx.reload().";

export interface ExtensionBindings {
	uiContext?: ExtensionUIContext;
	mode?: ExtensionMode;
	commandContextActions?: ExtensionCommandContextActions;
	abortHandler?: () => void;
	shutdownHandler?: ShutdownHandler;
	onError?: ExtensionErrorListener;
}

export interface AgentSessionExtensionBuildOptions {
	activeToolNames?: string[];
	flagValues?: Map<string, boolean | string>;
	includeAllExtensionTools?: boolean;
}

export interface AgentSessionExtensionHost {
	readonly agent: Agent;
	readonly cwd: string;
	readonly extensionRunner: ExtensionRunner;
	readonly resourceLoader: ResourceLoader;
	readonly sessionManager: SessionManager;
	readonly settingsManager: SettingsManager;
	readonly modelRegistry: ModelRegistry;
	readonly modelRuntime: ModelRuntime | undefined;
	readonly model: Model<any> | undefined;
	readonly thinkingLevel: ThinkingLevel;
	readonly isIdle: boolean;
	readonly pendingMessageCount: number;
	readonly systemPrompt: string;
	readonly baseSystemPromptOptions: BuildSystemPromptOptions;
	readonly promptTemplates: ReadonlyArray<PromptTemplate>;
	getActiveToolNames(): string[];
	getAllTools(): ToolInfo[];
	setActiveToolsByName(toolNames: string[]): void;
	refreshToolRegistry(): void;
	buildRuntime(options: AgentSessionExtensionBuildOptions): void;
	refreshSystemPrompt(): void;
	sendCustomMessage<T = unknown>(
		message: Pick<CustomMessage<T>, "customType" | "content" | "display" | "details">,
		options?: { triggerTurn?: boolean; deliverAs?: "steer" | "followUp" | "nextTurn" },
	): Promise<void>;
	sendUserMessage(
		content: string | (TextContent | ImageContent)[],
		options?: { deliverAs?: "steer" | "followUp" },
	): Promise<void>;
	setSessionName(name: string): void;
	setModel(model: Model<any>): Promise<void>;
	setThinkingLevel(level: ThinkingLevel): void;
	abortCurrentOperation(): Promise<void>;
	compact(customInstructions?: string): Promise<CompactionResult>;
	getContextUsage(): ContextUsage | undefined;
}

type ExtensionResourceEntry = { path: string; extensionPath: string };
type ExtensionResourcePath = NonNullable<ResourceExtensionPaths["skillPaths"]>[number];

export class AgentSessionExtensionRuntime {
	private readonly host: AgentSessionExtensionHost;
	private readonly sessionStartEvent: SessionStartEvent;
	private uiContext: ExtensionUIContext | undefined;
	private mode: ExtensionMode = "print";
	private commandContextActions: ExtensionCommandContextActions | undefined;
	private abortHandler: (() => void) | undefined;
	private shutdownHandler: ShutdownHandler | undefined;
	private errorListener: ExtensionErrorListener | undefined;
	private errorUnsubscriber: (() => void) | undefined;

	constructor(host: AgentSessionExtensionHost, sessionStartEvent: SessionStartEvent) {
		this.host = host;
		this.sessionStartEvent = sessionStartEvent;
	}

	async bindExtensions(bindings: ExtensionBindings): Promise<void> {
		if (bindings.uiContext !== undefined) this.uiContext = bindings.uiContext;
		if (bindings.mode !== undefined) this.mode = bindings.mode;
		if (bindings.commandContextActions !== undefined) {
			this.commandContextActions = bindings.commandContextActions;
		}
		if (bindings.abortHandler !== undefined) this.abortHandler = bindings.abortHandler;
		if (bindings.shutdownHandler !== undefined) this.shutdownHandler = bindings.shutdownHandler;
		if (bindings.onError !== undefined) this.errorListener = bindings.onError;

		this.applyBindings(this.host.extensionRunner);
		await this.host.extensionRunner.emit(this.sessionStartEvent);
		await this.extendResourcesFromExtensions(this.sessionStartEvent.reason === "reload" ? "reload" : "startup");
	}

	applyBindings(runner: ExtensionRunner): void {
		runner.setUIContext(this.uiContext, this.mode);
		runner.bindCommandContext(this.commandContextActions);

		this.errorUnsubscriber?.();
		this.errorUnsubscriber = this.errorListener ? runner.onError(this.errorListener) : undefined;
	}

	bindCore(runner: ExtensionRunner): void {
		const getCommands = (): SlashCommandInfo[] => {
			const extensionCommands: SlashCommandInfo[] = runner.getRegisteredCommands().map((command) => ({
				name: command.invocationName,
				description: command.description,
				source: "extension",
				sourceInfo: command.sourceInfo,
			}));
			const templates: SlashCommandInfo[] = this.host.promptTemplates.map((template) => ({
				name: template.name,
				description: template.description,
				source: "prompt",
				sourceInfo: template.sourceInfo,
			}));
			const skills: SlashCommandInfo[] = this.host.resourceLoader.getSkills().skills.map((skill) => ({
				name: `skill:${skill.name}`,
				description: skill.description,
				source: "skill",
				sourceInfo: skill.sourceInfo,
			}));
			return [...extensionCommands, ...templates, ...skills];
		};

		runner.bindCore(
			{
				sendMessage: (message, options) => {
					this.host.sendCustomMessage(message, options).catch((error) => {
						runner.emitError({
							extensionPath: "<runtime>",
							event: "send_message",
							error: error instanceof Error ? error.message : String(error),
						});
					});
				},
				sendUserMessage: (content, options) => {
					this.host.sendUserMessage(content, options).catch((error) => {
						runner.emitError({
							extensionPath: "<runtime>",
							event: "send_user_message",
							error: error instanceof Error ? error.message : String(error),
						});
					});
				},
				appendEntry: (customType, data) => this.host.sessionManager.appendCustomEntry(customType, data),
				setSessionName: (name) => this.host.setSessionName(name),
				getSessionName: () => this.host.sessionManager.getSessionName(),
				setLabel: (entryId, label) => this.host.sessionManager.appendLabelChange(entryId, label),
				getActiveTools: () => this.host.getActiveToolNames(),
				getAllTools: () => this.host.getAllTools(),
				setActiveTools: (toolNames) => this.host.setActiveToolsByName(toolNames),
				refreshTools: () => this.host.refreshToolRegistry(),
				getCommands,
				setModel: async (model) => {
					if (!this.host.modelRegistry.hasConfiguredAuth(model)) return false;
					await this.host.setModel(model);
					return true;
				},
				getThinkingLevel: () => this.host.thinkingLevel,
				setThinkingLevel: (level) => this.host.setThinkingLevel(level),
			},
			{
				getModel: () => this.host.model,
				isIdle: () => this.host.isIdle,
				getSignal: () => this.host.agent.signal,
				abort: () => {
					if (this.abortHandler) {
						this.abortHandler();
						return;
					}
					void this.host.abortCurrentOperation().catch(() => undefined);
				},
				hasPendingMessages: () => this.host.pendingMessageCount > 0,
				shutdown: () => this.shutdownHandler?.(),
				getContextUsage: () => this.host.getContextUsage(),
				compact: (options) => {
					void (async () => {
						try {
							const result = await this.host.compact(options?.customInstructions);
							options?.onComplete?.(result);
						} catch (error) {
							options?.onError?.(error instanceof Error ? error : new Error(String(error)));
						}
					})();
				},
				getSystemPrompt: () => this.host.systemPrompt,
				getSystemPromptOptions: () => this.host.baseSystemPromptOptions,
			},
			{
				registerNativeProvider: (provider) => {
					if (!this.host.modelRuntime) {
						throw new Error("Native provider registration requires ModelRuntime");
					}
					this.host.modelRuntime.registerNativeProvider(provider);
					this.refreshCurrentModelFromRegistry();
				},
				registerProvider: (name, config) => {
					const { modelRegistry, modelRuntime } = this.host;
					if (modelRuntime && !modelRegistry.isBackedBy(modelRuntime)) {
						modelRuntime.registerProvider(name, config);
						try {
							modelRegistry.registerProvider(name, config);
						} catch (error) {
							modelRuntime.unregisterProvider(name);
							throw error;
						}
					} else {
						modelRegistry.registerProvider(name, config);
					}
					this.refreshCurrentModelFromRegistry();
				},
				unregisterProvider: (name) => {
					const { modelRegistry, modelRuntime } = this.host;
					if (modelRuntime && !modelRegistry.isBackedBy(modelRuntime)) {
						modelRuntime.unregisterProvider(name);
					}
					modelRegistry.unregisterProvider(name);
					this.refreshCurrentModelFromRegistry();
				},
			},
		);
	}

	async reload(): Promise<void> {
		const previousRunner = this.host.extensionRunner;
		const previousFlagValues = previousRunner.getFlagValues();
		await emitSessionShutdownEvent(previousRunner, { type: "session_shutdown", reason: "reload" });
		await this.host.settingsManager.reload();
		await this.host.resourceLoader.reload();
		previousRunner.unregisterOwnedProviders?.();
		await this.host.modelRegistry.refresh();
		this.host.buildRuntime({
			activeToolNames: this.host.getActiveToolNames(),
			flagValues: previousFlagValues,
			includeAllExtensionTools: true,
		});
		previousRunner.invalidate(STALE_EXTENSION_CONTEXT_MESSAGE);
		this.refreshCurrentModelFromRegistry();

		if (this.hasBindings()) {
			await this.host.extensionRunner.emit({ type: "session_start", reason: "reload" });
			await this.extendResourcesFromExtensions("reload");
		}
	}

	private async extendResourcesFromExtensions(reason: "startup" | "reload"): Promise<void> {
		const runner = this.host.extensionRunner;
		if (!runner.hasHandlers("resources_discover")) return;

		const { skillPaths, promptPaths, themePaths } = await runner.emitResourcesDiscover(this.host.cwd, reason);
		if (skillPaths.length === 0 && promptPaths.length === 0 && themePaths.length === 0) return;

		this.host.resourceLoader.extendResources({
			skillPaths: this.buildExtensionResourcePaths(skillPaths),
			promptPaths: this.buildExtensionResourcePaths(promptPaths),
			themePaths: this.buildExtensionResourcePaths(themePaths),
		});
		this.host.refreshSystemPrompt();
	}

	private buildExtensionResourcePaths(entries: ExtensionResourceEntry[]): ExtensionResourcePath[] {
		return entries.map((entry) => ({
			path: entry.path,
			metadata: {
				source: this.getExtensionSourceLabel(entry.extensionPath),
				scope: "temporary",
				origin: "top-level",
				baseDir: entry.extensionPath.startsWith("<") ? undefined : dirname(entry.extensionPath),
			},
		}));
	}

	private getExtensionSourceLabel(extensionPath: string): string {
		if (extensionPath.startsWith("<")) {
			return `extension:${extensionPath.replace(/[<>]/g, "")}`;
		}
		return `extension:${basename(extensionPath).replace(/\.(ts|js)$/, "")}`;
	}

	private refreshCurrentModelFromRegistry(): void {
		const currentModel = this.host.model;
		if (!currentModel) return;

		const refreshedModel =
			this.host.modelRuntime?.getModel(currentModel.provider, currentModel.id) ??
			this.host.modelRegistry.resolveActiveModel(currentModel);
		if (refreshedModel !== currentModel) this.host.agent.state.model = refreshedModel;
	}

	private hasBindings(): boolean {
		return Boolean(this.uiContext || this.commandContextActions || this.shutdownHandler || this.errorListener);
	}
}
