import type { Agent, ThinkingLevel } from "@pi-recon/repi-agent-core";
import type { Model } from "@pi-recon/repi-ai";
import { clampThinkingLevel, getSupportedThinkingLevels, modelsAreEqual } from "@pi-recon/repi-ai";
import { DEFAULT_THINKING_LEVEL } from "./defaults.ts";
import type { ModelRegistry } from "./model-registry.ts";
import type { SessionManager } from "./session-manager.ts";
import type { SettingsManager } from "./settings-manager.ts";

export interface AgentSessionScopedModel {
	model: Model<any>;
	thinkingLevel?: ThinkingLevel;
}

export interface ModelCycleResult {
	model: Model<any>;
	thinkingLevel: ThinkingLevel;
	isScoped: boolean;
}

export interface AgentSessionModelHost {
	readonly agent: Agent;
	readonly sessionManager: SessionManager;
	readonly settingsManager: SettingsManager;
	readonly modelRegistry: ModelRegistry;
	readonly model: Model<any> | undefined;
	readonly thinkingLevel: ThinkingLevel;
	emitModelSelect(
		nextModel: Model<any>,
		previousModel: Model<any> | undefined,
		source: "set" | "cycle" | "restore",
	): Promise<void>;
	emitThinkingLevelChanged(level: ThinkingLevel): void;
	emitThinkingLevelSelect(level: ThinkingLevel, previousLevel: ThinkingLevel): void;
}

const THINKING_LEVELS: ThinkingLevel[] = ["off", "minimal", "low", "medium", "high"];

export class AgentSessionModelRuntime {
	private readonly host: AgentSessionModelHost;
	private scopedModels: AgentSessionScopedModel[];

	constructor(host: AgentSessionModelHost, scopedModels: AgentSessionScopedModel[] = []) {
		this.host = host;
		this.scopedModels = scopedModels;
	}

	getScopedModels(): ReadonlyArray<AgentSessionScopedModel> {
		return this.scopedModels;
	}

	setScopedModels(scopedModels: AgentSessionScopedModel[]): void {
		this.scopedModels = scopedModels;
	}

	async setModel(model: Model<any>): Promise<void> {
		if (!this.host.modelRegistry.hasConfiguredAuth(model)) {
			throw new Error(`No API key for ${model.provider}/${model.id}`);
		}

		const previousModel = this.host.model;
		const thinkingLevel = this.getThinkingLevelForModelSwitch();
		this.applyModel(model);
		this.setThinkingLevel(thinkingLevel);
		await this.emitModelSelect(model, previousModel, "set");
	}

	async cycleModel(direction: "forward" | "backward" = "forward"): Promise<ModelCycleResult | undefined> {
		if (this.scopedModels.length > 0) {
			return this.cycleScopedModel(direction);
		}
		return this.cycleAvailableModel(direction);
	}

	setThinkingLevel(level: ThinkingLevel): void {
		const availableLevels = this.getAvailableThinkingLevels();
		const effectiveLevel = availableLevels.includes(level) ? level : this.clampThinkingLevel(level);
		const previousLevel = this.host.agent.state.thinkingLevel;
		if (effectiveLevel === previousLevel) return;

		this.host.agent.state.thinkingLevel = effectiveLevel;
		this.host.sessionManager.appendThinkingLevelChange(effectiveLevel);
		if (this.supportsThinking() || effectiveLevel !== "off") {
			this.host.settingsManager.setDefaultThinkingLevel(effectiveLevel);
		}
		this.host.emitThinkingLevelChanged(effectiveLevel);
		this.host.emitThinkingLevelSelect(effectiveLevel, previousLevel);
	}

	cycleThinkingLevel(): ThinkingLevel | undefined {
		if (!this.supportsThinking()) return undefined;
		const levels = this.getAvailableThinkingLevels();
		const currentIndex = levels.indexOf(this.host.thinkingLevel);
		const nextLevel = levels[(currentIndex + 1) % levels.length];
		this.setThinkingLevel(nextLevel);
		return nextLevel;
	}

	getAvailableThinkingLevels(): ThinkingLevel[] {
		return this.host.model ? (getSupportedThinkingLevels(this.host.model) as ThinkingLevel[]) : THINKING_LEVELS;
	}

	supportsThinking(): boolean {
		return Boolean(this.host.model?.reasoning);
	}

	private async cycleScopedModel(direction: "forward" | "backward"): Promise<ModelCycleResult | undefined> {
		const models = this.scopedModels.filter(({ model }) => this.host.modelRegistry.hasConfiguredAuth(model));
		if (models.length <= 1) return undefined;

		const currentModel = this.host.model;
		const currentIndex = Math.max(
			0,
			models.findIndex(({ model }) => modelsAreEqual(model, currentModel)),
		);
		const nextIndex =
			direction === "forward"
				? (currentIndex + 1) % models.length
				: (currentIndex - 1 + models.length) % models.length;
		const next = models[nextIndex];
		const thinkingLevel = this.getThinkingLevelForModelSwitch(next.thinkingLevel);

		this.applyModel(next.model);
		this.setThinkingLevel(thinkingLevel);
		await this.emitModelSelect(next.model, currentModel, "cycle");
		return { model: next.model, thinkingLevel: this.host.thinkingLevel, isScoped: true };
	}

	private async cycleAvailableModel(direction: "forward" | "backward"): Promise<ModelCycleResult | undefined> {
		const models = await this.host.modelRegistry.getAvailable();
		if (models.length <= 1) return undefined;

		const currentModel = this.host.model;
		const currentIndex = Math.max(
			0,
			models.findIndex((model) => modelsAreEqual(model, currentModel)),
		);
		const nextIndex =
			direction === "forward"
				? (currentIndex + 1) % models.length
				: (currentIndex - 1 + models.length) % models.length;
		const nextModel = models[nextIndex];
		const thinkingLevel = this.getThinkingLevelForModelSwitch();

		this.applyModel(nextModel);
		this.setThinkingLevel(thinkingLevel);
		await this.emitModelSelect(nextModel, currentModel, "cycle");
		return { model: nextModel, thinkingLevel: this.host.thinkingLevel, isScoped: false };
	}

	private applyModel(model: Model<any>): void {
		this.host.agent.state.model = model;
		this.host.sessionManager.appendModelChange(model.provider, model.id);
		this.host.settingsManager.setDefaultModelAndProvider(model.provider, model.id);
	}

	private async emitModelSelect(
		nextModel: Model<any>,
		previousModel: Model<any> | undefined,
		source: "set" | "cycle" | "restore",
	): Promise<void> {
		if (!modelsAreEqual(previousModel, nextModel)) {
			await this.host.emitModelSelect(nextModel, previousModel, source);
		}
	}

	private getThinkingLevelForModelSwitch(explicitLevel?: ThinkingLevel): ThinkingLevel {
		if (explicitLevel !== undefined) return explicitLevel;
		if (!this.supportsThinking()) {
			return this.host.settingsManager.getDefaultThinkingLevel() ?? DEFAULT_THINKING_LEVEL;
		}
		return this.host.thinkingLevel;
	}

	private clampThinkingLevel(level: ThinkingLevel): ThinkingLevel {
		return this.host.model ? (clampThinkingLevel(this.host.model, level) as ThinkingLevel) : "off";
	}
}
