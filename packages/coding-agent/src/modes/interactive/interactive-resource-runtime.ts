import * as os from "node:os";
import * as path from "node:path";
import type {
	AutocompleteItem,
	AutocompleteProvider,
	Container,
	EditorComponent,
	MarkdownTheme,
	SlashCommand,
	TUI,
} from "@pi-recon/repi-tui";
import {
	CombinedAutocompleteProvider,
	fuzzyFilter,
	getCapabilities,
	hyperlink,
	Markdown,
	Spacer,
	Text,
} from "@pi-recon/repi-tui";
import { APP_NAME, getAgentDir, IS_REPI_PRODUCT, VERSION } from "../../config.ts";
import type { AgentSession } from "../../core/agent-session.ts";
import type { AutocompleteProviderFactory, ExtensionRunner } from "../../core/extensions/index.ts";
import { DefaultPackageManager } from "../../core/package-manager.ts";
import { type ThemeColor, theme } from "../../core/presentation/theme-runtime.ts";
import type { ResourceDiagnostic } from "../../core/resource-loader.ts";
import type { SessionManager } from "../../core/session-manager.ts";
import type { SettingsManager } from "../../core/settings-manager.ts";
import { BUILTIN_SLASH_COMMANDS } from "../../core/slash-commands.ts";
import type { SourceInfo } from "../../core/source-info.ts";
import { isInstallTelemetryEnabled } from "../../core/telemetry.ts";
import { getChangelogPath, getNewEntries, parseChangelog } from "../../utils/changelog.ts";
import { parseGitUrl } from "../../utils/git.ts";
import { drainResponseBody } from "../../utils/http-drain.ts";
import { getCwdRelativePath } from "../../utils/paths.ts";
import { getPiUserAgent } from "../../utils/pi-user-agent.ts";
import { ensureTool } from "../../utils/tools-manager.ts";
import type { LatestPiRelease } from "../../utils/version-check.ts";
import type { CustomEditor } from "./components/custom-editor.ts";
import { DynamicBorder } from "./components/dynamic-border.ts";

type ResourceItem = { path: string; sourceInfo?: SourceInfo };

type ScopeGroup = {
	scope: "user" | "project" | "path";
	paths: ResourceItem[];
	packages: Map<string, ResourceItem[]>;
};

export type ShowLoadedResourcesOptions = {
	extensions?: ResourceItem[];
	force?: boolean;
	showDiagnosticsWhenQuiet?: boolean;
};

export type InteractiveResourceHost = {
	session: AgentSession;
	sessionManager: SessionManager;
	settingsManager: SettingsManager;
	chatContainer: Container;
	defaultEditor: CustomEditor;
	editor: EditorComponent;
	autocompleteProvider?: AutocompleteProvider;
	autocompleteProviderWrappers: AutocompleteProviderFactory[];
	options: { verbose?: boolean };
	version: string;
	toolOutputExpanded: boolean;
	ui: TUI;
	getMarkdownThemeWithSettings(): MarkdownTheme;
};

export class ExpandableText extends Text {
	private readonly getCollapsedText: () => string;
	private readonly getExpandedText: () => string;

	constructor(
		getCollapsedText: () => string,
		getExpandedText: () => string,
		expanded = false,
		paddingX = 0,
		paddingY = 0,
	) {
		super(expanded ? getExpandedText() : getCollapsedText(), paddingX, paddingY);
		this.getCollapsedText = getCollapsedText;
		this.getExpandedText = getExpandedText;
	}

	setExpanded(expanded: boolean): void {
		this.setText(expanded ? this.getExpandedText() : this.getCollapsedText());
	}
}

export class InteractiveResourceRuntime {
	private readonly host: InteractiveResourceHost;
	private fdPath: string | undefined;
	private changelogMarkdown: string | undefined;
	private startupNoticesShown = false;

	constructor(host: InteractiveResourceHost) {
		this.host = host;
	}

	async initializeStartupResources(): Promise<void> {
		this.changelogMarkdown = this.getChangelogForDisplay();
		const [fdPath] = await Promise.all([ensureTool("fd"), ensureTool("rg")]);
		this.fdPath = fdPath;
	}

	private getAutocompleteSourceTag(sourceInfo?: SourceInfo): string | undefined {
		if (!sourceInfo) {
			return undefined;
		}

		const scopePrefix = sourceInfo.scope === "user" ? "u" : sourceInfo.scope === "project" ? "p" : "t";
		const source = sourceInfo.source.trim();

		if (source === "auto" || source === "local" || source === "cli") {
			return scopePrefix;
		}

		if (source.startsWith("npm:")) {
			return `${scopePrefix}:${source}`;
		}

		const gitSource = parseGitUrl(source);
		if (gitSource) {
			const ref = gitSource.ref ? `@${gitSource.ref}` : "";
			return `${scopePrefix}:git:${gitSource.host}/${gitSource.path}${ref}`;
		}

		return scopePrefix;
	}

	private prefixAutocompleteDescription(description: string | undefined, sourceInfo?: SourceInfo): string | undefined {
		const sourceTag = this.getAutocompleteSourceTag(sourceInfo);
		if (!sourceTag) {
			return description;
		}
		return description ? `[${sourceTag}] ${description}` : `[${sourceTag}]`;
	}

	private getBuiltInCommandConflictDiagnostics(extensionRunner: ExtensionRunner): ResourceDiagnostic[] {
		const builtinNames = new Set(BUILTIN_SLASH_COMMANDS.map((command) => command.name));
		return extensionRunner
			.getRegisteredCommands()
			.filter((command) => builtinNames.has(command.name))
			.map((command) => ({
				type: "warning" as const,
				message:
					command.invocationName === command.name
						? `Extension command '/${command.name}' conflicts with built-in interactive command. Skipping in autocomplete.`
						: `Extension command '/${command.name}' conflicts with built-in interactive command. Available as '/${command.invocationName}'.`,
				path: command.sourceInfo.path,
			}));
	}

	private createBaseAutocompleteProvider(): AutocompleteProvider {
		const slashCommands: SlashCommand[] = BUILTIN_SLASH_COMMANDS.map((command) => ({
			name: command.name,
			description: command.description,
		}));

		const modelCommand = slashCommands.find((command) => command.name === "model");
		if (modelCommand) {
			modelCommand.getArgumentCompletions = (prefix: string): AutocompleteItem[] | null => {
				const models =
					this.host.session.scopedModels.length > 0
						? this.host.session.scopedModels.map((scopedModel) => scopedModel.model)
						: this.host.session.modelRegistry.getAvailable();

				if (models.length === 0) return null;

				const items = models.map((model) => ({
					id: model.id,
					provider: model.provider,
					label: `${model.provider}/${model.id}`,
				}));
				const filtered = fuzzyFilter(items, prefix, (item) => `${item.id} ${item.provider}`);
				if (filtered.length === 0) return null;

				return filtered.map((item) => ({
					value: item.label,
					label: item.id,
					description: item.provider,
				}));
			};
		}

		const templateCommands: SlashCommand[] = this.host.session.promptTemplates.map((command) => ({
			name: command.name,
			description: this.prefixAutocompleteDescription(command.description, command.sourceInfo),
			...(command.argumentHint && { argumentHint: command.argumentHint }),
		}));

		const builtinCommandNames = new Set(slashCommands.map((command) => command.name));
		const extensionCommands: SlashCommand[] = this.host.session.extensionRunner
			.getRegisteredCommands()
			.filter((command) => !builtinCommandNames.has(command.name))
			.map((command) => ({
				name: command.invocationName,
				description: this.prefixAutocompleteDescription(command.description, command.sourceInfo),
				getArgumentCompletions: command.getArgumentCompletions,
			}));

		const skillCommands: SlashCommand[] = [];
		if (this.host.settingsManager.getEnableSkillCommands()) {
			for (const skill of this.host.session.resourceLoader.getSkills().skills) {
				skillCommands.push({
					name: `skill:${skill.name}`,
					description: this.prefixAutocompleteDescription(skill.description, skill.sourceInfo),
				});
			}
		}

		return new CombinedAutocompleteProvider(
			[...slashCommands, ...templateCommands, ...extensionCommands, ...skillCommands],
			this.host.sessionManager.getCwd(),
			this.fdPath,
		);
	}

	setupAutocompleteProvider(): void {
		let provider = this.createBaseAutocompleteProvider();
		for (const wrapProvider of this.host.autocompleteProviderWrappers) {
			provider = wrapProvider(provider);
		}

		this.host.autocompleteProvider = provider;
		this.host.defaultEditor.setAutocompleteProvider(provider);
		if (this.host.editor !== this.host.defaultEditor) {
			this.host.editor.setAutocompleteProvider?.(provider);
		}
	}

	getStartupExpansionState(): boolean {
		return this.host.options.verbose === true || this.host.toolOutputExpanded;
	}

	showStartupNoticesIfNeeded(): void {
		if (this.startupNoticesShown) {
			return;
		}
		this.startupNoticesShown = true;

		if (!this.changelogMarkdown) {
			return;
		}

		if (this.host.chatContainer.children.length > 0) {
			this.host.chatContainer.addChild(new Spacer(1));
		}
		this.host.chatContainer.addChild(new DynamicBorder());
		if (this.host.settingsManager.getCollapseChangelog()) {
			const versionMatch = this.changelogMarkdown.match(/##\s+\[?(\d+\.\d+\.\d+)\]?/);
			const latestVersion = versionMatch ? versionMatch[1] : this.host.version;
			const condensedText = `Updated to v${latestVersion}. Use ${theme.bold("/changelog")} to view full changelog.`;
			this.host.chatContainer.addChild(new Text(condensedText, 1, 0));
		} else {
			this.host.chatContainer.addChild(new Text(theme.bold(theme.fg("accent", "What's New")), 1, 0));
			this.host.chatContainer.addChild(new Spacer(1));
			this.host.chatContainer.addChild(
				new Markdown(this.changelogMarkdown.trim(), 1, 0, this.host.getMarkdownThemeWithSettings()),
			);
			this.host.chatContainer.addChild(new Spacer(1));
		}
		this.host.chatContainer.addChild(new DynamicBorder());
	}

	async checkForPackageUpdates(): Promise<string[]> {
		if (IS_REPI_PRODUCT || process.env.PI_SKIP_PACKAGE_UPDATE_CHECK || process.env.PI_OFFLINE) {
			return [];
		}

		try {
			const packageManager = new DefaultPackageManager({
				cwd: this.host.sessionManager.getCwd(),
				agentDir: getAgentDir(),
				settingsManager: this.host.settingsManager,
			});
			const updates = await packageManager.checkForAvailableUpdates();
			return updates.map((update) => update.displayName);
		} catch {
			return [];
		}
	}

	private getChangelogForDisplay(): string | undefined {
		if (IS_REPI_PRODUCT || this.host.session.state.messages.length > 0) {
			return undefined;
		}

		const lastVersion = this.host.settingsManager.getLastChangelogVersion();
		const entries = parseChangelog(getChangelogPath());

		if (!lastVersion) {
			this.host.settingsManager.setLastChangelogVersion(VERSION);
			this.reportInstallTelemetry(VERSION);
			return undefined;
		}

		const newEntries = getNewEntries(entries, lastVersion);
		if (newEntries.length > 0) {
			this.host.settingsManager.setLastChangelogVersion(VERSION);
			this.reportInstallTelemetry(VERSION);
			return newEntries.map((entry) => entry.content).join("\n\n");
		}

		return undefined;
	}

	private reportInstallTelemetry(version: string): void {
		if (IS_REPI_PRODUCT || process.env.PI_OFFLINE || !isInstallTelemetryEnabled(this.host.settingsManager)) {
			return;
		}

		void fetch(`https://pi.dev/api/report-install?version=${encodeURIComponent(version)}`, {
			headers: {
				"User-Agent": getPiUserAgent(version),
			},
			signal: AbortSignal.timeout(5000),
		})
			.then((response) => drainResponseBody(response))
			.catch(() => undefined);
	}

	showNewVersionNotification(release: LatestPiRelease): void {
		if (IS_REPI_PRODUCT) return;
		const action = theme.fg("accent", `${APP_NAME} update`);
		const updateInstruction = theme.fg("muted", `New version ${release.version} is available. Run `) + action;
		const changelogUrl = "https://pi.dev/changelog";
		const changelogLink = getCapabilities().hyperlinks
			? hyperlink(theme.fg("accent", "open changelog"), changelogUrl)
			: theme.fg("accent", changelogUrl);
		const changelogLine = theme.fg("muted", "Changelog: ") + changelogLink;
		const note = release.note?.trim();

		this.host.chatContainer.addChild(new Spacer(1));
		this.host.chatContainer.addChild(new DynamicBorder((text) => theme.fg("warning", text)));
		this.host.chatContainer.addChild(
			new Text(`${theme.bold(theme.fg("warning", "Update Available"))}\n${updateInstruction}`, 1, 0),
		);
		if (note) {
			this.host.chatContainer.addChild(new Spacer(1));
			this.host.chatContainer.addChild(
				new Markdown(note, 1, 0, this.host.getMarkdownThemeWithSettings(), {
					color: (text) => theme.fg("muted", text),
				}),
			);
			this.host.chatContainer.addChild(new Spacer(1));
		}
		this.host.chatContainer.addChild(new Text(changelogLine, 1, 0));
		this.host.chatContainer.addChild(new DynamicBorder((text) => theme.fg("warning", text)));
		this.host.ui.requestRender();
	}

	showPackageUpdateNotification(packages: string[]): void {
		if (IS_REPI_PRODUCT) return;
		const action = theme.fg("accent", `${APP_NAME} update`);
		const updateInstruction = theme.fg("muted", "Package updates are available. Run ") + action;
		const packageLines = packages.map((packageName) => `- ${packageName}`).join("\n");

		this.host.chatContainer.addChild(new Spacer(1));
		this.host.chatContainer.addChild(new DynamicBorder((text) => theme.fg("warning", text)));
		this.host.chatContainer.addChild(
			new Text(
				`${theme.bold(theme.fg("warning", "Package Updates Available"))}\n${updateInstruction}\n${theme.fg("muted", "Packages:")}\n${packageLines}`,
				1,
				0,
			),
		);
		this.host.chatContainer.addChild(new DynamicBorder((text) => theme.fg("warning", text)));
		this.host.ui.requestRender();
	}

	private formatDisplayPath(resourcePath: string): string {
		const home = os.homedir();
		return resourcePath.startsWith(home) ? `~${resourcePath.slice(home.length)}` : resourcePath;
	}

	private formatExtensionDisplayPath(resourcePath: string): string {
		return this.formatDisplayPath(resourcePath)
			.replace(/\/index\.ts$/, "")
			.replace(/\/index\.js$/, "");
	}

	private formatContextPath(resourcePath: string): string {
		const cwd = path.resolve(this.host.sessionManager.getCwd());
		const absolutePath = path.isAbsolute(resourcePath) ? path.resolve(resourcePath) : path.resolve(cwd, resourcePath);
		const relativePath = getCwdRelativePath(absolutePath, cwd);
		return relativePath ?? this.formatDisplayPath(absolutePath);
	}

	private isPackageSource(sourceInfo?: SourceInfo): boolean {
		const source = sourceInfo?.source ?? "";
		return source.startsWith("npm:") || source.startsWith("git:");
	}

	private getShortPath(fullPath: string, sourceInfo?: SourceInfo): string {
		const baseDir = sourceInfo?.baseDir;
		if (baseDir && this.isPackageSource(sourceInfo)) {
			const relativePath = path.relative(path.resolve(baseDir), path.resolve(fullPath));
			if (
				relativePath &&
				relativePath !== "." &&
				!relativePath.startsWith("..") &&
				!relativePath.startsWith(`..${path.sep}`) &&
				!path.isAbsolute(relativePath)
			) {
				return relativePath.replace(/\\/g, "/");
			}
		}

		const source = sourceInfo?.source ?? "";
		const npmMatch = fullPath.match(/node_modules\/(@?[^/]+(?:\/[^/]+)?)\/(.*)/);
		if (npmMatch && source.startsWith("npm:")) {
			return npmMatch[2];
		}

		const gitMatch = fullPath.match(/git\/[^/]+\/[^/]+\/(.*)/);
		if (gitMatch && source.startsWith("git:")) {
			return gitMatch[1];
		}

		return this.formatDisplayPath(fullPath);
	}

	private getCompactPathLabel(resourcePath: string, sourceInfo?: SourceInfo): string {
		const shortPath = this.getShortPath(resourcePath, sourceInfo);
		const segments = shortPath
			.replace(/\\/g, "/")
			.split("/")
			.filter((segment) => segment.length > 0 && segment !== "~");
		return segments.length > 0 ? segments[segments.length - 1]! : shortPath;
	}

	private getCompactPackageSourceLabel(sourceInfo?: SourceInfo): string {
		const source = sourceInfo?.source ?? "";
		if (source.startsWith("npm:")) {
			return source.slice("npm:".length) || source;
		}

		const gitSource = parseGitUrl(source);
		return gitSource ? gitSource.path || source : source;
	}

	private getCompactExtensionLabel(resourcePath: string, sourceInfo?: SourceInfo): string {
		if (!this.isPackageSource(sourceInfo)) {
			return this.getCompactPathLabel(resourcePath, sourceInfo);
		}

		const sourceLabel = this.getCompactPackageSourceLabel(sourceInfo);
		if (!sourceLabel) {
			return this.getCompactPathLabel(resourcePath, sourceInfo);
		}

		const shortPath = this.getShortPath(resourcePath, sourceInfo).replace(/\\/g, "/");
		const packagePath = shortPath.startsWith("extensions/") ? shortPath.slice("extensions/".length) : shortPath;
		const parsedPath = path.posix.parse(packagePath);

		if (parsedPath.name === "index") {
			return !parsedPath.dir || parsedPath.dir === "." ? sourceLabel : `${sourceLabel}:${parsedPath.dir}`;
		}

		return `${sourceLabel}:${packagePath}`;
	}

	private getCompactDisplayPathSegments(resourcePath: string): string[] {
		return this.formatDisplayPath(resourcePath)
			.replace(/\\/g, "/")
			.split("/")
			.filter((segment) => segment.length > 0 && segment !== "~");
	}

	private getCompactNonPackageExtensionLabel(
		resourcePath: string,
		index: number,
		allPaths: Array<{ path: string; segments: string[] }>,
	): string {
		const segments = allPaths[index]?.segments;
		if (!segments || segments.length === 0) {
			return this.getCompactPathLabel(resourcePath);
		}

		for (let segmentCount = 1; segmentCount <= segments.length; segmentCount += 1) {
			const candidate = segments.slice(-segmentCount).join("/");
			const isUnique = allPaths.every(
				(item, itemIndex) => itemIndex === index || item.segments.slice(-segmentCount).join("/") !== candidate,
			);
			if (isUnique) {
				return candidate;
			}
		}

		return segments.join("/");
	}

	private getCompactExtensionLabels(extensions: ResourceItem[]): string[] {
		const nonPackageExtensions = extensions
			.map((extension) => {
				const segments = this.getCompactDisplayPathSegments(extension.path);
				const lastSegment = segments[segments.length - 1];
				if (segments.length > 1 && (lastSegment === "index.ts" || lastSegment === "index.js")) {
					segments.pop();
				}
				return { path: extension.path, sourceInfo: extension.sourceInfo, segments };
			})
			.filter((extension) => !this.isPackageSource(extension.sourceInfo));

		return extensions.map((extension) => {
			if (this.isPackageSource(extension.sourceInfo)) {
				return this.getCompactExtensionLabel(extension.path, extension.sourceInfo);
			}

			const nonPackageIndex = nonPackageExtensions.findIndex((item) => item.path === extension.path);
			return nonPackageIndex === -1
				? this.getCompactPathLabel(extension.path, extension.sourceInfo)
				: this.getCompactNonPackageExtensionLabel(extension.path, nonPackageIndex, nonPackageExtensions);
		});
	}

	private getDisplaySourceInfo(sourceInfo?: SourceInfo): { label: string; scopeLabel?: string } {
		const source = sourceInfo?.source ?? "local";
		const scope = sourceInfo?.scope ?? "project";
		if (source === "local") {
			if (scope === "user") return { label: "user" };
			if (scope === "project") return { label: "project" };
			if (scope === "temporary") return { label: "path", scopeLabel: "temp" };
			return { label: "path" };
		}

		if (source === "cli") {
			return { label: "path", scopeLabel: scope === "temporary" ? "temp" : undefined };
		}

		const scopeLabel =
			scope === "user" ? "user" : scope === "project" ? "project" : scope === "temporary" ? "temp" : undefined;
		return { label: source, scopeLabel };
	}

	private getScopeGroup(sourceInfo?: SourceInfo): "user" | "project" | "path" {
		const source = sourceInfo?.source ?? "local";
		const scope = sourceInfo?.scope ?? "project";
		if (source === "cli" || scope === "temporary") return "path";
		if (scope === "user") return "user";
		if (scope === "project") return "project";
		return "path";
	}

	private buildScopeGroups(items: ResourceItem[]): ScopeGroup[] {
		const groups: Record<ScopeGroup["scope"], ScopeGroup> = {
			user: { scope: "user", paths: [], packages: new Map() },
			project: { scope: "project", paths: [], packages: new Map() },
			path: { scope: "path", paths: [], packages: new Map() },
		};

		for (const item of items) {
			const group = groups[this.getScopeGroup(item.sourceInfo)];
			const source = item.sourceInfo?.source ?? "local";
			if (this.isPackageSource(item.sourceInfo)) {
				const packageItems = group.packages.get(source) ?? [];
				packageItems.push(item);
				group.packages.set(source, packageItems);
			} else {
				group.paths.push(item);
			}
		}

		return [groups.project, groups.user, groups.path].filter(
			(group) => group.paths.length > 0 || group.packages.size > 0,
		);
	}

	private formatScopeGroups(
		groups: ScopeGroup[],
		options: {
			formatPath: (item: ResourceItem) => string;
			formatPackagePath: (item: ResourceItem, source: string) => string;
		},
	): string {
		const lines: string[] = [];
		for (const group of groups) {
			lines.push(`  ${theme.fg("accent", group.scope)}`);
			for (const item of [...group.paths].sort((a, b) => a.path.localeCompare(b.path))) {
				lines.push(theme.fg("dim", `    ${options.formatPath(item)}`));
			}

			const sortedPackages = Array.from(group.packages.entries()).sort(([a], [b]) => a.localeCompare(b));
			for (const [source, items] of sortedPackages) {
				lines.push(`    ${theme.fg("mdLink", source)}`);
				for (const item of [...items].sort((a, b) => a.path.localeCompare(b.path))) {
					lines.push(theme.fg("dim", `      ${options.formatPackagePath(item, source)}`));
				}
			}
		}

		return lines.join("\n");
	}

	private findSourceInfoForPath(resourcePath: string, sourceInfos: Map<string, SourceInfo>): SourceInfo | undefined {
		const exact = sourceInfos.get(resourcePath);
		if (exact) return exact;

		let current = resourcePath;
		while (current.includes("/")) {
			current = current.substring(0, current.lastIndexOf("/"));
			const parent = sourceInfos.get(current);
			if (parent) return parent;
		}

		return undefined;
	}

	private formatPathWithSource(resourcePath: string, sourceInfo?: SourceInfo): string {
		if (!sourceInfo) {
			return this.formatDisplayPath(resourcePath);
		}
		const shortPath = this.getShortPath(resourcePath, sourceInfo);
		const { label, scopeLabel } = this.getDisplaySourceInfo(sourceInfo);
		return `${scopeLabel ? `${label} (${scopeLabel})` : label} ${shortPath}`;
	}

	private formatDiagnostics(diagnostics: readonly ResourceDiagnostic[], sourceInfos: Map<string, SourceInfo>): string {
		const lines: string[] = [];
		const collisions = new Map<string, ResourceDiagnostic[]>();
		const otherDiagnostics: ResourceDiagnostic[] = [];

		for (const diagnostic of diagnostics) {
			if (diagnostic.type === "collision" && diagnostic.collision) {
				const collisionList = collisions.get(diagnostic.collision.name) ?? [];
				collisionList.push(diagnostic);
				collisions.set(diagnostic.collision.name, collisionList);
			} else {
				otherDiagnostics.push(diagnostic);
			}
		}

		for (const [name, collisionList] of collisions) {
			const first = collisionList[0]?.collision;
			if (!first) continue;
			lines.push(theme.fg("warning", `  "${name}" collision:`));
			lines.push(
				theme.fg(
					"dim",
					`    ${theme.fg("success", "✓")} ${this.formatPathWithSource(first.winnerPath, this.findSourceInfoForPath(first.winnerPath, sourceInfos))}`,
				),
			);
			for (const diagnostic of collisionList) {
				if (!diagnostic.collision) continue;
				lines.push(
					theme.fg(
						"dim",
						`    ${theme.fg("warning", "✗")} ${this.formatPathWithSource(diagnostic.collision.loserPath, this.findSourceInfoForPath(diagnostic.collision.loserPath, sourceInfos))} (skipped)`,
					),
				);
			}
		}

		for (const diagnostic of otherDiagnostics) {
			const color = diagnostic.type === "error" ? "error" : "warning";
			if (diagnostic.path) {
				const formattedPath = this.formatPathWithSource(
					diagnostic.path,
					this.findSourceInfoForPath(diagnostic.path, sourceInfos),
				);
				lines.push(theme.fg(color, `  ${formattedPath}`));
				lines.push(theme.fg(color, `    ${diagnostic.message}`));
			} else {
				lines.push(theme.fg(color, `  ${diagnostic.message}`));
			}
		}

		return lines.join("\n");
	}

	showLoadedResources(options?: ShowLoadedResourcesOptions): void {
		const showListing = options?.force || this.host.options.verbose || !this.host.settingsManager.getQuietStartup();
		const showDiagnostics = showListing || options?.showDiagnosticsWhenQuiet === true;
		if (!showListing && !showDiagnostics) return;

		const sectionHeader = (name: string, color: ThemeColor = "mdHeading") => theme.fg(color, `[${name}]`);
		const formatCompactList = (items: string[], sort = true): string => {
			const labels = items.map((item) => item.trim()).filter((item) => item.length > 0);
			if (sort) labels.sort((a, b) => a.localeCompare(b));
			return theme.fg("dim", `  ${labels.join(", ")}`);
		};
		const addLoadedSection = (
			name: string,
			collapsedBody: string,
			expandedBody = collapsedBody,
			color: ThemeColor = "mdHeading",
		): void => {
			this.host.chatContainer.addChild(
				new ExpandableText(
					() => `${sectionHeader(name, color)}\n${collapsedBody}`,
					() => `${sectionHeader(name, color)}\n${expandedBody}`,
					this.getStartupExpansionState(),
				),
			);
			this.host.chatContainer.addChild(new Spacer(1));
		};

		const skillsResult = this.host.session.resourceLoader.getSkills();
		const promptsResult = this.host.session.resourceLoader.getPrompts();
		const themesResult = this.host.session.resourceLoader.getThemes();
		const extensions =
			options?.extensions ??
			this.host.session.resourceLoader.getExtensions().extensions.map((extension) => ({
				path: extension.path,
				sourceInfo: extension.sourceInfo,
			}));
		const sourceInfos = new Map<string, SourceInfo>();
		for (const extension of extensions) {
			if (extension.sourceInfo) sourceInfos.set(extension.path, extension.sourceInfo);
		}
		for (const skill of skillsResult.skills) {
			if (skill.sourceInfo) sourceInfos.set(skill.filePath, skill.sourceInfo);
		}
		for (const prompt of promptsResult.prompts) {
			if (prompt.sourceInfo) sourceInfos.set(prompt.filePath, prompt.sourceInfo);
		}
		for (const loadedTheme of themesResult.themes) {
			if (loadedTheme.sourcePath && loadedTheme.sourceInfo) {
				sourceInfos.set(loadedTheme.sourcePath, loadedTheme.sourceInfo);
			}
		}

		if (showListing) {
			const contextFiles = this.host.session.resourceLoader.getAgentsFiles().agentsFiles;
			if (contextFiles.length > 0) {
				this.host.chatContainer.addChild(new Spacer(1));
				const contextList = contextFiles
					.map((file) => theme.fg("dim", `  ${this.formatDisplayPath(file.path)}`))
					.join("\n");
				addLoadedSection(
					"Context",
					formatCompactList(
						contextFiles.map((file) => this.formatContextPath(file.path)),
						false,
					),
					contextList,
				);
			}

			const skills = skillsResult.skills;
			if (skills.length > 0) {
				const skillList = this.formatScopeGroups(
					this.buildScopeGroups(skills.map((skill) => ({ path: skill.filePath, sourceInfo: skill.sourceInfo }))),
					{
						formatPath: (item) => this.formatDisplayPath(item.path),
						formatPackagePath: (item) => this.getShortPath(item.path, item.sourceInfo),
					},
				);
				addLoadedSection("Skills", formatCompactList(skills.map((skill) => skill.name)), skillList);
			}

			const templates = this.host.session.promptTemplates;
			if (templates.length > 0) {
				const templateByPath = new Map(templates.map((template) => [template.filePath, template]));
				const templateList = this.formatScopeGroups(
					this.buildScopeGroups(
						templates.map((template) => ({ path: template.filePath, sourceInfo: template.sourceInfo })),
					),
					{
						formatPath: (item) => {
							const template = templateByPath.get(item.path);
							return template ? `/${template.name}` : this.formatDisplayPath(item.path);
						},
						formatPackagePath: (item) => {
							const template = templateByPath.get(item.path);
							return template ? `/${template.name}` : this.formatDisplayPath(item.path);
						},
					},
				);
				addLoadedSection(
					"Prompts",
					formatCompactList(templates.map((template) => `/${template.name}`)),
					templateList,
				);
			}

			if (extensions.length > 0) {
				const extensionList = this.formatScopeGroups(this.buildScopeGroups(extensions), {
					formatPath: (item) => this.formatExtensionDisplayPath(item.path),
					formatPackagePath: (item) =>
						this.formatExtensionDisplayPath(this.getShortPath(item.path, item.sourceInfo)),
				});
				addLoadedSection(
					"Extensions",
					formatCompactList(this.getCompactExtensionLabels(extensions)),
					extensionList,
				);
			}

			const customThemes = themesResult.themes.filter((loadedTheme) => loadedTheme.sourcePath);
			if (customThemes.length > 0) {
				const themeList = this.formatScopeGroups(
					this.buildScopeGroups(
						customThemes.map((loadedTheme) => ({
							path: loadedTheme.sourcePath!,
							sourceInfo: loadedTheme.sourceInfo,
						})),
					),
					{
						formatPath: (item) => this.formatDisplayPath(item.path),
						formatPackagePath: (item) => this.getShortPath(item.path, item.sourceInfo),
					},
				);
				addLoadedSection(
					"Themes",
					formatCompactList(
						customThemes.map(
							(loadedTheme) =>
								loadedTheme.name ?? this.getCompactPathLabel(loadedTheme.sourcePath!, loadedTheme.sourceInfo),
						),
					),
					themeList,
				);
			}
		}

		if (showDiagnostics) {
			this.addDiagnosticsSection("Skill conflicts", skillsResult.diagnostics, sourceInfos);
			this.addDiagnosticsSection("Prompt conflicts", promptsResult.diagnostics, sourceInfos);

			const extensionDiagnostics: ResourceDiagnostic[] = [];
			for (const error of this.host.session.resourceLoader.getExtensions().errors) {
				extensionDiagnostics.push({ type: "error", message: error.error, path: error.path });
			}
			extensionDiagnostics.push(...this.host.session.extensionRunner.getCommandDiagnostics());
			extensionDiagnostics.push(...this.getBuiltInCommandConflictDiagnostics(this.host.session.extensionRunner));
			extensionDiagnostics.push(...this.host.session.extensionRunner.getShortcutDiagnostics());
			this.addDiagnosticsSection("Extension issues", extensionDiagnostics, sourceInfos);
			this.addDiagnosticsSection("Theme conflicts", themesResult.diagnostics, sourceInfos);
		}
	}

	private addDiagnosticsSection(
		name: string,
		diagnostics: readonly ResourceDiagnostic[],
		sourceInfos: Map<string, SourceInfo>,
	): void {
		if (diagnostics.length === 0) return;
		const warningLines = this.formatDiagnostics(diagnostics, sourceInfos);
		this.host.chatContainer.addChild(new Text(`${theme.fg("warning", `[${name}]`)}\n${warningLines}`, 0, 0));
		this.host.chatContainer.addChild(new Spacer(1));
	}
}
