/**
 * Extension loader - loads TypeScript extension modules using jiti.
 *
 */

import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as _bundledPiAgentCore from "@pi-recon/repi-agent-core";
import * as _bundledPiAgentCoreNode from "@pi-recon/repi-agent-core/node";
import type { Provider } from "@pi-recon/repi-ai";
import * as _bundledPiAi from "@pi-recon/repi-ai";
import * as _bundledPiAiOauth from "@pi-recon/repi-ai/oauth";
import type { KeyId } from "@pi-recon/repi-tui";
import * as _bundledPiTui from "@pi-recon/repi-tui";
import { createJiti } from "jiti/static";
// Static imports of packages that extensions may use.
// These MUST be static so Bun bundles them into the compiled binary.
// The virtualModules option then makes them available to extensions.
import * as _bundledTypebox from "typebox";
import * as _bundledTypeboxCompile from "typebox/compile";
import * as _bundledTypeboxValue from "typebox/value";
import { CONFIG_DIR_NAME, getAgentDir, isBunBinary } from "../../config.ts";
import { resolvePath } from "../../utils/paths.ts";
import { createEventBus, type EventBus } from "../event-bus.ts";
import type { ExecOptions } from "../exec.ts";
import { execCommand } from "../exec.ts";
import { createSyntheticSourceInfo } from "../source-info.ts";
import type {
	Extension,
	ExtensionAPI,
	ExtensionFactory,
	ExtensionRuntime,
	LoadExtensionsResult,
	MessageRenderer,
	ProviderConfig,
	RegisteredCommand,
	ToolDefinition,
} from "./types.ts";
import * as _bundledPiCodingAgentExtensionSdk from "./types.ts";

/** Modules available to extensions via virtualModules (for compiled Bun binary) */
const VIRTUAL_MODULES: Record<string, unknown> = {
	typebox: _bundledTypebox,
	"typebox/compile": _bundledTypeboxCompile,
	"typebox/value": _bundledTypeboxValue,
	"@sinclair/typebox": _bundledTypebox,
	"@sinclair/typebox/compile": _bundledTypeboxCompile,
	"@sinclair/typebox/value": _bundledTypeboxValue,
	"@pi-recon/repi-agent-core": _bundledPiAgentCore,
	"@pi-recon/repi-agent-core/node": _bundledPiAgentCoreNode,
	"@pi-recon/repi-tui": _bundledPiTui,
	"@pi-recon/repi-ai": _bundledPiAi,
	"@pi-recon/repi-ai/compat": _bundledPiAi,
	"@pi-recon/repi-ai/oauth": _bundledPiAiOauth,
	"@pi-recon/repi-coding-agent": _bundledPiCodingAgentExtensionSdk,
	"@mariozechner/repi-agent-core": _bundledPiAgentCore,
	"@mariozechner/repi-agent-core/node": _bundledPiAgentCoreNode,
	"@mariozechner/repi-tui": _bundledPiTui,
	"@mariozechner/repi-ai": _bundledPiAi,
	"@mariozechner/repi-ai/compat": _bundledPiAi,
	"@mariozechner/repi-ai/oauth": _bundledPiAiOauth,
	"@mariozechner/repi-coding-agent": _bundledPiCodingAgentExtensionSdk,
	"@earendil-works/pi-agent-core": _bundledPiAgentCore,
	"@earendil-works/pi-agent-core/node": _bundledPiAgentCoreNode,
	"@earendil-works/pi-tui": _bundledPiTui,
	"@earendil-works/pi-ai": _bundledPiAi,
	"@earendil-works/pi-ai/compat": _bundledPiAi,
	"@earendil-works/pi-ai/oauth": _bundledPiAiOauth,
	"@earendil-works/pi-coding-agent": _bundledPiCodingAgentExtensionSdk,
};

const require = createRequire(import.meta.url);

/**
 * Get aliases for jiti (used in Node.js/development mode).
 * In Bun binary mode, virtualModules is used instead.
 */
let _aliases: Record<string, string> | null = null;

function getAliases(): Record<string, string> {
	if (_aliases) return _aliases;

	const __dirname = path.dirname(fileURLToPath(import.meta.url));
	const runningFromSource = __dirname.split(path.sep).includes("src");
	const extensionSdkJs = path.resolve(__dirname, "types.js");
	const extensionSdkTs = path.resolve(__dirname, "types.ts");

	const typeboxEntry = require.resolve("typebox");
	const typeboxCompileEntry = require.resolve("typebox/compile");
	const typeboxValueEntry = require.resolve("typebox/value");

	const packagesRoot = path.resolve(__dirname, "../../../../");
	const resolveWorkspaceOrImport = (
		sourceWorkspaceRelativePath: string,
		distWorkspaceRelativePath: string,
		specifier: string,
	): string => {
		const candidates = runningFromSource
			? [sourceWorkspaceRelativePath, distWorkspaceRelativePath]
			: [distWorkspaceRelativePath, sourceWorkspaceRelativePath];
		for (const workspaceRelativePath of candidates) {
			const workspacePath = path.join(packagesRoot, workspaceRelativePath);
			if (fs.existsSync(workspacePath)) {
				return workspacePath;
			}
		}
		return fileURLToPath(import.meta.resolve(specifier));
	};

	const piCodingAgentEntry = runningFromSource
		? fs.existsSync(extensionSdkTs)
			? extensionSdkTs
			: extensionSdkJs
		: fs.existsSync(extensionSdkJs)
			? extensionSdkJs
			: extensionSdkTs;
	const piAgentCoreEntry = resolveWorkspaceOrImport(
		"agent/src/index.ts",
		"agent/dist/index.js",
		"@pi-recon/repi-agent-core",
	);
	const piAgentCoreNodeEntry = resolveWorkspaceOrImport(
		"agent/src/node.ts",
		"agent/dist/node.js",
		"@pi-recon/repi-agent-core/node",
	);
	const piTuiEntry = resolveWorkspaceOrImport("tui/src/index.ts", "tui/dist/index.js", "@pi-recon/repi-tui");
	const piAiEntry = resolveWorkspaceOrImport("ai/src/index.ts", "ai/dist/index.js", "@pi-recon/repi-ai");
	const piAiCompatEntry = resolveWorkspaceOrImport(
		"ai/src/compat.ts",
		"ai/dist/compat.js",
		"@pi-recon/repi-ai/compat",
	);
	const piAiOauthEntry = resolveWorkspaceOrImport("ai/src/oauth.ts", "ai/dist/oauth.js", "@pi-recon/repi-ai/oauth");

	_aliases = {
		"@pi-recon/repi-coding-agent": piCodingAgentEntry,
		"@pi-recon/repi-agent-core": piAgentCoreEntry,
		"@pi-recon/repi-agent-core/node": piAgentCoreNodeEntry,
		"@pi-recon/repi-tui": piTuiEntry,
		"@pi-recon/repi-ai": piAiEntry,
		"@pi-recon/repi-ai/compat": piAiCompatEntry,
		"@pi-recon/repi-ai/oauth": piAiOauthEntry,
		"@mariozechner/repi-coding-agent": piCodingAgentEntry,
		"@mariozechner/repi-agent-core": piAgentCoreEntry,
		"@mariozechner/repi-agent-core/node": piAgentCoreNodeEntry,
		"@mariozechner/repi-tui": piTuiEntry,
		"@mariozechner/repi-ai": piAiEntry,
		"@mariozechner/repi-ai/compat": piAiCompatEntry,
		"@mariozechner/repi-ai/oauth": piAiOauthEntry,
		"@earendil-works/pi-coding-agent": piCodingAgentEntry,
		"@earendil-works/pi-agent-core": piAgentCoreEntry,
		"@earendil-works/pi-agent-core/node": piAgentCoreNodeEntry,
		"@earendil-works/pi-tui": piTuiEntry,
		"@earendil-works/pi-ai": piAiEntry,
		"@earendil-works/pi-ai/compat": piAiCompatEntry,
		"@earendil-works/pi-ai/oauth": piAiOauthEntry,
		typebox: typeboxEntry,
		"typebox/compile": typeboxCompileEntry,
		"typebox/value": typeboxValueEntry,
		"@sinclair/typebox": typeboxEntry,
		"@sinclair/typebox/compile": typeboxCompileEntry,
		"@sinclair/typebox/value": typeboxValueEntry,
	};

	return _aliases;
}

type HandlerFn = (...args: unknown[]) => Promise<unknown>;

/**
 * Create a runtime with throwing stubs for action methods.
 * Runner.bindCore() replaces these with real implementations.
 */
export function createExtensionRuntime(): ExtensionRuntime {
	const notInitialized = () => {
		throw new Error("Extension runtime not initialized. Action methods cannot be called during extension loading.");
	};
	const state: { staleMessage?: string } = {};
	const assertActive = () => {
		if (state.staleMessage) {
			throw new Error(state.staleMessage);
		}
	};

	const runtime: ExtensionRuntime = {
		sendMessage: notInitialized,
		sendUserMessage: notInitialized,
		appendEntry: notInitialized,
		setSessionName: notInitialized,
		getSessionName: notInitialized,
		setLabel: notInitialized,
		getActiveTools: notInitialized,
		getAllTools: notInitialized,
		setActiveTools: notInitialized,
		// registerTool() is valid during extension load; refresh is only needed post-bind.
		refreshTools: () => {},
		getCommands: notInitialized,
		setModel: () => Promise.reject(new Error("Extension runtime not initialized")),
		getThinkingLevel: notInitialized,
		setThinkingLevel: notInitialized,
		flagValues: new Map(),
		pendingProviderRegistrations: [],
		pendingNativeProviderRegistrations: [],
		nextProviderRegistrationOrder: 0,
		assertActive,
		invalidate: (message) => {
			state.staleMessage ??=
				message ??
				"This extension ctx is stale after session replacement or reload. Do not use a captured pi or command ctx after ctx.newSession(), ctx.fork(), ctx.switchSession(), or ctx.reload(). For newSession, fork, and switchSession, move post-replacement work into withSession and use the ctx passed to withSession. For reload, do not use the old ctx after await ctx.reload().";
		},
		// Pre-bind: queue registrations so bindCore() can flush them once the
		// model registry is available. bindCore() replaces both with direct calls.
		registerProvider: (name, config, extensionPath = "<unknown>") => {
			runtime.pendingProviderRegistrations.push({
				name,
				config,
				extensionPath,
				order: runtime.nextProviderRegistrationOrder++,
			});
		},
		registerNativeProvider: (provider, extensionPath = "<unknown>") => {
			runtime.pendingNativeProviderRegistrations.push({
				provider,
				extensionPath,
				order: runtime.nextProviderRegistrationOrder++,
			});
		},
		unregisterProvider: (name, extensionPath = "<unknown>") => {
			runtime.pendingProviderRegistrations = runtime.pendingProviderRegistrations.filter(
				(registration) => registration.name !== name || registration.extensionPath !== extensionPath,
			);
			runtime.pendingNativeProviderRegistrations = runtime.pendingNativeProviderRegistrations.filter(
				(registration) => registration.provider.id !== name || registration.extensionPath !== extensionPath,
			);
		},
	};

	return runtime;
}

/**
 * Create the ExtensionAPI for an extension.
 * Registration methods write to the extension object.
 * Action methods delegate to the shared runtime.
 */
function createExtensionAPI(
	extension: Extension,
	runtime: ExtensionRuntime,
	cwd: string,
	eventBus: EventBus,
): ExtensionAPI {
	const api = {
		// Registration methods - write to extension
		on(event: string, handler: HandlerFn): void {
			runtime.assertActive();
			const list = extension.handlers.get(event) ?? [];
			list.push(handler);
			extension.handlers.set(event, list);
		},

		registerTool(tool: ToolDefinition): void {
			runtime.assertActive();
			extension.tools.set(tool.name, {
				definition: tool,
				sourceInfo: extension.sourceInfo,
			});
			runtime.refreshTools();
		},

		registerCommand(name: string, options: Omit<RegisteredCommand, "name" | "sourceInfo">): void {
			runtime.assertActive();
			extension.commands.set(name, {
				name,
				sourceInfo: extension.sourceInfo,
				...options,
			});
		},

		registerShortcut(
			shortcut: KeyId,
			options: {
				description?: string;
				handler: (ctx: import("./types.ts").ExtensionContext) => Promise<void> | void;
			},
		): void {
			runtime.assertActive();
			extension.shortcuts.set(shortcut, { shortcut, extensionPath: extension.path, ...options });
		},

		registerFlag(
			name: string,
			options: { description?: string; type: "boolean" | "string"; default?: boolean | string },
		): void {
			runtime.assertActive();
			extension.flags.set(name, { name, extensionPath: extension.path, ...options });
			if (options.default !== undefined && !runtime.flagValues.has(name)) {
				runtime.flagValues.set(name, options.default);
			}
		},

		registerMessageRenderer<T>(customType: string, renderer: MessageRenderer<T>): void {
			runtime.assertActive();
			extension.messageRenderers.set(customType, renderer as MessageRenderer);
		},

		// Flag access - checks extension registered it, reads from runtime
		getFlag(name: string): boolean | string | undefined {
			runtime.assertActive();
			if (!extension.flags.has(name)) return undefined;
			return runtime.flagValues.get(name);
		},

		// Action methods - delegate to shared runtime
		sendMessage(message, options): void {
			runtime.assertActive();
			runtime.sendMessage(message, options);
		},

		sendUserMessage(content, options): void {
			runtime.assertActive();
			runtime.sendUserMessage(content, options);
		},

		appendEntry(customType: string, data?: unknown): void {
			runtime.assertActive();
			runtime.appendEntry(customType, data);
		},

		setSessionName(name: string): void {
			runtime.assertActive();
			runtime.setSessionName(name);
		},

		getSessionName(): string | undefined {
			runtime.assertActive();
			return runtime.getSessionName();
		},

		setLabel(entryId: string, label: string | undefined): void {
			runtime.assertActive();
			runtime.setLabel(entryId, label);
		},

		exec(command: string, args: string[], options?: ExecOptions) {
			runtime.assertActive();
			return execCommand(command, args, options?.cwd ?? cwd, options);
		},

		getActiveTools(): string[] {
			runtime.assertActive();
			return runtime.getActiveTools();
		},

		getAllTools() {
			runtime.assertActive();
			return runtime.getAllTools();
		},

		setActiveTools(toolNames: string[]): void {
			runtime.assertActive();
			runtime.setActiveTools(toolNames);
		},

		getCommands() {
			runtime.assertActive();
			return runtime.getCommands();
		},

		setModel(model) {
			runtime.assertActive();
			return runtime.setModel(model);
		},

		getThinkingLevel() {
			runtime.assertActive();
			return runtime.getThinkingLevel();
		},

		setThinkingLevel(level) {
			runtime.assertActive();
			runtime.setThinkingLevel(level);
		},

		registerProvider(providerOrName: Provider | string, config?: ProviderConfig) {
			runtime.assertActive();
			if (typeof providerOrName === "string") {
				if (!config) throw new Error("Provider config is required when registering by name");
				runtime.registerProvider(providerOrName, config, extension.path);
				return;
			}
			runtime.registerNativeProvider(providerOrName, extension.path);
		},

		unregisterProvider(name: string) {
			runtime.assertActive();
			runtime.unregisterProvider(name, extension.path);
		},

		events: eventBus,
	} as ExtensionAPI;

	return api;
}

async function loadExtensionModule(extensionPath: string) {
	const jiti = createJiti(import.meta.url, {
		moduleCache: false,
		// Force jiti to resolve extension imports so upstream pi aliases are honored
		// for transitive imports too. Native TS loaders otherwise try resolving
		// @earendil-works/* directly from the extension package first, which hangs
		// or fails for packages such as @narumitw/pi-goal.
		tryNative: false,
		// In Bun binary: use virtualModules for bundled packages (no filesystem resolution).
		// In Node.js/dev: use aliases to resolve to workspace/dist entries.
		...(isBunBinary ? { virtualModules: VIRTUAL_MODULES } : { alias: getAliases() }),
	});

	const module = await jiti.import(extensionPath, { default: true });
	const factory = module as ExtensionFactory;
	return typeof factory !== "function" ? undefined : factory;
}

/**
 * Create an Extension object with empty collections.
 */
function createExtension(extensionPath: string, resolvedPath: string): Extension {
	const source =
		extensionPath.startsWith("<") && extensionPath.endsWith(">")
			? extensionPath.slice(1, -1).split(":")[0] || "temporary"
			: "local";
	const baseDir = extensionPath.startsWith("<") ? undefined : path.dirname(resolvedPath);

	return {
		path: extensionPath,
		resolvedPath,
		sourceInfo: createSyntheticSourceInfo(extensionPath, { source, baseDir }),
		handlers: new Map(),
		tools: new Map(),
		messageRenderers: new Map(),
		commands: new Map(),
		flags: new Map(),
		shortcuts: new Map(),
	};
}

async function loadExtension(
	extensionPath: string,
	cwd: string,
	eventBus: EventBus,
	runtime: ExtensionRuntime,
): Promise<{ extension: Extension | null; error: string | null }> {
	const resolvedPath = resolvePath(extensionPath, cwd, { normalizeUnicodeSpaces: true });

	try {
		const factory = await loadExtensionModule(resolvedPath);
		if (!factory) {
			return { extension: null, error: `Extension does not export a valid factory function: ${extensionPath}` };
		}

		const extension = createExtension(extensionPath, resolvedPath);
		const api = createExtensionAPI(extension, runtime, cwd, eventBus);
		await factory(api);

		return { extension, error: null };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { extension: null, error: `Failed to load extension: ${message}` };
	}
}

/**
 * Create an Extension from an inline factory function.
 */
export async function loadExtensionFromFactory(
	factory: ExtensionFactory,
	cwd: string,
	eventBus: EventBus,
	runtime: ExtensionRuntime,
	extensionPath = "<inline>",
): Promise<Extension> {
	const extension = createExtension(extensionPath, extensionPath);
	const resolvedCwd = resolvePath(cwd);
	const api = createExtensionAPI(extension, runtime, resolvedCwd, eventBus);
	await factory(api);
	return extension;
}

/**
 * Load extensions from paths.
 */
export async function loadExtensions(paths: string[], cwd: string, eventBus?: EventBus): Promise<LoadExtensionsResult> {
	const extensions: Extension[] = [];
	const errors: Array<{ path: string; error: string }> = [];
	const resolvedCwd = resolvePath(cwd);
	const resolvedEventBus = eventBus ?? createEventBus();
	const runtime = createExtensionRuntime();

	for (const extPath of paths) {
		const { extension, error } = await loadExtension(extPath, resolvedCwd, resolvedEventBus, runtime);

		if (error) {
			errors.push({ path: extPath, error });
			continue;
		}

		if (extension) {
			extensions.push(extension);
		}
	}

	return {
		extensions,
		errors,
		runtime,
	};
}

interface PiManifest {
	extensions?: string[];
	themes?: string[];
	skills?: string[];
	prompts?: string[];
}

function readPiManifest(packageJsonPath: string): PiManifest | null {
	try {
		const content = fs.readFileSync(packageJsonPath, "utf-8");
		const pkg = JSON.parse(content);
		if (pkg.pi && typeof pkg.pi === "object") {
			return pkg.pi as PiManifest;
		}
		return null;
	} catch {
		return null;
	}
}

function isExtensionFile(name: string): boolean {
	return name.endsWith(".ts") || name.endsWith(".js");
}

/**
 * Resolve extension entry points from a directory.
 *
 * Checks for:
 * 1. package.json with "pi.extensions" field -> returns declared paths
 * 2. index.ts or index.js -> returns the index file
 *
 * Returns resolved paths or null if no entry points found.
 */
function resolveExtensionEntries(dir: string): string[] | null {
	// Check for package.json with "pi" field first
	const packageJsonPath = path.join(dir, "package.json");
	if (fs.existsSync(packageJsonPath)) {
		const manifest = readPiManifest(packageJsonPath);
		if (manifest?.extensions?.length) {
			const entries: string[] = [];
			for (const extPath of manifest.extensions) {
				const resolvedExtPath = path.resolve(dir, extPath);
				if (fs.existsSync(resolvedExtPath)) {
					entries.push(resolvedExtPath);
				}
			}
			if (entries.length > 0) {
				return entries;
			}
		}
	}

	// Check for index.ts or index.js
	const indexTs = path.join(dir, "index.ts");
	const indexJs = path.join(dir, "index.js");
	if (fs.existsSync(indexTs)) {
		return [indexTs];
	}
	if (fs.existsSync(indexJs)) {
		return [indexJs];
	}

	return null;
}

/**
 * Discover extensions in a directory.
 *
 * Discovery rules:
 * 1. Direct files: `extensions/*.ts` or `*.js` → load
 * 2. Subdirectory with index: `extensions/* /index.ts` or `index.js` → load
 * 3. Subdirectory with package.json: `extensions/* /package.json` with "pi" field → load what it declares
 *
 * No recursion beyond one level. Complex packages must use package.json manifest.
 */
function discoverExtensionsInDir(dir: string): string[] {
	if (!fs.existsSync(dir)) {
		return [];
	}

	const discovered: string[] = [];

	try {
		const entries = fs.readdirSync(dir, { withFileTypes: true });

		for (const entry of entries) {
			const entryPath = path.join(dir, entry.name);

			// 1. Direct files: *.ts or *.js
			if ((entry.isFile() || entry.isSymbolicLink()) && isExtensionFile(entry.name)) {
				discovered.push(entryPath);
				continue;
			}

			// 2 & 3. Subdirectories
			if (entry.isDirectory() || entry.isSymbolicLink()) {
				const entries = resolveExtensionEntries(entryPath);
				if (entries) {
					discovered.push(...entries);
				}
			}
		}
	} catch {
		return [];
	}

	return discovered;
}

/**
 * Discover and load extensions from standard locations.
 */
export async function discoverAndLoadExtensions(
	configuredPaths: string[],
	cwd: string,
	agentDir: string = getAgentDir(),
	eventBus?: EventBus,
): Promise<LoadExtensionsResult> {
	const resolvedCwd = resolvePath(cwd);
	const resolvedAgentDir = resolvePath(agentDir);
	const allPaths: string[] = [];
	const seen = new Set<string>();

	const addPaths = (paths: string[]) => {
		for (const p of paths) {
			const resolved = path.resolve(p);
			if (!seen.has(resolved)) {
				seen.add(resolved);
				allPaths.push(p);
			}
		}
	};

	// 1. Project-local extensions: cwd/${CONFIG_DIR_NAME}/extensions/
	const localExtDir = path.join(resolvedCwd, CONFIG_DIR_NAME, "extensions");
	addPaths(discoverExtensionsInDir(localExtDir));

	// 2. Global extensions: agentDir/extensions/
	const globalExtDir = path.join(resolvedAgentDir, "extensions");
	addPaths(discoverExtensionsInDir(globalExtDir));

	// 3. Explicitly configured paths
	for (const p of configuredPaths) {
		const resolved = resolvePath(p, resolvedCwd, { normalizeUnicodeSpaces: true });
		if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
			// Check for package.json with pi manifest or index.ts
			const entries = resolveExtensionEntries(resolved);
			if (entries) {
				addPaths(entries);
				continue;
			}
			// No explicit entries - discover individual files in directory
			addPaths(discoverExtensionsInDir(resolved));
			continue;
		}

		addPaths([resolved]);
	}

	return loadExtensions(allPaths, resolvedCwd, eventBus);
}
