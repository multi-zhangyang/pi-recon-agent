/**
 * CLI argument parsing and help display
 */

import type { ThinkingLevel } from "@pi-recon/repi-agent-core";
import chalk from "chalk";
import { APP_NAME, CONFIG_DIR_NAME, IS_REPI_PRODUCT } from "../config.ts";
import type { ExtensionFlag } from "../core/extensions/types.ts";

export type Mode = "text" | "json" | "rpc";

export interface Args {
	provider?: string;
	model?: string;
	apiKey?: string;
	systemPrompt?: string;
	appendSystemPrompt?: string[];
	recon?: boolean;
	thinking?: ThinkingLevel;
	continue?: boolean;
	resume?: boolean;
	help?: boolean;
	version?: boolean;
	mode?: Mode;
	name?: string;
	noSession?: boolean;
	session?: string;
	sessionId?: string;
	fork?: string;
	sessionDir?: string;
	models?: string[];
	tools?: string[];
	excludeTools?: string[];
	noTools?: boolean;
	noBuiltinTools?: boolean;
	extensions?: string[];
	noExtensions?: boolean;
	print?: boolean;
	export?: string;
	noSkills?: boolean;
	skills?: string[];
	promptTemplates?: string[];
	noPromptTemplates?: boolean;
	themes?: string[];
	noThemes?: boolean;
	noContextFiles?: boolean;
	listModels?: string | true;
	offline?: boolean;
	verbose?: boolean;
	projectTrustOverride?: boolean;
	messages: string[];
	fileArgs: string[];
	/** Unknown flags (potentially extension flags) - map of flag name to value */
	unknownFlags: Map<string, boolean | string>;
	diagnostics: Array<{ type: "warning" | "error"; message: string }>;
}

const VALID_THINKING_LEVELS = ["off", "minimal", "low", "medium", "high", "xhigh"] as const;

export function isValidThinkingLevel(level: string): level is ThinkingLevel {
	return VALID_THINKING_LEVELS.includes(level as ThinkingLevel);
}

export function parseArgs(args: string[]): Args {
	const result: Args = {
		messages: [],
		fileArgs: [],
		unknownFlags: new Map(),
		diagnostics: [],
	};

	for (let i = 0; i < args.length; i++) {
		const arg = args[i];

		if (arg === "--help" || arg === "-h") {
			result.help = true;
		} else if (arg === "--version" || arg === "-v") {
			result.version = true;
		} else if (arg === "--mode" && i + 1 < args.length) {
			const mode = args[++i];
			if (mode === "text" || mode === "json" || mode === "rpc") {
				result.mode = mode;
			}
		} else if (arg === "--continue" || arg === "-c") {
			result.continue = true;
		} else if (arg === "--resume" || arg === "-r") {
			result.resume = true;
		} else if (arg === "--provider" && i + 1 < args.length) {
			result.provider = args[++i];
		} else if (arg === "--model" && i + 1 < args.length) {
			result.model = args[++i];
		} else if (arg === "--api-key" && i + 1 < args.length) {
			result.apiKey = args[++i];
		} else if (arg === "--system-prompt" && i + 1 < args.length) {
			result.systemPrompt = args[++i];
		} else if (arg === "--append-system-prompt" && i + 1 < args.length) {
			result.appendSystemPrompt = result.appendSystemPrompt ?? [];
			result.appendSystemPrompt.push(args[++i]);
		} else if (arg === "--recon" || arg === "--reverse-pentest") {
			result.recon = true;
		} else if (arg === "--name" || arg === "-n") {
			if (i + 1 < args.length) {
				result.name = args[++i];
			} else {
				result.diagnostics.push({ type: "error", message: "--name requires a value" });
			}
		} else if (arg === "--no-session") {
			result.noSession = true;
		} else if (arg === "--session" && i + 1 < args.length) {
			result.session = args[++i];
		} else if (arg === "--session-id" && i + 1 < args.length) {
			result.sessionId = args[++i];
		} else if (arg === "--fork" && i + 1 < args.length) {
			result.fork = args[++i];
		} else if (arg === "--session-dir" && i + 1 < args.length) {
			result.sessionDir = args[++i];
		} else if (arg === "--models" && i + 1 < args.length) {
			result.models = args[++i].split(",").map((s) => s.trim());
		} else if (arg === "--no-tools" || arg === "-nt") {
			result.noTools = true;
		} else if (arg === "--no-builtin-tools" || arg === "-nbt") {
			result.noBuiltinTools = true;
		} else if ((arg === "--tools" || arg === "-t") && i + 1 < args.length) {
			result.tools = args[++i]
				.split(",")
				.map((s) => s.trim())
				.filter((name) => name.length > 0);
		} else if ((arg === "--exclude-tools" || arg === "-xt") && i + 1 < args.length) {
			result.excludeTools = args[++i]
				.split(",")
				.map((s) => s.trim())
				.filter((name) => name.length > 0);
		} else if (arg === "--thinking" && i + 1 < args.length) {
			const level = args[++i];
			if (isValidThinkingLevel(level)) {
				result.thinking = level;
			} else {
				result.diagnostics.push({
					type: "warning",
					message: `Invalid thinking level "${level}". Valid values: ${VALID_THINKING_LEVELS.join(", ")}`,
				});
			}
		} else if (arg === "--print" || arg === "-p") {
			result.print = true;
			const next = args[i + 1];
			if (next !== undefined && !next.startsWith("@") && (!next.startsWith("-") || next.startsWith("---"))) {
				result.messages.push(next);
				i++;
			}
		} else if (arg === "--export" && i + 1 < args.length) {
			result.export = args[++i];
		} else if ((arg === "--extension" || arg === "-e") && i + 1 < args.length) {
			result.extensions = result.extensions ?? [];
			result.extensions.push(args[++i]);
		} else if (arg === "--no-extensions" || arg === "-ne") {
			result.noExtensions = true;
		} else if (arg === "--skill" && i + 1 < args.length) {
			result.skills = result.skills ?? [];
			result.skills.push(args[++i]);
		} else if (arg === "--prompt-template" && i + 1 < args.length) {
			result.promptTemplates = result.promptTemplates ?? [];
			result.promptTemplates.push(args[++i]);
		} else if (arg === "--theme" && i + 1 < args.length) {
			result.themes = result.themes ?? [];
			result.themes.push(args[++i]);
		} else if (arg === "--no-skills" || arg === "-ns") {
			result.noSkills = true;
		} else if (arg === "--no-prompt-templates" || arg === "-np") {
			result.noPromptTemplates = true;
		} else if (arg === "--no-themes") {
			result.noThemes = true;
		} else if (arg === "--no-context-files" || arg === "-nc") {
			result.noContextFiles = true;
		} else if (arg === "--list-models") {
			// Check if next arg is a search pattern (not a flag or file arg)
			if (i + 1 < args.length && !args[i + 1].startsWith("-") && !args[i + 1].startsWith("@")) {
				result.listModels = args[++i];
			} else {
				result.listModels = true;
			}
		} else if (arg === "--verbose") {
			result.verbose = true;
		} else if (arg === "--approve" || arg === "-a") {
			result.projectTrustOverride = true;
		} else if (arg === "--no-approve" || arg === "-na") {
			result.projectTrustOverride = false;
		} else if (arg === "--offline") {
			result.offline = true;
		} else if (arg.startsWith("@")) {
			result.fileArgs.push(arg.slice(1)); // Remove @ prefix
		} else if (arg.startsWith("--")) {
			const eqIndex = arg.indexOf("=");
			if (eqIndex !== -1) {
				result.unknownFlags.set(arg.slice(2, eqIndex), arg.slice(eqIndex + 1));
			} else {
				const flagName = arg.slice(2);
				const next = args[i + 1];
				if (next !== undefined && !next.startsWith("-") && !next.startsWith("@")) {
					result.unknownFlags.set(flagName, next);
					i++;
				} else {
					result.unknownFlags.set(flagName, true);
				}
			}
		} else if (arg.startsWith("-") && !arg.startsWith("--")) {
			result.diagnostics.push({ type: "error", message: `Unknown option: ${arg}` });
		} else if (!arg.startsWith("-")) {
			result.messages.push(arg);
		}
	}

	return result;
}

export function printHelp(extensionFlags?: ExtensionFlag[]): void {
	const isReconPrimary = process.env.REPI_PRIMARY === "1" || process.env.REPI_PRODUCT === "1" || APP_NAME === "repi";
	const description = isReconPrimary
		? "REPI reverse/pentest execution agent with read, bash, edit, write tools"
		: "AI coding assistant with read, bash, edit, write tools";
	const reconBanner = isReconPrimary
		? `${chalk.bold("REPI:")} independent product; built-in reverse/pentest kernel is enabled. Runtime storage: ~/${CONFIG_DIR_NAME}/agent.\n${chalk.bold("Models:")} default catalog is empty; configure REPI_* env, models.json, or extension providers.\n\n`
		: "";
	const extensionFlagsText =
		extensionFlags && extensionFlags.length > 0
			? `\n${chalk.bold("Extension CLI Flags:")}\n${extensionFlags
					.map((flag) => {
						const value = flag.type === "string" ? " <value>" : "";
						const description = flag.description ?? `Registered by ${flag.extensionPath}`;
						return `  --${flag.name}${value}`.padEnd(30) + description;
					})
					.join("\n")}\n`
			: "";
	const updateCommandLine = IS_REPI_PRODUCT
		? `  ${APP_NAME} update [source]          Update installed extension packages`
		: `  ${APP_NAME} update [source|self|pi]   Update pi and installed extensions`;
	const shareViewerLine = IS_REPI_PRODUCT
		? `  REPI_SHARE_VIEWER_URL            - Base URL for /share command (default: https://gist.github.com/<gist-id>)`
		: `  PI_SHARE_VIEWER_URL              - Base URL for /share command (default: https://pi.dev/session/)`;
	console.log(`${chalk.bold(APP_NAME)} - ${description}

${reconBanner}

${chalk.bold("Usage:")}
  ${APP_NAME} [options] [@files...] [messages...]

${chalk.bold("Commands:")}
  ${APP_NAME} install <source> [-l]     Install extension source and add to settings
  ${APP_NAME} remove <source> [-l]      Remove extension source from settings
  ${APP_NAME} uninstall <source> [-l]   Alias for remove
${updateCommandLine}
  ${APP_NAME} doctor [--fix|--json]
                                 Check and optionally repair the REPI install/runtime profile
  ${APP_NAME} smoke [--full|--json]
                                 Run fast REPI runtime checks
  ${APP_NAME} selfcheck [--deep|--json] [--provider <name>] [--model <id>]
                                 End-to-end selfcheck for model/tool/parallel/orchestration usability
  ${APP_NAME} bugreport [--output <path>|--stdout|--json]
                                 Create a strictly redacted local diagnostic bundle
  ${APP_NAME} trust status|yes|no|clear [path]
                                 Show, save, or clear project trust decision
  ${APP_NAME} model list|add|edit|remove|login|test|default|reset|doctor|cost|export|import
                                 Configure providers, store local credentials, test/reset models, export/import templates, and estimate cost
  ${APP_NAME} mcp status|list|probe [server-id]
                                 Inspect and probe configured MCP stdio/http servers and tool lists
  ${APP_NAME} swarm plan|run|status|merge|llm-run <target> --workers N
                                 Plan/run isolated parallel LLM worker processes and write a merge report
  ${APP_NAME} list [--approve|--no-approve]
                                 List installed extensions from settings
  ${APP_NAME} config [--no-approve]
                                 Open TUI to enable/disable package resources
  ${APP_NAME} provider-doctor --base-url <url> --model <id>
                                 Probe OpenAI/Anthropic-compatible endpoints and print a REPI models.json template
  ${APP_NAME} <command> --help          Show help for package/provider commands; wrapper commands support their own --help

${chalk.bold("Options:")}
  --provider <name>              Explicitly configured provider id (default: resolved configured model)
  --model <pattern>              Model pattern or ID (supports "provider/id" and optional ":<thinking>")
  --api-key <key>                Runtime API key override (prefer env/model login; shell-history risk)
  --system-prompt <text>         System prompt (default: REPI reverse/pentest kernel prompt)
  --append-system-prompt <text>  Append text or file contents to the system prompt (can be used multiple times)
  --recon, --reverse-pentest     Enable built-in REPI reverse/pentest kernel profile
  --mode <mode>                  Output mode: text (default), json, or rpc
  --print, -p                    Non-interactive mode: process prompt and exit
  --continue, -c                 Continue previous session
  --resume, -r                   Select a session to resume
  --session <path|id>            Use specific session file or partial UUID
  --session-id <id>              Use exact project session ID, creating it if missing
  --fork <path|id>               Fork specific session file or partial UUID into a new session
  --session-dir <dir>            Directory for session storage and lookup
  --no-session                   Don't save session (ephemeral)
  --name, -n <name>              Set session display name
  --models <patterns>            Comma-separated model patterns for Ctrl+P cycling
                                 Supports globs (gateway/*, *reasoning*) and fuzzy matching
  --no-tools, -nt                Disable all tools by default (built-in and extension)
  --no-builtin-tools, -nbt       Disable built-in tools by default but keep extension/custom tools enabled
  --tools, -t <tools>            Comma-separated allowlist of tool names to enable
                                 Applies to built-in, extension, and custom tools
  --exclude-tools, -xt <tools>   Comma-separated denylist of tool names to disable
                                 Applies to built-in, extension, and custom tools
  --thinking <level>             Set thinking level: off, minimal, low, medium, high, xhigh
  --extension, -e <path>         Load an extension file (can be used multiple times)
  --no-extensions, -ne           Disable extension discovery (explicit -e paths still work)
  --skill <path>                 Load a skill file or directory (can be used multiple times)
  --no-skills, -ns               Disable skills discovery and loading
  --prompt-template <path>       Load a prompt template file or directory (can be used multiple times)
  --no-prompt-templates, -np     Disable prompt template discovery and loading
  --theme <path>                 Load a theme file or directory (can be used multiple times)
  --no-themes                    Disable theme discovery and loading
  --no-context-files, -nc        Disable AGENTS.md and CLAUDE.md discovery and loading
  --export <file>                Export session file to HTML and exit
  --list-models [search]         List available models (with optional fuzzy search)
  --verbose                      Force verbose startup (overrides quietStartup setting)
  --approve, -a                  Trust project-local files for this run
  --no-approve, -na              Ignore project-local files for this run
  --clean-room                   REPI wrapper flag: ignore project context/resources for this run
  --project-context              REPI compatibility flag: project trust store controls context loading
  --with-project-resources       REPI compatibility flag: project trust store controls resource loading
  --offline                      Disable startup network operations (same as REPI_OFFLINE=1)
  --help, -h                     Show this help
  --version, -v                  Show version number

Extensions can register additional flags (e.g., --plan from plan-mode extension).${extensionFlagsText}

${chalk.bold("Examples:")}
  # Interactive REPI session
  ${APP_NAME}

  # Start with a reverse-engineering target
  ${APP_NAME} "先对当前目录做被动 mapping，找二进制入口和验证路径"

  # Non-interactive mode: generate a bounded task plan
  ${APP_NAME} -p "对 ./challenge 生成 re_map、re_operator、re_verifier 执行计划"

  # Include files in the initial message
  ${APP_NAME} @notes.md @traffic.har "从这些材料提取接口、签名参数和证据缺口"

  # Continue previous REPI session
  ${APP_NAME} --continue "继续上次任务，先读取未闭合 evidence gaps"

  # Start a named investigation session
  ${APP_NAME} --name "firmware-auth-analysis"

  # Use an explicitly configured OpenAI-compatible provider/model
  ${APP_NAME} --provider gateway --model provider/model-id "分析 Web/API 授权状态机"

  # Diagnose a custom gateway and generate a REPI models.json template
  ${APP_NAME} provider-doctor --base-url https://gateway.example/v1 --model provider/model-id --api auto

  # Use model with provider prefix (no --provider needed)
  ${APP_NAME} --model gateway/provider-model "生成 exploit-lab 复现矩阵"

  # Use model with thinking level shorthand
  ${APP_NAME} --model gateway/provider-model:high "构建 pwn 目标的 leak→primitive→proof 路线"

  # Limit model cycling to specific models
  ${APP_NAME} --models gateway/*,local/model-id:low

  # Limit to a specific provider with glob pattern
  ${APP_NAME} --models "gateway/*"

  # Cycle models with fixed thinking levels
  ${APP_NAME} --models gateway/reasoning:high,local/fast:low

  # Start with a specific thinking level
  ${APP_NAME} --thinking high "审计当前仓库的 REPI 运行时与 profile 缺口"

  # Passive/read-only mapping mode
  ${APP_NAME} --tools read,grep,find,ls -p "只读分析 src/ 的路由、鉴权和入口"

  # Disable one tool while keeping the rest available
  ${APP_NAME} --exclude-tools ask_question

  # Export a session file to HTML
  ${APP_NAME} --export ~/${CONFIG_DIR_NAME}/agent/sessions/--path--/session.jsonl
  ${APP_NAME} --export session.jsonl output.html

${chalk.bold("Environment Variables:")}
  REPI_AUTH_TOKEN                  - Env-only model API key (preferred under REPI)
  REPI_BASE_URL                    - Env-only provider base URL; OpenAI-compatible usually https://host/v1, Anthropic-compatible usually https://host
  REPI_PROVIDER                    - Optional env-only provider id shown in the footer (default: repi-env)
  REPI_PROVIDER_NAME               - Optional display name for the env-only provider
  REPI_MODEL                       - Env-only model id
  REPI_MODEL_NAME                  - Optional display name for the primary env-only model
  REPI_MODEL_API                   - openai-compatible|openai-responses|anthropic (default: openai-compatible)
  REPI_CONTEXT_WINDOW              - Env-only model context window
  REPI_AUTO_COMPACT_WINDOW         - Alias of REPI_CONTEXT_WINDOW for Claude Code-style setup
  REPI_MAX_TOKENS                  - Env-only model output-token cap
  REPI_MODEL_INPUT                 - Comma-separated input modalities: text or text,image
  REPI_MODEL_REASONING             - Whether the env-only model supports reasoning (true/false)
  REPI_MODEL_THINKING_LEVEL_MAP    - JSON map of REPI thinking levels to provider values; null means unsupported
  REPI_HEADERS                     - JSON provider request headers; values may reference $ENV_VAR
  REPI_MODEL_HEADERS               - JSON model request headers merged over provider headers; null removes a header
  REPI_COMPAT                      - JSON provider wire-compatibility overrides
  REPI_MODEL_COMPAT                - JSON model wire-compatibility overrides merged over provider compat
  REPI_AUTH_HEADER                 - Add Authorization: Bearer <token> from the resolved env-only token when true
  REPI_MODEL_COST_INPUT            - Input price in USD per million tokens
  REPI_MODEL_COST_OUTPUT           - Output price in USD per million tokens
  REPI_MODEL_COST_CACHE_READ       - Cache-read price in USD per million tokens
  REPI_MODEL_COST_CACHE_WRITE      - Cache-write price in USD per million tokens
  REPI_MODEL_COST_TIERS            - JSON tiers; highest inputTokensAbove exceeded by total input usage applies
  REPI_SUBAGENT_MODEL              - Optional env-only worker/subagent model id
  REPI_SUBAGENT_MODEL_NAME         - Optional display name for the env-only worker/subagent model
  REPI_PACKAGE_DIR                 - Override REPI package directory
  REPI_OFFLINE                     - Disable startup network operations when set to 1/true/yes
  REPI_TELEMETRY                   - Override REPI telemetry switch (default: 0 in product mode)
  REPI_SKIP_VERSION_CHECK          - Disable REPI version checks when set (default: on)
  REPI_SKIP_PACKAGE_UPDATE_CHECK   - Disable REPI package update checks when set (default: on)
  REPI_PRINT_PROGRESS              - Print-mode progress/heartbeat to stderr (default: 1 under repi)
  REPI_PRINT_TIMEOUT_MS            - Print-mode wall timeout before abort (default: 210000)
  REPI_PRINT_TIMEOUT_GRACE_MS      - Extra assistant-output grace after wall timeout (default: 30000)
  REPI_PRINT_TIMEOUT_TOOL_GRACE_MS - Extra grace when wall timeout fires mid-tool (e.g. long re_subagent); default 300000
  REPI_RPC_EOF_DRAIN_TIMEOUT_MS    - Max wait for an active RPC prompt after stdin EOF before aborting (default: 210000)
  REPI_PRINT_MAX_TURNS             - Print-mode assistant/tool loop cap (default: 10; final turn is tool-free synthesis)
  REPI_PRINT_MAX_TOOL_CALLS        - Print-mode total tool-call cap (default: 48)
  REPI_STDIN_READ_TIMEOUT_MS       - Non-TTY stdin read guard when stdin is left open (default: 1500)
  REPI_READ_STDIN_WITH_PROMPT      - Set 1 to combine stdin with an explicit -p/message prompt
  REPI_BASH_DEFAULT_TIMEOUT_SECONDS - Default bash tool timeout when model omits timeout (default: 120)
${shareViewerLine}

${chalk.bold("Built-in Tool Names:")}
  read   - Read file contents
  bash   - Execute bash commands
  edit   - Edit files with find/replace
  write  - Write files (creates/overwrites)
  grep   - Search file contents (read-only, off by default)
  find   - Find files by glob pattern (read-only, off by default)
  ls     - List directory contents (read-only, off by default)
`);
}
