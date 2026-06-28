import { commandContainsPoison } from "./target.ts";
import { uniqueNonEmpty } from "./text.ts";

export function normalizeReconCommand(command: string): string {
	return command.trim().replace(/^\//, "").replace(/^re-/i, "re_").replace(/\s+/g, " ");
}

export function extractMemoryCommands(text: string): string[] {
	const fenced = Array.from(text.matchAll(/```(?:bash|sh|shell)?\s*([\s\S]*?)```/gi)).flatMap((match) =>
		(match[1] ?? "")
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter(Boolean),
	);
	const inline = text
		.split(/\r?\n/)
		.map((line) => line.replace(/^-\s*/, "").trim())
		.filter((line) =>
			/^(?:re[-_]\w+|python3?\s|node\s|bash\s|curl\s|rg\s|find\s|jq\s|nmap\s|ffuf\s|gdb\s|frida\s|tshark\s|checksec\s)/i.test(
				line,
			),
		);
	return uniqueNonEmpty(
		[...fenced, ...inline].filter((command) => !commandContainsPoison(command) && !/[<][A-Z_]+[>]/.test(command)),
		24,
	);
}
