/**
 * Normalize object schemas at the provider boundary without mutating the tool registry.
 * Some OpenAI-compatible gateways materialize an omitted `required` as null, which is
 * invalid JSON Schema. An empty array is equivalent for an all-optional object schema.
 */
export function normalizeOpenAIToolSchema(schema: unknown): Record<string, unknown> {
	const normalize = (value: unknown): unknown => {
		if (Array.isArray(value)) return value.map(normalize);
		if (!isRecord(value)) return value;

		const output = Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalize(child)]));
		if ((output.type === "object" || isRecord(output.properties)) && !Array.isArray(output.required)) {
			output.required = [];
		}
		return output;
	};

	const normalized = normalize(schema);
	return isRecord(normalized) ? normalized : { type: "object", properties: {}, required: [] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
