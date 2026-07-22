# @pi-recon/repi-ai

Unified LLM API with explicit model configuration, wire-adapter dispatch, token and cost tracking, and simple context
persistence and hand-off to other models mid-session.

The package ships protocol adapters and auth helpers, not a model/provider catalog. Model metadata is supplied by the
host as an explicit `Model` object or by a higher-level runtime such as coding-agent's `ModelRuntime` loading
`models.json`, `REPI_*` variables, or an extension. Endpoint, capability, context, and pricing data therefore stay
current and application-owned. Models do not need tool calling unless the application uses tools.

## Table of Contents

- [Supported API Adapters](#supported-api-adapters)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tools](#tools)
  - [Defining Tools](#defining-tools)
  - [Handling Tool Calls](#handling-tool-calls)
  - [Streaming Tool Calls with Partial JSON](#streaming-tool-calls-with-partial-json)
  - [Validating Tool Arguments](#validating-tool-arguments)
  - [Complete Event Reference](#complete-event-reference)
- [Image Input](#image-input)
- [Image Generation](#image-generation)
  - [Basic Image Generation](#basic-image-generation)
  - [Notes and Limitations](#notes-and-limitations)
- [Thinking/Reasoning](#thinkingreasoning)
  - [Unified Interface](#unified-interface-streamsimplecompletesimple)
  - [Provider-Specific Options](#provider-specific-options-streamcomplete)
  - [Streaming Thinking Content](#streaming-thinking-content)
- [Stop Reasons](#stop-reasons)
- [Error Handling](#error-handling)
  - [Aborting Requests](#aborting-requests)
  - [Continuing After Abort](#continuing-after-abort)
- [APIs, Models, and Providers](#apis-models-and-providers)
  - [Providers and Models](#providers-and-models)
  - [Supplying Providers and Models](#supplying-providers-and-models)
  - [Custom Models](#custom-models)
  - [OpenAI Compatibility Settings](#openai-compatibility-settings)
  - [Type Safety](#type-safety)
- [Cross-Provider Handoffs](#cross-provider-handoffs)
- [Context Serialization](#context-serialization)
- [Browser Usage](#browser-usage)
  - [Browser Compatibility Notes](#browser-compatibility-notes)
  - [Environment Variables](#environment-variables-nodejs-only)
- [OAuth Providers](#oauth-providers)
- [License](#license)

## Supported API Adapters

These are wire-level adapters registered by the package. They describe request/response protocols, not bundled model
IDs or provider catalogs. A host can assign any provider ID to a `Model` and select the appropriate adapter via `api`,
including for a private proxy or local server.

- **`anthropic-messages`**: Anthropic Messages and compatible endpoints (for example Fireworks, MiniMax, Kimi for Coding)
- **`google-generative-ai`**: Google Generative AI
- **`google-vertex`**: Google Vertex AI
- **`mistral-conversations`**: Mistral Conversations
- **`openai-completions`**: OpenAI Chat Completions-compatible services (for example Ollama, vLLM, LM Studio, Groq, xAI, OpenRouter, and custom gateways)
- **`openai-responses`**: OpenAI Responses and compatible gateways
- **`azure-openai-responses`**: Azure OpenAI Responses
- **`openai-codex-responses`**: OpenAI Codex Responses (OAuth subscription flow)
- **`bedrock-converse-stream`**: Amazon Bedrock Converse
- **`openrouter-images`**: OpenRouter image generation

Authentication-specific provider IDs (such as `openai`, `anthropic`, or `github-copilot`) identify auth/routing context
on a `Model`; registering an adapter never registers models or performs discovery.

## Installation

This fork is distributed through GitHub Release tarballs, not the npm registry. Download the AI tarball named in `repi-release-manifest.json`, then install that local file:

```bash
npm install ./pi-recon-repi-ai-0.1.3.tgz
```

TypeBox exports are re-exported from `@pi-recon/repi-ai`: `Type`, `Static`, and `TSchema`.

## Quick Start

```typescript
import { Type, stream, complete, type Context, type Model, type Tool } from '@pi-recon/repi-ai';

// Models are explicit application data; no default catalog lookup occurs.
const model: Model<'openai-responses'> = {
  id: 'gpt-4o-mini',
  name: 'GPT-4o mini',
  api: 'openai-responses',
  provider: 'openai',
  baseUrl: 'https://api.openai.com/v1',
  reasoning: false,
  input: ['text', 'image'],
  cost: { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0 },
  contextWindow: 128000,
  maxTokens: 16384,
};

// Define tools with TypeBox schemas for type safety and validation
const tools: Tool[] = [{
  name: 'get_time',
  description: 'Get the current time',
  parameters: Type.Object({
    timezone: Type.Optional(Type.String({ description: 'Optional timezone (e.g., America/New_York)' }))
  })
}];

// Build a conversation context (easily serializable and transferable between models)
const context: Context = {
  systemPrompt: 'You are a helpful assistant.',
  messages: [{ role: 'user', content: 'What time is it?' }],
  tools
};

// Option 1: Streaming with all event types
const s = stream(model, context);

for await (const event of s) {
  switch (event.type) {
    case 'start':
      console.log(`Starting with ${event.partial.model}`);
      break;
    case 'text_start':
      console.log('\n[Text started]');
      break;
    case 'text_delta':
      process.stdout.write(event.delta);
      break;
    case 'text_end':
      console.log('\n[Text ended]');
      break;
    case 'thinking_start':
      console.log('[Model is thinking...]');
      break;
    case 'thinking_delta':
      process.stdout.write(event.delta);
      break;
    case 'thinking_end':
      console.log('[Thinking complete]');
      break;
    case 'toolcall_start':
      console.log(`\n[Tool call started: index ${event.contentIndex}]`);
      break;
    case 'toolcall_delta':
      // Partial tool arguments are being streamed
      const partialCall = event.partial.content[event.contentIndex];
      if (partialCall.type === 'toolCall') {
        console.log(`[Streaming args for ${partialCall.name}]`);
      }
      break;
    case 'toolcall_end':
      console.log(`\nTool called: ${event.toolCall.name}`);
      console.log(`Arguments: ${JSON.stringify(event.toolCall.arguments)}`);
      break;
    case 'done':
      console.log(`\nFinished: ${event.reason}`);
      break;
    case 'error':
      console.error(`Error: ${event.error}`);
      break;
  }
}

// Get the final message after streaming, add it to the context
const finalMessage = await s.result();
context.messages.push(finalMessage);

// Handle tool calls if any
const toolCalls = finalMessage.content.filter(b => b.type === 'toolCall');
for (const call of toolCalls) {
  // Execute the tool
  const result = call.name === 'get_time'
    ? new Date().toLocaleString('en-US', {
        timeZone: call.arguments.timezone || 'UTC',
        dateStyle: 'full',
        timeStyle: 'long'
      })
    : 'Unknown tool';

  // Add tool result to context (supports text and images)
  context.messages.push({
    role: 'toolResult',
    toolCallId: call.id,
    toolName: call.name,
    content: [{ type: 'text', text: result }],
    isError: false,
    timestamp: Date.now()
  });
}

// Continue if there were tool calls
if (toolCalls.length > 0) {
  const continuation = await complete(model, context);
  context.messages.push(continuation);
  console.log('After tool execution:', continuation.content);
}

console.log(`Total tokens: ${finalMessage.usage.input} in, ${finalMessage.usage.output} out`);
console.log(`Cost: $${finalMessage.usage.cost.total.toFixed(4)}`);

// Option 2: Get complete response without streaming
const response = await complete(model, context);

for (const block of response.content) {
  if (block.type === 'text') {
    console.log(block.text);
  } else if (block.type === 'toolCall') {
    console.log(`Tool: ${block.name}(${JSON.stringify(block.arguments)})`);
  }
}
```

## Tools

Tools enable LLMs to interact with external systems. This library uses TypeBox schemas for type-safe tool definitions with automatic validation using TypeBox's built-in validator and value conversion utilities. TypeBox schemas can be serialized and deserialized as plain JSON, making them ideal for distributed systems.

### Defining Tools

```typescript
import { Type, Tool, StringEnum } from '@pi-recon/repi-ai';

// Define tool parameters with TypeBox
const weatherTool: Tool = {
  name: 'get_weather',
  description: 'Get current weather for a location',
  parameters: Type.Object({
    location: Type.String({ description: 'City name or coordinates' }),
    units: StringEnum(['celsius', 'fahrenheit'], { default: 'celsius' })
  })
};

// Note: For Google API compatibility, use StringEnum helper instead of Type.Enum
// Type.Enum generates anyOf/const patterns that Google doesn't support

const bookMeetingTool: Tool = {
  name: 'book_meeting',
  description: 'Schedule a meeting',
  parameters: Type.Object({
    title: Type.String({ minLength: 1 }),
    startTime: Type.String({ format: 'date-time' }),
    endTime: Type.String({ format: 'date-time' }),
    attendees: Type.Array(Type.String({ format: 'email' }), { minItems: 1 })
  })
};
```

### Handling Tool Calls

Tool results use content blocks and can include both text and images:

```typescript
import { readFileSync } from 'fs';

const context: Context = {
  messages: [{ role: 'user', content: 'What is the weather in London?' }],
  tools: [weatherTool]
};

const response = await complete(model, context);

// Check for tool calls in the response
for (const block of response.content) {
  if (block.type === 'toolCall') {
    // Execute your tool with the arguments
    // See "Validating Tool Arguments" section for validation
    const result = await executeWeatherApi(block.arguments);

    // Add tool result with text content
    context.messages.push({
      role: 'toolResult',
      toolCallId: block.id,
      toolName: block.name,
      content: [{ type: 'text', text: JSON.stringify(result) }],
      isError: false,
      timestamp: Date.now()
    });
  }
}

// Tool results can also include images (for vision-capable models)
const imageBuffer = readFileSync('chart.png');
context.messages.push({
  role: 'toolResult',
  toolCallId: 'tool_xyz',
  toolName: 'generate_chart',
  content: [
    { type: 'text', text: 'Generated chart showing temperature trends' },
    { type: 'image', data: imageBuffer.toString('base64'), mimeType: 'image/png' }
  ],
  isError: false,
  timestamp: Date.now()
});
```

### Streaming Tool Calls with Partial JSON

During streaming, tool call arguments are progressively parsed as they arrive. This enables real-time UI updates before the complete arguments are available:

```typescript
const s = stream(model, context);

for await (const event of s) {
  if (event.type === 'toolcall_delta') {
    const toolCall = event.partial.content[event.contentIndex];

    // toolCall.arguments contains partially parsed JSON during streaming
    // This allows for progressive UI updates
    if (toolCall.type === 'toolCall' && toolCall.arguments) {
      // BE DEFENSIVE: arguments may be incomplete
      // Example: Show file path being written even before content is complete
      if (toolCall.name === 'write_file' && toolCall.arguments.path) {
        console.log(`Writing to: ${toolCall.arguments.path}`);

        // Content might be partial or missing
        if (toolCall.arguments.content) {
          console.log(`Content preview: ${toolCall.arguments.content.substring(0, 100)}...`);
        }
      }
    }
  }

  if (event.type === 'toolcall_end') {
    // Here toolCall.arguments is complete (but not yet validated)
    const toolCall = event.toolCall;
    console.log(`Tool completed: ${toolCall.name}`, toolCall.arguments);
  }
}
```

**Important notes about partial tool arguments:**
- During `toolcall_delta` events, `arguments` contains the best-effort parse of partial JSON
- Fields may be missing or incomplete - always check for existence before use
- String values may be truncated mid-word
- Arrays may be incomplete
- Nested objects may be partially populated
- At minimum, `arguments` will be an empty object `{}`, never `undefined`
- The Google provider does not support function call streaming. Instead, you will receive a single `toolcall_delta` event with the full arguments.

### Validating Tool Arguments

When using `agentLoop`, tool arguments are automatically validated against your TypeBox schemas before execution. If validation fails, the error is returned to the model as a tool result, allowing it to retry.

When implementing your own tool execution loop with `stream()` or `complete()`, use `validateToolCall` to validate arguments before passing them to your tools:

```typescript
import { stream, validateToolCall, Tool } from '@pi-recon/repi-ai';

const tools: Tool[] = [weatherTool, calculatorTool];
const s = stream(model, { messages, tools });

for await (const event of s) {
  if (event.type === 'toolcall_end') {
    const toolCall = event.toolCall;

    try {
      // Validate arguments against the tool's schema (throws on invalid args)
      const validatedArgs = validateToolCall(tools, toolCall);
      const result = await executeMyTool(toolCall.name, validatedArgs);
      // ... add tool result to context
    } catch (error) {
      // Validation failed - return error as tool result so model can retry
      context.messages.push({
        role: 'toolResult',
        toolCallId: toolCall.id,
        toolName: toolCall.name,
        content: [{ type: 'text', text: error.message }],
        isError: true,
        timestamp: Date.now()
      });
    }
  }
}
```

### Complete Event Reference

All streaming events emitted during assistant message generation:

| Event Type | Description | Key Properties |
|------------|-------------|----------------|
| `start` | Stream begins | `partial`: Initial assistant message structure |
| `text_start` | Text block starts | `contentIndex`: Position in content array |
| `text_delta` | Text chunk received | `delta`: New text, `contentIndex`: Position |
| `text_end` | Text block complete | `content`: Full text, `contentIndex`: Position |
| `thinking_start` | Thinking block starts | `contentIndex`: Position in content array |
| `thinking_delta` | Thinking chunk received | `delta`: New text, `contentIndex`: Position |
| `thinking_end` | Thinking block complete | `content`: Full thinking, `contentIndex`: Position |
| `toolcall_start` | Tool call begins | `contentIndex`: Position in content array |
| `toolcall_delta` | Tool arguments streaming | `delta`: JSON chunk, `partial.content[contentIndex].arguments`: Partial parsed args |
| `toolcall_end` | Tool call complete | `toolCall`: Complete validated tool call with `id`, `name`, `arguments` |
| `done` | Stream complete | `reason`: Stop reason ("stop", "length", "toolUse"), `message`: Final assistant message |
| `error` | Error occurred | `reason`: Error type ("error" or "aborted"), `error`: AssistantMessage with partial content |

Streaming events for different content blocks are not guaranteed to be contiguous. Providers may emit deltas for text, thinking, and tool calls in the same upstream chunk, and pi may surface corresponding events interleaved, for example `text_start`, `text_delta`, `toolcall_start`, `text_delta`, `toolcall_delta`. Consumers must use `contentIndex` to associate each delta/end event with its block and must not assume that a block's `*_start`/`*_delta`/`*_end` sequence is uninterrupted by events for other blocks.

## Image Input

Models with vision capabilities can process images. You can check if a model supports images via the `input` property. If you pass images to a non-vision model, they are silently ignored.

```typescript
import { readFileSync } from 'fs';
import { complete, Model } from '@pi-recon/repi-ai';

const model: Model<'openai-responses'> = {
  id: 'gpt-4o-mini',
  name: 'GPT-4o mini',
  api: 'openai-responses',
  provider: 'openai',
  baseUrl: 'https://api.openai.com/v1',
  reasoning: false,
  input: ['text', 'image'],
  cost: { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0 },
  contextWindow: 128000,
  maxTokens: 16384,
};

// Check if model supports images
if (model.input.includes('image')) {
  console.log('Model supports vision');
}

const imageBuffer = readFileSync('image.png');
const base64Image = imageBuffer.toString('base64');

const response = await complete(model, {
  messages: [{
    role: 'user',
    content: [
      { type: 'text', text: 'What is in this image?' },
      { type: 'image', data: base64Image, mimeType: 'image/png' }
    ]
  }]
});

// Access the response
for (const block of response.content) {
  if (block.type === 'text') {
    console.log(block.text);
  }
}
```

## Image Generation

Image generation uses a separate API surface from text/chat generation. Pass an explicit `ImagesModel` to
`generateImages()` to get the final result. Keep image model metadata in the application or in the higher-level runtime
that owns the model configuration; this package does not populate a model list.

Do not use `stream()` or `complete()` for image generation. Image generation is a one-shot API: `generateImages()` waits for the provider response and returns the final `AssistantImages` result.

### Basic Image Generation

```typescript
import { generateImages, ImagesModel } from '@pi-recon/repi-ai';

const model: ImagesModel<'openrouter-images'> = {
  id: 'google/gemini-2.5-flash-image',
  name: 'Gemini 2.5 Flash Image',
  api: 'openrouter-images',
  provider: 'openrouter',
  baseUrl: 'https://openrouter.ai/api/v1',
  input: ['text', 'image'],
  output: ['image', 'text'],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
};

const result = await generateImages(model, {
  input: [{ type: 'text', text: 'Generate a red circle on a plain white background.' }]
}, {
  apiKey: process.env.OPENROUTER_API_KEY
});

for (const block of result.output) {
  if (block.type === 'text') {
    console.log(block.text);
  } else if (block.type === 'image') {
    console.log(block.mimeType);
    console.log(block.data.substring(0, 32));
  }
}
```

Some models also support image input:

```typescript
import { readFileSync } from 'fs';

const imageBuffer = readFileSync('input.png');
const result = await generateImages(model, {
  input: [
    { type: 'text', text: 'Create a variation of this image with a blue background.' },
    { type: 'image', data: imageBuffer.toString('base64'), mimeType: 'image/png' }
  ]
}, {
  apiKey: process.env.OPENROUTER_API_KEY
});
```

Check capabilities on the model metadata:

```typescript
console.log(model.input);   // ['text', 'image']
console.log(model.output);  // ['image'] or ['image', 'text']
```

### Notes and Limitations

- Use an explicit `ImagesModel`; chat `Model` objects are not interchangeable.
- Use `generateImages()`, not `stream()` / `complete()`.
- Image-generation models do not participate in tool calling.
- Outputs are returned in `AssistantImages.output` and can include both base64-encoded `ImageContent` blocks and `TextContent` blocks.
- Some models return only images, others return images plus text. Check `model.output`.
- Some models accept image input, others are text-to-image only. Check `model.input`.
- Like the streaming APIs, image generation supports options such as `apiKey`, `signal`, `headers`, `onPayload`, and `onResponse`, and results may include `stopReason`, `responseId`, and `usage`.
- If you want a model to analyze images in a conversation or call tools, use the regular `stream()` / `complete()` APIs with a model that supports image input.
- The built-in image adapter currently targets OpenRouter; extensions can register other image APIs.

## Thinking/Reasoning

Many models support thinking/reasoning capabilities where they can show their internal thought process. You can check if a model supports reasoning via the `reasoning` property. If you pass reasoning options to a non-reasoning model, they are silently ignored.

### Unified Interface (streamSimple/completeSimple)

```typescript
import { Model, streamSimple, completeSimple } from '@pi-recon/repi-ai';

const model: Model<'anthropic-messages'> = {
  id: 'claude-sonnet-4-5',
  name: 'Claude Sonnet 4.5',
  api: 'anthropic-messages',
  provider: 'anthropic',
  baseUrl: 'https://api.anthropic.com',
  reasoning: true,
  input: ['text', 'image'],
  cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  contextWindow: 200000,
  maxTokens: 64000,
};

// Check if model supports reasoning
if (model.reasoning) {
  console.log('Model supports reasoning/thinking');
}

// Use the simplified reasoning option
const response = await completeSimple(model, {
  messages: [{ role: 'user', content: 'Solve: 2x + 5 = 13' }]
}, {
  reasoning: 'medium'  // 'minimal' | 'low' | 'medium' | 'high' | 'xhigh'
});

// Access thinking and text blocks
for (const block of response.content) {
  if (block.type === 'thinking') {
    console.log('Thinking:', block.thinking);
  } else if (block.type === 'text') {
    console.log('Response:', block.text);
  }
}
```

### Provider-Specific Options (stream/complete)

For fine-grained control, use the provider-specific options:

```typescript
import { complete, Context, Model } from '@pi-recon/repi-ai';

// Each Model is supplied by the application; these functions do not query a catalog.
async function useProviderReasoning(
  context: Context,
  openaiModel: Model<'openai-responses'>,
  anthropicModel: Model<'anthropic-messages'>,
  googleModel: Model<'google-generative-ai'>,
) {
  // OpenAI reasoning
  await complete(openaiModel, context, {
    reasoningEffort: 'medium',
    reasoningSummary: 'detailed'  // OpenAI Responses API only
  });

  // Anthropic thinking
  await complete(anthropicModel, context, {
    thinkingEnabled: true,
    thinkingBudgetTokens: 8192  // Optional token limit
  });

  // Google Gemini thinking
  await complete(googleModel, context, {
    thinking: {
      enabled: true,
      budgetTokens: 8192  // -1 for dynamic, 0 to disable
    }
  });
}
```

### Streaming Thinking Content

When streaming, thinking content is delivered through specific events:

```typescript
const s = streamSimple(model, context, { reasoning: 'high' });

for await (const event of s) {
  switch (event.type) {
    case 'thinking_start':
      console.log('[Model started thinking]');
      break;
    case 'thinking_delta':
      process.stdout.write(event.delta);  // Stream thinking content
      break;
    case 'thinking_end':
      console.log('\n[Thinking complete]');
      break;
  }
}
```

## Stop Reasons

Every `AssistantMessage` includes a `stopReason` field that indicates how the generation ended:

- `"stop"` - Normal completion, the model finished its response
- `"length"` - Output hit the maximum token limit
- `"toolUse"` - Model is calling tools and expects tool results
- `"error"` - An error occurred during generation
- `"aborted"` - Request was cancelled via abort signal

`AssistantMessage` may also include `responseId`, a provider-specific upstream response or message identifier when the underlying API exposes one. Do not assume it is always present across providers.

## Error Handling

When a request ends with an error (including aborts and tool call validation errors), the streaming API emits an error event:

```typescript
// In streaming
for await (const event of stream) {
  if (event.type === 'error') {
    // event.reason is either "error" or "aborted"
    // event.error is the AssistantMessage with partial content
    console.error(`Error (${event.reason}):`, event.error.errorMessage);
    console.log('Partial content:', event.error.content);
  }
}

// The final message will have the error details
const message = await stream.result();
if (message.stopReason === 'error' || message.stopReason === 'aborted') {
  console.error('Request failed:', message.errorMessage);
  // message.content contains any partial content received before the error
  // message.usage contains partial token counts and costs
}
```

### Aborting Requests

The abort signal allows you to cancel in-progress requests. Aborted requests have `stopReason === 'aborted'`:

```typescript
import { Model, stream } from '@pi-recon/repi-ai';

const model: Model<'openai-responses'> = {
  id: 'gpt-4o-mini',
  name: 'GPT-4o mini',
  api: 'openai-responses',
  provider: 'openai',
  baseUrl: 'https://api.openai.com/v1',
  reasoning: false,
  input: ['text', 'image'],
  cost: { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0 },
  contextWindow: 128000,
  maxTokens: 16384,
};
const controller = new AbortController();

// Abort after 2 seconds
setTimeout(() => controller.abort(), 2000);

const s = stream(model, {
  messages: [{ role: 'user', content: 'Write a long story' }]
}, {
  signal: controller.signal
});

for await (const event of s) {
  if (event.type === 'text_delta') {
    process.stdout.write(event.delta);
  } else if (event.type === 'error') {
    // event.reason tells you if it was "error" or "aborted"
    console.log(`${event.reason === 'aborted' ? 'Aborted' : 'Error'}:`, event.error.errorMessage);
  }
}

// Get results (may be partial if aborted)
const response = await s.result();
if (response.stopReason === 'aborted') {
  console.log('Request was aborted:', response.errorMessage);
  console.log('Partial content received:', response.content);
  console.log('Tokens used:', response.usage);
}
```

### Continuing After Abort

Aborted messages can be added to the conversation context and continued in subsequent requests:

```typescript
const context = {
  messages: [
    { role: 'user', content: 'Explain quantum computing in detail' }
  ]
};

// First request gets aborted after 2 seconds
const controller1 = new AbortController();
setTimeout(() => controller1.abort(), 2000);

const partial = await complete(model, context, { signal: controller1.signal });

// Add the partial response to context
context.messages.push(partial);
context.messages.push({ role: 'user', content: 'Please continue' });

// Continue the conversation
const continuation = await complete(model, context);
```

### Debugging Provider Payloads

Use the `onPayload` callback to inspect the request payload sent to the provider. This is useful for debugging request formatting issues or provider validation errors.

```typescript
const response = await complete(model, context, {
  onPayload: (payload) => {
    console.log('Provider payload:', JSON.stringify(payload, null, 2));
  }
});
```

The callback is supported by `stream`, `complete`, `streamSimple`, and `completeSimple`.

## APIs, Models, and Providers

The library uses a registry of API implementations. Built-in APIs include:

- **`anthropic-messages`**: Anthropic Messages API (`streamAnthropic`, `AnthropicOptions`)
- **`google-generative-ai`**: Google Generative AI API (`streamGoogle`, `GoogleOptions`)
- **`google-vertex`**: Google Vertex AI API (`streamGoogleVertex`, `GoogleVertexOptions`)
- **`mistral-conversations`**: Mistral Conversations API (`streamMistral`, `MistralOptions`)
- **`openai-completions`**: OpenAI Chat Completions API (`streamOpenAICompletions`, `OpenAICompletionsOptions`)
- **`openai-responses`**: OpenAI Responses API (`streamOpenAIResponses`, `OpenAIResponsesOptions`)
- **`openai-codex-responses`**: OpenAI Codex Responses API (`streamOpenAICodexResponses`, `OpenAICodexResponsesOptions`)
- **`azure-openai-responses`**: Azure OpenAI Responses API (`streamAzureOpenAIResponses`, `AzureOpenAIResponsesOptions`)
- **`bedrock-converse-stream`**: Amazon Bedrock Converse API (`streamBedrock`, `BedrockOptions`)

### Faux provider for tests

`registerFauxProvider()` registers a temporary in-memory provider for tests and demos. It is opt-in and not part of the
built-in API adapter set.

```typescript
import {
  complete,
  fauxAssistantMessage,
  fauxText,
  fauxThinking,
  fauxToolCall,
  registerFauxProvider,
  stream,
} from '@pi-recon/repi-ai';

const registration = registerFauxProvider({
  tokensPerSecond: 50 // optional
});

const model = registration.getModel();
const context = {
  messages: [{ role: 'user', content: 'Summarize package.json and then call echo', timestamp: Date.now() }]
};

registration.setResponses([
  fauxAssistantMessage([
    fauxThinking('Need to inspect package metadata first.'),
    fauxToolCall('echo', { text: 'package.json' })
  ], { stopReason: 'toolUse' })
]);

const first = await complete(model, context, {
  sessionId: 'session-1',
  cacheRetention: 'short'
});
context.messages.push(first);

context.messages.push({
  role: 'toolResult',
  toolCallId: first.content.find((block) => block.type === 'toolCall')!.id,
  toolName: 'echo',
  content: [{ type: 'text', text: 'package.json contents here' }],
  isError: false,
  timestamp: Date.now()
});

registration.setResponses([
  fauxAssistantMessage([
    fauxThinking('Now I can summarize the tool output.'),
    fauxText('Here is the summary.')
  ])
]);

const s = stream(model, context);
for await (const event of s) {
  console.log(event.type);
}

// Optional: register multiple faux models for model-switching tests
const multiModel = registerFauxProvider({
  models: [
    { id: 'faux-fast', reasoning: false },
    { id: 'faux-thinker', reasoning: true }
  ]
});
const thinker = multiModel.getModel('faux-thinker');

console.log(thinker?.reasoning);
console.log(registration.getPendingResponseCount());
console.log(registration.state.callCount);
registration.unregister();
multiModel.unregister();
```

Notes:
- Responses are consumed from a queue in request start order.
- If the queue is empty, the faux provider returns an assistant error message with `errorMessage: "No more faux responses queued"`.
- Use `registration.setResponses([...])` to replace the remaining queue and `registration.appendResponses([...])` to add more responses.
- `registration.models` exposes all registered faux models. `registration.getModel()` returns the first one, and `registration.getModel(id)` returns a specific one.
- Use `fauxAssistantMessage(...)` for scripted assistant replies. Use `fauxText(...)`, `fauxThinking(...)`, and `fauxToolCall(...)` to build content blocks without filling in low-level fields manually.
- `registration.unregister()` removes the temporary provider from the global API registry.
- Usage is estimated at roughly 1 token per 4 characters. When `sessionId` is present and `cacheRetention` is not `"none"`, prompt cache reads and writes are simulated automatically.
- Tool call arguments stream incrementally via `toolcall_delta` chunks.
- By default, each streamed chunk is emitted on its own microtask. Set `tokensPerSecond` to pace chunk delivery in real time.
- The intended use is one deterministic scripted flow per registration. If you need independent concurrent flows, register separate faux providers.

### Providers and Models

A **provider** offers models through a specific API. The package does not ship a generated model/provider catalog.
Direct callers provide model metadata themselves; coding-agent applications can instead let `ModelRuntime` load
explicit entries from `models.json`, `REPI_*` environment variables, or an extension. This keeps the AI package small,
avoids stale model metadata, and lets operators own endpoint, capability, and pricing data.

For example:
- **Anthropic** models use the `anthropic-messages` API
- **Google** models use the `google-generative-ai` API
- **OpenAI** models use the `openai-responses` API
- **Mistral** models use the `mistral-conversations` API
- **xAI, Cerebras, Groq, NVIDIA NIM, Together AI, etc.** models use the `openai-completions` API (OpenAI-compatible)

### Supplying Providers and Models

Keep model selection in the application that owns deployment configuration. A small application can keep an explicit
list in memory and select from it without relying on package-global state:

```typescript
import { type Model, stream } from '@pi-recon/repi-ai';

const models: Model<'openai-responses'>[] = [
  {
    id: 'gpt-4o-mini',
    name: 'GPT-4o mini',
    api: 'openai-responses',
    provider: 'openai',
    baseUrl: 'https://api.openai.com/v1',
    reasoning: false,
    input: ['text', 'image'],
    cost: { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0 },
    contextWindow: 128000,
    maxTokens: 16384,
  },
];

const model = models.find((candidate) => candidate.id === 'gpt-4o-mini');
if (!model) throw new Error('Model is not configured');
const response = await stream(model, { messages: [{ role: 'user', content: 'Hello' }] }).result();
console.log(response.stopReason);
```

For coding-agent, pass the `ModelRuntime` and let it load the same explicit metadata from `models.json`, `REPI_*`, or
an extension. No upstream provider list is downloaded or inferred from a model ID.

### Custom Models

You can create custom models for local inference servers or custom endpoints:

```typescript
import { Model, stream } from '@pi-recon/repi-ai';

// Example: Ollama using OpenAI-compatible API
const ollamaModel: Model<'openai-completions'> = {
  id: 'llama-3.1-8b',
  name: 'Llama 3.1 8B (Ollama)',
  api: 'openai-completions',
  provider: 'ollama',
  baseUrl: 'http://localhost:11434/v1',
  reasoning: false,
  input: ['text'],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 128000,
  maxTokens: 32000
};

// Example: LiteLLM proxy with explicit compat settings
const litellmModel: Model<'openai-completions'> = {
  id: 'gpt-4o',
  name: 'GPT-4o (via LiteLLM)',
  api: 'openai-completions',
  provider: 'litellm',
  baseUrl: 'http://localhost:4000/v1',
  reasoning: false,
  input: ['text', 'image'],
  cost: { input: 2.5, output: 10, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 128000,
  maxTokens: 16384,
  compat: {
    supportsStore: false,  // LiteLLM doesn't support the store field
  }
};

// Example: Custom endpoint with headers (bypassing Cloudflare bot detection)
const proxyModel: Model<'anthropic-messages'> = {
  id: 'claude-sonnet-4',
  name: 'Claude Sonnet 4 (Proxied)',
  api: 'anthropic-messages',
  provider: 'custom-proxy',
  baseUrl: 'https://proxy.example.com/v1',
  reasoning: true,
  input: ['text', 'image'],
  cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  contextWindow: 200000,
  maxTokens: 8192,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'X-Custom-Auth': 'bearer-token-here'
  }
};

// Use the custom model
const response = await stream(ollamaModel, context, {
  apiKey: 'dummy' // Ollama doesn't need a real key
});
```

`cost.input`, `cost.output`, `cost.cacheRead`, and `cost.cacheWrite` are USD per million tokens. Optional `cost.tiers`
entries contain the same four rates plus `inputTokensAbove`; the highest matching threshold applies to the full
request. Keep these values with the rest of the host-owned model metadata rather than baking them into an adapter.

Some OpenAI-compatible servers do not understand the `developer` role used for reasoning-capable models. For those providers, set `compat.supportsDeveloperRole` to `false` so the system prompt is sent as a `system` message instead. If the server also does not support `reasoning_effort`, set `compat.supportsReasoningEffort` to `false` too.

Use model-level `thinkingLevelMap` to describe model-specific thinking controls. Keys are pi thinking levels (`off`, `minimal`, `low`, `medium`, `high`, `xhigh`). Missing keys use provider defaults, string values are sent to the provider, and `null` marks a level unsupported.

This commonly applies to Ollama, vLLM, SGLang, and similar OpenAI-compatible servers. You can set `compat` at the provider level or per model.

```typescript
const ollamaReasoningModel: Model<'openai-completions'> = {
  id: 'gpt-oss:20b',
  name: 'GPT-OSS 20B (Ollama)',
  api: 'openai-completions',
  provider: 'ollama',
  baseUrl: 'http://localhost:11434/v1',
  reasoning: true,
  input: ['text'],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 131072,
  maxTokens: 32000,
  thinkingLevelMap: {
    minimal: null,
    low: null,
    medium: null,
    high: 'high',
    xhigh: null,
  },
  compat: {
    supportsDeveloperRole: false,
    supportsReasoningEffort: false,
  }
};
```

### OpenAI Compatibility Settings

The `openai-completions` API is implemented by many providers with minor differences. By default, the library auto-detects compatibility settings based on `baseUrl` for a small set of known OpenAI-compatible providers (Cerebras, xAI, Chutes, DeepSeek, NVIDIA NIM, Together AI, zAi, OpenCode, Cloudflare Workers AI, etc.). For custom proxies or unknown endpoints, you can override these settings via the `compat` field. For `openai-responses` models, the compat field supports Responses-specific flags.

```typescript
interface OpenAICompletionsCompat {
  supportsStore?: boolean;           // Whether provider supports the `store` field (default: true)
  supportsDeveloperRole?: boolean;   // Whether provider supports `developer` role vs `system` (default: true)
  supportsReasoningEffort?: boolean; // Whether provider supports `reasoning_effort` (default: true)
  supportsUsageInStreaming?: boolean; // Whether provider supports `stream_options: { include_usage: true }` (default: true)
  supportsStrictMode?: boolean;      // Whether provider supports `strict` in tool definitions (default: true)
  sendSessionAffinityHeaders?: boolean; // Whether to send `session_id`, `x-client-request-id`, and `x-session-affinity` from `sessionId` when caching is enabled (default: false)
  maxTokensField?: 'max_completion_tokens' | 'max_tokens';  // Which field name to use (default: max_completion_tokens)
  requiresToolResultName?: boolean;  // Whether tool results require the `name` field (default: false)
  requiresAssistantAfterToolResult?: boolean; // Whether tool results must be followed by an assistant message (default: false)
  requiresThinkingAsText?: boolean;  // Whether thinking blocks must be converted to text (default: false)
  requiresReasoningContentOnAssistantMessages?: boolean; // Whether all replayed assistant messages must include empty reasoning_content when reasoning is enabled (default: auto-detected for DeepSeek)
  thinkingFormat?: 'openai' | 'openrouter' | 'deepseek' | 'together' | 'zai' | 'qwen' | 'qwen-chat-template' | 'string-thinking' | 'ant-ling'; // Format for reasoning param: 'openai' uses reasoning_effort, 'openrouter' uses reasoning: { effort }, 'deepseek' uses thinking: { type } plus reasoning_effort when supported, 'together' uses reasoning: { enabled } plus reasoning_effort when supported, 'zai' uses enable_thinking, 'qwen' uses enable_thinking, 'qwen-chat-template' uses chat_template_kwargs.enable_thinking, 'string-thinking' uses top-level thinking, 'ant-ling' uses reasoning: { effort } only for mapped efforts (default: openai)
  cacheControlFormat?: 'anthropic';  // Anthropic-style cache_control on system prompt, last tool, and last user/assistant text content
  openRouterRouting?: OpenRouterRouting; // OpenRouter routing preferences (default: {})
  vercelGatewayRouting?: VercelGatewayRouting; // Vercel AI Gateway routing preferences (default: {})
}

interface OpenAIResponsesCompat {
  supportsDeveloperRole?: boolean;   // Whether provider supports `developer` role vs `system` (default: true)
  sendSessionIdHeader?: boolean;     // Whether to send `session_id` from `sessionId` when caching is enabled (default: true)
  supportsLongCacheRetention?: boolean; // Whether provider supports `prompt_cache_retention: "24h"` (default: true)
}
```

If `compat` is not set, the library falls back to URL-based detection. If `compat` is partially set, unspecified fields use the detected defaults. This is useful for:

- **LiteLLM proxies**: May not support `store` field
- **Custom inference servers**: May use non-standard field names
- **Self-hosted endpoints**: May have different feature support

### Type Safety

Models are typed by their API, which keeps the model metadata accurate. Provider-specific option types are enforced when you call the provider functions directly. The generic `stream` and `complete` functions accept `StreamOptions` with additional provider fields.

```typescript
import { streamAnthropic, type AnthropicOptions, type Model } from '@pi-recon/repi-ai';

// Construct this from application-owned metadata (as in the Custom Models section).
const claude: Model<'anthropic-messages'> = {
  id: 'claude-sonnet-4-5',
  name: 'Claude Sonnet 4.5',
  api: 'anthropic-messages',
  provider: 'anthropic',
  baseUrl: 'https://api.anthropic.com',
  reasoning: true,
  input: ['text', 'image'],
  cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  contextWindow: 200000,
  maxTokens: 64000,
};

const options: AnthropicOptions = {
  thinkingEnabled: true,
  thinkingBudgetTokens: 2048
};

await streamAnthropic(claude, context, options);
```

## Cross-Provider Handoffs

The library supports seamless handoffs between different LLM providers within the same conversation. This allows you to switch models mid-conversation while preserving context, including thinking blocks, tool calls, and tool results.

### How It Works

When messages from one provider are sent to a different provider, the library automatically transforms them for compatibility:

- **User and tool result messages** are passed through unchanged
- **Assistant messages from the same provider/API** are preserved as-is
- **Assistant messages from different providers** have their thinking blocks converted to text with `<thinking>` tags
- **Tool calls and regular text** are preserved unchanged

### Example: Multi-Provider Conversation

```typescript
import { complete, Context, Model } from '@pi-recon/repi-ai';

async function handOff(
  claude: Model<'anthropic-messages'>,
  gpt5: Model<'openai-responses'>,
  gemini: Model<'google-generative-ai'>,
) {
  // Each argument is loaded from application-owned configuration.
  const context: Context = { messages: [] };

  context.messages.push({ role: 'user', content: 'What is 25 * 18?' });
  const claudeResponse = await complete(claude, context, {
    thinkingEnabled: true
  });
  context.messages.push(claudeResponse);

  // GPT-5 sees Claude's thinking as <thinking> tagged text.
  context.messages.push({ role: 'user', content: 'Is that calculation correct?' });
  const gptResponse = await complete(gpt5, context);
  context.messages.push(gptResponse);

  context.messages.push({ role: 'user', content: 'What was the original question?' });
  return complete(gemini, context);
}
```

### Provider Compatibility

All providers can handle messages from other providers, including:
- Text content
- Tool calls and tool results (including images in tool results)
- Thinking/reasoning blocks (transformed to tagged text for cross-provider compatibility)
- Aborted messages with partial content

This enables flexible workflows where you can:
- Start with a fast model for initial responses
- Switch to a more capable model for complex reasoning
- Use specialized models for specific tasks
- Maintain conversation continuity across provider outages

## Context Serialization

The `Context` object can be easily serialized and deserialized using standard JSON methods, making it simple to persist conversations, implement chat history, or transfer contexts between services:

```typescript
import { Context, Model, complete } from '@pi-recon/repi-ai';

async function persistContext(
  model: Model<'openai-responses'>,
  newModel: Model<'anthropic-messages'>,
) {
  // Both models are explicit inputs loaded by the host.
  const context: Context = {
    systemPrompt: 'You are a helpful assistant.',
    messages: [
      { role: 'user', content: 'What is TypeScript?' }
    ]
  };

  const response = await complete(model, context);
  context.messages.push(response);

  const serialized = JSON.stringify(context);
  console.log('Serialized context size:', serialized.length, 'bytes');

  localStorage.setItem('conversation', serialized);

  const restored: Context = JSON.parse(localStorage.getItem('conversation')!);
  restored.messages.push({ role: 'user', content: 'Tell me more about its type system' });

  return complete(newModel, restored);
}
```

> **Note**: If the context contains images (encoded as base64 as shown in the Image Input section), those will also be serialized.

## Browser Usage

The library supports browser environments. You must pass the API key explicitly since environment variables are not available in browsers:

```typescript
import { complete, Model } from '@pi-recon/repi-ai';

// API key must be passed explicitly in browser; model metadata is explicit too.
const model: Model<'anthropic-messages'> = {
  id: 'claude-3-5-haiku-20241022',
  name: 'Claude 3.5 Haiku',
  api: 'anthropic-messages',
  provider: 'anthropic',
  baseUrl: 'https://api.anthropic.com',
  reasoning: false,
  input: ['text', 'image'],
  cost: { input: 0.8, output: 4, cacheRead: 0.08, cacheWrite: 1 },
  contextWindow: 200000,
  maxTokens: 8192,
};

const response = await complete(model, {
  messages: [{ role: 'user', content: 'Hello!' }]
}, {
  apiKey: 'your-api-key'
});
```

> **Security Warning**: Exposing API keys in frontend code is dangerous. Anyone can extract and abuse your keys. Only use this approach for internal tools or demos. For production applications, use a backend proxy that keeps your API keys secure.

### Browser Compatibility Notes

- Amazon Bedrock (`bedrock-converse-stream`) is not supported in browser environments.
- OAuth login flows are not supported in browser environments. Use the `@pi-recon/repi-ai/oauth` entry point in Node.js.
- A host-registered Bedrock model can still appear in browser model lists, but calls fail at runtime.
- Use a server-side proxy or backend service if you need Bedrock or OAuth-based auth from a web app.

### Environment Variables (Node.js only)

Environment variables provide credentials only. They never create a provider, discover a model, or supply endpoint,
capability, context-window, or pricing metadata.

For an explicit model, the default lookup is the normalized provider ID followed by `_API_KEY`:

```bash
export MY_GATEWAY_API_KEY="..."
```

A model with `provider: "my-gateway"` can use that key automatically. For providers with non-standard credential
flows, pass `apiKey` or `headers` explicitly, or resolve the credential in the host runtime:

```typescript
const response = await complete(model, context, {
  apiKey: process.env.MY_GATEWAY_TOKEN,
  headers: { "X-Route": process.env.MY_GATEWAY_ROUTE ?? "default" },
});
```

The coding-agent runtime additionally supports `REPI_*` environment configuration. Set
`REPI_AUTH_TOKEN`, `REPI_BASE_URL`, `REPI_MODEL`, and `REPI_MODEL_API` to define one explicit runtime model.
Optional `REPI_CONTEXT_WINDOW`, `REPI_MAX_TOKENS`, `REPI_MODEL_INPUT`, `REPI_MODEL_REASONING`, and cost variables
describe its limits and billing metadata. Keep those values in the process environment or an environment-backed
`models.json` reference rather than committing secrets.

## OAuth Providers

OAuth implementations are opt-in helpers. Import the implementation you need, register it in your host, and keep
credential storage in that host. Importing `@pi-recon/repi-ai/oauth` never registers a provider and this package
does not provide a login CLI or a default OAuth catalog.

```typescript
import { anthropicOAuthProvider, registerOAuthProvider } from '@pi-recon/repi-ai/oauth';

registerOAuthProvider(anthropicOAuthProvider);
// Build an explicit Model with provider: 'anthropic' and pass the resolved credential
// through your host's auth/runtime layer.
```

For a custom OAuth integration, implement `OAuthProviderInterface` and register it under the provider ID used by
your explicit model. The AI package only handles the protocol adapter and token helpers; it does not create
`auth.json`, choose models, or discover endpoints.

## Development

### Adding a New API Adapter

Add code only when an endpoint needs a wire protocol the existing adapters cannot express. A new brand, endpoint, or
model normally requires configuration only. This checklist covers a genuinely new API adapter:

#### 1. Core Types (`src/types.ts`)

- Add the API identifier to `KnownApi` (for example `"bedrock-converse-stream"`)
- Create an options interface extending `StreamOptions` (for example `BedrockOptions`)
- Use any provider ID string in the explicit model definition; no provider-name union or catalog update is required.

#### 2. Adapter Implementation (`src/providers/`)

Create a new adapter file (for example `amazon-bedrock.ts`) that exports:

- `stream<Provider>()` function returning `AssistantMessageEventStream`
- `streamSimple<Provider>()` for `SimpleStreamOptions` mapping
- Provider-specific options interface
- Message conversion functions to transform `Context` to provider format
- Tool conversion if the provider supports tools
- Response parsing to emit standardized events (`text`, `tool_call`, `thinking`, `usage`, `stop`)

#### 3. API Registry Integration (`src/providers/register-builtins.ts`)

- Register the API with `registerApiProvider()`
- Add a package subpath export in `package.json` for the provider module (`./dist/providers/<provider>.js`)
- Add lazy loader wrappers in `src/providers/register-builtins.ts`, do not statically import provider implementation modules there
- Add any root-level `export type` re-exports in `src/index.ts` that should remain available from `@pi-recon/repi-ai`
- Add only protocol-specific credential resolution when the adapter genuinely
  needs it; generic providers use `<NORMALIZED_PROVIDER_ID>_API_KEY` or an
  explicit key/header supplied by the host
- Ensure `streamSimple` resolves credentials through the provider's auth configuration or its protocol-specific flow

The protocol adapter and model configuration are separate concerns: adding an adapter does not add any model IDs. A
host supplies one or more explicit models that target the adapter, including custom endpoints and pricing.

#### 4. Dynamic Model Configuration

- Do not add a generated model file or a package-wide default catalog.
- For direct library use, construct explicit `Model` / `ImagesModel` objects in the application.
- For REPI's coding-agent runtime, put model metadata in `models.json`, expose it through `REPI_*` environment variables,
  or provide it from an extension. Include `baseUrl`, API protocol, input modalities, reasoning flags, context/output
  limits, headers/compatibility overrides, and input/output/cache pricing (including optional tiers).
- Keep discovery and refresh provider-owned; persist only model lists explicitly configured by the host.

#### 5. Tests (`test/`)

Create or update test files to cover the new provider:

- `stream.test.ts` - Basic streaming and tool use
- `tokens.test.ts` - Token usage reporting
- `abort.test.ts` - Request cancellation
- `empty.test.ts` - Empty message handling
- `context-overflow.test.ts` - Context limit errors
- `image-limits.test.ts` - Image support (if applicable)
- `unicode-surrogate.test.ts` - Unicode handling
- `tool-call-without-result.test.ts` - Orphaned tool calls
- `image-tool-result.test.ts` - Images in tool results
- `total-tokens.test.ts` - Token counting accuracy
- `cross-provider-handoff.test.ts` - Cross-provider context replay

For `cross-provider-handoff.test.ts`, add at least one provider/model pair. If the provider exposes multiple model families (for example GPT and Claude), add at least one pair per family.

For adapters with non-standard auth (AWS, Google Vertex), create a utility like `bedrock-utils.ts` with credential detection helpers.

#### 6. Coding Agent Integration (`../coding-agent/`)

Do not add a provider or model to a hard-coded default map. Verify instead that the coding agent can load the model's
provider ID, adapter, endpoint, capabilities, limits, and pricing from `models.json`, `REPI_*` environment variables, or
an extension.

Update `src/cli/args.ts`:

- Add environment variable documentation in the help text

Update `README.md` only when the adapter adds a new wire contract or an
auth-specific requirement. Do not add a vendor/provider catalog entry.

#### 7. Documentation

Update `packages/ai/README.md`:

- Add a wire adapter to Supported API Adapters only when the endpoint uses a new protocol
- Document any provider-specific options or authentication requirements
- Keep environment guidance generic; document a new variable only when it is a
  coding-agent runtime control (`REPI_*`) or a protocol-specific credential

#### 8. Changelog

Add an entry to `packages/ai/CHANGELOG.md` under `## [Unreleased]`:

```markdown
### Added
- Added support for [API adapter or auth capability] ([#PR](link) by [@author](link))
```

## License

MIT
