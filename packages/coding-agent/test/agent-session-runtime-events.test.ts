import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, registerFauxProvider } from "@pi-recon/repi-ai";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentSession } from "../src/core/agent-session.ts";
import {
	type CreateAgentSessionRuntimeFactory,
	createAgentSessionFromServices,
	createAgentSessionRuntime,
	createAgentSessionServices,
} from "../src/core/agent-session-runtime.ts";
import { AuthStorage } from "../src/core/auth-storage.ts";
import { SessionManager } from "../src/core/session-manager.ts";
import type {
	ExtensionFactory,
	SessionBeforeForkEvent,
	SessionBeforeSwitchEvent,
	SessionShutdownEvent,
	SessionStartEvent,
} from "../src/index.ts";

type RecordedSessionEvent =
	| SessionBeforeSwitchEvent
	| SessionBeforeForkEvent
	| SessionShutdownEvent
	| SessionStartEvent;

describe("AgentSessionRuntime session lifecycle events", () => {
	const cleanups: Array<() => Promise<void> | void> = [];

	afterEach(async () => {
		while (cleanups.length > 0) {
			await cleanups.pop()?.();
		}
	});

	async function createRuntimeHost(extensionFactory: ExtensionFactory, options?: { inMemory?: boolean }) {
		const tempDir = join(tmpdir(), `pi-runtime-events-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });

		const faux = registerFauxProvider();
		faux.setResponses([fauxAssistantMessage("one"), fauxAssistantMessage("two"), fauxAssistantMessage("three")]);

		const authStorage = AuthStorage.inMemory();
		authStorage.setRuntimeApiKey(faux.getModel().provider, "faux-key");

		const runtimeOptions = {
			agentDir: tempDir,
			authStorage,
			model: faux.getModel(),
			resourceLoaderOptions: {
				extensionFactories: [extensionFactory],
				noSkills: true,
				noPromptTemplates: true,
				noThemes: true,
			},
		};
		let failNextRuntimeCreation = false;
		const createdSessions: AgentSession[] = [];
		const createRuntime: CreateAgentSessionRuntimeFactory = async ({ cwd, sessionManager, sessionStartEvent }) => {
			if (failNextRuntimeCreation) {
				failNextRuntimeCreation = false;
				throw new Error("replacement runtime creation failed");
			}
			const services = await createAgentSessionServices({
				...runtimeOptions,
				cwd,
			});
			const created = await createAgentSessionFromServices({
				services,
				sessionManager,
				sessionStartEvent,
				model: faux.getModel(),
			});
			createdSessions.push(created.session);
			return {
				...created,
				services,
				diagnostics: services.diagnostics,
			};
		};
		const runtimeHost = await createAgentSessionRuntime(createRuntime, {
			cwd: tempDir,
			agentDir: tempDir,
			sessionManager: options?.inMemory ? SessionManager.inMemory(tempDir) : SessionManager.create(tempDir),
		});
		await runtimeHost.session.bindExtensions({});

		cleanups.push(async () => {
			await runtimeHost.dispose();
			faux.unregister();
			if (existsSync(tempDir)) {
				rmSync(tempDir, { recursive: true, force: true });
			}
		});

		return {
			runtimeHost,
			faux,
			tempDir,
			createdSessions,
			failNextRuntimeCreation: () => {
				failNextRuntimeCreation = true;
			},
		};
	}

	it("emits session_before_switch and session_start for new and resume flows", async () => {
		const events: RecordedSessionEvent[] = [];
		const { runtimeHost } = await createRuntimeHost((pi) => {
			pi.on("session_before_switch", (event) => {
				events.push(event);
			});
			pi.on("session_shutdown", (event) => {
				events.push(event);
			});
			pi.on("session_start", (event) => {
				events.push(event);
			});
		});

		expect(events).toEqual([{ type: "session_start", reason: "startup" }]);
		events.length = 0;

		await runtimeHost.session.prompt("hello");
		const originalSessionFile = runtimeHost.session.sessionFile;
		expect(originalSessionFile).toBeTruthy();

		const newSessionResult = await runtimeHost.newSession();
		expect(newSessionResult.cancelled).toBe(false);
		await runtimeHost.session.bindExtensions({});
		const secondSessionFile = runtimeHost.session.sessionFile;
		expect(events).toEqual([
			{ type: "session_before_switch", reason: "new", targetSessionFile: undefined },
			{ type: "session_shutdown", reason: "new", targetSessionFile: secondSessionFile },
			{ type: "session_start", reason: "new", previousSessionFile: originalSessionFile },
		]);

		events.length = 0;
		expect(secondSessionFile).toBeTruthy();

		const switchResult = await runtimeHost.switchSession(originalSessionFile!);
		expect(switchResult.cancelled).toBe(false);
		await runtimeHost.session.bindExtensions({});
		expect(events).toEqual([
			{ type: "session_before_switch", reason: "resume", targetSessionFile: originalSessionFile },
			{ type: "session_shutdown", reason: "resume", targetSessionFile: originalSessionFile },
			{ type: "session_start", reason: "resume", previousSessionFile: secondSessionFile },
		]);
	});

	it("honors session_before_switch cancellation", async () => {
		const events: RecordedSessionEvent[] = [];
		const { runtimeHost } = await createRuntimeHost((pi) => {
			pi.on("session_before_switch", (event) => {
				events.push(event);
				return { cancel: true };
			});
			pi.on("session_start", (event) => {
				events.push(event);
			});
		});

		expect(events).toEqual([{ type: "session_start", reason: "startup" }]);
		events.length = 0;

		await runtimeHost.session.prompt("hello");
		const originalSessionFile = runtimeHost.session.sessionFile;

		const result = await runtimeHost.newSession();
		expect(result.cancelled).toBe(true);
		expect(runtimeHost.session.sessionFile).toBe(originalSessionFile);
		expect(events).toEqual([{ type: "session_before_switch", reason: "new", targetSessionFile: undefined }]);
	});

	it("runs beforeSessionInvalidate after session_shutdown and before rebindSession", async () => {
		const phases: string[] = [];
		const { runtimeHost } = await createRuntimeHost((pi) => {
			pi.on("session_shutdown", () => {
				phases.push("session_shutdown");
			});
		});
		const oldSession = runtimeHost.session;
		runtimeHost.setBeforeSessionInvalidate(() => {
			phases.push("beforeSessionInvalidate");
			expect(oldSession.extensionRunner.createContext().cwd).toBe(oldSession.sessionManager.getCwd());
		});
		runtimeHost.setRebindSession(async () => {
			phases.push("rebindSession");
		});

		await runtimeHost.newSession();

		expect(phases).toEqual(["session_shutdown", "beforeSessionInvalidate", "rebindSession"]);
		expect(() => oldSession.extensionRunner.createContext().cwd).toThrow(
			"This extension ctx is stale after session replacement or reload. Do not use a captured pi or command ctx after ctx.newSession(), ctx.fork(), ctx.switchSession(), or ctx.reload(). For newSession, fork, and switchSession, move post-replacement work into withSession and use the ctx passed to withSession. For reload, do not use the old ctx after await ctx.reload().",
		);
		runtimeHost.setBeforeSessionInvalidate(undefined);
		runtimeHost.setRebindSession(undefined);
	});

	it("keeps the current session usable when replacement runtime creation fails", async () => {
		const shutdownReasons: SessionShutdownEvent["reason"][] = [];
		const { runtimeHost, tempDir, failNextRuntimeCreation } = await createRuntimeHost((pi) => {
			pi.on("session_shutdown", (event) => {
				shutdownReasons.push(event.reason);
			});
		});
		await runtimeHost.session.prompt("hello");
		const currentSession = runtimeHost.session;
		const currentSessionFile = currentSession.sessionFile;
		const forkEntry = currentSession.getUserMessagesForForking()[0];
		expect(currentSessionFile).toBeTruthy();
		expect(forkEntry).toBeTruthy();

		const expectCreationFailure = async (replace: () => Promise<unknown>) => {
			failNextRuntimeCreation();
			await expect(replace()).rejects.toThrow("replacement runtime creation failed");
			expect(runtimeHost.session).toBe(currentSession);
			expect(currentSession.extensionRunner.createContext().cwd).toBe(tempDir);
			expect(shutdownReasons).toEqual([]);
		};

		await expectCreationFailure(() => runtimeHost.newSession());
		await expectCreationFailure(() => runtimeHost.switchSession(currentSessionFile!));
		await expectCreationFailure(() => runtimeHost.fork(forkEntry.entryId));
		await expectCreationFailure(() => runtimeHost.importFromJsonl(currentSessionFile!));

		await currentSession.prompt("still usable");
		expect(runtimeHost.session.messages.filter((message) => message.role === "assistant")).toHaveLength(2);
	});

	it("updates cwd-bound global state only after a replacement commits", async () => {
		const { runtimeHost, tempDir, failNextRuntimeCreation } = await createRuntimeHost(() => {});
		const originalSessionFile = runtimeHost.session.sessionFile;
		const otherCwd = join(tempDir, "other-project");
		const otherSessionDir = join(tempDir, "other-sessions");
		mkdirSync(otherCwd, { recursive: true });
		const otherSession = SessionManager.create(otherCwd, otherSessionDir);
		otherSession.appendMessage({
			role: "user",
			content: [{ type: "text", text: "other" }],
			timestamp: Date.now(),
		});
		otherSession.appendMessage(fauxAssistantMessage("other"));
		const otherSessionFile = otherSession.getSessionFile();
		expect(originalSessionFile).toBeTruthy();
		expect(otherSessionFile).toBeTruthy();

		const previousMissionScope = process.env.REPI_MISSION_SCOPE;
		cleanups.push(() => {
			if (previousMissionScope === undefined) delete process.env.REPI_MISSION_SCOPE;
			else process.env.REPI_MISSION_SCOPE = previousMissionScope;
		});
		process.env.REPI_MISSION_SCOPE = runtimeHost.cwd;
		const appliedCwds: string[] = [];
		runtimeHost.setAfterSessionApply((cwd) => {
			process.env.REPI_MISSION_SCOPE = cwd;
			appliedCwds.push(cwd);
		});

		await runtimeHost.switchSession(otherSessionFile!);
		expect(process.env.REPI_MISSION_SCOPE).toBe(otherCwd);
		expect(appliedCwds).toEqual([otherCwd]);

		failNextRuntimeCreation();
		await expect(runtimeHost.switchSession(originalSessionFile!)).rejects.toThrow(
			"replacement runtime creation failed",
		);
		expect(runtimeHost.cwd).toBe(otherCwd);
		expect(process.env.REPI_MISSION_SCOPE).toBe(otherCwd);
		expect(appliedCwds).toEqual([otherCwd]);
	});

	it("removes fork and import artifacts when replacement creation fails", async () => {
		const { runtimeHost, tempDir, failNextRuntimeCreation } = await createRuntimeHost(() => {});
		await runtimeHost.session.prompt("hello");
		const sessionManager = runtimeHost.session.sessionManager;
		const sessionDir = sessionManager.getSessionDir();
		const originalSessionFile = runtimeHost.session.sessionFile!;
		const assistantEntry = sessionManager
			.getEntries()
			.find((entry) => entry.type === "message" && entry.message.role === "assistant");
		expect(assistantEntry).toBeTruthy();
		const filesBefore = readdirSync(sessionDir).sort();

		failNextRuntimeCreation();
		await expect(runtimeHost.fork(assistantEntry!.id, { position: "at" })).rejects.toThrow(
			"replacement runtime creation failed",
		);
		expect(readdirSync(sessionDir).sort()).toEqual(filesBefore);

		const importSource = join(tempDir, `external-${Date.now()}.jsonl`);
		copyFileSync(originalSessionFile, importSource);
		failNextRuntimeCreation();
		await expect(runtimeHost.importFromJsonl(importSource)).rejects.toThrow("replacement runtime creation failed");
		expect(readdirSync(sessionDir).sort()).toEqual(filesBefore);
	});

	it("keeps the current session usable when new-session setup fails", async () => {
		const shutdownReasons: SessionShutdownEvent["reason"][] = [];
		const { runtimeHost, createdSessions, tempDir } = await createRuntimeHost((pi) => {
			pi.on("session_shutdown", (event) => {
				shutdownReasons.push(event.reason);
			});
		});
		await runtimeHost.session.prompt("hello");
		const currentSession = runtimeHost.session;
		const currentSessionFile = currentSession.sessionFile;
		const currentEntries = currentSession.sessionManager.getEntries();
		const currentMessages = [...currentSession.messages];

		await expect(
			runtimeHost.newSession({
				setup: async (sessionManager) => {
					sessionManager.appendCustomMessageEntry("test", "candidate-only", false);
					throw new Error("setup failed");
				},
			}),
		).rejects.toThrow("setup failed");

		const candidate = createdSessions.at(-1);
		expect(candidate).toBeDefined();
		expect(candidate).not.toBe(currentSession);
		expect(runtimeHost.session).toBe(currentSession);
		expect(currentSession.sessionFile).toBe(currentSessionFile);
		expect(currentSession.sessionManager.getEntries()).toEqual(currentEntries);
		expect(currentSession.messages).toEqual(currentMessages);
		expect(currentSession.extensionRunner.createContext().cwd).toBe(tempDir);
		expect(shutdownReasons).toEqual([]);
		expect(() => candidate!.extensionRunner.createContext().cwd).toThrow(
			"This extension ctx is stale after session replacement or reload",
		);

		await currentSession.prompt("still usable after setup failure");
		expect(runtimeHost.session.messages.filter((message) => message.role === "assistant")).toHaveLength(2);
	});

	it("leaves the in-memory session unchanged when fork runtime creation fails", async () => {
		const shutdownReasons: SessionShutdownEvent["reason"][] = [];
		const { runtimeHost, failNextRuntimeCreation, tempDir } = await createRuntimeHost(
			(pi) => {
				pi.on("session_shutdown", (event) => {
					shutdownReasons.push(event.reason);
				});
			},
			{ inMemory: true },
		);
		await runtimeHost.session.prompt("hello");
		await runtimeHost.session.prompt("again");
		const currentSession = runtimeHost.session;
		const sessionManager = currentSession.sessionManager;
		const forkEntry = currentSession.getUserMessagesForForking()[0];
		expect(forkEntry).toBeTruthy();

		const currentSessionId = sessionManager.getSessionId();
		const currentHeader = sessionManager.getHeader();
		const currentLeafId = sessionManager.getLeafId();
		const currentEntries = sessionManager.getEntries();
		const currentMessages = [...currentSession.messages];

		const expectForkCreationFailure = async (position: "before" | "at") => {
			failNextRuntimeCreation();
			await expect(runtimeHost.fork(forkEntry.entryId, { position })).rejects.toThrow(
				"replacement runtime creation failed",
			);
			expect(runtimeHost.session).toBe(currentSession);
			expect(sessionManager.getSessionId()).toBe(currentSessionId);
			expect(sessionManager.getHeader()).toEqual(currentHeader);
			expect(sessionManager.getLeafId()).toBe(currentLeafId);
			expect(sessionManager.getEntries()).toEqual(currentEntries);
			expect(currentSession.messages).toEqual(currentMessages);
			expect(currentSession.extensionRunner.createContext().cwd).toBe(tempDir);
			expect(shutdownReasons).toEqual([]);
		};

		await expectForkCreationFailure("before");
		await expectForkCreationFailure("at");

		await currentSession.prompt("still usable after fork failure");
		expect(runtimeHost.session.messages.filter((message) => message.role === "assistant")).toHaveLength(3);
	});

	it("disposes a created candidate when teardown fails before apply", async () => {
		const { runtimeHost, createdSessions, tempDir } = await createRuntimeHost(() => {});
		const currentSession = runtimeHost.session;
		runtimeHost.setBeforeSessionInvalidate(() => {
			throw new Error("host teardown failed");
		});

		await expect(runtimeHost.newSession()).rejects.toThrow("host teardown failed");
		const candidate = createdSessions.at(-1);
		expect(candidate).toBeDefined();
		expect(candidate).not.toBe(currentSession);
		expect(runtimeHost.session).toBe(currentSession);
		expect(currentSession.extensionRunner.createContext().cwd).toBe(tempDir);
		expect(() => candidate!.extensionRunner.createContext().cwd).toThrow(
			"This extension ctx is stale after session replacement or reload",
		);

		runtimeHost.setBeforeSessionInvalidate(undefined);
		await currentSession.prompt("still usable after teardown failure");
		expect(runtimeHost.session.messages.some((message) => message.role === "assistant")).toBe(true);
	});

	it("emits session_before_fork and session_start and honors cancellation", async () => {
		const events: RecordedSessionEvent[] = [];
		let cancelNextFork = false;
		const { runtimeHost } = await createRuntimeHost((pi) => {
			pi.on("session_before_fork", (event) => {
				events.push(event);
				if (cancelNextFork) {
					cancelNextFork = false;
					return { cancel: true };
				}
			});
			pi.on("session_shutdown", (event) => {
				events.push(event);
			});
			pi.on("session_start", (event) => {
				events.push(event);
			});
		});

		expect(events).toEqual([{ type: "session_start", reason: "startup" }]);
		events.length = 0;

		await runtimeHost.session.prompt("hello");
		const userMessage = runtimeHost.session.getUserMessagesForForking()[0];
		const previousSessionFile = runtimeHost.session.sessionFile;

		const successResult = await runtimeHost.fork(userMessage.entryId);
		expect(successResult.cancelled).toBe(false);
		expect(successResult.selectedText).toBe("hello");
		await runtimeHost.session.bindExtensions({});
		expect(events).toEqual([
			{ type: "session_before_fork", entryId: userMessage.entryId, position: "before" },
			{ type: "session_shutdown", reason: "fork", targetSessionFile: runtimeHost.session.sessionFile },
			{ type: "session_start", reason: "fork", previousSessionFile },
		]);

		events.length = 0;
		cancelNextFork = true;
		const cancelResult = await runtimeHost.fork(userMessage.entryId);
		expect(cancelResult).toEqual({ cancelled: true });
		expect(events).toEqual([{ type: "session_before_fork", entryId: userMessage.entryId, position: "before" }]);

		events.length = 0;
		cancelNextFork = true;
		const cancelAtResult = await runtimeHost.fork("missing-entry", { position: "at" });
		expect(cancelAtResult).toEqual({ cancelled: true });
		expect(events).toEqual([{ type: "session_before_fork", entryId: "missing-entry", position: "at" }]);
	});
});
