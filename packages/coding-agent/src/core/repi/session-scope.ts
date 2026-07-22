import { AsyncLocalStorage } from "node:async_hooks";

type MissionSessionScope = string | null;

const scopeStorage = new AsyncLocalStorage<MissionSessionScope>();

/**
 * Run work with an explicit mission session binding. `null` is meaningful: it
 * represents an in-memory/no-session runtime and must not fall back to a
 * process-wide environment value from another caller.
 */
export function runMissionSessionScope<T>(sessionFile: string | undefined, callback: () => T): T {
	return scopeStorage.run(sessionFile?.trim() || null, callback);
}

/** Return the binding visible to the current async execution context. */
export function missionSessionScopeContext(): { bound: boolean; sessionFile?: string } {
	const scoped = scopeStorage.getStore();
	if (scoped !== undefined) return scoped ? { bound: true, sessionFile: scoped } : { bound: true };
	const fromEnvironment = process.env.REPI_MISSION_SESSION_SCOPE?.trim();
	return fromEnvironment ? { bound: false, sessionFile: fromEnvironment } : { bound: false };
}

/** Return the session file for mission path derivation. */
export function currentMissionSessionScope(): string | undefined {
	return missionSessionScopeContext().sessionFile;
}

/** Propagate an explicit async-local binding to a child process environment. */
export function missionScopedEnvironment(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const env = { ...base };
	const scope = missionSessionScopeContext();
	if (!scope.bound) return env;
	if (scope.sessionFile) env.REPI_MISSION_SESSION_SCOPE = scope.sessionFile;
	else delete env.REPI_MISSION_SESSION_SCOPE;
	return env;
}
