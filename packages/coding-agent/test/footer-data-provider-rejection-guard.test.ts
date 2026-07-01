import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FooterDataProvider } from "../src/core/footer-data-provider.ts";

// Regression guard for opt #53: FooterDataProvider's background git-branch refresh is
// fire-and-forget. `scheduleRefresh`'s debounce timer does `void this.refreshGitBranchAsync()`
// (footer-data-provider.ts:209) — the `void` drops the returned promise. refreshGitBranchAsync
// had a try/finally with NO catch, and notifyBranchChange (called inside the try block when the
// branch changes) iterated `branchChangeCallbacks` calling each `cb()` with no per-callback guard.
// A single throwing branch-change callback (a misbehaving TUI component / extension consumer),
// or any unexpected throw in the try block, rejected the promise → the `void` caller dropped it
// → `unhandledRejection` → process crash. There is NO global unhandledRejection handler, so the
// rejection is fatal — a bad footer callback could take down the whole agent.
//
// opt #53 fixes both layers: notifyBranchChange guards each callback (swallow + continue), and
// refreshGitBranchAsync adds a catch (swallow; finally still drains the refresh queue). The two
// fixes are deliberately redundant (defense-in-depth), so each is pinned by its OWN test below
// and an integration test repros the real crash scenario with both in place.

// FooterDataProvider's private methods are accessed via bracket notation — they are the units
// under test. `any` is intentional: the public API has no hook to force a refresh or a throwing
// callback path deterministically without watcher timing flakiness.
type ProviderLike = {
	notifyBranchChange: () => void;
	refreshGitBranchAsync: () => Promise<void>;
	resolveGitBranchAsync: () => Promise<string | null>;
	refreshInFlight: boolean;
	cachedBranch: string | null | undefined;
};

describe("footer-data-provider fire-and-forget rejection guards (opt #53)", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "repi-footer-guard-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
	});

	it("notifyBranchChange swallows a throwing callback and still runs sibling callbacks", () => {
		// Construct in a non-git dir: findGitPaths returns null, setupGitWatcher early-returns.
		const provider = new FooterDataProvider(tempDir) as unknown as ProviderLike;
		let goodCallbackRan = false;
		provider; // satisfy noUnusedExpressions-style lints via reference
		const unsubscribeBad = (provider as unknown as { onBranchChange: (cb: () => void) => () => void }).onBranchChange(
			() => {
				throw new Error("callback-boom");
			},
		);
		const unsubscribeGood = (
			provider as unknown as { onBranchChange: (cb: () => void) => () => void }
		).onBranchChange(() => {
			goodCallbackRan = true;
		});

		// Pre-fix: `for (const cb of set) cb()` — the first (throwing) callback aborts the loop
		// and the throw propagates out of notifyBranchChange → refreshGitBranchAsync's try block
		// → rejection. Post-fix: per-callback try/catch swallows the bad one, the good one runs.
		expect(() => provider.notifyBranchChange()).not.toThrow();
		expect(goodCallbackRan).toBe(true);

		unsubscribeBad();
		unsubscribeGood();
	});

	it("refreshGitBranchAsync swallows a throw from resolveGitBranchAsync (no rejection) and releases refreshInFlight", async () => {
		const provider = new FooterDataProvider(tempDir) as unknown as ProviderLike;
		// Force the try block to throw from the awaited call (bypassing notifyBranchChange's
		// guard entirely) — this pins the catch in refreshGitBranchAsync independently of the
		// notifyBranchChange guard. Pre-fix (try/finally, no catch): awaiting rejects.
		provider.resolveGitBranchAsync = async () => {
			throw new Error("resolve-boom");
		};

		// Must NOT reject — the catch swallows; the finally releases refreshInFlight so the
		// footer recovers on the next watcher tick instead of crashing the agent.
		await expect(provider.refreshGitBranchAsync()).resolves.toBeUndefined();
		expect(provider.refreshInFlight).toBe(false);
	});

	it("refreshGitBranchAsync does not reject on a real branch change when a callback throws (integration repro)", async () => {
		// Minimal real git repo so resolveGitBranchAsync reads HEAD and returns a branch.
		const repoDir = join(tempDir, "repo");
		const gitDir = join(repoDir, ".git");
		mkdirSync(gitDir, { recursive: true });
		const headPath = join(gitDir, "HEAD");
		writeFileSync(headPath, "ref: refs/heads/main\n", "utf-8");

		const provider = new FooterDataProvider(repoDir) as unknown as ProviderLike;
		// Prime the cache so the next refresh sees a CHANGE (cachedBranch !== undefined && !==
		// next) and fires notifyBranchChange — the exact path that reaches the throwing callback.
		provider.cachedBranch = "main";

		(provider as unknown as { onBranchChange: (cb: () => void) => () => void }).onBranchChange(() => {
			throw new Error("branch-change-boom");
		});

		// Switch the branch so resolveGitBranchAsync returns "feature" ≠ cached "main".
		writeFileSync(headPath, "ref: refs/heads/feature\n", "utf-8");

		// Pre-fix: refreshGitBranchAsync's try block calls notifyBranchChange → the throwing
		// callback rejects the promise → the production `void` caller drops it →
		// unhandledRejection → crash. Here we await to observe the rejection deterministically.
		// Post-fix (both layers): resolves cleanly, cache updated to the new branch.
		await expect(provider.refreshGitBranchAsync()).resolves.toBeUndefined();
		expect(provider.cachedBranch).toBe("feature");
		expect(provider.refreshInFlight).toBe(false);
	});
});
