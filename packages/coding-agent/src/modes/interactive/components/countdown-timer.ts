/**
 * Reusable countdown timer for dialog components.
 */

import type { TUI } from "@pi-recon/repi-tui";

export class CountdownTimer {
	private intervalId: ReturnType<typeof setInterval> | undefined;
	private remainingSeconds: number;
	private tui: TUI | undefined;
	private onTick: (seconds: number) => void;
	private onExpire: () => void;

	constructor(timeoutMs: number, tui: TUI | undefined, onTick: (seconds: number) => void, onExpire: () => void) {
		this.tui = tui;
		this.onTick = onTick;
		this.onExpire = onExpire;
		this.remainingSeconds = Math.ceil(timeoutMs / 1000);
		this.onTick(this.remainingSeconds);

		this.intervalId = setInterval(() => {
			this.remainingSeconds--;
			this.onTick(this.remainingSeconds);
			this.tui?.requestRender();

			if (this.remainingSeconds <= 0) {
				this.dispose();
				this.onExpire();
			}
		}, 1000);
		// Defense-in-depth (opt #143): an undisposed countdown interval would
		// keep the event loop alive + fire onTick/requestRender on a detached
		// retry UI. unref() so a leaked interval never blocks process exit.
		this.intervalId.unref();
	}

	dispose(): void {
		if (this.intervalId) {
			clearInterval(this.intervalId);
			this.intervalId = undefined;
		}
	}
}
