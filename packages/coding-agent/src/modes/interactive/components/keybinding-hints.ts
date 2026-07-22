/** Interactive compatibility wrappers around the shared presentation helpers. */

import type { Keybinding } from "@pi-recon/repi-tui";
import {
	formatKeyText,
	keyDisplayText,
	keyText,
	themedKeyHint,
	themedRawKeyHint,
} from "../../../core/presentation/keybinding-hints.ts";
import { theme } from "../../../core/presentation/theme-runtime.ts";

export type { KeyTextFormatOptions } from "../../../core/presentation/keybinding-hints.ts";
export { formatKeyText, keyDisplayText, keyText };

export function keyHint(keybinding: Keybinding, description: string): string {
	return themedKeyHint(theme, keybinding, description);
}

export function rawKeyHint(key: string, description: string): string {
	return themedRawKeyHint(theme, key, description);
}
