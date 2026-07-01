/**
 * Foundational opt #253 — substituteArgs SINGLE-PASS substitution (MED CORRECTNESS).
 *
 * The old impl ran four sequential `String.replace` passes (`$N`, `${@:N}`,
 * `$ARGUMENTS`, `$@`). A value inserted by an earlier pass was re-scanned by a
 * later pass: `substituteArgs("$1", ["$@", "extra"])` → pass 1 turned `$1` into
 * the literal arg `$@`, then pass 4 (`$@`) re-expanded that into allArgs =
 * "$@ extra" — the user's literal "$@" arg became the joined arg list. Fix:
 * scan content once, append substituted values to result without re-scanning.
 */
import { describe, expect, it } from "vitest";
import { substituteArgs } from "../src/harness/prompt-templates.ts";

describe("substituteArgs single-pass (opt #253)", () => {
	it("does not re-expand a positional arg value containing $@", () => {
		// The crux: arg[0] is the literal string "$@". `$1` substitutes it in; the
		// old `$@` pass then re-expanded that literal into the joined arg list.
		expect(substituteArgs("$1", ["$@", "extra"])).toBe("$@");
	});

	it("does not re-expand a positional arg value containing $ARGUMENTS", () => {
		// arg[0] = "$ARGUMENTS extra". Old pass 3 (`$ARGUMENTS`) re-expanded the
		// inserted prefix into allArgs, producing "a b $ARGUMENTS extra"-style
		// corruption. Single-pass leaves the literal arg intact.
		expect(substituteArgs("$1", ["$ARGUMENTS", "x"])).toBe("$ARGUMENTS");
	});

	it("does not re-expand arg values across multiple placeholders", () => {
		// `$1`→"$@" then `$2`→"y" → "$@ and y". Old pass 4 re-expanded the "$@"
		// half → "$@ y and y". Single-pass preserves the literal.
		expect(substituteArgs("$1 and $2", ["$@", "y"])).toBe("$@ and y");
	});

	it("preserves ordinary substitution behavior (no regression)", () => {
		expect(substituteArgs("Test: $ARGUMENTS", ["a", "b", "c"])).toBe("Test: a b c");
		expect(substituteArgs("$@", ["a", "b"])).toBe("a b");
		expect(substituteArgs("$1: $2", ["x", "y"])).toBe("x: y");
		expect(substituteArgs(`\${@:2}`, ["a", "b", "c"])).toBe("b c");
		expect(substituteArgs(`\${@:2:1}`, ["a", "b", "c"])).toBe("b");
		// bash: $0 → $1 (start clamped to 0)
		expect(substituteArgs(`\${@:0}`, ["a", "b"])).toBe("a b");
		// missing positional arg → empty (placeholder consumed, bash-style)
		expect(substituteArgs("[$5]", ["a", "b"])).toBe("[]");
		expect(substituteArgs("price: $5 each", [])).toBe("price:  each");
		// non-matching ${...} preserved
		expect(substituteArgs(`\${FOO}`, ["a"])).toBe(`\${FOO}`);
		// lone "$" (not a placeholder) preserved
		expect(substituteArgs("cost: $ each", ["a"])).toBe("cost: $ each");
		// greedy digits
		expect(
			substituteArgs(
				"$12",
				Array.from({ length: 12 }, (_, k) => `v${k + 1}`),
			),
		).toBe("v12");
	});

	it("does not re-expand $@ inserted via slice substitution", () => {
		// `${@:1:1}` selects arg[0] = "$@". Old pass 4 re-expanded it. Single-pass
		// returns the literal slice.
		expect(substituteArgs(`\${@:1:1} done`, ["$@", "extra"])).toBe("$@ done");
	});
});
