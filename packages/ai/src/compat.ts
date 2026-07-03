/**
 * Compatibility surface for upstream pi extensions that import
 * `@earendil-works/pi-ai/compat`.
 *
 * REPI's current AI package already exposes the old compat primitives
 * (`complete`, `stream`, `StringEnum`, `Model`, `Message`, etc.) from the root
 * module. Keeping this explicit subpath lets pi 0.79+ extension packages load
 * unchanged through the REPI extension loader aliases.
 */
export * from "./index.ts";
