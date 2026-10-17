/**
 * Hermetic process environment — side-effect module.
 *
 * Import this module FIRST, before anything that loads `src/` or `dist/`.
 * ES modules evaluate imports in source order, so a bare
 * `import './helpers/hermetic.js';` placed above the others runs before them.
 *
 * 1. `TZ=UTC` (see ./tz.ts).
 * 2. Every operator knob inherited from the parent shell is removed. The
 *    server reads `PKINATIVE_MCP_*` at boot or per call (the output sandbox,
 *    the response cache, the HTTP port and token, the operator password, the
 *    instant pin, the three ceilings); a developer's shell must not change
 *    the bytes a script produces, open a cache, or hand a password to a
 *    corpus run.
 *
 * Scripts that want a pin set it explicitly after this import
 * (`PKINATIVE_MCP_AT`, `PKINATIVE_MCP_OUTPUT_DIR` — see ./io.ts).
 */
import './tz.js';

/** The prefix of every variable the server reads. */
export const OPERATOR_PREFIX = 'PKINATIVE_MCP_';

/** True for a variable the server would read at boot or per call. */
export function isOperatorKnob(name: string): boolean {
    return name.startsWith(OPERATOR_PREFIX);
}

/** Remove every operator knob from `env` in place; returns the removed names. */
export function scrubEnv(env: NodeJS.ProcessEnv): string[] {
    const removed: string[] = [];
    for (const key of Object.keys(env)) {
        if (isOperatorKnob(key)) {
            Reflect.deleteProperty(env, key);
            removed.push(key);
        }
    }
    return removed;
}

scrubEnv(process.env);
process.env.NO_COLOR = '1';
process.env.FORCE_COLOR = '0';
