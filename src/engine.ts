/**
 * Engine identity and runtime capability probes.
 *
 * pkinative exports no `VERSION` constant and needs no initialisation: the
 * version is read from its `package.json` (exposed through the engine's
 * exports map) exactly as pkinative-cli does, and the three Web Crypto
 * probes (`canVerify`, `canSign`, `canDecrypt`) tell whether this host can
 * verify, sign and open keys at all. `ensureEngineReady()` is kept for
 * symmetry with the sibling servers (a memoised no-op that resolves the
 * version once).
 */
import { createRequire } from 'node:module';

import { canDecrypt, canSign, canVerify } from 'pkinative';

const require = createRequire(import.meta.url);

/** The installed pkinative version (from its package.json). */
export const PKINATIVE_VERSION: string = (require('pkinative/package.json') as { version: string }).version;

/** The engine's Node floor (CVE-2026-21713: variable-time PKCS#12 MAC compare below it). */
export const PKINATIVE_NODE_FLOOR = '^22.22.2 || ^24.14.1 || >=25.8.2';

let _ready: Promise<void> | null = null;

/** Resolve once; safe to call repeatedly. */
export function ensureEngineReady(): Promise<void> {
    if (_ready === null) _ready = Promise.resolve();
    return _ready;
}

export interface RuntimeCapabilities {
    /** Web Crypto can verify signatures on this host. */
    readonly canVerify: boolean;
    /** Web Crypto can sign (ECDSA / RSA / Ed25519 / Ed448 as the host supports). */
    readonly canSign: boolean;
    /** Web Crypto can derive and decrypt (PBES2 keys, PKCS#12). */
    readonly canDecrypt: boolean;
    /** Node.js version in use. */
    readonly node: string;
    /** Whether the running Node satisfies the engine's security floor. */
    readonly nodeFloorSatisfied: boolean;
    readonly platform: string;
}

/** True when `version` (e.g. 22.23.2) satisfies the engine floor ranges. */
export function satisfiesNodeFloor(version: string): boolean {
    const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
    if (m === null) return false;
    const [major, minor, patch] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const atLeast = (a: number, b: number, c: number): boolean => major > a || (major === a && (minor > b || (minor === b && patch >= c)));
    if (major === 22) return atLeast(22, 22, 2);
    if (major === 24) return atLeast(24, 14, 1);
    if (major >= 25) return atLeast(25, 8, 2);
    return false;
}

/** Probe what the current runtime offers (synchronous, no side effects). */
export function probeRuntime(): RuntimeCapabilities {
    return {
        canVerify: canVerify(),
        canSign: canSign(),
        canDecrypt: canDecrypt(),
        node: process.version,
        nodeFloorSatisfied: satisfiesNodeFloor(process.version),
        platform: process.platform,
    };
}
