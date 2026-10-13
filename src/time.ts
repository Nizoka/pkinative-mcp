/**
 * Instants: the `at` input of every verdict tool, `notBefore` / `notAfter`
 * of a certificate spec, `signingTime` of a CMS signature, and the operator
 * pin `PKINATIVE_MCP_AT` (the analogue of pdfnative-mcp's creation-date pin).
 *
 * Parsing is computed from the ISO 8601 fields — never through Date.parse,
 * whose leniency differs between engines (vendored from pkinative-cli
 * `src/utils/time.ts`). A date-time without a zone is read as UTC, so a
 * verdict never depends on the host's time zone; a date that does not exist
 * (2027-02-31) is refused, never rolled over.
 *
 * Resolution order when a tool's instant is omitted: `PKINATIVE_MCP_AT`
 * (reproducible by operator decision), else the wall clock (never cached).
 */
import { ToolError } from './errors.js';

/** The operator pin: an ISO 8601 instant every omitted `at` / `notBefore` / `signingTime` falls back to. */
export const AT_ENV = 'PKINATIVE_MCP_AT';

// YYYY-MM-DD, then optionally Thh:mm[:ss[.fraction]] and a zone (Z or ±hh[:]mm).
const ISO = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(\.\d{1,9})?)?(Z|([+-])(\d{2}):?(\d{2}))?)?$/i;

function daysIn(year: number, month: number): number {
    if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
    return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function fromFields(m: RegExpExecArray): number | undefined {
    const [year, month, day, hour, minute, second] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i] ?? '0')) as [number, number, number, number, number, number];
    const [zoneHours, zoneMinutes] = [Number(m[10] ?? '0'), Number(m[11] ?? '0')];
    if (month < 1 || month > 12 || day < 1 || day > daysIn(year, month) || hour > 23 || minute > 59 || second > 59 || zoneHours > 23 || zoneMinutes > 59) return undefined;
    const date = new Date(0);
    date.setUTCFullYear(year, month - 1, day);
    date.setUTCHours(hour, minute, second, Math.floor(Number(`0${m[7] ?? ''}`) * 1000));
    const offset = (m[9] === '-' ? -1 : 1) * (zoneHours * 60 + zoneMinutes) * 60_000;
    return date.getTime() - offset;
}

/** True when `raw` is an ISO 8601 date or date-time this module accepts (not `now`, not digits). */
export function isIsoInstant(raw: string): boolean {
    const m = ISO.exec(raw.trim());
    return m !== null && fromFields(m) !== undefined;
}

/**
 * Parse an instant input: epoch milliseconds (a number or digits), `'now'`,
 * or an ISO 8601 date or date-time. Throws `VALIDATION_ERROR` naming the input.
 */
export function parseInstant(raw: string | number, field: string, now: () => number = Date.now): number {
    if (typeof raw === 'number') {
        if (Number.isSafeInteger(raw)) return raw;
        throw new ToolError('VALIDATION_ERROR', `${field} must be a safe integer of epoch milliseconds, got ${raw}.`, { field });
    }
    const v = raw.trim();
    if (v === 'now') return now();
    if (/^\d+$/.test(v)) {
        const n = Number(v);
        if (Number.isSafeInteger(n)) return n;
    } else {
        const m = ISO.exec(v);
        const instant = m === null ? undefined : fromFields(m);
        if (instant !== undefined) return instant;
    }
    throw new ToolError('VALIDATION_ERROR', `${field} expects an ISO 8601 date-time (UTC unless zoned), epoch milliseconds or "now", got "${raw}".`, { field });
}

/** The operator pin, parsed, or `null` when unset. An invalid value throws (checked at boot by the CLI). */
export function readPinnedInstant(env: NodeJS.ProcessEnv = process.env): number | null {
    const raw = env[AT_ENV];
    if (raw === undefined || raw.trim() === '') return null;
    if (raw.trim() === 'now') throw new Error(`${AT_ENV} must be an ISO 8601 instant or epoch milliseconds, not "now".`);
    try {
        return parseInstant(raw, AT_ENV);
    } catch (err) {
        throw new Error(err instanceof ToolError ? err.message : String(err));
    }
}

export interface ResolvedInstant {
    /** The instant in epoch milliseconds. */
    readonly ms: number;
    /** Where it came from: an explicit input, the operator pin, or the wall clock. */
    readonly source: 'input' | 'pinned' | 'clock';
    /** ISO 8601 rendering (UTC) echoed in every report so a verdict can be reproduced. */
    readonly iso: string;
}

/**
 * Resolve a tool's instant input: an explicit value wins, then
 * `PKINATIVE_MCP_AT`, then the wall clock. `'now'` is the clock explicitly.
 */
export function resolveInstant(raw: string | number | undefined, field: string, now: () => number = Date.now): ResolvedInstant {
    if (raw !== undefined && raw !== 'now') {
        const ms = parseInstant(raw, field, now);
        return { ms, source: 'input', iso: formatInstant(ms) };
    }
    if (raw === undefined) {
        const pinned = readPinnedInstant();
        if (pinned !== null) return { ms: pinned, source: 'pinned', iso: formatInstant(pinned) };
    }
    const ms = now();
    return { ms, source: 'clock', iso: formatInstant(ms) };
}

/** True when a call's instant will come from the wall clock (and must therefore never be cached). */
export function isClockDependent(raw: string | number | undefined): boolean {
    if (raw === 'now') return true;
    if (raw !== undefined) return false;
    return readPinnedInstant() === null;
}

/** ISO 8601 rendering of an instant (UTC). */
export function formatInstant(ms: number): string {
    return new Date(ms).toISOString();
}

/** JSON Schema fragment for an instant input. */
export function instantSchema(description: string): { readonly type: 'string'; readonly minLength: 1; readonly description: string } {
    return { type: 'string', minLength: 1, description: `${description} An ISO 8601 date-time (UTC unless zoned; e.g. 2027-01-01T00:00:00Z), epoch milliseconds as digits, or 'now'. Omitted: PKINATIVE_MCP_AT when the operator pinned it, else the wall clock (a clock-dependent result is never cached).` } as const;
}
