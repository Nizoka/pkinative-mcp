/**
 * Pin the process timezone to UTC — side-effect module.
 *
 * Every verdict depends on an instant (`at`, validity windows, CRL
 * freshness) and the scripts format instants themselves when they report.
 * A pinned `PKINATIVE_MCP_AT` is not enough on its own: a script that
 * renders a date with the host calendar would still differ between Paris and
 * a UTC CI runner, so the zone is pinned here, as vitest.config.ts pins it
 * for the test suite.
 *
 * Import this module FIRST, before anything that formats a date. ES modules
 * evaluate imports in source order, so a bare `import './helpers/tz.js';`
 * placed above the others runs before them.
 *
 * `process.env.TZ` has been honoured at runtime on every platform since
 * Node 16.2; the project's engine floor is Node 22.
 */
process.env.TZ = 'UTC';
