import { defineConfig } from 'vitest/config';

/**
 * Reporters are chosen for token-cheap output: `dot` prints one character
 * per test instead of one line per file, and `github-actions` adds inline
 * annotations on CI only. When `scripts/gate.ts` drives the run (GATE=1) a
 * JSON report is written as well, which is where the gate reads the test
 * count from; nothing else needs the file, so it is not produced otherwise.
 */
const reporters: Array<'dot' | 'github-actions' | ['json', { outputFile: string }]> = ['dot'];
if (process.env.GITHUB_ACTIONS) reporters.push('github-actions');
if (process.env.GATE === '1') reporters.push(['json', { outputFile: 'test-output/.gate/vitest.json' }]);

export default defineConfig({
    test: {
        include: ['tests/**/*.test.ts'],
        environment: 'node',
        globals: false,
        reporters,
        // Every verdict depends on an instant (`at`, validity windows, CRL
        // freshness) and tests format instants themselves. Pinning the zone
        // makes the suite machine-independent; scripts/helpers/hermetic.ts
        // does the same for the sample generator.
        env: { TZ: 'UTC' },
        // Process isolation: a test that leaks a global, a timer, an env var
        // (PKINATIVE_MCP_*) or the process-wide ceilings cannot influence the
        // next file's outcome.
        pool: 'forks',
        // Determinism: the same ordering on every machine, so a failure seen
        // in CI reproduces locally without a seed.
        sequence: { shuffle: false },
        // PBKDF2 at the engine's default iteration bound and RSA-PSS signing
        // under v8 coverage instrumentation can exceed the 5 s default.
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            // Excluded from coverage thresholds:
            //   - cli.ts    process entry point (transport wiring, signal
            //               handling); the gate's `smoke` step and
            //               tests/cli-stdio.test.ts drive the built binary
            //   - index.ts  re-exports only, no logic of its own
            exclude: [
                'src/cli.ts',
                'src/index.ts',
            ],
            reporter: ['text-summary', 'json-summary', 'html'],
            thresholds: {
                // Thresholds sit about 4 points below the values measured on the
                // release tree so a regression fails CI while ordinary churn does
                // not. Never lower these; raise them when a release lifts coverage.
                statements: 94,
                branches: 90,
                functions: 95,
                lines: 94,
            },
        },
    },
});
