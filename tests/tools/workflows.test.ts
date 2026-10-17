import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// ── Workflow, supply-chain and contributor invariants ─────────────────
//
// None of this is visible to the type checker or to the test suite proper:
// a floating action tag, a checkout that keeps the job token, a release job
// that quietly skips OpenSSL, an npm client that drifts between two publishes.
// Each is locked here as a plain-text assertion on the files that carry it.
// Ported from pdfnative-mcp 1.7.0 (tests/tools/workflows.test.ts), with the
// OpenSSL interoperability workflow this repository keeps instead of veraPDF.

const ROOT = process.cwd();
const WORKFLOWS = join(ROOT, '.github', 'workflows');
const workflowFiles = readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml')).sort();
// Every tracked text blob is LF (.gitattributes eol=lf), but a working copy
// may still be CRLF on Windows; normalise so the regexes below see one line ending.
const readWorkflow = (f: string): string => readFileSync(join(WORKFLOWS, f), 'utf8').replace(/\r\n/g, '\n');
const readText = (...parts: string[]): string => readFileSync(join(ROOT, ...parts), 'utf8').replace(/\r\n/g, '\n');
/** Escape every regular-expression metacharacter, backslash included, of a literal. */
const escapeRegExp = (s: string): string => s.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');

const HARDEN_RUNNER = 'step-security/harden-runner@';

/** The seven contexts the main ruleset requires, in ruleset order. */
const REQUIRED_CHECKS = ['ci (22)', 'ci (24)', 'os (windows-latest)', 'os (macos-latest)', 'sample-regression', 'interop (ubuntu-24.04)', 'interop (windows-latest)'];

/** Every `- name:`/`- uses:` step block of every job, in order, keyed by job id. */
function jobSteps(text: string): Map<string, string[]> {
    const jobs = new Map<string, string[]>();
    const jobsAt = text.search(/^jobs:\s*$/m);
    if (jobsAt < 0) return jobs;
    let job: string | null = null;
    let steps: string[] | null = null;
    for (const line of text.slice(jobsAt).split('\n').slice(1)) {
        const jobHead = /^  ([A-Za-z0-9_-]+):\s*$/.exec(line);
        if (jobHead) { job = jobHead[1]; steps = null; continue; }
        if (/^    steps:\s*$/.test(line) && job) { steps = []; jobs.set(job, steps); continue; }
        if (steps === null) continue;
        if (/^      - /.test(line)) steps.push(line);
        else if (/^ {8,}\S/.test(line) && steps.length > 0) steps[steps.length - 1] += `\n${line}`;
    }
    return jobs;
}

function requiredContexts(): string[] {
    const ruleset = JSON.parse(readText('.github', 'rulesets', 'main.json')) as {
        rules: Array<{ type: string; parameters?: { required_status_checks?: Array<{ context: string }> } }>;
    };
    return ruleset.rules.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks?.map((c) => c.context) ?? [];
}

// ── Actions: pinned, hardened, credential-free ───────────────────────

describe('every workflow', () => {
    const allFiles = workflowFiles.map((f) => ({ label: f, text: readWorkflow(f) }));

    it('is the expected set of workflows', () => {
        expect(workflowFiles).toEqual([
            'audit.yml', 'ci.yml', 'codeql.yml', 'dependency-review.yml', 'docs.yml', 'interop.yml',
            'node-current.yml', 'publish.yml', 'sample-regression.yml', 'scorecard.yml',
        ]);
    });

    it('pins every action to a 40-hex commit SHA with a version comment', () => {
        for (const { label, text } of allFiles) {
            const uses = [...text.matchAll(/^\s*(?:- )?uses:\s*(\S+)[^\n]*$/gm)];
            expect(uses.length, `${label} declares no action`).toBeGreaterThan(0);
            for (const m of uses) {
                const ref = m[1];
                expect(ref, `${label}: ${ref}`).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
                expect(m[0], `${label}: ${ref} lacks a "# vX.Y.Z" comment`).toMatch(/#\s*v\d+\.\d+\.\d+\s*$/);
            }
        }
    });

    it('pins each action to ONE SHA across the tree (no version drift between workflows)', () => {
        const pins = new Map<string, Set<string>>();
        for (const { text } of allFiles) {
            for (const m of text.matchAll(/uses:\s*([^@\s]+)@([0-9a-f]{40})/g)) {
                // github/codeql-action/{init,autobuild,analyze,upload-sarif} share one release.
                const action = m[1].startsWith('github/codeql-action/') ? 'github/codeql-action' : m[1];
                const set = pins.get(action) ?? new Set<string>();
                set.add(m[2]);
                pins.set(action, set);
            }
        }
        for (const [action, shas] of pins) expect([...shas], action).toHaveLength(1);
    });

    it('every actions/checkout step disables persist-credentials', () => {
        for (const { label, text } of allFiles) {
            const re = /uses: actions\/checkout@[^\n]*\n((?:[ \t]+[^\n]*\n)*)/g;
            let m: RegExpExecArray | null;
            while ((m = re.exec(text)) !== null) {
                const block = m[1].split('\n').filter((l) => l.trim() !== '' && !/^\s+- /.test(l));
                expect(block.some((l) => /persist-credentials:\s*false/.test(l)), `${label}: checkout keeps credentials`).toBe(true);
            }
        }
    });

    it('declares top-level permissions with contents: read (or read-all)', () => {
        for (const { label, text } of allFiles) {
            expect(text, `${label}: permissions`).toMatch(/^permissions:(?:\s*read-all\s*$|\s*\n(?:  [a-z-]+:\s*\w+\s*\n)*  contents:\s*read\s*$)/m);
        }
    });
});

describe('every workflow job', () => {
    it('starts with harden-runner in audit mode (skipped on macOS only, by condition)', () => {
        for (const f of workflowFiles) {
            const jobs = jobSteps(readWorkflow(f));
            expect(jobs.size, `${f}: no job with steps`).toBeGreaterThan(0);
            for (const [job, steps] of jobs) {
                expect(steps[0], `${f} › ${job}: first step`).toContain(HARDEN_RUNNER);
                expect(steps[0], `${f} › ${job}: egress policy`).toMatch(/egress-policy:\s*audit/);
                const conditional = /if:\s*runner\.os != 'macOS'/.test(steps[0]);
                const hasMacLeg = /macos-latest/.test(readWorkflow(f));
                expect(conditional, `${f} › ${job}: harden-runner is conditional only on a job with a macOS leg`).toBe(conditional ? hasMacLeg : false);
            }
        }
    });

    it('installs dependencies with --ignore-scripts', () => {
        for (const f of workflowFiles) {
            for (const m of readWorkflow(f).matchAll(/run: npm ci\b[^\n]*/g)) {
                expect(m[0], `${f}`).toContain('npm ci --ignore-scripts');
            }
        }
    });

    it('declares permissions, a timeout and (except publish) a cancelling concurrency group', () => {
        for (const f of workflowFiles) {
            const text = readWorkflow(f);
            expect(text, `${f}: permissions`).toMatch(/^permissions:/m);
            expect(text, `${f}: timeout`).toMatch(/timeout-minutes:\s*\d+/);
            if (f === 'publish.yml') continue;
            if (['audit.yml', 'dependency-review.yml'].includes(f)) continue; // single short job, no cancel needed
            expect(text, `${f}: concurrency`).toMatch(/concurrency:\s*\n\s*group:[^\n]+\n\s*cancel-in-progress:\s*true/);
        }
    });

    it('requires the OpenSSL interoperability suite wherever the gate runs', () => {
        for (const f of workflowFiles) {
            const text = readWorkflow(f);
            if (!/scripts\/gate\.ts --(?:ci|publish) --require-all/.test(text)) continue;
            expect(text, `${f}: PKINATIVE_INTEROP_REQUIRED`).toMatch(/PKINATIVE_INTEROP_REQUIRED:\s*'1'/);
            expect(text, `${f}: openssl version recorded`).toMatch(/run: openssl version/);
        }
    });
});

// ── The gate is the only definition of green ─────────────────────────

describe('ci.yml', () => {
    const ci = readWorkflow('ci.yml');

    it('keeps the job id and matrix the ruleset requires (ci (22), ci (24))', () => {
        expect(ci).toMatch(/^  ci:\s*$/m);
        expect(ci).toMatch(/node-version:\s*\[22, 24\]/);
        expect(requiredContexts()).toEqual(REQUIRED_CHECKS);
    });

    it('runs the gate with --require-all and audits outside it', () => {
        expect(ci).toMatch(/run: npx tsx scripts\/gate\.ts --ci --require-all/);
        expect(ci).toMatch(/run: npm audit --audit-level=high/);
        expect(ci).toMatch(/if: failure\(\)[\s\S]*upload-artifact[\s\S]*test-output\/\.gate\//);
    });

    it('lists no gate step by hand', () => {
        // The `ci` job; the `os` job is held to the same rule in the next describe.
        const gated = (jobSteps(ci).get('ci') ?? []).join('\n');
        expect(gated).toContain('scripts/gate.ts');
        for (const step of ['typecheck:all', 'test:coverage', 'validate:pki', 'corpus:pki', 'test:interop', 'verify:samples', 'verify:docs', 'npm run build', 'npm run lint', 'node dist/cli.js']) {
            expect(gated, step).not.toMatch(new RegExp(`run: (npm run )?${escapeRegExp(step)}\\s*$`, 'm'));
        }
    });
});

describe('ci.yml os matrix job (Windows and macOS)', () => {
    const ci = readWorkflow('ci.yml');
    const steps = jobSteps(ci).get('os') ?? [];
    const index = (needle: string): number => steps.findIndex((s) => s.includes(needle));

    it('runs the same gate on windows-latest and macos-latest from the pinned Node line, as required checks', () => {
        expect(ci).toMatch(/^  os:\s*\n\s*runs-on:\s*\$\{\{ matrix\.os \}\}/m);
        expect(ci).toMatch(/os:\s*\[windows-latest, macos-latest\]/);
        expect(steps.some((s) => /node-version-file:\s*\.nvmrc/.test(s)), 'setup-node reads .nvmrc').toBe(true);
        expect(index('run: npm ci --ignore-scripts')).toBeGreaterThanOrEqual(0);
        expect(index('run: npx tsx scripts/gate.ts --ci --require-all')).toBeGreaterThan(index('run: npm ci --ignore-scripts'));
        expect(steps.some((s) => /if: failure\(\)[\s\S]*upload-artifact[\s\S]*test-output\/\.gate\//.test(s)), 'gate logs uploaded on failure').toBe(true);
        expect(steps.join('\n')).not.toMatch(/run: npm (test|run build)\s*$/m); // the gate, never a hand-written subset
        const ruleset = readText('.github', 'rulesets', 'main.json');
        expect(ruleset).toContain('"os (windows-latest)"');
        expect(ruleset).toContain('"os (macos-latest)"');
    });

    it('exposes OpenSSL 3 before recording its version: Git for Windows on Windows, Homebrew on macOS', () => {
        const windows = steps.findIndex((s) => /if: runner\.os == 'Windows'/.test(s) && /GITHUB_PATH/.test(s));
        const macos = steps.findIndex((s) => /if: runner\.os == 'macOS'/.test(s) && /GITHUB_PATH/.test(s));
        expect(windows, 'Windows exposure step').toBeGreaterThanOrEqual(0);
        expect(macos, 'macOS exposure step').toBeGreaterThanOrEqual(0);
        expect(steps[windows]).toMatch(/shell: pwsh/);
        expect(steps[windows]).toContain('C:\\Program Files\\Git\\usr\\bin');
        expect(steps[macos]).toMatch(/shell: bash/);
        expect(steps[macos]).toMatch(/brew --prefix openssl@3/);
        const version = index('run: openssl version');
        expect(version).toBeGreaterThan(Math.max(windows, macos));
        expect(version).toBeLessThan(index('run: npx tsx scripts/gate.ts --ci --require-all'));
    });

    it('skips harden-runner on macOS only (the action supports Linux, and Windows in audit mode) and says so', () => {
        expect(steps[0]).toContain(HARDEN_RUNNER);
        expect(steps[0]).toMatch(/if: runner\.os != 'macOS'/);
        expect(ci).toMatch(/harden-runner supports Windows runners in audit mode only/);
        expect(ci).toMatch(/does not support\s+# macOS at all/);
    });
});

// ── OpenSSL: the external judge, on four images ──────────────────────

describe('interop.yml', () => {
    const wf = readWorkflow('interop.yml');
    const steps = jobSteps(wf).get('interop') ?? [];
    const index = (needle: string | RegExp): number => steps.findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));

    it('runs on push, pull request, a weekly schedule and on demand, with no paths filter', () => {
        expect(wf).toMatch(/^on:\s*\n\s*push:\s*\n\s*branches:[^\n]*\n\s*pull_request:/m);
        expect(wf).toMatch(/schedule:\s*\n\s*- cron:/);
        expect(wf).toMatch(/workflow_dispatch:/);
        expect(wf).not.toMatch(/^\s*paths(-ignore)?:/m);
    });

    it('is the `interop` job over four images, two of which are required checks', () => {
        expect(wf).toMatch(/^  interop:\s*\n\s*runs-on:\s*\$\{\{ matrix\.os \}\}/m);
        expect(wf).toMatch(/os:\s*\[ubuntu-22\.04, ubuntu-24\.04, windows-latest, macos-latest\]/);
        expect(wf).not.toMatch(/^    name:/m); // the default `interop (<os>)` context names
        const contexts = requiredContexts();
        expect(contexts).toContain('interop (ubuntu-24.04)');
        expect(contexts).toContain('interop (windows-latest)');
        expect(contexts).not.toContain('interop (ubuntu-22.04)');
        expect(contexts).not.toContain('interop (macos-latest)');
    });

    it('exposes OpenSSL, records the versions, builds, generates the corpus, validates and runs the suite in order', () => {
        const order = [
            index(/if: runner\.os == 'Windows'[\s\S]*GITHUB_PATH/),
            index(/if: runner\.os == 'macOS'[\s\S]*GITHUB_PATH/),
            index('Record tool versions'),
            index('run: npm ci --ignore-scripts'),
            index('run: npm run build'),
            index('run: npm run corpus:pki'),
            index('npm run validate:pki'),
            index('run: npm run test:interop'),
        ];
        expect(order.every((i) => i >= 0), `steps: ${order.join(',')}`).toBe(true);
        for (let i = 1; i < order.length; i++) expect(order[i], `step ${i}`).toBeGreaterThan(order[i - 1]);
        expect(wf).toMatch(/PKINATIVE_INTEROP_REQUIRED:\s*'1'/);
        expect(steps[index('Record tool versions')]).toMatch(/openssl version/);
        expect(steps[index('Record tool versions')]).toMatch(/GITHUB_STEP_SUMMARY/);
    });

    it('uploads the manifest and the reports always, and writes a verdict summary', () => {
        const upload = steps[index('upload-artifact')];
        expect(upload).toMatch(/if: always\(\)/);
        expect(upload).toContain('test-output/pki/manifest.json');
        expect(upload).toContain('test-output/pki/reports/');
        const summary = steps[index('Job summary')];
        expect(summary).toMatch(/if: always\(\)/);
        expect(summary).toMatch(/GITHUB_STEP_SUMMARY/);
        expect(summary).toMatch(/INFRA/);
        expect(wf).not.toMatch(/^\s*continue-on-error:/m);
    });
});

describe('publish.yml', () => {
    const publish = readWorkflow('publish.yml');
    const jobs = jobSteps(publish);

    it('mints an OIDC token and never reads an NPM_TOKEN secret', () => {
        expect(publish).toMatch(/^\s*id-token:\s*write/m);
        expect(publish).not.toMatch(/secrets\.NPM_TOKEN/);
    });

    it('publishes from the npm-publish environment, one release at a time', () => {
        expect(publish).toMatch(/^\s*environment:\s*npm-publish\s*$/m);
        expect(publish).toMatch(/concurrency:\s*\n\s*group:\s*publish\s*\n\s*cancel-in-progress:\s*false/);
    });

    it('pins the npm client to one exact 11.x release, at least 11.5.1, before publishing', () => {
        const pins = [...publish.matchAll(/npm install -g npm@(\S+)/g)].map((m) => m[1]);
        expect(pins).toHaveLength(1);
        expect(pins[0]).toMatch(/^\d+\.\d+\.\d+$/);
        const [major, minor, patch] = pins[0].split('.').map(Number);
        expect(major === 11 && (minor > 5 || (minor === 5 && patch >= 1))).toBe(true);
        expect(publish).toContain(`test "$(npm --version)" = "${pins[0]}"`);
        expect(publish.indexOf('npm install -g npm@')).toBeLessThan(publish.indexOf('run: npm publish'));
    });

    it('builds on the .nvmrc Node line and publishes with provenance', () => {
        expect(publish).toMatch(/node-version-file:\s*\.nvmrc/);
        expect(publish).not.toMatch(/node-version:\s*'>=/);
        expect(publish).toMatch(/run: npm publish --provenance --access public\s*$/m);
        expect(publish).toMatch(/run: npm pack --dry-run/);
    });

    it('verifies the tag against package.json', () => {
        expect(publish).toMatch(/does not match package\.json version/);
    });

    it('runs the publish gate with --require-all after OpenSSL and the linters, and lists no gate step by hand', () => {
        const steps = jobs.get('publish') ?? [];
        const index = (needle: string | RegExp): number => steps.findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));
        const openssl = index('run: openssl version');
        const zlint = index('Install zlint');
        const pkilint = index('Install pkilint');
        const gate = index('run: npx tsx scripts/gate.ts --publish --require-all');
        const pack = index('run: npm pack --dry-run');
        const pub = index(/run: npm publish/);
        expect([openssl, zlint, pkilint, gate, pack, pub].every((i) => i >= 0)).toBe(true);
        expect(openssl).toBeLessThan(gate);
        expect(zlint).toBeLessThan(gate);
        expect(pkilint).toBeLessThan(gate);
        expect(gate).toBeLessThan(pack);
        expect(pack).toBeLessThan(pub);
        expect(steps[gate]).toMatch(/PKINATIVE_INTEROP_REQUIRED:\s*'1'/);
        for (const hand of ['npm run validate:pki', 'npm run corpus:pki', 'npm run test:interop', 'npm run verify:samples', 'npm run test:coverage', 'npm run typecheck:all', 'npm run verify:tool-shape']) {
            expect(publish, hand).not.toContain(`run: ${hand}`);
        }
    });

    it('pins zlint by archive SHA-256 and pkilint by --require-hashes, both conditional on the requirements file, as is REQUIRE_LINT', () => {
        const steps = jobs.get('publish') ?? [];
        const zlint = steps.find((s) => s.includes('Install zlint')) ?? '';
        expect(zlint).toMatch(/ZLINT_SHA256:\s*[0-9a-f]{64}/);
        expect(zlint).toMatch(/sha256sum --check --strict/);
        expect(zlint).toMatch(/--proto '=https'/);
        expect(zlint).toMatch(/if: steps\.lint\.outputs\.available == 'true'/);
        const pkilint = steps.find((s) => s.includes('Install pkilint')) ?? '';
        expect(pkilint).toMatch(/--require-hashes --no-deps --only-binary :all:/);
        expect(pkilint).toContain('scripts/data/lint-python-requirements.txt');
        expect(pkilint).toMatch(/if: steps\.lint\.outputs\.available == 'true'/);
        const gate = steps.find((s) => s.includes('scripts/gate.ts --publish')) ?? '';
        expect(gate).toMatch(/REQUIRE_LINT:\s*\$\{\{ steps\.lint\.outputs\.available == 'true' && '1' \|\| '' \}\}/);
    });

    it('has an attest job with exactly three permissions that attests the tarball and the SBOM', () => {
        const attest = /^  attest:\s*\n([\s\S]*?)(?=^  [a-z-]+:\s*$|(?![\s\S]))/m.exec(publish);
        expect(attest).not.toBeNull();
        const body = attest![1];
        expect(body).toMatch(/needs:\s*publish/);
        const perms = /permissions:\s*\n((?:\s{6}[a-z-]+:\s*\w+\s*\n)+)/.exec(body);
        expect(perms).not.toBeNull();
        const granted = perms![1].trim().split('\n').map((l) => l.trim()).sort();
        expect(granted).toEqual(['attestations: write', 'contents: write', 'id-token: write']);
        expect(body).toMatch(/npm sbom --sbom-format cyclonedx --omit dev --package-lock-only/);
        expect(body).not.toMatch(/cyclonedx-npm/);
        expect(body).toMatch(/uses: actions\/attest-build-provenance@[0-9a-f]{40}/);
        expect(body).toMatch(/pkinative-mcp-\$\{VERSION\}\.tgz/);
        expect(body).toMatch(/gh release view "v\$\{VERSION\}"[\s\S]*gh release upload "v\$\{VERSION\}"[^\n]*--clobber/);
        expect(body).not.toMatch(/gh release create/);
    });

    it('lists the endpoints for the future block policy', () => {
        for (const host of ['github.com', 'api.github.com', 'registry.npmjs.org', 'release-assets.githubusercontent.com', 'pypi.org', 'files.pythonhosted.org', 'fulcio.sigstore.dev', 'rekor.sigstore.dev', 'tuf-repo-cdn.sigstore.dev']) {
            expect(publish).toContain(host);
        }
    });
});

// ── Certificate linters: one version, pinned in every place that names it ──

describe('certificate linters pinned in lock-step (publish.yml, SECURITY-INSIGHTS.yml, CONTRIBUTING.md, the requirements file)', () => {
    const publish = readWorkflow('publish.yml');
    const zlintStep = (jobSteps(publish).get('publish') ?? []).find((s) => s.includes('Install zlint')) ?? '';
    const zlintVersion = /ZLINT_VERSION:\s*(\d+\.\d+\.\d+)\s*$/m.exec(zlintStep)?.[1];
    const zlintSha = /ZLINT_SHA256:\s*([0-9a-f]{64})\s*$/m.exec(zlintStep)?.[1];

    it('A2-012: publish.yml pins zlint to one exact version and verifies the archive against a 64-hex SHA-256', () => {
        expect(zlintVersion, 'ZLINT_VERSION').toMatch(/^\d+\.\d+\.\d+$/);
        expect(zlintSha, 'ZLINT_SHA256').toMatch(/^[0-9a-f]{64}$/);
        // The archive name derives from the version, the checksum is checked strictly, and the binary path the
        // gate receives names the same version — a bump that forgets one of the three fails here.
        expect(zlintStep).toContain('zlint_${ZLINT_VERSION}_Linux_x86_64.tar.gz');
        expect(zlintStep).toContain('releases/download/v${ZLINT_VERSION}/${ARCHIVE}');
        expect(zlintStep).toMatch(/echo "\$\{ZLINT_SHA256\}  \$\{RUNNER_TEMP\}\/\$\{ARCHIVE\}" \| sha256sum --check --strict/);
        expect(publish).toContain(`zlint_${zlintVersion}_Linux_x86_64/zlint`);
        expect((publish.match(/zlint_\d+\.\d+\.\d+_Linux_x86_64/g) ?? []).every((m) => m === `zlint_${zlintVersion}_Linux_x86_64`)).toBe(true);
    });

    it('A2-012: SECURITY-INSIGHTS.yml names the same zlint version, pinned by archive hash, under the publish gate', () => {
        const insights = readText('.github', 'SECURITY-INSIGHTS.yml');
        const entry = /- name: zlint\s*\n([\s\S]*?)(?=\n\s*- name: )/.exec(insights)?.[1];
        expect(entry, 'a zlint tool entry').toBeDefined();
        expect(entry).toContain(`v${zlintVersion}`);
        expect(entry).toMatch(/archive hash/);
        expect(entry).toMatch(/release:\s*true/);
        // No other version is quoted in the zlint entry.
        const quoted = [...(entry ?? '').matchAll(/\bv(\d+\.\d+\.\d+)\b/g)].map((m) => m[1]);
        expect(quoted.length).toBeGreaterThan(0);
        expect(new Set(quoted)).toEqual(new Set([zlintVersion]));
        const pkilint = /- name: pkilint\s*\n([\s\S]*?)(?=\n\s*- name: )/.exec(insights)?.[1];
        expect(pkilint, 'a pkilint tool entry').toBeDefined();
        expect(pkilint).toContain('scripts/data/lint-python-requirements.txt');
        expect(pkilint).toMatch(/release:\s*true/);
    });

    it('A2-012: CONTRIBUTING.md documents the same zlint version', () => {
        const contributing = readText('CONTRIBUTING.md');
        expect(contributing).toMatch(new RegExp(`zlint \\(v${escapeRegExp(zlintVersion ?? '')}\\b`));
        const quoted = [...contributing.matchAll(/zlint \(v(\d+\.\d+\.\d+)/g)].map((m) => m[1]);
        expect(new Set(quoted)).toEqual(new Set([zlintVersion]));
    });

    it('A2-012: pkilint is installed with --require-hashes from a requirements file where every requirement carries a sha256 hash', () => {
        const pkilintStep = (jobSteps(publish).get('publish') ?? []).find((s) => s.includes('Install pkilint')) ?? '';
        expect(pkilintStep).toMatch(/pip install --require-hashes --no-deps --only-binary :all: -r scripts\/data\/lint-python-requirements\.txt/);
        const requirements = readText('scripts', 'data', 'lint-python-requirements.txt');
        const lines = requirements.split('\n').map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'));
        expect(lines.length).toBeGreaterThan(10);
        const packages: Array<{ name: string; version: string; hashes: number }> = [];
        for (const line of lines) {
            const requirement = /^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)\s*\\$/.exec(line);
            const hash = /^--hash=sha256:[0-9a-f]{64}\s*(\\)?$/.exec(line);
            expect(requirement !== null || hash !== null, `unexpected requirements line: ${line}`).toBe(true);
            if (requirement) packages.push({ name: requirement[1], version: requirement[2], hashes: 0 });
            else packages[packages.length - 1]!.hashes += 1;
        }
        for (const p of packages) expect(p.hashes, `${p.name}==${p.version} has no --hash=sha256:`).toBeGreaterThan(0);
        // pkilint itself is there, as a wheel (sdist builds are refused by --only-binary) with its hash.
        const pkilint = packages.find((p) => p.name === 'pkilint');
        expect(pkilint).toBeDefined();
        expect(pkilint!.version).toMatch(/^\d+\.\d+\.\d+$/);
        // The header documents the install line the workflow runs — the two cannot drift silently.
        expect(requirements).toContain('pip install --require-hashes --no-deps --only-binary :all: -r');
    });
});

describe('package.json publish settings', () => {
    const pkg = JSON.parse(readText('package.json')) as {
        publishConfig?: Record<string, unknown>;
        scripts: Record<string, string>;
        dependencies: Record<string, string>;
    };

    it('declares public access with provenance', () => {
        expect(pkg.publishConfig).toEqual({ access: 'public', provenance: true });
    });

    it('keeps exactly three runtime dependencies', () => {
        expect(Object.keys(pkg.dependencies).sort()).toEqual(['@modelcontextprotocol/server', 'pkinative', 'zod']);
    });

    it('does not rely on lifecycle scripts that .npmrc disables', () => {
        // ignore-scripts=true: `prepare` would never run, so the build is a gate step.
        expect(pkg.scripts['prepare']).toBeUndefined();
        expect(pkg.scripts['prepublishOnly']).toBe('npm run build');
    });

    it('exposes the opt-in git hooks', () => {
        expect(pkg.scripts['hooks:install']).toBe('node scripts/install-git-hooks.mjs');
        expect(pkg.scripts['hooks:uninstall']).toBe('node scripts/install-git-hooks.mjs --uninstall');
        expect(existsSync(join(ROOT, '.githooks', 'pre-commit'))).toBe(true);
        expect(existsSync(join(ROOT, '.githooks', 'pre-push'))).toBe(true);
        expect(readText('.githooks', 'pre-push')).toContain('scripts/gate.ts --fast');
        expect(readText('.githooks', 'pre-commit')).toMatch(/npm run lint/);
    });

    it('names every script the workflows call', () => {
        for (const script of ['build', 'test:generate', 'test:interop', 'corpus:pki', 'validate:pki', 'verify:docs', 'typecheck:scripts', 'agents:rules']) {
            expect(pkg.scripts[script], script).toBeDefined();
        }
    });
});

// ── Sample regression: a required check with no paths filter ─────────

describe('sample-regression.yml', () => {
    const wf = readWorkflow('sample-regression.yml');

    it('runs on every push and pull request, with no paths filter, deciding the scope inside', () => {
        expect(wf).toMatch(/^on:\s*\n\s*push:\s*\n\s*branches:[^\n]*\n\s*pull_request:/m);
        expect(wf).not.toMatch(/^\s*paths(-ignore)?:/m);
        expect(wf).toMatch(/package-lock\\\.json/);
        expect(wf).toMatch(/tests\/fixtures\//); // the OpenSSL fixtures the samples sign with
    });

    it('builds the server before generating and verifying strictly', () => {
        const steps = jobSteps(wf).get('sample-regression') ?? [];
        const index = (needle: string): number => steps.findIndex((s) => s.includes(needle));
        expect(index('run: npm run build')).toBeGreaterThan(index('run: npm ci --ignore-scripts'));
        expect(index('run: npm run test:generate')).toBeGreaterThan(index('run: npm run build'));
        expect(index('run: npx tsx scripts/verify-samples.ts --strict')).toBeGreaterThan(index('run: npm run test:generate'));
    });
});

// ── Node Current: advisory, never required, never masked ─────────────

describe('node-current.yml', () => {
    const wf = readWorkflow('node-current.yml');

    it('runs the gate on Node 26 as an advisory check, with no continue-on-error', () => {
        expect(wf).toMatch(/node-version:\s*26/);
        expect(wf).toMatch(/run: npx tsx scripts\/gate\.ts --ci --require-all/);
        expect(wf).not.toMatch(/^\s*continue-on-error:/m); // a YAML key, not the comment that explains its absence
        expect(requiredContexts().some((c) => /node/i.test(c))).toBe(false);
    });
});

// ── Dependency hygiene ───────────────────────────────────────────────

describe('dependency review and audit', () => {
    it('reviews every pull request for high vulnerabilities and licences', () => {
        const review = readWorkflow('dependency-review.yml');
        expect(review).toMatch(/^on:\s*\n\s*pull_request:/m);
        expect(review).toMatch(/uses: actions\/dependency-review-action@[0-9a-f]{40}/);
        expect(review).toMatch(/fail-on-severity:\s*high/);
        expect(review).toMatch(/allow-licenses:\s*MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, 0BSD, CC0-1.0, Unlicense/);
        expect(review).toMatch(/comment-summary-in-pr:\s*on-failure/);
    });

    it('audits the lockfile weekly', () => {
        const audit = readWorkflow('audit.yml');
        expect(audit).toMatch(/schedule:\s*\n\s*- cron:/);
        expect(audit).toMatch(/workflow_dispatch:/);
        expect(audit).toMatch(/run: npm ci --ignore-scripts/);
        expect(audit).toMatch(/run: npm audit --audit-level=high/);
    });

    it('.npmrc, .nvmrc and .node-version carry the contributor defaults', () => {
        expect(readText('.npmrc')).toBe('ignore-scripts=true\nfund=false\naudit-level=high\n');
        expect(readText('.node-version')).toBe('22\n');
        expect(readText('.nvmrc')).toBe('22\n');
    });

    it('keeps dependabot on npm and github-actions, weekly, with the toolchain majors held back', () => {
        const bot = readText('.github', 'dependabot.yml');
        expect(bot).toMatch(/package-ecosystem:\s*npm/);
        expect(bot).toMatch(/package-ecosystem:\s*github-actions/);
        expect((bot.match(/interval:\s*weekly/g) ?? []).length).toBe(2);
        for (const name of ['typescript', 'eslint', 'vitest']) expect(bot).toMatch(new RegExp(`dependency-name:\\s*"${name}"\\s*\\n\\s*update-types:\\s*\\["version-update:semver-major"\\]`));
    });

    it('protects release tags with a ruleset the maintainer creates tags under', () => {
        const tags = JSON.parse(readText('.github', 'rulesets', 'tags.json')) as {
            target: string; conditions: { ref_name: { include: string[] } }; rules: Array<{ type: string }>;
        };
        expect(tags.target).toBe('tag');
        expect(tags.conditions.ref_name.include).toEqual(['refs/tags/v*']);
        expect(tags.rules.map((r) => r.type).sort()).toEqual(['deletion', 'non_fast_forward', 'update']);
    });

    it('main ruleset: no deletion, no force push, pull request required with threads resolved', () => {
        const main = JSON.parse(readText('.github', 'rulesets', 'main.json')) as {
            target: string; rules: Array<{ type: string; parameters?: Record<string, unknown> }>;
        };
        expect(main.target).toBe('branch');
        const types = main.rules.map((r) => r.type);
        expect(types).toEqual(expect.arrayContaining(['deletion', 'non_fast_forward', 'pull_request', 'required_status_checks']));
        const pr = main.rules.find((r) => r.type === 'pull_request')?.parameters ?? {};
        expect(pr['required_review_thread_resolution']).toBe(true);
    });
});

// ── Contributor checklist parity ─────────────────────────────────────

describe('pull request template', () => {
    const template = readText('.github', 'pull_request_template.md');
    const contributing = join(ROOT, 'CONTRIBUTING.md');

    it('lists the gate, the release flow and the PKI-specific checks', () => {
        expect(template).toMatch(/`npm run gate` passes/);
        for (const mention of ['ROADMAP.md', 'release-notes/vX.Y.Z.md', 'rebaseline', 'AGENT_RULES.md', 'TOOL_API_VERSION', 'corpus:pki', 'test:interop', 'No secret in the diff', 'assertResultClean']) {
            expect(template).toContain(mention);
        }
    });

    it.skipIf(!existsSync(contributing))('mirrors CONTRIBUTING.md §Pull Request Checklist word for word', () => {
        const section = /## Pull Request Checklist\s*\n([\s\S]*?)\n## /.exec(readText('CONTRIBUTING.md'));
        expect(section).not.toBeNull();
        const items = section![1].split('\n').filter((l) => l.startsWith('- [ ]'));
        expect(items.length).toBeGreaterThan(5);
        // Links are rewritten to reach CONTRIBUTING.md from .github/; the wording is identical.
        const normalise = (s: string): string => s.replace(/\]\((?:\.\.\/CONTRIBUTING\.md)?#/g, '](#');
        for (const item of items) expect(normalise(template), item.slice(0, 60)).toContain(normalise(item));
        const templateItems = template.split('\n').filter((l) => l.startsWith('- [ ]'));
        expect(templateItems.map(normalise).sort()).toEqual(items.map(normalise).sort());
    });
});
