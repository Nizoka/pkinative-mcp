// A2-009 — the English-only prose detector (scripts/lib/prose-language.ts),
// ported from pdfnative-mcp 1.7.0's tests/prose-language.test.ts. It is the
// one definition the `prose-language` rule of verify-docs (docs, README,
// examples, release notes) and the repository scan below share. It is
// deliberately narrow: French is the language that slipped into pdfnative's
// samples, and a false positive costs a `demo-language:` marker while a
// false negative ships a document nobody reviewed in the project language.

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { classifyLine, findNonEnglishProse, DEMO_LANGUAGE_MARKER } from '../../scripts/lib/prose-language.js';

const ROOT = resolve(import.meta.dirname, '..', '..');

describe('classifyLine', () => {
    it('A2-009: flags the French headings the pdfnative 1.8.0 samples shipped with', () => {
        for (const line of [
            "{ type: 'heading', text: 'Césure douce et espaces insécables', level: 1 },",
            "title: 'Crénage',",
            "headers: ['Mois', 'Débit', 'Crédit'],",
            "['Janvier', '1 111,00', '8 888,00'],",
            "balanceText: 'Solde au 31/12/2026 : 12 345,67 EUR',",
            'Le crénage rapproche les paires que le dessin des lettres laisse trop ouvertes.',
        ]) {
            expect(classifyLine(line), line).not.toBeNull();
        }
    });

    it('flags two distinct French function words but not one', () => {
        expect(classifyLine('la ponctuation qui borde une ligne')).not.toBeNull();
        expect(classifyLine('Sans dictionnaire, le fournisseur reçoit chaque mot')).not.toBeNull();
        expect(classifyLine('set the par value of the bond')).toBeNull();
        expect(classifyLine('EST is five hours behind UTC')).toBeNull();
        expect(classifyLine('a sur-name is not a surname')).toBeNull();
    });

    it('flags UTF-8 text decoded as Latin-1', () => {
        expect(classifyLine("balanceText: 'â‚¬ 1,000.00',")).toMatch(/mojibake/);
        expect(classifyLine('pkinative â€” the PKI engine')).toMatch(/mojibake/);
    });

    it('leaves English typographic vocabulary and isolated accents alone', () => {
        for (const line of [
            'Brackets and Guillemets',
            'A café résumé with naïve façade — €42',
            "expect(rdn('Café <2026>')).toBe('CN=Café <2026>');",
            'files that parse the parser output',
            '« » are the French quotation marks',
        ]) {
            expect(classifyLine(line), line).toBeNull();
        }
    });

    it('flags Spanish, Italian, Portuguese and German prose under their own name', () => {
        expect(classifyLine('El proyecto está en la fase final, pero todo funciona')).toMatch(/^Spanish/);
        expect(classifyLine('La casa che sta sulla collina è molto bella, anche di notte')).toMatch(/^Italian/);
        expect(classifyLine('A casa que fica na colina é muito bonita, mas também fria')).toMatch(/^Portuguese/);
        expect(classifyLine('Die Zertifikate liegen außerhalb der Kette und werden nicht geprüft')).toMatch(/^German/);
    });

    it("never mistakes English for another language — this repository's own vocabulary included", () => {
        for (const line of [
            'The old APIs die when the shim is removed, per the deprecation policy.',
            'Cast the die: the fallback is deterministic and the den of legacy code is gone.',
            'The server is a thin wrapper over pkinative, as documented.',
            // `der` (DER encoding) and `mit` (the licence) are filtered out of the German list on purpose.
            'Convert DER to PEM with openssl; the MIT licence applies.',
            'the der input, the mit licence, the pem block and the tbs part',
            '<em>Validated</em> against OpenSSL 3 as a conformant certificate',
            "{ label: 'Font', value: 'Noto Sans Tai Le' }",
            'Le Corbusier and Les Paul are proper names, not prose.',
            'Under an unsupported intent the claim can die; a den of stale bytes remains.',
            'pkinative inspect --input leaf.crt.pem --output report.json --format json',
            'C=FR, O=Acme, CN=Acme Test CA — a distinguished name is not prose.',
        ]) {
            expect(classifyLine(line), line).toBeNull();
        }
    });

    it('uses Unicode word boundaries, so "est" does not match inside "está"', () => {
        expect(classifyLine('está aquí')).toMatch(/^Spanish/);
        expect(classifyLine('It is a test of the est, honestly.')).toBeNull();
    });

    it('does not detect Turkish, Vietnamese or Polish — by design, documented', () => {
        for (const line of [
            'Zażółć gęślą jaźń',
            'Việt Nam đất nước tươi đẹp',
            'Restoran Menüsü – Akşam Yemeği',
        ]) {
            expect(classifyLine(line), line).toBeNull();
        }
    });

    it('counts lowercase tokens only: a capitalised token mid-line is a proper name', () => {
        expect(classifyLine('Les Paul played with Mary Ford; La Jolla is in California')).toBeNull();
        expect(classifyLine('les paul played with la jolla')).not.toBeNull();
    });
});

describe('findNonEnglishProse', () => {
    it('A2-009: reports line numbers and skips lines marked with demo-language: (the line and the one after it)', () => {
        const text = [
            'English line',
            "title: 'Crénage',",
            `// ${DEMO_LANGUAGE_MARKER} fr (kerning demo)`,
            "title: 'Crénage',",
            `text: 'Vraiment ? Oui ! Total : 42.', // ${DEMO_LANGUAGE_MARKER} fr (punctuation)`,
            'an English line, so the marker above does not reach the next one',
            'la ponctuation qui borde une ligne',
        ].join('\n');
        const found = findNonEnglishProse(text, 'sample.ts');
        expect(found.map((f) => f.line)).toEqual([2, 7]);
        expect(found[0]!.snippet).toContain('Crénage');
        expect(found[0]!.reason).toMatch(/French word/);
    });

    it('skips comment lines in TypeScript but not in other files', () => {
        const ts = "// Lexique des règles typographiques de l'Imprimerie nationale\nconst x = 1;";
        expect(findNonEnglishProse(ts, 'a.ts')).toEqual([]);
        expect(findNonEnglishProse(ts, 'a.mjs')).toEqual([]);
        expect(findNonEnglishProse('// la ponctuation qui borde une ligne', 'a.md')).toHaveLength(1);
        expect(findNonEnglishProse('// la ponctuation qui borde une ligne', 'a.json')).toHaveLength(1);
    });

    it('exempts a fenced block that follows a marker in Markdown, and only that block', () => {
        const md = [
            `<!-- ${DEMO_LANGUAGE_MARKER} fr (example) -->`,
            '```ts',
            "const s = 'Vraiment ? Oui ! Total : 42. Et une « citation » pour finir.';",
            "const t = 'la ponctuation qui borde une ligne';",
            '```',
            'la ponctuation qui borde une ligne',
            '```',
            'la ponctuation qui borde une ligne',
            '```',
        ].join('\n');
        expect(findNonEnglishProse(md, 'guide.md').map((f) => f.line)).toEqual([6, 8]);
    });

    it('honours a caller-supplied suppression marker (verify-docs:allow prose-language)', () => {
        const md = '<!-- verify-docs:allow prose-language (history) -->\nla ponctuation qui borde une ligne';
        expect(findNonEnglishProse(md, 'x.md', { suppress: 'verify-docs:allow prose-language' })).toEqual([]);
        expect(findNonEnglishProse(md, 'x.md')).toHaveLength(1);
    });

    it('truncates a long snippet and keeps the reason', () => {
        const long = `la ponctuation qui borde une ligne ${'x'.repeat(200)}`;
        const [finding] = findNonEnglishProse(long, 'x.txt', { kind: 'other' });
        expect(finding!.snippet.length).toBeLessThanOrEqual(100);
        expect(finding!.snippet.endsWith('…')).toBe(true);
    });
});

describe('repository prose is English', () => {
    // The verify-docs rule covers the documentation corpus (docs, README,
    // examples, release notes); this scan covers what it does not read: the
    // server source, the scripts and the tests. The OpenSSL fixtures are
    // binary or PEM, never prose, and are out of scope.
    function* walk(dir: string, filter: (name: string) => boolean): Generator<string> {
        if (!existsSync(dir)) return;
        for (const entry of readdirSync(dir).sort()) {
            if (entry === 'node_modules' || entry.startsWith('.')) continue;
            const full = join(dir, entry);
            if (statSync(full).isDirectory()) yield* walk(full, filter);
            else if (filter(entry)) yield full;
        }
    }

    it('A2-009: source, scripts and tests carry no unmarked non-English line', () => {
        // The detector's own vocabulary and this file's fixtures are the one place the words are written on purpose.
        const SELF = new Set(['prose-language.ts', 'prose-language.test.ts']);
        const files = [
            ...walk(join(ROOT, 'scripts'), (n) => (n.endsWith('.ts') || n.endsWith('.mjs')) && !SELF.has(n)),
            ...walk(join(ROOT, 'src'), (n) => n.endsWith('.ts')),
            ...walk(join(ROOT, 'tests'), (n) => n.endsWith('.ts') && !SELF.has(n)),
        ];
        expect(files.length).toBeGreaterThan(100);
        const offenders: string[] = [];
        for (const file of files) {
            for (const f of findNonEnglishProse(readFileSync(file, 'utf8'), file)) {
                offenders.push(`${relative(ROOT, file).replace(/\\/g, '/')}:${f.line} ${f.reason}: ${f.snippet}`);
            }
        }
        expect(offenders, 'mark demonstrated content with `demo-language: <tag> (reason)` on or above the line').toEqual([]);
    });

    it('the verify-docs rule and this scan are the same detector, with the same marker', () => {
        const verifyDocs = readFileSync(join(ROOT, 'scripts', 'verify-docs.ts'), 'utf8');
        expect(verifyDocs).toContain("from './lib/prose-language.js'");
        expect(verifyDocs).toMatch(/findNonEnglishProse\(text, file, \{ suppress: 'verify-docs:allow prose-language' \}\)/);
        expect(DEMO_LANGUAGE_MARKER).toBe('demo-language:');
    });
});
