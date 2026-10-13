/**
 * Tests for `src/content-input.ts` — the content input of the signing /
 * verification / time-stamping tools (text / base64 / path, no extension
 * restriction) and the shared hex-string grammar.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';

import { contentInputSchema, ContentInputSchema, HEX_PATTERN, hexSchema, HexSchema, loadContent } from '../src/content-input.js';
import { ToolError } from '../src/errors.js';
import { fixtureBytes, fixtureText } from './_pki-fixtures.js';
import { cleanupSandbox, makeSandbox } from './_sandbox.js';

async function rejectionOf(p: Promise<unknown>): Promise<ToolError> {
    try {
        await p;
    } catch (err) {
        if (err instanceof ToolError) return err;
        throw err;
    }
    throw new Error('expected the call to reject');
}

describe('schemas', () => {
    it('contentInputSchema is a closed object with the three exclusive members', () => {
        const schema = contentInputSchema('The content to sign');
        expect(schema).toMatchObject({ type: 'object', additionalProperties: false, description: 'The content to sign: exactly one of text / base64 / path.' });
        const properties = schema['properties'] as Record<string, Record<string, unknown>>;
        expect(Object.keys(properties)).toEqual(['text', 'base64', 'path']);
        expect(properties['text']).toMatchObject({ type: 'string' });
        expect(properties['base64']?.['description']).toContain('128 MiB');
        expect(properties['path']).toMatchObject({ type: 'string', minLength: 1 });
        expect(properties['path']?.['description']).toContain('any extension');
    });

    it('ContentInputSchema: exactly one member, no unknown key, an empty text is allowed', () => {
        expect(ContentInputSchema.safeParse({ text: '' }).success).toBe(true);
        expect(ContentInputSchema.safeParse({ text: 'hello' }).success).toBe(true);
        expect(ContentInputSchema.safeParse({ base64: 'aGVsbG8=' }).success).toBe(true);
        expect(ContentInputSchema.safeParse({ path: 'content.txt' }).success).toBe(true);
        expect(ContentInputSchema.safeParse({}).success).toBe(false);
        expect(ContentInputSchema.safeParse({ text: 'a', base64: 'YQ==' }).success).toBe(false);
        expect(ContentInputSchema.safeParse({ base64: 'YQ==', path: 'x' }).success).toBe(false);
        expect(ContentInputSchema.safeParse({ path: '' }).success).toBe(false);
        expect(ContentInputSchema.safeParse({ text: 'a', bogus: true }).success).toBe(false);
        expect(ContentInputSchema.safeParse({ pem: '-----BEGIN' }).success).toBe(false);
    });
});

describe('loadContent', () => {
    let sandbox: string | null = null;

    afterEach(async () => {
        await cleanupSandbox(sandbox);
        sandbox = null;
    });

    it('text is UTF-8 encoded; base64 is decoded (empty allowed, a data: URI tolerated, garbage refused by name)', async () => {
        expect(await loadContent({ text: 'héllo' }, 'content')).toEqual({ bytes: new TextEncoder().encode('héllo'), source: 'text' });
        expect(await loadContent({ text: '' }, 'content')).toEqual({ bytes: new Uint8Array(0), source: 'text' });
        expect(await loadContent({ base64: Buffer.from(fixtureText('content.txt')).toString('base64') }, 'content')).toEqual({ bytes: fixtureBytes('content.txt'), source: 'base64' });
        expect(await loadContent({ base64: '' }, 'content')).toEqual({ bytes: new Uint8Array(0), source: 'base64' });
        expect((await loadContent({ base64: 'data:text/plain;base64,aGVs bG8=' }, 'content')).bytes).toEqual(new TextEncoder().encode('hello'));
        const bad = await rejectionOf(loadContent({ base64: '!!!' }, 'content'));
        expect(bad.code).toBe('VALIDATION_ERROR');
        expect(bad.data).toEqual({ field: 'content.base64' });
    });

    it('none of the members is VALIDATION_ERROR naming the input', async () => {
        const err = await rejectionOf(loadContent({}, 'content'));
        expect(err.code).toBe('VALIDATION_ERROR');
        expect(err.message).toBe('content: pass exactly one of text / base64 / path');
        expect(err.data).toEqual({ path: 'content' });
    });

    it('path reads any file of the sandbox regardless of its extension; the source is the relative path', async () => {
        sandbox = await makeSandbox();
        await fs.mkdir(path.join(sandbox, 'in'));
        await fs.writeFile(path.join(sandbox, 'in', 'payload.whatever'), fixtureBytes('content.txt'));
        await fs.writeFile(path.join(sandbox, 'in', 'noext'), Buffer.from([0, 1, 2]));
        expect(await loadContent({ path: 'in/payload.whatever' }, 'content')).toEqual({ bytes: fixtureBytes('content.txt'), source: 'in/payload.whatever' });
        expect((await loadContent({ path: 'in/noext' }, 'content')).bytes).toEqual(new Uint8Array([0, 1, 2]));
        const missing = await rejectionOf(loadContent({ path: 'in/missing' }, 'content'));
        expect(missing.code).toBe('INPUT_NOT_FOUND');
        expect(missing.message).toContain('content.path');
        expect((await rejectionOf(loadContent({ path: 'in' }, 'content'))).code).toBe('INPUT_NOT_FOUND');
        expect((await rejectionOf(loadContent({ path: '../escape' }, 'content'))).code).toBe('SECURITY_VIOLATION');
        expect((await rejectionOf(loadContent({ path: '/etc/passwd' }, 'content'))).code).toBe('SECURITY_VIOLATION');
    });

    it('path is SECURITY_VIOLATION when the sandbox is unset; inline forms still work', async () => {
        const err = await rejectionOf(loadContent({ path: 'content.txt' }, 'content'));
        expect(err.code).toBe('SECURITY_VIOLATION');
        expect(err.message).toContain('PKINATIVE_MCP_OUTPUT_DIR');
        expect((await loadContent({ text: 'x' }, 'content')).source).toBe('text');
    });
});

describe('hex grammar', () => {
    const re = new RegExp(HEX_PATTERN);

    it('HEX_PATTERN accepts an 0x prefix, colons and spaces; refuses odd lengths and non-hex', () => {
        for (const ok of ['00', '0xdead', 'DEAD', 'de:ad:be:ef', 'de ad be ef', '0xde:ad', '0a0b0c']) expect(re.test(ok), ok).toBe(true);
        for (const bad of ['', 'd', 'dea', 'zz', '0x', 'de-ad', 'deadbee', '0xg0']) expect(re.test(bad), bad).toBe(false);
    });

    it('hexSchema / HexSchema share the grammar and the 2-character floor', () => {
        const schema = hexSchema('The serial number.');
        expect(schema).toEqual({ type: 'string', minLength: 2, pattern: HEX_PATTERN, description: 'The serial number. Hexadecimal (an 0x prefix, colons and spaces are tolerated).' });
        expect(HexSchema.safeParse('0x1001').success).toBe(true);
        expect(HexSchema.safeParse('10:01').success).toBe(true);
        expect(HexSchema.safeParse('10 01').success).toBe(true);
        expect(HexSchema.safeParse('1').success).toBe(false);
        expect(HexSchema.safeParse('100').success).toBe(false);
        expect(HexSchema.safeParse('xyz').success).toBe(false);
        expect(HexSchema.safeParse(4097).success).toBe(false);
    });
});
