// scripts/lib/json-schema-lite.ts holds server.json to the vendored MCP
// registry schema inside the hermetic gate (step `server-json`). It is a
// draft-07 subset on purpose; what these tests pin is that the subset can
// never turn into a silent pass — an unimplemented keyword is a failure —
// and that the real server.json validates against the real vendored schema.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { validate, type Json } from '../../scripts/lib/json-schema-lite.js';

type Obj = { readonly [key: string]: Json };
const ROOT = resolve(import.meta.dirname, '..', '..');

describe('json-schema-lite: keywords', () => {
    it('checks type, with integer ⊂ number', () => {
        expect(validate(3, { type: 'integer' })).toEqual([]);
        expect(validate(3, { type: 'number' })).toEqual([]);
        expect(validate(3.5, { type: 'integer' })).toHaveLength(1);
        expect(validate('3', { type: 'number' })).toHaveLength(1);
        expect(validate(null, { type: 'null' })).toEqual([]);
        expect(validate([], { type: 'object' })).toHaveLength(1);
    });

    it('checks required, properties and additionalProperties: false, with JSON-pointer-style paths', () => {
        const schema: Obj = { type: 'object', required: ['name'], properties: { name: { type: 'string' }, n: { type: 'integer' } }, additionalProperties: false };
        expect(validate({ name: 'x', n: 1 }, schema)).toEqual([]);
        const failures = validate({ n: 'one', extra: true }, schema);
        expect(failures.join('\n')).toMatch(/name/);
        expect(failures.join('\n')).toMatch(/\$\.n/);
        expect(failures.join('\n')).toMatch(/extra/);
    });

    it('checks string and array bounds, pattern, enum, const and uniqueItems', () => {
        expect(validate('abc', { type: 'string', minLength: 2, maxLength: 3, pattern: '^[a-c]+$' })).toEqual([]);
        expect(validate('abcd', { type: 'string', maxLength: 3 })).toHaveLength(1);
        expect(validate('xyz', { type: 'string', pattern: '^[a-c]+$' })).toHaveLength(1);
        expect(validate('b', { enum: ['a', 'b'] })).toEqual([]);
        expect(validate('c', { enum: ['a', 'b'] })).toHaveLength(1);
        expect(validate('a', { const: 'a' })).toEqual([]);
        expect(validate('b', { const: 'a' })).toHaveLength(1);
        expect(validate([1, 2], { type: 'array', items: { type: 'integer' }, minItems: 1, maxItems: 2, uniqueItems: true })).toEqual([]);
        expect(validate([1, 1], { type: 'array', uniqueItems: true })).toHaveLength(1);
        expect(validate([1, 'x'], { type: 'array', items: { type: 'integer' } })).toHaveLength(1);
        expect(validate(5, { minimum: 1, maximum: 4 })).toHaveLength(1);
    });

    it('checks anyOf, oneOf, allOf and not', () => {
        expect(validate('x', { anyOf: [{ type: 'string' }, { type: 'integer' }] })).toEqual([]);
        expect(validate(true, { anyOf: [{ type: 'string' }, { type: 'integer' }] })).not.toEqual([]);
        expect(validate(3, { oneOf: [{ type: 'integer' }, { type: 'number' }] })).not.toEqual([]);
        expect(validate(3.5, { oneOf: [{ type: 'integer' }, { type: 'number' }] })).toEqual([]);
        expect(validate('ab', { allOf: [{ minLength: 1 }, { maxLength: 1 }] })).not.toEqual([]);
        expect(validate('a', { not: { type: 'string' } })).not.toEqual([]);
    });

    it('resolves local $ref pointers and fails on one it cannot resolve', () => {
        const schema: Obj = { definitions: { id: { type: 'string', minLength: 1 } }, type: 'object', properties: { id: { $ref: '#/definitions/id' } } };
        expect(validate({ id: 'a' }, schema)).toEqual([]);
        expect(validate({ id: '' }, schema)).toHaveLength(1);
        expect(validate('x', { $ref: '#/definitions/missing' })).not.toEqual([]);
        expect(validate('x', { $ref: 'https://example.com/other.json' })).not.toEqual([]);
    });
});

describe('json-schema-lite: never a silent pass', () => {
    it('reports a keyword it does not implement instead of ignoring it', () => {
        const failures = validate({ a: 1 }, { type: 'object', patternProperties: { '^a': { type: 'string' } } });
        expect(failures.join('\n')).toMatch(/patternProperties/);
        expect(validate('x', { type: 'string', if: { minLength: 1 } }).join('\n')).toMatch(/\bif\b/);
    });

    it('accepts annotations, including format, without checking them', () => {
        expect(validate('not-a-uri', { type: 'string', format: 'uri', title: 't', description: 'd', examples: ['x'], default: 'y', $comment: 'c' })).toEqual([]);
    });
});

describe('json-schema-lite: the real server.json', () => {
    const serverJson = JSON.parse(readFileSync(resolve(ROOT, 'server.json'), 'utf8')) as Obj;
    const revision = /\/schemas\/([^/]+)\/server\.schema\.json$/.exec(String(serverJson['$schema']))?.[1];
    const schema = JSON.parse(readFileSync(resolve(ROOT, 'tests', '_fixtures', `server.schema.${revision}.json`), 'utf8')) as Obj;

    it('names a schema revision that is vendored under tests/_fixtures/, with the same $id', () => {
        expect(revision).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(schema['$id']).toBe(serverJson['$schema']);
    });

    it('validates — and a perturbed copy does not', () => {
        expect(validate(serverJson, schema)).toEqual([]);
        expect(validate({ ...serverJson, name: 42 }, schema)).not.toEqual([]);
        const { name: _dropped, ...withoutName } = serverJson as { name: Json } & Obj;
        expect(validate(withoutName, schema)).not.toEqual([]);
    });
});
