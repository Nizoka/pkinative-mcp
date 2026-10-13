import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { PKINATIVE_MCP_VERSION } from '../src/version.js';

describe('version lock-step', () => {
    it('src/version.ts matches package.json', () => {
        const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
        expect(PKINATIVE_MCP_VERSION).toBe(pkg.version);
    });
});
