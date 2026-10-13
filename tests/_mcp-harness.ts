/**
 * In-process MCP client harness for tests.
 *
 * Drives a `createServer()` instance through the SDK's `InMemoryTransport`
 * with raw JSON-RPC, so tests exercise the real wire path (request/result
 * validation, codec projection) instead of reaching into SDK internals.
 * Era: legacy 2025-11-25 `initialize` handshake by default (what today's
 * hosts speak); the HTTP tests cover the 2026-07-28 envelope separately.
 */
import { InMemoryTransport, type Server } from '@modelcontextprotocol/server';

import { createServer } from '../src/server.js';

export interface JsonRpcError {
    code: number;
    message: string;
    data?: unknown;
}

export class McpRpcError extends Error {
    readonly code: number;
    readonly data: unknown;
    constructor(err: JsonRpcError) {
        super(err.message);
        this.name = 'McpRpcError';
        this.code = err.code;
        this.data = err.data;
    }
}

export interface McpTestClient {
    request<T = Record<string, unknown>>(method: string, params?: Record<string, unknown>): Promise<T>;
    listTools(): Promise<{ tools: Array<Record<string, unknown> & { name: string }> }>;
    callTool<T = Record<string, unknown>>(name: string, args?: Record<string, unknown>): Promise<T>;
    readResource<T = Record<string, unknown>>(uri: string): Promise<T>;
    getPrompt<T = Record<string, unknown>>(name: string): Promise<T>;
    close(): Promise<void>;
}

/**
 * Connect a fresh (or supplied) server through an in-memory transport and
 * complete the legacy `initialize` handshake.
 */
export async function connectLegacy(server: Server = createServer(), protocolVersion = '2025-11-25'): Promise<McpTestClient> {
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
    let nextId = 1;

    clientSide.onmessage = (message) => {
        if (!('id' in message) || message.id === undefined || message.id === null) return;
        const entry = pending.get(Number(message.id));
        if (entry === undefined) return;
        pending.delete(Number(message.id));
        if ('error' in message) {
            entry.reject(new McpRpcError(message.error as JsonRpcError));
        } else if ('result' in message) {
            entry.resolve(message.result);
        }
    };

    await server.connect(serverSide);
    await clientSide.start();

    const request = <T,>(method: string, params: Record<string, unknown> = {}): Promise<T> => {
        const id = nextId++;
        return new Promise<T>((resolve, reject) => {
            pending.set(id, { resolve: (v) => resolve(v as T), reject });
            void clientSide.send({ jsonrpc: '2.0', id, method, params });
        });
    };

    await request('initialize', {
        protocolVersion,
        capabilities: {},
        clientInfo: { name: 'pkinative-mcp-tests', version: '0.0.0' },
    });
    await clientSide.send({ jsonrpc: '2.0', method: 'notifications/initialized' });

    return {
        request,
        listTools: () => request('tools/list'),
        callTool: (name, args = {}) => request('tools/call', { name, arguments: args }),
        readResource: (uri) => request('resources/read', { uri }),
        getPrompt: (name) => request('prompts/get', { name }),
        close: async () => {
            await clientSide.close();
            await server.close();
        },
    };
}
