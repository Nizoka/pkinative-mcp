/**
 * The wrapper's randomness. pkinative generates nothing random by doctrine
 * (no key generation, no serial, no nonce): the caller supplies them. This
 * server offers `'random'` as an explicit value for a serial number and the
 * OCSP / time-stamp nonces, drawn from Node's CSPRNG here, and every summary
 * that used it says so (`randomSerial`, `randomNonce`) — `describe_engine`
 * reports `randomness.wrapper: 'node:crypto'`.
 */
import { webcrypto } from 'node:crypto';

/** A 127-bit positive serial number (RFC 5280 §4.1.2.2: ≤ 20 octets, positive, non-zero). */
export function randomSerialNumber(): bigint {
    const bytes = webcrypto.getRandomValues(new Uint8Array(16));
    bytes[0] = ((bytes[0] as number) & 0x7f) | 0x01;
    return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

/** Random bytes for an OCSP nonce (16 bytes by default, within the 1–32 RFC 8954 range). */
export function randomNonceBytes(length = 16): Uint8Array {
    return webcrypto.getRandomValues(new Uint8Array(length));
}

/** A random 63-bit positive integer for a time-stamp request nonce (RFC 3161 §2.4.1). */
export function randomNonceInteger(): bigint {
    const bytes = webcrypto.getRandomValues(new Uint8Array(8));
    bytes[0] = (bytes[0] as number) & 0x7f;
    const value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
    return value === 0n ? 1n : value;
}

/** The sources of randomness, for `describe_engine`. */
export const RANDOMNESS = {
    engine: 'none',
    wrapper: 'node:crypto',
    usedBy: ["create_certificate spec.serialNumber:'random'", "create_ocsp_request nonce:'random'", "create_timestamp_request nonce:'random'"],
} as const;
