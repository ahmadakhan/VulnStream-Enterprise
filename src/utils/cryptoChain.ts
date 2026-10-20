import { sha256 as digest } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import type { AuditLog } from '../types';

/** Synchronous SHA-256 for browser state updates. */
export function quickHash(input: string): string {
  return bytesToHex(digest(utf8ToBytes(input)));
}

export async function sha256(message: string): Promise<string> {
  return quickHash(message);
}

export function generateHmacSignature(payload: string, secret: string): string {
  return `sha256=${bytesToHex(hmac(digest, utf8ToBytes(secret), utf8ToBytes(payload)))}`;
}

export function hashAuditLog(log: AuditLog): string {
  return quickHash(JSON.stringify([log.prevHash, log.id, log.timestamp, log.category,
    log.level, log.event, log.details, log.actor, log.ipAddress]));
}

/** Input and output are newest-first; use only when adding newly created logs. */
export function chainAuditLogs(logs: AuditLog[], previousHash = '0'.repeat(64)): AuditLog[] {
  return [...logs].reverse().map(log => {
    const entry = { ...log, prevHash: previousHash };
    entry.hash = hashAuditLog(entry);
    previousHash = entry.hash;
    return entry;
  }).reverse();
}

/** Checks retained content and links. An external trusted anchor is still required
 * to detect replacement of the entire chain or deletion of its newest entries. */
export function verifyAuditChain(logs: AuditLog[]): boolean {
  return logs.every((log, i) => /^[a-f0-9]{64}$/.test(log.hash)
    && log.hash === hashAuditLog(log)
    && (i === logs.length - 1 || log.prevHash === logs[i + 1].hash));
}
