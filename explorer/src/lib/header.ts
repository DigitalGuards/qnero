/**
 * Headers.
 *
 * `qp_header::Header` carries `zkTreeRoot` between `extrinsicsRoot` and
 * `digest`, in the SCALE encoding and in the JSON, which no stock Substrate
 * header has. This parses the JSON `chain_getHeader` returns and takes the
 * digest apart itself.
 *
 * The hash is never recomputed here. A block hash is Poseidon2 over a felt
 * encoding. Blake2 of the SCALE header, which is what a generic Substrate
 * client computes, is a different number that looks exactly as plausible.
 * Hashes come from `chain_getBlockHash` and from the node's own answers,
 * always.
 */

import type { DigestItem } from './digest';
import { authorLabel, decodeDigestLogs, sealPayload } from './digest';

export interface RawHeader {
  parentHash: string;
  number: string;
  stateRoot: string;
  extrinsicsRoot: string;
  zkTreeRoot: string;
  digest: { logs: string[] };
}

export interface BlockHeader {
  number: number;
  parentHash: string;
  stateRoot: string;
  extrinsicsRoot: string;
  zkTreeRoot: string;
  digestItems: DigestItem[];
  /** The `pow_` pre-runtime payload: a label for this block alone. */
  authorLabel: string | null;
  seal: string | null;
}

function requireHex(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    throw new Error(`a header's ${what} is not a hex string`);
  }
  return value;
}

export function parseHeader(raw: unknown): BlockHeader {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('chain_getHeader returned no header');
  }
  const source = raw as Record<string, unknown>;
  const digest = source['digest'];
  const logsValue =
    typeof digest === 'object' && digest !== null
      ? (digest as Record<string, unknown>)['logs']
      : undefined;
  const logs = Array.isArray(logsValue) ? logsValue.map((log) => requireHex(log, 'digest log')) : [];
  const items = decodeDigestLogs(logs);
  const numberHex = source['number'];
  if (typeof numberHex !== 'string') {
    throw new Error("a header's number is not a hex string");
  }
  return {
    number: Number(BigInt(numberHex)),
    parentHash: requireHex(source['parentHash'], 'parentHash'),
    stateRoot: requireHex(source['stateRoot'], 'stateRoot'),
    extrinsicsRoot: requireHex(source['extrinsicsRoot'], 'extrinsicsRoot'),
    zkTreeRoot: requireHex(source['zkTreeRoot'], 'zkTreeRoot'),
    digestItems: items,
    authorLabel: authorLabel(items),
    seal: sealPayload(items),
  };
}
