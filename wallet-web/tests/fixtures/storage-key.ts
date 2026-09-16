import { xxhashAsHex } from '@polkadot/util-crypto';

export function storagePrefix(pallet: string, item: string): string {
  return xxhashAsHex(pallet, 128) + xxhashAsHex(item, 128).slice(2);
}

export function indexKey(index: number): string {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(index), true);
  return Buffer.from(bytes).toString('hex');
}

export function indexOfKey(key: string, prefix: string): number {
  const bytes = Buffer.from(key.slice(prefix.length), 'hex');
  return Number(bytes.readBigUInt64LE());
}
