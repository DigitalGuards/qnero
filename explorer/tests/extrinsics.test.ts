import { describe, expect, it } from 'vitest';

import { decodeExtrinsic, type ExtrinsicLayout } from '../src/lib/extrinsics';
import { hexToBytes } from '../src/lib/hex';
import fixture from './fixtures/extrinsics.json' with { type: 'json' };

const layout: ExtrinsicLayout = {
  signatureLengths: new Map(fixture.layout.signatureLengths as [number, number][]),
  extensions: fixture.layout.extensions,
  multiAddress: fixture.layout.multiAddress,
};

function entry(block: string, index: number): { hex: string; bytes: number; truncated: boolean } {
  const found = fixture.entries.find((item) => item.block === block && item.index === index);
  if (found === undefined) {
    throw new Error(`no fixture for ${block} extrinsic ${index}`);
  }
  return found;
}

function decode(block: string, index: number): ReturnType<typeof decodeExtrinsic> {
  const item = entry(block, index);
  return decodeExtrinsic(hexToBytes(item.hex), index, layout);
}

describe('extrinsic envelopes', () => {
  it('reads the runtime’s signature lengths out of metadata rather than assuming one', () => {
    expect(layout.signatureLengths.get(0)).toBe(7219);
    expect(layout.signatureLengths.get(1)).toBe(5261);
    expect(layout.extensions).toHaveLength(11);
    expect(layout.multiAddress).toBe(true);
  });

  it('names the timestamp inherent, which is bare', () => {
    const envelope = decode('shield', 0);
    expect(envelope.kind).toBe('bare');
    expect(envelope.call).toEqual({ palletIndex: 1, callIndex: 0 });
    expect(envelope.unresolved).toBeNull();
  });

  it('names the coinbase inherent', () => {
    expect(decode('shield', 1).call).toEqual({ palletIndex: 24, callIndex: 3 });
  });

  it('reads both bare format versions this chain produces', () => {
    // The node writes its inherents at version 5 and the wallet writes its
    // settlements at version 4. A parser that pinned one would drop the other.
    expect(decode('shield', 0).version).toBe(5);
    expect(decode('shield', 1).version).toBe(5);
    expect(decode('settlement', 2).version).toBe(4);
    expect(decode('shield', 2).version).toBe(4);
  });

  it('walks a signed extrinsic past a 7219-byte ML-DSA-87 signature to its call', () => {
    const envelope = decode('shield', 2);
    expect(envelope.kind).toBe('signed');
    expect(envelope.call).toEqual({ palletIndex: 24, callIndex: 2 });
    expect(envelope.byteLength).toBe(entry('shield', 2).bytes);
    expect(envelope.unresolved).toBeNull();
  });

  it('names a settlement, which is unsigned and pays no account', () => {
    const envelope = decode('settlement', 2);
    expect(envelope.kind).toBe('bare');
    expect(envelope.call).toEqual({ palletIndex: 24, callIndex: 0 });
    expect(entry('settlement', 2).truncated).toBe(true);
  });

  it('leaves the call unresolved on an extension it does not know, rather than guessing a width', () => {
    const envelope = decodeExtrinsic(hexToBytes(entry('shield', 2).hex), 2, {
      ...layout,
      extensions: [...layout.extensions, 'CheckSomethingNew'],
    });
    expect(envelope.call).toBeNull();
    expect(envelope.unresolved).toMatch(/CheckSomethingNew/);
  });

  it('leaves the call unresolved on a signature scheme metadata does not declare', () => {
    const envelope = decodeExtrinsic(hexToBytes(entry('shield', 2).hex), 2, {
      ...layout,
      signatureLengths: new Map(),
    });
    expect(envelope.call).toBeNull();
    expect(envelope.unresolved).toMatch(/signature scheme/);
  });

  it('keeps the whole encoding in byteLength, which is what the hash covers', () => {
    for (const item of fixture.entries) {
      if (item.truncated) {
        continue;
      }
      expect(decodeExtrinsic(hexToBytes(item.hex), item.index, layout).byteLength).toBe(item.bytes);
    }
  });
});
