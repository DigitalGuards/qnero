/**
 * The anchor's two Blake2 roots, reduced before the prover sees them.
 *
 * `stateRoot` and `extrinsicsRoot` are Blake2-256 outputs, so each of their
 * four 8-byte little-endian limbs lands at or above the Goldilocks modulus
 * about once in four billion. The chain does not care: `HeaderInputs::new`
 * reduces both mod p and hashes what comes out. The browser prover module
 * decoded them strictly and refused any such limb, so a wallet could not
 * anchor at that block at all while the chain, the node and the CLI wallet all
 * hashed it happily.
 *
 * The module is fixed in `crates/qnero-prover-wasm/src/request.rs`, and the
 * reduction is done here as well, because the deployed wasm is prebuilt and
 * staged by digest: a module that still decodes strictly takes canonical bytes
 * and hashes them to the value the chain hashes.
 *
 * The vector below is the parity fixture
 * `request.rs::the_reduction_matches_the_browser_wallets_parity_vector`
 * asserts against the Rust reduction, one limb per case: `p + 1`, `u64::MAX`,
 * `p - 1` and `p` itself.
 */

import { describe, expect, it } from 'vitest';

import {
  anchorFromHeader,
  canonicalBlakeRoot,
  GOLDILOCKS_MODULUS,
  type RawChainHeader,
} from '../src/chain/anchor';

const NON_CANONICAL_VECTOR = '02000000ffffffffffffffffffffffff00000000ffffffff01000000ffffffff';
const REDUCED_VECTOR = '0100000000000000feffffff0000000000000000ffffffff0000000000000000';

/** One limb as eight little-endian bytes, the rest zero. */
function rootWithFirstLimb(value: bigint): string {
  const bytes = new Uint8Array(32);
  for (let byte = 0; byte < 8; byte += 1) {
    bytes[byte] = Number((value >> BigInt(8 * byte)) & 0xffn);
  }
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function header(stateRoot: string, extrinsicsRoot = `0x${'11'.repeat(32)}`): RawChainHeader {
  return {
    parentHash: `0x${'00'.repeat(32)}`,
    number: '0x7',
    stateRoot: stateRoot.startsWith('0x') ? stateRoot : `0x${stateRoot}`,
    extrinsicsRoot,
    zkTreeRoot: `0x${'01'.repeat(32)}`,
    digest: { logs: [] },
  };
}

describe('a Blake2 header root', () => {
  it('reduces every limb the way the chain does, on the shared parity vector', () => {
    expect(canonicalBlakeRoot(NON_CANONICAL_VECTOR)).toBe(REDUCED_VECTOR);
    expect(canonicalBlakeRoot(`0x${NON_CANONICAL_VECTOR}`)).toBe(REDUCED_VECTOR);
  });

  it('is one conditional subtraction, because 2p overflows a u64', () => {
    expect(canonicalBlakeRoot(rootWithFirstLimb(GOLDILOCKS_MODULUS - 1n))).toBe(
      rootWithFirstLimb(GOLDILOCKS_MODULUS - 1n),
    );
    expect(canonicalBlakeRoot(rootWithFirstLimb(GOLDILOCKS_MODULUS))).toBe(rootWithFirstLimb(0n));
    expect(canonicalBlakeRoot(rootWithFirstLimb(GOLDILOCKS_MODULUS + 1n))).toBe(
      rootWithFirstLimb(1n),
    );
  });

  it('leaves a root that is already canonical byte for byte', () => {
    const canonical = '00'.repeat(32);
    expect(canonicalBlakeRoot(canonical)).toBe(canonical);
    expect(canonicalBlakeRoot(REDUCED_VECTOR)).toBe(REDUCED_VECTOR);
  });

  it('refuses anything that is not 32 bytes', () => {
    expect(() => canonicalBlakeRoot('0x00')).toThrow(/32/);
  });
});

describe('the anchor a spend hands the prover', () => {
  it('hands over the reduced roots, so a strict decoder takes them', () => {
    const anchor = anchorFromHeader(header(NON_CANONICAL_VECTOR, `0x${NON_CANONICAL_VECTOR}`));
    expect(anchor.state_root).toBe(REDUCED_VECTOR);
    expect(anchor.extrinsics_root).toBe(REDUCED_VECTOR);
  });

  it('builds the same anchor from a raw root as from the reduced one', () => {
    // The equality is the property: the chain reduces, so the two headers are
    // one header as far as `block_hash` is concerned, and the prover has to
    // agree. Asserting it here needs no wasm.
    expect(anchorFromHeader(header(NON_CANONICAL_VECTOR))).toEqual(
      anchorFromHeader(header(REDUCED_VECTOR)),
    );
  });

  it('passes the two Poseidon2 fields through untouched', () => {
    // Their limbs are circuit outputs and are canonical already. A header
    // carrying one that is not is a header the prover should refuse by name,
    // which `request.rs` still does.
    const raw = header(REDUCED_VECTOR);
    raw.parentHash = `0x${NON_CANONICAL_VECTOR}`;
    raw.zkTreeRoot = `0x${NON_CANONICAL_VECTOR}`;
    const anchor = anchorFromHeader(raw);
    expect(anchor.parent_hash).toBe(NON_CANONICAL_VECTOR);
    expect(anchor.zk_tree_root).toBe(NON_CANONICAL_VECTOR);
  });
});
