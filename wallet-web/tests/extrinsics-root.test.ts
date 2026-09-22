/**
 * What authenticates a block body, and what a body this wallet will not read
 * looks like.
 *
 * Note ciphertexts are in block bodies and in no state map, so a body is the
 * read that makes an incoming payment readable at all, and a node that can
 * choose what is in one can choose which payments this wallet sees. Three
 * steps decide it, in this order: the header at the hash asked for is rehashed
 * from its own preimage, the body beside it is fetched, and the body is rooted
 * and compared against that header's `extrinsicsRoot`.
 *
 * # What is asserted here and what is not
 *
 * The trie construction itself is not. It is `LayoutV0<Blake2Hasher>::
 * ordered_trie_root`, which is what `frame_system` reaches while the runtime's
 * `system_version` is 1, and it lives in the prover module because that module
 * already links sp-trie: two implementations of one consensus construction
 * would be two ways to disagree with the chain, and a TypeScript re-write here
 * would be the second. It is covered in Rust, against the runtime's own
 * answer, in `crates/qnero-state-proof/tests/extrinsics_root_kat.rs`.
 *
 * What is asserted here is the wiring: that the body this page sends the
 * module is the body the node served, in order, unchanged; that the answer is
 * compared against the header's field and a disagreement refuses; and the
 * three refusals that happen before the module is called at all. The known
 * answer is read from the same fixture file the Rust test reads, so the
 * request this page makes is pinned to a body whose root is byte fixed.
 *
 * **Release check, left to the release runbook:** that a rebuilt module answers
 * `KAT.root` for `KAT.extrinsics`. The `extrinsicsRoot` export exists in the
 * crate and the staged modules under `public/wasm` predate it, so it is a
 * runbook item for the release qualification, run against a module built on a
 * machine that can build one.
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import type { ChainContext } from '../src/chain/api';
import {
  authenticatedBody,
  bindStateProofVerifier,
  MAX_BODY_BYTES,
  MAX_BODY_EXTRINSICS,
} from '../src/chain/authenticated';
import { blockPayloads, extrinsicPayloads } from '../src/chain/body';
import { hexToBytes } from '../src/lib/hex';
import {
  coinbaseExtrinsic,
  settlementExtrinsic,
  shieldExtrinsic,
  TEST_BODY_LAYOUT,
  timestampExtrinsic,
  transferExtrinsic,
} from './fixtures/body';

/**
 * The byte-fixed body and root both wallets are held to.
 *
 * One file, read by this test and by `extrinsics_root_kat.rs`, so the browser
 * and the command-line wallet cannot drift apart on what a body roots to. The
 * runtime writes its own copy out of a block it executed, and that one is the
 * authority.
 */
const KAT = JSON.parse(
  readFileSync(
    new URL(
      '../../crates/qnero-state-proof/tests/fixtures/extrinsics_root_kat.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as { extrinsics: string[]; root: string };

const AT = `0x${'aa'.repeat(32)}`;

/**
 * A node that serves one header and one body.
 *
 * The header hashes to `AT` unless a test says otherwise, because a header
 * that does not is the first refusal and the `extrinsicsRoot` inside it is
 * then a number a node chose.
 */
function node(options: {
  body?: unknown;
  headerRoot?: string;
  answersRoot?: string;
  hashesTo?: string;
}): { context: ChainContext; calls: { method: string; params: unknown[] }[] } {
  const calls: { method: string; params: unknown[] }[] = [];
  const context = {
    send: <T,>(method: string, params: unknown[]): Promise<T> => {
      calls.push({ method, params });
      if (method === 'chain_getHeader') {
        return Promise.resolve({
          parentHash: `0x${'00'.repeat(32)}`,
          number: '0x9',
          stateRoot: `0x${'11'.repeat(32)}`,
          extrinsicsRoot: options.headerRoot ?? KAT.root,
          zkTreeRoot: `0x${'33'.repeat(32)}`,
          digest: { logs: [] },
        } as T);
      }
      if (method === 'chain_getBlock') {
        return Promise.resolve({ block: { extrinsics: options.body ?? KAT.extrinsics } } as T);
      }
      throw new Error(`this fixture answers no ${method}`);
    },
  } as unknown as ChainContext;
  bindStateProofVerifier(context, {
    headerBlockHash: () => Promise.resolve(options.hashesTo ?? AT),
    // Stood in for. The construction is the module's and is covered in Rust;
    // what a test needs here is an answer it chose, so the comparison against
    // the header can be driven in both directions.
    extrinsicsRoot: () => Promise.resolve(options.answersRoot ?? KAT.root),
    readStateProof: () => Promise.resolve([]),
    readStatePrefix: () => Promise.resolve([]),
  });
  return { context, calls };
}

describe('the body a header carries', () => {
  it('sends the module the bytes the node served, in order and unchanged', async () => {
    const { context, calls } = node({});
    const asked = vi.fn(() => Promise.resolve(KAT.root));
    bindStateProofVerifier(context, {
      headerBlockHash: () => Promise.resolve(AT),
      extrinsicsRoot: asked,
      readStateProof: () => Promise.resolve([]),
      readStatePrefix: () => Promise.resolve([]),
    });

    expect(await authenticatedBody(context, AT)).toEqual(KAT.extrinsics);
    // The request shape, pinned: one list of `0x` hex extrinsics, in body
    // order, with each one's compact length prefix still on it. The trie is
    // keyed by the index, so a page that reordered or re-encoded them would
    // reach a root no header carries.
    expect(asked).toHaveBeenCalledWith(KAT.extrinsics);
    // And the order of the three steps: the header first, because its
    // `extrinsicsRoot` is what the body is checked against.
    expect(calls.map((call) => call.method)).toEqual(['chain_getHeader', 'chain_getBlock']);
  });

  it('refuses a header that does not hash to the block asked for', async () => {
    // The first step, and everything rests on it: a header that does not hash
    // to its own name authenticates no body, because its `extrinsicsRoot` is
    // then a number the node picked to match whatever it was about to serve.
    const { context, calls } = node({ hashesTo: `0x${'bb'.repeat(32)}` });
    await expect(authenticatedBody(context, AT)).rejects.toThrow(/hashes to another block/);
    // And no body was fetched at all.
    expect(calls.map((call) => call.method)).toEqual(['chain_getHeader']);
  });

  it('refuses a body one flipped byte from the one the header carries', async () => {
    // The module answers over the bytes it was handed, so a flipped byte is a
    // different root, and the header does not carry it. This drives the
    // comparison from the answer's side, which is the side a node controls.
    const flipped = [...KAT.extrinsics];
    const target = flipped[1] as string;
    flipped[1] = `${target.slice(0, 10)}${(Number.parseInt(target.slice(10, 12), 16) ^ 1)
      .toString(16)
      .padStart(2, '0')}${target.slice(12)}`;
    const { context } = node({
      body: flipped,
      answersRoot: `0x${'cd'.repeat(32)}`,
    });
    await expect(authenticatedBody(context, AT)).rejects.toThrow(
      /roots to 0xcdcd.* where the extrinsicsRoot in the header it hashes to is/,
    );
  });

  it('refuses a body above the byte budget before anything is hashed', async () => {
    // `RuntimeBlockLength` lets a block carry 5 MiB of extrinsic data and this
    // stops at 6, which covers the compact length prefixes `chain_getBlock`
    // hands each extrinsic over with. The guard runs on the page, before a
    // node's answer is copied across the worker boundary at all.
    const one = `0x${'00'.repeat(1024 * 1024)}`;
    const { context, calls } = node({ body: Array.from({ length: 7 }, () => one) });
    await expect(authenticatedBody(context, AT)).rejects.toThrow(
      new RegExp(`above ${MAX_BODY_BYTES} bytes`),
    );
    expect(calls.map((call) => call.method)).toEqual(['chain_getHeader', 'chain_getBlock']);
  });

  it('refuses a body above the extrinsic-count budget before anything is hashed', async () => {
    // The trie is keyed by `Compact<u32>` of the index, so the construction has
    // no count limit of its own. This one is a memory guard on what a node can
    // hand over before anything is allocated per item.
    const { context } = node({
      body: Array.from({ length: MAX_BODY_EXTRINSICS + 1 }, () => '0x'),
    });
    await expect(authenticatedBody(context, AT)).rejects.toThrow(
      new RegExp(`above the ${MAX_BODY_EXTRINSICS} this wallet will hash`),
    );
  });

  it('refuses a block the node serves a header for and no body', async () => {
    // The one failure the body path has that the state path did not, and the
    // whole of it: a body roots as a whole, so there is no per-payload absence
    // left to detect. Reading it as a block that carried nothing would step
    // over every payment in it and write a watermark above the lot.
    for (const body of [undefined, null, 'not a list'] as unknown[]) {
      const { context } = node({});
      const broken = {
        ...context,
        send: <T,>(method: string, params: unknown[]): Promise<T> =>
          method === 'chain_getBlock'
            ? Promise.resolve({ block: { extrinsics: body } } as T)
            : context.send<T>(method, params),
      };
      bindStateProofVerifier(broken, {
        headerBlockHash: () => Promise.resolve(AT),
        extrinsicsRoot: () => Promise.resolve(KAT.root),
        readStateProof: () => Promise.resolve([]),
        readStatePrefix: () => Promise.resolve([]),
      });
      await expect(authenticatedBody(broken, AT)).rejects.toThrow(/and no body beside it/);
    }
  });
});

describe('the walk out of a body', () => {
  it('reads both ciphertexts of every settled slot and nothing else', () => {
    const first = new Uint8Array([1, 1, 1]);
    const second = new Uint8Array([2, 2, 2]);
    const third = new Uint8Array([3, 3, 3]);
    const fourth = new Uint8Array([4, 4, 4]);
    const body = [
      timestampExtrinsic(1000),
      settlementExtrinsic([
        [first, second],
        [third, fourth],
      ]),
      coinbaseExtrinsic(),
    ];
    expect(blockPayloads(TEST_BODY_LAYOUT, body)).toEqual([first, second, third, fourth]);
  });

  it("reads a shield's ciphertext out past its ML-DSA-87 signature", () => {
    // A generic Substrate client cannot: the signature is a fixed 7219-byte
    // array and polkadot-js refuses a fixed array above 2048, so
    // `chain_getBlock` through a typed API throws on every block carrying one.
    const payload = new Uint8Array([7, 7, 7, 7]);
    expect(blockPayloads(TEST_BODY_LAYOUT, [shieldExtrinsic(payload, 10n)])).toEqual([payload]);
  });

  it('reads nothing out of a transparent transfer, whose arguments it walks past', () => {
    // The sender, the recipient and the amount are in the body forever. The
    // walk goes as far as the call index and stops.
    expect(blockPayloads(TEST_BODY_LAYOUT, [transferExtrinsic()])).toEqual([]);
  });

  it('refuses an extension it cannot lay out rather than guessing its width', () => {
    // An extension this wallet does not know shifts the call index as surely
    // as it shifts a signature, and a call index read off by one is a payload
    // silently not found.
    const payload = new Uint8Array([7, 7, 7, 7]);
    expect(() =>
      extrinsicPayloads(
        { ...TEST_BODY_LAYOUT, extensions: [...TEST_BODY_LAYOUT.extensions, 'CheckSomethingNew'] },
        hexToBytes(shieldExtrinsic(payload)),
      ),
    ).toThrow(/transaction extension this wallet cannot lay out/);
  });

  it('refuses a call whose arguments it decodes short, naming the whole body position', () => {
    // A call this wallet decodes short is a call whose shape has moved, and
    // reading a payload out of the wrong offsets is how a payment goes missing
    // without anything saying so.
    const settlement = settlementExtrinsic([[new Uint8Array([1]), new Uint8Array([2])]]);
    const truncated = settlement.slice(0, -2);
    expect(() => blockPayloads(TEST_BODY_LAYOUT, [truncated])).toThrow(
      /extrinsic 0 of this block cannot be walked/,
    );
  });
});
