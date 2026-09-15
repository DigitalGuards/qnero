/**
 * One payment, end to end.
 *
 * The order here is a set of rules rather than a convenience, and each step
 * names the failure it exists to prevent. `docs/WALLET.md` section G is the
 * authority and `crates/qnero-wallet/src/wallet.rs` is the implementation this
 * mirrors.
 *
 * 0. **The chain first, read off the node.** The store is bound to a genesis
 *    hash by its first committed operation, and every note's `leafIndex` is an
 *    index into that chain's tree. A node on another chain rebuilds another tree, and the root
 *    gate below passes over it, because a rebuild over that node's own leaves
 *    roots to that node's own header. What follows is either a phantom note
 *    written off on a chain it never lived on, or a leaf mismatch reported as
 *    a stale store. `Wallet::prepare_spend` opens with this check and so does
 *    this, before a fee is computed.
 * 1. **The fee floor first**, measured from the ciphertexts the submission
 *    will actually carry. The fee is a public input fixed at proving time, so
 *    a low one costs a whole 33-second proof and comes back as
 *    `PayloadUnderpaid`.
 * 2. **The memo pad**, checked against both of the runtime's bounds. Over the
 *    cap is a refusal; a runtime whose divisor merged the two fee buckets is a
 *    warning and the spend goes ahead, because the operator cannot change the
 *    divisor and a wallet shrinking its own pad below everyone else's would
 *    publish its own ciphertext length.
 * 3. **Selection**, largest first, at most two, ties on the lowest leaf index
 *    so a retry proves the same leaf.
 * 4. **Build the circuits**, then take the anchor. Not the other way round:
 *    the anchor block is a public input, so anchoring before a twelve-second
 *    build would publish this machine's build time in the anchor-to-inclusion
 *    gap.
 * 5. **The anchor is the current head**, taken fresh per submission. An anchor
 *    at head minus k, or one cached across two spends, is a distinguisher
 *    inside the 256-block window marking both spends as one wallet's.
 * 6. **The node's own tree against this wallet's watermark, then the rebuild
 *    before proving.** The watermark gate first, the one `runSync` refuses a
 *    short node with: a note's leaf index is always below the watermark that
 *    recorded it, so everything below, the phantom write-off included, rests
 *    on this node being at or ahead of every leaf the store has read. Then the
 *    rebuilt root against the header's `zkTreeRoot`, because that is what
 *    makes a leaf index mean anything, then each leaf against its own
 *    commitment, then each path's recomputed root against the header.
 * 7. **Draw the payment's output slot.** The circuit derives each output's
 *    `rho` from its slot index, so either assignment proves and settles
 *    unchanged, and a fixed assignment would tell every chain reader which of
 *    a settlement's two leaves is the sender's change.
 * 8. **Prove, verify locally, write the change note, then submit.** What that
 *    row is, exactly: a claim that the note exists, so a balance shown before
 *    the next sync includes the change. It seals no randomness, and what lets
 *    it is the recovery: the circuit derives the change note's `rho` from its
 *    output slot, the proving module draws its `r` per output
 *    (`crates/qnero-prover-wasm/src/request.rs`), and both come back by
 *    decrypting this wallet's own ciphertext off the chain, which needs only
 *    the seed. The order is kept for the weaker reason: a tab reclaimed
 *    between the submit and the write shows a balance missing its own change
 *    until the next sync reaches it.
 * 9. **And the row goes when the settlement does not.** A submission the pool
 *    refuses, a segment skipped for a stale anchor or a claimed nullifier, and
 *    a settlement nothing carries inside the window all leave a change
 *    commitment that is never appended, so no scan can meet it and clear the
 *    row. A sync drops one anchored outside the window for the same reason.
 */

import type { ChainContext } from '../chain/api';
import { anchorFromHeader, parseRawHeader, type Anchor } from '../chain/anchor';
import { blockHashAt, fetchHead, fetchLeafHashes, fetchTreeShape, headerAt } from '../chain/reads';
import { encodeSettlement, submitSettlement, waitForInclusion } from '../chain/submit';
import type { ProverClient } from '../worker/client';
import type { ProverLimits } from '../worker/protocol';
import {
  ensureCiphertextFits,
  ensureMemoPadFits,
  memoPadSeparationWarning,
  slotFeeFloor,
} from './fee';
import { normaliseHash } from '../lib/hex';
import { memoRefusal } from '../lib/memo';
import { formatStepsAsQnr } from '../lib/units';
import { birthdayWatermarkNote, unscannedBirthday, type NoteSecret, type PendingNote, type StoredNote } from './model';
import { selectNotes } from './select';
import type { WalletStore } from './store';

export interface SpendRequest {
  to: string;
  /** The amount, as a count of pool steps. */
  amount: bigint;
  memo: string;
  /** The wallet's own address, which the change note is written to. */
  changeAddress: string;
  /** Notes this spend may choose from: on chain, unspent, one per nullifier. */
  candidates: readonly { note: StoredNote; secret: NoteSecret }[];
  /** Override of the computed floor. Never below it. */
  fee?: bigint;
}

export interface SpendProgress {
  stage:
    | 'fee'
    | 'select'
    | 'build'
    | 'anchor'
    | 'tree'
    | 'prove'
    | 'submit'
    | 'confirm'
    | 'done';
  detail?: string;
}

export interface SpendResult {
  /** What was paid, and to whom. The two facts the payment was about. */
  to: string;
  amount: bigint;
  fee: bigint;
  change: bigint;
  inputs: { commitment: string; value: bigint }[];
  /** The two commitments the settlement publishes, in slot order. */
  commitments: [string, string];
  nullifiers: [string, string];
  /** Which slot the payment landed in. Drawn, so it is reported rather than assumed. */
  paymentSlot: 1 | 2;
  extrinsicHash: string;
  proofBytes: number;
  proveMillis: number;
  phases: { phase: string; millis: number }[];
  peakLinearMemoryBytes: number;
  inclusion: { blockNumber: number; blockHash: string; settled: boolean } | null;
  warnings: string[];
}

/**
 * The refusal a store bound to one chain owes a node serving another, or null.
 *
 * One function, called twice: once by the page, against the hash the
 * connection was opened with, so the message renders where a spend error
 * renders without a round trip, and once at the top of [`spend`], against a
 * hash read off the node, so the non-UI path cannot skip it and a reconnected
 * socket cannot answer for a chain that is no longer there. `runSync` writes the same refusal from its own gate
 * (`wallet/sync.ts`), and the wording is the same on purpose: it is the same
 * mistake, met on a different screen.
 */
export function chainMismatchRefusal(
  storeGenesis: string | null,
  nodeGenesis: string | undefined,
): string | null {
  if (storeGenesis === null || nodeGenesis === undefined) {
    // An unbound store is one that has never committed a sync, and it binds
    // itself to the first chain it commits against. There is nothing to
    // disagree with yet.
    return null;
  }
  if (normaliseHash(storeGenesis) === normaliseHash(nodeGenesis)) {
    return null;
  }
  return (
    `this wallet is bound to the chain whose genesis is ${storeGenesis} and this node serves ` +
    `${nodeGenesis}. Every transfer it holds is an index into the other chain's tree, so ` +
    'nothing has been built and nothing has been written off. Point the wallet at a node on ' +
    'its own chain.'
  );
}

/** The floor this spend owes, from the runtime's constants and the pad. */
export function feeFloorFor(context: ChainContext, limits: ProverLimits): bigint {
  return slotFeeFloor(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.padded_ciphertext_bytes,
  );
}

export async function spend(
  context: ChainContext,
  prover: ProverClient,
  store: WalletStore,
  request: SpendRequest,
  limits: ProverLimits,
  report: (progress: SpendProgress) => void,
): Promise<SpendResult> {
  const warnings: string[] = [];

  if (context.storageDrift.length > 0) {
    // The gate the sync opens with, here too, for the reason its own comment
    // gives: an absent key and an empty map are the same answer, and this path
    // reads a leaf count and a tree.
    throw new Error(
      'this runtime declares storage differently from what this build assumes, so spending ' +
        `against it is refused: ${context.storageDrift.join('; ')}. Nothing has been built and ` +
        'nothing has been submitted.',
    );
  }

  // Before the fee, before the selection, before anything is read. A wrong
  // node here is a note written off on a chain it never lived on.
  //
  // Read off the node rather than off the connection. `ChainContext.genesisHash`
  // is captured once, when the socket was first opened, and a `WsProvider`
  // reconnects on its own: a tab left open across a chain relaunch at the same
  // URL reconnects to a different chain with the cached hash still naming the
  // old one. The root gate below then passes, because a rebuild over that
  // node's leaves roots to that node's own header, and every selected note is
  // written off as a note the chain does not carry. `runSync` reads block zero
  // live for the same reason, and so does the command-line wallet on every
  // sync, shield and spend.
  const nodeGenesis = await blockHashAt(context, 0);
  if (nodeGenesis === null) {
    throw new Error(
      'this node has no block zero, so it cannot say which chain it serves. Nothing has been built.',
    );
  }
  // Read once and held: the genesis binding is one field of it, and the leaf
  // watermark the tree gate below compares against is another.
  const meta = await store.meta();
  const mismatch = chainMismatchRefusal(meta.genesisHash, nodeGenesis);
  if (mismatch !== null) {
    throw new Error(mismatch);
  }

  report({ stage: 'fee' });
  // The memo against the pad, before anything is measured. The send screen
  // refuses the same bound where it is typed, from the same function.
  const refusal = memoRefusal(request.memo, limits.memo_bytes);
  if (refusal !== null) {
    throw new Error(`${refusal}. Nothing has been built.`);
  }
  // The recipient, checked before anything is built. A Qnero address is about
  // 2,600 characters, so a truncated paste is the ordinary mistake, and the
  // module decodes it at the end of the proving call: after the circuit build,
  // the anchor read and a rebuild of every leaf on the chain. The send form
  // refuses the same thing as it is typed, through the same check.
  //
  // Trimmed once, and the trimmed value is what is paid, so the address that
  // passed the checksum is the address the proof commits to.
  const recipient = request.to.trim();
  if (!(await prover.addressIsValid(recipient))) {
    throw new Error(
      'that is not a valid Qnero address: its bech32m checksum does not hold, which is what a ' +
        'truncated or edited paste looks like. Nothing has been built.',
    );
  }
  // The pad against both of the runtime's bounds. The cap is a refusal, the
  // divisor is a warning: see `fee.ts`.
  ensureMemoPadFits(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.memo_bytes,
    limits.ciphertext_fixed_bytes,
  );
  const separation = memoPadSeparationWarning(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.memo_bytes,
    limits.ciphertext_fixed_bytes,
  );
  if (separation !== null) {
    warnings.push(separation);
  }
  ensureCiphertextFits(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.memo_bytes,
    'payment',
  );

  const floor = feeFloorFor(context, limits);
  const fee = request.fee ?? floor;
  if (fee < floor) {
    throw new Error(
      `this runtime's floor for one slot is ${formatStepsAsQnr(floor)} and this spend offers ` +
        `${formatStepsAsQnr(fee)}. The fee is a public input fixed at proving time, so an ` +
        'underpaid one costs the whole proof and comes back as PayloadUnderpaid.',
    );
  }

  report({ stage: 'select' });
  const target = request.amount + fee;
  const selection = selectNotes(
    request.candidates.map((candidate) => candidate.note),
    target,
  );
  const chosen = selection.notes.map((note) => {
    const held = request.candidates.find(
      (candidate) => candidate.note.commitment === note.commitment,
    );
    if (held === undefined) {
      throw new Error('a selected transfer lost its secrets between selection and proving');
    }
    return held;
  });
  const change = selection.total - target;

  // The circuits first, then the anchor. Reversing these two publishes this
  // machine's build time in the anchor-to-inclusion gap.
  report({ stage: 'build' });
  await prover.buildProver();

  report({ stage: 'anchor' });
  const head = await fetchHead(context);
  const raw = await headerAt(context, head.hash);
  const anchor: Anchor = anchorFromHeader(parseRawHeader(raw));
  // The rebuild the wallet did of the header preimage, hashed by the circuit's
  // own function and compared against what the chain says. The digest
  // re-encoding is the part that goes wrong, and the alternative to checking
  // is paying for the proof and reading `BlockHashMismatch`.
  const recomputed = await prover.headerBlockHash(anchor);
  if (recomputed.toLowerCase() !== head.hash.toLowerCase().replace(/^0x/, '')) {
    throw new Error(
      `the header this wallet rebuilt for block ${anchor.block_number} hashes to ${recomputed} ` +
        `where the chain says ${head.hash}. Proving against it would be refused with ` +
        'BlockHashMismatch.',
    );
  }

  report({ stage: 'tree', detail: 'rebuilding the tree at the anchor' });
  const shape = await fetchTreeShape(context, head.hash, limits.max_tree_depth);
  // The leaf gate, before a single note is looked at, and it is the gate
  // `runSync` already refuses this node with (`wallet/sync.ts`). Every other
  // check below is against this node's own answers: the rebuild roots to this
  // node's own header, so a node whose tree is shorter than what this wallet
  // has already read passes all of them and still reaches the write-off below,
  // which then marks a real, canonical, spendable note off chain. A losing
  // fork, a rolled-back snapshot and a head this node has not finished
  // executing all have that shape, and none of them is a statement that the
  // chain dropped a leaf.
  //
  // On a node that is not behind it can never fire: a note's `leafIndex` was
  // read below the watermark that recorded it, and a tree only grows along one
  // chain, so any head at or above that point holds at least that many leaves.
  if (shape.leafCount < meta.nextLeaf) {
    // A watermark that is still a birthday's own count was never checked
    // against a header, so "sync first" is advice no node can take: the
    // sentence says whose number it is and what drops it.
    const birthdayBlock = unscannedBirthday(meta.birthday, meta.nextLeaf);
    throw new Error(
      `this node reports ${shape.leafCount} leaves at its head and this wallet has already read ` +
        `${meta.nextLeaf}. A node on this chain whose leaf count is short has a head it has not ` +
        'finished executing, so the leaf indices this wallet holds cannot be checked against it. ' +
        'Nothing has been written off and nothing has been submitted. ' +
        // Syncing works for every node that is behind and for nothing else, so
        // where the watermark itself is the unchecked number the advice is
        // replaced rather than followed by a contradiction.
        (birthdayBlock === null ? 'Sync first.' : birthdayWatermarkNote(birthdayBlock)),
    );
  }
  const leafHashes = await fetchLeafHashes(
    context,
    0,
    shape.leafCount,
    head.hash,
    shape.leafCount,
    (done) => {
      report({ stage: 'tree', detail: `${done} of ${shape.leafCount} leaves` });
    },
  );

  // The root gate first. Without it a leaf index means nothing at all, and
  // every check after it would be comparing against a tree the anchor does not
  // commit to.
  const rebuiltRoot = await prover.treeRoot(copyOf(leafHashes), shape.depth);
  if (rebuiltRoot.toLowerCase() !== anchor.zk_tree_root.toLowerCase()) {
    throw new Error(
      `the tree this wallet rebuilt over ${shape.leafCount} leaves at depth ${shape.depth} roots ` +
        `to ${rebuiltRoot} and the anchor header says ${anchor.zk_tree_root}. Nothing has been ` +
        'proved. Sync again: the node may have appended a leaf between the two reads.',
    );
  }

  const inputs = [];
  for (const held of chosen) {
    if (held.note.leafIndex >= shape.leafCount) {
      // Past the end of a tree that roots correctly. Either the leaf is not
      // folded yet, which is "wait one block", or the store recorded its block
      // strictly below the anchor, which makes it a note this chain does not
      // carry. Reporting the second as a race leaves somebody retrying
      // forever, because selection picks the same phantom every time.
      const recordedBelow =
        held.note.blockNumber !== null && held.note.blockNumber < anchor.block_number;
      if (recordedBelow) {
        // Written off here rather than left for a sync to notice. The sync's
        // orphan marking runs only when a checkpoint walk rewound, and a
        // rescan never runs it at all, so "sync so it is marked off chain"
        // would be advice that does not always hold and selection would pick
        // the same phantom on every retry.
        await store.markOffChain(held.note.commitment);
        throw new Error(
          `the transfer ${held.note.commitment} is recorded at leaf ${held.note.leafIndex}, ` +
            `which is past the end of a ${shape.leafCount}-leaf tree the anchor confirms, and ` +
            `it was recorded at block ${held.note.blockNumber}, below the anchor. This chain ` +
            'does not carry it, so it is marked off chain. Send again: the next selection will ' +
            'not offer it. To look for it again, rescan from Settings against a second node: ' +
            'an ordinary sync starts at the watermark, so a leaf below it is never read again.',
        );
      }
      throw new Error(
        `the transfer ${held.note.commitment} sits at leaf ${held.note.leafIndex} and the ` +
          `tree at the anchor holds ${shape.leafCount}. A payment cannot be received and spent ` +
          'in the same block: wait one block and send again.',
      );
    }
    const path = await prover.treePath(copyOf(leafHashes), shape.depth, held.note.leafIndex);
    if (path.leaf.toLowerCase() !== held.note.commitment.toLowerCase()) {
      // The note is at an index this chain holds something else at, and the
      // tree it was read from roots at the value the anchor header carries, so
      // the chain is not the thing that is wrong. An ordinary sync cannot
      // repair it: the leaf is below the watermark and a pass starts above it.
      // The rescan on the Settings screen reads the range again from leaf
      // zero and moves the note to the index the chain holds it at, which is
      // also the recovery for a leaf a node moved inside its own group of
      // four (`docs/WALLET.md`, "What bound A does not cover").
      throw new Error(
        `leaf ${held.note.leafIndex} carries ${path.leaf} on this chain and this wallet holds ` +
          `a transfer whose tree entry is ${held.note.commitment}. Rescan from Settings, ` +
          'against a second node where there is one: this leaf is below the watermark, so an ' +
          'ordinary sync starts above it and never reads it again.',
      );
    }
    if (path.root.toLowerCase() !== anchor.zk_tree_root.toLowerCase()) {
      throw new Error(
        `the path for leaf ${held.note.leafIndex} reaches ${path.root} and the anchor header ` +
          `says ${anchor.zk_tree_root}.`,
      );
    }
    inputs.push({
      value: held.note.value,
      rho: held.secret.rho,
      r: held.secret.r,
      path: { siblings: path.siblings, positions: path.positions },
    });
  }

  // The payment's slot is drawn. Both outputs are the same size and the
  // circuit derives each `rho` from its slot index, so either assignment
  // proves and settles unchanged; a fixed one would split every settlement's
  // outputs publicly into "counterparty" and "sender's change".
  const draw = crypto.getRandomValues(new Uint8Array(1))[0] ?? 0;
  const paymentSlot: 1 | 2 = draw % 2 === 0 ? 1 : 2;
  const payment = { address: recipient, value: request.amount.toString(), memo: request.memo };
  const changeOutput = {
    address: request.changeAddress,
    value: change.toString(),
    // A change memo is always empty, which is why both are padded to one size.
    memo: '',
  };
  const outputs = paymentSlot === 1 ? [payment, changeOutput] : [changeOutput, payment];

  report({ stage: 'prove', detail: 'the circuits are built; proving one private batch' });
  const proveStarted = performance.now();
  const submission = await prover.proveTransfer({
    anchor,
    tree_depth: shape.depth,
    fee: fee.toString(),
    inputs,
    outputs,
  });
  const proveMillis = performance.now() - proveStarted;

  // The two ciphertexts the fee was computed from have to be the two the
  // submission carries. Equal to each other, because a difference is the leak
  // the padding closes, and equal to the pad, because the fee is already
  // fixed inside the proof.
  const [size1, size2] = submission.report.ciphertext_bytes;
  if (size1 !== size2) {
    throw new Error(
      `this submission's ciphertexts are ${size1} and ${size2} bytes. A difference is the memo ` +
        'length in the clear, which is the leak the pad closes. Nothing has been submitted.',
    );
  }
  if (size1 !== limits.padded_ciphertext_bytes) {
    throw new Error(
      `the fee was computed from ${limits.padded_ciphertext_bytes}-byte ciphertexts and this ` +
        `submission carries ${size1}. Nothing has been submitted.`,
    );
  }

  report({ stage: 'submit' });
  const encoded = encodeSettlement(context, submission.proof, [
    { ct1: submission.ct1, ct2: submission.ct2 },
  ]);

  // Before the submission, in one committed transaction. Not because the row
  // holds the only copy of anything: it seals empty strings, and the change
  // note's randomness comes back by decrypting this wallet's own ciphertext
  // off the chain. It is written first so a tab reclaimed between the two
  // still shows the change in its balance.
  const changeCommitment = submission.report.public_inputs.commitments[paymentSlot === 1 ? 1 : 0];
  const pending: PendingNote = {
    commitment: changeCommitment,
    kind: 'change',
    value: change.toString(),
    submittedAtBlock: anchor.block_number,
    secret: await store.sealPendingSecret(changeCommitment, {
      // Empty because neither value's only copy is here. The circuit derives
      // the change note's `rho` from its output slot and the proving module
      // draws its `r` per output, so `r` is fresh randomness, and it rides in
      // the ciphertext the settlement publishes: the next scan decrypts this
      // wallet's own ciphertext with the seed and recovers both. What is
      // recorded here is the claim that the note exists, so a sync that has
      // not reached it still shows it.
      rho: '',
      r: '',
      nullifier: '',
      memo: '',
    }),
  };
  await store.commitPending(pending);

  let extrinsicHash: string;
  try {
    extrinsicHash = await submitSettlement(context, encoded);
  } catch (error) {
    // The row goes with the submission that did not happen. It is written
    // first so a tab reclaimed in the gap still shows the change, and there is
    // no gap left to cover once the pool has refused: leaving it makes a
    // pending figure that no sync can ever clear, because the commitment it
    // waits for was never appended.
    await store.dropPending(changeCommitment);
    throw error;
  }

  report({ stage: 'confirm', detail: 'waiting for the settlement to land' });
  const inclusion = await waitForInclusion(
    context,
    encoded,
    submission.report.public_inputs.nullifiers,
    {
      // Six block intervals: the five an unsigned settlement keeps in the pool
      // under `longevity(5)`, plus the one it was submitted inside. That window
      // is the real bound, because inside it the submission is still live and
      // will almost certainly land; past it the answer is to prove again
      // against a fresh anchor, which is what this screen then says.
      //
      // Denominated in the chain's own interval, floored at the two minutes a
      // dev chain used to get. A flat 120 000 ms was one whole block interval
      // at the public 120 s target: the residual wait to the next block is
      // exponential with a mean of one interval, so about a third of correct
      // payments would have been reported as failed, their change row dropped
      // and their inputs left unlatched while the settlement landed anyway.
      timeoutMs: Math.max(120_000, context.targetBlockTimeMs * 6),
      // These bytes did not exist before the anchor, so no block at or below
      // it can carry them and none after it is skipped.
      fromBlock: anchor.block_number,
      onBlock: (height) => {
        report({ stage: 'confirm', detail: `block ${height}` });
      },
    },
  );

  if (inclusion === null || !inclusion.settled) {
    // In a block and skipped, or nowhere inside the window. Either way this
    // settlement is not the one that appends the change note, and the screen
    // tells the reader to prove again against a fresh anchor. The row it would
    // otherwise leave behind is the balance's, forever.
    await store.dropPending(changeCommitment);
  }

  if (inclusion !== null && inclusion.settled) {
    // Latch the flag now, on the nullifiers rather than on the commitments. A
    // send that happens before the next sync would otherwise select the other
    // member of a conflict set, which carries the nullifier the chain has just
    // settled. See `WalletStore.markSpentByNullifier`.
    await store.markSpentByNullifier(
      chosen.map((held) => held.secret.nullifier),
      inclusion.blockNumber,
    );
  }

  report({ stage: 'done' });
  return {
    to: recipient,
    amount: request.amount,
    fee,
    change,
    inputs: chosen.map((held) => ({
      commitment: held.note.commitment,
      value: BigInt(held.note.value),
    })),
    commitments: submission.report.public_inputs.commitments,
    nullifiers: submission.report.public_inputs.nullifiers,
    paymentSlot,
    extrinsicHash,
    proofBytes: submission.report.proof_bytes,
    proveMillis,
    phases: submission.report.phases,
    peakLinearMemoryBytes: submission.report.peak_linear_memory_bytes_since_init,
    inclusion,
    warnings,
  };
}

/**
 * A copy of the leaf range, because the worker takes ownership of what it is
 * transferred and a spend with two inputs asks for two paths out of the same
 * bytes.
 */
function copyOf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  return out;
}
