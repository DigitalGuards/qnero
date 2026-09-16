/**
 * Everything the worker does, with nothing that is only true inside a worker.
 *
 * The dispatch lives here rather than in `prover.worker.ts` so the rules it
 * enforces can be run against a stub module. Two of them cost a gigabyte or a
 * secret when they are wrong and neither is visible from the page:
 *
 * - **One prover per module, ever.** The circuits are rebuilt from compiled
 *   code on request, and a payment asks for them on every send. wasm linear
 *   memory never shrinks and wasm-bindgen only frees a replaced handle at the
 *   next garbage collection, so a second build adds its own quarter gigabyte
 *   permanently and the third adds another. The build is answered from cache
 *   after the first, and terminating the worker is the only thing that undoes
 *   it, which is what the settings screen offers.
 * - **The seed never leaves.** It arrives transferred, is turned into hex once,
 *   and the transferred buffer is zeroed. The hex string cannot be wiped: a
 *   JavaScript string is immutable and garbage collected, which is the boundary
 *   the crate docs name.
 *
 * `loadModule` is injected rather than imported so the core has no reference
 * to `self`, and so a test can hand it a module that counts its own calls.
 */

import { ENTRY_WALK_LIMIT } from './protocol';
import type {
  BuildAnswer,
  DecryptedNote,
  InitAnswer,
  PathAnswer,
  ProverAccount,
  ProverLimits,
  SubmissionAnswer,
  WorkerRequest,
} from './protocol';

export interface WasmSubmission {
  readonly proof: Uint8Array;
  readonly ct1: Uint8Array;
  readonly ct2: Uint8Array;
  readonly reportJson: string;
}

export interface WasmProver {
  readonly numLeaves: number;
  readonly buildReportJson: string;
  proveTransfer(requestJson: string): WasmSubmission;
  verifyProof(proof: Uint8Array): number;
}

export interface WasmModule {
  default: (input?: unknown) => Promise<{ memory: WebAssembly.Memory }>;
  initThreadPool?: (threads: number) => Promise<void>;
  entropySelfCheck: () => void;
  walletLimits: () => string;
  readStateProof: (requestJson: string) => string;
  deriveAccount: (seedHex: string) => string;
  minerKey: (seedHex: string) => string;
  decryptNote: (seedHex: string, ciphertext: Uint8Array, expected: string) => string;
  noteDigests: (seedHex: string, value: bigint, rho: string, r: string) => string;
  coinbaseNote: (seedHex: string, genesis: string, block: number, value: bigint) => string;
  entryRho: (block: number, entryIndex: bigint) => string;
  headerBlockHash: (anchorJson: string) => string;
  headerBlockHashes: (headersJson: string) => string;
  authorLabel: (seedHex: string, parentHashHex: string) => string;
  blockRoots: (leafHashes: Uint8Array, countsJson: string) => string;
  treePath: (leafHashes: Uint8Array, depth: number, leafIndex: number) => string;
  treeRoot: (leafHashes: Uint8Array, depth: number) => string;
  depthFor: (leafCount: number) => number;
  addressIsValid: (address: string) => boolean;
  memoFits: (memo: string) => number;
  ctDigest: (ct1: Uint8Array, ct2: Uint8Array) => string;
  chainNumLeaves: () => number;
  peakLinearMemoryBytes: () => number;
  WasmWalletProver: { fromSource: (numLeaves: number) => WasmProver };
}

/** How the module is fetched. The worker's own loader; a stub in a test. */
export type ModuleLoader = (
  base: string,
  maxThreads: number,
) => Promise<{ module: WasmModule; threads: number }>;

export type Progress = (stage: string, detail?: string) => void;

export interface Answer {
  value: unknown;
  transfer?: Transferable[];
}

/**
 * The address out of a derivation, and only the address.
 *
 * The module answers with `pk`, `ak` and `cvk` beside it, and `cvk` is the
 * viewing key that picks this wallet's coinbase notes out of the tree. The
 * page reads the address and nothing else, so nothing else is handed over: a
 * secret the other side never holds is one no later diagnostic can serialise.
 */
function accountOf(json: string): ProverAccount {
  const parsed = JSON.parse(json) as { address: string };
  return { address: parsed.address };
}

/**
 * One digest, in the one spelling.
 *
 * Both sides of the shield comparison come out of the same module, so they
 * already agree. It is written down because the values crossing this boundary
 * are hex strings and a comparison of hex strings is exactly where a `0x` or a
 * capital letter turns a shield into a transfer with nothing to see.
 */
function normaliseDigest(hex: string): string {
  return hex.replace(/^0x/i, '').toLowerCase();
}

/** The size of one call over the module's own resource timing, or zero. */
function moduleBytes(): number {
  const entry = performance
    .getEntriesByType('resource')
    .find((resource) => resource.name.endsWith('.wasm'));
  if (entry === undefined) {
    return 0;
  }
  const timing = entry as PerformanceResourceTiming;
  return timing.encodedBodySize || timing.transferSize || 0;
}

export class ProverCore {
  private wasm: WasmModule | null = null;
  private limits: ProverLimits | null = null;
  private threadCount = 1;
  private seedHex: string | null = null;
  private prover: WasmProver | null = null;
  /** The first build's report, which every later request is answered from. */
  private build: BuildAnswer | null = null;

  constructor(private readonly load: ModuleLoader) {}

  private requireWasm(): WasmModule {
    if (this.wasm === null) {
      throw new Error('the prover module has not been loaded');
    }
    return this.wasm;
  }

  private requireSeed(): string {
    if (this.seedHex === null) {
      throw new Error('this wallet is locked, so the worker holds no seed');
    }
    return this.seedHex;
  }

  async handle(request: WorkerRequest, progress: Progress): Promise<Answer> {
    switch (request.kind) {
      case 'readStateProof':
        return { value: JSON.parse(this.requireWasm().readStateProof(JSON.stringify(request))) };
      case 'init': {
        const started = performance.now();
        progress('module', 'fetching and instantiating the prover');
        const loaded = await this.load(request.wasmBase, request.maxThreads);
        this.wasm = loaded.module;
        this.threadCount = loaded.threads;
        const initMillis = performance.now() - started;

        // Both entropy paths, once, before anything is offered. Without it a
        // page served from a non-secure context fails tens of seconds into the
        // first private batch, inside plonky2, with an error nobody can
        // attribute.
        const entropyStarted = performance.now();
        progress('entropy', 'drawing from both entropy paths');
        loaded.module.entropySelfCheck();
        const entropyMillis = performance.now() - entropyStarted;

        const limits = JSON.parse(loaded.module.walletLimits()) as ProverLimits;
        this.limits = limits;
        // A wrong leaf count is only detected after the whole proving cost has
        // been paid, and its only failure message is "the proof did not verify",
        // which reads identically to a feature-graph divergence. So it is
        // checked here and refused.
        if (limits.chain_num_leaves !== request.numLeaves) {
          throw new Error(
            `this prover builds ${limits.chain_num_leaves} leaf slots per batch and this app is ` +
              `configured for ${request.numLeaves}. A proof at the wrong count is refused by the ` +
              'runtime only after the full proving cost, and the message it comes back with says ' +
              'nothing about the count.',
          );
        }
        const answer: InitAnswer = {
          limits,
          threads: this.threadCount,
          moduleBytes: moduleBytes(),
          initMillis,
          entropyMillis,
        };
        return { value: answer };
      }

      case 'limits': {
        if (this.limits === null) {
          throw new Error('the prover module has not been loaded');
        }
        return { value: this.limits };
      }

      case 'minerKey': {
        // From the seed this worker already holds. The request carries none:
        // a page that had to read the vault back out to ask this question
        // would hold an uncleanable copy of the spend key for the life of the
        // tab, on a screen anybody may open.
        return { value: this.requireWasm().minerKey(this.requireSeed()) };
      }

      case 'unlock': {
        // The module before the seed. Installing the seed first and then
        // finding there is no module to derive with left the worker holding a
        // plaintext spend key while the page read "locked" on every screen,
        // with the two controls that could clear it behind an open wallet.
        const module = this.requireWasm();
        const bytes = request.seed;
        let hex = '';
        for (const byte of bytes) {
          hex += byte.toString(16).padStart(2, '0');
        }
        // The transferred buffer is this worker's now, and it is erased. What
        // cannot be erased is `hex`: a JavaScript string is immutable and
        // garbage collected, which is the boundary the crate docs name.
        bytes.fill(0);
        // Installed only once the derivation has answered, so a refusal
        // leaves this worker holding nothing.
        const account = accountOf(module.deriveAccount(hex));
        this.seedHex = hex;
        return { value: account };
      }

      case 'lock': {
        this.seedHex = null;
        return { value: null };
      }

      case 'addressIsValid': {
        return { value: this.requireWasm().addressIsValid(request.address) };
      }

      case 'memoFits': {
        try {
          return { value: { fits: true, bytes: this.requireWasm().memoFits(request.memo) } };
        } catch (error) {
          return { value: { fits: false, reason: (error as Error).message } };
        }
      }

      case 'decryptBatch': {
        // A note's value crosses this boundary as a JSON number, here and
        // again as `Number(input.value)` in `proveTransfer`, so both are exact
        // only below 2^53. The chain's own cap is what makes that safe:
        // the pool step is 1e10 planck and the supply cap is 21,000,000
        // units, so the whole supply is about 2.1e9 steps, and 2^53 is
        // four million times that. A chain with a larger step or no cap
        // would need this to carry the value as a string end to end.
        const module = this.requireWasm();
        const seed = this.requireSeed();
        const out: (DecryptedNote | null)[] = [];
        for (const item of request.items) {
          try {
            // Opened without the commitment beside it, and compared here. The
            // module refuses on a mismatch when it is handed one, which folds
            // "this wallet's note, moved" into "somebody else's" and loses the
            // one reading a wallet can tell apart on its own: a stranger's
            // bytes do not open at all, while these did. The comparison is the
            // same one `try_receive` makes, kept in this worker so the page
            // never holds a rule the seed decides. See `OpenedLeaf` in
            // `crates/qnero-wallet/src/wallet.rs`.
            const decrypted = JSON.parse(module.decryptNote(seed, item.ciphertext, '')) as {
              value: number;
              rho: string;
              r: string;
              commitment: string;
              memo: string;
            };
            const digests = JSON.parse(
              module.noteDigests(seed, BigInt(decrypted.value), decrypted.rho, decrypted.r),
            ) as { commitment: string; nullifier: string };
            const opened = normaliseDigest(digests.commitment);
            const moved = opened !== normaliseDigest(item.commitment);
            out.push({
              value: String(decrypted.value),
              rho: decrypted.rho,
              r: decrypted.r,
              commitment: digests.commitment,
              nullifier: digests.nullifier,
              memo: decrypted.memo,
              ...(moved ? { moved: true } : {}),
            });
          } catch {
            // Not this wallet's ciphertext, which is the ordinary answer for
            // almost every leaf on the chain. The refusal says nothing about
            // what was inside it and neither does this.
            out.push(null);
          }
        }
        return { value: out };
      }

      case 'coinbaseBatch': {
        const module = this.requireWasm();
        const seed = this.requireSeed();
        const out: (DecryptedNote | null)[] = [];
        for (const item of request.items) {
          out.push(this.receiveCoinbase(module, seed, item));
        }
        return { value: out };
      }

      case 'entryRhoMatches': {
        // The whole counter, the way `crates/qnero-wallet/src/wallet.rs` walks
        // it, up to `ENTRY_WALK_LIMIT`. A shield predicts
        // `(head + 1, EntryCount)`, so a settled one is somewhere below the
        // counter read at the head, and a walk bounded to the newest entries
        // mislabelled every older shield of a restored wallet.
        //
        // The ceiling is the node's: this is one Poseidon2 hash per unit of a
        // number the node hands over, on the thread that holds the seed, and
        // the loop is synchronous, so an unbounded one is a node answer that
        // ends the session. See `ENTRY_WALK_LIMIT`, and `runSync` warns when a
        // pass reads a counter above it.
        const module = this.requireWasm();
        const wanted = normaliseDigest(request.rho);
        const entries =
          BigInt(request.entryCount) > ENTRY_WALK_LIMIT
            ? ENTRY_WALK_LIMIT
            : BigInt(request.entryCount);
        for (let index = 0n; index < entries; index += 1n) {
          if (normaliseDigest(module.entryRho(request.blockNumber, index)) === wanted) {
            return { value: true };
          }
        }
        return { value: false };
      }

      case 'noteDigests': {
        return {
          value: JSON.parse(
            this.requireWasm().noteDigests(
              this.requireSeed(),
              BigInt(request.value),
              request.rho,
              request.r,
            ),
          ) as { inner: string; commitment: string; nullifier: string },
        };
      }

      case 'headerBlockHash': {
        return { value: this.requireWasm().headerBlockHash(JSON.stringify(request.anchor)) };
      }

      case 'headerBlockHashes': {
        // One crossing for a whole scanned range. A sync rehashes every header
        // it is handed, because the `zkTreeRoot` a block's leaf range is
        // checked against and the author label that says whose block it is are
        // authenticated by that hash and by nothing else.
        return {
          value: JSON.parse(
            this.requireWasm().headerBlockHashes(JSON.stringify(request.headers)),
          ) as string[],
        };
      }

      case 'authorLabels': {
        // From the seed this worker already holds, like `minerKey`. The label
        // is `H("qnero/author-label", cvk, parent_hash)` and `cvk` is viewing
        // tier secret, so it is derived here and never on the page.
        const module = this.requireWasm();
        const seed = this.requireSeed();
        return {
          value: request.parentHashes.map((parentHash) => module.authorLabel(seed, parentHash)),
        };
      }

      case 'blockRoots': {
        return {
          value: JSON.parse(
            this.requireWasm().blockRoots(request.leafHashes, JSON.stringify(request.counts)),
          ) as string[],
        };
      }

      case 'treePath': {
        return {
          value: JSON.parse(
            this.requireWasm().treePath(request.leafHashes, request.depth, request.leafIndex),
          ) as PathAnswer,
        };
      }

      case 'treeRoot': {
        return { value: this.requireWasm().treeRoot(request.leafHashes, request.depth) };
      }

      case 'depthFor': {
        return { value: this.requireWasm().depthFor(request.leafCount) };
      }

      case 'buildProver': {
        const module = this.requireWasm();
        if (this.prover !== null && this.build !== null) {
          // The circuits are already resident. Rebuilding them costs a fresh
          // quarter gigabyte of linear memory that never comes back, and buys
          // a set identical to the one already here.
          return {
            value: {
              ...this.build,
              cached: true,
              peakLinearMemoryBytes: module.peakLinearMemoryBytes(),
            } satisfies BuildAnswer,
          };
        }
        progress('build', 'building the leaf and private-batch circuits');
        const started = performance.now();
        // From the compiled code, reading nothing. That removes the fetch, the
        // cache invalidation and the pinning surface entirely, and it costs one
        // padding-leaf prove more than the artifact route, which is noise
        // against the build.
        const prover = module.WasmWalletProver.fromSource(module.chainNumLeaves());
        const millis = performance.now() - started;
        const report = JSON.parse(prover.buildReportJson) as {
          leaf_degree_bits: number;
          private_batch_degree_bits: number;
        };
        const answer: BuildAnswer = {
          threads: this.threadCount,
          millis,
          cached: false,
          peakLinearMemoryBytes: module.peakLinearMemoryBytes(),
          degreeBits: {
            leaf: report.leaf_degree_bits,
            privateBatch: report.private_batch_degree_bits,
          },
        };
        this.prover = prover;
        this.build = answer;
        return { value: answer };
      }

      case 'proveTransfer': {
        const prover = this.prover;
        if (prover === null) {
          throw new Error('the circuits have not been built');
        }
        const seed = this.requireSeed();
        progress('prove', 'proving the leaf and the private batch');
        const payload = {
          seed,
          anchor: request.request.anchor,
          tree_depth: request.request.tree_depth,
          fee: Number(request.request.fee),
          inputs: request.request.inputs.map((input) => ({
            value: Number(input.value),
            rho: input.rho,
            r: input.r,
            path: input.path,
          })),
          outputs: request.request.outputs.map((output) => ({
            address: output.address,
            value: Number(output.value),
            memo: output.memo ?? '',
          })),
        };
        const submission = prover.proveTransfer(JSON.stringify(payload));
        const proof = submission.proof;
        const ct1 = submission.ct1;
        const ct2 = submission.ct2;

        // Verify locally before the page is told the proof exists. Fourteen
        // milliseconds turns a wallet-side mistake into a local error; the pool
        // refuses a bad settlement without saying which public input was wrong.
        progress('verify', 'verifying the proof against this build');
        const verifyMillis = prover.verifyProof(proof);
        const report = JSON.parse(submission.reportJson) as SubmissionAnswer['report'];
        report.phases.push({ phase: 'local_verify', millis: verifyMillis });
        const answer: SubmissionAnswer = { proof, ct1, ct2, report };
        return {
          value: answer,
          transfer: [proof.buffer, ct1.buffer, ct2.buffer],
        };
      }
    }
  }

  /**
   * One coinbase leaf, by the chain's own rule.
   *
   * The miner-key derivation first, which is what a wallet mining its own
   * blocks meets. A coinbase paid to an address by somebody else carries a
   * ciphertext instead, and the rule for that one is the CLI's
   * `try_receive_coinbase`: the value comes from `Shielded::CoinbaseValues`
   * and the value inside the payload is ignored, because the chain hashed its
   * own arithmetic into the commitment. So the payload is opened without a
   * commitment check, the note is rebuilt at the chain's value, and the
   * commitment decides. Opening it with the ordinary transfer rule would
   * rebuild at the payload's value, fail the check, and read this wallet's own
   * coinbase as nobody's with no error anywhere.
   */
  private receiveCoinbase(
    module: WasmModule,
    seed: string,
    item: { blockNumber: number; value: string; genesisHash: string; commitment: string; ciphertext: Uint8Array | null },
  ): DecryptedNote | null {
    const expected = item.commitment.toLowerCase().replace(/^0x/, '');
    try {
      const derived = JSON.parse(
        module.coinbaseNote(seed, item.genesisHash, item.blockNumber, BigInt(item.value)),
      ) as { rho: string; r: string; commitment: string; nullifier: string };
      if (derived.commitment.toLowerCase().replace(/^0x/, '') === expected) {
        // `mined` is what makes ownership at a coinbase position a property of
        // the coinbase viewing key rather than of the author label a node
        // published: the caller requires the value at every coinbase position,
        // rebuilds here at every coinbase position, and reads the label only
        // as a cross-check afterwards. See `wallet/sync.ts`.
        return {
          value: item.value,
          rho: derived.rho,
          r: derived.r,
          commitment: derived.commitment,
          nullifier: derived.nullifier,
          memo: '',
          mined: true,
        };
      }
    } catch {
      // A miner key that derives nothing for this block. The ciphertext, if
      // there is one, is the other way in.
    }
    if (item.ciphertext === null) {
      return null;
    }
    try {
      // No expected commitment: the check below is against the chain's value
      // rather than the payload's, and `try_receive` would apply the payload's.
      const opened = JSON.parse(module.decryptNote(seed, item.ciphertext, '')) as {
        rho: string;
        r: string;
        memo: string;
      };
      const digests = JSON.parse(
        module.noteDigests(seed, BigInt(item.value), opened.rho, opened.r),
      ) as { commitment: string; nullifier: string };
      if (digests.commitment.toLowerCase().replace(/^0x/, '') !== expected) {
        return null;
      }
      return {
        value: item.value,
        rho: opened.rho,
        r: opened.r,
        commitment: digests.commitment,
        nullifier: digests.nullifier,
        memo: opened.memo,
      };
    } catch {
      return null;
    }
  }
}
