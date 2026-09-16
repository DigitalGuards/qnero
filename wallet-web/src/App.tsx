/**
 * The wallet, wired together.
 *
 * The screen flow is MyMonero's: a landing that asks how you would like to add
 * a wallet, a create path that shows the key once and takes it back in
 * writing, a lock screen, and then a wallet with its balance on top, its send,
 * its receive and its settings behind a tab bar. What is different is under
 * it, and the differences are the deliberate ones: keys are generated and used
 * in this page, proving happens in a worker on this machine, and the node is
 * asked only for public data read whole.
 *
 * # Where the work happens
 *
 * This component owns the socket and the store. The worker owns the seed, the
 * wasm module and every rule that touches a secret. Nothing here can leak a
 * secret into a request, because it holds none; nothing there can leak one
 * either, because it cannot open a socket.
 *
 * # Why the routes are hashes
 *
 * `HashRouter`, so a built directory works when it is dropped on any static
 * host and at any path under it. A path router needs the host to rewrite every
 * unknown path to `index.html`, and a host that does not is a wallet that
 * works until somebody reloads the send screen.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Navigate, Route, Routes, useNavigate } from 'react-router';

import { loadConfig, type WalletConfig } from './chain/config';
import { blockHashAt, fetchBirthday, fetchHead } from './chain/reads';
import { chainAdapter, cryptoAdapter } from './app/adapters';
import { readEndpoint, writeEndpoint } from './app/endpoint';
import { readMeasuredSendSeconds, writeMeasuredSendSeconds } from './app/proverMode';
import {
  RECONNECT_ATTEMPTS_BEFORE_SETTINGS,
  reconnectDelayMs,
  secondsUntil,
} from './app/reconnect';
import { Session, type ConnectionState } from './app/session';
import { Notice } from './components/UI/Notice';
import { Panel } from './components/UI/Panel';
import { TabBar } from './components/TabBar';
import { Landing } from './screens/Landing';
import { CreateWallet } from './screens/CreateWallet';
import { RestoreWallet } from './screens/RestoreWallet';
import { Unlock } from './screens/Unlock';
import { BalanceScreen } from './screens/BalanceScreen';
import { SendScreen } from './screens/SendScreen';
import { ReceiveScreen } from './screens/ReceiveScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import {
  deriveKey,
  deriveStoreKey,
  newSalt,
  bytesToHex,
  hexToBytes,
  PBKDF2_ITERATIONS,
  WrongPassphraseError,
} from './wallet/crypto';
import { createStore, WalletStore } from './wallet/store';
import type { Balances, NoteRow, RejectedNote, StoreMeta, StoredNote } from './wallet/model';
import { formatCount } from './lib/units';
import { collapseRows, reachableTotal, spendable } from './wallet/select';
import {
  birthdayNoticeFor,
  readBirthday,
  type BirthdayReads,
  type BirthdaySources,
  type RecordedBirthday,
} from './wallet/birthday';
import { runSync, type SyncReport } from './wallet/sync';
import {
  chainMismatchRefusal,
  feeFloorFor,
  spend,
  type SpendProgress,
  type SpendResult,
} from './wallet/send';

type Phase =
  | { kind: 'booting' }
  | { kind: 'broken'; message: string }
  | { kind: 'landing' }
  | { kind: 'create' }
  | { kind: 'restore' }
  | { kind: 'locked'; meta: StoreMeta }
  | { kind: 'open' };

const EMPTY_BALANCES: Balances = {
  unspent: 0n,
  pending: 0n,
  offChain: 0n,
  reachable: 0n,
  noteCount: 0,
};

/**
 * One session per tab, created when this module loads.
 *
 * Not a ref. The worker, the database handle and the chain connection are one
 * per tab by their nature, and a ref would make them one per mount; a ref read
 * during render is also a value React cannot see change. What the component
 * holds is state mirroring the parts of it a screen depends on.
 */
const session = new Session();

/** The two chain reads a birthday is made of, as this page makes them. */
const BIRTHDAY_READS: BirthdayReads = {
  birthdayAt: fetchBirthday,
  genesisHash: (context) => blockHashAt(context, 0),
};

/**
 * The session fields a birthday read polls, read fresh on every pass.
 *
 * Getters rather than values: the whole point of the wait is that these two
 * are `null` now and will not be in a moment.
 */
/**
 * Whether this browser has asked for stillness.
 *
 * Read on each call rather than subscribed to: the one thing it gates is a
 * once-a-second interval, and a reader who changes the setting mid-wait gets
 * the answer at the next failed attempt.
 */
function stillness(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function birthdaySources(current: Session): BirthdaySources {
  return {
    context: () => current.context,
    limits: () => current.limits,
  };
}

export function App(): ReactNode {
  const navigate = useNavigate();
  const [config, setConfig] = useState<WalletConfig | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: 'booting' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  /**
   * What was recorded as this wallet's birthday, said once after it is made.
   *
   * It is where the first sync starts reading the chain, and it is the node's
   * claim rather than a fact, so it is shown rather than left implicit: a
   * wallet quietly starting above a note is a balance quietly short.
   */
  const [birthdayNotice, setBirthdayNotice] = useState<string | null>(null);
  /**
   * A restore height typed while nothing was answering, still to be recorded.
   *
   * The wizard's last step waits for the socket before it reads the birthday
   * (see `wallet/birthday.ts`). When that wait runs out the number is held
   * here rather than dropped, and the effect below writes it into the store
   * the moment a node answers.
   */
  const [pendingBirthday, setPendingBirthday] = useState<number | null>(null);
  /** The block this wallet reads the chain from: its birthday, or zero. */
  const [readsFrom, setReadsFrom] = useState(0);

  const [address, setAddress] = useState('');
  const [minerKey, setMinerKey] = useState<string | null>(null);
  const [balances, setBalances] = useState<Balances>(EMPTY_BALANCES);
  const [notes, setNotes] = useState<NoteRow[]>([]);
  const [rejected, setRejected] = useState<RejectedNote[]>([]);
  const [syncReport, setSyncReport] = useState<SyncReport | null>(null);
  const [syncing, setSyncing] = useState(false);
  /**
   * The stage a running pass is in, and what it is counting.
   *
   * The two are held apart rather than joined into one line: the wallet screen
   * names the phase itself and prints the count beside it, so a stage name the
   * pass uses internally never reaches a screen.
   */
  const [syncStage, setSyncStage] = useState<{ stage: string; detail: string | null } | null>(
    null,
  );

  const [connection, setConnection] = useState<ConnectionState>({
    kind: 'offline',
    endpoint: '',
  });
  /**
   * The clock the reconnect countdown is read against.
   *
   * Set at the moment an attempt fails and then once a second while one is
   * pending. Its own state rather than a `Date.now()` in render, because a
   * value read in render does not re-render anything when it changes.
   */
  const [tick, setTick] = useState(() => Date.now());
  const [proverThreads, setProverThreads] = useState(1);
  /**
   * What the last payment on this machine cost end to end, in seconds, or
   * null. The send button to a settled block, which is what the sending
   * screen's own clock measures.
   */
  const [measuredSendSeconds, setMeasuredSendSeconds] = useState<number | null>(null);
  const [circuitsBuilt, setCircuitsBuilt] = useState(false);
  // Mirrors of session fields a screen reads. The session is a module
  // singleton and React does not re-render for a field on one, so the two that
  // a screen depends on are held here.
  const [persisted, setPersisted] = useState(false);
  const [proverRunning, setProverRunning] = useState(false);
  const [storeUnlocked, setStoreUnlocked] = useState(false);

  const [spendProgress, setSpendProgress] = useState<SpendProgress | null>(null);
  const [spendResult, setSpendResult] = useState<SpendResult | null>(null);
  const [spendError, setSpendError] = useState<string | null>(null);
  const [spendRunning, setSpendRunning] = useState(false);

  /**
   * Which of the two long jobs is running, if either. One at a time.
   *
   * A sync reads every note up front and then spends tens of seconds paging
   * the settled set and decrypting; a payment writes `spent` and `onChain` on
   * those same rows when it settles. Run together, the sync's commit put its
   * own stale copy of a row back over the spend's latch, the balance offered a
   * consumed note again and the pool refused the next settlement after a whole
   * proof had been paid for. `commitSync` merges field by field so a store can
   * never lose that write, and this keeps the two from overlapping in the
   * first place.
   *
   * A ref, because the `syncing` and `spendRunning` state is set for the
   * screens and React applies it after the handler returns: two taps inside one
   * frame both read `false`.
   *
   * **Claimed before the first `await` in both handlers**, and that ordering is
   * the whole of the guarantee. A ref read and written in one synchronous run
   * cannot be interleaved, because a handler holds the thread until it awaits;
   * anything read or awaited before the claim is a window two presses both get
   * through. `send` used to read `store.meta()` for the genesis check above its
   * claim, so two presses inside that one await both claimed `spend` and the
   * second proved against a note set the first had already selected from. Every
   * check above the claim in either handler is synchronous, and the ones that
   * need the store were moved under it.
   */
  const running = useRef<'sync' | 'spend' | null>(null);

  /** Recompute the view of the store. Locked wallets get everything but memos. */
  const refresh = useCallback(async (): Promise<void> => {
    const store = session.store;
    if (store === null) {
      return;
    }
    const [stored, pending, rejectedNotes, meta] = await Promise.all([
      store.notes(),
      store.pending(),
      store.rejected(),
      store.meta(),
    ]);
    // Where this wallet starts reading, for the one line on the wallet screen
    // that says so. It used to be a thirty-word banner over the balance on
    // every open screen: 22% of the first screen, spent on sync theory.
    setReadsFrom(meta.birthday?.blockNumber ?? 0);

    const rows: NoteRow[] = [];
    const byNullifier = new Map<string, StoredNote[]>();
    for (const note of stored) {
      let secret = null;
      if (store.isUnlocked) {
        try {
          secret = await store.openNoteSecret(note);
        } catch {
          // A record this key cannot open. It is kept and shown, because
          // dropping it would drop the only copy of its randomness.
          secret = null;
        }
      }
      rows.push({ note, secret, conflictMembers: 1 });
      if (secret !== null) {
        const members = byNullifier.get(secret.nullifier) ?? [];
        members.push(note);
        byNullifier.set(secret.nullifier, members);
      }
    }
    for (const row of rows) {
      if (row.secret !== null) {
        row.conflictMembers = byNullifier.get(row.secret.nullifier)?.length ?? 1;
      }
    }

    // One member per nullifier, on chain and unspent: the same rule selection
    // uses, so the balance and what a spend can reach never disagree.
    //
    // While the wallet is locked no secret opens, so `nullifierOf` falls back
    // to the commitment and a conflict set stops collapsing. These totals are
    // not rendered in that state: a locked wallet has exactly one screen, the
    // unlock one, and `redirectFor` sends every other route to it. They are
    // computed on the boot path so an unlock has nothing to wait for.
    const nullifierOf = (note: StoredNote): string => {
      const row = rows.find((entry) => entry.note.commitment === note.commitment);
      return row?.secret?.nullifier ?? note.commitment;
    };
    const candidates = spendable(stored, nullifierOf);
    const unspent = candidates.reduce((sum, note) => sum + BigInt(note.value), 0n);
    // The off-chain heading collapses too, and by the same rule the table
    // under it uses. Two members of one conflict set are two rows and one
    // amount: at most one of them can ever settle, so summing both would print
    // a heading that overstates its own table.
    const offChainBest = new Map<string, StoredNote>();
    for (const note of stored) {
      if (note.onChain || note.spent) {
        continue;
      }
      const key = nullifierOf(note);
      const best = offChainBest.get(key);
      if (
        best === undefined ||
        BigInt(note.value) > BigInt(best.value) ||
        (BigInt(note.value) === BigInt(best.value) && note.leafIndex < best.leafIndex)
      ) {
        offChainBest.set(key, note);
      }
    }
    const offChain = [...offChainBest.values()].reduce(
      (sum, note) => sum + BigInt(note.value),
      0n,
    );
    const pendingTotal = pending.reduce((sum, note) => sum + BigInt(note.value), 0n);

    // One row per nullifier, by the rule the headings above the table use. Two
    // members of one conflict set are two notes and one amount: at most one of
    // them can ever settle, so a table that printed both summed to a number
    // the chain will never back, under a heading that had counted the set
    // once.
    setNotes(collapseRows(rows));
    setRejected(rejectedNotes);
    setBalances({
      unspent,
      pending: pendingTotal,
      offChain,
      reachable: reachableTotal(candidates),
      noteCount: stored.length,
    });
  }, []);

  /**
   * Open a connection, and then follow it.
   *
   * The state is not decided once here. The socket's own edges move it between
   * `live` and `connecting` for the life of the tab, and the head subscription
   * keeps the block number beside the chain name true: a wallet that read both
   * at connect time and never again shows a green dot and a twenty-block-old
   * height over a node that died, with a Sync button that cannot work.
   */
  const openConnection = useCallback(
    async (endpoint: string): Promise<void> => {
      const current = session;
      // Leaving `failed` is what cancels any scheduled attempt: the timer
      // below lives on that state, so a press of Connect, a changed endpoint
      // and the scheduled attempt itself all supersede it by moving off it.
      setConnection((held) => ({
        kind: 'connecting',
        endpoint,
        attempts: held.endpoint === endpoint ? held.attempts : 0,
      }));
      try {
        const context = await current.connect(endpoint, {
          onStatus: (kind) => {
            setConnection((held) =>
              held.endpoint === endpoint && (held.kind === 'live' || held.kind === 'connecting')
                ? { ...held, kind }
                : held,
            );
            if (kind === 'live') {
              // The head subscription fires on the next block, and a chain
              // that has just come back may be a while.
              void fetchHead(current.context ?? context)
                .then((head) => {
                  setConnection((held) =>
                    held.endpoint === endpoint ? { ...held, head: head.number } : held,
                  );
                })
                .catch(() => undefined);
            }
          },
          onHead: (height) => {
            setConnection((held) =>
              held.endpoint === endpoint ? { ...held, head: height } : held,
            );
          },
        });
        const head = await fetchHead(context);
        setConnection({
          kind: 'live',
          endpoint,
          head: head.number,
          specName: context.specName,
          specVersion: context.specVersion,
          targetBlockTimeMs: context.targetBlockTimeMs,
          drift: context.storageDrift,
        });
      } catch (connectError) {
        setConnection((held) => {
          const attempts = (held.endpoint === endpoint ? (held.attempts ?? 0) : 0) + 1;
          return {
            kind: 'failed',
            endpoint,
            error: (connectError as Error).message,
            retryAt: Date.now() + reconnectDelayMs(attempts),
            attempts,
          };
        });
        // The countdown's anchor, set at the same moment the deadline is, so
        // the first frame after a failure reads the whole wait rather than
        // whatever this clock last held.
        setTick(Date.now());
      }
    },
    [],
  );

  // Boot: read the config, start the worker, look for a store.
  //
  // An `AbortController` rather than a closed-over boolean. A `let cancelled =
  // false` that is only reassigned inside the cleanup closure narrows to
  // `false` for the whole body, so every check on it reads as dead code and
  // the compiler is right about the text and wrong about the program.
  useEffect(() => {
    const abandoned = new AbortController();
    // Through a call rather than a property read: TypeScript keeps the
    // narrowing from the first check across every `await` after it, so a
    // repeated `signal.aborted` reads as dead code.
    const stopped = (): boolean => abandoned.signal.aborted;
    void (async (): Promise<void> => {
      try {
        const loaded = await loadConfig();
        if (stopped()) {
          return;
        }
        setConfig(loaded);
        const threads = await session.startProver(loaded);
        if (stopped()) {
          return;
        }
        setProverThreads(threads);
        setProverRunning(session.prover.isRunning);
        setMeasuredSendSeconds(readMeasuredSendSeconds(threads));
        const meta = await session.loadMeta();
        if (stopped()) {
          return;
        }
        setPersisted(session.persisted);
        const endpoint = readEndpoint(loaded.rpcEndpoint);
        void openConnection(endpoint);
        if (meta === null) {
          setPhase({ kind: 'landing' });
          return;
        }
        const db = session.db;
        if (db === null) {
          throw new Error('the wallet database closed while it was being read');
        }
        session.store = WalletStore.locked(db, meta.address);
        setAddress(meta.address);
        await refresh();
        setPhase({ kind: 'locked', meta });
      } catch (bootError) {
        if (!stopped()) {
          setPhase({ kind: 'broken', message: (bootError as Error).message });
        }
      }
    })();
    return () => {
      abandoned.abort();
    };
  }, [openConnection, refresh]);

  /**
   * The scheduled attempt, which is a timer that lives on the failed state.
   *
   * A wallet that reached "no node" used to stay there: the provider was
   * disconnected in the catch above and nothing scheduled another attempt, so
   * a phone that opened Qloak in a tunnel was dead until the reader found
   * Settings and pressed Connect with the same endpoint. Because the timer
   * hangs off `retryAt`, every way out of `failed` cancels it through this
   * effect's cleanup: a manual Connect, an endpoint change, and the attempt
   * itself, which moves the state to `connecting` before it does anything.
   */
  const retryAt = connection.kind === 'failed' ? connection.retryAt : undefined;
  const retryEndpoint = connection.endpoint;
  useEffect(() => {
    if (retryAt === undefined) {
      return;
    }
    const timer = setTimeout(
      () => {
        void openConnection(retryEndpoint);
      },
      Math.max(0, retryAt - Date.now()),
    );
    return () => {
      clearTimeout(timer);
    };
  }, [retryAt, retryEndpoint, openConnection]);

  /**
   * The countdown to that attempt, in whole seconds, or null.
   *
   * It ticks once a second while an attempt is pending and holds still under
   * reduced motion, where a number changing every second is the motion. The
   * figure is still shown there: what the setting asks for is stillness, and
   * the whole wait is the honest thing to show when it cannot move.
   */
  useEffect(() => {
    if (retryAt === undefined || stillness()) {
      return;
    }
    const timer = setInterval(() => {
      setTick(Date.now());
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [retryAt]);
  const retrySeconds = retryAt === undefined ? null : secondsUntil(retryAt, tick);
  const pointAtSettings = (connection.attempts ?? 0) >= RECONNECT_ATTEMPTS_BEFORE_SETTINGS;

  // The worker's progress, wherever it comes from.
  useEffect(() => {
    return session.prover.onProgress((stage, detail) => {
      setSyncStage({ stage, detail: detail ?? null });
    });
  }, []);

  /**
   * The restore height the wizard could not record, written when a node answers.
   *
   * A wallet made while nothing was answering has no birthday, and the height
   * somebody typed is a number that is still true a minute later. So it is
   * held and recorded here, once, before anything has been read: the store
   * refuses to move a birthday it already has and refuses one on a wallet that
   * has synced, so a late arrival can never lower a watermark under rows that
   * have been typed.
   */
  useEffect(() => {
    if (pendingBirthday === null || connection.kind !== 'live' || !storeUnlocked) {
      return;
    }
    const abandoned = new AbortController();
    void (async (): Promise<void> => {
      const current = session;
      const outcome = await readBirthday(
        birthdaySources(current),
        BIRTHDAY_READS,
        pendingBirthday,
        // No wait: this runs on a live connection, so either the context is
        // there or this edge is not the one to read on.
        { now: () => Date.now(), sleep: () => Promise.resolve(), waitMs: 0 },
      );
      if (abandoned.signal.aborted) {
        return;
      }
      if (outcome.kind === 'read') {
        const store = current.store;
        if (store !== null && (await store.recordBirthday(outcome.birthday))) {
          setBirthdayNotice(birthdayNoticeFor(outcome));
          await refresh();
        }
        setPendingBirthday(null);
      } else if (outcome.kind === 'refused') {
        setBirthdayNotice(birthdayNoticeFor(outcome));
        setPendingBirthday(null);
      }
    })();
    return () => {
      abandoned.abort();
    };
  }, [pendingBirthday, connection.kind, storeUnlocked, refresh]);

  /**
   * Create or restore a wallet, and record where it starts reading the chain.
   *
   * `restoreHeight` is the chain height somebody restoring says this wallet was
   * created at, `null` for a restore that gave none, and it is absent for a
   * wallet being created now, which starts at the node's own head. Either way
   * the height is rounded down to its epoch before it is recorded: see
   * `BIRTHDAY_EPOCH`.
   *
   * A birthday needs the node, and a wallet can be created with no connection
   * at all. So a node that cannot be reached is a warning on the screen and
   * not a refusal: the wallet is made, it records no birthday, and its first
   * sync reads the chain from block zero, which is correct and slow.
   */
  const createWallet = useCallback(
    async (
      seedHex: string,
      passphrase: string,
      restoreHeight?: number | null,
    ): Promise<void> => {
      const current = session;
      setBusy(true);
      setError(null);
      try {
        const db = await current.openDatabase();
        // A prover somebody switched off before erasing the last wallet is
        // started again here, for the reason the unlock path does it: the
        // screens that can switch it back on are the open wallet's, and this
        // is the path to having one.
        if (!current.prover.isRunning) {
          if (config === null) {
            throw new Error('this wallet has not finished loading its configuration');
          }
          setProverThreads(await current.startProver(config));
          setProverRunning(current.prover.isRunning);
          setCircuitsBuilt(current.circuitsBuilt);
        }
        // One crossing. The seed goes to the worker as a transferred buffer,
        // the page's copy is detached by the transfer, and the answer carries
        // the address the store binds its records to. It used to cross twice:
        // a `deriveAccount` request carrying the seed as a plain string, which
        // structured clone copies into the worker's heap where neither side
        // can erase it, for an address this call already returns.
        const account = await current.prover.unlock(hexToBytes(seedHex));
        const saltHex = bytesToHex(newSalt());
        const key = await deriveKey(passphrase, saltHex);
        // Read before the store is written, so a store is never created with
        // half a birthday in it. `restoreHeight === undefined` is a wallet
        // being created now, which starts at the head; `null` is a restore
        // that asked for the whole chain.
        //
        // The read waits for the socket rather than looking once: the wizard
        // is three screens long and the connection is opened at boot, so
        // looking once lost the race on a slow network and took a typed
        // restore height down with it. See `wallet/birthday.ts`.
        let birthday: RecordedBirthday | null = null;
        if (restoreHeight !== null) {
          const outcome = await readBirthday(
            birthdaySources(current),
            BIRTHDAY_READS,
            restoreHeight ?? null,
          );
          if (outcome.kind === 'read') {
            birthday = outcome.birthday;
            setPendingBirthday(null);
          } else if (outcome.kind === 'no-node' && outcome.restoreHeight !== null) {
            // Kept, not dropped. A height is a number somebody typed and it
            // is still true when the node comes back.
            setPendingBirthday(outcome.restoreHeight);
          }
          setBirthdayNotice(birthdayNoticeFor(outcome));
        }
        const store = await createStore(db, {
          address: account.address,
          seedHex,
          key,
          saltHex,
          iterations: PBKDF2_ITERATIONS,
          birthday,
        });
        current.store = store;
        current.account = account;
        setAddress(account.address);
        setStoreUnlocked(true);
        await refresh();
        // The route follows the phase: see `redirectFor`.
        setPhase({ kind: 'open' });
      } catch (createError) {
        // Nothing stays unlocked, here as at the unlock screen: a store that
        // failed to be written is a seed the worker is holding for a wallet
        // that does not exist.
        await current.lock().catch(() => undefined);
        setStoreUnlocked(false);
        setError((createError as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [config, refresh],
  );

  const unlock = useCallback(
    async (passphrase: string): Promise<void> => {
      const current = session;
      if (phase.kind !== 'locked') {
        return;
      }
      setBusy(true);
      setUnlockError(null);
      try {
        const db = await current.openDatabase();
        // From the parameters this store recorded rather than from this
        // build's constants: see `deriveStoreKey`.
        const key = await deriveStoreKey(passphrase, phase.meta.kdf);
        const store = WalletStore.unlocked(db, phase.meta.address, key);
        const seed = await store.seed();
        // A prover somebody switched off in settings is started again here
        // rather than refused. Locking after stopping it left the wallet with
        // one reachable screen, an unlock that refused with "turn it back on
        // in settings", and no way to reach settings: the advice named a
        // screen the locked phase forbids, and the other button on that screen
        // erases the wallet.
        if (!current.prover.isRunning) {
          if (config === null) {
            throw new Error('this wallet has not finished loading its configuration');
          }
          setProverThreads(await current.startProver(config));
          setProverRunning(current.prover.isRunning);
          setCircuitsBuilt(current.circuitsBuilt);
        }
        const account = await current.prover.unlock(seed as Uint8Array<ArrayBuffer>);
        if (account.address !== phase.meta.address) {
          // The post-decrypt identity check. A valid envelope from another
          // wallet is refused here even when AAD binding did not catch it.
          //
          // Both sides are locked, not just this one. By this point the worker
          // has been handed the seed, and locking only the page's key handle
          // would leave a spend key this wallet has just refused resident in
          // the worker for the life of the tab.
          store.lock();
          await current.prover.lock().catch(() => undefined);
          throw new WrongPassphraseError(
            'the seed this passphrase opened does not derive this wallet\'s address',
          );
        }
        current.store = store;
        current.account = account;
        setAddress(account.address);
        setStoreUnlocked(true);
        await refresh();
        setPhase({ kind: 'open' });
      } catch (error_) {
        // Whatever failed, nothing stays unlocked. An unlock that threw after
        // the seed reached the worker (a module that is not loaded, a
        // derivation that refused) would otherwise leave the seed there with
        // every control that could clear it behind an open wallet.
        await current.lock().catch(() => undefined);
        setStoreUnlocked(false);
        setUnlockError((error_ as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [config, phase, refresh],
  );

  /**
   * Read the chain.
   *
   * `automatic` is a pass nobody pressed: the one that runs when the wallet
   * opens and on each new head. Every refusal below is a sentence about a
   * button, so an automatic pass takes them silently and waits for the next
   * head. A wallet that put "this wallet is not connected to a node" on the
   * screen by itself, once a block, would be shouting about a state its own
   * header already shows with a red dot.
   */
  const sync = useCallback(
    async (rescan: boolean, automatic = false): Promise<void> => {
      const current = session;
      const store = current.store;
      const context = current.context;
      const refuse = (message: string): void => {
        if (!automatic) {
          setError(message);
        }
      };
      if (store === null) {
        return;
      }
      if (context === null) {
        refuse('this wallet is not connected to a node');
        return;
      }
      if (context.storageDrift.length > 0) {
        refuse(
          'this runtime declares storage differently from what this build assumes, so syncing ' +
            'against it is refused. An absent key and an empty map are indistinguishable, and an ' +
            'empty map here is a zero balance, or an amount already spent reported as unspent.',
        );
        return;
      }
      if (!store.isUnlocked) {
        refuse('unlock this wallet before syncing: a scan needs its viewing key');
        return;
      }
      const limits = current.limits;
      if (limits === null) {
        refuse('this wallet has not finished loading its prover, which a scan reads its bounds from');
        return;
      }
      if (running.current !== null) {
        refuse(
          running.current === 'spend'
            ? 'a payment is being proved and submitted. A scan reads everything this wallet ' +
              'holds before it starts and commits at the end, so the two would write the same ' +
              'rows from two different moments. It will run once the payment has settled.'
            : 'a scan is already running.',
        );
        return;
      }
      // Claimed above every `await` in this function, the way `send` claims it:
      // every check before this line reads state the render already holds.
      running.current = 'sync';
      setSyncing(true);
      setError(null);
      try {
        const [meta, stored, rejectedNotes, checkpoints, pending] = await Promise.all([
          store.meta(),
          store.notes(),
          store.rejected(),
          store.checkpoints(),
          store.pending(),
        ]);
        const held = [];
        for (const note of stored) {
          held.push({ note, secret: await store.openNoteSecret(note) });
        }
        const result = await runSync(
          {
            meta,
            held,
            rejected: rejectedNotes,
            checkpoints,
            pending: pending.map((entry) => ({
              commitment: entry.commitment,
              submittedAtBlock: entry.submittedAtBlock,
            })),
          },
          chainAdapter(context, limits),
          cryptoAdapter(current.prover),
          {
            rescan,
            onProgress: (stage, detail) => {
              setSyncStage({ stage, detail: detail ?? null });
            },
          },
        );
        // Seal every note's secrets here, where the key is. The sync rules
        // never see an envelope and never see a key.
        const sealed = [];
        for (const entry of result.notes) {
          sealed.push({
            ...entry.note,
            secret: await store.sealNoteSecret(entry.note.commitment, entry.secret),
          });
        }
        await store.commitSync({
          meta: result.meta,
          notes: sealed,
          // The rows as this pass read them, so the write merges against
          // anything that moved since: see `WalletStore.commitSync`.
          base: stored,
          removedNotes: result.removedNotes,
          rejected: result.rejected,
          removedRejected: result.removedRejected,
          checkpoints: result.checkpoints,
          clearedPending: result.clearedPending,
        });
        setSyncReport(result.report);
        await refresh();
      } catch (syncError) {
        // A pass that got as far as reading the chain and failed is said out
        // loud whoever started it: this one is about the node rather than
        // about a button.
        setError((syncError as Error).message);
      } finally {
        running.current = null;
        setSyncing(false);
        setSyncStage(null);
      }
    },
    [refresh],
  );

  /**
   * The head this wallet has already read for, so a head is read once.
   *
   * A ref, because it is a latch rather than a thing a screen renders, and the
   * effect below both reads and writes it inside one run.
   */
  const autoSyncedAt = useRef<number | null>(null);

  /**
   * Sync when the wallet opens, and again on each new head.
   *
   * MyMonero syncs on open and on each new block and never says the word; this
   * wallet made a reader press an amber button for it, so the one accent on
   * the wallet screen was spent on housekeeping and a first-time visitor who
   * had just been paid saw 0.00 and a line about a session. The header already
   * subscribes to heads, so this costs one subscription and no polling.
   *
   * Refusals are silent here: see `sync`.
   */
  useEffect(() => {
    if (phase.kind !== 'open' || !storeUnlocked || !proverRunning) {
      return;
    }
    if (connection.kind !== 'live' || connection.head === undefined) {
      return;
    }
    if (autoSyncedAt.current === connection.head || running.current !== null) {
      return;
    }
    autoSyncedAt.current = connection.head;
    void sync(false, true);
  }, [phase.kind, storeUnlocked, proverRunning, connection, sync]);

  const send = useCallback(
    async (to: string, amount: bigint, memo: string): Promise<void> => {
      const current = session;
      const store = current.store;
      const context = current.context;
      const limits = current.limits;
      if (store === null || context === null || limits === null) {
        setSpendError('this wallet is not connected, or the prover has not loaded');
        return;
      }
      if (context.storageDrift.length > 0) {
        // The same gate the sync runs, hoisted above everything a payment
        // pays for. Without it a drifted runtime is met after the circuit
        // build, the anchor read and a whole tree rebuild.
        setSpendError(
          'this runtime declares storage differently from what this build assumes, so spending ' +
            'against it is refused. Nothing has been built and nothing has been submitted.',
        );
        return;
      }
      if (running.current !== null) {
        setSpendError(
          running.current === 'sync'
            ? 'a scan is running. It reads everything this wallet holds before it starts and ' +
              'commits at the end, so a payment settling underneath it would be writing the same ' +
              'rows from a later moment. Wait for the scan to finish.'
            : 'a payment is already being proved.',
        );
        return;
      }
      // Claimed here, above every `await` in this function. The genesis check
      // below reads the store, and while it was above this line two presses
      // inside that one await both reached it and both claimed `spend`.
      running.current = 'spend';
      setSpendRunning(true);
      setSpendError(null);
      setSpendResult(null);
      // The clock the sending screen shows starts at this button, so the
      // figure it quotes is measured from here too.
      const startedAt = performance.now();
      try {
        const mismatch = chainMismatchRefusal(
          (await store.meta()).genesisHash,
          context.genesisHash,
        );
        if (mismatch !== null) {
          // The gate `spend` opens with, hoisted here so it renders as a spend
          // error rather than arriving as a thrown string mid-payment. A note
          // written off against the wrong chain is a real note out of every
          // balance until a full rescan. The `finally` below hands the job slot
          // back on this return like any other.
          setSpendError(mismatch);
          return;
        }
        const stored = await store.notes();
        const candidates = [];
        for (const note of stored) {
          if (note.spent || !note.onChain) {
            continue;
          }
          candidates.push({ note, secret: await store.openNoteSecret(note) });
        }
        // One member per nullifier: a private batch constrains its two
        // nullifiers pairwise distinct, so two members in one leaf is a proof
        // that fails in circuit.
        const byNullifier = new Map<string, (typeof candidates)[number]>();
        for (const candidate of candidates) {
          const held = byNullifier.get(candidate.secret.nullifier);
          if (
            held === undefined ||
            BigInt(candidate.note.value) > BigInt(held.note.value) ||
            (BigInt(candidate.note.value) === BigInt(held.note.value) &&
              candidate.note.leafIndex < held.note.leafIndex)
          ) {
            byNullifier.set(candidate.secret.nullifier, candidate);
          }
        }
        const result = await spend(
          context,
          current.prover,
          store,
          {
            to,
            amount,
            memo,
            changeAddress: address,
            candidates: [...byNullifier.values()],
          },
          limits,
          (progress) => {
            setSpendProgress(progress);
            if (progress.stage === 'build') {
              setCircuitsBuilt(true);
              current.circuitsBuilt = true;
            }
          },
        );
        setSpendResult(result);
        // What the sending screen quotes next time. The published figure is
        // one workstation's; this one is the machine the reader is on. The
        // whole send rather than `result.proveMillis`: a payment is a circuit
        // build, two proofs, a submission and a wait for a block, and the
        // screen that quotes this prints it beside a clock measuring all five.
        //
        // Only when the block actually settled, which is the same expression
        // the result panel titles itself with. `spend` returns normally on a
        // settlement that timed out inside the 120-second wait and on one a
        // segment skipped, so an unsettled send used to store the timeout
        // itself: about 135 seconds against a real threaded cost of 24, kept
        // per browser until the next send that did settle. That is the failure
        // this figure was introduced to remove, arriving from the other side.
        if (result.inclusion?.settled === true) {
          writeMeasuredSendSeconds(proverThreads, performance.now() - startedAt);
          setMeasuredSendSeconds(readMeasuredSendSeconds(proverThreads));
        }
        await refresh();
      } catch (sendError) {
        setSpendError((sendError as Error).message);
      } finally {
        running.current = null;
        setSpendRunning(false);
        setSpendProgress(null);
      }
    },
    [address, proverThreads, refresh],
  );

  /**
   * Everything on screen that belongs to one wallet and one moment.
   *
   * One function rather than a line per field in `forget` and another in
   * `lock`, because the failure was a field that had been added to one and not
   * the other. `forget` promises that it clears every record, and the last
   * payment's recipient, amount, both nullifiers and extrinsic hash sat in
   * React state on the Send tab afterwards: one click and a wallet created
   * after the erase rendered the erased wallet's payment.
   */
  const clearWalletView = useCallback((): void => {
    setBirthdayNotice(null);
    setSpendProgress(null);
    setSpendResult(null);
    setSpendError(null);
    setSyncStage(null);
    setError(null);
    setUnlockError(null);
  }, []);

  const forget = useCallback(async (): Promise<void> => {
    const current = session;
    const store = current.store;
    if (store === null) {
      return;
    }
    await store.destroy();
    await current.lock();
    current.store = null;
    // `destroy` closed the handle and deleted the database. The next operation
    // that needs one opens a fresh database rather than writing through a
    // handle to a database that is gone.
    current.db = null;
    setStoreUnlocked(false);
    setAddress('');
    setMinerKey(null);
    setNotes([]);
    setRejected([]);
    setBalances(EMPTY_BALANCES);
    setSyncReport(null);
    setPendingBirthday(null);
    autoSyncedAt.current = null;
    clearWalletView();
    setPhase({ kind: 'landing' });
  }, [clearWalletView]);

  const lock = useCallback(async (): Promise<void> => {
    const current = session;
    const meta = await current.store?.meta();
    await current.lock();
    autoSyncedAt.current = null;
    setStoreUnlocked(false);
    setMinerKey(null);
    // The same reset a wipe does. A locked wallet that unlocks onto the last
    // payment it made, on a screen whose own notice says its text may name a
    // note, is the lock showing what the lock was for.
    clearWalletView();
    await refresh();
    if (meta !== undefined) {
      setPhase({ kind: 'locked', meta });
    }
  }, [clearWalletView, refresh]);

  const feeFloor = useMemo(() => {
    const context = session.context;
    const limits = session.limits;
    if (context === null || limits === null) {
      return 0n;
    }
    return feeFloorFor(context, limits);
    // The floor is a function of this runtime's constants and the memo pad,
    // both of which come from the connection, so it is recomputed when the
    // connection changes and at no other time. The session's own fields are
    // not React state, so they cannot be dependencies.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connection]);

  const chainName = config?.chainName ?? 'Qnero';
  const open = phase.kind === 'open';
  const wizard = phase.kind === 'create' || phase.kind === 'restore' || phase.kind === 'locked';

  /**
   * Where a route sends you when this phase does not allow it.
   *
   * One function rather than a guard per route, because the rule is about the
   * phase rather than about the path: a locked wallet has exactly one screen,
   * a wallet that does not exist yet has three, and an open one has four.
   */
  const redirectFor = (want: 'public' | 'locked' | 'open'): string | null => {
    if (phase.kind === 'open') {
      if (want === 'open') {
        return null;
      }
      // A wallet that just opened while the create or restore screen was up is
      // one somebody has this second finished making, and the first useful
      // thing about it is its address. Deciding it here rather than navigating
      // from the callback keeps one rule: a redirect that raced a navigation
      // put the new wallet on its balance screen about half the time.
      return want === 'public' ? '/receive' : '/wallet';
    }
    if (phase.kind === 'locked') {
      return want === 'locked' ? null : '/unlock';
    }
    return want === 'public' ? null : '/';
  };

  const guard = (want: 'public' | 'locked' | 'open', element: ReactNode): ReactNode => {
    const to = redirectFor(want);
    return to === null ? element : <Navigate to={to} replace />;
  };

  return (
    <div className="min-h-dvh bg-ground">
      <a
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50
          focus:rounded-control focus:bg-raised focus:px-3 focus:py-2 focus:text-ui focus:text-ink"
        href="#main"
      >
        Skip to content
      </a>
      {/* The wordmark and chain status share the content gutters and wrap
          when a narrow viewport needs another line. */}
      <header className="border-b border-edge bg-deep">
        <div
          className={
            open
              ? 'mx-auto flex min-h-16 w-full max-w-[var(--shell-width)] flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-4'
              : 'mx-auto flex min-h-16 w-full max-w-[var(--wizard-width)] flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-4'
          }
        >
          {/* The wordmark, in MyMonero's header type: the name in the body
              size at semibold, the descriptor beside it at label size in
              caps. "Qloak, a Qnero wallet" is the full form, and it is set
              where a subtitle has room: the tab title, the readme and the
              docs. */}
          <div className="flex items-baseline gap-2">
            <span className="text-body font-semibold tracking-label text-ink">Qloak</span>
            <span className="text-label uppercase tracking-label text-muted">wallet</span>
          </div>
          <span
            className="flex min-w-0 items-center gap-2 text-meta text-muted"
            data-testid="chain-status"
          >
            <span
              aria-hidden
              className={
                connection.kind === 'live'
                  ? 'size-[7px] shrink-0 rounded-full bg-positive'
                  : connection.kind === 'failed'
                    ? 'size-[7px] shrink-0 rounded-full bg-destructive'
                    : 'size-[7px] shrink-0 rounded-full bg-muted'
              }
            />
            {/* Tabular figures, because the block number and the countdown
                both change in place and a proportional digit shifts the
                sentence around them once a second. */}
            <span className="truncate tabular-nums">
              {chainName}
              {connection.kind === 'live' && connection.head !== undefined
                ? ` · block ${formatCount(connection.head)}`
                : connection.kind === 'connecting'
                  ? ' · connecting'
                  : connection.kind === 'failed'
                    ? retrySeconds === null
                      ? ' · no node'
                      : ` · no node · retrying in ${retrySeconds} s`
                    : ''}
            </span>
          </span>
        </div>
        {/* Two pixels of motion while the page loads itself, and none once it
            has. See `.mm-indeterminate`. */}
        {phase.kind === 'booting' && <div className="mm-indeterminate" role="presentation" />}
      </header>
      <div
        className={
          open
            ? 'mx-auto w-full max-w-[var(--shell-width)] px-4 pb-28 pt-6 sm:pt-8'
            : 'mx-auto w-full max-w-[var(--wizard-width)] px-4 pb-12 pt-6 sm:pt-8'
        }
      >
        <main id="main" className="space-y-4">
          {error !== null && (
            <Notice tone="error" testId="app-error" sensitive>
              {error}
            </Notice>
          )}

          {/* Said once, and put down. Where this wallet starts reading the
              chain lives in the wallet screen's status line and behind its
              Last sync disclosure; this is the one case that is not routine,
              which is a restore height, or a node that never answered. */}
          {birthdayNotice !== null && open && (
            <Notice
              testId="birthday-notice"
              onDismiss={() => {
                setBirthdayNotice(null);
              }}
            >
              {birthdayNotice}
            </Notice>
          )}

          {phase.kind === 'booting' && (
            <Panel>
              <p className="text-meta text-muted">Loading the prover…</p>
            </Panel>
          )}

          {phase.kind === 'broken' && (
            <Panel title="This wallet could not start">
              <Notice tone="error">{phase.message}</Notice>
            </Panel>
          )}

          {phase.kind !== 'booting' && phase.kind !== 'broken' && (
            <Routes>
              <Route
                path="/"
                element={guard('public', <Landing />)}
              />
              <Route
                path="/create"
                element={guard(
                  'public',
                  <CreateWallet
                    busy={busy}
                    // Said where it is actionable: the step that shows the
                    // spend key, rather than over the landing's two buttons.
                    storageWarning={
                      persisted
                        ? null
                        : 'This browser has not marked its storage persistent. Under storage ' +
                          'pressure it may drop this wallet, and what you write down now is then ' +
                          'the only way back to it.'
                    }
                    onCancel={() => {
                      void navigate('/');
                    }}
                    onCreated={(seedHex, passphrase) => {
                      void createWallet(seedHex, passphrase);
                    }}
                  />,
                )}
              />
              <Route
                path="/restore"
                element={guard(
                  'public',
                  <RestoreWallet
                    busy={busy}
                    head={connection.kind === 'live' ? (connection.head ?? null) : null}
                    targetBlockTimeMs={session.context?.targetBlockTimeMs ?? null}
                    onCancel={() => {
                      void navigate('/');
                    }}
                    onRestore={(seedHex, passphrase, restoreHeight) => {
                      void createWallet(seedHex, passphrase, restoreHeight);
                    }}
                  />,
                )}
              />
              <Route
                path="/unlock"
                element={guard(
                  'locked',
                  <Unlock
                    address={phase.kind === 'locked' ? phase.meta.address : ''}
                    busy={busy}
                    error={unlockError}
                    onUnlock={(passphrase) => {
                      void unlock(passphrase);
                    }}
                    onForget={() => {
                      void forget();
                    }}
                  />,
                )}
              />
              <Route
                path="/wallet"
                element={guard(
                  'open',
                  <BalanceScreen
                    balances={balances}
                    notes={notes}
                    rejected={rejected}
                    readsFrom={readsFrom}
                    report={syncReport}
                    syncing={syncing}
                    syncStage={syncStage}
                    // The prover too. A sync runs every node gate and pages
                    // the whole settled set before it needs the worker, so a
                    // stopped prover spends all of that to refuse.
                    //
                    // And never while a payment is in flight: the scan reads
                    // every note at the start and commits at the end, and the
                    // payment writes `spent` on those same rows when it
                    // settles.
                    canSync={connection.kind === 'live' && proverRunning && !spendRunning}
                    // Why it is off, in the line beside it. A control that
                    // refuses and says nothing is the wallet having stopped.
                    syncBlocked={
                      connection.kind === 'connecting'
                        ? 'connecting to the node'
                        : connection.kind !== 'live'
                          ? retrySeconds === null
                            ? 'no node: check Settings'
                            : pointAtSettings
                              ? `no node: retrying in ${retrySeconds} s, or check Settings`
                              : `no node: retrying in ${retrySeconds} s`
                          : !proverRunning
                          ? 'prover stopped: check Settings'
                          : spendRunning
                            ? 'a payment is being proved'
                            : null
                    }
                    onSync={() => {
                      void sync(false);
                    }}
                  />,
                )}
              />
              <Route
                path="/send"
                element={guard(
                  'open',
                  <SendScreen
                    feeFloor={feeFloor}
                    memoBytes={session.limits?.memo_bytes ?? 61}
                    reachable={balances.reachable}
                    // This machine's last payment if there has been one. The
                    // published figure is a first-payment estimate and it was
                    // out by a factor of two on this workstation, which the
                    // sending screen then printed beside its own elapsed
                    // clock. See `app/proverMode.ts`.
                    measuredSeconds={measuredSendSeconds}
                    provingSeconds={
                      proverThreads > 1
                        ? (config?.expectedProvingSeconds.threaded ?? 12)
                        : (config?.expectedProvingSeconds.single ?? 36)
                    }
                    // The block half of the wait, from the chain, and null
                    // until the chain has answered. `Session.connect` publishes
                    // the context before `openConnection` writes the target
                    // into this state, and `SendScreen` is mounted on the
                    // wallet being open, with the connection's state reaching
                    // no gate above it, so a send pressed inside that window
                    // would otherwise quote
                    // "one block interval of 0 seconds" to the one reader who
                    // has no measured figure to correct it: a first payment.
                    blockSeconds={
                      connection.targetBlockTimeMs === undefined
                        ? null
                        : Math.round(connection.targetBlockTimeMs / 1000)
                    }
                    checkAddress={(candidate) => session.prover.addressIsValid(candidate)}
                    circuitsBuilt={circuitsBuilt}
                    proverThreads={proverThreads}
                    progress={spendProgress}
                    running={spendRunning}
                    // The other half of the rule `canSync` carries: one of the
                    // two long jobs at a time, and the button says which is
                    // holding it rather than refusing on the press.
                    syncing={syncing}
                    result={spendResult}
                    error={spendError}
                    onDismiss={() => {
                      setSpendResult(null);
                      setSpendError(null);
                      void navigate('/wallet');
                    }}
                    onSend={(to, amount, memo) => {
                      void send(to, amount, memo);
                    }}
                  />,
                )}
              />
              <Route
                path="/receive"
                element={guard(
                  'open',
                  <ReceiveScreen
                    address={address}
                    minerKey={minerKey}
                    locked={!storeUnlocked}
                    onRevealMinerKey={() => {
                      void (async (): Promise<void> => {
                        // No seed crosses here. The worker has held it since
                        // the unlock, and re-reading the vault to hand it back
                        // would put a second uncleanable copy of the spend key
                        // in this page and a third in the worker, for a
                        // derivation the worker can already do.
                        setMinerKey(await session.prover.minerKey());
                      })();
                    }}
                  />,
                )}
              />
              <Route
                path="/settings"
                element={guard(
                  'open',
                  <SettingsScreen
                    connection={connection}
                    chainName={chainName}
                    endpoint={connection.endpoint}
                    busy={busy || syncing}
                    spending={spendRunning}
                    persisted={persisted}
                    proverThreads={proverThreads}
                    proverRunning={proverRunning}
                    onEndpoint={(endpoint) => {
                      writeEndpoint(endpoint);
                      void openConnection(endpoint);
                    }}
                    onLock={() => {
                      void lock();
                    }}
                    onRescan={() => {
                      void navigate('/wallet');
                      void sync(true);
                    }}
                    onStopProver={() => {
                      session.stopProver();
                      setCircuitsBuilt(false);
                      // Read back rather than assumed: the switch on screen
                      // and the session have to agree about whether a worker
                      // is running, and the client is what knows.
                      setProverRunning(session.prover.isRunning);
                    }}
                    onStartProver={() => {
                      void (async (): Promise<void> => {
                        if (config === null) {
                          return;
                        }
                        setBusy(true);
                        setError(null);
                        try {
                          setProverThreads(await session.restartProver(config));
                          setProverRunning(session.prover.isRunning);
                          setCircuitsBuilt(session.circuitsBuilt);
                        } catch (startError) {
                          setError((startError as Error).message);
                        } finally {
                          setBusy(false);
                        }
                      })();
                    }}
                    onForget={() => {
                      void forget();
                    }}
                  />,
                )}
              />
              <Route path="*" element={<Navigate to={open ? '/wallet' : '/'} replace />} />
            </Routes>
          )}
        </main>

        {!open && !wizard && (
          <footer className="mt-6 text-meta text-muted">
            keys in this browser · proofs in a worker · no server
          </footer>
        )}
      </div>

      {open && <TabBar />}
    </div>
  );
}
