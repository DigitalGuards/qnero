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

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Navigate, Route, Routes, useNavigate } from 'react-router';

import { loadConfig, type WalletConfig } from './chain/config';
import { fetchHead } from './chain/reads';
import { chainAdapter, cryptoAdapter } from './app/adapters';
import { readEndpoint, writeEndpoint } from './app/endpoint';
import { readMeasuredSendSeconds, writeMeasuredSendSeconds } from './app/proverMode';
import { Session, type ConnectionState } from './app/session';
import { Notice } from './components/UI/Notice';
import { Panel } from './components/UI/Panel';
import { ThemeToggle } from './components/UI/ThemeToggle';
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
  newSalt,
  bytesToHex,
  hexToBytes,
  PBKDF2_ITERATIONS,
  WrongPassphraseError,
} from './wallet/crypto';
import { createStore, WalletStore } from './wallet/store';
import type { Balances, NoteRow, RejectedNote, StoreMeta, StoredNote } from './wallet/model';
import { reachableTotal, spendable } from './wallet/select';
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

export function App(): ReactNode {
  const navigate = useNavigate();
  const [config, setConfig] = useState<WalletConfig | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: 'booting' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unlockError, setUnlockError] = useState<string | null>(null);

  const [address, setAddress] = useState('');
  const [minerKey, setMinerKey] = useState<string | null>(null);
  const [balances, setBalances] = useState<Balances>(EMPTY_BALANCES);
  const [notes, setNotes] = useState<NoteRow[]>([]);
  const [rejected, setRejected] = useState<RejectedNote[]>([]);
  const [syncReport, setSyncReport] = useState<SyncReport | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncStage, setSyncStage] = useState<string | null>(null);

  const [connection, setConnection] = useState<ConnectionState>({
    kind: 'offline',
    endpoint: '',
  });
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

  /** Recompute the view of the store. Locked wallets get everything but memos. */
  const refresh = useCallback(async (): Promise<void> => {
    const store = session.store;
    if (store === null) {
      return;
    }
    const [stored, pending, rejectedNotes] = await Promise.all([
      store.notes(),
      store.pending(),
      store.rejected(),
    ]);

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

    setNotes(rows);
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
      setConnection({ kind: 'connecting', endpoint });
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
          drift: context.storageDrift,
        });
      } catch (connectError) {
        setConnection({
          kind: 'failed',
          endpoint,
          error: (connectError as Error).message,
        });
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

  // The worker's progress, wherever it comes from.
  useEffect(() => {
    return session.prover.onProgress((stage, detail) => {
      setSyncStage(detail === undefined ? stage : `${stage}: ${detail}`);
    });
  }, []);

  const createWallet = useCallback(
    async (seedHex: string, passphrase: string): Promise<void> => {
      const current = session;
      setBusy(true);
      setError(null);
      try {
        const db = await current.openDatabase();
        // One crossing. The seed goes to the worker as a transferred buffer,
        // the page's copy is detached by the transfer, and the answer carries
        // the address the store binds its records to. It used to cross twice:
        // a `deriveAccount` request carrying the seed as a plain string, which
        // structured clone copies into the worker's heap where neither side
        // can erase it, for an address this call already returns.
        const account = await current.prover.unlock(hexToBytes(seedHex));
        const saltHex = bytesToHex(newSalt());
        const key = await deriveKey(passphrase, saltHex);
        const store = await createStore(db, {
          address: account.address,
          seedHex,
          key,
          saltHex,
          iterations: PBKDF2_ITERATIONS,
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
    [refresh],
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
        const key = await deriveKey(passphrase, phase.meta.kdf.saltHex);
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

  const sync = useCallback(
    async (rescan: boolean): Promise<void> => {
      const current = session;
      const store = current.store;
      const context = current.context;
      if (store === null) {
        return;
      }
      if (context === null) {
        setError('this wallet is not connected to a node');
        return;
      }
      if (context.storageDrift.length > 0) {
        setError(
          'this runtime declares storage differently from what this build assumes, so syncing ' +
            'against it is refused. An absent key and an empty map are indistinguishable, and an ' +
            'empty map here is a zero balance or a settled note reported unspent.',
        );
        return;
      }
      if (!store.isUnlocked) {
        setError('unlock this wallet before syncing: a scan needs its viewing key');
        return;
      }
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
            pending: pending.map((entry) => entry.commitment),
          },
          chainAdapter(context),
          cryptoAdapter(current.prover),
          {
            rescan,
            onProgress: (stage, detail) => {
              setSyncStage(detail === undefined ? stage : `${stage}, ${detail}`);
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
          removedNotes: result.removedNotes,
          rejected: result.rejected,
          removedRejected: result.removedRejected,
          checkpoints: result.checkpoints,
          clearedPending: result.clearedPending,
        });
        setSyncReport(result.report);
        await refresh();
      } catch (syncError) {
        setError((syncError as Error).message);
      } finally {
        setSyncing(false);
        setSyncStage(null);
      }
    },
    [refresh],
  );

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
      const mismatch = chainMismatchRefusal((await store.meta()).genesisHash, context.genesisHash);
      if (mismatch !== null) {
        // The gate `spend` opens with, hoisted here so it renders as a spend
        // error rather than arriving as a thrown string mid-payment. A note
        // written off against the wrong chain is a real note out of every
        // balance until a full rescan.
        setSpendError(mismatch);
        return;
      }
      setSpendRunning(true);
      setSpendError(null);
      setSpendResult(null);
      // The clock the sending screen shows starts at this button, so the
      // figure it quotes is measured from here too.
      const startedAt = performance.now();
      try {
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
        writeMeasuredSendSeconds(proverThreads, performance.now() - startedAt);
        setMeasuredSendSeconds(readMeasuredSendSeconds(proverThreads));
        await refresh();
      } catch (sendError) {
        setSpendError((sendError as Error).message);
      } finally {
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
    clearWalletView();
    setPhase({ kind: 'landing' });
  }, [clearWalletView]);

  const lock = useCallback(async (): Promise<void> => {
    const current = session;
    const meta = await current.store?.meta();
    await current.lock();
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
      <div
        className={
          open
            ? 'mx-auto w-full max-w-[var(--shell-width)] px-4 pb-24 pt-4'
            : 'mx-auto w-full max-w-[var(--wizard-width)] px-4 pb-10 pt-4'
        }
      >
        <header className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-baseline gap-2">
            <span className="text-body font-semibold tracking-label text-ink">Qnero</span>
            <span className="text-label uppercase tracking-label text-muted">wallet</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 text-meta text-muted" data-testid="chain-status">
              <span
                aria-hidden
                className={
                  connection.kind === 'live'
                    ? 'size-1.5 rounded-full bg-positive'
                    : connection.kind === 'failed'
                      ? 'size-1.5 rounded-full bg-destructive'
                      : 'size-1.5 rounded-full bg-dim'
                }
              />
              {chainName}
              {connection.kind === 'live' && connection.head !== undefined
                ? ` · block ${connection.head}`
                : connection.kind === 'connecting'
                  ? ' · connecting'
                  : connection.kind === 'failed'
                    ? ' · no node'
                    : ''}
            </span>
            <ThemeToggle />
          </div>
        </header>

        <main id="main" className="space-y-3">
          {error !== null && (
            <Notice tone="error" testId="app-error" sensitive>
              {error}
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
                element={guard(
                  'public',
                  <Landing
                    storageWarning={
                      !persisted
                        ? 'This browser has not marked its storage persistent. Under storage ' +
                          'pressure it may drop this wallet, and the seed written down is then ' +
                          'the only way back to it. Write the spend key down.'
                        : null
                    }
                  />,
                )}
              />
              <Route
                path="/create"
                element={guard(
                  'public',
                  <CreateWallet
                    busy={busy}
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
                    onCancel={() => {
                      void navigate('/');
                    }}
                    onRestore={(seedHex, passphrase) => {
                      void createWallet(seedHex, passphrase);
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
                    report={syncReport}
                    syncing={syncing}
                    syncStage={syncStage}
                    // The prover too. A sync runs every node gate and pages
                    // the whole settled set before it needs the worker, so a
                    // stopped prover spends all of that to refuse.
                    canSync={connection.kind === 'live' && proverRunning}
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
                    expectedSeconds={
                      // This machine's last payment if there has been one.
                      // The published figure is a first-payment estimate and
                      // it was out by a factor of two on this workstation,
                      // which the sending screen then printed beside its own
                      // elapsed clock. See `app/proverMode.ts`.
                      measuredSendSeconds ??
                      (proverThreads > 1
                        ? (config?.expectedSendSeconds.threaded ?? 23)
                        : (config?.expectedSendSeconds.single ?? 55))
                    }
                    expectedFrom={measuredSendSeconds === null ? 'published' : 'measured'}
                    checkAddress={(candidate) => session.prover.addressIsValid(candidate)}
                    circuitsBuilt={circuitsBuilt}
                    proverThreads={proverThreads}
                    progress={spendProgress}
                    running={spendRunning}
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
