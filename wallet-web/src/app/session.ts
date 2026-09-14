/**
 * The session: the things that are one per tab and are not React state.
 *
 * The worker, the database handle, the chain connection and the derived key
 * all outlive any render and none of them belongs in a component. What React
 * holds is the view of them.
 */

import { connect, watchConnection, type ChainContext } from '../chain/api';
import { watchHead } from '../chain/reads';
import type { WalletConfig } from '../chain/config';
import { ProverClient } from '../worker/client';
import type { ProverAccount, ProverLimits } from '../worker/protocol';
import { openDatabase, requestPersistence, WalletStore } from '../wallet/store';
import type { StoreMeta } from '../wallet/model';
import { readThreadCap } from './proverMode';

export interface ConnectionState {
  kind: 'offline' | 'connecting' | 'live' | 'failed';
  endpoint: string;
  head?: number;
  chainName?: string;
  specName?: string;
  specVersion?: number;
  error?: string;
  drift?: string[];
}

export class Session {
  readonly prover = new ProverClient();
  db: IDBDatabase | null = null;
  store: WalletStore | null = null;
  context: ChainContext | null = null;
  account: ProverAccount | null = null;
  limits: ProverLimits | null = null;
  /** Whether the store's origin is exempt from eviction. */
  persisted = false;
  /** Whether the circuits are resident, which is what a payment waits on. */
  circuitsBuilt = false;
  /** Subscriptions on the current connection, dropped when it is replaced. */
  private watching: (() => void)[] = [];

  async openDatabase(): Promise<IDBDatabase> {
    if (this.db === null) {
      this.db = await openDatabase();
      this.persisted = await requestPersistence();
    }
    return this.db;
  }

  async loadMeta(): Promise<StoreMeta | null> {
    const db = await this.openDatabase();
    const opened = await WalletStore.open(db);
    return opened === null ? null : opened.meta;
  }

  async startProver(config: WalletConfig): Promise<number> {
    // Resolved against the document rather than left relative. A worker
    // resolves a relative URL against its own script, and a built worker lives
    // in `assets/`, so `wasm/` from inside one asks for `assets/wasm/` and
    // gets a 404 that reads as a missing prover.
    const base = new URL(config.wasmBase, document.baseURI).href;
    const answer = await this.prover.init(base, config.numLeaves, readThreadCap());
    this.limits = answer.limits;
    return answer.threads;
  }

  /**
   * Connect, and follow both things that change under a live connection: the
   * socket and the head.
   *
   * The listeners are how the page's status strip stays true. Without them the
   * connection state is decided once, at the one connect that succeeded, and a
   * dropped socket reads as a green dot over a block height that stopped
   * moving twenty blocks ago.
   */
  async connect(
    endpoint: string,
    listeners: { onStatus: (kind: 'live' | 'connecting') => void; onHead: (height: number) => void },
  ): Promise<ChainContext> {
    await this.disconnect();
    const context = await connect(endpoint);
    this.context = context;
    this.watching.push(
      watchConnection(context, {
        onConnected: () => {
          listeners.onStatus('live');
        },
        onDisconnected: () => {
          listeners.onStatus('connecting');
        },
      }),
    );
    this.watching.push(await watchHead(context, listeners.onHead));
    return context;
  }

  async disconnect(): Promise<void> {
    for (const stop of this.watching.splice(0)) {
      try {
        stop();
      } catch {
        // A subscription on a socket that has already gone. Nothing to undo.
      }
    }
    if (this.context === null) {
      return;
    }
    const context = this.context;
    this.context = null;
    await context.api.disconnect().catch(() => undefined);
  }

  /** Drop the key handle and the worker's seed. Everything sealed closes. */
  async lock(): Promise<void> {
    this.store?.lock();
    this.account = null;
    await this.prover.lock().catch(() => undefined);
  }

  /**
   * Start the worker again after it was stopped, and hand it the seed if this
   * wallet is open.
   *
   * The seed is the part that is easy to forget: stopping the worker takes the
   * seed with it, so a worker restarted without this one syncs to "this wallet
   * is locked, so the worker holds no seed" while the page shows an unlocked
   * wallet.
   */
  async restartProver(config: WalletConfig): Promise<number> {
    const threads = await this.startProver(config);
    const store = this.store;
    if (store !== null && store.isUnlocked) {
      const seed = await store.seed();
      this.account = await this.prover.unlock(seed as Uint8Array<ArrayBuffer>);
    }
    return threads;
  }

  /**
   * Stop the worker, which is the only way the circuits' linear memory comes
   * back. The next payment pays the twelve-second build again.
   */
  stopProver(): void {
    this.prover.terminate();
    this.circuitsBuilt = false;
    this.limits = null;
  }
}
