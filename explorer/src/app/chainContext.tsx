/**
 * The connection, shared by every page.
 *
 * One WebSocket, one metadata read, one head subscription. Subscriptions are
 * WS only, which is why the configured endpoint has to be one.
 */

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { connect, type ChainContext } from '../chain/api';
import { BlockCache } from '../chain/blocks';
import { loadConfig, type ExplorerConfig } from '../chain/config';
import {
  fetchConsensusConstants,
  type ConsensusConstants,
} from '../chain/state';
import { parseHeader, type BlockHeader } from '../lib/header';
import { messageOf } from './useAsync';

export type ConnectionStatus = 'connecting' | 'live' | 'offline' | 'failed';

/**
 * How long the first connection is given before the page says so.
 *
 * A WsProvider retries an unreachable endpoint on its own and `ApiPromise`
 * never settles while it does, so without a deadline the commonest deployment
 * mistake, a wrong or down endpoint, reads as "connecting" and "Reading the
 * chain head" for as long as the tab is open, with the 'failed' state built for
 * it unreachable.
 */
const CONNECT_DEADLINE_MS = 15_000;

export interface Head {
  header: BlockHeader;
  hash: string;
}

export interface ChainBundle {
  config: ExplorerConfig;
  context: ChainContext;
  /**
   * Null until the three runtime calls answer, and null for good if they do
   * not. They are read after the connection is published, so a node that
   * refuses `state_call` or a runtime that renames a `QPoWApi` method costs
   * the fields that need them and nothing else.
   */
  constants: ConsensusConstants | null;
  constantsError: string | null;
  cache: BlockCache;
}

interface ChainState {
  status: ConnectionStatus;
  bundle: ChainBundle | null;
  /** Held from the moment config.json is read, so a failing address can be shown while it fails. */
  endpoint: string | null;
  /**
   * Held from the same moment, so the header names the chain this page is
   * pointed at from the first paint. The slot used to read "no chain" for the
   * whole connect, which is the first thing a visitor read about the chain.
   */
  chainName: string | null;
  head: Head | null;
  error: string | null;
}

const Context = createContext<ChainState>({
  status: 'connecting',
  bundle: null,
  endpoint: null,
  chainName: null,
  head: null,
  error: null,
});

/** The connection, with a deadline, and no socket left retrying behind a failed page. */
async function connectWithin(endpoint: string, ms: number): Promise<ChainContext> {
  const attempt = connect(endpoint);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      attempt,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(
            new Error(
              `${endpoint} did not answer in ${ms / 1000} seconds. The node may be down, or this page may be configured with the wrong endpoint.`,
            ),
          );
        }, ms);
      }),
    ]);
  } catch (error: unknown) {
    void attempt.then(
      (context) => context.api.disconnect(),
      () => undefined,
    );
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function useChain(): ChainState {
  return useContext(Context);
}

export function ChainProvider({ children }: { children: ReactNode }): ReactNode {
  const [state, setState] = useState<ChainState>({
    status: 'connecting',
    bundle: null,
    endpoint: null,
    chainName: null,
    head: null,
    error: null,
  });

  useEffect(() => {
    const session = { live: true };
    const stillLive = (): boolean => session.live;
    let unsubscribe: (() => void) | null = null;
    let bundle: ChainBundle | null = null;

    const start = async (): Promise<void> => {
      const config = await loadConfig();
      if (stillLive()) {
        setState((previous) => ({
          ...previous,
          endpoint: config.rpcEndpoint,
          chainName: config.chainName,
        }));
      }
      const context = await connectWithin(config.rpcEndpoint, CONNECT_DEADLINE_MS);
      if (!stillLive()) {
        await context.api.disconnect();
        return;
      }
      bundle = {
        config,
        context,
        constants: null,
        constantsError: null,
        cache: new BlockCache(),
      };
      setState((previous) => ({ ...previous, status: 'live', bundle, error: null }));

      // The consensus constants are three runtime calls, and a page that needs
      // none of them should not wait for them or die with them.
      const settleConstants = (
        constants: ConsensusConstants | null,
        constantsError: string | null,
      ): void => {
        if (!stillLive()) {
          return;
        }
        setState((previous) =>
          previous.bundle === null
            ? previous
            : { ...previous, bundle: { ...previous.bundle, constants, constantsError } },
        );
      };
      void fetchConsensusConstants(context).then(
        (constants) => {
          settleConstants(constants, null);
        },
        (error: unknown) => {
          settleConstants(null, messageOf(error));
        },
      );

      context.api.on('disconnected', () => {
        setState((previous) => ({ ...previous, status: 'offline' }));
      });
      context.api.on('connected', () => {
        setState((previous) => ({ ...previous, status: 'live' }));
      });

      const onHead = async (raw: unknown): Promise<void> => {
        const header = parseHeader(raw);
        const hash = await context.provider.send<string | null>('chain_getBlockHash', [
          header.number,
        ]);
        if (stillLive() && hash !== null) {
          setState((previous) => ({ ...previous, head: { header, hash } }));
        }
      };

      const id = await context.provider.subscribe(
        'chain_newHead',
        'chain_subscribeNewHeads',
        [],
        (error, raw: unknown) => {
          if (error === null) {
            void onHead(raw);
          }
        },
      );
      unsubscribe = () => {
        void context.provider.unsubscribe('chain_newHead', 'chain_unsubscribeNewHeads', id);
      };
      // The subscription only fires on the next block, so seed the head now.
      const bestHash = await context.provider.send<string>('chain_getBlockHash', []);
      const bestHeader = await context.provider.send<unknown>('chain_getHeader', [bestHash]);
      if (stillLive()) {
        const seeded: Head = { header: parseHeader(bestHeader), hash: bestHash };
        setState((previous) => ({
          ...previous,
          head: previous.head === null ? seeded : previous.head,
        }));
      }
    };

    start().catch((error: unknown) => {
      if (stillLive()) {
        setState((previous) => ({
          status: 'failed',
          bundle: null,
          endpoint: previous.endpoint,
          chainName: previous.chainName,
          head: null,
          error: messageOf(error),
        }));
      }
    });

    return () => {
      session.live = false;
      unsubscribe?.();
      void bundle?.context.api.disconnect();
    };
  }, []);

  const value = useMemo(() => state, [state]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
