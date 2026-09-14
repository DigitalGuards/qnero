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

export interface Head {
  header: BlockHeader;
  hash: string;
}

export interface ChainBundle {
  config: ExplorerConfig;
  context: ChainContext;
  constants: ConsensusConstants;
  cache: BlockCache;
}

interface ChainState {
  status: ConnectionStatus;
  bundle: ChainBundle | null;
  head: Head | null;
  error: string | null;
}

const Context = createContext<ChainState>({
  status: 'connecting',
  bundle: null,
  head: null,
  error: null,
});

export function useChain(): ChainState {
  return useContext(Context);
}

export function ChainProvider({ children }: { children: ReactNode }): ReactNode {
  const [state, setState] = useState<ChainState>({
    status: 'connecting',
    bundle: null,
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
      const context = await connect(config.rpcEndpoint);
      const constants = await fetchConsensusConstants(context);
      if (!stillLive()) {
        await context.api.disconnect();
        return;
      }
      bundle = { config, context, constants, cache: new BlockCache() };
      setState((previous) => ({ ...previous, status: 'live', bundle, error: null }));

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
        setState({ status: 'failed', bundle: null, head: null, error: messageOf(error) });
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
