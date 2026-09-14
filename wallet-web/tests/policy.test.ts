/**
 * Two rules that sit outside the app's own code, and hold only while something
 * checks them.
 *
 * The Content-Security-Policy is what turns "this page contacts nothing but
 * the node you configure" from a sentence in the README into a refusal the
 * browser makes. It is one string in `vite.config.ts`, and the edit that would
 * matter reads as harmless in review: a `https:` added to `connect-src` opens
 * every destination a compromised dependency would reach for, the page goes on
 * working, and nothing else in this suite would say a word. The seed is
 * reachable at three points (the unlock message into the worker, the create
 * path's seed hex, and the create wizard's own state), so the directive that
 * decides where bytes may go is the one with a test on it.
 *
 * The reconnect delay decides whether a session survives a laptop sleeping, a
 * network changing or a node restarting. `WsProvider` takes `false` for "do
 * not retry", which is what it was given, and the failure was silent: in-flight
 * requests rejected, nothing scheduled afterwards, and a green dot over a dead
 * socket for the life of the tab. The delay and the two socket edges the status
 * strip follows are asserted here because a browser is the only other place
 * they show.
 */

import { describe, expect, it } from 'vitest';

import { CONTENT_SECURITY_POLICY } from '../vite.config';
import { RECONNECT_DELAY_MS, watchConnection, type ChainContext } from '../src/chain/api';

/** One directive's sources, by name, as the policy spells them. */
function sources(name: string): string[] {
  const found = CONTENT_SECURITY_POLICY.split('; ').find(
    (entry) => entry === name || entry.startsWith(`${name} `),
  );
  if (found === undefined) {
    throw new Error(`the policy declares no ${name}`);
  }
  return found.split(' ').slice(1);
}

describe('the policy the built page carries', () => {
  it('refuses every source it does not name', () => {
    expect(sources('default-src')).toEqual(["'none'"]);
  });

  it('admits scripts from this origin alone, plus the keyword wasm compilation needs', () => {
    expect(sources('script-src')).toEqual(["'self'", "'wasm-unsafe-eval'"]);
  });

  it('leaves eval and inline script out, which is how a copied policy stays the built one', () => {
    // The dev server relaxes `script-src` for React's refresh preamble. That
    // relaxation is named in `vite.config.ts` and lives on that path alone;
    // what ships carries neither keyword.
    expect(CONTENT_SECURITY_POLICY).not.toContain("'unsafe-eval'");
    expect(sources('script-src')).not.toContain("'unsafe-inline'");
  });

  it('allows a WebSocket to the configured node, and no http destination at all', () => {
    // The endpoint is chosen at runtime from the settings screen, so the
    // scheme is the part that can be pinned here. `http:` or `https:` in this
    // list is a `fetch` that carries a seed off the machine.
    expect(sources('connect-src')).toEqual(["'self'", 'ws:', 'wss:']);
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/https?:/);
  });

  it('keeps images and fonts local, with the data URLs a QR code is drawn from', () => {
    expect(sources('img-src')).toEqual(["'self'", 'data:']);
    expect(sources('font-src')).toEqual(["'self'"]);
  });

  it('admits the workers the prover and its rayon pool are', () => {
    expect(sources('worker-src')).toEqual(["'self'", 'blob:']);
  });

  it('pins the base URL and the form target, which this app has no use for', () => {
    expect(sources('base-uri')).toEqual(["'none'"]);
    expect(sources('form-action')).toEqual(["'none'"]);
  });

  it('carries no wildcard, in any directive', () => {
    expect(CONTENT_SECURITY_POLICY).not.toContain('*');
  });
});

/** A provider that records what was subscribed and what was dropped. */
function fakeSocket(): {
  context: ChainContext;
  emit: (type: 'connected' | 'disconnected') => void;
  listening: () => number;
} {
  const listeners = new Map<string, () => void>();
  const context = {
    provider: {
      on: (type: string, handler: () => void) => {
        listeners.set(type, handler);
        return () => {
          listeners.delete(type);
        };
      },
    },
  } as unknown as ChainContext;
  return {
    context,
    emit: (type) => {
      const handler = listeners.get(type);
      if (handler === undefined) {
        throw new Error(`nothing is listening for ${type}`);
      }
      handler();
    },
    listening: () => listeners.size,
  };
}

describe('the socket the page follows', () => {
  it('waits and tries again, because a session that ends at the first drop ends for good', () => {
    expect(RECONNECT_DELAY_MS).toBeGreaterThan(0);
    expect(RECONNECT_DELAY_MS).toBeLessThanOrEqual(10_000);
  });

  it('reports a drop, which is what moves the status strip off live', () => {
    const socket = fakeSocket();
    let drops = 0;
    watchConnection(socket.context, { onDisconnected: () => (drops += 1) });
    socket.emit('disconnected');
    expect(drops).toBe(1);
  });

  it('reports the reconnection the provider makes on its own', () => {
    const socket = fakeSocket();
    let ups = 0;
    watchConnection(socket.context, { onConnected: () => (ups += 1) });
    socket.emit('connected');
    socket.emit('connected');
    expect(ups).toBe(2);
  });

  it('stops listening on both edges when it is told to', () => {
    const socket = fakeSocket();
    const stop = watchConnection(socket.context, { onConnected: () => undefined });
    expect(socket.listening()).toBe(2);
    stop();
    expect(socket.listening()).toBe(0);
  });
});
