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
 * The palette is the third. Hue separation is not visible in a diff and it is
 * not visible in a screenshot of one screen either: what went wrong was that
 * the accent and the notice ended up 11 to 16 degrees apart, so the storage
 * warning over "Create new wallet" and the circuits notice over "Send" read as
 * one warm block. The rule is stated here because nothing else can hold it.
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

import { readFileSync } from 'node:fs';

import { CONTENT_SECURITY_POLICY, cspDirectives } from '../vite.config';
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

  it('refuses every http destination, and admits a WebSocket to any host', () => {
    // Both halves, because only the first was true of the claim this replaces.
    // `http:` or `https:` in this list is a `fetch` that carries a seed off
    // the machine, and it is absent. `ws:` and `wss:` are a WebSocket to any
    // host at all, which is the residual exfiltration path and is the reason
    // a deployment with a fixed node should build with `QNERO_ENDPOINT`.
    expect(sources('connect-src')).toEqual(["'self'", 'ws:', 'wss:']);
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/https?:/);
  });

  it('pins one origin when the build is given one, and drops the wide schemes', () => {
    const pinned = cspDirectives('wss://node.example:443/some/path');
    expect(pinned).toContain("connect-src 'self' wss://node.example");
    expect(pinned.join('; ')).not.toMatch(/\bwss:(?!\/\/)/);
    expect(pinned.join('; ')).not.toMatch(/\bws:(?!\/\/)/);
  });

  it('refuses a build endpoint that is not a WebSocket, rather than shipping a dead policy', () => {
    expect(() => cspDirectives('https://node.example')).toThrow(/reached over ws or wss/);
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

// ---------------------------------------------------------------------------
// The palette, and the one thing a screenshot of a single screen cannot show.
// ---------------------------------------------------------------------------

const TOKENS = readFileSync(new URL('../src/styles/tokens.css', import.meta.url), 'utf8');
const APP_CSS = readFileSync(new URL('../src/styles/app.css', import.meta.url), 'utf8');

/** The declarations of one rule block, by the selector that opens it. */
function declarations(selector: string): Map<string, string> {
  const start = TOKENS.indexOf(selector);
  if (start < 0) {
    throw new Error(`the token file declares no ${selector}`);
  }
  let depth = 0;
  let end = start;
  for (let index = TOKENS.indexOf('{', start); index < TOKENS.length; index += 1) {
    if (TOKENS[index] === '{') {
      depth += 1;
    }
    if (TOKENS[index] === '}') {
      depth -= 1;
      if (depth === 0) {
        end = index;
        break;
      }
    }
  }
  const out = new Map<string, string>();
  for (const match of TOKENS.slice(start, end).matchAll(/(--[\w-]+):\s*([^;]+);/g)) {
    out.set(match[1] ?? '', (match[2] ?? '').trim());
  }
  return out;
}

const LIGHT = declarations(':root {');
const DARK_OVER = declarations(":root[data-theme='dark'] {");
const DARK = new Map([...LIGHT, ...DARK_OVER]);

/** One token's value, following `var()` indirection the way a browser does. */
function resolve(theme: Map<string, string>, name: string, depth = 0): string {
  const value = theme.get(name);
  if (value === undefined) {
    throw new Error(`no ${name} in this theme`);
  }
  const reference = /^var\((--[\w-]+)\)$/.exec(value);
  if (reference === null || depth > 4) {
    return value;
  }
  return resolve(theme, reference[1] ?? '', depth + 1);
}

/** Hue in degrees and saturation in 0..1, from a `#rrggbb` value. */
function hsl(hex: string): { hue: number; saturation: number } {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  if (match === null) {
    throw new Error(`${hex} is not a six-digit hex colour`);
  }
  const body = match[1] ?? '';
  const [r, g, b] = [0, 2, 4].map((at) => Number.parseInt(body.slice(at, at + 2), 16) / 255) as [
    number,
    number,
    number,
  ];
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const span = max - min;
  const lightness = (max + min) / 2;
  if (span === 0) {
    return { hue: 0, saturation: 0 };
  }
  const saturation = span / (1 - Math.abs(2 * lightness - 1));
  let hue: number;
  if (max === r) {
    hue = 60 * (((g - b) / span) % 6);
  } else if (max === g) {
    hue = 60 * ((b - r) / span + 2);
  } else {
    hue = 60 * ((r - g) / span + 4);
  }
  return { hue: (hue + 360) % 360, saturation };
}

function hueDistance(a: number, b: number): number {
  const raw = Math.abs(a - b) % 360;
  return raw > 180 ? 360 - raw : raw;
}

describe.each([
  ['light', LIGHT],
  ['dark', DARK],
])('the %s palette', (_name, theme) => {
  it('keeps the notice out of the accent\'s hue band', () => {
    // Measured, at 11 degrees in light and 16 in dark, when the notice was
    // MyMonero's yellow beside Qnero's amber. MyMonero can afford that yellow
    // because its action is cyan, 141 degrees away. Either the notice is
    // unsaturated, which is what it is now, or it is a long way off the
    // accent: a warm notice beside a warm button is one block.
    const accent = hsl(resolve(theme, '--accent-fill'));
    const border = resolve(theme, '--notice-border');
    if (border === 'transparent') {
      return;
    }
    const notice = hsl(border);
    if (notice.saturation >= 0.12) {
      expect(hueDistance(accent.hue, notice.hue)).toBeGreaterThanOrEqual(60);
    }
  });

  it('gives the notice no fill, so the one filled warm thing is the action', () => {
    expect(resolve(theme, '--notice-bg')).toBe('transparent');
  });

  it('keeps the accent saturated, because it is the one thing carrying identity', () => {
    expect(hsl(resolve(theme, '--accent-fill')).saturation).toBeGreaterThan(0.3);
  });
});

describe('the sideways scroll', () => {
  it('spends the edge-shadow tokens the palette defines', () => {
    // They were defined three times over and read nowhere, while the notes
    // table dropped its memo column at 400 px with no cue at all.
    expect(APP_CSS).toContain('.mm-scroll-x');
    expect(APP_CSS).toContain('var(--shadow-edge)');
    expect(APP_CSS).toContain('var(--shadow-edge-fade)');
    const table = readFileSync(new URL('../src/components/UI/Table.tsx', import.meta.url), 'utf8');
    expect(table).toContain('mm-scroll-x');
  });
});
