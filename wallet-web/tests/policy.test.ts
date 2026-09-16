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

import { afterEach, describe, expect, it } from 'vitest';

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { CONTENT_SECURITY_POLICY, cspDirectives } from '../vite.config';
import { RECONNECT_DELAY_MS, watchConnection, type ChainContext } from '../src/chain/api';
import {
  RECONNECT_ATTEMPTS_BEFORE_SETTINGS,
  RECONNECT_SCHEDULE_MS,
  reconnectDelayMs,
  secondsUntil,
} from '../src/app/reconnect';
import { applyTheme, readTheme, storeTheme, THEME_KEY } from '../src/app/theme';
import { CIPHERTEXT_SUBSTITUTION_HINT, fullScanEstimate } from '../src/wallet/sync';

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

/** Relative luminance, per WCAG 2. */
function luminance(hex: string): number {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  if (match === null) {
    throw new Error(`${hex} is not a six-digit hex colour`);
  }
  const body = match[1] ?? '';
  const channels = [0, 2, 4].map((at) => {
    const value = Number.parseInt(body.slice(at, at + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

/** The contrast ratio between two opaque colours. */
function contrast(a: string, b: string): number {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (high + 0.05) / (low + 0.05);
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

  it('fills the one action a screen is for with the same amber in both themes', () => {
    // The link ink and the filled ground are two roles. In light the ink is
    // the dark amber, because it is text on a near-white ground; the fill is a
    // ground of its own and owes contrast only to its own label, so it stays
    // the amber this project is recognised by. `site/css/site.css` carries the
    // identical pair, and a wallet whose primary button went brown in daylight
    // is a wallet that reads as another project.
    expect(resolve(theme, '--accent-fill')).toBe('#e6a145');
    expect(contrast(resolve(theme, '--accent-on-fill'), resolve(theme, '--accent-fill')))
      .toBeGreaterThanOrEqual(4.5);
    // And hovering it stays a fill, rather than taking the link ink's hover.
    expect(contrast(resolve(theme, '--accent-on-fill'), resolve(theme, '--accent-fill-hover')))
      .toBeGreaterThanOrEqual(4.5);
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

// ---------------------------------------------------------------------------
// The name, which is fixed by decision and spelled one way.
// ---------------------------------------------------------------------------

describe('the wordmark', () => {
  /**
   * One spelling, "Qloak": a capital Q and the rest lower case.
   *
   * The spelling is fixed by decision, and until this test nothing in the
   * one-second gate read it: the header and the tab title passed lint, types,
   * every unit case and the production build with "QLoak" or "qloak" written
   * into them, and the whole of the wallet's own suite had no assertion on the
   * name at all. So the two files a reader meets the name in are read here,
   * and every spelling of it in them is compared against the one.
   */
  it('spells the name one way in the header and the tab title', () => {
    const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
    const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
    expect(app).toContain('>Qloak<');
    expect(html).toContain('<title>Qloak, a Qnero wallet</title>');
    for (const [file, source] of [
      ['src/App.tsx', app],
      ['index.html', html],
    ] as const) {
      for (const found of source.matchAll(/qloak/gi)) {
        expect(`${file}: ${found[0]}`).toBe(`${file}: Qloak`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// The theme, which has to be on the page before the first paint.
// ---------------------------------------------------------------------------

/** A `localStorage` that answers, and one that throws the way a locked one does. */
function fakeStorage(seed: Record<string, string> = {}): Storage {
  const held = new Map(Object.entries(seed));
  return {
    get length(): number {
      return held.size;
    },
    clear: (): void => {
      held.clear();
    },
    getItem: (key: string): string | null => held.get(key) ?? null,
    key: (index: number): string | null => [...held.keys()][index] ?? null,
    removeItem: (key: string): void => {
      held.delete(key);
    },
    setItem: (key: string, value: string): void => {
      held.set(key, value);
    },
  };
}

describe('the theme this browser chose', () => {
  afterEach(() => {
    Reflect.deleteProperty(globalThis, 'localStorage');
    Reflect.deleteProperty(globalThis, 'document');
  });

  it('reads the two real answers and treats everything else as the system', () => {
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      value: fakeStorage({ [THEME_KEY]: 'light' }),
    });
    expect(readTheme()).toBe('light');
    localStorage.setItem(THEME_KEY, 'dark');
    expect(readTheme()).toBe('dark');
    localStorage.setItem(THEME_KEY, 'sepia');
    expect(readTheme()).toBe('system');
    localStorage.removeItem(THEME_KEY);
    expect(readTheme()).toBe('system');
  });

  it('is the system theme when site data is blocked, rather than a failure', () => {
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get: () => {
        throw new Error('the browser refuses site data on this origin');
      },
    });
    expect(readTheme()).toBe('system');
    expect(() => {
      storeTheme('dark');
    }).not.toThrow();
  });

  it('puts a choice on the root element and takes it off again for the system', () => {
    const attributes = new Map<string, string>();
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      value: {
        documentElement: {
          setAttribute: (name: string, value: string): void => {
            attributes.set(name, value);
          },
          removeAttribute: (name: string): void => {
            attributes.delete(name);
          },
        },
      },
    });
    applyTheme('light');
    expect(attributes.get('data-theme')).toBe('light');
    applyTheme('dark');
    expect(attributes.get('data-theme')).toBe('dark');
    applyTheme('system');
    expect(attributes.has('data-theme')).toBe(false);
  });

  /**
   * The rule that matters is where it is called from.
   *
   * Only `ThemeToggle` used to write `data-theme`, and that component mounts
   * on the settings screen alone: a reader who chose light on a dark-system
   * phone was handed the dark wallet on every open, unlock screen included,
   * until they opened Settings, at which point the page flipped mid-session.
   * Nothing in a unit suite sees that, so the call site is read here.
   */
  it('is applied before the root is mounted, not by the screen that sets it', () => {
    const main = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
    const applied = main.indexOf('applyTheme(readTheme())');
    const mounted = main.indexOf('createRoot(');
    expect(applied, 'main.tsx applies no stored theme').toBeGreaterThan(-1);
    expect(applied, 'the theme is applied after the root is mounted').toBeLessThan(mounted);
  });

  it('spells the storage key in one module, which both call sites import', () => {
    // Two copies of a key is how a stored choice becomes unreadable by half
    // the app after a rename that looks harmless in both diffs.
    const toggle = readFileSync(
      new URL('../src/components/UI/ThemeToggle.tsx', import.meta.url),
      'utf8',
    );
    const main = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
    for (const [name, source] of [
      ['ThemeToggle.tsx', toggle],
      ['main.tsx', main],
    ] as const) {
      expect(`${name} spells the key itself: ${String(source.includes(THEME_KEY))}`).toBe(
        `${name} spells the key itself: false`,
      );
      expect(source, `${name} does not import app/theme`).toContain('app/theme');
    }
  });
});

// ---------------------------------------------------------------------------
// The retry a dead endpoint gets, which is the difference between a wallet
// that comes back when the network does and one that does not.
// ---------------------------------------------------------------------------

describe('the schedule a failed connection is retried on', () => {
  it('waits seconds first, because the common failure is a network changing', () => {
    expect(RECONNECT_SCHEDULE_MS[0]).toBe(5_000);
    expect(reconnectDelayMs(1)).toBe(5_000);
    expect(reconnectDelayMs(2)).toBe(15_000);
    expect(reconnectDelayMs(3)).toBe(60_000);
  });

  it('holds at the last wait rather than growing without bound', () => {
    expect(reconnectDelayMs(4)).toBe(60_000);
    expect(reconnectDelayMs(40)).toBe(60_000);
  });

  it('never returns a wait of zero, whatever it is asked', () => {
    expect(reconnectDelayMs(0)).toBe(5_000);
    expect(reconnectDelayMs(-3)).toBe(5_000);
  });

  it('points a reader at Settings only after the third failure', () => {
    // Two failures is a network settling. Three is an endpoint that is wrong
    // or gone, which is the only case where Settings is the answer.
    expect(RECONNECT_ATTEMPTS_BEFORE_SETTINGS).toBe(3);
    expect(RECONNECT_ATTEMPTS_BEFORE_SETTINGS).toBe(RECONNECT_SCHEDULE_MS.length);
  });

  it('counts down in whole seconds and stops at zero', () => {
    // A fixed clock rather than the wall one: the countdown is what a reader
    // reads, and a test that drifted by a millisecond would read one second
    // fewer at random.
    const now = 1_700_000_000_000;
    expect(secondsUntil(now + 12_000, now)).toBe(12);
    // Rounded up, so the last second of a wait reads as one second and never
    // as "retrying in 0 s" over a connection nothing has tried yet.
    expect(secondsUntil(now + 11_400, now)).toBe(12);
    expect(secondsUntil(now + 1, now)).toBe(1);
    expect(secondsUntil(now, now)).toBe(0);
    expect(secondsUntil(now - 5_000, now)).toBe(0);
  });

  it('counts the whole wait down from the moment an attempt fails', () => {
    const failedAt = 1_700_000_000_000;
    for (const attempt of [1, 2, 3, 9]) {
      const delay = reconnectDelayMs(attempt);
      expect(secondsUntil(failedAt + delay, failedAt)).toBe(delay / 1000);
    }
  });
});


/**
 * The words this project spends in the explorer and nowhere else.
 *
 * A Qnero wallet screen talks about payments and transfers. `leaf`, `note`,
 * `commitment`, `nullifier` and `output` are the names of the things the chain
 * publishes, they are what the explorer is for, and on a wallet screen they
 * explain a reader's balance in a vocabulary nothing on that screen defines.
 *
 * It is a rule about prose, so it is checked over prose: the two texts a sync
 * always produces, and the words the screens themselves render between tags.
 * The per-entry warnings are out of it deliberately. Those fire only when a
 * pass has actually found an anomaly, they are held byte for byte against the
 * command-line wallet's own literals by `tests/leaf-typing.test.ts`, and the
 * sentences are the operator's, so they are named in this project's open
 * issues rather than quietly asserted to be something they are not.
 */
describe('the words a wallet screen spends', () => {
  const EXPLORER_WORDS = /\b(leaf|leaves|note|notes|commitment|commitments|nullifier|nullifiers|output|outputs)\b/i;

  /**
   * `leaves` is also an ordinary verb, and "your viewing key never leaves this
   * page" is the sentence on the balance screen that says where the key goes.
   */
  const NOT_THE_NOUN = [/\bleaves (this|the) page\b/gi];

  function prose(text: string): string {
    return NOT_THE_NOUN.reduce((rest, verb) => rest.replace(verb, ''), text);
  }

  it('keeps them out of the two texts every sync can produce', () => {
    expect(prose(CIPHERTEXT_SUBSTITUTION_HINT)).not.toMatch(EXPLORER_WORDS);
    expect(prose(fullScanEstimate(262_980))).not.toMatch(EXPLORER_WORDS);
  });

  it('keeps them out of what the screens render', () => {
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) {
          walk(path);
        } else if (path.endsWith('.tsx')) {
          files.push(path);
        }
      }
    };
    walk('src/screens');
    walk('src/components');
    expect(files.length).toBeGreaterThan(10);

    const offences: string[] = [];
    for (const file of files) {
      // Comments first: this rule is about what a reader is shown, and the
      // reasoning above a line of JSX is free to name what the chain writes.
      const source = readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/\/\/[^\n]*/g, ' ');
      // Text between tags, which is the prose. An expression in braces is an
      // identifier, and identifiers are the code's own words.
      for (const match of source.matchAll(/>([^<>{}]+)</g)) {
        const line = (match[1] ?? '').replace(/\s+/g, ' ').trim();
        if (line !== '' && EXPLORER_WORDS.test(prose(line))) {
          offences.push(`${file}: ${line}`);
        }
      }
    }
    expect(offences).toEqual([]);
  });
});
