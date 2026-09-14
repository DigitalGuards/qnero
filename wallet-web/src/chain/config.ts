/**
 * Runtime configuration.
 *
 * One JSON file beside the built assets, read at startup, so the same build
 * serves a devnet and a testnet. Nothing about a chain is compiled in, and
 * nothing but the configured endpoint is ever contacted: there is no backend,
 * no price feed and no telemetry in this wallet.
 *
 * The endpoint is also settable at runtime from the settings screen, and that
 * choice is what persists. `config.json` is the default a fresh install gets.
 */

export interface WalletConfig {
  /** WebSocket endpoint. Subscriptions are WS only and the head needs one. */
  rpcEndpoint: string;
  chainName: string;
  /** Where the prover module and its glue are served from, relative to the app. */
  wasmBase: string;
  /** Leaf slots per private batch. Checked against the module before proving. */
  numLeaves: number;
  /**
   * What one payment is expected to cost in this browser, in seconds, per
   * module, measured from the send button to a settled block.
   *
   * That interval rather than the proof's, because it is the interval the
   * reader is in: the sending screen prints this beside its own elapsed clock,
   * which starts at the button. A proving-only figure there was exceeded about
   * halfway through every correct payment, so the one sentence the wallet
   * offers about how long a wait will be withdrew itself every time.
   *
   * Two numbers rather than one. The threaded module proves in about a third
   * of the single-threaded one's time (`docs/BENCH.md`, M10), and a page that
   * quoted one figure beside the live thread count told a reader on four
   * threads to expect three times the wait they were about to have. A single
   * number in `config.json` is still read, as both.
   */
  expectedSendSeconds: { threaded: number; single: number };
}

const DEFAULTS = {
  wasmBase: 'wasm/',
  numLeaves: 6,
  // The M10 table's "Send to settled" rows after the review fixes, rounded:
  // 21.6, 25.6 and 23.6 s threaded, 55.4 s on one thread (`docs/BENCH.md`).
  expectedSendSeconds: { threaded: 23, single: 55 },
} as const;

function readNumber(source: Record<string, unknown>, key: string, fallback: number): number {
  const value = source[key];
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`config.json: ${key} must be a positive number`);
  }
  return value;
}

export function parseConfig(raw: unknown): WalletConfig {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('config.json must hold a JSON object');
  }
  const source = raw as Record<string, unknown>;
  const rpcEndpoint = source['rpcEndpoint'];
  if (typeof rpcEndpoint !== 'string' || rpcEndpoint.length === 0) {
    throw new Error('config.json: rpcEndpoint must be a WebSocket URL');
  }
  if (!rpcEndpoint.startsWith('ws://') && !rpcEndpoint.startsWith('wss://')) {
    throw new Error('config.json: rpcEndpoint must start with ws:// or wss://');
  }
  const chainName = source['chainName'];
  if (typeof chainName !== 'string' || chainName.length === 0) {
    throw new Error('config.json: chainName must be a non-empty string');
  }
  const wasmBase = source['wasmBase'];
  if (wasmBase !== undefined && typeof wasmBase !== 'string') {
    throw new Error('config.json: wasmBase must be a string');
  }
  return {
    rpcEndpoint,
    chainName,
    wasmBase: wasmBase ?? DEFAULTS.wasmBase,
    numLeaves: readNumber(source, 'numLeaves', DEFAULTS.numLeaves),
    expectedSendSeconds: readExpectation(source['expectedSendSeconds']),
  };
}

/** One number for both modules, or one per module, or neither. */
function readExpectation(value: unknown): { threaded: number; single: number } {
  if (value === undefined) {
    return DEFAULTS.expectedSendSeconds;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error('config.json: expectedSendSeconds must be a positive number');
    }
    return { threaded: value, single: value };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(
      'config.json: expectedSendSeconds must be a number or {threaded, single} in seconds',
    );
  }
  const source = value as Record<string, unknown>;
  return {
    threaded: readNumber(source, 'threaded', DEFAULTS.expectedSendSeconds.threaded),
    single: readNumber(source, 'single', DEFAULTS.expectedSendSeconds.single),
  };
}

/** The endpoint a WebSocket URL has to be to reach a node from this page. */
export function endpointIsWebSocket(endpoint: string): boolean {
  return endpoint.startsWith('ws://') || endpoint.startsWith('wss://');
}

export async function loadConfig(): Promise<WalletConfig> {
  const url = `${import.meta.env.BASE_URL}config.json`;
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`config.json could not be read: HTTP ${response.status}`);
  }
  return parseConfig(await response.json());
}
