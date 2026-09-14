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
   * What the proof alone is expected to cost in this browser, in seconds, per
   * module.
   *
   * The sending screen quotes a wait as a composition: this figure, then up to
   * one block interval read from the chain. The block half cannot live in a
   * file, because the same build serves a 120 s public chain and a 12 s dev
   * chain and the node is the only thing that knows which. What a file can
   * carry is the half that belongs to the browser, which is the proof.
   *
   * This key replaced `expectedSendSeconds`, which was one number for both
   * halves and therefore wrong on any chain but the one it was measured on.
   *
   * Two numbers rather than one. The threaded module proves in about a third
   * of the single-threaded one's time (`docs/BENCH.md`, M10), and a page that
   * quoted one figure beside the live thread count told a reader on four
   * threads to expect three times the wait they were about to have. A single
   * number in `config.json` is still read, as both.
   */
  expectedProvingSeconds: { threaded: number; single: number };
}

const DEFAULTS = {
  wasmBase: 'wasm/',
  numLeaves: 6,
  // The M10 table's `proveTransfer` rows after the review fixes, rounded:
  // 11.6, 11.9 and 13.3 s threaded, 36.0 s on one thread (`docs/BENCH.md`).
  // The block half is added at render time from the chain's own target.
  expectedProvingSeconds: { threaded: 12, single: 36 },
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
    expectedProvingSeconds: readExpectation(source['expectedProvingSeconds']),
  };
}

/** One number for both modules, or one per module, or neither. */
function readExpectation(value: unknown): { threaded: number; single: number } {
  if (value === undefined) {
    return DEFAULTS.expectedProvingSeconds;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error('config.json: expectedProvingSeconds must be a positive number');
    }
    return { threaded: value, single: value };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(
      'config.json: expectedProvingSeconds must be a number or {threaded, single} in seconds',
    );
  }
  const source = value as Record<string, unknown>;
  return {
    threaded: readNumber(source, 'threaded', DEFAULTS.expectedProvingSeconds.threaded),
    single: readNumber(source, 'single', DEFAULTS.expectedProvingSeconds.single),
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
