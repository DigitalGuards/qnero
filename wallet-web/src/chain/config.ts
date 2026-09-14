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
  /** What one payment is expected to cost in this browser, in seconds. */
  expectedProveSeconds: number;
}

const DEFAULTS = {
  wasmBase: 'wasm/',
  numLeaves: 6,
  expectedProveSeconds: 34,
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
    expectedProveSeconds: readNumber(source, 'expectedProveSeconds', DEFAULTS.expectedProveSeconds),
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
