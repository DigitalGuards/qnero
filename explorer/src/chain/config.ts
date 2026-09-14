/**
 * Runtime configuration.
 *
 * One JSON file beside the built assets, read at startup, so the same build
 * serves a devnet and a testnet. Nothing about a chain is compiled in.
 */

export interface ExplorerConfig {
  /** WebSocket endpoint. Subscriptions are WS only, and the live head needs one. */
  rpcEndpoint: string;
  chainName: string;
  /** Blocks in the home page's recent list and in the rolling block-time window. */
  recentBlocks: number;
  /** How far back a search by extrinsic hash or commitment walks before giving up. */
  searchWindowBlocks: number;
  /** Pages of 1000 keys the nullifier count reads before it reports a floor instead of a total. */
  nullifierPageLimit: number;
}

const DEFAULTS = {
  recentBlocks: 12,
  searchWindowBlocks: 512,
  nullifierPageLimit: 25,
} as const;

function readNumber(source: Record<string, unknown>, key: string, fallback: number): number {
  const value = source[key];
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`config.json: ${key} must be a positive number`);
  }
  return Math.floor(value);
}

export function parseConfig(raw: unknown): ExplorerConfig {
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
  return {
    rpcEndpoint,
    chainName,
    recentBlocks: readNumber(source, 'recentBlocks', DEFAULTS.recentBlocks),
    searchWindowBlocks: readNumber(source, 'searchWindowBlocks', DEFAULTS.searchWindowBlocks),
    nullifierPageLimit: readNumber(source, 'nullifierPageLimit', DEFAULTS.nullifierPageLimit),
  };
}

export async function loadConfig(): Promise<ExplorerConfig> {
  const url = `${import.meta.env.BASE_URL}config.json`;
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`config.json could not be read: HTTP ${response.status}`);
  }
  return parseConfig(await response.json());
}
