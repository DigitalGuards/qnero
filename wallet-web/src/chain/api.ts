/**
 * The connection, and everything read out of the runtime's own metadata.
 *
 * Lifted from `explorer/src/chain/api.ts`, because the two seams a generic
 * Substrate client gets silently wrong are the same ones: the header carries
 * `zkTreeRoot` between `extrinsicsRoot` and `digest`, which no stock Substrate
 * header type has, so a custom `Header` is registered or every header decodes
 * to plausible garbage; and `U512` has no polkadot-js codec.
 *
 * What this file adds over the explorer's is the metadata a wallet needs to
 * spend: the four `Shielded` constants that decide a fee floor and a memo pad,
 * and the extrinsic format version, which is what decides whether the bare
 * preamble a settlement rides in decodes at all. None of them is compiled in.
 * The runtime moved `CiphertextBytesPerFeeQuantum` inside one `spec_version`
 * during M4, and a wallet holding a copy would have paid for a proof and read
 * `PayloadUnderpaid` off the pool.
 *
 * # The transport seam
 *
 * Every read this wallet makes goes through [`ChainContext.send`], which is
 * one function. That is deliberate: "the node learns nothing" is a property of
 * the request stream and no assertion over an answer can see it, so the
 * property is tested by recording every call at this one seam
 * (`tests/privacy.test.ts`). A read that bypassed it would bypass the test.
 */

import { ApiPromise, WsProvider } from '@polkadot/api';
import type { QueryableStorageEntry } from '@polkadot/api/types';

export const CHAIN_TYPES = {
  U512: '[u8; 64]',
  Header: {
    parentHash: 'Hash',
    number: 'Compact<BlockNumber>',
    stateRoot: 'Hash',
    extrinsicsRoot: 'Hash',
    zkTreeRoot: 'Hash',
    digest: 'Digest',
  },
} as const;

/**
 * Every storage item this wallet builds a key for or reads by name, with the
 * hasher it assumes.
 *
 * None of it is checked by the node. A renamed item or a changed hasher makes
 * a key that is simply absent, and an absent key is indistinguishable from an
 * empty map: `LeafCount` read as absent is a scan of nothing and a balance of
 * zero, and `UsedNullifiers` read as absent is every spent note reported
 * unspent and readmitted into the next spend. So the list is checked against
 * metadata at startup and a drift refuses the sync.
 */
export const REQUIRED_STORAGE: ReadonlyArray<{
  pallet: string;
  item: string;
  hasher: string | null;
}> = [
  { pallet: 'Shielded', item: 'Ciphertexts', hasher: 'Identity' },
  { pallet: 'Shielded', item: 'LeafBlocks', hasher: 'Identity' },
  { pallet: 'Shielded', item: 'CoinbaseValues', hasher: 'Identity' },
  { pallet: 'Shielded', item: 'UsedNullifiers', hasher: 'Blake2_128Concat' },
  { pallet: 'Shielded', item: 'EntryCount', hasher: null },
  { pallet: 'ZkTree', item: 'Leaves', hasher: 'Identity' },
  { pallet: 'ZkTree', item: 'LeafCount', hasher: null },
  { pallet: 'ZkTree', item: 'Depth', hasher: null },
];

/** The four `Shielded` constants a spend is priced and sized against. */
export interface ShieldedConstants {
  /** Anchor window, in blocks. A proof outside it is refused. */
  blockHashWindow: number;
  /** Flat floor per real leaf slot, in pool quanta. */
  minLeafFee: bigint;
  /** Ciphertext bytes one quantum of fee buys. */
  ciphertextBytesPerFeeQuantum: number;
  /** Size cap on one ciphertext. Over it the extrinsic fails its SCALE decode. */
  maxCiphertextBytes: number;
}

export interface ChainContext {
  api: ApiPromise;
  provider: WsProvider;
  /** The one seam every raw read goes through. See the module docs. */
  send: <T>(method: string, params: unknown[]) => Promise<T>;
  specName: string;
  specVersion: number;
  transactionVersion: number;
  tokenSymbol: string;
  tokenDecimals: number;
  genesisHash: string;
  /** The format version the runtime declares. A bare preamble decodes at 4 and 5. */
  extrinsicVersion: number;
  constants: ShieldedConstants;
  /** Storage items the runtime declares differently from what this build assumes. */
  storageDrift: string[];
}

/** How long a connection may sit in `connecting` before it is called failed. */
export const CONNECT_DEADLINE_MS = 15_000;

/**
 * Connect, or fail by the deadline.
 *
 * `WsProvider` retries forever on its own and `ApiPromise.create` never
 * settles while it does, so a wrong or down endpoint is a permanent
 * "connecting" with nothing said. The deadline turns the commonest deployment
 * mistake into a named failure.
 */
export async function connect(endpoint: string): Promise<ChainContext> {
  const provider = new WsProvider(endpoint, false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      (async (): Promise<void> => {
        await provider.connect();
        await provider.isReady;
      })(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${endpoint} did not answer within ${CONNECT_DEADLINE_MS / 1000} s`));
        }, CONNECT_DEADLINE_MS);
      }),
    ]);
    const api = await ApiPromise.create({ provider, noInitWarn: true, types: CHAIN_TYPES });
    return describe(api, provider);
  } catch (error) {
    await provider.disconnect().catch(() => undefined);
    throw error;
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/** A little-endian constant value out of metadata, as a bigint. */
function leBigInt(hex: string): bigint {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  let out = 0n;
  for (let index = body.length - 2; index >= 0; index -= 2) {
    out = (out << 8n) | BigInt(Number.parseInt(body.slice(index, index + 2), 16));
  }
  return out;
}

/**
 * The extrinsic format version the runtime declares.
 *
 * Three shapes, and the third is the one this chain answers with. Metadata v14
 * and v15 publish one `version` as a `u8` codec. Metadata v16 publishes
 * `versions`, because a runtime may accept several, and polkadot-js decodes
 * that field as `Bytes`: a `Uint8Array` subclass whose entries are plain
 * numbers. `Array.isArray` is false for it and its entries have no
 * `toNumber`, so a reader written for a `Vec<u8>` of codecs falls through to
 * "this runtime declares no version" against a runtime that declares two. The
 * chain answers `0x0405`, which is versions 4 and 5.
 *
 * The bare preamble a settlement rides in decodes at 4 and 5 and nowhere else,
 * so what matters is the highest declared version this wallet can write. The
 * check downstream is against the same list either way.
 */
function declaredVersions(value: unknown): number[] | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (value instanceof Uint8Array) {
    return [...value];
  }
  if (Array.isArray(value)) {
    return value.map((entry: unknown) =>
      typeof entry === 'number'
        ? entry
        : (entry as { toNumber: () => number }).toNumber(),
    );
  }
  return null;
}

function extrinsicVersionOf(metadata: { extrinsic: unknown }): number {
  const extrinsic = metadata.extrinsic as Record<string, unknown>;
  const single = extrinsic['version'];
  if (single !== undefined && typeof (single as { toNumber?: unknown }).toNumber === 'function') {
    return (single as { toNumber: () => number }).toNumber();
  }
  const declared = declaredVersions(extrinsic['versions']);
  if (declared !== null && declared.length > 0) {
    const usable = declared.filter((version) => BARE_PREAMBLE_VERSIONS.includes(version));
    return usable.length > 0 ? Math.max(...usable) : (declared[0] ?? 0);
  }
  throw new Error("this runtime's metadata declares no extrinsic format version");
}

function describe(api: ApiPromise, provider: WsProvider): ChainContext {
  const properties = api.registry.getChainProperties();
  const metadata = api.runtimeMetadata.asLatest;

  const shielded = [...metadata.pallets].find((pallet) => pallet.name.toString() === 'Shielded');
  if (shielded === undefined) {
    throw new Error('this runtime has no Shielded pallet, so it is not a Qnero chain');
  }
  const constantOf = (name: string): string => {
    const entry = shielded.constants.find((constant) => constant.name.toString() === name);
    if (entry === undefined) {
      throw new Error(`the Shielded pallet declares no ${name} constant`);
    }
    return entry.value.toHex();
  };

  const storageDrift: string[] = [];
  for (const required of REQUIRED_STORAGE) {
    const pallet = [...metadata.pallets].find((entry) => entry.name.toString() === required.pallet);
    if (pallet === undefined || pallet.storage.isNone) {
      storageDrift.push(`${required.pallet} declares no storage`);
      continue;
    }
    const item = pallet.storage
      .unwrap()
      .items.find((entry) => entry.name.toString() === required.item);
    if (item === undefined) {
      storageDrift.push(`${required.pallet}::${required.item} is gone`);
      continue;
    }
    const hasher = item.type.isMap ? item.type.asMap.hashers.map(String).join(',') : null;
    if (hasher !== required.hasher) {
      storageDrift.push(
        `${required.pallet}::${required.item} is hashed ${hasher ?? 'plain'} where this build assumes ${
          required.hasher ?? 'plain'
        }`,
      );
    }
  }

  return {
    api,
    provider,
    send: async <T,>(method: string, params: unknown[]): Promise<T> =>
      provider.send<T>(method, params),
    specName: api.runtimeVersion.specName.toString(),
    specVersion: api.runtimeVersion.specVersion.toNumber(),
    transactionVersion: api.runtimeVersion.transactionVersion.toNumber(),
    tokenSymbol: properties?.tokenSymbol.unwrapOr([])[0]?.toString() ?? 'QNR',
    tokenDecimals: properties?.tokenDecimals.unwrapOr([])[0]?.toNumber() ?? 12,
    genesisHash: api.genesisHash.toHex(),
    extrinsicVersion: extrinsicVersionOf(metadata),
    constants: {
      blockHashWindow: Number(leBigInt(constantOf('BlockHashWindow'))),
      minLeafFee: leBigInt(constantOf('MinLeafFee')),
      ciphertextBytesPerFeeQuantum: Number(leBigInt(constantOf('CiphertextBytesPerFeeQuantum'))),
      maxCiphertextBytes: Number(leBigInt(constantOf('MaxCiphertextBytes'))),
    },
    storageDrift,
  };
}

/**
 * A bare preamble decodes at extrinsic format versions 4 and 5 and nowhere
 * else. Outside that range the node answers `Invalid transaction version` and
 * says nothing more, after the proof exists.
 */
export const BARE_PREAMBLE_VERSIONS = [4, 5];

export function ensureBarePreambleDecodes(context: ChainContext): void {
  if (!BARE_PREAMBLE_VERSIONS.includes(context.extrinsicVersion)) {
    throw new Error(
      `this runtime declares extrinsic format version ${context.extrinsicVersion}, and a ` +
        `settlement rides in a bare preamble, which decodes at ${BARE_PREAMBLE_VERSIONS.join(' and ')}. ` +
        'The node would answer "Invalid transaction version" after the proof was built.',
    );
  }
}

/** One storage entry, by the camel-case names polkadot-js derives from metadata. */
export function storage(
  context: ChainContext,
  pallet: string,
  item: string,
): QueryableStorageEntry<'promise'> {
  const entry = context.api.query[pallet]?.[item];
  if (entry === undefined) {
    throw new Error(`the runtime declares no ${pallet}.${item}`);
  }
  return entry;
}
