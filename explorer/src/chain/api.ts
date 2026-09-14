/**
 * The connection, and everything read out of the runtime's own metadata.
 *
 * Two seams matter here. The header carries `zkTreeRoot` between
 * `extrinsicsRoot` and `digest`, which no stock Substrate header type has, so
 * a custom `Header` is registered or every header decodes to plausible
 * garbage. And `U512` has no polkadot-js codec, so it is registered as its 64
 * raw little-endian bytes and read as an integer by hand.
 */

import { ApiPromise, WsProvider } from '@polkadot/api';
import type { QueryableStorageEntry } from '@polkadot/api/types';
import type { EventRecord as PolkadotEventRecord } from '@polkadot/types/interfaces';

import type { EventPhase, EventRecord } from '../lib/events';
import type { ExtrinsicLayout } from '../lib/extrinsics';

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
 * Every storage item this explorer builds a key for or reads by name, with the
 * hasher it assumes.
 *
 * None of it is checked by the node. A renamed item or a changed hasher makes
 * a key that is simply absent, and an absent key is indistinguishable from an
 * empty map, so the site would render "0 leaves, 0 nullifiers" with no error
 * anywhere. This list is checked against metadata at startup instead.
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
  { pallet: 'Shielded', item: 'PoolValue', hasher: null },
  { pallet: 'ZkTree', item: 'Leaves', hasher: 'Identity' },
  { pallet: 'ZkTree', item: 'LeafCount', hasher: null },
  { pallet: 'ZkTree', item: 'Depth', hasher: null },
  { pallet: 'ZkTree', item: 'Root', hasher: null },
  { pallet: 'System', item: 'Events', hasher: null },
];

export interface PalletInfo {
  index: number;
  name: string;
  calls: ReadonlyMap<number, string>;
}

export interface ChainContext {
  api: ApiPromise;
  provider: WsProvider;
  specName: string;
  specVersion: number;
  transactionVersion: number;
  tokenSymbol: string;
  tokenDecimals: number;
  ss58Format: number;
  genesisHash: string;
  layout: ExtrinsicLayout;
  pallets: ReadonlyMap<number, PalletInfo>;
  /** Storage items the runtime declares differently from what this build assumes. */
  storageDrift: string[];
}

export async function connect(endpoint: string): Promise<ChainContext> {
  const provider = new WsProvider(endpoint);
  const api = await ApiPromise.create({ provider, noInitWarn: true, types: CHAIN_TYPES });
  return describe(api, provider);
}

function describe(api: ApiPromise, provider: WsProvider): ChainContext {
  const properties = api.registry.getChainProperties();
  const metadata = api.runtimeMetadata.asLatest;
  const pallets = new Map<number, PalletInfo>();
  const lookup = new Map<number, (typeof metadata.lookup.types)[number]['type']>();
  for (const entry of metadata.lookup.types) {
    lookup.set(entry.id.toNumber(), entry.type);
  }
  for (const pallet of metadata.pallets) {
    const calls = new Map<number, string>();
    if (pallet.calls.isSome) {
      const callsType = lookup.get(pallet.calls.unwrap().type.toNumber());
      if (callsType?.def.isVariant) {
        for (const variant of callsType.def.asVariant.variants) {
          calls.set(variant.index.toNumber(), variant.name.toString());
        }
      }
    }
    pallets.set(pallet.index.toNumber(), {
      index: pallet.index.toNumber(),
      name: pallet.name.toString(),
      calls,
    });
  }

  const signatureLengths = new Map<number, number>();
  const signatureType = lookup.get(metadata.extrinsic.signatureType.toNumber());
  if (signatureType?.def.isVariant) {
    for (const variant of signatureType.def.asVariant.variants) {
      const first = variant.fields[0];
      if (first === undefined) {
        continue;
      }
      const inner = lookup.get(first.type.toNumber());
      const innerField = inner?.def.isComposite ? inner.def.asComposite.fields[0] : undefined;
      const arrayType = innerField ? lookup.get(innerField.type.toNumber()) : undefined;
      if (arrayType?.def.isArray) {
        signatureLengths.set(variant.index.toNumber(), arrayType.def.asArray.len.toNumber());
      }
    }
  }
  const addressType = lookup.get(metadata.extrinsic.addressType.toNumber());
  const layout: ExtrinsicLayout = {
    signatureLengths,
    extensions: metadata.extrinsic.transactionExtensions.map((extension) =>
      extension.identifier.toString(),
    ),
    multiAddress: addressType === undefined ? false : addressType.path.map(String).includes('MultiAddress'),
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
    specName: api.runtimeVersion.specName.toString(),
    specVersion: api.runtimeVersion.specVersion.toNumber(),
    transactionVersion: api.runtimeVersion.transactionVersion.toNumber(),
    tokenSymbol: properties?.tokenSymbol.unwrapOr([])[0]?.toString() ?? 'QNR',
    tokenDecimals: properties?.tokenDecimals.unwrapOr([])[0]?.toNumber() ?? 12,
    ss58Format: properties?.ss58Format.unwrapOr(undefined)?.toNumber() ?? 42, // eslint-disable-line @typescript-eslint/no-unnecessary-condition
    genesisHash: api.genesisHash.toHex(),
    layout,
    pallets,
    storageDrift,
  };
}

/**
 * One storage entry, by the camel-case names polkadot-js derives from
 * metadata. Missing means the runtime moved it, and saying so beats reading
 * an absent key as an empty map.
 */
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

/** The same entry, decorated at one block hash. */
export async function storageAt(
  context: ChainContext,
  hash: string,
  pallet: string,
  item: string,
): Promise<QueryableStorageEntry<'promise'>> {
  const at = await context.api.at(hash);
  const entry = at.query[pallet]?.[item];
  if (entry === undefined) {
    throw new Error(`the runtime at ${hash} declares no ${pallet}.${item}`);
  }
  return entry;
}

/** The name a pallet index and call index resolve to, from metadata. */
export function callName(
  pallets: ReadonlyMap<number, PalletInfo>,
  palletIndex: number,
  callIndex: number,
): string {
  const pallet = pallets.get(palletIndex);
  if (pallet === undefined) {
    return `pallet ${palletIndex}, call ${callIndex}`;
  }
  const call = pallet.calls.get(callIndex);
  return call === undefined ? `${pallet.name}.call ${callIndex}` : `${pallet.name}.${call}`;
}

function phaseOf(record: PolkadotEventRecord): EventPhase {
  if (record.phase.isApplyExtrinsic) {
    return { kind: 'applyExtrinsic', index: record.phase.asApplyExtrinsic.toNumber() };
  }
  if (record.phase.isFinalization) {
    return { kind: 'finalization' };
  }
  return { kind: 'initialization' };
}

/**
 * Events in the shape the decoders take: field names from metadata, values as
 * JSON. A variant with unnamed fields is keyed by position, which is the only
 * honest thing to do with one.
 */
export function normaliseEvents(records: readonly PolkadotEventRecord[]): EventRecord[] {
  return records.map((record) => {
    const fields: Record<string, unknown> = {};
    const values = record.event.data.toJSON() as unknown[];
    record.event.meta.fields.forEach((meta, index) => {
      const name = meta.name.isSome ? meta.name.unwrap().toString() : `${index}`;
      fields[name] = values[index];
    });
    return {
      phase: phaseOf(record),
      section: record.event.section,
      method: record.event.method,
      fields,
    };
  });
}
