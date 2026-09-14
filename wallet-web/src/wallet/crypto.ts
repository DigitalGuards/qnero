/**
 * Encryption at rest, and what it is and is not worth.
 *
 * The construction is the one the sibling web wallet uses
 * (`myqrlwallet-frontend/src/utils/crypto/walletEncryption.ts`): PBKDF2-SHA-256
 * at 600,000 iterations over a 16-byte salt, deriving one non-extractable
 * AES-256-GCM key, with a fresh 12-byte IV per record per write.
 *
 * Three rules, each of which has a failure behind it:
 *
 * 1. **Derive once per unlock, hold the key.** 600,000 iterations is about a
 *    second of work. Deriving per record makes a wallet with forty notes
 *    unusable. The `CryptoKey` is non-extractable, so what is held is a handle
 *    rather than bytes.
 * 2. **A fresh IV on every write, including a rewrite of the same note.** A
 *    repeated 12-byte IV under one key publishes the XOR of the two plaintexts
 *    and the authentication key. This is the same discipline the prover
 *    enforces for ML-KEM `kem_randomness`, and for the same reason: nothing
 *    inside the primitive checks it.
 * 3. **Bind the ciphertext to where it is stored.** The additional data is
 *    `address/store/id`, so an envelope lifted out of one record cannot be
 *    pasted into another's slot, and a store belonging to another wallet
 *    cannot be opened with this one's passphrase even if the passphrases
 *    match.
 *
 * # What this does not buy
 *
 * A JavaScript `String` is immutable and garbage collected. A seed that has
 * ever been a string cannot be wiped, and `crypto.subtle.decrypt` hands back a
 * buffer that was allocated before this code sees it. Secrets are carried as
 * `Uint8Array` from the moment they are decrypted and overwritten with
 * `fill(0)` when done, which is a real erase of that buffer and nothing more.
 * The browser is the trust boundary. `README.md` says so in the same words.
 */

/** OWASP's 2023 floor, and what the sibling wallet uses. */
export const PBKDF2_ITERATIONS = 600_000;
/**
 * The shortest passphrase this build will derive a key from.
 *
 * Enforced here rather than on the screen that asks for one. A form rule is a
 * hint: `react-hook-form` skips `minLength` on an empty field, so a screen
 * carrying only that rule accepts the empty string and seals the spend key
 * under a key derived from it. This is the boundary every path crosses, and
 * there is no way to reach a `CryptoKey` around it.
 *
 * An existing store cannot have been written under a shorter one, because no
 * key existed to seal it with, so refusing here at unlock costs nothing and
 * says what happened instead of reporting a wrong passphrase.
 */
export const MIN_PASSPHRASE = 8;
export const SALT_BYTES = 16;
/** 96 bits, the AES-GCM standard nonce. */
export const IV_BYTES = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * One encrypted value.
 *
 * `v` is the envelope format and it is deliberately separate from the store's
 * schema version: the two change for different reasons, and a record written
 * under an older envelope in a current store has to be readable.
 */
export interface Envelope {
  v: number;
  iv: string;
  ct: string;
}

/** The envelope format this build writes. */
export const ENVELOPE_VERSION = 1;

/** Thrown when the passphrase is wrong, which GCM makes distinguishable. */
export class WrongPassphraseError extends Error {
  constructor(message = 'that passphrase does not open this wallet') {
    super(message);
    this.name = 'WrongPassphraseError';
  }
}

/** Thrown when a passphrase is below [`MIN_PASSPHRASE`]. */
export class WeakPassphraseError extends Error {
  constructor(message = `a passphrase is at least ${MIN_PASSPHRASE} characters`) {
    super(message);
    this.name = 'WeakPassphraseError';
  }
}

/** Thrown when the store was written by a format this build cannot read. */
export class UnreadableStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnreadableStoreError';
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error('not a hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

/** 16 fresh bytes, for a store that is being created. */
export function newSalt(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

/**
 * The key one unlock derives, held for the session.
 *
 * Non-extractable: the bytes never exist in the JavaScript heap, so the worst
 * a later bug can do is use the key, which is already what an unlocked wallet
 * permits.
 *
 * A passphrase below [`MIN_PASSPHRASE`] is refused here, which is the only
 * place the floor is real: see that constant.
 */
export async function deriveKey(passphrase: string, saltHex: string): Promise<CryptoKey> {
  if (passphrase.length < MIN_PASSPHRASE) {
    throw new WeakPassphraseError();
  }
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: hexToBytes(saltHex),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * The additional data one record's ciphertext is bound to.
 *
 * `address` is the wallet, `store` is the object store, `id` is the record's
 * own key. Together they are the slot, so a valid envelope from anywhere else
 * fails to open here rather than decrypting into the wrong row.
 */
export function recordAad(address: string, store: string, id: string): Uint8Array<ArrayBuffer> {
  // TypeScript 5.7 made `Uint8Array` generic over its buffer, and `BufferSource`
  // takes only the `ArrayBuffer` instantiation: a plain `Uint8Array` could be
  // backed by a `SharedArrayBuffer`, which WebCrypto refuses. Every buffer this
  // module hands to `crypto.subtle` is narrowed at its source rather than cast
  // at the call.
  return encoder.encode(`${address}/${store}/${id}`);
}

export async function sealBytes(
  key: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Envelope> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    plaintext,
  );
  return {
    v: ENVELOPE_VERSION,
    iv: bytesToHex(iv),
    ct: bytesToHex(new Uint8Array(ciphertext)),
  };
}

export async function openBytes(
  key: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  envelope: Envelope,
): Promise<Uint8Array<ArrayBuffer>> {
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new UnreadableStoreError(
      `this record is in envelope format ${envelope.v} and this build reads ${ENVELOPE_VERSION}`,
    );
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(envelope.iv), additionalData: aad },
      key,
      hexToBytes(envelope.ct),
    );
    return new Uint8Array(plaintext);
  } catch {
    // GCM authenticates, so a wrong key throws rather than returning plausible
    // bytes. It is indistinguishable here from a tampered record, and both
    // answers are the same to the person holding the passphrase.
    throw new WrongPassphraseError();
  }
}

/** A JSON value, sealed. Used for every secret-bearing field of a record. */
export async function sealJson(
  key: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  value: unknown,
): Promise<Envelope> {
  const bytes = encoder.encode(JSON.stringify(value));
  const envelope = await sealBytes(key, aad, bytes);
  bytes.fill(0);
  return envelope;
}

export async function openJson<T>(
  key: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  envelope: Envelope,
): Promise<T> {
  const bytes = await openBytes(key, aad, envelope);
  try {
    return JSON.parse(decoder.decode(bytes)) as T;
  } finally {
    // The buffer this code owns is erased. The string `decode` produced and
    // `JSON.parse`'s allocations are the garbage collector's, and no
    // JavaScript can reach them. See the module docs.
    bytes.fill(0);
  }
}

/**
 * A 32-byte spending seed, drawn from the browser's CSPRNG.
 *
 * `crypto.getRandomValues` throws outside a secure context rather than
 * returning weak bytes, which is the behaviour to want: a seed drawn from a
 * broken source is a wallet whose notes somebody else can spend, and it would
 * look exactly like a working one.
 */
export function newSeed(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(32));
}

/** Whether a string is the 64 hex characters a seed is written as. */
export function seedHexIsWellFormed(hex: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(hex.trim());
}
