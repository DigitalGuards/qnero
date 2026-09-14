/**
 * The store's encryption at rest.
 *
 * Four properties, and each of them is a failure the sibling web wallet or
 * this workspace's prover has already met once:
 *
 * - a fresh IV on every write, including a rewrite of the same value;
 * - a wrong passphrase throws rather than returning plausible bytes;
 * - an envelope is bound to the slot it was written into;
 * - the seed a store opens with has to derive that store's own address.
 */

import { describe, expect, it } from 'vitest';

import {
  bytesToHex,
  deriveKey,
  ENVELOPE_VERSION,
  hexToBytes,
  newSalt,
  newSeed,
  openBytes,
  openJson,
  recordAad,
  sealBytes,
  sealJson,
  seedHexIsWellFormed,
  UnreadableStoreError,
  WrongPassphraseError,
} from '../src/wallet/crypto';

/**
 * A deliberately cheap key, so a suite of a dozen cases is not a dozen seconds
 * of PBKDF2. The iteration count the wallet actually uses is asserted where it
 * is declared, in `store.test.ts`.
 */
async function testKey(passphrase = 'a passphrase', saltHex = '00'.repeat(16)): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 1, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

describe('the envelope', () => {
  it('draws a fresh nonce for every write of the same value', async () => {
    const key = await testKey();
    const aad = recordAad('qn1abc', 'notes', 'cm');
    const plaintext = new TextEncoder().encode('the same note');
    const first = await sealBytes(key, aad, plaintext);
    const second = await sealBytes(key, aad, plaintext);

    // A repeated 12-byte IV under one key publishes the XOR of the two
    // plaintexts and the authentication key. Nothing inside AES-GCM checks it,
    // which is exactly the discipline the prover enforces for ML-KEM
    // randomness.
    expect(first.iv).not.toEqual(second.iv);
    expect(first.ct).not.toEqual(second.ct);
    expect(first.iv).toHaveLength(24);
  });

  it('opens what it sealed', async () => {
    const key = await testKey();
    const aad = recordAad('qn1abc', 'notes', 'cm');
    const sealed = await sealJson(key, aad, { rho: 'aa', r: 'bb', nullifier: 'cc', memo: 'hi' });
    expect(sealed.v).toBe(ENVELOPE_VERSION);
    await expect(openJson(key, aad, sealed)).resolves.toEqual({
      rho: 'aa',
      r: 'bb',
      nullifier: 'cc',
      memo: 'hi',
    });
  });

  it('refuses a key that is not the one it was sealed with', async () => {
    const aad = recordAad('qn1abc', 'notes', 'cm');
    const sealed = await sealJson(await testKey('right'), aad, { value: 1 });
    await expect(openJson(await testKey('wrong'), aad, sealed)).rejects.toBeInstanceOf(
      WrongPassphraseError,
    );
  });

  it('refuses an envelope pasted into another slot', async () => {
    const key = await testKey();
    const sealed = await sealJson(key, recordAad('qn1abc', 'notes', 'one'), { value: 1 });
    // The same wallet, the same store, another record.
    await expect(
      openJson(key, recordAad('qn1abc', 'notes', 'two'), sealed),
    ).rejects.toBeInstanceOf(WrongPassphraseError);
    // The same record id, another wallet.
    await expect(
      openJson(key, recordAad('qn1zzz', 'notes', 'one'), sealed),
    ).rejects.toBeInstanceOf(WrongPassphraseError);
    // The same record id, another store.
    await expect(
      openJson(key, recordAad('qn1abc', 'pending', 'one'), sealed),
    ).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('refuses an envelope format it cannot read, and says which', async () => {
    const key = await testKey();
    const aad = recordAad('qn1abc', 'notes', 'cm');
    const sealed = await sealJson(key, aad, { value: 1 });
    await expect(openBytes(key, aad, { ...sealed, v: 99 })).rejects.toBeInstanceOf(
      UnreadableStoreError,
    );
  });

  it('refuses a tampered ciphertext rather than returning plausible bytes', async () => {
    const key = await testKey();
    const aad = recordAad('qn1abc', 'notes', 'cm');
    const sealed = await sealJson(key, aad, { value: 1 });
    const flipped = `${sealed.ct.slice(0, -2)}${sealed.ct.slice(-2) === 'ff' ? '00' : 'ff'}`;
    await expect(openJson(key, aad, { ...sealed, ct: flipped })).rejects.toBeInstanceOf(
      WrongPassphraseError,
    );
  });
});

describe('the key derivation', () => {
  it('is a function of the passphrase and the salt together', async () => {
    const saltA = bytesToHex(newSalt());
    const saltB = bytesToHex(newSalt());
    expect(saltA).not.toEqual(saltB);

    const aad = recordAad('qn1abc', 'notes', 'cm');
    const sealed = await sealJson(await deriveKey('passphrase', saltA), aad, { value: 7 });
    // The same passphrase under another salt is another key, which is what
    // makes one leaked derivation useless against another store.
    await expect(
      openJson(await deriveKey('passphrase', saltB), aad, sealed),
    ).rejects.toBeInstanceOf(WrongPassphraseError);
    await expect(openJson(await deriveKey('passphrase', saltA), aad, sealed)).resolves.toEqual({
      value: 7,
    });
  }, 20_000);
});

describe('a seed', () => {
  it('is 32 bytes of browser randomness and round-trips through its hex', () => {
    const seed = newSeed();
    expect(seed).toHaveLength(32);
    const hex = bytesToHex(seed);
    expect(seedHexIsWellFormed(hex)).toBe(true);
    expect([...hexToBytes(hex)]).toEqual([...seed]);
    // Two draws are two seeds. A CSPRNG that returned a constant would be a
    // wallet somebody else can spend, and it would look like a working one.
    expect(bytesToHex(newSeed())).not.toEqual(hex);
  });

  it('refuses anything that is not 64 hex characters', () => {
    expect(seedHexIsWellFormed('')).toBe(false);
    expect(seedHexIsWellFormed('ab'.repeat(31))).toBe(false);
    expect(seedHexIsWellFormed('ab'.repeat(33))).toBe(false);
    expect(seedHexIsWellFormed(`${'ab'.repeat(31)}zz`)).toBe(false);
    expect(seedHexIsWellFormed(` ${'ab'.repeat(32)} `)).toBe(true);
  });
});
