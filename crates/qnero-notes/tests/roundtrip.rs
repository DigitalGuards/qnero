use qnero_notes::{
    ct_digest, encrypt_note, try_receive, Address, Note, NotesError, SpendingKey, MAX_VALUE,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn sk(seed: u8) -> SpendingKey {
    SpendingKey::from_bytes([seed; 32])
}

#[test]
fn address_roundtrip() {
    let addr = sk(1).address();
    let s = addr.encode();
    assert!(s.starts_with("qn1"));
    let back = Address::decode(&s).unwrap();
    assert_eq!(addr, back);
    assert_eq!(addr.to_bytes().len(), qnero_notes::address::ADDRESS_LEN);
}

#[test]
fn address_rejects_tampering() {
    let s = sk(1).address().encode();
    let mut chars: Vec<char> = s.chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
    let t: String = chars.into_iter().collect();
    assert!(matches!(
        Address::decode(&t),
        Err(NotesError::InvalidAddress(_))
    ));
}

#[test]
fn keys_are_deterministic_and_distinct() {
    let a = sk(7);
    let b = sk(7);
    let c = sk(8);
    assert_eq!(a.pk(), b.pk());
    assert_eq!(a.address(), b.address());
    assert_ne!(a.pk(), c.pk());
    assert_ne!(a.ask(), a.nk());
    assert_ne!(a.ak(), a.pk());
}

#[test]
fn note_encrypt_scan_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let recipient = sk(2);
    let addr = recipient.address();
    let note = Note::random(&mut rng, addr.pk, 1_000_000).unwrap();
    let cm = note.commitment();
    let ct = encrypt_note(&addr.ek, &note, b"hello", &[9u8; 32]).unwrap();

    let ivk = recipient.incoming_viewing_key();
    let got = try_receive(&ivk, &ct, &cm).unwrap();
    assert_eq!(got.note, note);
    assert_eq!(got.memo, b"hello");
    assert_eq!(got.commitment, cm);

    let fvk = recipient.full_viewing_key();
    assert_eq!(
        got.note.nullifier(&fvk.nk()),
        note.nullifier(&recipient.nk())
    );
}

#[test]
fn wrong_recipient_cannot_read() {
    let mut rng = StdRng::seed_from_u64(1);
    let addr = sk(3).address();
    let note = Note::random(&mut rng, addr.pk, 5).unwrap();
    let ct = encrypt_note(&addr.ek, &note, b"", &[1u8; 32]).unwrap();
    let other = sk(4).incoming_viewing_key();
    assert!(matches!(
        try_receive(&other, &ct, &note.commitment()),
        Err(NotesError::NotOurs)
    ));
}

#[test]
fn commitment_mismatch_is_rejected() {
    let mut rng = StdRng::seed_from_u64(2);
    let r = sk(5);
    let addr = r.address();
    let note = Note::random(&mut rng, addr.pk, 5).unwrap();
    let other = Note::random(&mut rng, addr.pk, 6).unwrap();
    let ct = encrypt_note(&addr.ek, &note, b"", &[1u8; 32]).unwrap();
    assert!(matches!(
        try_receive(&r.incoming_viewing_key(), &ct, &other.commitment()),
        Err(NotesError::CommitmentMismatch)
    ));
}

#[test]
fn value_bound() {
    let pk = sk(6).pk();
    let d = pk;
    assert!(Note::new(pk, MAX_VALUE, d, d).is_ok());
    assert!(matches!(
        Note::new(pk, MAX_VALUE + 1, d, d),
        Err(NotesError::ValueTooLarge(_))
    ));
}

#[test]
fn coinbase_public_opening() {
    let pk = sk(9).pk();
    let note = Note::new(pk, 12_345, pk, pk).unwrap();
    let inner = note.inner();
    assert_eq!(
        qnero_notes::note::commitment_from_inner(&inner, 12_345),
        note.commitment()
    );
    assert_ne!(
        qnero_notes::note::commitment_from_inner(&inner, 12_346),
        note.commitment()
    );
}

/// `ct_digest` is the one leaf public input the circuit does not constrain:
/// the chain recomputes it from the ciphertexts in the extrinsic and compares.
/// That comparison binds the ciphertexts only while the rule is injective, so
/// the count and the per-ciphertext lengths are in the preimage and a reorder
/// or a swap is a different digest.
#[test]
fn ct_digest_binds_the_ciphertexts_in_order() {
    let mut rng = StdRng::seed_from_u64(77);
    let a = sk(11).address();
    let b = sk(12).address();
    let note_a = Note::random(&mut rng, a.pk, 100).unwrap();
    let note_b = Note::random(&mut rng, b.pk, 200).unwrap();
    let ct_a = encrypt_note(&a.ek, &note_a, b"a", &[1u8; 32]).unwrap();
    let ct_b = encrypt_note(&b.ek, &note_b, b"bb", &[2u8; 32]).unwrap();

    let digest = ct_digest(&[ct_a.clone(), ct_b.clone()]);
    assert_eq!(digest, ct_digest(&[ct_a.clone(), ct_b.clone()]));
    assert_ne!(digest, ct_digest(&[ct_b.clone(), ct_a.clone()]));
    assert_ne!(digest, ct_digest(std::slice::from_ref(&ct_a)));
    assert_ne!(digest, ct_digest(&[]));

    // A memo one byte longer is a different ciphertext and a different digest,
    // which is what stops a relayer from swapping the payloads attached to a
    // settled leaf.
    let ct_a_longer = encrypt_note(&a.ek, &note_a, b"aa", &[1u8; 32]).unwrap();
    assert_ne!(digest, ct_digest(&[ct_a_longer, ct_b]));
}

/// A note and a decrypted note are the two most linkable objects a wallet
/// holds, and `{:?}` is how they end up in a log line or an error context.
/// Every downstream type that carries the same values redacts them, so these
/// two must as well: the leaf publishes `nf = H(NF, nk, rho, r)` on chain, and
/// a log carrying `rho`, `r`, the value and the memo links a settled nullifier
/// to the amount, the recipient key and the message.
#[test]
fn note_debug_does_not_leak_the_note() {
    let mut rng = StdRng::seed_from_u64(91);
    let recipient = sk(21).address();
    let note = Note::random(&mut rng, recipient.pk, 123_456_789).unwrap();

    let dump = format!("{note:?}");
    assert!(dump.contains("REDACTED"), "got: {dump}");
    assert!(!dump.contains("123456789"), "got: {dump}");
    assert!(!dump.contains(&format!("{:?}", note.rho)), "got: {dump}");
    assert!(!dump.contains(&format!("{:?}", note.r)), "got: {dump}");
    assert!(!dump.contains(&format!("{:?}", note.pk)), "got: {dump}");
}

#[test]
fn received_note_debug_does_not_leak_the_note_or_the_memo() {
    let mut rng = StdRng::seed_from_u64(92);
    let recipient = sk(22).address();
    let note = Note::random(&mut rng, recipient.pk, 4242).unwrap();
    let ct = encrypt_note(&recipient.ek, &note, b"top-secret-memo", &[9u8; 32]).unwrap();
    let received = try_receive(&sk(22).incoming_viewing_key(), &ct, &note.commitment()).unwrap();

    let dump = format!("{received:?}");
    assert!(dump.contains("REDACTED"), "got: {dump}");
    assert!(!dump.contains("top-secret-memo"), "got: {dump}");
    assert!(!dump.contains("4242"), "got: {dump}");
    // The commitment is on chain already, so it stays readable.
    assert!(
        dump.contains(&format!("{:?}", received.commitment)),
        "got: {dump}"
    );
}
