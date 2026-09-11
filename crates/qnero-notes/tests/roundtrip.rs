use qnero_notes::{encrypt_note, try_receive, Address, Note, NotesError, SpendingKey, MAX_VALUE};
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
