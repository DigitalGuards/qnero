//! The wallet's operations: scan, shield, spend.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use qnero_circuit::chain::ct_digest;
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{encrypt_note, entry_rho, try_receive, Address, Digest, Note, NoteCiphertext};
use qnero_notes::{IncomingViewingKey, SpendingKey};
use qnero_prover::WalletProver;
use rand::TryRngCore;

use crate::chain::Chain;
use crate::extrinsic::{
    encode_shield_call, encode_signed, encode_submit_private_batch, ShieldedOutput, SigningContext,
};
use crate::fee::{ensure_ciphertext_fits, slot_fee_floor, submission_fee_floor};
use crate::keys::store_path_for;
use crate::metadata::ChainMetadata;
use crate::rpc::hex_0x;
use crate::select::select_notes;
use crate::store::{NoteOrigin, PendingKind, PendingNote, RejectedNote, StoredNote, WalletStore};
use crate::POOL_QUANTUM;

/// Leaf slots in a private batch. Not a metadata value and not discoverable
/// over RPC: `chain/pallets/shielded/build.rs` reads it from
/// `qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS`, so the wallet reads it
/// from the same constant. A wallet built at a different `N` produces a proof
/// whose public-input length the chain's embedded verifier refuses, after the
/// full proving cost has been paid.
pub const NUM_LEAF_PROOFS: usize = qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS;

/// How long a submission is waited on before the wallet gives up.
///
/// An unsigned settlement has `longevity(5)`: it leaves the pool after five
/// blocks and a byte-identical rebroadcast will not displace it, so the answer
/// to a timeout is to prove again against a fresh anchor.
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Wallet {
    pub seed_path: PathBuf,
    pub store_path: PathBuf,
    key: SpendingKey,
    pub store: WalletStore,
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wallet")
            .field("seed_path", &self.seed_path)
            .field("address", &self.store.address)
            .finish()
    }
}

impl Wallet {
    pub fn open(seed_path: &Path) -> Result<Self> {
        let key = crate::keys::load_seed(seed_path)?;
        let address = key.address().encode();
        let store_path = store_path_for(seed_path);
        let store = WalletStore::load_or_new(&store_path, &address)?;
        Ok(Self {
            seed_path: seed_path.to_path_buf(),
            store_path,
            key,
            store,
        })
    }

    pub fn address(&self) -> Address {
        self.key.address()
    }

    pub fn ivk(&self) -> IncomingViewingKey {
        self.key.incoming_viewing_key()
    }

    pub fn save(&self) -> Result<()> {
        self.store.save(&self.store_path)
    }

    /// Scan from the last synced leaf to the tree's current count.
    ///
    /// Every read is pinned to one block hash, so a leaf appended mid-scan
    /// cannot be counted and then read as absent.
    pub fn sync(&mut self, chain: &Chain) -> Result<SyncReport> {
        let head = chain.head()?;
        let leaf_count = chain.leaf_count_at(&head.hash)?;
        let start = self.store.next_leaf;
        let mut report = SyncReport {
            head_block: head.number,
            scanned_from: start,
            scanned_to: leaf_count,
            ..Default::default()
        };

        if leaf_count > start {
            let ivk = self.ivk();
            let nk = self.key.nk();
            for record in chain.leaves(start..leaf_count, &head.hash)? {
                report.leaves_scanned += 1;
                let (Some(commitment), Some(ciphertext)) = (record.commitment, record.ciphertext)
                else {
                    // A wormhole transfer leaf or a mining-reward leaf. The
                    // shielded pool shares one tree with both, so most leaf
                    // indices carry no ciphertext at all.
                    continue;
                };
                let Ok(commitment) = Digest::from_bytes(&commitment) else {
                    continue;
                };
                let Ok(parsed) = NoteCiphertext::from_bytes(&ciphertext) else {
                    continue;
                };
                let Ok(received) = try_receive(&ivk, &parsed, &commitment) else {
                    continue;
                };

                let commitment_hex = commitment.to_hex();
                if self.store.has_commitment(&commitment_hex) {
                    continue;
                }
                let nullifier = received.note.nullifier(&nk);
                let nullifier_hex = nullifier.to_hex();

                // `docs/CIRCUIT.md` section 9.8: a sender picks `rho` and `r`
                // for a note it creates, so a sender that repeats a pair
                // hands over two notes sharing one nullifier, of which
                // exactly one can ever be spent. The recipient is the last
                // line, so the duplicate is refused. Carrying it would be a
                // balance that cannot move.
                if self.store.known_nullifiers().contains(&nullifier_hex) {
                    self.store.rejected.push(RejectedNote {
                        leaf_index: record.index,
                        commitment: commitment_hex,
                        nullifier: nullifier_hex,
                        value: received.note.value,
                        reason: "its nullifier duplicates a note this wallet already holds".into(),
                    });
                    report.rejected += 1;
                    continue;
                }
                if chain.nullifiers_used(&[nullifier.to_bytes()], &head.hash)?[0] {
                    self.store.rejected.push(RejectedNote {
                        leaf_index: record.index,
                        commitment: commitment_hex,
                        nullifier: nullifier_hex,
                        value: received.note.value,
                        reason: "its nullifier is already settled on chain".into(),
                    });
                    report.rejected += 1;
                    continue;
                }

                let origin = match record.block_number {
                    Some(block)
                        if entry_rho_matches(block, &received.note.rho, chain, &head.hash)? =>
                    {
                        NoteOrigin::Shield
                    }
                    _ => NoteOrigin::Spend,
                };
                report.received += 1;
                report.received_value += received.note.value;
                self.store.notes.push(StoredNote {
                    leaf_index: record.index,
                    block_number: record.block_number,
                    value: received.note.value,
                    commitment: commitment_hex.clone(),
                    nullifier: nullifier_hex,
                    rho: received.note.rho.to_hex(),
                    r: received.note.r.to_hex(),
                    memo: String::from_utf8_lossy(&received.memo).into_owned(),
                    origin,
                    spent: false,
                    spent_seen_at_block: None,
                });
                self.store
                    .pending
                    .retain(|pending| pending.commitment != commitment_hex);
            }
        }

        // Spent status. Only the nullifier key can ask this question, and it
        // is asked of every unspent note on every sync: a note this wallet
        // holds may have been spent by another copy of the same seed.
        let unspent: Vec<(String, [u8; 32])> = self
            .store
            .unspent()
            .map(|note| -> Result<(String, [u8; 32])> {
                Ok((
                    note.nullifier.clone(),
                    crate::store::parse_digest(&note.nullifier, "nullifier")?.to_bytes(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let raw: Vec<[u8; 32]> = unspent.iter().map(|(_, bytes)| *bytes).collect();
        for (used, (hex, _)) in chain
            .nullifiers_used(&raw, &head.hash)?
            .iter()
            .zip(&unspent)
        {
            if *used {
                self.store.mark_spent(hex, head.number);
                report.newly_spent += 1;
            }
        }

        self.store.next_leaf = leaf_count;
        self.store.last_synced_block = head.number;
        self.save()?;
        Ok(report)
    }

    /// Move transparent value into the pool as one note owned by this wallet.
    pub fn shield(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        from: &crate::dev_account::TransparentKey,
        quanta: u64,
        memo: &str,
    ) -> Result<ShieldReport> {
        if quanta == 0 {
            bail!("a shield of zero moves nothing and the chain refuses it");
        }
        let head = chain.head()?;
        let entry_index = chain.entry_count_at(&head.hash)?;
        // The entry `rho` rule hashes the block the shield lands in and the
        // chain-wide entry counter at that moment
        // (`qnero_note_core::entry_rho`). Neither is knowable before
        // submission, so both are predicted and checked afterwards. The chain
        // does not evaluate the rule, and a prediction that misses strands
        // nothing: the note is this wallet's own and its commitment opens
        // whatever `rho` went into it.
        let predicted_block = head.number + 1;
        let rho = entry_rho(predicted_block, entry_index);
        let r = random_digest(b"qnero-wallet/shield-r")?;
        let note = Note::new(self.key.pk(), quanta, rho, r)?;
        let inner = note.inner();
        let ciphertext = encrypt_note(
            &self.ivk().encapsulation_key(),
            &note,
            memo.as_bytes(),
            &random_bytes()?,
        )?
        .to_bytes();
        ensure_ciphertext_fits(metadata, ciphertext.len(), "shield")?;

        let planck = u128::from(quanta)
            .checked_mul(POOL_QUANTUM)
            .ok_or_else(|| anyhow!("{quanta} quanta overflows the chain's balance type"))?;
        let call = encode_shield_call(metadata, planck, &inner.to_bytes(), &ciphertext);
        let (spec_version, transaction_version) = chain.runtime_version()?;
        let context = SigningContext {
            spec_version,
            transaction_version,
            genesis_hash: chain.genesis_hash()?,
            nonce: chain.account_nonce(&from.account_id())?,
            tip: 0,
        };
        let encoded = encode_signed(metadata, from, &call, &context)?;

        // Written before the submission: the store is the only copy of this
        // note's `r`, and a crash between `author_submitExtrinsic` and the
        // confirmation would otherwise burn the value into a commitment
        // nothing can open.
        self.store.pending.push(PendingNote {
            kind: PendingKind::Shield,
            commitment: note.commitment().to_hex(),
            value: quanta,
            rho: rho.to_hex(),
            r: r.to_hex(),
            memo: memo.to_string(),
            submitted_at_block: head.number,
            extrinsic: hex_0x(&encoded),
        });
        self.save()?;

        let started = Instant::now();
        chain.submit_extrinsic(&encoded)?;
        let included_at = wait_for_inclusion(chain, &hex_0x(&encoded), head.number)?;
        let inclusion = started.elapsed();

        let included_hash = chain.block_hash(included_at)?;
        let actual_entry = chain.entry_count_at(&included_hash)?;
        let rho_matches = entry_rho(included_at, entry_index) == rho;

        Ok(ShieldReport {
            quanta,
            commitment: note.commitment().to_hex(),
            included_at,
            inclusion,
            predicted_block,
            predicted_entry_index: entry_index,
            entry_count_after: actual_entry,
            entry_rho_matches: rho_matches,
        })
    }

    /// Resolve the fee and check the spend is fundable, before any circuit is
    /// built.
    ///
    /// Building the prover is seconds and proving is tens of seconds, and both
    /// are wasted on a spend that a fee floor or a two-input selection was
    /// always going to refuse. Everything here is a few ML-KEM encapsulations
    /// and a sort.
    pub fn preflight(
        &self,
        metadata: &ChainMetadata,
        to: &Address,
        amount: u64,
        requested_fee: Option<u64>,
        memo: &str,
    ) -> Result<u64> {
        let fee = self.resolve_fee(metadata, to, memo, requested_fee)?;
        let target = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("{amount} plus {fee} overflows"))?;
        select_notes(self.store.unspent(), target)?;
        Ok(fee)
    }

    /// The fee this submission owes, or the caller's if it clears the floor.
    ///
    /// The ciphertext sizes decide the floor and the fee is a public input
    /// fixed at proving time, so both are settled before a witness exists. A
    /// `NoteCiphertext` is a fixed size plus its memo and the note's value
    /// does not move it, so measuring a probe pair is exact.
    fn resolve_fee(
        &self,
        metadata: &ChainMetadata,
        to: &Address,
        memo: &str,
        requested_fee: Option<u64>,
    ) -> Result<u64> {
        let probe_payment = probe_ciphertext_len(&to.ek, memo.as_bytes())?;
        let probe_change = probe_ciphertext_len(&self.ivk().encapsulation_key(), b"")?;
        ensure_ciphertext_fits(metadata, probe_payment, "payment")?;
        ensure_ciphertext_fits(metadata, probe_change, "change")?;
        let floor = slot_fee_floor(metadata, probe_payment, probe_change);
        debug_assert_eq!(
            floor,
            submission_fee_floor(metadata, 1, (probe_payment + probe_change) as u64)
        );
        match requested_fee {
            None => Ok(floor),
            Some(fee) if fee < floor => bail!(
                "a fee of {fee} quanta is below this submission's floor of {floor}. The pallet \
                 asks MinLeafFee ({}) plus one quantum per started {} bytes of ciphertext, and \
                 the two outputs here are {} bytes. The fee is a public input of the proof, so \
                 it cannot be raised afterwards: the settlement would be refused with \
                 PayloadUnderpaid.",
                metadata.min_leaf_fee,
                metadata.ciphertext_bytes_per_fee_quantum,
                probe_payment + probe_change
            ),
            Some(fee) => Ok(fee),
        }
    }

    /// Spend up to two notes into a payment and a change note.
    ///
    /// [`Wallet::prepare_spend`] then [`Wallet::submit_spend`]: the two halves
    /// are apart so an aggregator can take the proof between them and wrap it
    /// in a public batch. A wallet calls this.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        prover: &WalletProver,
        to: &Address,
        amount: u64,
        requested_fee: Option<u64>,
        memo: &str,
    ) -> Result<SendReport> {
        let prepared =
            self.prepare_spend(chain, metadata, prover, to, amount, requested_fee, memo)?;
        self.submit_spend(chain, metadata, prepared)
    }

    /// Everything up to and including the proof, with nothing submitted and
    /// nothing written to the store.
    ///
    /// What comes back is exactly what `submit_private_batch` takes, and it is
    /// also exactly what an aggregator wraps: a public batch's inner is a
    /// private batch that would have been accepted on its own.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_spend(
        &self,
        chain: &Chain,
        metadata: &ChainMetadata,
        prover: &WalletProver,
        to: &Address,
        amount: u64,
        requested_fee: Option<u64>,
        memo: &str,
    ) -> Result<PreparedSpend> {
        let fee = self.resolve_fee(metadata, to, memo, requested_fee)?;
        let probe_payment = probe_ciphertext_len(&to.ek, memo.as_bytes())?;
        let probe_change = probe_ciphertext_len(&self.ivk().encapsulation_key(), b"")?;

        let target = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("{amount} plus {fee} overflows"))?;
        let selected: Vec<StoredNote> = select_notes(self.store.unspent(), target)?
            .into_iter()
            .cloned()
            .collect();
        let input_total: u64 = selected.iter().map(|note| note.value).sum();
        let change = input_total - target;

        // The anchor. `zkTree_getMerkleProof` and `chain_getHeader` are read
        // at one hash, because the tree root moves every block and the header
        // the proof binds to must be the one whose root the path reaches.
        let head = chain.head()?;
        let (header, anchor_hash) = chain.anchor_header(head.number)?;

        let pk = self.key.pk();
        let derived = self.key.derived();
        let mut paths = Vec::new();
        for note in &selected {
            let stored = note.note(pk)?;
            let path = chain
                .merkle_path(note.leaf_index, stored.commitment(), &anchor_hash)?
                .ok_or_else(|| {
                    anyhow!(
                        "leaf {} is not folded into the tree at block {} yet. A note cannot be \
                         minted and spent in the same block; wait one block and retry.",
                        note.leaf_index,
                        head.number
                    )
                })?;
            if path.root != header.zk_tree_root {
                bail!(
                    "the Merkle proof for leaf {} reaches root {} where header {} carries {}",
                    note.leaf_index,
                    path.root.to_hex(),
                    head.number,
                    header.zk_tree_root.to_hex()
                );
            }
            paths.push((stored, path.path));
        }

        let depth = paths[0].1.depth();
        let mut rng = rand::rng();
        let inputs: [InputNote; 2] = match paths.len() {
            1 => {
                let (note, path) = paths.remove(0);
                [
                    InputNote::real(&derived, &note, path)?,
                    // `dummy_random` draws its `(rho, r)` from a CSPRNG. A
                    // repeated pair publishes a nullifier the chain has
                    // already settled and the whole submission is refused,
                    // naming a value the wallet cannot map to any note it
                    // holds.
                    InputNote::dummy_random(&mut rng, &derived, depth),
                ]
            }
            2 => {
                let (second_note, second_path) = paths.remove(1);
                let (first_note, first_path) = paths.remove(0);
                [
                    InputNote::real(&derived, &first_note, first_path)?,
                    InputNote::real(&derived, &second_note, second_path)?,
                ]
            }
            other => bail!("selected {other} notes for a circuit with two input slots"),
        };

        let outputs = [
            OutputNote::new(to.pk, amount, random_digest(b"qnero-wallet/out-payment")?),
            OutputNote::new(pk, change, random_digest(b"qnero-wallet/out-change")?),
        ];
        // `ct_digest` binds ciphertexts that carry a `rho` the witness derives
        // from its own nullifiers, so the witness is built first with a
        // placeholder and the digest written once the outputs exist. Nothing
        // is proved in between.
        let mut witness = SpendWitness {
            header,
            depth,
            inputs,
            outputs,
            fee,
            ct_digest: Digest::from_bytes(&[0u8; 32]).expect("zero is canonical"),
        };
        witness.validate()?;

        let payment_note = witness.output_note(0)?;
        let change_note = witness.output_note(1)?;
        let ct_1 =
            encrypt_note(&to.ek, &payment_note, memo.as_bytes(), &random_bytes()?)?.to_bytes();
        let ct_2 = encrypt_note(
            &self.ivk().encapsulation_key(),
            &change_note,
            b"",
            // Fresh per output, and nothing enforces it inside `encrypt_note`:
            // two outputs sharing `kem_randomness` are encrypted under one
            // ChaCha20-Poly1305 key and nonce, which leaks the XOR of the two
            // plaintexts and the authentication key.
            &random_bytes()?,
        )?
        .to_bytes();
        if ct_1.len() != probe_payment || ct_2.len() != probe_change {
            bail!(
                "the ciphertexts came out at {} and {} bytes where the fee was computed for {} \
                 and {}",
                ct_1.len(),
                ct_2.len(),
                probe_payment,
                probe_change
            );
        }
        let outputs = vec![ShieldedOutput {
            ct_1: ct_1.clone(),
            ct_2: ct_2.clone(),
        }];
        witness.ct_digest = output_ct_digest(&outputs[0])?;
        witness.validate()?;

        let nullifiers = [
            witness.inputs[0].nullifier().to_bytes(),
            witness.inputs[1].nullifier().to_bytes(),
        ];

        let proving_started = Instant::now();
        let proof = prover
            .prove_submission(vec![witness])
            .context("failed to prove the private batch")?;
        let proving = proving_started.elapsed();
        // Verifying before sending costs milliseconds and turns a wallet-side
        // mistake into a local error. The pool refuses a bad settlement
        // without saying which public input was wrong.
        prover
            .batch_verifier_data()
            .verify(proof.clone())
            .map_err(|_| anyhow!("this wallet's own private-batch proof does not verify"))?;
        let proof_bytes = proof.to_bytes();

        Ok(PreparedSpend {
            proof: proof_bytes,
            outputs,
            nullifiers,
            change_note: PendingNote {
                kind: PendingKind::Change,
                commitment: change_note.commitment().to_hex(),
                value: change,
                rho: change_note.rho.to_hex(),
                r: change_note.r.to_hex(),
                memo: String::new(),
                submitted_at_block: head.number,
                extrinsic: String::new(),
            },
            spent_nullifiers: selected.iter().map(|note| note.nullifier.clone()).collect(),
            input_leaves: selected.iter().map(|note| note.leaf_index).collect(),
            amount,
            fee,
            change,
            anchor_block: head.number,
            proving,
        })
    }

    /// Submit a prepared spend and wait for it to settle.
    pub fn submit_spend(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        prepared: PreparedSpend,
    ) -> Result<SendReport> {
        let encoded = encode_submit_private_batch(metadata, &prepared.proof, &prepared.outputs);
        let encoded_hex = hex_0x(&encoded);

        // Written before the submission: the store is the only copy of the
        // change note's `r`, and a crash between here and the confirmation
        // would leave a commitment in the tree that nothing can open.
        let mut change_note = prepared.change_note.clone();
        change_note.extrinsic = encoded_hex.clone();
        self.store.pending.push(change_note);
        self.save()?;

        let submit_started = Instant::now();
        chain.submit_extrinsic(&encoded)?;
        let included_at = wait_for_inclusion(chain, &encoded_hex, prepared.anchor_block)?;
        let inclusion = submit_started.elapsed();

        // The settlement is what marks the inputs spent, so it is confirmed
        // against the chain: an extrinsic in a block is not yet a settled one.
        // A segment whose anchor went stale or whose nullifier was claimed
        // elsewhere is skipped, and the block carries it either way.
        let included_hash = chain.block_hash(included_at)?;
        let settled = chain.nullifiers_used(&prepared.nullifiers, &included_hash)?;
        if !settled[0] || !settled[1] {
            bail!(
                "the submission was included in block {included_at} and its nullifiers are not \
                 settled. The segment was skipped; re-sync and try again against a fresh anchor."
            );
        }
        for nullifier in &prepared.spent_nullifiers {
            self.store.mark_spent(nullifier, included_at);
        }
        self.save()?;

        Ok(SendReport {
            amount: prepared.amount,
            fee: prepared.fee,
            change: prepared.change,
            inputs: prepared.input_leaves,
            anchor_block: prepared.anchor_block,
            included_at,
            proof_bytes: prepared.proof.len(),
            proving: prepared.proving,
            inclusion,
        })
    }
}

/// A proved spend, before anything is submitted or recorded.
#[derive(Debug, Clone)]
pub struct PreparedSpend {
    /// The private-batch proof, in plonky2's canonical encoding.
    pub proof: Vec<u8>,
    /// One entry per real leaf slot, in settlement order.
    pub outputs: Vec<ShieldedOutput>,
    /// Both nullifiers the leaf publishes, the dummy's included.
    pub nullifiers: [[u8; 32]; 2],
    change_note: PendingNote,
    spent_nullifiers: Vec<String>,
    pub input_leaves: Vec<u64>,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub anchor_block: u32,
    pub proving: Duration,
}

/// The `ct_digest` of one settlement slot, over the bytes the extrinsic
/// carries.
///
/// One rule, one implementation: `qnero_circuit::chain::ct_digest` is what
/// `pallet-shielded` recomputes over the `ShieldedOutput` it decoded, and it
/// is what the leaf's public input commits to. What a wallet owes is the
/// order, `ct_1` beside `cm_out_1`, and the exact bytes it is about to send.
pub fn output_ct_digest(output: &ShieldedOutput) -> Result<Digest> {
    Digest::from_bytes(&ct_digest(&[&output.ct_1, &output.ct_2]))
        .map_err(|_| anyhow!("ct_digest is not a canonical digest"))
}

/// Whether a note's `rho` is the one the entry rule produces for the block its
/// leaf landed in.
///
/// The rule hashes `(block_number, entry_index)` and only the `Shielded` event
/// publishes `entry_index`, which needs the runtime's full type registry to
/// decode. So this walks the entry counter instead: the counter is chain wide
/// and monotone, a dev chain's is small, and a miss is not an error. A `false`
/// means the note came from a spend, whose `rho` the circuit derived from two
/// nullifiers, or from a shielder that ignored the rule.
fn entry_rho_matches(block: u32, rho: &Digest, chain: &Chain, at: &[u8; 32]) -> Result<bool> {
    let entries = chain.entry_count_at(at)?;
    Ok((0..entries).any(|index| entry_rho(block, index) == *rho))
}

/// Poll blocks for the exact extrinsic that was submitted.
///
/// Matching the bytes keeps this honest about what it saw.
/// An unsigned settlement's `provides` tag is a function of the bundle, so a
/// rebroadcast of the same proof never displaces the copy already in the pool;
/// there is nothing useful to do but wait and then prove again.
fn wait_for_inclusion(chain: &Chain, extrinsic_hex: &str, from_block: u32) -> Result<u32> {
    let deadline = Instant::now() + INCLUSION_TIMEOUT;
    let mut next = from_block + 1;
    loop {
        let head = chain.head()?;
        while next <= head.number {
            let hash = chain.block_hash(next)?;
            if chain
                .block_extrinsics(&hash)?
                .iter()
                .any(|encoded| encoded == extrinsic_hex)
            {
                return Ok(next);
            }
            next += 1;
        }
        if Instant::now() >= deadline {
            bail!(
                "the submission was not included within {} seconds (watched blocks {}..={}). An \
                 unsigned settlement leaves the pool after five blocks and a rebroadcast of the \
                 same bytes will not displace it: prove again against a fresh anchor.",
                INCLUSION_TIMEOUT.as_secs(),
                from_block + 1,
                head.number
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn probe_ciphertext_len(ek: &qnero_pqcrypto::ml_kem::MlKemPublicKey, memo: &[u8]) -> Result<usize> {
    let note = Note::new(
        Digest::hash_bytes(&[b"qnero-wallet/probe-pk"]),
        0,
        Digest::hash_bytes(&[b"qnero-wallet/probe-rho"]),
        Digest::hash_bytes(&[b"qnero-wallet/probe-r"]),
    )?;
    Ok(encrypt_note(ek, &note, memo, &random_bytes()?)?
        .to_bytes()
        .len())
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("the operating system's RNG refused")?;
    Ok(bytes)
}

fn random_digest(domain: &[u8]) -> Result<Digest> {
    Ok(Digest::hash_bytes(&[domain, &random_bytes()?]))
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub head_block: u32,
    pub scanned_from: u64,
    pub scanned_to: u64,
    pub leaves_scanned: u64,
    pub received: u64,
    pub received_value: u64,
    pub rejected: u64,
    pub newly_spent: u64,
}

#[derive(Debug)]
pub struct ShieldReport {
    pub quanta: u64,
    pub commitment: String,
    pub included_at: u32,
    pub inclusion: Duration,
    pub predicted_block: u32,
    pub predicted_entry_index: u64,
    pub entry_count_after: u64,
    pub entry_rho_matches: bool,
}

#[derive(Debug)]
pub struct SendReport {
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub inputs: Vec<u64>,
    pub anchor_block: u32,
    pub included_at: u32,
    pub proof_bytes: usize,
    pub proving: Duration,
    pub inclusion: Duration,
}
