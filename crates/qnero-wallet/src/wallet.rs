//! The wallet's operations: scan, shield, spend.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use qnero_circuit::chain::ct_digest;
use qnero_circuit::merkle::MerklePath;
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
/// over RPC.
///
/// `chain/pallets/shielded/build.rs` resolves it as
/// `QNERO_NUM_LEAF_PROOFS`, falling back to
/// `qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS`, so the wallet resolves it
/// the same way: one environment produces one `N` on both sides. Reading only
/// the default would leave a wallet at six against a runtime someone built at
/// eight, and the chain's embedded verifier would refuse the proof's
/// public-input length after the full proving cost had been paid, with no
/// local check to catch it first.
pub const NUM_LEAF_PROOFS: usize = match option_env!("QNERO_NUM_LEAF_PROOFS") {
    Some(text) => parse_leaf_proofs(text),
    None => qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS,
};

/// `str::parse` is not const, and this has to be one so the constant stays a
/// constant.
const fn parse_leaf_proofs(text: &str) -> usize {
    let bytes = text.as_bytes();
    assert!(
        !bytes.is_empty(),
        "QNERO_NUM_LEAF_PROOFS is set to an empty string"
    );
    let mut value = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(
            digit >= b'0' && digit <= b'9',
            "QNERO_NUM_LEAF_PROOFS must be a decimal number"
        );
        value = value * 10 + (digit - b'0') as usize;
        index += 1;
    }
    assert!(value > 0, "QNERO_NUM_LEAF_PROOFS must be at least one");
    value
}

/// Where an input note's Merkle path comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MerkleSource {
    /// Rebuild the tree locally from `ZkTree::Leaves` at the anchor block.
    ///
    /// The default, and the private one. `Chain::leaves` already reads the
    /// whole leaf range during a scan, and that read says nothing about which
    /// leaves matter to the reader.
    #[default]
    Local,
    /// Ask the node for `zkTree_getMerkleProof(leaf_index)`, one call per
    /// input.
    ///
    /// Cheaper, and it tells the node exactly which leaves this wallet is
    /// about to spend, seconds before the settlement that publishes their
    /// nullifiers arrives on the same connection.
    Rpc,
}

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
    ///
    /// The metadata is taken because the storage layout every key here is
    /// built from is checked against the runtime's own declaration first. On
    /// the read path a drifted key is silent: it reads as an empty map, and an
    /// empty map is a zero balance or a settled note reported unspent.
    pub fn sync(&mut self, chain: &Chain, metadata: &ChainMetadata) -> Result<SyncReport> {
        metadata.ensure_known_storage()?;
        let head = chain.head()?;
        let leaf_count = chain.leaf_count_at(&head.hash)?;
        // The settled nullifier set, read whole and pinned to the same block.
        //
        // Spent status used to be a question asked of the node about this
        // wallet's own nullifiers, one key at a time. `UsedNullifiers` is
        // `Blake2_128Concat`, so those keys carried the raw nullifiers in the
        // clear, and a node that logged them learned the set of values this
        // wallet would publish when it spent, before any of them existed on
        // chain. Reading the public map whole and deciding locally asks the
        // same question and names nothing.
        self.store.used_nullifiers = chain.used_nullifiers_at(&head.hash)?;
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
                if self.store.nullifier_settled(&nullifier_hex) {
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

        // Spent status, decided against the local copy of the settled set.
        // Only the nullifier key can compute these values at all, and a note
        // this wallet holds may have been spent by another copy of the same
        // seed, so the question is asked of every unspent note on every sync.
        // It is asked locally: see the note above the set's refresh.
        let newly_spent: Vec<String> = self
            .store
            .unspent()
            .filter(|note| self.store.used_nullifiers.contains(&note.nullifier))
            .map(|note| note.nullifier.clone())
            .collect();
        for nullifier in &newly_spent {
            self.store.mark_spent(nullifier, head.number);
            report.newly_spent += 1;
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

        // An extrinsic in a block is not a dispatch that succeeded. A shield
        // whose signer cannot pay, or whose value is not a whole multiple of
        // `POOL_QUANTUM`, is included and then fails, appends no leaf and
        // creates no note. Reporting that as a success leaves a pending entry
        // in the store forever and an exit code of zero, and it is also what
        // would swallow a `POOL_QUANTUM` drift, which `crate::POOL_QUANTUM`
        // argues is loud precisely because `ValueNotQuantized` would surface.
        let included_hash = chain.block_hash(included_at)?;
        let parent_hash = chain.block_hash(included_at.saturating_sub(1))?;
        let commitment = note.commitment();
        let leaves_before = chain.leaf_count_at(&parent_hash)?;
        let leaves_after = chain.leaf_count_at(&included_hash)?;
        let appended = chain.leaf_hashes(leaves_before..leaves_after, &included_hash)?;
        let Some(offset) = appended.iter().position(|leaf| *leaf == commitment) else {
            self.store
                .pending
                .retain(|pending| pending.commitment != commitment.to_hex());
            self.save()?;
            bail!(
                "the shield was included in block {included_at} and its dispatch failed: no leaf \
                 in that block carries the commitment {}, so no note was created. The usual \
                 causes are a dev account that cannot pay {} planck and a value that is not a \
                 whole multiple of POOL_QUANTUM. The pending entry has been dropped.",
                commitment.to_hex(),
                planck
            );
        };
        let leaf_index = leaves_before + offset as u64;

        // Both halves of the entry rule, against what the chain actually
        // assigned. Comparing `entry_rho(included_at, entry_index)` with the
        // `rho` built from that same `entry_index` only ever tested the block
        // half; the counter could have moved between the read and inclusion
        // and the check would still have said it matched.
        let entry_before = chain.entry_count_at(&parent_hash)?;
        let entry_after = chain.entry_count_at(&included_hash)?;
        let entry_check = classify_entry_rho(
            predicted_block,
            entry_index,
            included_at,
            entry_before,
            entry_after,
        );

        Ok(ShieldReport {
            quanta,
            commitment: commitment.to_hex(),
            leaf_index,
            included_at,
            inclusion,
            predicted_block,
            predicted_entry_index: entry_index,
            entry_count_after: entry_after,
            entry_check,
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
        merkle: MerkleSource,
    ) -> Result<SendReport> {
        let prepared = self.prepare_spend(
            chain,
            metadata,
            prover,
            to,
            amount,
            requested_fee,
            memo,
            merkle,
        )?;
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
        merkle: MerkleSource,
    ) -> Result<PreparedSpend> {
        metadata.ensure_known_storage()?;
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

        // The anchor. Every read of it is pinned to one hash, because the tree
        // root moves every block and the header a proof binds to must be the
        // one whose root the input paths reach.
        //
        // The anchor is always the current head, and that is a privacy policy
        // as much as a correctness one. The anchor block is a public input of
        // the settlement, so an observer reads the gap between anchor and
        // inclusion. Every wallet anchoring at the head makes that gap the
        // same short interval for everyone; an anchor at head minus k, or one
        // cached and reused across two spends to save a `chain_getHeader`, is
        // a distinguisher inside the 256-block window and marks both spends as
        // one wallet's. So the anchor is always the head, and it is taken
        // fresh for every submission. The head is taken after the circuits are
        // built for the same reason, since the anchor-to-inclusion gap
        // otherwise publishes this machine's circuit build time.
        let head = chain.head()?;
        let (header, anchor_hash) = chain.anchor_header(head.number)?;

        let pk = self.key.pk();
        let derived = self.key.derived();
        let mut paths = match merkle {
            MerkleSource::Local => {
                self.local_paths(chain, &selected, &header, &anchor_hash, head.number)?
            }
            MerkleSource::Rpc => {
                self.rpc_paths(chain, &selected, &header, &anchor_hash, head.number)?
            }
        };

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

    /// Input paths, rebuilt locally from the whole leaf range at the anchor.
    ///
    /// The private route, and the default. `zkTree_getMerkleProof` is asked
    /// only about leaves a wallet is about to spend, so every such call names
    /// one of this wallet's own leaves to the node, and the settlement that
    /// publishes the matching nullifier arrives on the same connection seconds
    /// later. That join is the sender side of the pool deanonymized against
    /// whoever runs the RPC. Reading the whole leaf range says nothing about
    /// which leaf matters, and it is the read a scan already performs.
    ///
    /// `CommitmentTree` mirrors `pallet-zk-tree` exactly: the same 4-ary node
    /// rule, the same sorted children, the same all-zero padding for an absent
    /// child. The root it reaches is compared against the header's before any
    /// proving, which is the same check the RPC route makes and it covers the
    /// rebuild as well.
    fn local_paths(
        &self,
        chain: &Chain,
        selected: &[StoredNote],
        header: &qnero_circuit::header::HeaderInputs,
        anchor_hash: &[u8; 32],
        anchor_block: u32,
    ) -> Result<Vec<(Note, MerklePath)>> {
        let tree = chain.rebuild_tree(anchor_hash)?;
        for note in selected {
            if note.leaf_index >= tree.leaf_count() {
                bail!(
                    "leaf {} is not folded into the tree at block {anchor_block} yet. A note \
                     cannot be minted and spent in the same block; wait one block and retry.",
                    note.leaf_index
                );
            }
        }
        if tree.root() != header.zk_tree_root {
            bail!(
                "the tree this wallet rebuilt from {} leaves at depth {} roots at {} where \
                 header {anchor_block} carries {}. Proving against it would be refused. \
                 `--merkle-rpc` asks the node for the paths, at the cost of telling it which \
                 leaves are yours.",
                tree.leaf_count(),
                tree.depth(),
                tree.root().to_hex(),
                header.zk_tree_root.to_hex()
            );
        }
        let pk = self.key.pk();
        let mut paths = Vec::with_capacity(selected.len());
        for note in selected {
            let stored = note.note(pk)?;
            let on_chain = tree
                .leaf(note.leaf_index)
                .ok_or_else(|| anyhow!("leaf {} is out of range", note.leaf_index))?;
            if on_chain != stored.commitment() {
                bail!(
                    "leaf {} holds {} on chain and this wallet holds a note committing to {}",
                    note.leaf_index,
                    on_chain.to_hex(),
                    stored.commitment().to_hex()
                );
            }
            let path = tree.path(note.leaf_index)?;
            let reached = path.root(stored.commitment())?;
            if reached != header.zk_tree_root {
                bail!(
                    "the path rebuilt for leaf {} reaches {} where header {anchor_block} carries \
                     {}",
                    note.leaf_index,
                    reached.to_hex(),
                    header.zk_tree_root.to_hex()
                );
            }
            paths.push((stored, path));
        }
        Ok(paths)
    }

    /// Input paths from `zkTree_getMerkleProof`, one call per input.
    ///
    /// Behind `--merkle-rpc`, and it tells the node which leaves this wallet
    /// is spending. See [`Wallet::local_paths`].
    fn rpc_paths(
        &self,
        chain: &Chain,
        selected: &[StoredNote],
        header: &qnero_circuit::header::HeaderInputs,
        anchor_hash: &[u8; 32],
        anchor_block: u32,
    ) -> Result<Vec<(Note, MerklePath)>> {
        let pk = self.key.pk();
        let mut paths = Vec::with_capacity(selected.len());
        for note in selected {
            let stored = note.note(pk)?;
            let path = chain
                .merkle_path(note.leaf_index, stored.commitment(), anchor_hash)?
                .ok_or_else(|| {
                    anyhow!(
                        "leaf {} is not folded into the tree at block {anchor_block} yet. A note \
                         cannot be minted and spent in the same block; wait one block and retry.",
                        note.leaf_index
                    )
                })?;
            if path.root != header.zk_tree_root {
                bail!(
                    "the Merkle proof for leaf {} reaches root {} where header {anchor_block} \
                     carries {}",
                    note.leaf_index,
                    path.root.to_hex(),
                    header.zk_tree_root.to_hex()
                );
            }
            paths.push((stored, path.path));
        }
        Ok(paths)
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
    /// The leaf the note actually landed at. Its existence is the proof the
    /// dispatch succeeded.
    pub leaf_index: u64,
    pub included_at: u32,
    pub inclusion: Duration,
    pub predicted_block: u32,
    pub predicted_entry_index: u64,
    pub entry_count_after: u64,
    pub entry_check: EntryRhoCheck,
}

/// What became of the entry-`rho` prediction a shield made.
///
/// The rule is `rho = H(RHO_ENTRY, block_number, entry_index)`
/// (`docs/CIRCUIT.md` section 9.8) and neither half is knowable before
/// submission: the block is the producer's choice and `EntryCount` moves with
/// every other shield. Both halves are checked afterwards against what the
/// chain assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryRhoCheck {
    /// Both halves confirmed. The block is the predicted one, the counter had
    /// not moved, and exactly one entry settled in that block, so the index
    /// the chain assigned is the predicted one.
    Confirmed,
    /// The prediction missed, and the note's `rho` does not follow the rule
    /// for the identifier the chain assigned it.
    Missed { reason: String },
    /// More than one shield settled in the inclusion block, so which index
    /// went to this note is not decidable from storage alone: only the
    /// `Shielded` event carries it, and decoding that needs the runtime's full
    /// type registry.
    Unproven { entries_in_block: u64 },
}

/// Classify a shield's entry-`rho` prediction against the chain.
///
/// Apart from the RPC so the rule can be exercised, which is what the
/// half-checked version could not be.
pub fn classify_entry_rho(
    predicted_block: u32,
    predicted_entry_index: u64,
    included_at: u32,
    entry_count_before: u64,
    entry_count_after: u64,
) -> EntryRhoCheck {
    if included_at != predicted_block {
        return EntryRhoCheck::Missed {
            reason: format!(
                "the shield was predicted to land in block {predicted_block} and landed in \
                 block {included_at}"
            ),
        };
    }
    if entry_count_before != predicted_entry_index {
        return EntryRhoCheck::Missed {
            reason: format!(
                "the entry counter stood at {predicted_entry_index} when the note was built and \
                 at {entry_count_before} when the block opened, so the chain assigned this note \
                 a different entry index"
            ),
        };
    }
    let entries_in_block = entry_count_after.saturating_sub(entry_count_before);
    match entries_in_block {
        0 => EntryRhoCheck::Missed {
            reason: "the inclusion block settled no shield entry at all".into(),
        },
        1 => EntryRhoCheck::Confirmed,
        entries => EntryRhoCheck::Unproven {
            entries_in_block: entries,
        },
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The check this replaces compared `entry_rho(included_at, entry_index)`
    /// against a `rho` built from that same `entry_index`, which reduces to
    /// comparing the two block numbers. The counter half was fetched and
    /// thrown away, so a counter that moved between the read and inclusion was
    /// reported as a match, and two wallets shielding into one block both
    /// recorded the same `rho` for notes the chain gave different entry
    /// indices.
    #[test]
    fn the_entry_rule_is_checked_on_both_halves() {
        // The block matched, the counter had not moved, one entry settled.
        assert_eq!(
            classify_entry_rho(11, 7, 11, 7, 8),
            EntryRhoCheck::Confirmed
        );

        // The block missed. The counter agreeing does not save it.
        let missed = classify_entry_rho(11, 7, 12, 7, 8);
        assert!(matches!(missed, EntryRhoCheck::Missed { .. }));

        // The block matched and the counter moved under it. This is the case
        // the old check reported as a match.
        let missed = classify_entry_rho(11, 7, 11, 9, 10);
        match missed {
            EntryRhoCheck::Missed { reason } => {
                assert!(reason.contains("entry counter"), "{reason}");
            }
            other => panic!("a moved counter must be a miss, got {other:?}"),
        }

        // Two shields in one block: the counter started where the prediction
        // said, so one of the two notes holds the predicted index and storage
        // alone cannot say which.
        assert_eq!(
            classify_entry_rho(11, 7, 11, 7, 9),
            EntryRhoCheck::Unproven {
                entries_in_block: 2
            }
        );

        // A block that settled no entry at all cannot have settled this one.
        assert!(matches!(
            classify_entry_rho(11, 7, 11, 7, 7),
            EntryRhoCheck::Missed { .. }
        ));
    }

    /// `N` is resolved from the environment the way the pallet's build script
    /// resolves it. A wallet at a different `N` from its runtime pays the full
    /// proving cost and has its public-input length refused.
    #[test]
    fn the_leaf_slot_count_parses_the_way_the_build_script_reads_it() {
        assert_eq!(parse_leaf_proofs("6"), 6);
        assert_eq!(parse_leaf_proofs("53"), 53);
        assert_eq!(parse_leaf_proofs("1"), 1);
        if option_env!("QNERO_NUM_LEAF_PROOFS").is_none() {
            assert_eq!(
                NUM_LEAF_PROOFS,
                qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS
            );
        }
    }

    /// The private route is the default one. A default that asked the node for
    /// proofs would name every leaf this wallet spends.
    #[test]
    fn paths_are_rebuilt_locally_unless_asked_otherwise() {
        assert_eq!(MerkleSource::default(), MerkleSource::Local);
    }
}
