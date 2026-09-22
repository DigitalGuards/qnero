# Qnero Runtime Surface

Complete inventory of every piece of code that gets compiled into the on-chain
runtime WASM. This is the authoritative map of the runtime's attack/audit
surface: the runtime crate's own modules, the pallets composed into the runtime,
their dispatchable calls, the runtime APIs, transaction extensions, genesis
logic, and the workspace primitive crates pulled in.

Reconciled with the runtime at M6 (2026-09-12), which removed `pallet-wormhole`
and its transaction extension, added `pallet-shielded` at index 24, and renamed
the runtime. `docs/DESIGN.md` section 7 is the v1 policy this inventory is the
surface of.

- **Crate:** `qnero-runtime` (`runtime/`), version `1.0.0-gm`. Renamed from `quantus-runtime` in `e3d3889`, along with the node package; the wasm it emits is `wbuild/qnero-runtime/qnero_runtime.wasm`. The chain identifies itself by the spec below.
- **Spec:** `spec_name = qnero`, `impl_name = qnero-node`, `spec_version = 104`, `transaction_version = 7`, `authoring_version = 1`
- **Build:** `no_std` WASM via `substrate-wasm-builder` (`runtime/build.rs`); native `std` build for the node/client
- **Block time target:** 120s (`TARGET_BLOCK_TIME_MS = 120_000`), Monero's interval. It is the public default and the value in metadata; what a chain actually retargets against is `pallet_qpow::TargetBlockTimeMs`, written once at genesis from the chain spec, which the `dev` preset sets to `12_000`. `QPoWApi::get_target_block_time` reads it. Derived block counts: `MINUTES = 1` (so 2 minutes, the shortest a block count can express), `HOURS = 30`, `DAYS = 720`
- **Consensus:** QPoW (quantum-resistant Proof of Work, Poseidon2-based)
- **Signatures:** ML-DSA-87 at the transparent entry. The upstream `DilithiumSignatureScheme` enum keeps its second variant so subtree merges stay clean, and `runtime/src/extrinsic.rs` refuses a signed extrinsic carrying it with `InvalidTransaction::BadSigner`. That is a consensus rule; `docs/DESIGN.md` section 7.3 in the repository root is the write-up
- **SS58 prefix:** 189

---

## 1. Runtime crate source files (`runtime/src/`)

| File | Responsibility |
| --- | --- |
| `lib.rs` | Crate root. Core type aliases, `RuntimeVersion`, opaque types, `TxExtension`, `UncheckedExtrinsic`, `Executive`, and the `#[frame_support::runtime]` pallet composition (indices 0–24). |
| `configs/mod.rs` | All `impl pallet::Config for Runtime` blocks, `parameter_types!`, fee model, `HighSecurityConfig`, `TryFrom<RuntimeCall>` impls, the `QneroCallFilter` v1 call filter, the `QpowAuthor` `FindAuthor` seam, and `NoTransferProofNeeded`. |
| `apis.rs` | `impl_runtime_apis!` - every runtime API exposed to the client/RPC. |
| `extrinsic.rs` | `QneroUncheckedExtrinsic`, the runtime's own extrinsic type. SCALE-transparent wrapper over the upstream generic one whose `Checkable` implementation carries one consensus rule: the transparent entry admits ML-DSA-87 and refuses the ML-DSA-65 variant with `InvalidTransaction::BadSigner`, on the live path and the `try-runtime` replay path alike. |
| `transaction_extensions.rs` | Custom transaction extension `ReversibleTransactionExtension`, and `HighSecurityFungibleAdapter`, the configured `OnChargeTransaction`. |
| `governance/mod.rs` + `governance/definitions.rs` | Referenda tracks (`TechCollectiveTracksInfo`, the only lane), preimage deposit model, custom origins, rank converters. |
| `genesis_config_presets/` | Genesis presets: `dev`, `heisenberg`, `planck`, `mainnet`. Mainnet allocation is `mainnet_vesting.rs`. |
| `benchmarks.rs` | `define_benchmarks!` list (only under `runtime-benchmarks`). |

### Core type aliases (`lib.rs`)

| Type | Definition |
| --- | --- |
| `Signature` | `DilithiumSignatureScheme` (post-quantum). Only the ML-DSA-87 variant is admissible; `extrinsic.rs` refuses the other one at the entry |
| `AccountId` | Derived from the Dilithium signer (`AccountId32`) |
| `Balance` | `u128` |
| `AssetId` | `u32` |
| `Nonce` | `u32` |
| `BlockNumber` | `u32` |
| `Hash` | `sp_core::H256` |
| `Difficulty` | `U512` |
| `Address` | `MultiAddress<AccountId, ()>` |
| `Header` | `qp_header::Header<BlockNumber, BlakeTwo256>` (Poseidon block hash, Blake2 state trie) |
| `Block` | `generic::Block<Header, UncheckedExtrinsic>`, where `UncheckedExtrinsic` is `extrinsic::QneroUncheckedExtrinsic` |
| `Executive` | `frame_executive::Executive<Runtime, Block, ChainContext, Runtime, AllPalletsWithSystem, ()>` |
| `SessionKeys` | empty (`impl_opaque_keys!` - no session keys; PoW chain) |

### Economic constants (`lib.rs`)

`UNIT = 10^12`, `MILLI_UNIT = 10^9`, `MICRO_UNIT = 10^6`, `EXISTENTIAL_DEPOSIT = MILLI_UNIT`,
`MINUTES/HOURS/DAYS` derived from block time, `BLOCK_HASH_COUNT = 2400`.

---

## 2. Pallet composition (`#[frame_support::runtime]`)

The runtime derives `RuntimeCall`, `RuntimeEvent`, `RuntimeError`, `RuntimeOrigin`,
`RuntimeFreezeReason`, `RuntimeHoldReason`, `RuntimeSlashReason`, `RuntimeLockId`, `RuntimeTask`.

| Index | Alias | Source crate | Origin | Calls? |
| --- | --- | --- | --- | --- |
| 0 | `System` | `frame-system` `45.0.0` | **Local fork** (`pallets/frame-system`) | yes |
| 1 | `Timestamp` | `pallet-timestamp` `44.0.0` | **Inlined** (`pallets/timestamp`) | yes |
| 2 | `Balances` | `pallet-balances` `46.0.0` | **Inlined** (`pallets/balances`) | yes |
| 3 | `TransactionPayment` | `pallet-transaction-payment` `45.0.0` | **Inlined** (`pallets/transaction-payment`) | (no extrinsics) |
| 4 | - | *(vacant; was `pallet-sudo`)* | - | - |
| 5 | `QPoW` | `pallet-qpow` | **Local** (`pallets/qpow`) | no |
| 6 | `MiningRewards` | `pallet-mining-rewards` | **Local** (`pallets/mining-rewards`) | no |
| 7 | `Preimage` | `pallet-preimage` `45.0.0` | **Inlined** (`pallets/preimage`) | yes |
| 8 | `Scheduler` | `pallet-scheduler` | **Local fork** (`pallets/scheduler`) | **calls disabled** (`#[runtime::disable_call]`) |
| 9 | `Utility` | `pallet-utility` `45.0.0` | **Inlined** (`pallets/utility`) | yes |
| 10 | - | *(vacant; was community `Referenda`)* | - | - |
| 11 | `ReversibleTransfers` | `pallet-reversible-transfers` | **Local** (`pallets/reversible-transfers`) | yes |
| 12 | - | *(vacant; was `ConvictionVoting`)* | - | - |
| 13 | `TechCollective` | `pallet-ranked-collective` `45.0.0` | **Inlined** (`pallets/ranked-collective`) | yes |
| 14 | `TechReferenda` | `pallet-referenda::Pallet<Runtime, Instance1>` `45.0.0` | **Inlined** (2nd instance) | yes |
| 15 | `TreasuryPallet` | `pallet-treasury` | **Local** (`pallets/treasury`) | yes |
| 16 | - | *(vacant)* | - | - |
| 17 | - | *(vacant; was `pallet-assets`)* | - | - |
| 18 | - | *(vacant; was `pallet-assets-holder`)* | - | - |
| 19 | `Multisig` | `pallet-multisig` | **Local** (`pallets/multisig`) | yes |
| 20 | - | *(vacant; was `pallet-wormhole`, removed at M6 with the transparent exit)* | - | - |
| 21 | `ZkTree` | `pallet-zk-tree` | **Local fork** (`pallets/zk-tree`) | no |
| 22 | `Vesting` | `pallet-vesting` | **Local** (`pallets/vesting`) | yes |
| 23 | `Origins` | `pallet_custom_origins` | **Local** (`runtime/src/governance/origins.rs`) | no |
| 24 | `Shielded` | `pallet-shielded` | **Local** (`pallets/shielded`) | yes (two unsigned, one signed, one inherent) |

> Indices 4, 10, 12, 16, 17, 18 and 20 are intentionally left vacant after pallet removals so downstream indices stay stable. The `pallet-wormhole` crate stays in the tree and is out of the runtime; `qp-wormhole`, the primitives crate, stays in the runtime because the QPoW author derivation lives there.

---

## 3. Pallet configuration & dispatchable surface

All `Config` impls live in `runtime/src/configs/mod.rs` unless noted.

**Read this section against the call filter.** `frame_system::BaseCallFilter =
QneroCallFilter` (`configs/mod.rs`) refuses every call that moves transparent
value between accounts a user chooses, and it recurses through `Utility::batch_all`
and `Multisig::execute`. A call listed below as dispatchable may therefore be
refused at dispatch for an ordinary signer; `docs/DESIGN.md` section 7.2 is the
allowlist and `runtime/tests/call_filter.rs` is the test. Root bypasses the
filter (`dispatch_bypass_filter`), so governance can still enact what an account
cannot submit.

### Index 0 - `System` (`frame-system`, local fork)
- Config via `#[derive_impl(SolochainDefaultConfig)]`. `Block = Block`, `Hashing = BlakeTwo256`, `AccountData = pallet_balances::AccountData<Balance>`, `SS58Prefix = 189`, `MaxConsumers = 16`, `BlockHashCount = 4096`.
- `RuntimeBlockWeights`: 6s ref_time, `proof_size = u64::MAX` (uncapped - solo PoW chain).
- `RuntimeBlockLength`: 5 MB, normal dispatch ratio 75%.
- **Local fork additions:** `ZkTreeRoot` storage + `set_zk_tree_root` / `deposit_log` helpers; intra-block entropy.
- **Calls (call_index):** `remark`(0), `set_heap_pages`(1), `set_code`(2), `set_code_without_checks`(3), `set_storage`(4), `kill_storage`(5), `kill_prefix`(6), `remark_with_event`(7), `do_task`(8), `authorize_upgrade`(9), `authorize_upgrade_without_checks`(10), `apply_authorized_upgrade`(11).

### Index 1 - `Timestamp` (`pallet-timestamp`)
- `Moment = u64`, `MinimumPeriod = 100`, `OnTimestampSet = Vesting` (one-shot rebase of the genesis offset schedules onto the first non-zero timestamp in the block-1 inherent; constant-bounded by the genesis table's fixed capacity, `MAX_GENESIS_SCHEDULES` = 64).
- Provides the timestamp inherent.

### Index 2 - `Balances` (`pallet-balances`)
- `Balance = u128`, `ExistentialDeposit = MILLI_UNIT`, `AccountStore = System`, `MaxLocks = 50`, `MaxFreezes = VariantCountOf<RuntimeFreezeReason>`, hold/freeze reasons wired to runtime enums.
- **Calls:** `transfer_allow_death`(0), `transfer_keep_alive`(3), `transfer_all`(4), `burn`(10). There is no `force_transfer` and no `set_balance` in this fork. The three transfers are refused by `QneroCallFilter`; `burn` destroys the caller's own balance and moves nothing to anyone, so it stays dispatchable.

### Index 3 - `TransactionPayment` (`pallet-transaction-payment`)
- `OnChargeTransaction = transaction_extensions::HighSecurityFungibleAdapter`, which wraps `FungibleAdapter<Balances, pallet_mining_rewards::TransactionFeesCollector<Runtime>>` and rejects any non-zero tip from a high-security signer. 100% of fees reach the block's author, and under v1 they reach it as part of the block's coinbase note rather than as a transparent credit (index 6, index 24).
- `WeightToFee = ScaledIdentityFee` (identity mapping × `FEE_SCALE`; 1s compute ≈ `FEE_SCALE` UNIT).
- `LengthToFee = LengthToFeeMultiplier` (custom, `LENGTH_FEE_MULTIPLIER = 10^6` × `FEE_SCALE`; 1 MB ≈ `FEE_SCALE` UNIT).
- `FeeMultiplierUpdate = ConstFeeMultiplier` (multiplier fixed at 1), `OperationalFeeMultiplier = 5`.
- Every absolute-QNR price (fees, deposits, the high-security fee cap) derives from the `FEE_SCALE_NUM/DEN` dial in `runtime/src/lib.rs` via `scale_fee`; percentage rates, the existential deposit, and the leaf step are deliberately not scaled.

### Index 5 - `QPoW` (`pallet-qpow`, local)
- `InitialDifficulty = U512([1_000_000, 0, …])`, `TargetBlockTime = 120_000ms`, `MaxReorgDepth = u32::MAX`, `SeedEpochBlocks = 2_048`, `SeedEpochLag = 128`, `WeightInfo = SubstrateWeight<Runtime>`.
- `TargetBlockTimeMs` is a genesis-configured storage value with no setter, defaulting to the constant above; `Pallet::target_block_time()` falls back to the constant when it is unset. That is what lets one binary serve a 120 s public chain and a 12 s dev chain.
- No dispatchable calls. Implements `Hooks` (`on_initialize`/`on_finalize`) to track block timing and recompute difficulty. Powers the `QPoWApi` runtime API.

### Index 6 - `MiningRewards` (`pallet-mining-rewards`, local)
- `Currency = Balances`, `CoinbaseSink = Shielded`, `ShieldedSupply = pallet_shielded::ShieldedSupply<Runtime>`, `FindAuthor = QpowAuthor`, `MaxSupply = 21_000_000 * UNIT`, `EmissionDivisor = 5_000_000`, `Unit = UNIT`. Credits are aligned to the pool step (`AMOUNT_SCALE_DOWN_FACTOR` = 10^10, 0.01 QNR).
- No dispatchable calls. Exposes `TransactionFeesCollector` + `collect_transaction_fees`. `on_finalize` combines transaction fees and the block reward into one credit and hands it to the sink, which mints it as the block's coinbase note; **no account is credited** under v1. Emission measures supply across both books, `Balances::total_issuance()` plus the pool, because a planck inside the pool has left issuance. A sub-step remainder stays in `CollectedFees` for the next block. Nothing is minted to treasury.

### Index 7 - `Preimage` (`pallet-preimage`)
- `ManagerOrigin = EnsureRoot`, `Consideration = PreimageDeposit` (custom: 0.1 UNIT base + 0.0001 UNIT/byte, × `FEE_SCALE`, see `governance/definitions.rs`).
- **Calls:** `note_preimage`, `unnote_preimage`, `request_preimage`, `unrequest_preimage`, `ensure_updated` (upstream).

### Index 8 - `Scheduler` (`pallet-scheduler`, local) - **calls disabled**
- `RuntimeCall`, `MaximumWeight = 80% max block`, `MaxScheduledPerBlock = 50`, `ScheduleOrigin = EnsureRoot`, `Preimages = Preimage`, `TimeProvider = Timestamp`, `Moment = u64`, `TimestampBucketSize = 2 * block time`.
- Calls exist (`schedule`(0), `cancel`(1), `schedule_named`(2), `cancel_named`(3), `schedule_after`(4), `schedule_named_after`(5), `set_retry`(6), `set_retry_named`(7), `cancel_retry`(8), `cancel_retry_named`(9)) but are **disabled at the runtime level** so users cannot enqueue arbitrary calls. Used internally by reversible-transfers and governance via the `ScheduleNamed` trait. Local fork adds block-number-or-timestamp scheduling.
- **Priority-reserved headroom:** tasks scheduled at `LOWEST_PRIORITY` (the permissionless scheduling surface - reversible transfers) may occupy at most ~80% of a block's agenda (40 of 50 slots). This reserves ~20% per block - at least one slot even if `MaxScheduledPerBlock < 5` - so a permissionless caller cannot cheaply pre-fill a referendum's deterministic enactment block with priority-255 tasks. Mid-priority tasks (e.g. referendum alarms at 128) can still occupy reserved slots, but `schedule_enactment` retries at `when + 1` for up to 16 blocks on `Exhausted` before logging failure.

### Index 9 - `Utility` (`pallet-utility`)
- `RuntimeCall`, `PalletsOrigin = OriginCaller`.
- **Calls:** `batch_all` only (`call_index` 2). Other FRAME utility combinators (`batch`, `as_derivative`, `dispatch_as`, `force_batch`, `with_weight`, `if_else`, `dispatch_as_fallible`) are omitted.

### Index 11 - `ReversibleTransfers` (`pallet-reversible-transfers`, local)
- `AssetId = u32` (retained for wire-format compatibility; asset transfers are rejected), `Scheduler = Scheduler`, `DefaultDelay = 1 DAY`, `MinDelayPeriodBlocks = 2`, `MaxPendingPerAccount = 16`, `VolumeFee = 1%` (high-security reversals, burned), `ProofRecorder = ()` (nothing to record: every call this pallet schedules or executes moves transparent value between accounts and the v1 call filter refuses all of them), `PalletId = "rtpallet"`.
- **Every call on this pallet is refused by `QneroCallFilter` under v1**, `set_high_security` included. The configuration below is the surface as it stands, reachable only by a privileged origin.
- **Calls:** `set_high_security`(0), `cancel`(1), `execute_transfer`(2), `schedule_transfer`(3), `schedule_transfer_with_delay`(4), `recover_funds`(7). Call indices 5/6 were `schedule_asset_transfer` / `schedule_asset_transfer_with_delay` (removed with assets); kept vacant so `recover_funds` stays at 7. Pending transfers with `Some(asset_id)` fail with `AssetsNotSupported`.
- There is deliberately no on-chain guardian → protected-accounts index (a bounded one could be filled by strangers to grief a popular guardian; enrollment needs no guardian consent since guardianship grants only passive powers). Guardianship is authoritative in `HighSecurityAccounts`; offchain indexers (Subsquid) reconstruct the reverse mapping from `HighSecuritySet` events.
- The guardian holds instant, total seizure power (`recover_funds` sweeps all holds plus the whole free balance to it, no delay, no second approver, immutable relationship), so the recommended guardian is a **multisig address**: `pallet_multisig` dispatches as its derived address, and the cancel/recover lifecycle under a multisig guardian is pinned by an integration test.
- Backs `HighSecurityConfig` (account whitelist/guardian logic).

### Index 13 - `TechCollective` (`pallet-ranked-collective`)
- `AddOrigin = EnsureRootWithSuccess<AccountId, ConstU16<0>>` (Root-only, i.e. a passed TechReferenda vote; #91267), `RemoveOrigin = EnsureRootRemoveKeepsMemberFloor` (Root-only **and** refuses removals that would leave fewer than `MIN_TECH_COLLECTIVE_MEMBERS` members - the floor that keeps the tech-referenda lane live), `Promote/Demote/ExchangeOrigin = NeverEnsureOrigin`, `Polls = TechReferenda (Instance1)`, `VoteWeight = Linear`, `MaxMemberCount = 13` (via `GlobalMaxMembers`).
- **Calls:** `add_member`, `promote_member`, `demote_member`, `remove_member`, `vote`, `cleanup_poll`, `exchange_member`. Removal intentionally leaves the member's votes in ongoing tallies (upstream behavior); `support` clamps at 100% so the shrunken electorate cannot overflow the curve.

### Index 14 - `TechReferenda` (`pallet-referenda`, `Instance1`)
- `SubmitOrigin = RootOrMemberForTechReferendaOrigin`, `Tracks = TechCollectiveTracksInfo` (track 0 for Root proposals, 61% approval / 60% support constant curves; track 1 `fast_upgrade` for `FastUpgrade` proposals, 80%/80% constant curves with 10-minute prepare/confirm/enactment), `Tally = pallet_ranked_collective::TallyOf<Runtime>`, `MaxActive = 128` / `MaxActivePerAccount = 8` (global + per-submitter caps on `Ongoing` referenda; storage `ActiveReferendaCount` / `ActiveSubmissionCount`; errors `TooManyActive` / `TooManyActiveBySubmitter`), `MaxProposalSize = 4 KiB`.
- **Calls:** the stock `pallet-referenda` set (`submit`, `place_decision_deposit`, `refund_decision_deposit`, `cancel`, `kill`, `nudge_referendum`, `one_fewer_deciding`, `refund_submission_deposit`, `set_metadata`). This is the only referenda instance; the community lane at index 10 and its `ConvictionVoting` at index 12 are gone.

### Index 15 - `TreasuryPallet` (`pallet-treasury`, local)
- Minimal local treasury. Config only sets `WeightInfo`.
- **Calls:** `set_treasury_account`(0, root). Exposes `account_id()`. Treasury is not paid from mining rewards.

### Index 19 - `Multisig` (`pallet-multisig`, local)
- `MaxSigners = 100`, `MaxTotalProposalsInStorage = 200`, `MaxCallSize = 10 KB`, `MultisigFee = 0.03 × FEE_SCALE UNIT` (burned), `ProposalDeposit = 0.01 × FEE_SCALE UNIT`, `ProposalFee = 0.05 × FEE_SCALE UNIT`, `MaxExpiryDuration ≈ 2 weeks`, `MaxInnerCallWeight = (10^12, 2.5 MB)`, `HighSecurity = HighSecurityConfig`, `PalletId = "py/mltsg"`.
- **Calls:** `create_multisig`(0), `propose`(1), `approve`(2), `cancel`(3), `remove_expired`(4), `claim_deposits`(5), `execute`(6). Exposes `derive_multisig_address`.

### Index 20 - vacant (was `Wormhole`)

`pallet-wormhole` held the transparent exit (`verify_private_batch`,
`verify_public_batch`), the `TransferProofRecorder` implementation that wrote a
spendable leaf for every transparent credit, and the block-1 hook that recorded
a proof for each genesis endowment. M6 removed all three from the runtime with
its transaction extension: under v1 there are no transparent transfers to
record and no exit to take. The crate stays in the tree; `qp-wormhole`, the
primitives crate, stays in the runtime because `derive_wormhole_address` is
what the `QpowAuthor` seam hashes a block author's digest item with.

### Index 21 - `ZkTree` (`pallet-zk-tree`, local fork)
- `AssetId = u32`, `Balance = u128`. No dispatchable calls.
- **Storage:** `Leaves` (raw `Hash256` note commitments since M4; the old typed `ZkLeaf` fold is gone, which is why an upstream `quantus-runtime` state cannot be carried across), `Nodes`, `LeafCount`, `Depth`, `Root`.
- `on_finalize` commits the merkle root into the header. Backs the `ZkTreeApi` runtime API. Under v1 every leaf is a note commitment and nothing else appends to it.

### Index 22 - `Vesting` (`pallet-vesting`, local)
- Pull-based "vesting wallet": the pallet's sovereign pot (`PalletId(*b"qvesting")`, keyless) holds the entire unclaimed allocation; beneficiaries are paid by plain keep-alive transfers only when a payout is due. **No locks, freezes, or holds ever touch a beneficiary account.** Under v1 every beneficiary must be an account that can sign, since `claim` pays a plain transparent balance and `shield` is the only way onward; `every_genesis_planck_is_reachable_under_the_call_filter` is the test.
- Config: `Currency = Balances` (`fungible::{Inspect, Mutate}`), `TimeProvider = Timestamp` (ms since epoch), `AdminOrigin = EitherOfDiverse<EnsureRoot, EnsureTreasury>` (`EnsureTreasury` = signed by the configured treasury account; the treasury multisig executes proposals as a plain signed origin), `TreasuryAccount = TreasuryAccountOption` (Option-returning storage read, never panics), `ProofRecorder = NoTransferProofNeeded` (records nothing and reports success; the pallet treats a dropped credit as fatal and there is no leaf to write since the exit is gone), `PayoutQuantum = SCALE_DOWN_FACTOR` (10^10 = 0.01 QNR), `MinClaimInterval = 86,400,000 ms` (24 hours). Non-final claims are further aligned to `pallet_vesting::NON_FINAL_PAYOUT_QUANTA` (2,500) leaf quanta = 25 QNR, the smallest 4 bps fee-exact multiple. Timestamp `OnTimestampSet = Vesting`: when genesis used `anchor_to_first_timestamp`, the first non-zero timestamp (block 1 inherent, not genesis-block `Now` which is 0) is stored in `Launch` and added onto those genesis offsets. The genesis table is a `BoundedVec` of at most `MAX_GENESIS_SCHEDULES` (64) entries, so that one-time rebase is constant-bounded.
- **Storage:** `Schedules: schedule_id (u64) → { beneficiary, start, cliff, end, total, claimed, last_claim_at }` (ids sequential, never reused; a beneficiary may hold any number of schedules), `NextScheduleId`, `Launch` (absent on absolute-time chains; `Pending` → `Anchored(moment)` once offset genesis schedules are rebased). Storage version 0 has no migration: an in-place upgrade with no schedules may leave the pot unfunded, and `create_schedule` then fails with `PotUnderfunded` until the treasury sends it one ED.
- Vesting math: `vested(t) = 0` before `cliff`, `total` from `end`, else `⌊total·(t−start)/(end−start)⌋` (256-bit rational, floor; the `end` branch guarantees exactness).
- **Payout policy:** the leaf quantum is `10^10`, so a sub-quantum payout used to create a zero-value leaf and strand funds on a keyless beneficiary; the quantization stays as it is now that no leaf is written. Schedule totals must be a positive multiple of `PayoutQuantum`; payouts are quantized and `claimed` stays aligned. A successful claim must pay at least one quantum and be at least 24 hours after that schedule's previous payout. Non-final claims additionally round down to 25 QNR (`NON_FINAL_PAYOUT_QUANTA` leaf quanta), which used to make each intermediate leaf's 4 bps wormhole fee exact; leftover dust stays on the schedule. The final claim pays the exact remainder (at least one quantum). `end_schedule` pays the unpaid vested part rounded to the nearest `PayoutQuantum` to the beneficiary when that amount is at least one quantum; otherwise the sliver is refunded with every leftover planck to treasury. No leg writes a leaf under v1.
- **Proof recording:** the pallet still calls `TransferProofRecorder` itself (`transfer_and_record` fuses transfer + record and fails with `TransferProofNotRecorded` if the recorder drops the credit, rolling the transfer back), and under v1 the configured recorder is `NoTransferProofNeeded`, which writes no leaf and reports success. `pallet_vesting::weights` still prices the insert it no longer performs (one leaf for `claim` and `create_schedule`, two for `end_schedule`), which is an overcharge on the one transparent payout v1 keeps.
- **Calls:** `claim`(0) - **permissionless**; pays the largest valid claim from the pot to the schedule's stored beneficiary (never the caller); the only claim path for keyless/high-security beneficiaries. `create_schedule`(1) - admin; validates the schedule and funds the pot from the treasury in the same call. `end_schedule`(2) - admin; unpaid vested part rounded to the nearest quantum → beneficiary if it is at least one quantum, otherwise the whole remainder → treasury; schedule removed. `retarget_schedule`(3) - admin; changes the beneficiary and pays nothing out. A retarget replaces the *same* grantee's lost/stolen/abandoned wallet, so settling the old address would burn funds or pay a thief; everything vested but unclaimed stays on the schedule and reaches the new wallet at its next claim. (A permissionless claim landing before the retarget still pays the old address, so rotations should happen promptly.)
- Genesis build validates every schedule (`start ≤ cliff ≤ end`, `start < end`, `total` a positive multiple of `PayoutQuantum`, beneficiary ≠ pot) and, for a non-empty table, asserts the pot holds exactly `Σ schedule totals + ED`; a misconfigured chain refuses to start. `try_state` validates stored schedules, aligned claims, remaining obligations of zero or at least one quantum, and, when any schedule exists, `pot balance ≥ Σ(total − claimed) + ED`; an empty schedule table is valid with an unfunded pot.

### Index 23 - `Origins` (`pallet_custom_origins`, local)
- Storage-less, call-less, event-less origin declaration: its whole body is one `#[pallet::origin] enum Origin { FastUpgrade }`. A pallet is the only way to contribute a variant to `RuntimeOrigin`/`OriginCaller`.
- `Origin::FastUpgrade` is the proposal origin of tech-referenda track 1 (`fast_upgrade`) and is honored **only** by `system.authorize_upgrade` (`AuthorizeUpgradeOrigin = EitherOfDiverse<EnsureRoot, FastUpgrade>` in the forked frame-system). `set_code` and `authorize_upgrade_without_checks` remain Root-only, so the track can publish an upgrade hash and nothing else.
- **Calls:** none. See `docs/RUNTIME_UPGRADE_VIA_GOVERNANCE.md` for the authorize-then-apply flow.

### Index 24 - `Shielded` (`pallet-shielded`, local)

The shielded pool. Under v1 it holds every planck created after genesis, and it
is the only pallet that appends to the tree.

- `Currency = Balances`, `ZkTree = ZkTree` (the same single instance the header's root commits to), `FindAuthor = QpowAuthor`, `BlockHashWindow = 256`, `MinLeafFee = 1` pool step (0.01 QNR), `CiphertextBytesPerFeeQuantum = 512`, `FeeBurnRate = 50%`, `MaxCiphertextBytes = 2048`.
- **Calls:** `submit_private_batch`(0) and `submit_public_batch`(1), both **unsigned** with `#[pallet::validate_unsigned]` three-stage admission and both fee free at the extrinsic level (the leaf fee is charged out of the pool); `shield`(2), **signed**, the only entry into the pool, which burns the caller's own balance and appends one note; `coinbase`(3), an **inherent** (`ProvideInherent`, `DispatchClass::Mandatory`, `ensure_none`), which records the block author's note payload. `is_inherent` matches the `coinbase` variant alone, so the two unsigned settlements are not reclassified.
- **Storage:** `UsedNullifiers` (`Blake2_128Concat`, prover-chosen keys), `Ciphertexts` (`Identity`, by leaf index), `LeafBlocks` (`Identity`), `EntryCount`, `PoolValue` (planck the pool stands behind), `PendingCoinbase` (the payload from this block's inherent, killed at `on_initialize` and taken by the mint), `PendingCoinbaseFee` (the author's share of settled fees, waiting for a coinbase note), `CoinbaseValues` (`Identity`, a coinbase note's public value in pool steps; presence is what marks a leaf a coinbase).
- **Hooks:** `on_initialize` kills a stale payload and reserves the weight the mint costs. This pallet declares no `on_finalize`: the mint runs inside `pallet-mining-rewards`' `on_finalize`, which calls `CoinbaseSink::deposit_coinbase` on this pallet, and that indirection is the whole reason the sink exists. Hooks run in pallet-index order, `MiningRewards` is index 6 and `ZkTree` index 21, so the coinbase leaf is appended well before `ZkTree` folds the block's leaves; a mint from a hook of this pallet, at index 24, would append after the fold and push every coinbase leaf out of the root its own block's header carries (the comment on the pallet declaration in `runtime/src/lib.rs` is the same argument). The mint computes `cm = H(CM, inner, total)` where `total` is the emission handed over by `MiningRewards` plus `PendingCoinbaseFee`, and writes the sub-step remainder of that sum back into `PendingCoinbaseFee`. A block with no coinbase inherent fails on import, because the inherent is required.
- Exposes `ShieldedSupply` (what `pallet-mining-rewards` adds to `total_issuance` to measure supply) and `CoinbaseSink` (the sink that turns the block reward into a note). `docs/CIRCUIT.md` section 10 is the coinbase record and `docs/DESIGN.md` section 7 the policy.

---

## 4. Runtime APIs (`apis.rs`, `impl_runtime_apis!`)

| API | Methods |
| --- | --- |
| `sp_api::Core` | `version`, `execute_block`, `initialize_block` |
| `sp_api::Metadata` | `metadata`, `metadata_at_version`, `metadata_versions` |
| `sp_block_builder::BlockBuilder` | `apply_extrinsic`, `finalize_block`, `inherent_extrinsics`, `check_inherents` |
| `sp_transaction_pool::TaggedTransactionQueue` | `validate_transaction` |
| `sp_offchain::OffchainWorkerApi` | `offchain_worker` |
| `sp_session::SessionKeys` | `generate_session_keys`, `decode_session_keys` (empty - no session keys) |
| `sp_consensus_qpow::QPoWApi` | `verify_nonce_on_import_block`, `verify_nonce_local_mining`, `get_max_reorg_depth`, `get_difficulty`, `get_last_block_time`, `get_last_block_duration`, `get_chain_height`, `get_max_difficulty`, `verify_and_get_achieved_difficulty` |
| `pallet_zk_tree::ZkTreeApi` | `get_root`, `get_leaf_count`, `get_depth`, `get_merkle_proof` |
| `frame_system_rpc_runtime_api::AccountNonceApi` | `account_nonce` |
| `pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi` | `query_info`, `query_fee_details`, `query_weight_to_fee`, `query_length_to_fee` |
| `pallet_transaction_payment_rpc_runtime_api::TransactionPaymentCallApi` | `query_call_info`, `query_call_fee_details`, `query_weight_to_fee`, `query_length_to_fee` |
| `sp_genesis_builder::GenesisBuilder` | `build_state`, `get_preset`, `preset_names` |
| `frame_benchmarking::Benchmark` | `benchmark_metadata`, `dispatch_benchmark` *(only `runtime-benchmarks`)* |
| `frame_try_runtime::TryRuntime` | `on_runtime_upgrade`, `execute_block` *(only `try-runtime`)* |

---

## 5. Transaction extensions (`TxExtension` in `lib.rs`)

Signed-extension pipeline applied to every extrinsic, in order.
`WormholeProofRecorderExtension` was position 9 until M6 removed it with
`pallet-wormhole`; dropping it is what changed the signed extrinsic encoding and
moved `transaction_version` to 7.

1. `frame_system::CheckNonZeroSender`
2. `frame_system::CheckSpecVersion`
3. `frame_system::CheckTxVersion`
4. `frame_system::CheckGenesis`
5. `frame_system::CheckEra`
6. `frame_system::CheckNonce`
7. `frame_system::CheckWeight`
8. `transaction_extensions::ReversibleTransactionExtension` - **custom**: blocks non-whitelisted calls from high-security accounts, and rejects a high-security signer that has already included 16 extrinsics in the rolling 24h window (`HighSecurityTxQuota`: ring of 16 block numbers, O(1) update).
9. `pallet_transaction_payment::ChargeTransactionPayment` - **stock**. The high-security zero-tip policy is not on this extension: it is enforced by `transaction_extensions::HighSecurityFungibleAdapter`, the configured `OnChargeTransaction`, which sees both the signer and the tip on every fee path (`can_withdraw_fee` during mempool and consensus validation, `withdraw_fee` at inclusion) and rejects any non-zero tip from a high-security signer - so no refactor of the extension tuple can silently reopen the tip channel.
10. `frame_metadata_hash_extension::CheckMetadataHash`
11. `frame_system::WeightReclaim` - re-runs the block-weight reclaim so refunds made by earlier extensions (which `CheckWeight`'s own reclaim runs too early to see) are returned to block capacity.

The high-security whitelist (`HighSecurityConfig::is_whitelisted`, extension 8) admits `ReversibleTransfers::{schedule_transfer, cancel, recover_funds}` and a flat `Utility::batch_all` of 1..=`MaxHighSecurityBatchLen` (16, deliberately decoupled from `MaxPendingPerAccount`) of those leaf calls. Nested or empty batches are rejected so a packed wrapper cannot inflate the inclusion fee. `schedule_transfer` is admitted only when `dest` is `MultiAddress::Id` - other `MultiAddress` variants (in particular unbounded `Raw`) are rejected so a stolen key cannot inflate the length fee. `Vesting::claim` is permissionless (any signer, payout always to the stored beneficiary), so a high-security account does not need it on the list. Beyond the shape rules, extension 8 enforces two blanket bounds on every high-security extrinsic: at most `MAX_HIGH_SECURITY_EXTRINSIC_LEN` (10 KiB) encoded bytes, and a zero-tip inclusion fee of at most `MAX_HIGH_SECURITY_INCLUSION_FEE` (`FEE_SCALE` UNIT - scaled in lockstep with the fees it bounds, ~10x the costliest legitimate call) - so a future whitelisted call with an unforeseen length or weight surface cannot reopen the fee-drain channel. Combined with the 16-per-day quota, the worst-case drain from a stolen key is 16 × `FEE_SCALE` UNIT per rolling day, and the *balance* is untouchable because every call on the list is delayed and both `cancel` and `recover_funds` beat the delay. `Shielded::shield` and `Balances::burn` are deliberately off the list for that reason: both are immediate, both are irreversible, and `recover_funds` walks `PendingTransfersBySender` and releases holds, so neither would leave the guardian anything to recover. Under v1 nothing enrols an account anyway: `QneroCallFilter` refuses `set_high_security` and no non-benchmark preset seeds `HighSecurityAccounts`. An account enrolled before v1 can therefore sign nothing at all, which is the documented cost of keeping the guarantee whole (`runtime/tests/call_filter.rs::the_high_security_whitelist_admits_only_reversible_calls`). The quota keys on the outer signer, so a single-key high-security guardian shares it with its own traffic and can be locked out of `cancel`/`recover_funds` for up to a day - a documented limitation; the recommended multisig guardian is immune because the derived address never signs extrinsics (its signers do), even when the multisig itself is enrolled as high-security.

---

## 6. Governance definitions (`governance/definitions.rs`)

- `PreimageDeposit` - custom `Consideration` fee model for preimages.
- `TechCollectiveTracksInfo` - tech-collective referenda; track 0 for Root proposals (10 × `FEE_SCALE` UNIT deposit, 61% approval / 60% support constant curves, 1-day decision/confirm/enactment) and track 1 `fast_upgrade` for `FastUpgrade` proposals (10 × `FEE_SCALE` UNIT deposit, 80%/80% constant curves = 8-of-10 at genesis, 10-minute prepare/confirm/enactment - the runtime-upgrade lane, see `docs/RUNTIME_UPGRADE_VIA_GOVERNANCE.md`).
- `MinRankOfClassConverter`, `GlobalMaxMembers` - rank/membership converters.
- `RootOrMemberForTechReferendaOrigin` - custom origin for TechReferenda submission (Root or ranked-collective member).
- `governance/origins.rs` (`pallet_custom_origins`, runtime index 23 as `Origins`) - storage-less origin declarations; `Origin::FastUpgrade` is dispatched by approved fast-track referenda and honored only by `system.authorize_upgrade` (`AuthorizeUpgradeOrigin = Root or FastUpgrade` in the forked frame-system).
- `apply_test_timing` - compiled only under `fast-governance` (collapses all timing windows to 2 blocks for CI).

---

## 7. Genesis presets (`genesis_config_presets/`)

- **Presets:** `dev` (`DEV_RUNTIME_PRESET`), `heisenberg`, `planck`, `mainnet` (`MAINNET_RUNTIME_PRESET`, gated on `mainnet_vesting::FINALIZED`).
- **Network roles:**
  - `dev` - local development.
  - `heisenberg` - **internal integration testnet**, not mainnet. Tokens have no monetary value; the network may be reset.
  - `planck` - public testnet (live treasury signers + faucet).
  - `mainnet` - production genesis. Allocation is `runtime/src/genesis_config_presets/mainnet_vesting.rs`: **2% of `MAX_SUPPLY` (420_000) at TGE, and it is a placeholder.** `VESTING` is one row of `(account, amount, start day, end day)`: 419_940 QNR to `PLACEHOLDER`, locked until day 365 then linear to day 1460. `SEED` (3 QNR) is endowed as free balance to each of the 10 `TREASURERS` and 10 `TECH_COLLECTIVE` members so they can act from block 1; the two lists are distinct. `sum(VESTING) + 20 × SEED == GENESIS_ALLOCATION` is a compile-time assertion; the pot's ED is the only issuance outside it. The treasury is the 6-of-10 multisig derived from `TREASURERS` and holds no genesis balance and no schedule. Vesting clocks are offsets from the first non-zero timestamp. The preset panics until `FINALIZED` is flipped. The inherited 27% across 48 rows was removed on 2026-09-14: `docs/DESIGN.md` sections 7.1 and 7.3 carry the decision and the pre-mainnet check, and `PLACEHOLDER` is replaced or the row deleted before any mainnet genesis.
- **Vesting genesis:** every preset endows the vesting pot with `Σ schedule totals + ED` (ED alone when the table is empty, as on `planck`). The pot is keyless, so `Vesting::claim` is the only call that moves its balance, and v1's call filter leaves that one call dispatchable for exactly that reason. `dev`/`heisenberg` seed the same example schedules (one account with two schedules). `mainnet` uses the `VESTING` table in `mainnet_vesting.rs` (address, amount, start day, end day; no personal names). Times are offsets from the first non-zero timestamp (`anchor_to_first_timestamp`); the genesis block timestamp is 0 and is not used. Every row has `start == cliff`, so nothing unlocks as a lump.
- Dilithium well-known accounts: `crystal_alice`, `dilithium_bob`, `crystal_charlie` (public seeds `[0]` / `[1]` / `[2]`). Used by `dev` and **intentionally also by `heisenberg`** so integrators and CI can exercise governance, treasury, and transfer flows without distributing secrets. Those private keys are public by design; do **not** reuse this pattern on a mainnet or any value-bearing chain (Planck already uses distinct live treasury signers).
- Treasury = 2-of-3 multisig of the three signers for `dev`/`heisenberg`, 6-of-10 of `TREASURERS` for `mainnet`; no liquid treasury genesis balance (the mainnet treasury receives its share through vesting rows).
- Tech-collective seeded via the chain-spec-only `tech_collective_seed_members` JSON field (`prepare_genesis_build_input` + `seed_tech_collective`).
- Genesis balances are transparent and stay that way until their holder shields them. v1 removed `pallet-wormhole`, so nothing derives a spendable leaf from a genesis balance and no preset endows an account that cannot sign.

---

## 8. In-tree FRAME core (`frame/`)

All FRAME runtime glue compiled into the WASM is now vendored in-tree (copied from
polkadot-sdk, with `[patch.crates-io]` ensuring transitive resolution):

| Crate | Path | Role in runtime |
| --- | --- | --- |
| `frame-support-procedural-tools-derive` | `frame/support-procedural-tools-derive` | Proc-macro helper for parsing struct fields. |
| `frame-support-procedural-tools` | `frame/support-procedural-tools` | Proc-macro utilities shared by `frame-support-procedural`. |
| `frame-support-procedural` | `frame/support-procedural` | `#[pallet::…]` and `#[frame_support::runtime]` proc macros. |
| `frame-support` `45.1.0` | `frame/support` | Storage, dispatch, origins, pallet traits, runtime composition. |
| `frame-metadata` `23.0.1` | `frame/metadata` | Metadata type definitions consumed by `frame-support`. |
| `frame-executive` `45.0.1` | `frame/executive` | Block execution engine (`Executive`). |
| `frame-metadata-hash-extension` `0.13.0` | `frame/metadata-hash-extension` | `CheckMetadataHash` signed extension. |
| `frame-system-rpc-runtime-api` `40.0.0` | `frame/system-rpc-runtime-api` | `AccountNonceApi` runtime API. |
| `frame-try-runtime` `0.51.0` | `frame/try-runtime` | Try-runtime helpers *(only `try-runtime` feature)*. |
| `frame-benchmarking` `45.0.3` | `frame/benchmarking` | Benchmark harness *(only `runtime-benchmarks` feature)*. |
| `frame-system-benchmarking` `45.0.0` | `frame/system-benchmarking` | System pallet benchmarks *(only `runtime-benchmarks` feature)*. |

Related transaction-payment RPC surface (patched for WASM + node builds):

| Crate | Path | In WASM? |
| --- | --- | --- |
| `pallet-transaction-payment-rpc-runtime-api` `45.0.0` | `pallets/transaction-payment-rpc-runtime-api` | **yes** - runtime API declarations |
| `pallet-transaction-payment-rpc` `48.0.0` | `pallets/transaction-payment-rpc` | no - node RPC only; patched so the family stays in-tree |

---

## 9. Workspace primitive crates compiled into the runtime

| Crate | Path | Role in runtime |
| --- | --- | --- |
| `qp-dilithium-crypto` | `primitives/dilithium-crypto` | Post-quantum signatures; `DilithiumSignatureScheme` = the chain's `Signature`/`AccountId`. Upstream, untouched, both variants intact; the runtime refuses the ML-DSA-65 one at the entry (`runtime/src/extrinsic.rs`). |
| `qp-header` | `primitives/header` | Custom block `Header` (Poseidon block hash + Blake2 state trie); `ZkTreeRootProvider` trait. |
| `qp-high-security` | `primitives/high-security` | `HighSecurityInspector` trait shared by multisig, reversible-transfers, tx-extensions (breaks circular dep). |
| `qp-scheduler` | `primitives/scheduler` | `BlockNumberOrTimestamp`, `DispatchTime`, `ScheduleNamed` trait for delayed dispatch. |
| `qp-wormhole` | `primitives/wormhole` | `TransferProofRecorder` trait, wormhole address derivation, author extraction. The pallet is out of the runtime; this crate is not. |
| `qp-coinbase` | `primitives/coinbase` | The coinbase inherent identifier, its payload type, its error, and the `CoinbaseSink` trait. Shared by the node and `pallet-shielded` so one constant defines both sides. |
| `sp-consensus-qpow` | `primitives/consensus/qpow` | `QPoWApi` runtime API declaration, `POW_ENGINE_ID`, `Seal`. |
| `qpow-math` | `qpow-math` | Poseidon2 PoW nonce hashing & difficulty/target math used by `pallet-qpow`. |

External Quantus crates (crates.io, used by wormhole/zk-tree): `qp-plonky2`,
`qp-poseidon-core`, `qp-rusty-crystals-dilithium`, `qp-wormhole-*` (aggregator,
circuit, circuit-builder, inputs, prover, verifier), `qp-zk-circuits-common`.

**Still external (crates.io):** the `sp-*` Substrate primitives (`sp-api`,
`sp-runtime`, `sp-core`, `sp-io`, `sp-state-machine`, `sp-trie`, …), plus codec
layer crates (`parity-scale-codec`, `scale-info`, `primitive-types`,
`binary-merkle-tree`, `bounded-collections`). See `runtime/Cargo.toml` / root
`Cargo.toml` for exact versions.

> All runtime pallets, FRAME core crates, and the transaction-payment family are
> **in-tree** via workspace path deps and `[patch.crates-io]`. Client-only patches
> (`sc-cli`, `sc-network*`, `sc-informant`, `litep2p`) are not compiled into
> the runtime WASM.

---

## 10. Cargo features affecting the compiled runtime (`runtime/Cargo.toml`)

| Feature | Effect on compiled runtime |
| --- | --- |
| `default = ["std"]` | Native build; enables `std` across all deps + `substrate-wasm-builder`. WASM build is `no_std`. |
| `runtime-benchmarks` | Compiles `benchmarks.rs`, benchmark `Config` impls, and `Benchmark` API; adds benchmark-only genesis (reversible-transfers HS account). |
| `try-runtime` | Compiles `TryRuntime` API and migration checks. |
| `metadata-hash` | Enables `CheckMetadataHash` metadata generation (double WASM compile). |
| `fast-governance` | **Test/CI only.** Collapses every referenda timing window to 2 blocks (`apply_test_timing`). Must be OFF for production. |
| `on-chain-release-build` | `metadata-hash` + `sp-api/disable-logging` for release WASM. |

---

## 11. Lifecycle hooks (per-block execution surface)

| Pallet | Hooks implemented |
| --- | --- |
| `frame-system` (local) | `integrity_test` |
| `QPoW` | `on_initialize`, `on_finalize` (difficulty + block timing) |
| `MiningRewards` | `integrity_test`, `on_initialize`, `on_finalize` (emission + collected fees handed to the coinbase sink) |
| `Scheduler` (local) | `on_initialize` (executes due agenda items) |
| `ZkTree` | `on_finalize` (commit merkle root) |
| `ReversibleTransfers` | `integrity_test` |
| `Shielded` | `integrity_test`, `on_initialize` (kill a stale coinbase payload), `on_finalize` (mint the block's coinbase note) |

Plus the upstream pallets' own hooks, all driven through
`Executive` over `AllPalletsWithSystem`.
