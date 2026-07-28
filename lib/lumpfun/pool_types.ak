// ══════════════════════════════════════════════════════════════════════════════
// LumpFun v3 — pool datum & redeemer
//
// TWO states, and the transition between them is one-way:
//
//   • Bootstrap — the virtual-reserve bonding curve. `Buy` / `Sell`.
//   • Amm       — LumpFun's OWN permanent constant-product pool, offset 0 on
//                 BOTH sides. `AmmBuy` / `AmmSell`, forever.
//
// `Graduate` flips Bootstrap -> Amm IN PLACE. Nothing is drained, nothing is
// destroyed, no foreign venue is involved.
//
// ── WHY v3's FLIP HAS NO PRICE GAP AND v2's DOES ─────────────────────────────
// v2 flips the same flag and sets its ADA offset to 0
// (contracts/cardano/validators/lump_pool.ak:176-181), which divides the price by
// exactly `s = sqrt(m)`:
//
//     close = (A + V)/T      open = A/T      open/close = A/(A+V) = (s-1)/s
//
// because v2's calibration gives `A = V·(s-1)`. m = 64 -> −12.50%; m = 8 ->
// −35.36%. v3 removes it with the PRE-ALLOCATED POOL BAG instead of with a
// second offset: at curve close the pool's REAL balances are already
// `(A, pool_bag_v3)`, and `A / pool_bag_v3` IS the curve's closing price to
// within a few parts in 1e10. See `math_v3.amm_open_price_matches_the_curve_close`
// for the exact-integer statement and the exact residual — it is NOT bit-exact and
// the tests say so rather than claiming 0.
//
// So the Amm side needs NO offset machinery at all: `mode_offset` does not exist
// in v3, and the only thing `mode` selects is WHICH value invariant and WHICH
// quote function apply.
// ══════════════════════════════════════════════════════════════════════════════

use aiken/builtin
use aiken/collection/list
use lumpfun/params_v3.{pool_bag_v3}

/// Reserved asset name for the pool-authenticity NFT. Unchanged from v2 — the
/// CIP-68 label-100 prefix (0x000643b0) keeps it from colliding with any
/// user-chosen ticker and stops wallets rendering it as tradable.
///
/// Minted 1-of-1 by the SAME one-shot policy as the curve token, and required to
/// be present in the pool UTxO on every spend. Without it a "pool" is recognised
/// only by sitting at the pool address and holding the curve token — and anyone
/// can park a self-consistent decoy there (2 ADA + 1 token, datum to match) that
/// satisfies every arithmetic check while a buyer routed to it pays real ADA for
/// nothing, with `min_out` useless because it was quoted from the decoy.
///
/// This matters MORE in v3 than it did in v2: v3's pool is UNPARAMETERISED, so
/// every LumpFun token in the cohort shares one address and decoys cost nothing
/// to create. The NFT is the only thing separating the real pool from the noise.
///
/// ── AND IT IS NOW NEVER BURNED. ──────────────────────────────────────────────
/// `lump_mint_v3` has no `Retire` redeemer: graduation is an in-place flip, so
/// the NFT authenticates the pool for the life of the token. That makes the
/// policy Launch-only and supply provably immutable at `total_supply_v3` for
/// life — see the C-1 banner in `minting_policy.ak`.
pub const pool_nft_name: ByteArray = #"000643b0504f4f4c"

/// Which half of the pool's life this UTxO is in. Nullary constructors, so on the
/// wire `Bootstrap` is `Constr(0, [])` and `Amm` is `Constr(1, [])` —
/// pinned by `pool_mode_wire_shape` below.
///
/// THE TRANSITION IS ONE-WAY AND HAPPENS EXACTLY ONCE. `with_reserves` freezes
/// this field on every trade branch, and `with_graduation` — the ONLY helper that
/// may change it — hardcodes the target as `Amm`. Combined with `validate_graduate`'s
/// `mode == Bootstrap` precondition on the INPUT, `Amm -> Bootstrap` is
/// unconstructible and a graduated pool can never re-graduate.
pub type PoolMode {
  Bootstrap
  Amm
}

/// Inline datum on every v3 pool UTxO.
///
/// ── CONSTRUCTOR INDEX ────────────────────────────────────────────────────────
/// `PoolDatumV3` is at constructor index **1**, not 0. Index 0 is occupied by a
/// nullary `ReservedV2Slot` that is never constructed and can never appear
/// on-chain. Measured wire forms (`aiken/cbor.diagnostic`, this toolchain):
///
///     v3 PoolDatumV3    122([_ h'…', h'…', 1000000000, …])   tag 1, arity 11
///     v2 PoolDatum      121([_ 1000, 2000, 121([])])         tag 0, arity  3
///     ReservedV2Slot    121([])                              tag 0, arity  0
///
/// ── WHAT ACTUALLY PREVENTS THE v2/v3 COLLISION, AND WHAT DOES NOT ────────────
/// THE BELT is Aiken v1.1.17's soft-cast, which checks constructor tag AND arity
/// exactly: a real v2 `Constr(0, [Int, Int, Constr(0,[])])` is rejected by
/// `expect d: PoolDatum` on both counts. That is verified, and it is the only
/// enforcement that actually bites today.
///
/// THE BRACES is this distinct tag — but an earlier version of this comment
/// claimed it makes the collision "structurally impossible" for the reader named
/// in plan §8.1, and THAT IS FALSE. `web/src/lib/cardano-tx.ts:663` and `:754`
/// compute `const isV2 = chainConstr.fields.length >= 3` and NEVER read the
/// constructor index. A v3 datum has ELEVEN fields, `11 >= 3` is true, so the
/// deployed reader classifies a v3 datum as v2 and reads fields[0]/fields[1] —
/// `policy_id` and `asset_name`, both ByteArrays — as the reserves.
///
/// §8.1 STAGE 1 IS THEREFORE STILL MANDATORY. Phase 2 must discriminate on
/// `constr.index === 1` for v3 and `index === 0 && fields.length === 3` for v2,
/// never on field count alone. (Checked and clean: the dangerous direction is
/// avoided — `pool-v2.ts:111`'s `if (!isV2) return;` fail-open triggers only when
/// `isV2` is false, so with 11 fields the pool-NFT authenticity guard stays ARMED
/// against v3 datums. That is the benign half of the collision, not the silent
/// one.)
///
/// ── ██ AND `mode` MOVED TOO: v2 READS IT AT fields[2], v3 CARRIES IT AT fields[10]. ██
/// The paragraph above covers the RESERVES half only, and that is not enough — fixing
/// the reserves and leaving the mode line alone produces a reader that is CORRECT
/// about the numbers and PERMANENTLY WRONG about the state. The very next line of the
/// deployed reader (`cardano-tx.ts:666` and `:757`) is
///
///     mode = isV2 && (chainConstr.fields[2] as Constr<Data>).index === 1
///              ? 'Amm' : 'Bootstrap'
///
/// In v3, field index 2 is `ada_reserve` — an Int. `(bigint as Constr).index` is
/// `undefined`, `undefined === 1` is false, so EVERY v3 pool reads as `Bootstrap`
/// FOREVER, graduated or not. The consequence is that a graduated v3 token is
/// untradeable through any tooling derived from the v2 reader: the quoter calls
/// `quoteBuyForMode(..., 'Bootstrap')`, builds a `Buy` redeemer, and
/// `validate_buy`'s `mode == Bootstrap` guard rejects it. Fail-closed, so no funds
/// are lost — but every buy and every sell on the AMM half of a token's life, where
/// most lifetime volume is, dies with an opaque script error immediately after the
/// one irreversible transition, and there is NO on-chain symptom to diagnose from.
///
/// Note the irony and do not "fix" it by moving the field: appending `mode` last is
/// the RIGHT choice (see the field-ordering note below) and it is precisely what makes
/// the v2 mode line silently wrong rather than loudly wrong.
///
/// SO A READER MUST SWITCH BOTH INDICES TOGETHER. The v3 reader must assert
/// `constr.index === 1 && constr.fields.length === 11`, then read `mode` from
/// `fields[10]`, and THROW rather than default if `fields[10]` is not a Constr of
/// index 0 or 1. A default-to-`Bootstrap` fallback is exactly what turns this into a
/// silent failure instead of a loud one.
///
/// ReservedV2Slot is never constructed and Aiken emits no dead-code warning for
/// it, so "remove the unused constructor" is a plausible future cleanup that
/// would silently move every v3 datum to index 0 and collide with v2 on the wire.
/// `v3_datum_wire_shape_is_constr_one_with_eleven_fields` below is the only test
/// in the project that fails if that happens — every other test builds and reads
/// `PoolDatumV3` symmetrically and would stay green.
///
/// ── `mode` IS APPENDED, NOT INSERTED. ────────────────────────────────────────
/// It is the LAST field (position 10) so that positions 0..9 keep the meanings
/// every off-chain reader already assigns them. §8.1's stage-1 reader work is
/// index-based; inserting `mode` next to the reserves, where it reads better,
/// would silently shift `creator_pkh`…`royalty_pub_key` by one and turn a
/// field-count bug into a field-MEANING bug. Appending is the boring choice and
/// it is the right one.
///
/// ── WHAT `token_reserve` MEANS — AND THAT IT DEPENDS ON `mode` ───────────────
/// In `Bootstrap`, `token_reserve` is the VIRTUAL reserve `X_c − sold`; the real
/// balance is `token_reserve − token_offset_v3`, and `ada_reserve` EXCLUDES
/// `pool_floor_v3`:
///
///     lovelace_of(value) == ada_reserve + pool_floor_v3
///     quantity_of(value, policy_id, asset_name) == token_reserve − token_offset_v3
///
/// In `Amm` BOTH offsets are ZERO — that is the entire content of the flip:
///
///     lovelace_of(value) == ada_reserve
///     quantity_of(value, policy_id, asset_name) == token_reserve
///
/// `Graduate` is where the two conventions meet: `ada_reserve` is UNCHANGED (the
/// `pool_floor_v3` that was sitting beside it leaves as the submitter's bounty)
/// and `token_reserve` is REBASED from `curve_exhausted_token_reserve` (virtual)
/// to `pool_bag_v3` (real). Both are compile-time constants, so the rebase is an
/// exact equality and not a computation — see `with_graduation`.
///
/// ── WHY THE CONFIG FIELDS ARE HERE ───────────────────────────────────────────
/// v2 carried `policy_id`, `asset_name`, `creator_fee_bps`, `treasury_pkh`,
/// `creator_pkh` and `graduation_ada` as SCRIPT PARAMETERS, so they were baked
/// into the pool's script hash and therefore its address. v3's pool is
/// unparameterised (§5.6) — one shared reference script and one curve address
/// for every LumpFun token, which is what lets `lump_mint_v3` pin the pool
/// ADDRESS and close the circular-dependency hole recorded at
/// contracts/cardano/validators/minting_policy.ak:72-76.
///
/// The cost, accepted deliberately: these facts move from "baked into the hash"
/// to "pinned in the datum at genesis and preserved on every spend". Equally
/// immutable, differently proven — and the proof is `with_reserves` /
/// `with_graduation` below, which EVERY branch must run. Skip it on one branch and
/// a 10 ADA trade can rewrite `royalty_pub_key` and capture the creator's
/// perpetual royalty (R-5, Critical).
pub type PoolDatum {
  /// Constructor index 0 — RESERVED, NEVER CONSTRUCTED, NEVER VALID ON-CHAIN.
  /// It exists only to push `PoolDatumV3` to index 1 so v3 datums are
  /// distinguishable from v2's index-0 `PoolDatum` by tag alone. Do not give it
  /// fields and do not build it.
  ReservedV2Slot
  /// Constructor index 1 — the live v3 pool datum.
  PoolDatumV3 {
    /// One-shot policy id of BOTH the curve token and the pool NFT. 28 bytes,
    /// asserted at launch. Read from the datum because the pool is
    /// unparameterised; pinned to the minting policy's own id by `pool_seeded`,
    /// and frozen thereafter by `with_reserves` / `with_graduation`.
    policy_id: ByteArray,
    /// Curve token asset name.
    asset_name: ByteArray,
    /// MUTABLE. ADA reserve in lovelace. In `Bootstrap` it EXCLUDES
    /// `pool_floor_v3`; in `Amm` it is the pool's whole lovelace balance.
    ada_reserve: Int,
    /// MUTABLE. In `Bootstrap`, the VIRTUAL token reserve `X_c − sold` (real
    /// balance is this minus `token_offset_v3`). In `Amm`, the REAL token
    /// balance.
    token_reserve: Int,
    /// Creator's payment key hash — receives the perpetual rev-share on BOTH
    /// halves of the pool's life, and is the identity shown in the UI. 28 bytes,
    /// asserted at launch.
    creator_pkh: ByteArray,
    /// LumpFun treasury payment key hash. 28 bytes, asserted at launch, and
    /// asserted DISTINCT from `creator_pkh` so one output cannot satisfy both
    /// existential fee checks at once.
    treasury_pkh: ByteArray,
    /// Creator rev-share in bps. Pinned to `creator_fee_bps_v3` at launch.
    creator_fee_bps: Int,
    /// Platform rev-share in bps. Pinned to `platform_fee_bps_v3` at launch —
    /// §5.6's "the platform fee becomes a per-pool datum fact pinned at genesis
    /// and preserved on every spend". If it were free-form, a creator building
    /// their own launch tx would set it to 0.
    platform_fee_bps: Int,
    /// Flat platform fee in lovelace. Pinned to `platform_fee_flat_v3`.
    platform_fee_flat: Int,
    /// The creator's raw ed25519 public key, EXACTLY 32 bytes — asserted at
    /// LAUNCH by `lump_mint_v3`.
    ///
    /// ── IT HAS NO ON-CHAIN CONSUMER SINCE SPLASH WAS PARKED. IT STAYS. ───────
    /// It existed to become field 13 (`royaltyPubKey`) of a Splash royaltyPool
    /// datum. That path is parked (2026-07-26) and LumpFun's own Amm does not read
    /// this field, so today it is an inert, immutable, creator-owned commitment.
    ///
    /// Keeping it is deliberate and it is NOT free-riding on inertia:
    ///   • It is part of the datum SHAPE. Dropping it is a wire-format change to
    ///     every reader plus both script hashes, for zero on-chain benefit.
    ///   • "Pinned at genesis and immutable for life" is a property that CANNOT be
    ///     retrofitted. If any future rail — a royalty registry, an off-chain
    ///     attestation, a second venue — needs a key the creator committed to
    ///     BEFORE their token had a price, the only way to have one is to have
    ///     kept this field. Re-adding it later gives a key chosen after the fact.
    ///   • The 32-byte assert at launch costs one comparison and turns a silent
    ///     downstream drop into a failed launch.
    /// See the report in the Phase-3 build notes; the recommendation was KEEP.
    royalty_pub_key: ByteArray,
    /// Which half of the pool's life this is. `Bootstrap` at genesis, flipped to
    /// `Amm` exactly once by `Graduate`, and then frozen forever.
    ///
    /// APPENDED LAST on purpose — see the note on field ordering above.
    mode: PoolMode,
  }
}

/// v3 pool redeemer. Five branches, and that is the whole surface.
///
/// The two halves are MUTUALLY EXCLUSIVE and each rejects the other's mode:
/// `Buy`/`Sell` require `Bootstrap`, `AmmBuy`/`AmmSell` require `Amm`. Four
/// cross-mode reject tests bind that in `lump_pool.ak`.
///
/// ══════════════════════════════════════════════════════════════════════════════
/// THERE IS DELIBERATELY NO WITHDRAW / REMOVE-LIQUIDITY REDEEMER.
/// ══════════════════════════════════════════════════════════════════════════════
/// The graduated pool's liquidity is LOCKED FOR LIFE, exactly as v2 documents at
/// contracts/cardano/validators/lump_pool.ak:25-28 ("There is deliberately NO
/// withdraw redeemer, so the liquidity is locked for life (rug-proof)"). There are
/// no LP tokens to hold, no admin key, no timelock, and no migration branch: the
/// ONLY ways lovelace leaves an `Amm` pool are `AmmSell` at the pool's own price,
/// and the fee outputs, which are surcharges paid by the trader and never come out
/// of the reserve. DO NOT ADD ONE.
pub type PoolRedeemer {
  /// BOOTSTRAP. ADA in, tokens out on the virtual-reserve curve. `min_out` =
  /// token slippage floor.
  Buy { min_out: Int }
  /// BOOTSTRAP. Tokens in, ADA out. `min_out` = NET-ADA slippage floor (after
  /// both fees).
  Sell { min_out: Int }
  /// The one-way flip. Bootstrap -> Amm IN PLACE: `ada_reserve` unchanged,
  /// `token_reserve` rebased from virtual to real, `pool_floor_v3` released to
  /// the submitter as the permissionless bounty. NO witness field — v3's
  /// graduation has nothing to guess and nothing to check a guess against.
  Graduate
  /// AMM. ADA in, tokens out on the REAL reserves, offset 0 both sides.
  AmmBuy { min_out: Int }
  /// AMM. Tokens in, ADA out on the REAL reserves. `min_out` = NET ADA.
  AmmSell { min_out: Int }
}

/// ══════════════════════════════════════════════════════════════════════════════
/// R-5 (Critical) — whole-datum reconstruction, HALF ONE OF TWO.
/// ══════════════════════════════════════════════════════════════════════════════
///
/// Returns `d` with ONLY the two mutable reserve fields replaced. `mode` is
/// FROZEN, alongside every config field. Every TRADE branch — `Buy`, `Sell`,
/// `AmmBuy`, `AmmSell` — must assert `with_reserves(d, new_ada, new_tok) == new_d`,
/// which is the ONLY thing standing between an attacker's 10 ADA trade and a
/// rewritten `royalty_pub_key`, `creator_pkh`, `treasury_pkh` or fee schedule in
/// the continuation datum. v2 never needed it because those facts were script
/// parameters; v3's unparameterised pool makes it MANDATORY (§5.6: "if it is
/// skipped, keep the pool parameterised instead").
///
/// FREEZING `mode` HERE IS WHAT MAKES THE FLIP ONE-WAY. Without it, an `AmmSell`
/// of 10 ADA could set `mode` back to `Bootstrap` — at which point the pool is
/// priced by the curve again while holding `pool_bag_v3` real tokens against a
/// `token_reserve` the curve reads as virtual, and the whole `token_offset_v3`
/// substitution is off by 142,857,143 tokens in the attacker's favour.
///
/// Note the construction is EXPLICIT rather than a `{ ..d, … }` spread. That is
/// not merely a style choice — Aiken v1.1.17 FORBIDS record-update syntax on
/// multi-constructor types, so a spread is not available at all. The consequence
/// is the one we want: adding a field to `PoolDatumV3` makes this function fail to
/// COMPILE, forcing whoever adds it to decide whether it is mutable. That is
/// exactly how `mode` came to be a deliberate decision rather than a default.
pub fn with_reserves(
  d: PoolDatum,
  ada_reserve: Int,
  token_reserve: Int,
) -> PoolDatum {
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    royalty_pub_key,
    mode,
    ..
  } = d
  PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve,
    token_reserve,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    royalty_pub_key,
    mode,
  }
}

/// ══════════════════════════════════════════════════════════════════════════════
/// R-5, HALF TWO OF TWO — the ONE-WAY FLIP, and the ONLY helper that moves `mode`.
/// ══════════════════════════════════════════════════════════════════════════════
///
/// `Graduate` alone uses this. It permits exactly two changes and freezes the
/// other nine fields:
///
///   mode          -> `Amm`, HARDCODED. Not read from `d`, not read from the
///                    continuation. There is no expression here that can produce
///                    `Bootstrap`, so `Amm -> Bootstrap` cannot be expressed by
///                    the only function allowed to write the field.
///   token_reserve -> `pool_bag_v3`, HARDCODED. The rebase from the VIRTUAL
///                    `curve_exhausted_token_reserve` (404,061,018) to the REAL
///                    `pool_bag_v3` (261,203,875), because `Amm` runs at offset 0
///                    on the token side too. Both are compile-time constants, so
///                    this is an exact equality and not a computation.
///                    `params_exhausted_real_balance_is_pool_bag` is the identity
///                    that makes the rebase a no-op on the pool's REAL balance:
///                    404,061,018 − 142,857,143 == 261,203,875, so the flip does
///                    not move a single token, it only stops lying about them.
///   ada_reserve      CARRIED THROUGH UNCHANGED. The `pool_floor_v3` that sat
///                    beside it in the value is what leaves as the bounty.
///
/// ── WHAT THIS FUNCTION DOES *NOT* DO ────────────────────────────────────────
/// It does not check the INPUT's mode. `with_graduation(already_graduated_pool)`
/// equals that pool's own datum, so this equality ALONE would let a graduated pool
/// be "re-graduated" and release a second `pool_floor_v3` bounty out of the Amm's
/// reserve. `validate_graduate` asserts `mode == Bootstrap` on the input
/// separately, and `graduate_rejects_regraduating_an_amm_pool` is the test that
/// isolates it. Two independent guards, stated because the redundancy is not
/// redundancy: they cover different halves of monotonicity.
pub fn with_graduation(d: PoolDatum) -> PoolDatum {
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    royalty_pub_key,
    ..
  } = d
  PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve,
    token_reserve: pool_bag_v3,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    royalty_pub_key,
    mode: Amm,
  }
}

/// The two mutable fields, for callers that only need those.
pub fn reserves_of(d: PoolDatum) -> (Int, Int) {
  expect PoolDatumV3 { ada_reserve, token_reserve, .. } = d
  (ada_reserve, token_reserve)
}

/// `d`'s mode, for callers that only need that.
pub fn mode_of(d: PoolDatum) -> PoolMode {
  expect PoolDatumV3 { mode, .. } = d
  mode
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A canonical Bootstrap datum for the shape tests below.
fn wire_datum(mode: PoolMode) -> PoolDatum {
  PoolDatumV3 {
    policy_id: #"a0a0a0a0",
    asset_name: #"4c554d50",
    ada_reserve: 1_000_000_000,
    token_reserve: 1_030_181_086,
    creator_pkh: #"c0c0c0c0",
    treasury_pkh: #"b0b0b0b0",
    creator_fee_bps: 80,
    platform_fee_bps: 50,
    platform_fee_flat: 500_000,
    royalty_pub_key: #"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
    mode,
  }
}

/// THE CONSTRUCTOR INDEX AND ARITY, PINNED ON THE WIRE.
///
/// This module had no tests at all, and the v3/v2 tag separation — which plan
/// §8.1 requires and which `ReservedV2Slot` exists solely to produce — was
/// asserted by nothing anywhere in the project. Deleting `ReservedV2Slot` as dead
/// code moves `PoolDatumV3` to `Constr(0, [11 fields])`, tag-identical to v2, and
/// the entire rest of the suite stays green because every other test builds and
/// reads the datum symmetrically.
///
/// The ARITY half went 10 -> 11 when `mode` was added. It is not decoration: a
/// v3.0 datum (10 fields, no mode) and a v3.1 datum (11 fields) would BOTH
/// soft-cast if the arity were unpinned in either direction, and a 10-field datum
/// read as 11 is a `mode` field read out of a field that does not exist. Aiken's
/// soft-cast checks arity exactly, so the enforcement is real; this test is what
/// stops the EXPECTED arity drifting silently.
///
/// This test reads the ACTUAL encoded form, so it is the tripwire.
test v3_datum_wire_shape_is_constr_one_with_eleven_fields() {
  let raw: Data = wire_datum(Bootstrap)
  let p = builtin.un_constr_data(raw)
  p.1st == 1 && list.length(p.2nd) == 11
}

/// …and the Amm form is the SAME shape. `mode` changing must not change the tag
/// or the arity, or a graduated pool stops being readable by the same decoder.
test v3_amm_datum_has_the_identical_wire_shape() {
  let raw: Data = wire_datum(Amm)
  let p = builtin.un_constr_data(raw)
  p.1st == 1 && list.length(p.2nd) == 11
}

/// `PoolMode` on the wire: two nullary constructors, `Bootstrap` at 0 and `Amm`
/// at 1. Pinned because the field is a one-way latch and a silent reordering
/// would make every already-deployed Bootstrap pool decode as graduated.
test pool_mode_wire_shape() {
  let b: Data = Bootstrap
  let a: Data = Amm
  let pb = builtin.un_constr_data(b)
  let pa = builtin.un_constr_data(a)
  and {
    pb.1st == 0,
    list.length(pb.2nd) == 0,
    pa.1st == 1,
    list.length(pa.2nd) == 0,
  }
}

/// The reserved slot really is nullary at index 0 — the shape that keeps v3 off
/// index 0. If someone gives it fields, v3 moves and this fails.
test reserved_v2_slot_is_nullary_at_index_zero() {
  let raw: Data = ReservedV2Slot
  let p = builtin.un_constr_data(raw)
  p.1st == 0 && list.length(p.2nd) == 0
}

/// `ReservedV2Slot` DOES soft-cast to `PoolDatum` — it is a legal constructor of
/// the type, so `expect d: PoolDatum` accepts it. What stops it reaching any
/// arithmetic is the SECOND `expect PoolDatumV3` in each spend branch. Recorded
/// because "the soft-cast rejects it" is the wrong mental model and would justify
/// dropping that second expect.
test reserved_v2_slot_passes_the_pool_datum_soft_cast() {
  let raw: Data = ReservedV2Slot
  if raw is _d: PoolDatum {
    True
  } else {
    False
  }
}

// ── The two reconstruction helpers, as pure functions ────────────────────────
//
// The validator's per-field reject tests exercise these THROUGH a mock
// transaction, which is where they have to be bound (a reject must prove the
// branch refuses the tx). These direct tests bind the helpers' OWN contract, so
// a change to either one is caught even if a branch stops calling it.

/// `with_reserves` moves the two reserves and NOTHING else — `mode` included.
test with_reserves_freezes_mode_and_config() {
  let d = wire_datum(Bootstrap)
  let out = with_reserves(d, 7, 9)
  out == PoolDatumV3 {
    policy_id: #"a0a0a0a0",
    asset_name: #"4c554d50",
    ada_reserve: 7,
    token_reserve: 9,
    creator_pkh: #"c0c0c0c0",
    treasury_pkh: #"b0b0b0b0",
    creator_fee_bps: 80,
    platform_fee_bps: 50,
    platform_fee_flat: 500_000,
    royalty_pub_key: #"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
    mode: Bootstrap,
  }
}

/// …and it carries `Amm` through just as faithfully, so an AmmBuy cannot walk the
/// pool back to `Bootstrap`.
test with_reserves_carries_amm_through() {
  mode_of(with_reserves(wire_datum(Amm), 7, 9)) == Amm
}

/// `with_graduation` sets `mode` to `Amm`, rebases `token_reserve` to
/// `pool_bag_v3`, and carries `ada_reserve` UNCHANGED.
test with_graduation_flips_mode_and_rebases_the_token_reserve() {
  let d = wire_datum(Bootstrap)
  let out = with_graduation(d)
  let (a, t) = reserves_of(out)
  and {
    a == 1_000_000_000,
    t == pool_bag_v3,
    t == 261_203_875,
    mode_of(out) == Amm,
  }
}

/// The rebase target is HARDCODED, so the input's `token_reserve` is irrelevant —
/// two different curve reserves graduate to the same Amm reserve. This is what
/// makes `validate_graduate`'s G0 (`token_reserve == curve_exhausted_token_reserve`)
/// load-bearing rather than cosmetic: without it, a pool with a DIFFERENT virtual
/// reserve would still produce a well-formed `with_graduation` datum.
test with_graduation_ignores_the_input_token_reserve() {
  let a = with_graduation(wire_datum(Bootstrap))
  let b =
    with_graduation(
      PoolDatumV3 {
        policy_id: #"a0a0a0a0",
        asset_name: #"4c554d50",
        ada_reserve: 1_000_000_000,
        token_reserve: 404_061_018,
        creator_pkh: #"c0c0c0c0",
        treasury_pkh: #"b0b0b0b0",
        creator_fee_bps: 80,
        platform_fee_bps: 50,
        platform_fee_flat: 500_000,
        royalty_pub_key: #"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        mode: Bootstrap,
      },
    )
  a == b
}

/// ██ THE MONOTONICITY HOLE `with_graduation` DOES NOT CLOSE. ██
///
/// Applying it to an ALREADY-graduated pool is a fixed point, so the equality
/// `with_graduation(d) == new_d` is satisfied by a re-graduation. That is why
/// `validate_graduate` checks the input's mode separately. Asserted rather than
/// commented, so nobody deletes that check on the grounds that "the datum helper
/// already handles it".
test with_graduation_is_a_fixed_point_on_an_amm_pool() {
  let graduated = with_graduation(wire_datum(Bootstrap))
  with_graduation(graduated) == graduated
}

/// `with_graduation` freezes the config half exactly as `with_reserves` does —
/// the flip is not a licence to rewrite the fee schedule or the royalty key.
test with_graduation_freezes_the_config_half() {
  let out = with_graduation(wire_datum(Bootstrap))
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    royalty_pub_key,
    ..
  } = out
  and {
    policy_id == #"a0a0a0a0",
    asset_name == #"4c554d50",
    creator_pkh == #"c0c0c0c0",
    treasury_pkh == #"b0b0b0b0",
    creator_fee_bps == 80,
    platform_fee_bps == 50,
    platform_fee_flat == 500_000,
    royalty_pub_key == #"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
  }
}
