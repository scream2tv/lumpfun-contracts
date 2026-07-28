// ══════════════════════════════════════════════════════════════════════════════
// LumpFun v3 — curve constants
//
// AUTHORITY: docs/LUMPFUN-V3-PLAN.md §3.2. These seven numbers were derived and
// then re-verified TWICE with exact rational arithmetic in Phase 0. They are the
// best available integer roundings of the governing identities
//
//     X_c = S·s²/(s²−1)      V_c = F₀·s²/(s²−1)      C = X_c·(s−1)/s
//     P   = S − C            A   = V_c·(s−1)
//
// with S = 1e9, F₀ = 8,000 ADA, m = 8, s = √m = 2.828427…
//
// DO NOT "tidy" ANY OF THEM. Once the first v3 token launches these become
// immutable facts about deployed bytes, exactly as v1's and v2's are
// (contracts/cardano/lib/lumpfun/fees.ak:6-21 documents the same rule).
//
// A — the ADA raised at graduation, ≈16,717.048 ADA — is DELIBERATELY ABSENT.
// It is PATH-DEPENDENT and must NEVER be hardcoded anywhere.
//
// ── HOW PATH-DEPENDENT, EXACTLY ───────────────────────────────────────────────
// An earlier version of this comment said "over a range of ~64 lovelace". THAT
// IS WRONG and the error is not conservative — it understates the drift by three
// orders of magnitude. 64 lovelace is the width of the floor-division window for
// a SINGLE one-shot buy from genesis; it is NOT a bound on A across paths.
//
// A is MONOTONICALLY NON-INCREASING in the number of trades. Every Buy destroys
// `k mod new_effective` of k (up to new_effective − 1 ≈ 2.59e10 near the close),
// and the closing reserve is `k/X_c_exhausted − virtual_ada_v3`, so each buy can
// move the eventual A down by up to 64 lovelace. Measured with exact integer
// arithmetic:
//
//     one-shot maximum                     16,717,047,991   (the ceiling)
//     ~112 buys of 150 ADA                 16,717,045,621   (−2,370)
//     ~1,115 buys of 15 ADA                16,717,023,366   (−24,625)
//     1,672 buys of 10 ADA                 16,717,011,721   (−36,270 = 0.036 ADA)
//
// The ceiling is `k0 // curve_exhausted_token_reserve − virtual_ada_v3` where
// k0 = virtual_ada_v3 × virtual_token_v3, and it is pinned by
// `params_max_reachable_close_is_the_one_shot_ceiling` below. A busy token closes
// TENS OF THOUSANDS of lovelace beneath it.
//
// NEVER ASSERT A LOWER BOUND ON A ANYWHERE — not on-chain, not in the reconciler,
// not in a launch-monitor sanity check. A reconciler written against the old
// "~64 lovelace" figure false-positives on any token with a normal number of
// trades. §3.2's identity "P × close_price = A exactly" holds only to within this
// drift, and LumpFun's OWN graduated AMM therefore opens at 63.99999x rather than
// exactly 64.
//
// ── ██ ROUND TRIPS *DO* ACCUMULATE DRIFT. THE OLD CLAIM HERE WAS TOO BROAD. ██ ─
// This note used to say "grinding round trips does not accumulate drift — a full
// round-trip to genesis restores k exactly". That is true ONLY OF THE CAPPED SELL.
// `quote_sell_gross`'s cap binds only when the uncapped gross would exceed
// `ada_reserve`, which near genesis forces `new_token_reserve ≈ X_c` and hence
// k' = V·X_c = k0. A PARTIAL MID-CURVE ROUND TRIP IS UNCAPPED and each one leaves the
// pool short: measured at (16,000,000,000, 415,584,415), one 10 ADA round trip
// destroys 11,636,363,620 of k and moves the eventual A down by exactly 28 lovelace
// (the token side returns to where it started, so the A loss IS the ADA leak). Near
// the close the leak is larger — up to the 64 lovelace pinned by
// `math_v3.sell_round_trip_leak_near_the_close_is_64_lovelace`.
//
// It is not exploitable and it is not meant to be reassuring — it is a correction to
// the bound. Each round trip pays 1.26 ADA of mandatory fees to move A by 28–64
// lovelace, so 1 ADA of A costs ~19,700–45,000 ADA in fees paid to the creator and to
// LumpFun, and it moves the graduated pool's opening price in the FIRST BUYER's
// favour. See `math_v3.amm_open_price_gap_bound_from_closing_buys_only`, which is
// named for what it actually bounds.
//
// The v3 curve terminates in TOKEN space, not ADA space — that is the whole
// point of the pre-allocated pool bag (§3.1: an ADA threshold plus an overshoot
// clamp plus a minimum trade size is a permanent-freeze deadlock).
// ══════════════════════════════════════════════════════════════════════════════

use aiken/builtin

/// Genesis supply, and the supply forever. v3 has no burn, no retire of curve
/// tokens, and no mint after launch — §3.3. Every tool agrees on the supply
/// automatically because nothing ever changes it.
pub const total_supply_v3: Int = 1_000_000_000

/// V_c — the virtual ADA reserve, in lovelace.
///
/// DELIBERATELY NOT 9_142_857_143. The exact identity gives 9,142,857,142.857…;
/// rounding UP to …144 rather than to the nearer …143 makes the launch price
/// EXACTLY 8 lovelace/token, because 9_142_857_144 = 8 × 1_142_857_143. That
/// single lovelace is what turns "launch FDV ≈ 8,000 ADA" into "launch FDV is
/// 8,000.000000 ADA". DO NOT "correct" it — a reviewer who recomputes the
/// identity and sees …143 is looking at the un-rounded value, not a bug.
pub const virtual_ada_v3: Int = 9_142_857_144

/// X_c — the virtual TOKEN reserve at genesis. Greater than `total_supply_v3`:
/// the pool holds 1e9 real tokens but prices as if it held 1,142,857,143. The
/// difference is `token_offset_v3` and it is what reserves the pool bag.
pub const virtual_token_v3: Int = 1_142_857_143

/// X_c − S. The gap between the VIRTUAL token reserve carried in `PoolDatum`
/// and the REAL token balance held in the pool UTxO:
///
///     real token balance = token_reserve − token_offset_v3
///
/// This is the token-side twin of v2's `mode_offset` and it is the one
/// substitution that has to be applied everywhere a value invariant is written.
pub const token_offset_v3: Int = 142_857_143

/// C — the sellable allocation. The curve can never sell more than this, which
/// is what terminates it in token space.
pub const sellable_v3: Int = 738_796_125

/// P = S − C — the pre-allocated pool bag. Seated in the pool UTxO at genesis and
/// never sellable on the curve. Sized so that P × closing_price = A exactly, so the
/// graduated pool opens at the curve's closing price and there is NOTHING to retire
/// (§3.2).
///
/// ── IT DOES NOT GO ANYWHERE AT GRADUATION. IT STAYS EXACTLY WHERE IT IS. ─────
/// An earlier version of this comment said the bag was "handed to the Splash pool at
/// graduation". That venue is parked and, more importantly, the sentence describes
/// the OPPOSITE of what `validate_graduate` does. The flip is IN PLACE: not one token
/// moves, and the pool's real balance is `pool_bag_v3` before the flip and
/// `pool_bag_v3` after it. All that changes is that `token_reserve` stops describing
/// the bag through `token_offset_v3` (as the virtual 404,061,018) and starts naming it
/// directly (as the real 261,203,875) — see `pool_types.with_graduation`. Anyone who
/// believes the bag LEAVES will read "let the graduation pay the bag somewhere" as a
/// restoration when it is a regression.
pub const pool_bag_v3: Int = 261_203_875

/// virtual_token_v3 − sellable_v3 — the VIRTUAL token reserve at which the curve
/// is exactly exhausted. This is the v3 replacement for v2's `graduation_ada`:
///
///   • `Buy` requires  new_d.token_reserve >= curve_exhausted_token_reserve
///   • `Graduate` requires  d.token_reserve == curve_exhausted_token_reserve
///
/// At that point the pool's REAL token balance is
/// `curve_exhausted_token_reserve − token_offset_v3` = `pool_bag_v3`, which the
/// identity test below pins.
pub const curve_exhausted_token_reserve: Int = 404_061_018

/// 10 ADA seated in the pool UTxO at genesis and EXCLUDED from `ada_reserve`.
///
///     lovelace_of(pool.value) == d.ada_reserve + pool_floor_v3
///
/// Two jobs: it pays the pool UTxO's min-UTxO so `ada_reserve` can be exactly 0
/// at launch, and at graduation it becomes the submitter's bounty (§5.1) — which
/// is what makes permissionless graduation actually happen rather than merely
/// being permitted. v2 had neither: `minting_policy.ak:94` required
/// `d.ada_reserve == lovelace_of(pool.value)` and accepted ANY genesis ADA, so a
/// creator seeding 8,000 ADA doubled their own launch FDV. That is a live v2 bug
/// and v3 rejects it (see `pool_seeded`).
/// ── ██ SET TO THE LEDGER'S OWN MINIMUM. LAUNCHING IS FREE. ██ ───────────────
/// The operator's requirement is that launching a token costs nothing beyond the
/// transaction fee. This constant cannot be zero: the genesis output holds 1e9
/// curve tokens, the pool NFT and a 154-byte inline datum, and the ledger charges
/// min-UTxO on it. MEASURED at `utxoCostPerByte = 4310`:
///
///     8-byte ticker   257 output bytes -> (160 + 257) * 4310 = 1,797,270
///     32-byte ticker  307 output bytes -> (160 + 307) * 4310 = 2,012,770  (max)
///
/// 2.5 ADA clears the WORST case with ~0.49 ADA of headroom, so a launch cannot
/// become unbuildable because someone chose a long ticker. Anything at or below
/// 2 ADA is a trap: it works for short tickers and silently makes long ones
/// impossible, because `pool_seeded` demands `lovelace == pool_floor_v3` EXACTLY
/// and the ledger would refuse the output.
///
/// It is not a fee and it is not lost: it pays the pool's min-UTxO so
/// `ada_reserve` can be exactly 0 at launch, and at graduation it leaves as the
/// submitter's bounty (§5.1) — which is what makes permissionless graduation
/// actually happen rather than merely being permitted. v2 had neither:
/// `minting_policy.ak:94` required `d.ada_reserve == lovelace_of(pool.value)` and
/// accepted ANY genesis ADA, so a creator seeding 8,000 ADA doubled their own
/// launch FDV. That is a live v2 bug and v3 rejects it (see `pool_seeded`).
pub const pool_floor_v3: Int = 2_500_000

/// 1.00% to the creator on every trade, ADA-denominated. §4.1.
pub const creator_fee_bps_v3: Int = 100

/// ── ██ ZERO. THE PLATFORM FEE IS THE FLAT 2 ADA BELOW, AND NOTHING ELSE. ██ ──
/// Operator decision, 2026-07-26: the trade fee is "2 ADA flat and 1% to the
/// creator" — two fees, named. A percentage platform fee on top was neither asked
/// for nor wanted, so this is 0 rather than being quietly retained.
///
/// The field is KEPT at zero rather than deleted: it is part of `PoolDatumV3`'s
/// shape and `fee_schedule_ok` pins it on every trade, so removing it would be a
/// wire-format change to every reader plus both script hashes. Keeping it also
/// leaves a future cohort the option of a percentage rate without a datum
/// migration. `creator_fee_paid`'s `fee == 0` hatch already covers a zero fee
/// safely; `platform_fee_paid` has no hatch and does not need one, because the
/// flat component below is never zero.
pub const platform_fee_bps_v3: Int = 0

/// 2 ADA flat per trade to LumpFun. The whole platform fee. Matches what v2
/// charges, which is the number users already understand. Operator decision,
/// 2026-07-27: stays 2 ADA flat for the v3.2 cohort.
pub const platform_fee_flat_v3: Int = 2_000_000

/// ── ██ v3.2: THE LP FEE. RETAINED IN THE POOL, PAID TO NOBODY. ██ ────────────
/// Uniswap-V2-style 0.30% fee on AMM trades only, retained IN the pool
/// reserves. This pool has no LP tokens and no withdraw redeemer, so the fee is
/// not income to anyone — it is PERMANENT liquidity deepening: k strictly grows
/// with every AMM trade and slippage decays with cumulative volume, which
/// progressively heals the ÷2.393 depth step disclosed at graduation.
///
/// AMM-ONLY, deliberately. Retaining a fee during Bootstrap raises the ADA at
/// curve close to ceil(A/0.997) (+50.3 ADA) without changing the token path, so
/// the AMM would open +0.106% ABOVE the curve close — breaking the zero-gap
/// graduation calibration that is this design's headline property. Bootstrap
/// quotes are untouched (§4.2 of the v3.2 plan).
///
/// This constant is compiled into the quote functions, so changing it is a new
/// cohort — both script hashes and every future policy id move with it.
pub const amm_lp_fee_bps_v3: Int = 30

/// ══════════════════════════════════════════════════════════════════════════════
/// ██  `min_trade_ada_v3` IS DELETED. THERE IS NO MINIMUM TRADE.  ██
/// ══════════════════════════════════════════════════════════════════════════════
///
/// Operator decision, 2026-07-26: any trade size is allowed. The 2 ADA flat fee
/// makes a very small buy expensive as a PERCENTAGE, and that is the trader's
/// call to make — it is not the validator's job to refuse it.
///
/// ██ IT WAS REPLACED, NOT REMOVED. ██ The old guard was
/// `ada_in >= min_trade_ada_v3 || new_tok == curve_exhausted_token_reserve`, and
/// its note recorded that it SUBSUMED `ada_in > 0`. Deleting it outright would
/// therefore have left a zero-ADA buy structurally admissible: `quote_buy` of 0
/// returns 0 tokens, the reconstructed datum is unchanged, the value invariant
/// still holds, and the branch would ACCEPT a no-op that pays the flat fee for
/// nothing — or, on `AmmBuy`, be spammed to grief the pool UTxO. Both buy
/// branches now assert `ada_in > 0` explicitly in its place.
///
/// The CLOSING-BUY EXEMPTION disappears with the minimum, and that is safe rather
/// than merely convenient: the exemption existed only because a minimum could
/// make the final buy illegal, stranding the curve one buy short of the close.
/// With no minimum there is no such state, so the deadlock it fixed cannot arise.
///
/// The sell side never had a minimum and still does not. That asymmetry was a
/// hard-won fix, not an oversight: `quote_sell_gross` caps the gross at
/// `ada_reserve`, so the largest gross obtainable from any state is
/// `ada_reserve` itself, and a sell-side minimum dust-locked every holder out of
/// exiting once the reserve fell below it — reachable in TWO trades from genesis.
/// Do not reintroduce one.

/// ══════════════════════════════════════════════════════════════════════════════
/// ██  PINNED 2026-07-25. IMMUTABLE FOR THE v3.0 COHORT.  ██
/// ══════════════════════════════════════════════════════════════════════════════
///
/// LumpFun's treasury payment key hash, 28 bytes. This is the payment credential
/// of the mainnet operator treasury
///   addr1qx3jlr942a0udz8w3hyrs5y5zwv87y8yz552zuqz5wmy2s3mdu2v03sde5qr9mafpaz80n
///   83vaevspp7aha9a30dhffqv2jqth
/// (bech32-decoded: header 0x01, payment credential = bytes 1..29).
///
/// ROTATION IS NOT POSSIBLE WITHIN THIS COHORT. This constant is compiled into
/// both `lump_pool_v3` and `lump_mint_v3`, so changing it changes both script
/// hashes and therefore produces a NEW contract family — exactly as plan §8.5
/// requires ("the constants and derivation for a shipped pool version are frozen
/// at the moment the first token launches on it"). Tokens already launched keep
/// paying this key for life. If the key must change, publish a v3.1 cohort; do
/// not edit this line and expect existing pools to follow.
///
/// It is only ever a fee RECIPIENT — it signs nothing and it cannot spend a pool.
/// A compromise of the treasury wallet therefore misdirects future fees but
/// cannot touch any pool's reserves.
///
/// WHY THIS CONSTANT EXISTS. `treasury_pkh` is the recipient of LumpFun's entire
/// revenue stream, and it lives in the POOL DATUM because v3's pool is
/// unparameterised. Before this constant existed, `pool_seeded` constrained it
/// only to "28 bytes and != creator_pkh": `lump_mint_v3` takes just
/// (one_shot_utxo, pool_script_hash), both of which are public, so anyone could
/// apply the published policy to their own seed UTxO, launch a token that is
/// structurally indistinguishable from a LumpFun launch, and point the platform
/// fee at themselves. R-5's whole-datum reconstruction then did its job perfectly
/// and froze the ATTACKER's key for the life of the pool. That is the one place
/// where "pinned at genesis and preserved on every spend" had only its second
/// half.
///
/// It is asserted in TWO places, deliberately:
///   • `lump_mint_v3.pool_seeded` — so a genuine launch cannot name another key.
///   • `lump_pool_v3.validate_buy` / `validate_sell` — so a pool that never went
///     through the minting policy at all cannot trade at the shared v3 curve
///     address either. The pool is unparameterised and `authentic` only proves
///     "this UTxO holds the NFT its own datum names", so the minting-policy
///     assertion alone does not bind a self-seeded pool.
pub const treasury_pkh_v3: ByteArray =
  #"a32f8cb5575fc688ee8dc838509413987f10e41528a17002a3b64542"

// ── Identity tests — these pin the constants against each other ────────────────
//
// Every one of these is an ALGEBRAIC consequence of the others. If a constant is
// ever edited, at least one of these fails, which is the point.

/// X_c − S = the offset.
test params_token_offset_identity() {
  virtual_token_v3 - total_supply_v3 == token_offset_v3
}

/// P = S − C.
test params_pool_bag_identity() {
  total_supply_v3 - sellable_v3 == pool_bag_v3
}

/// The curve-exhausted VIRTUAL reserve is X_c − C.
test params_curve_exhausted_identity() {
  virtual_token_v3 - sellable_v3 == curve_exhausted_token_reserve
}

/// …and the REAL balance left in the pool at that moment is exactly the pool
/// bag. This is the load-bearing one: it is why the flip can REBASE `token_reserve`
/// from 404,061,018 to `pool_bag_v3` without moving a single token, and why there is
/// no surplus to retire. (It formerly read "why graduation hands Splash the pool
/// bag" — nothing is handed anywhere; see the note on `pool_bag_v3`.)
test params_exhausted_real_balance_is_pool_bag() {
  curve_exhausted_token_reserve - token_offset_v3 == pool_bag_v3
}

/// Launch price is EXACTLY 8 lovelace/token — the reason virtual_ada_v3 ends
/// in 4 and not 3. 8 × 1,142,857,143 = 9,142,857,144.
test params_launch_price_is_exactly_eight() {
  virtual_ada_v3 == 8 * virtual_token_v3
}

/// Launch FDV is exactly 8,000 ADA.
///
/// DERIVED, not asserted about literals. The previous version of this test read
/// `8 * total_supply_v3 == 8_000_000_000`, which mentions neither
/// `virtual_ada_v3` nor `virtual_token_v3` and therefore could not detect a wrong
/// launch price at all — it was a fact about two literals that would have stayed
/// green through any curve retune. The launch price is
/// `virtual_ada_v3 / virtual_token_v3`, so FDV is that times the supply, and this
/// form fails if any of the three constants moves.
test params_launch_fdv_is_exactly_8000_ada() {
  virtual_ada_v3 * total_supply_v3 / virtual_token_v3 == 8_000_000_000
}

/// The 28-byte length the two datum-integrity assertions rely on. If the
/// placeholder above is replaced with a key of the wrong length, every launch
/// fails `pool_seeded`'s `length_of_bytearray(treasury_pkh) == 28` with no
/// diagnosable reason; this catches it at `aiken check` time instead.
test params_treasury_pkh_is_28_bytes() {
  builtin.length_of_bytearray(treasury_pkh_v3) == 28
}

/// THE CEILING ON A, pinned so nobody re-derives the deleted "~64 lovelace"
/// claim. The largest closing `ada_reserve` any path can reach is
///
///     k0 // curve_exhausted_token_reserve − virtual_ada_v3
///
/// because k is bounded above by its genesis value k0 (buys only lower it, and a
/// capped sell restores it to at most k0). Every real token closes at or below
/// this.
///
/// It is 9 lovelace BELOW `pool_bag_v3 × 64` = 16,717,048,000, so the reachable
/// ceiling price is `64 − 9/261,203,875` = 63.999999965544… and the design's exact 64
/// is a target the floor division cannot hit from any path. Pinned by
/// `math_v3.amm_open_price_is_nine_lovelace_short_of_the_design_sixty_four`.
///
/// (This used to say the 9-lovelace gap "is why the isqrt perfect-square degenerate
/// case is unreachable; see `math_v3.isqrt_ok`". `isqrt_ok` was DELETED with the
/// Splash path on 2026-07-26 — there is no integer square root anywhere in v3 and no
/// caller-supplied witness for one to bracket — so that was a dangling reference from
/// a live constant's justification to a guard that no longer exists. Nobody should go
/// hunting git history for it.)
test params_max_reachable_close_is_the_one_shot_ceiling() {
  let k0 = virtual_ada_v3 * virtual_token_v3
  let x_max = k0 / curve_exhausted_token_reserve - virtual_ada_v3
  x_max == 16_717_047_991 && x_max < 16_717_048_000
}

/// ── THE TRADE FEE IS 2 ADA FLAT + 1% TO THE CREATOR. ────────────────────────
/// Operator decision, 2026-07-26. This replaces `params_trader_fee_is_snek_parity`,
/// which asserted `creator_fee_bps_v3 + platform_fee_bps_v3 == 130` — snek.fun
/// parity at 1.30% + 0.50 ADA. That is no longer the schedule and the old test
/// would have been FALSE, so it is re-derived rather than relaxed.
///
/// The platform takes NO percentage: its whole fee is the flat component. Pinning
/// `platform_fee_bps_v3 == 0` here is what makes a silent reintroduction of a
/// percentage rate fail loudly.
test params_trade_fee_is_two_ada_flat_plus_one_percent_creator() {
  and {
    creator_fee_bps_v3 == 100,
    platform_fee_bps_v3 == 0,
    platform_fee_flat_v3 == 2_000_000,
  }
}

/// The flat fee is now the ENTIRE platform take, so it — not a bps rate — is what
/// `pool_seeded` and `fee_schedule_ok` have to defend. At 2 ADA a trader pays 6.3%
/// all-in on a 31.7 ADA buy and proportionally less above that; below it the flat
/// component dominates, which is accepted deliberately (there is no minimum trade).
test params_flat_fee_is_the_whole_platform_take() {
  platform_fee_bps_v3 == 0 && platform_fee_flat_v3 > 0
}
