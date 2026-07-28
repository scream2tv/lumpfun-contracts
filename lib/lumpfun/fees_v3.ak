// ── LumpFun v3 — fee arithmetic and fee-payment checks ───────────────────────
//
// v3's SHIPPED schedule (operator decision, 2026-07-26): 1.00% creator + 2 ADA
// flat platform, on both sides of the curve and of the AMM. The platform bps is
// ZERO — the flat is the whole platform take. Total trader cost 1.00% + 2 ADA.
// (This replaced §4.1's 0.80% + 0.50% + 0.50 ADA snek.fun-parity schedule; none
// of those numbers survive anywhere in this cohort.)
//
// ── BUY FEES ARE A SURCHARGE; SELL FEES ARE A DEDUCTION ──────────────────────
// The two sides are NOT symmetric and the plan's §4.2 tables do not say so.
//
//   BUY   `lump_pool.validate_buy` computes both fees on `ada_in`, which is the
//         lovelace that actually REACHES `ada_reserve`. The trader's total outlay
//         is `ada_in × 1.01 + 2,000,000`, paid to three separate outputs. So the
//         worked "100 ADA trade → all-in 3.00 ADA = 3.00%" is 3.00% OF THE
//         RESERVE-SIDE AMOUNT; as a fraction of what leaves the wallet it is
//         3.00/103.00 = 2.91%.
//
//   SELL  `lump_pool.validate_sell` computes both fees on `ada_gross`, the
//         lovelace that LEAVES `ada_reserve`, and `slippage_ok` compares
//         `min_out` against `sell_net` — gross minus both fees.
//
// The correctness consequence is off-chain and it is the D-1/D-2 seam the v2
// report says every real defect lived in: a web/ quote that treats the user's
// entered ADA as `ada_in` overcharges by the fee, and one that treats it as total
// spend and back-solves `ada_in = spend/1.013 − flat` will MISS the closing buy's
// 1-to-64-lovelace-wide window and die with an opaque script error. The closing
// buy must be solved RESERVE-SIDE; `math_v3`'s header carries the formula and a
// worked golden vector.
//
// Three things v2 had here are gone with the order book:
//   • `platform_fee_for(n_orders)` / `platform_fee_paid_n` — R-2's per-order
//     multiplier. v3 has no batches, so a trade owes exactly one fee.
//   • `order_min_utxo` and the buy/sell volume reconstruction — R-1. There are
//     no order UTxOs to reconstruct volume from; the trade's own `ada_in` /
//     `ada_gross` is read straight off the pool's datum delta and is already
//     pinned to the pool's real value by the V-6 invariant.
//   • the v1 `platform_fee` constant. v3 shares nothing with v1.
//
// The fee rates themselves live in the POOL DATUM, not here, because v3's pool
// is unparameterised (see pool_types.PoolDatum). `params_v3` holds the values
// the MINTING policy pins them to at genesis.

use aiken/collection/list
use cardano/address.{Credential}
use cardano/assets.{lovelace_of}
use cardano/transaction.{Output}

/// Creator rev-share on an ADA amount, in bps. Floor division: the creator is
/// rounded down, never the pool.
pub fn creator_fee(ada_amount: Int, bps: Int) -> Int {
  ada_amount * bps / 10_000
}

/// Platform take: a bps share plus the flat settlement-cost passthrough.
/// Always strictly positive because `flat` is, which is why the platform fee
/// check below never needs a zero-fee escape hatch.
pub fn platform_fee(ada_amount: Int, bps: Int, flat: Int) -> Int {
  ada_amount * bps / 10_000 + flat
}

/// Net ADA a seller keeps: gross minus both fees.
pub fn sell_net(ada_gross: Int, creator_bps: Int, platform_bps: Int, flat: Int) -> Int {
  ada_gross - creator_fee(ada_gross, creator_bps) - platform_fee(
    ada_gross,
    platform_bps,
    flat,
  )
}

/// True when at least one output pays `min_lovelace` to an address whose
/// PAYMENT credential matches `pkh` — VerificationKey or Script, so a creator
/// may route their rev-share to a script they control.
///
/// ── THE POOL'S OWN CONTINUATION IS EXCLUDED. THIS IS LOAD-BEARING. ───────────
/// `pool_hash` is `lump_pool_v3`'s own script hash and any output sitting there
/// is skipped. Without the exclusion, a launcher setting `treasury_pkh` or
/// `creator_pkh` to the POOL SCRIPT HASH (28 bytes, so every length assertion
/// passes) makes the pool's own continuation output — which always carries
/// `new_ada + pool_floor_v3` lovelace, vastly more than any fee — satisfy the fee
/// check on EVERY trade forever, with no fee output in the transaction at all.
/// The rates being pinned to `params_v3` does not help: the rates were pinned and
/// the RECIPIENT was free. It is strictly worse than a self-dealing treasury key,
/// because there is no fee output to notice missing.
///
/// `pool_seeded` additionally refuses both keys equal to the pool hash at
/// genesis. Both are kept: this one binds self-seeded pools that never went
/// through the minting policy at all.
///
/// ── STILL AN EXISTENTIAL CHECK — TWO PRECONDITIONS, IN TWO FILES ─────────────
/// It is exact only because:
///   1. `lump_pool.tx_shape_ok` confines every transaction to exactly one pool
///      input and forbids all other script inputs. Without it two pools in one
///      transaction share a single fee output and K trades pay one fee (R-3).
///   2. `minting_policy.pool_seeded` asserts `creator_pkh != treasury_pkh`
///      (minting_policy.ak, in the `datum_ok` block). Without it ONE output
///      satisfies BOTH checks and LumpFun is underpaid on every trade for the
///      life of the pool. `lump_pool`'s `buy_rejects_fees_both_paid_to_the_creator`
///      is the regression test for that, and it is a test of a MINTING-POLICY
///      precondition — the two must never be relaxed independently. This is the
///      kind of assertion someone relaxes to support a self-launch flow.
///
/// Note the residual, unchanged and accepted: the recipient's OWN change output
/// satisfies the check, so a creator trading their own curve pays themselves no
/// creator fee. Self-directed and harmless while (2) holds.
pub fn pays_at_least(
  outputs: List<Output>,
  pkh: ByteArray,
  min_lovelace: Int,
  pool_hash: ByteArray,
) -> Bool {
  list.any(
    outputs,
    fn(o) {
      when o.address.payment_credential is {
        Credential.VerificationKey(h) ->
          h == pkh && lovelace_of(o.value) >= min_lovelace
        Credential.Script(h) ->
          h != pool_hash && h == pkh && lovelace_of(o.value) >= min_lovelace
      }
    },
  )
}

/// Creator fee is satisfied when it is zero or paid.
///
/// ── THE `fee == 0` HATCH IS REACHABLE. DO NOT DELETE IT. ─────────────────────
/// With `min_trade_ada_v3` DELETED there is no minimum trade at all, so the
/// hatch's domain is every trade whose base amount keeps `creator_fee` at zero:
/// `creator_fee(x, 100) == 0` ⟺ `x × 100 < 10,000` ⟺ `x <= 99` — any dust buy
/// with `ada_in ∈ [1..99]`, any dust sell grossing at most 99, on the curve and
/// on the AMM alike, repeatedly, for the life of the pool.
///
/// The closing window is still the sharpest instance: from
/// `old_tok == curve_exhausted_token_reserve + 1` — a state the suite already
/// uses, e.g. (16,717,047,879, 404,061,019) — the admissible closing `ada_in`
/// window is [1..63] (bounded by `cap_ok`, not by any fee arithmetic), and
/// `creator_fee(63, 100) == 0`, so the hatch fires on EVERY closing buy from
/// that state. Economic impact is at most 1 lovelace of creator fee per
/// transaction; the platform is unaffected because `platform_fee`'s flat
/// component keeps it at 2,000,000.
///
/// If the hatch were deleted, a legal 1-lovelace closing buy would become
/// unbuildable and §3.1's freeze would come back at
/// `old_tok == curve_exhausted_token_reserve + 1`. It stays.
///
/// ── ██ THE AMM SELL SIDE IS THE *LARGER* DOMAIN, AND IT IS NOT THE CLOSING BUY. ██
/// The closing window fires once per token lifetime. `validate_amm_sell` HAS NO
/// SELL-SIDE MINIMUM — deliberately, because one dust-locks small holders — so
/// `ada_gross` there is unbounded below at 1 and the hatch is reachable on ORDINARY
/// dust sells, repeatedly, for the life of the pool. `creator_fee(g, 100) == 0` for
/// every `g <= 99`, and a ONE-TOKEN AmmSell from the canonical graduated state
/// (16,717,047,886, 261,203,875) grosses exactly 64 lovelace — squarely inside the
/// hatch. So dust AmmSells pay the creator NOTHING while the platform still collects
/// its 2,000,000 flat.
///
/// Correct behaviour, and bounded to absurdity: at most 1 lovelace of creator fee is
/// forgone per transaction, against 2,000,000 of platform fee plus ~170,000 of
/// ledger min-fee — roughly 2,000,000:1 against anyone doing it on purpose.
/// Recorded because a reviewer computing the hatch's reachable domain from the
/// closing-buy paragraph alone will UNDERESTIMATE it by every dust sell the AMM
/// will ever see. `fee_zero_hatch_domain_on_an_amm_dust_sell` pins it.
pub fn creator_fee_paid(
  outputs: List<Output>,
  creator_pkh: ByteArray,
  ada_amount: Int,
  bps: Int,
  pool_hash: ByteArray,
) -> Bool {
  let fee = creator_fee(ada_amount, bps)
  fee == 0 || pays_at_least(outputs, creator_pkh, fee, pool_hash)
}

/// Platform fee is never zero (the flat component), so no escape hatch — this
/// holds even on the 1-lovelace closing buy described above.
pub fn platform_fee_paid(
  outputs: List<Output>,
  treasury_pkh: ByteArray,
  ada_amount: Int,
  bps: Int,
  flat: Int,
  pool_hash: ByteArray,
) -> Bool {
  pays_at_least(
    outputs,
    treasury_pkh,
    platform_fee(ada_amount, bps, flat),
    pool_hash,
  )
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// Re-derived for the SHIPPED 100 / 0 / 2,000,000 schedule (2026-07-26). NONE of
// the 80 / 50 / 500,000 snek-parity numbers survive.

/// The worked 100 ADA buy: creator 1.00 ADA, platform 2.00 flat (0 bps).
test fee_hundred_ada_trade() {
  creator_fee(100_000_000, 100) == 1_000_000 && platform_fee(
    100_000_000,
    0,
    2_000_000,
  ) == 2_000_000
}

/// The worked 10 ADA trade: creator 0.10, platform 2.00 flat. All-in 2.10 ADA
/// = 21%. The flat dominates small trades; with no minimum trade that is the
/// trader's call to make, which `params_flat_fee_is_the_whole_platform_take`
/// records as the accepted design.
test fee_ten_ada_trade_flat_dominates() {
  let c = creator_fee(10_000_000, 100)
  let p = platform_fee(10_000_000, 0, 2_000_000)
  c == 100_000 && p == 2_000_000 && c + p == 2_100_000
}

/// A seller's net on the 193,163,966 gross of `math_v3.sell_twenty_million_tokens`:
///   creator  = 193,163,966 × 100 / 10,000 = 1,931,639
///   platform = 2,000,000 (flat; bps is 0)
///   net      = 193,163,966 − 1,931,639 − 2,000,000 = 189,232,327
test fee_sell_net_on_the_worked_sell() {
  sell_net(193_163_966, 100, 0, 2_000_000) == 189_232_327
}

/// Floor division rounds AGAINST the fee recipient, never against the pool.
/// 99 × 100 = 9,900 < 10,000 → 0 ; 100 × 100 = 10,000 → 1.
test fee_floors_against_the_recipient() {
  creator_fee(99, 100) == 0 && creator_fee(100, 100) == 1
}

/// The REACHABLE domain of the `fee == 0` hatch on a closing buy, pinned. From
/// `curve_exhausted_token_reserve + 1` the admissible closing `ada_in` window is
/// [1..63] — bounded by `cap_ok`, since with no minimum trade every size is
/// otherwise legal — and the creator fee is zero across that ENTIRE window (the
/// hatch itself extends to 99). So the hatch is not a contrived corner, it fires
/// on every closing buy from that state. Meanwhile the platform is still owed
/// its flat 2,000,000 at every point in the window, which is why
/// `platform_fee_paid` needs no hatch.
test fee_zero_hatch_domain_on_a_closing_buy() {
  and {
    creator_fee(1, 100) == 0,
    creator_fee(63, 100) == 0,
    // the fee is still 0 past the top of the closing window — the WINDOW is
    // bounded by `cap_ok`, the HATCH by the fee arithmetic at 99
    platform_fee(1, 0, 2_000_000) == 2_000_000,
    platform_fee(63, 0, 2_000_000) == 2_000_000,
  }
}

/// ██ THE HATCH'S *AMM* DOMAIN — the larger one, and it was pinned by nothing. ██
///
/// `validate_amm_sell` has no minimum, so the gross starts at 1 and the hatch is
/// reachable on ordinary dust sells for the life of the pool — not once per token
/// lifetime like the closing buy. The exact boundary of the arithmetic:
///
///   creator_fee(g, 100) == 0  ⟺  g × 100 < 10,000  ⟺  g <= 99
///   a ONE-TOKEN AmmSell from (16,717,047,886, 261,203,875) grosses 64:
///       k = 4,366,557,686,383,758,250 ; new_tok = 261,203,876
///       new_ada = k / 261,203,876 = 16,717,047,822 ; gross = 64
///   so the realistic dust-sell gross sits at 64, mid-hatch, not at a contrived 1.
///
/// 99 is the last zero and 100 is the first non-zero, which is the whole domain
/// (it was [1..124] under the old 80 bps rate). The platform still collects its
/// flat 2,000,000 at every one of these, which is why the asymmetry is safe.
test fee_zero_hatch_domain_on_an_amm_dust_sell() {
  and {
    // the realistic vector: a 1-token sell at the canonical graduated state
    creator_fee(64, 100) == 0,
    // the exact top of the hatch, and one past it
    creator_fee(99, 100) == 0,
    creator_fee(100, 100) == 1,
    // the platform is never inside a hatch, at any of them
    platform_fee(64, 0, 2_000_000) == 2_000_000,
    platform_fee(99, 0, 2_000_000) == 2_000_000,
    platform_fee(100, 0, 2_000_000) == 2_000_000,
  }
}
