// ══════════════════════════════════════════════════════════════════════════════
// LumpFun v3 — the bonding curve AND the permanent AMM
//
// ── BOOTSTRAP: constant product over the VIRTUAL reserves ────────────────────
//
//     effective_ada  = ada_reserve   + virtual_ada_v3
//     effective_tok  = token_reserve                      (already virtual)
//     k              = effective_ada · token_reserve
//
// `ada_reserve` is the REAL curve reserve and EXCLUDES `pool_floor_v3`;
// `token_reserve` is the VIRTUAL token reserve, so the REAL token balance held
// in the pool UTxO is `token_reserve − token_offset_v3` (`real_tokens` below).
//
// ── AMM: constant product over the REAL reserves, OFFSET 0 ON BOTH SIDES ─────
//
//     k = ada_reserve · token_reserve            and that is the whole model
//
// After graduation `ada_reserve` IS the pool's lovelace balance (no floor) and
// `token_reserve` IS its token balance (no offset). `amm_quote_buy` /
// `amm_quote_sell_gross` are therefore NOT the curve functions with different
// arguments — they are the same shape with both offsets set to zero, written out
// separately so no caller can accidentally apply one convention's substitution to
// the other's reserves. That mistake is worth 142,857,143 tokens.
//
// The off-chain quote (web/) must mirror this integer arithmetic exactly, the
// same contract v2's math.ak has with src/cardano/curve.ts.
//
// ── WHAT THE OFF-CHAIN SOLVER MUST SOLVE FOR ─────────────────────────────────
// EVERY quantity in this module is RESERVE-SIDE. `ada_in` is the lovelace that
// actually reaches `ada_reserve`, NOT the trader's total outlay: on a Buy or an
// AmmBuy both fees are a SURCHARGE on top of it, so the user spends
// `ada_in × 1.0130 + 500,000` (see fees_v3's header for the full asymmetry —
// the sell sides are the other way round and deduct from the gross).
//
// This matters most on the CLOSING BUY, where `ada_in` is fixed by the curve to a
// window as narrow as ONE lovelace. The solver must return the reserve-side
// value directly —
//
//     ada_in = (min N such that k // N == curve_exhausted_token_reserve)
//              − effective        where effective = ada_reserve + virtual_ada_v3
//
// — and must NOT derive it from the user's entered spend. A quote that computes
// `ada_in = spend / 1.013 − flat` misses the window and the transaction fails
// with an opaque script error, which is the exact symptom §8.1 warns about.
// (The AMM has no closing window and no exemption: `min_trade_ada_v3` binds
// unconditionally on `AmmBuy`, so back-solving is merely imprecise there, not
// fatal.)
//
// GOLDEN VECTOR for web/ to test against, one worked closing buy:
//   state      ada_reserve = 16,712,047,886   token_reserve = 404,139,159
//   effective  = 25,854,905,030   k = 25,854,905,030 × 404,139,159
//   ada_in     = 4,999,994  (the SMALLEST closing buy; the window runs to
//                            5,000,057, all landing on 404,061,018)
//   tokens_out = 78,141
//   fees       creator 39,999 ; platform 24,999 + 500,000 = 524,999
//   user spend = 4,999,994 + 39,999 + 524,999 = 5,564,992 lovelace
// ══════════════════════════════════════════════════════════════════════════════

use lumpfun/params_v3.{
  curve_exhausted_token_reserve, pool_bag_v3, sellable_v3, token_offset_v3,
  total_supply_v3, virtual_ada_v3, virtual_token_v3,
}

/// The REAL token balance a BOOTSTRAP pool UTxO must hold for a given VIRTUAL
/// reserve. Meaningless after graduation — an `Amm` pool's `token_reserve` IS its
/// real balance.
pub fn real_tokens(token_reserve: Int) -> Int {
  token_reserve - token_offset_v3
}

/// How many tokens a buyer receives for `ada_in` lovelace ON THE CURVE.
///
/// ROUNDING DIRECTION — READ THIS, IT IS INVERTED IN v2's SOURCE.
///
/// The floor is applied to `new_token_reserve`, i.e. to the reserve the pool
/// RETAINS. So the pool keeps up to one token LESS than the exact continuous
/// solution, the BUYER receives up to one token MORE, and k therefore weakly
/// DECREASES across a direct buy. Measured at v3 genesis, a single 10 ADA buy
/// moves k by −6,349,998,440 (relative error < 1e-9; the buyer's maximum gain is
/// one token against a 0.50 ADA flat fee, so it is not grindable).
///
/// contracts/cardano/lib/lumpfun/math.ak:19 claims the opposite ("buyers get
/// slightly fewer tokens — keeps k non-decreasing"). That comment is WRONG and
/// MUST NOT be ported. contracts/cardano/lib/lumpfun/amm.ak:15-22 states it
/// correctly and is the comment this one descends from.
///
/// Consequence for anyone writing a property test: DO NOT assert that k is
/// non-decreasing on the direct buy path — it will fail against correct code.
/// If you assert anything about k on that path, assert NON-INCREASING. The SAME
/// applies to `amm_quote_buy` below, which has the identical rounding.
pub fn quote_buy(ada_reserve: Int, token_reserve: Int, ada_in: Int) -> Int {
  let effective = ada_reserve + virtual_ada_v3
  let k = effective * token_reserve
  let new_effective = effective + ada_in
  let new_token_reserve = k / new_effective
  token_reserve - new_token_reserve
}

/// Gross ADA a seller receives for `tokens_in` before fees are deducted, ON THE
/// CURVE.
///
/// Mirror rounding: the floor lands on `new_effective`, so the gross is up to
/// one lovelace LARGER than the continuous solution and k again weakly
/// decreases. Capped at `ada_reserve` as a solvency bound — the curve reserve
/// can never be driven negative, and the cap can only bind on a full round-trip
/// back to genesis (it is exercised by `sell_full_round_trip_hits_the_cap`).
///
/// ── THE PER-ROUND-TRIP LEAK IS NOT ONE LOVELACE ──────────────────────────────
/// Buy-then-immediately-sell-back returns MORE than was paid in, because the
/// buy's k-drift (up to `new_effective − 1`, documented on `quote_buy`) dwarfs
/// the sell's mirror floor (at most 1). The leak is approximately one token's
/// worth of ADA, so it SCALES WITH PRICE:
///
///     at genesis      (10,000,000, 1,141,608,508)  uncapped gross 10,000,006
///     near the close  (16,722,047,886, 403,982,908) uncapped gross 10,000,064
///
/// At genesis the cap binds and swallows it; near the close IT DOES NOT — 64
/// lovelace genuinely leaves the pool. Both ends are pinned by
/// `sell_full_round_trip_hits_the_cap` and
/// `sell_round_trip_leak_near_the_close_is_64_lovelace`.
///
/// Not exploitable at the current schedule: ~64 lovelace extracted against a
/// mandatory ≥1.13 ADA of fees (0.50 flat each way + 1.30% each way on a ≥10 ADA
/// buy) is a 17,000:1 loss. But price any future relaxation — dropping the flat
/// fee, lowering `min_trade_ada_v3` — against 64, not against 1.
pub fn quote_sell_gross(
  ada_reserve: Int,
  token_reserve: Int,
  tokens_in: Int,
) -> Int {
  let effective = ada_reserve + virtual_ada_v3
  let k = effective * token_reserve
  let new_token_reserve = token_reserve + tokens_in
  let new_effective = k / new_token_reserve
  let gross = effective - new_effective
  if gross > ada_reserve {
    ada_reserve
  } else {
    gross
  }
}

/// The constant-product invariant, with the v3 virtual ADA offset. Not enforced
/// anywhere on the v3 spend paths (the exact quote is compared instead, which is
/// strictly tighter); exported so tests can measure the k drift documented above.
pub fn k_value(ada_reserve: Int, token_reserve: Int) -> Int {
  ( ada_reserve + virtual_ada_v3 ) * token_reserve
}

/// True when the curve still has sellable allocation left. Once
/// `token_reserve == curve_exhausted_token_reserve` the pool is FROZEN: no buy,
/// no sell, only `Graduate`. Freezing is deliberate — if sells could reopen the
/// curve, a 1-token sell in front of every graduation attempt would grief
/// graduation indefinitely (§5.1: "once the curve closes it is frozen, so
/// somebody must be paid to unfreeze it").
pub fn curve_open(token_reserve: Int) -> Bool {
  token_reserve > curve_exhausted_token_reserve
}

// ══════════════════════════════════════════════════════════════════════════════
// THE PERMANENT AMM — offset 0 on BOTH sides
// ══════════════════════════════════════════════════════════════════════════════

/// k for an `Amm` pool. No offsets — both reserves are real.
pub fn amm_k(ada_reserve: Int, token_reserve: Int) -> Int {
  ada_reserve * token_reserve
}

/// Tokens out for `ada_in` lovelace in the permanent AMM.
///
/// Identical rounding to `quote_buy` (floor on the RETAINED token reserve), so
/// the same warning applies: k weakly DECREASES on a buy, and a
/// "k is non-decreasing" property test fails against correct code.
///
/// ── THE POOL CANNOT BE EMPTIED OF TOKENS. ────────────────────────────────────
/// `new_token_reserve = k / (ada_reserve + ada_in)` is 0 only when
/// `ada_in > k − ada_reserve`. At the canonical graduated state
/// k = 16,717,047,886 × 261,203,875 = 4,366,557,686,383,758,250 lovelace-tokens,
/// so reaching zero needs ~4.37e18 lovelace = ~4.37 TRILLION ADA against a total
/// ADA supply of 45e9. Spending the ENTIRE ADA supply (4.5e16 lovelace) leaves 97
/// tokens — pinned by `amm_buy_cannot_empty_the_token_side`. The validator asserts
/// `new_tok >= 1` anyway, because a self-seeded pool graduated with
/// `ada_reserve = 1` has k = 261,203,875 and the bound does not hold there.
pub fn amm_quote_buy(ada_reserve: Int, token_reserve: Int, ada_in: Int) -> Int {
  let k = ada_reserve * token_reserve
  let new_ada_reserve = ada_reserve + ada_in
  let new_token_reserve = k / new_ada_reserve
  token_reserve - new_token_reserve
}

/// Gross ADA out for `tokens_in` in the permanent AMM, before fees.
///
/// Capped at `ada_reserve` for the same solvency reason as the curve version.
///
/// ── THE POOL CANNOT BE EMPTIED OF ADA EITHER. ────────────────────────────────
/// The largest possible `tokens_in` is the entire float outside the pool. At
/// graduation that is `sellable_v3` = 738,796,125 against `pool_bag_v3` in the
/// pool, so `new_token_reserve` maxes out at `total_supply_v3` = 1e9 and
/// `new_ada_reserve = k / 1e9 = 4,366,557,686` lovelace — the pool still holds
/// 4,366 ADA after 100% of the float is dumped into it. Pinned by
/// `amm_sell_of_the_whole_float_leaves_4366_ada`. The validator asserts
/// `new_ada >= 1` anyway, for self-seeded pools where k is tiny.
pub fn amm_quote_sell_gross(
  ada_reserve: Int,
  token_reserve: Int,
  tokens_in: Int,
) -> Int {
  let k = ada_reserve * token_reserve
  let new_token_reserve = token_reserve + tokens_in
  let new_ada_reserve = k / new_token_reserve
  let gross = ada_reserve - new_ada_reserve
  if gross > ada_reserve {
    ada_reserve
  } else {
    gross
  }
}

/// §5.5's G0 and G3 as a PURE FUNCTION — the CURVE-SIDE preconditions on a
/// graduation, and all that is left of them now that Splash is parked.
///
///   G0  token_reserve == curve_exhausted_token_reserve   (the curve is finished)
///   G3  ada_reserve >= 1 && pool_bag_v3 == token_reserve − token_offset_v3
///                                                        (the bag is the bag we
///                                                         promised — checked
///                                                         BOTH ways so a
///                                                         datum/value
///                                                         disagreement cannot
///                                                         slip a different bag
///                                                         through)
///
/// G4 IS GONE WITH THE SPLASH PATH. There is no `lq0` witness, no integer square
/// root, no `MAX_LQ_CAP`, and no LQ asset — so there is nothing left to check a
/// caller-supplied number against, and `Graduate` carries no field at all.
/// `isqrt_ok` and `lq_mint_of` were deleted rather than left dangling; if a future
/// venue needs them they are in git history at the Phase-2 commit.
///
/// G0 is ALGEBRAICALLY IDENTICAL to G3's second clause, because
/// `curve_exhausted_token_reserve − token_offset_v3 == pool_bag_v3`
/// (`params_v3.params_exhausted_real_balance_is_pool_bag`). Both are written out
/// because §5.5 specifies both and they express different intents; neither alone
/// is isolated by any test, and saying so is better than implying coverage.
///
/// ── `ada_reserve >= 1` IS LOAD-BEARING NOW IN A WAY IT WAS NOT BEFORE. ───────
/// Under the Splash path its job was to stop `isqrt_ok(0, 0, y)` accepting a zero
/// witness on an empty pool. Its job now is ARITHMETIC SURVIVAL: the graduated Amm
/// pool's k is `ada_reserve × pool_bag_v3`, and at `ada_reserve = 0` every
/// subsequent `AmmBuy` computes `k / new_ada = 0` and every `AmmSell` computes
/// `gross = 0 − 0`, so the pool would be permanently frozen at price zero holding
/// 261,203,875 real tokens that can never be bought. It is also the ledger's
/// problem — a 3-entry UTxO with 0 lovelace is unbuildable — but the validator must
/// not be the thing relying on that. Bound by
/// `graduation_checks_reject_an_empty_ada_reserve`.
///
/// ── ██ WHAT REJECTING THE FLIP AT x == 0 ACTUALLY COSTS: A DEAD CURVE. ██ ─────
/// State both halves, because a future reader weighing whether to relax this clause
/// needs them. Rejecting the graduation does NOT leave a recoverable pool — it leaves
/// `(ada_reserve == 0, token_reserve == Xex, mode Bootstrap)` UNSPENDABLE BY EVERY
/// BRANCH: `Buy` and `Sell` fail `curve_open` (the reserve is exactly exhausted),
/// `Graduate` fails right here, and `AmmBuy`/`AmmSell` fail `mode == Amm`. Its
/// `pool_floor_v3` and its 261,203,875 tokens are gone for good. So the clause trades
/// a dead AMM for a dead CURVE. That is still the right trade — a dead AMM would be
/// LISTED and QUOTABLE at price zero, and buyers would be routed into it — but it is
/// a trade, not a free win.
///
/// ── AND IT IS UNREACHABLE BY CONSTRUCTION, NOT MERELY UNECONOMIC. ────────────
/// `token_reserve == Xex` is reachable only by a `Buy`: `Sell` requires `curve_open`
/// on the OLD reserve and only ever INCREASES it. And `validate_buy` asserts
/// `ada_in > 0` against `old_ada >= 0`, so every reachable close carries A >= 1.
/// Therefore this clause can never reject a pool that got here honestly, and no
/// genuine curve can close at A = 0. `lump_mint_v3.pool_seeded` pins genesis to
/// `(0, virtual_token_v3)`, so a genuine launch cannot start in the dead state
/// either — only a self-seeder can construct it, at the cost of their own floor and
/// their own tokens.
pub fn graduation_curve_checks(ada_reserve: Int, token_reserve: Int) -> Bool {
  let g0 = token_reserve == curve_exhausted_token_reserve
  let g3 = ada_reserve >= 1 && pool_bag_v3 == token_reserve - token_offset_v3
  and {
    g0,
    g3,
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS
//
// Every arithmetic constant below is RE-DERIVED for v3 from the params_v3
// constants. Nothing is carried over from v2's V = 3,000 / A = 21,000 suite —
// a ported number passes for the wrong reason and proves nothing. Each
// derivation is written out so a reviewer can recompute it.
//
//   Genesis state:  ada_reserve = 0, token_reserve = X_c = 1,142,857,143
//                   effective = 0 + 9,142,857,144
//                   k = 9,142,857,144 × 1,142,857,143 = 10,448,979,594,448,979,592
// ══════════════════════════════════════════════════════════════════════════════

/// Genesis buy of exactly the 10 ADA minimum.
///   new_effective = 9,142,857,144 + 10,000,000 = 9,152,857,144
///   new_token_reserve = 10,448,979,594,448,979,592 / 9,152,857,144 = 1,141,608,508
///   tokens_out = 1,142,857,143 − 1,141,608,508 = 1,248,635
test buy_genesis_ten_ada() {
  quote_buy(0, virtual_token_v3, 10_000_000) == 1_248_635
}

/// Genesis buy of 1,000 ADA.
///   new_effective = 9,142,857,144 + 1,000,000,000 = 10,142,857,144
///   new_token_reserve = k / new_effective = 1,030,181,086
///   tokens_out = 1,142,857,143 − 1,030,181,086 = 112,676,057
test buy_genesis_thousand_ada() {
  quote_buy(0, virtual_token_v3, 1_000_000_000) == 112_676_057
}

/// The effective price of the genesis 10 ADA buy is ~8.009 lovelace/token —
/// i.e. a hair above the exact 8, as slippage requires, so the buyer paid MORE
/// than 8/token. If this ever flips, the curve is mispriced at launch.
///
/// CALLS `quote_buy`. The previous version asserted `1_248_635 * 8 < 10_000_000`
/// — a fact about two literals that never touched the curve and would have
/// stayed green through any change to `virtual_ada_v3` or `virtual_token_v3`,
/// despite its comment claiming to detect exactly that.
test buy_genesis_price_is_just_above_eight() {
  quote_buy(0, virtual_token_v3, 10_000_000) * 8 < 10_000_000
}

/// k is NON-INCREASING on the direct buy path — the corrected direction from
/// amm.ak:15-22. Asserting non-DEcreasing here would FAIL against correct code.
///   k_old = 10,448,979,594,448,979,592
///   k_new = (0 + 10,000,000 + 9,142,857,144) × 1,141,608,508
///         = 10,448,979,588,098,981,152
///   delta = −6,349,998,440
test buy_k_is_non_increasing_not_non_decreasing() {
  let tokens_out = quote_buy(0, virtual_token_v3, 10_000_000)
  let k_new = k_value(10_000_000, virtual_token_v3 - tokens_out)
  let k_old = k_value(0, virtual_token_v3)
  k_new <= k_old && k_new - k_old == -6_349_998_440
}

/// The whole curve, bought in one transaction, terminates EXACTLY on the
/// sellable allocation. This is the identity the entire pre-allocation design
/// rests on: 16,717,047,928 lovelace in ⇒ exactly C tokens out and exactly
/// `curve_exhausted_token_reserve` left.
///   new_effective = 9,142,857,144 + 16,717,047,928 = 25,859,905,072
///   k / 25,859,905,072 = 404,061,018  (= curve_exhausted_token_reserve)
///   tokens_out = 1,142,857,143 − 404,061,018 = 738,796,125 = sellable_v3
test buy_one_shot_exhausts_the_curve_exactly() {
  let out = quote_buy(0, virtual_token_v3, 16_717_047_928)
  out == sellable_v3 && virtual_token_v3 - out == curve_exhausted_token_reserve
}

/// …and the pool's REAL token balance at that moment is the pool bag, so
/// graduation hands the Amm exactly `pool_bag_v3` and moves not one token.
test buy_close_leaves_exactly_the_pool_bag() {
  real_tokens(curve_exhausted_token_reserve) == pool_bag_v3
}

/// A is PATH-DEPENDENT. For a SINGLE one-shot buy from genesis the floor division
/// admits a 64-lovelace-wide window of closing `ada_reserve` values that all map
/// to the identical closing token reserve:
///   k / (X_c-side) ⇒ E ∈ [25,859,905,072 .. 25,859,905,135]
///   ada_reserve   ∈ [16,717,047,928 .. 16,717,047,991]
/// Both endpoints close the curve; they differ by 63 lovelace of A.
///
/// THIS WINDOW IS NOT A BOUND ON A ACROSS PATHS — see
/// `close_drifts_far_below_the_window_over_many_trades` immediately below, and
/// the extended note in `params_v3`.
test close_is_path_dependent_over_a_64_lovelace_window() {
  let lo = quote_buy(0, virtual_token_v3, 16_717_047_928)
  let hi = quote_buy(0, virtual_token_v3, 16_717_047_991)
  let over = quote_buy(0, virtual_token_v3, 16_717_047_992)
  and {
    virtual_token_v3 - lo == curve_exhausted_token_reserve,
    virtual_token_v3 - hi == curve_exhausted_token_reserve,
    virtual_token_v3 - over < curve_exhausted_token_reserve,
  }
}

/// Repeated buys of `size`, stopping before the one that would close the curve.
/// The only multi-trade driver in the suite — every other arithmetic test starts
/// from a hand-written state, which is precisely how "A drifts by ~64 lovelace"
/// survived as long as it did.
fn buy_n_times(a: Int, t: Int, size: Int, n: Int) -> (Int, Int) {
  if n <= 0 {
    (a, t)
  } else {
    let out = quote_buy(a, t, size)
    if t - out <= curve_exhausted_token_reserve {
      (a, t)
    } else {
      buy_n_times(a + size, t - out, size, n - 1)
    }
  }
}

/// A FALLS with trade count, far beyond the one-shot window. 100 buys of 150 ADA
/// destroy 780,954,353,376 of k, and the best close reachable from the resulting
/// state is 16,717,046,058 — 1,933 lovelace BELOW the one-shot ceiling of
/// 16,717,047,991 and 1,870 below even the bottom of the one-shot window. A
/// 10-ADA-buy path drifts ~36,000 lovelace.
///
/// This is the D-1/D-2 off-chain-to-on-chain seam the v2 report says every real
/// defect lived in: an indexer or launch monitor that sanity-checks A against a
/// 64-lovelace window false-positives on any token with normal activity.
test close_drifts_far_below_the_window_over_many_trades() {
  let (a, t) = buy_n_times(0, virtual_token_v3, 150_000_000, 100)
  let k = ( a + virtual_ada_v3 ) * t
  let k0 = virtual_ada_v3 * virtual_token_v3
  let x_reachable = k / curve_exhausted_token_reserve - virtual_ada_v3
  and {
    a == 15_000_000_000,
    t == 432_797_939,
    k < k0,
    k0 - k == 780_954_353_376,
    x_reachable == 16_717_046_058,
    // strictly below the BOTTOM of the one-shot window, not merely inside it
    x_reachable < 16_717_047_928,
  }
}

/// Sell 20,000,000 tokens back from the post-1,000-ADA-buy state.
///   state: ada_reserve = 1,000,000,000, token_reserve = 1,030,181,086
///   effective = 10,142,857,144 ; k = effective × 1,030,181,086
///   new_token_reserve = 1,050,181,086
///   new_effective = k / 1,050,181,086 = 9,949,693,178
///   gross = 10,142,857,144 − 9,949,693,178 = 193,163,966
test sell_twenty_million_tokens() {
  quote_sell_gross(1_000_000_000, 1_030_181_086, 20_000_000) == 193_163_966
}

/// A full round-trip returns the reserve to 0 and exercises the solvency cap.
///
/// The UNCAPPED gross would be 10,000,006 — SIX lovelace over, and it comes
/// almost entirely from the BUY's k-drift of −6,349,998,440 (pinned by
/// `buy_k_is_non_increasing_not_non_decreasing`), not from the sell's mirror
/// floor, which contributes at most 1. An earlier comment here said "10,000,001
/// (one lovelace over, from the mirror floor)"; both the number and the cause
/// were wrong, and the number is the one a future reviewer would price a fee
/// relaxation against. The cap binds, so the seller receives exactly the
/// 10,000,000 actually in the reserve and the pool is never driven negative.
test sell_full_round_trip_hits_the_cap() {
  let out = quote_buy(0, virtual_token_v3, 10_000_000)
  let t = virtual_token_v3 - out
  let effective = 10_000_000 + virtual_ada_v3
  let uncapped = effective - effective * t / ( t + out )
  uncapped == 10_000_006 && quote_sell_gross(10_000_000, t, out) == 10_000_000
}

/// …and NEAR THE CLOSE the same round trip leaks 64 lovelace, because the cap
/// does NOT bind there: the pool holds 16,722 ADA and the uncapped gross is only
/// 10,000,064. This is the real bound on per-round-trip extraction and the number
/// any future fee change must be priced against.
///
///   state (16,712,047,886, 404,139,159); buy 10 ADA → 156,251 tokens
///   → (16,722,047,886, 403,982,908); sell all 156,251 back → gross 10,000,064
///
/// Harmless at the current schedule (≥1.13 ADA of mandatory fees against 64
/// lovelace of leak) and bounded — but ASSERTED here rather than claimed in
/// prose, so a relaxation that makes it profitable turns this test red.
test sell_round_trip_leak_near_the_close_is_64_lovelace() {
  let out = quote_buy(16_712_047_886, 404_139_159, 10_000_000)
  let gross = quote_sell_gross(16_722_047_886, 404_139_159 - out, out)
  out == 156_251 && gross == 10_000_064 && gross - 10_000_000 == 64
}

/// The curve is open at genesis and closed at exhaustion.
test curve_open_at_genesis_closed_at_exhaustion() {
  curve_open(virtual_token_v3) && !curve_open(curve_exhausted_token_reserve)
}

/// Total supply never changes: real balance at genesis is exactly 1e9.
test real_tokens_at_genesis_is_total_supply() {
  real_tokens(virtual_token_v3) == total_supply_v3
}

// ══════════════════════════════════════════════════════════════════════════════
// ██  THE GRADUATION BOUNDARY — PRICE CONTINUITY, EXACT INTEGERS.            ██
// ══════════════════════════════════════════════════════════════════════════════
//
// ██ READ THIS FIRST: *MARGINAL PRICE* IS CONTINUOUS. *DEPTH* IS NOT. ██
//
// The two facts are independent and only the first one is what "no price gap"
// means. Quoting the first without the second is how a trader gets surprised:
//
//   MARGINAL PRICE  continuous to between 1.19e-10 and 2.26e-06 relative,
//                   depending on where the curve closed. Both signs occur. The
//                   bound is asserted below; it is NOT zero and never claimed to be.
//   DEPTH (k)       STEPS DOWN BY A FACTOR OF 1.547 AT THE FLIP. On the curve
//                   k = (V + A)·Xex ≈ 1.04490e19; after the flip k = A·P ≈
//                   4.36656e18 — the AMM carries 41.78% of the curve's k. The ADA
//                   side's effective reserve falls from A + V = 25,859,905,030 to
//                   A = 16,717,047,886, so SLIPPAGE PER ADA RISES BY 1.547× the
//                   instant graduation lands.
//
// THAT IS THE DESIGN, NOT A DEFECT: the curve's virtual reserves are not real, so a
// pool holding only real reserves must be shallower. v2 has the SAME depth step AND
// a 12.50–35.36% marginal price step on top of it. But it must be MEASURED and
// QUOTED, because it is what an off-chain quoter has to be written against:
//
//   effective-price penalty of the AMM vs the curve at the same instant, by size
//   (from the canonical close, buy side — `amm_depth_step_by_trade_size` pins these)
//        10 ADA   156,190 -> 156,157 tokens    +0.021%   ← invisible at this size
//       100 ADA 1,556,482 -> 1,553,209         +0.211%
//     1,000 ADA 15,043,278 -> 14,743,082       +2.036%
//     5,000 ADA 65,466,990 -> 60,137,980       +8.861%
//
// AN AGGREGATOR OR UI THAT QUOTES ONE BLOCK BEFORE THE FLIP AND EXECUTES ONE BLOCK
// AFTER IT fills a 1,000 ADA buy 2.04% worse than quoted and a 5,000 ADA buy 8.86%
// worse, with NO on-chain rejection — `min_out` is the trader's own number and a
// stale quote sets it too loose. Re-quote across the flip; do not carry a quote over
// it. The sell side is the same shape and is pinned by
// `amm_depth_step_on_the_sell_side`.
//
// THE CLAIM BEING TESTED, stated precisely so the tests can be checked against it:
//
//   marginal close price (Bootstrap, VIRTUAL reserves)
//       P_close = (virtual_ada_v3 + A) / curve_exhausted_token_reserve
//   marginal open price (Amm, REAL reserves, offset 0)
//       P_open  = A / pool_bag_v3
//
//   where A is the closing `ada_reserve`. `Graduate` changes NEITHER reserve in
//   reality — it moves `pool_floor_v3` out and relabels `token_reserve` from
//   404,061,018 (virtual) to 261,203,875 (real) — so P_open/P_close is the ENTIRE
//   price discontinuity of graduation.
//
// ── THEY ARE EQUAL IFF A HITS ONE EXACT VALUE, AND A IS PATH-DEPENDENT ───────
// Cross-multiplying,  P_open == P_close  ⟺  (V + A)·P == A·(P + off)  ⟺
//
//       V·P == A·off       ⟺       A == V·P / off
//                                    == 9,142,857,144 × 261,203,875 / 142,857,143
//                                    == 2,388,149,714,584,233,000 / 142,857,143
//                                    == 16,717,047,985.372583…      ← NOT AN INTEGER
//
// So EXACT continuity is unattainable by construction: the zero-gap reserve is not
// a whole number of lovelace, and A is in any case path-dependent (params_v3's
// header). The honest statement is a BOUND, and it is the one asserted below:
//
//     A = 16,717,047,991  (one-shot ceiling)   gap = +1.190e-08 %
//     A = 16,717,047,928  (window bottom)      gap = −1.213e-07 %
//     A = 16,717,047,886  (canonical two-step) gap = −2.102e-07 %
//     A = 16,717,046,058  (100 × 150 ADA)      gap = −4.076e-06 %
//     A = 16,717,011,721  (1,672 × 10 ADA)     gap = −7.670e-05 %
//     A = 16,716,941,047  (pessimistic k bound) gap = −2.262e-04 %
//
// AGAINST v2's SAME FLIP: v2 sets its ADA offset to 0 and keeps the token side
// unchanged, so `P_open/P_close = A/(A+V) = (s−1)/s` and the gap is exactly
// `−1/sqrt(m)` — −12.50% at m = 64, −35.36% at m = 8. v3's worst case is
// −0.000226%, i.e. FIVE ORDERS OF MAGNITUDE smaller than v2's best case, and it
// comes entirely from floor-division drift rather than from the model.
//
// ██ DO NOT WRITE A TEST ASSERTING THE GAP IS ZERO. ██ It is not zero, it is not
// signed consistently (it flips at A = 16,717,047,985), and a zero-gap assertion
// would have to be written against a hand-picked A that no real token reaches.

/// The zero-gap reserve, and the fact that it is NOT an integer. This is the
/// arithmetic that makes every other test in this block a bound rather than an
/// equality, so it is asserted first.
///
///   V·P = 9,142,857,144 × 261,203,875 = 2,388,149,714,584,233,000
///   off = 142,857,143
///   2,388,149,714,584,233,000 = 142,857,143 × 16,717,047,985 + 53,226,145
///   ⇒ A_zero_gap = 16,717,047,985 + 53,226,145/142,857,143, remainder NON-ZERO
test amm_zero_gap_reserve_is_not_an_integer() {
  let numer = virtual_ada_v3 * pool_bag_v3
  and {
    numer == 2_388_149_714_584_233_000,
    numer / token_offset_v3 == 16_717_047_985,
    numer % token_offset_v3 == 53_226_145,
    // …and NOT zero, which is the whole point
    numer % token_offset_v3 > 0,
  }
}

/// ██ THE CONTINUITY PROOF, at the ONE-SHOT CEILING. ██
///
/// A = 16,717,047,991 is the largest closing reserve any path can reach
/// (`params_v3.params_max_reachable_close_is_the_one_shot_ceiling`).
///
///   P_close = (9,142,857,144 + 16,717,047,991) / 404,061,018
///           = 25,859,905,135 / 404,061,018
///   P_open  = 16,717,047,991 / 261,203,875
///
/// Cross-multiplied to stay in integers:
///   lhs = 25,859,905,135 × 261,203,875 = 6,754,707,428,394,398,125
///   rhs = 16,717,047,991 × 404,061,018 = 6,754,707,429,198,314,838
///   residual = lhs − rhs = −803,916,713        (lhs < rhs ⇒ P_open > P_close)
///
/// The AMM therefore opens a hair ABOVE the curve close here. Relative size:
/// 803,916,713 / 6,754,707,429,198,314,838 = 1.190e-10, i.e. the price step is
/// +0.0000000119%. Asserted as `|residual| × 1e9 < rhs` — a relative gap below one
/// part in a billion — because that is a statement about the RATIO and survives any
/// re-derivation, whereas the raw residual alone does not.
test amm_open_price_matches_the_curve_close_at_the_ceiling() {
  let a = 16_717_047_991
  let lhs = ( virtual_ada_v3 + a ) * pool_bag_v3
  let rhs = a * curve_exhausted_token_reserve
  and {
    lhs == 6_754_707_428_394_398_125,
    rhs == 6_754_707_429_198_314_838,
    lhs - rhs == -803_916_713,
    // the Amm opens ABOVE the close at this end of the range
    lhs < rhs,
    // relative gap < 1e-9
    ( rhs - lhs ) * 1_000_000_000 < rhs,
  }
}

/// The SAME proof at the CANONICAL TWO-STEP CLOSE the validator suite uses, where
/// the sign is the other way round.
///
///   A = 16,717,047,886
///   lhs = 25,859,905,030 × 261,203,875 = 6,754,707,400,967,991,250
///   rhs = 16,717,047,886 × 404,061,018 = 6,754,707,386,771,907,948
///   residual = +14,196,083,302        (lhs > rhs ⇒ P_open < P_close)
///
/// 14,196,083,302 / 6,754,707,386,771,907,948 = 2.102e-09 ⇒ −0.00000021%.
/// Both signs are exercised on purpose: a one-sided test would let a future
/// re-derivation that inverts the inequality look correct.
test amm_open_price_matches_the_curve_close_at_the_two_step_close() {
  let a = 16_717_047_886
  let lhs = ( virtual_ada_v3 + a ) * pool_bag_v3
  let rhs = a * curve_exhausted_token_reserve
  and {
    lhs == 6_754_707_400_967_991_250,
    rhs == 6_754_707_386_771_907_948,
    lhs - rhs == 14_196_083_302,
    // the Amm opens BELOW the close at this end
    lhs > rhs,
    // relative gap < 1e-8
    ( lhs - rhs ) * 100_000_000 < rhs,
  }
}

/// THE WORST CASE THAT IS ACTUALLY REACHABLE, driven rather than asserted.
///
/// `buy_n_times` runs 100 buys of 150 ADA — the same driver
/// `close_drifts_far_below_the_window_over_many_trades` uses — and the best close
/// reachable from the resulting state is 16,717,046,058. The gap there is
/// −4.076e-06 %, still four orders of magnitude inside v2's −12.5%.
///
/// Bound asserted: relative gap < 1e-6 (one part per million).
test amm_open_price_gap_stays_tiny_after_a_hundred_trades() {
  let (a0, t0) = buy_n_times(0, virtual_token_v3, 150_000_000, 100)
  let k = ( a0 + virtual_ada_v3 ) * t0
  let a = k / curve_exhausted_token_reserve - virtual_ada_v3
  let lhs = ( virtual_ada_v3 + a ) * pool_bag_v3
  let rhs = a * curve_exhausted_token_reserve
  and {
    a == 16_717_046_058,
    lhs > rhs,
    ( lhs - rhs ) * 1_000_000 < rhs,
  }
}

/// The PESSIMISTIC BOUND ON DRIFT FROM *CLOSING BUYS*: 1,671 minimum-size buys is
/// the most a curve that closes at ~16,717 ADA can carry, and each destroys at most
/// `new_effective − 1 < 25,859,905,135` of k. Even at that bound the gap is
/// −0.000226%.
///
///   k_destroyed_max = 1,671 × 25,859,905,135 = 43,211,901,480,585
///   A               = (k0 − 43,211,901,480,585) / 404,061,018 − V = 16,716,941,047
///
/// Relative gap < 1e-5 asserted.
///
/// ── ██ IT IS NOT A THEOREM ABOUT ALL PATHS, AND THE NAME NOW SAYS SO. ██ ──────
/// An earlier version of this comment called the result "the number to quote when
/// anyone asks how big can the graduation price step get". THAT OVERCLAIMS, because
/// the premise counts only buys that ADVANCE the curve. ROUND TRIPS — buy 10 ADA,
/// sell the tokens straight back — do not advance it and are UNBOUNDED in number, and
/// each one destroys k twice: `quote_buy` floors the retained reserve and
/// `quote_sell_gross` floors `new_effective`. So no fixed trade count bounds A, and
/// this test bounds the CLOSING-BUY contribution only.
///
/// MEASURED, from the reachable mid-curve state (16,000,000,000, 415,584,415):
/// one 10 ADA round trip destroys 11,636,363,620 of k and moves the eventual closing
/// A down by exactly 28 lovelace — exactly the ADA leak, because the token side
/// returns to its starting value and only the reserve is short. Near the close the
/// per-round-trip leak is larger (up to the 64 lovelace pinned by
/// `sell_round_trip_leak_near_the_close_is_64_lovelace`) and near genesis the sell
/// cap swallows it (`sell_full_round_trip_hits_the_cap`).
///
/// THE REAL BOUND IS ECONOMIC, AND IT IS THE ONE TO QUOTE. Each 10 ADA round trip
/// pays 1.26 ADA of MANDATORY fees (0.50 flat each way + 1.30% each way) to move A by
/// 28–64 lovelace. So 1 ADA of A costs roughly 19,700–45,000 ADA of fees, paid to the
/// creator and to LumpFun, and the payoff is moving the graduated pool's opening
/// price by ~0.006% in the FIRST BUYER's favour. Breaking the 1e-5 bound asserted
/// here needs A about 472,821 lovelace below the zero-gap point — 7,400–16,900 round
/// trips, 9,300–21,300 ADA of fees — so the assertion is exceedable FOR MONEY by an
/// adversary who wants to and is worth nothing to them. A reconciler must not treat
/// −0.000226% as a hard floor; treat the ECONOMIC ratio as the bound.
test amm_open_price_gap_bound_from_closing_buys_only() {
  let k0 = virtual_ada_v3 * virtual_token_v3
  let destroyed = 1_671 * 25_859_905_135
  let a = ( k0 - destroyed ) / curve_exhausted_token_reserve - virtual_ada_v3
  let lhs = ( virtual_ada_v3 + a ) * pool_bag_v3
  let rhs = a * curve_exhausted_token_reserve
  and {
    destroyed == 43_211_901_480_585,
    a == 16_716_941_047,
    lhs > rhs,
    ( lhs - rhs ) * 100_000 < rhs,
  }
}

/// The DESIGN close price is exactly 64 lovelace/token, and the reachable ceiling
/// is NINE LOVELACE short of the reserve that would realise it.
///   pool_bag_v3 × 64 = 261,203,875 × 64 = 16,717,048,000
///   ceiling          =                     16,717,047,991      (−9)
/// So `A/pool_bag_v3` is `64 − 9/261,203,875` = 63.999999965544… , not 64. The
/// design number is a target the floor division cannot hit; the tests say so
/// rather than rounding it away.
test amm_open_price_is_nine_lovelace_short_of_the_design_sixty_four() {
  and {
    pool_bag_v3 * 64 == 16_717_048_000,
    16_717_048_000 - 16_717_047_991 == 9,
    // strictly below 64, and by less than one lovelace per token
    16_717_047_991 < pool_bag_v3 * 64,
    pool_bag_v3 * 64 - 16_717_047_991 < pool_bag_v3,
  }
}

/// THE FLIP MOVES NO TOKENS. The rebase 404,061,018 -> 261,203,875 changes the
/// NUMBER IN THE DATUM by exactly `token_offset_v3` and changes the pool's REAL
/// balance by ZERO. This is the identity that makes the rebase safe, and it is
/// what `with_graduation` encodes.
test graduation_rebase_moves_no_real_tokens() {
  and {
    real_tokens(curve_exhausted_token_reserve) == pool_bag_v3,
    curve_exhausted_token_reserve - pool_bag_v3 == token_offset_v3,
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// AMM ARITHMETIC
//
// The canonical graduated state, used throughout and RE-DERIVED here rather than
// asserted about literals:
//   A = 16,717,047,886   T = pool_bag_v3 = 261,203,875
//   k = 16,717,047,886 × 261,203,875 = 4,366,557,686,383,758,250
// ══════════════════════════════════════════════════════════════════════════════

/// k at the canonical graduated state, pinned once so every vector below can be
/// recomputed from it by hand.
test amm_k_at_graduation() {
  amm_k(16_717_047_886, pool_bag_v3) == 4_366_557_686_383_758_250
}

/// AmmBuy of exactly the 10 ADA minimum.
///   new_ada = 16,717,047,886 + 10,000,000 = 16,727,047,886
///   new_tok = 4,366,557,686,383,758,250 / 16,727,047,886 = 261,047,718
///   tokens_out = 261,203,875 − 261,047,718 = 156,157
test amm_buy_ten_ada() {
  amm_quote_buy(16_717_047_886, pool_bag_v3, 10_000_000) == 156_157
}

/// AmmBuy of 100 ADA.
///   new_ada = 16,817,047,886
///   new_tok = k / 16,817,047,886 = 259,650,666
///   tokens_out = 261,203,875 − 259,650,666 = 1,553,209
test amm_buy_hundred_ada() {
  amm_quote_buy(16_717_047_886, pool_bag_v3, 100_000_000) == 1_553_209
}

/// AmmBuy of 1,000 ADA — the vector the validator's accept case uses.
///   new_ada = 17,717,047,886
///   new_tok = k / 17,717,047,886 = 246,460,793
///   tokens_out = 261,203,875 − 246,460,793 = 14,743,082
test amm_buy_thousand_ada() {
  amm_quote_buy(16_717_047_886, pool_bag_v3, 1_000_000_000) == 14_743_082
}

/// The AMM's opening effective price for a 10 ADA buy is a hair ABOVE the close
/// price of ~64, as slippage requires — 10,000,000/156,157 = 64.038 lovelace per
/// token. If this ever came out BELOW 64 the flip would be handing buyers a
/// discount, which is exactly the v2 defect being removed.
///   156,157 × 64 = 9,994,048 < 10,000,000        ⇒ paid more than 64/token
test amm_buy_price_is_just_above_the_close_price() {
  let out = amm_quote_buy(16_717_047_886, pool_bag_v3, 10_000_000)
  out * 64 < 10_000_000
}

/// …and the FIRST AmmBuy is more expensive than the same-size buy would have been
/// on the curve one instant earlier. The curve's effective price for a 10 ADA buy
/// from (16,717,047,886, 404,061,018) is 10,000,000/156,190 = 64.0246, the AMM's
/// is 64.0381: the AMM is SHALLOWER because its k is built on real reserves, so
/// slippage per ADA is higher. That is a property of the design, not a defect —
/// and it means the flip never opens a buy-side arbitrage against the curve.
///   curve  tokens_out = 156,190
///   amm    tokens_out = 156,157   (33 fewer for the same 10 ADA)
///
/// ██ THIS TEST ALONE IS NOT A MEASUREMENT OF THE DEPTH STEP. ██ 10 ADA is the
/// SMALLEST legal trade and the size at which the effect is essentially invisible —
/// 33 tokens out of 156,190, or +0.021%. A regression that widened the depth step
/// could not be detected here. `amm_depth_step_by_trade_size` below carries the
/// realistic sizes and `amm_depth_step_k_ratio` pins the underlying constant.
test amm_is_shallower_than_the_curve_at_the_same_instant() {
  let on_curve = quote_buy(16_717_047_886, curve_exhausted_token_reserve, 10_000_000)
  let on_amm = amm_quote_buy(16_717_047_886, pool_bag_v3, 10_000_000)
  and {
    on_curve == 156_190,
    on_amm == 156_157,
    on_amm < on_curve,
    on_curve - on_amm == 33,
  }
}

/// ██ THE DEPTH STEP AT REALISTIC SIZES — the vectors an off-chain quoter needs. ██
///
/// Same instant, same A, same trade: what the curve would have paid out one block
/// before the flip against what the AMM pays one block after it. Each count is
/// re-derived from the two k values, not ported:
///
///   curve  k = (9,142,857,144 + 16,717,047,886) × 404,061,018
///            = 25,859,905,030 × 404,061,018
///          out = 404,061,018 − k/(25,859,905,030 + ada_in)
///   amm    k = 16,717,047,886 × 261,203,875 = 4,366,557,686,383,758,250
///          out = 261,203,875 − k/(16,717,047,886 + ada_in)
///
///     ada_in         curve_out      amm_out    fewer   effective-price penalty
///       100 ADA      1,556,482    1,553,209    3,273   +0.21073%
///     1,000 ADA     15,043,278   14,743,082  300,196   +2.03618%
///     5,000 ADA     65,466,990   60,137,980 5,329,010  +8.86131%
///
/// The penalties are asserted as RATIO BRACKETS rather than as floats, so they are
/// exact-integer statements that survive re-derivation: for the 1,000 ADA case,
/// 2036/100,000 < (curve−amm)/amm < 2037/100,000.
test amm_depth_step_by_trade_size() {
  let a = 16_717_047_886
  let c100 = quote_buy(a, curve_exhausted_token_reserve, 100_000_000)
  let m100 = amm_quote_buy(a, pool_bag_v3, 100_000_000)
  let c1k = quote_buy(a, curve_exhausted_token_reserve, 1_000_000_000)
  let m1k = amm_quote_buy(a, pool_bag_v3, 1_000_000_000)
  let c5k = quote_buy(a, curve_exhausted_token_reserve, 5_000_000_000)
  let m5k = amm_quote_buy(a, pool_bag_v3, 5_000_000_000)
  and {
    c100 == 1_556_482,
    m100 == 1_553_209,
    c1k == 15_043_278,
    m1k == 14_743_082,
    c5k == 65_466_990,
    m5k == 60_137_980,
    // the AMM is strictly shallower at every size
    m100 < c100,
    m1k < c1k,
    m5k < c5k,
    // …and the penalty GROWS with size, which is the property the 10 ADA vector
    // cannot see: 0.211% -> 2.036% -> 8.861%
    ( c100 - m100 ) * 100_000 > m100 * 210,
    ( c100 - m100 ) * 100_000 < m100 * 211,
    ( c1k - m1k ) * 100_000 > m1k * 2036,
    ( c1k - m1k ) * 100_000 < m1k * 2037,
    ( c5k - m5k ) * 100_000 > m5k * 8861,
    ( c5k - m5k ) * 100_000 < m5k * 8862,
  }
}

/// ██ THE DEPTH STEP AS A PINNED CONSTANT: k FALLS TO 41.78%, i.e. ÷2.39296. ██
///
/// The identity behind every vector above, so a retune that changed the step is
/// caught once rather than in six places:
///
///   k_curve = (V + A)·Xex = 25,859,905,030 × 404,061,018 = 10,448,979,551,805,120,540
///   k_amm   = A·P         = 16,717,047,886 × 261,203,875 =  4,366,557,686,383,758,250
///   k_curve / k_amm = ((V+A)/A) · (Xex/P) = 1.5469181644 × 1.5469181611 = 2.3929558
///
/// NOTE WHY THE TWO FACTORS ARE NEARLY IDENTICAL: `(V+A)/A == Xex/P` is EXACTLY the
/// continuity condition `(V+A)·P == A·Xex` restated. So marginal-price continuity and
/// "the depth step is the square of the reserve ratio" are the same fact seen twice,
/// and sqrt(2.3929558) = 1.5469182 is the per-ADA slippage multiplier. That is why
/// the step is ~1.547 and not some independent number.
test amm_depth_step_k_ratio() {
  let a = 16_717_047_886
  let k_curve = ( virtual_ada_v3 + a ) * curve_exhausted_token_reserve
  let k_amm = a * pool_bag_v3
  and {
    k_curve == 10_448_979_551_805_120_540,
    k_amm == 4_366_557_686_383_758_250,
    // the AMM carries strictly less k
    k_amm < k_curve,
    // 41.78% of it: 4178/10,000 < k_amm/k_curve < 4179/10,000
    k_amm * 10_000 > k_curve * 4_178,
    k_amm * 10_000 < k_curve * 4_179,
    // equivalently k_curve/k_amm = 2.39295…
    k_amm * 23_929 < k_curve * 10_000,
    k_curve * 10_000 < k_amm * 23_930,
  }
}

/// ██ THE SELL SIDE OF THE SAME STEP — where a HOLDER notices it. ██
///
/// There was no sell-side statement of the depth step at all, and the sell side is
/// the one that generates the complaint: selling one block AFTER graduation returns
/// materially less than selling one block BEFORE it, at an identical displayed
/// marginal price. The price feed is continuous to 2.1e-09 while the depth more than
/// halves, so the two observations look contradictory unless both are written down.
///
///   tokens_in      curve_gross        amm_gross        less by
///     1,000,000     63,841,999       63,755,915        86,084   (0.135%)
///   100,000,000  5,130,312,424    4,628,147,438   502,164,986   (9.788%)
///
/// The 100,000,000 vector is the one `validate_amm_sell`'s canonical accept case
/// uses, so this ties the depth statement to the number the validator suite trades on.
test amm_depth_step_on_the_sell_side() {
  let a = 16_717_047_886
  let c1m = quote_sell_gross(a, curve_exhausted_token_reserve, 1_000_000)
  let m1m = amm_quote_sell_gross(a, pool_bag_v3, 1_000_000)
  let c100m = quote_sell_gross(a, curve_exhausted_token_reserve, 100_000_000)
  let m100m = amm_quote_sell_gross(a, pool_bag_v3, 100_000_000)
  and {
    c1m == 63_841_999,
    m1m == 63_755_915,
    c100m == 5_130_312_424,
    m100m == 4_628_147_438,
    // the AMM pays strictly less for the same tokens, at both sizes
    m1m < c1m,
    m100m < c100m,
    // 0.13484% and 9.78820% of the curve's gross, bracketed exactly
    ( c1m - m1m ) * 100_000 > c1m * 134,
    ( c1m - m1m ) * 100_000 < c1m * 135,
    ( c100m - m100m ) * 100_000 > c100m * 9_788,
    ( c100m - m100m ) * 100_000 < c100m * 9_789,
  }
}

/// AmmSell of 1,000,000 tokens.
///   new_tok = 261,203,875 + 1,000,000 = 262,203,875
///   new_ada = k / 262,203,875 = 16,653,291,971
///   gross = 16,717,047,886 − 16,653,291,971 = 63,755,915
test amm_sell_one_million_tokens() {
  amm_quote_sell_gross(16_717_047_886, pool_bag_v3, 1_000_000) == 63_755_915
}

/// AmmSell of 100,000,000 tokens — the vector the validator's accept case uses.
///   new_tok = 361,203,875
///   new_ada = k / 361,203,875 = 12,088,900,448
///   gross = 16,717,047,886 − 12,088,900,448 = 4,628,147,438
test amm_sell_hundred_million_tokens() {
  amm_quote_sell_gross(16_717_047_886, pool_bag_v3, 100_000_000) == 4_628_147_438
}

/// k is NON-INCREASING on the AMM buy path too, same rounding, same warning.
///   k_old = 4,366,557,686,383,758,250
///   k_new = 16,727,047,886 × 261,047,718 = 4,366,557,679,517,024,148
///   delta = −6,866,734,102
test amm_buy_k_is_non_increasing() {
  let out = amm_quote_buy(16_717_047_886, pool_bag_v3, 10_000_000)
  let k_new = amm_k(16_727_047_886, pool_bag_v3 - out)
  let k_old = amm_k(16_717_047_886, pool_bag_v3)
  k_new <= k_old && k_new - k_old == -6_866_734_102
}

/// The AMM round-trip leak, measured rather than assumed: buy 10 ADA, sell every
/// token back, receive 10,000,027 — 27 lovelace more than was paid in, from the
/// buy's k-drift exactly as on the curve. Against ≥1.13 ADA of mandatory fees on
/// the pair that is a 41,000:1 loss, so it is not grindable. PRICE ANY FUTURE FEE
/// RELAXATION AGAINST 27, not against 1.
test amm_round_trip_leak_is_27_lovelace() {
  let out = amm_quote_buy(16_717_047_886, pool_bag_v3, 10_000_000)
  let gross = amm_quote_sell_gross(16_727_047_886, pool_bag_v3 - out, out)
  and {
    out == 156_157,
    gross == 10_000_027,
    gross - 10_000_000 == 27,
  }
}

/// …and the leak on a 1,000 ADA round trip is 57 lovelace, i.e. it does NOT scale
/// with trade size (it is one token's worth of ADA, and price moves less than
/// linearly). Bounded, and pinned so a fee change can be priced.
test amm_round_trip_leak_does_not_scale_with_size() {
  let out = amm_quote_buy(16_717_047_886, pool_bag_v3, 1_000_000_000)
  let gross = amm_quote_sell_gross(17_717_047_886, pool_bag_v3 - out, out)
  and {
    gross == 1_000_000_057,
    gross - 1_000_000_000 == 57,
  }
}

/// ██ THE AMM CANNOT BE DRAINED OF ADA. ██
///
/// The largest sell that can ever be presented is the entire float outside the
/// pool. At graduation that is `sellable_v3` = 738,796,125, and dumping ALL of it
/// leaves the pool holding 4,366,557,686 lovelace = 4,366.56 ADA and the whole
/// 1e9 supply.
///
///   new_tok = 261,203,875 + 738,796,125 = 1,000,000,000 = total_supply_v3
///   new_ada = k / 1e9 = 4,366,557,686
///   gross   = 16,717,047,886 − 4,366,557,686 = 12,350,490,200
///
/// So the solvency cap in `amm_quote_sell_gross` NEVER binds on a genuine pool,
/// and "liquidity is locked for life" is not merely the absence of a withdraw
/// redeemer — the arithmetic keeps a floor under the pool that no volume of
/// selling can remove.
///
/// ── ██ THE FLIP SIDE, STATED SO NOBODY REPORTS IT AS A BUG: 26.12% OF THE RAISE
///        IS PERMANENTLY UNREACHABLE, AND IT IS NOT A TUNING PARAMETER. ██ ──────
/// The floor is `k / total_supply_v3 = A · pool_bag_v3 / total_supply_v3`, so as a
/// FRACTION of the raise it is exactly `pool_bag_v3 / total_supply_v3` =
/// 261,203,875 / 1,000,000,000 = 26.1203875% — independent of A, and equal to the
/// pool-bag fraction by construction rather than by coincidence. NO HOLDER CAN EVER
/// RECOVER THAT ADA: there is no withdraw path (deliberately), so 4,366.56 ADA of a
/// 16,717 ADA raise is locked in the pool forever.
///
/// That is the accepted price of "rug-proof", not a defect, and it cannot be tuned
/// down without shrinking `pool_bag_v3` — which would reintroduce v2's price gap at
/// the flip, since the bag is exactly what closes it. The two properties are the same
/// number seen from two sides. Asserted below as a derived identity so the percentage
/// is never re-hardcoded as a literal.
test amm_sell_of_the_whole_float_leaves_4366_ada() {
  let gross = amm_quote_sell_gross(16_717_047_886, pool_bag_v3, sellable_v3)
  let a = 16_717_047_886
  let left = a - gross
  and {
    pool_bag_v3 + sellable_v3 == total_supply_v3,
    gross == 12_350_490_200,
    left == 4_366_557_686,
    // the pool keeps more than 4,000 ADA no matter what
    left > 4_000_000_000,
    // ── the locked FRACTION is `pool_bag_v3 / total_supply_v3`, DERIVED ────────
    // left == A · P / S (floored), so left/A == P/S == 26.1203875%. Cross-multiplied
    // to stay in integers and bracketed by one part in 1e8, because the floor on
    // `k / total_supply_v3` loses a fraction of a lovelace:
    left * 100_000_000 > a * 26_120_387,
    left * 100_000_000 < a * 26_120_388,
    // ██ AND THE IDENTICAL BRACKET HOLDS FOR pool_bag_v3 / total_supply_v3. ██
    // That is the content of the claim: the permanently-locked share of the raise IS
    // the pool-bag share of the supply, not an independent number that happens to be
    // close to it. Shrink the bag and this shrinks with it — along with the bag's
    // ability to close the price gap at the flip.
    pool_bag_v3 * 100_000_000 > total_supply_v3 * 26_120_387,
    pool_bag_v3 * 100_000_000 < total_supply_v3 * 26_120_388,
  }
}

/// ██ AND IT CANNOT BE DRAINED OF TOKENS. ██
///
/// Spending the ENTIRE ADA SUPPLY (45e9 ADA = 4.5e16 lovelace) on one AmmBuy
/// leaves 97 tokens in the pool.
///   new_ada = 16,717,047,886 + 45,000,000,000,000,000 = 45,000,016,717,047,886
///   new_tok = k / new_ada = 97
/// Non-zero, so `token_reserve >= 1` holds on any reachable state — but the
/// validator asserts it anyway, because a self-seeded pool graduated at
/// `ada_reserve = 1` has k = 261,203,875 and this bound does not apply to it.
test amm_buy_cannot_empty_the_token_side() {
  let out = amm_quote_buy(16_717_047_886, pool_bag_v3, 45_000_000_000_000_000)
  and {
    pool_bag_v3 - out == 97,
    pool_bag_v3 - out >= 1,
  }
}

/// ██ THE FLOOR-DIVISION EDGE, MEASURED. ONE LOVELACE BUYS ONE WHOLE TOKEN. ██
///
/// This is NOT what a reviewer expects and the first version of this test asserted
/// the opposite ("63 lovelace buys nothing"), which is FALSE. Re-derived:
/// `new_tok = k / (A + ada_in)` and `k = A·P`, so
/// `k/(A+1) = P − P/(A+1) = 261,203,875 − 0.0156…`, whose FLOOR is `P − 1`. Any
/// `ada_in >= 1` therefore yields at least one token — worth ~64 lovelace — because
/// the floor lands on the reserve the pool RETAINS (`amm_quote_buy`'s doc comment).
///
/// It is the AMM twin of the curve's documented k-drift, and its worst case is the
/// same: one token per transaction. Two things make it unreachable and a third
/// makes it unprofitable even if they were removed:
///   • `AmmBuy` requires `ada_in >= min_trade_ada_v3` (10 ADA) with NO exemption —
///     the curve's closing-buy exemption has no analogue because the AMM never
///     closes.
///   • `platform_fee_flat_v3` is 500,000 lovelace per trade, ~7,800× the value of
///     the token extracted.
///   • the ledger's own min-fee on the transaction is another ~170,000 lovelace.
/// PINNED so that if the minimum is ever relaxed this is a known quantity rather
/// than a discovery.
test amm_buy_of_one_lovelace_still_returns_one_token() {
  and {
    amm_quote_buy(16_717_047_886, pool_bag_v3, 1) == 1,
    amm_quote_buy(16_717_047_886, pool_bag_v3, 63) == 1,
    // …and the flat platform fee alone is ~7,800 times the 64 lovelace extracted
    500_000 > 64 * 7_800,
  }
}

/// A one-token AmmSell returns 63 lovelace gross — less than the 500,000 flat
/// platform fee, so `sell_net` is negative and the trade is self-limiting without
/// a minimum. This is the same reasoning that removed the curve's sell-side
/// minimum; it applies unchanged here.
///   new_tok = 261,203,876 ; new_ada = k / 261,203,876 = 16,717,047,822
///   gross = 64
test amm_sell_of_one_token_is_priced_out_by_the_flat_fee() {
  let gross = amm_quote_sell_gross(16_717_047_886, pool_bag_v3, 1)
  gross == 64 && gross < 500_000
}

// ── G0 / G3 as pure arithmetic ───────────────────────────────────────────────
//
// `lump_pool.validate_graduate` CALLS `graduation_curve_checks`, so every test
// below is coverage of a reachable path.

/// The state a real graduation reaches by the two-step path used in the pool
/// validator's cap section: a 16,000 ADA genesis buy, then a 717,047,886 lovelace
/// closing buy.
test graduation_checks_accept_the_two_step_close() {
  graduation_curve_checks(16_717_047_886, curve_exhausted_token_reserve)
}

/// …and the other end of the reachable range, the one-shot ceiling.
test graduation_checks_accept_the_one_shot_ceiling() {
  graduation_curve_checks(16_717_047_991, curve_exhausted_token_reserve)
}

/// G0/G3 — one token short of exhaustion, and one token past it. (Both clauses
/// fire; they are the same condition, as the doc comment says.)
test graduation_checks_reject_off_by_one_token_reserves() {
  and {
    !graduation_curve_checks(16_717_047_879, curve_exhausted_token_reserve + 1),
    !graduation_curve_checks(16_717_047_886, curve_exhausted_token_reserve - 1),
  }
}

/// A LIVE curve — the C-1 skim — is not graduable.
test graduation_checks_reject_a_live_curve() {
  !graduation_curve_checks(1_000_000_000, 1_030_181_086)
}

/// ██ G3's `ada_reserve >= 1`, ISOLATED. ██
///
/// A closed curve with an EMPTY ADA reserve must not be graduable: the resulting
/// Amm pool would have k = 0, price 0, and 261,203,875 real tokens that can never
/// be bought or sold. `ada_reserve >= 1` is the only clause rejecting it (G0 and
/// G3's bag identity are both satisfied), so this is its isolating test.
test graduation_checks_reject_an_empty_ada_reserve() {
  and {
    !graduation_curve_checks(0, curve_exhausted_token_reserve),
    !graduation_curve_checks(-1, curve_exhausted_token_reserve),
    // …and one lovelace is enough to pass THIS check (the pool floor is the
    // ledger's problem, not this function's)
    graduation_curve_checks(1, curve_exhausted_token_reserve),
  }
}
