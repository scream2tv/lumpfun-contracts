use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Credential}
use cardano/assets.{Value, flatten, lovelace_of, quantity_of, tokens}
use cardano/transaction.{
  DatumHash, InlineDatum, Input, Output, OutputReference, Transaction,
}
use lumpfun/fees_v3.{creator_fee_paid, platform_fee_paid, sell_net}
use lumpfun/math_v3.{
  amm_quote_buy, amm_quote_sell_gross, curve_open, graduation_curve_checks,
  quote_buy, quote_sell_gross,
}
use lumpfun/params_v3.{
  curve_exhausted_token_reserve, platform_fee_bps_v3, platform_fee_flat_v3,
  pool_bag_v3, pool_floor_v3, token_offset_v3, total_supply_v3,
  treasury_pkh_v3, virtual_token_v3,
}
use lumpfun/pool_types.{
  Amm, AmmBuy, AmmSell, Bootstrap, Buy, Graduate, PoolDatum, PoolDatumV3,
  PoolMode, PoolRedeemer, ReservedV2Slot, Sell, pool_nft_name, with_graduation,
  with_reserves,
}
use lumpfun/test_helpers.{
  ada, ada_token, input_of, oref, pk_out, pk_out_token, script_out,
  script_out_staked,
}

// ══════════════════════════════════════════════════════════════════════════════
// LumpFun v3 pool validator — UNPARAMETERISED, TWO MODES, ONE ADDRESS
//
// One shared reference script and ONE address for every LumpFun v3 token (§5.6),
// across BOTH halves of a token's life:
//
//   Bootstrap  the virtual-reserve bonding curve.   `Buy`   / `Sell`
//   Graduate   the one-way flip, IN PLACE.          `Graduate`
//   Amm        LumpFun's own permanent pool.        `AmmBuy`/`AmmSell`, forever
//
// ══════════════════════════════════════════════════════════════════════════════
// ██  THE SPLASH PATH WAS BUILT, PROVEN, AND PARKED. DO NOT RE-DERIVE IT.    ██
// ══════════════════════════════════════════════════════════════════════════════
//
// Between 2026-07-25 and 2026-07-26 this branch graduated LumpFun tokens into a
// SPLASH royaltyPool: it destroyed the curve UTxO, burned the pool NFT via a
// `Retire` redeemer on `lump_mint_v3`, minted Splash's pool-NFT and LQ assets under
// their own one-shot policies with names derived as
// `sha2_256(H ‖ ser(i) ‖ ser(emission))`, verified a caller-supplied integer square
// root `lq0` against a strict bracket, and built a fifteen-field `RoyaltyPoolConfig`
// birth datum naming an always-fail DAOPolicy (`H_fail = 22c9a103…`) so that
// Splash's `DAOAction` could never execute against LumpFun's reserves. It was
// complete: §5.5's G0..G13, 290 green checks, 115 mutverify cases with 0 problems,
// a passing hash gate, and every Splash-side claim reproduced against the DEPLOYED
// mainnet bytecode through Ogmios `evaluateTransaction` on the local node (the
// `cb684a69` pool script, `d8eb52ca` NFT policy and `6e917b8b` mint-identifier
// policy) rather than inferred from the Plutarch sources. THE USER PARKED IT ON
// 2026-07-26 in favour of graduating into LumpFun's own permanent AMM. It was
// deleted rather than commented out — `lib/lumpfun/splash_v3.ak` and
// `validators/lumpfun_dao_fail.ak` are gone, along with `isqrt_ok`, `lq_mint_of`,
// `max_lq_cap`, `MintRedeemer.Retire` and the `H_fail` line in `hashes.expected`.
// It is recoverable in full from git history at the Phase-2 commit. Nobody needs to
// re-derive any of it, and nobody should re-introduce a foreign venue without
// re-reading why the four-entry value equality (G9) was the single most important
// line in that design.
//
// ── WHY THE IN-PLACE FLIP IS BETTER THAN v2's, NOT MERELY SIMPLER ────────────
// v2 also flips in place (contracts/cardano/validators/lump_pool.ak:176-181) and
// pays for it with a price gap of exactly `1/sqrt(m)` — −12.50% at m = 64, −35.36%
// at m = 8 — because it zeroes the ADA offset while leaving the token side alone.
// v3's PRE-ALLOCATED POOL BAG removes the gap instead of the offset: at curve close
// the pool's REAL balances are already `(ada_reserve, pool_bag_v3)`, and
// `ada_reserve / pool_bag_v3` IS the curve's closing marginal price to within a few
// parts in 1e10. The graduated pool therefore opens where the curve closed.
//
// IT IS NOT BIT-EXACT AND THE TESTS DO NOT CLAIM IT IS. The zero-gap reserve is
// `virtual_ada_v3 × pool_bag_v3 / token_offset_v3 = 16,717,047,985.372…`, which is
// not a whole number of lovelace, and the actual closing reserve is path-dependent.
// Measured range of the price step: +1.19e-08 % at the one-shot ceiling to
// −2.26e-04 % at the pessimistic k-drift bound. See `math_v3`'s
// `amm_open_price_matches_the_curve_close_*` block for the exact-integer proof, both
// signs, and the residuals.
//
// ── WHAT v3 STILL DOES NOT HAVE ─────────────────────────────────────────────
//   • `mode_offset`. v2 needs a function mapping mode -> ADA offset. v3's Amm runs
//     at offset 0 on BOTH sides, so `mode` selects a value INVARIANT and a QUOTE
//     FUNCTION and nothing else. There is no arithmetic offset keyed on mode
//     anywhere in this file.
//   • `BatchSpend`, the order book, `order_book_hash`, R-1's gross-volume
//     reconstruction, R-2's per-order fee multiplier, `fee_accumulator` — deleted
//     with the order book, and D-2's whole defect class with them.
//   • `graduation_ada` and `cap_ok`-on-ADA. The v3 curve terminates in TOKEN space:
//     `Buy` requires `new_d.token_reserve >= curve_exhausted_token_reserve` and
//     `Graduate` requires EQUALITY. No ADA threshold, no overshoot, no clamp, and
//     therefore none of §3.1's permanent-freeze deadlock.
//   • ██ ANY WITHDRAW / REMOVE-LIQUIDITY BRANCH. ██ The graduated pool's liquidity
//     is LOCKED FOR LIFE, exactly as v2 documents at
//     contracts/cardano/validators/lump_pool.ak:25-28. No LP token, no admin key,
//     no timelock, no migration path. The ONLY ways lovelace leaves an `Amm` pool
//     are `AmmSell` at the pool's own price and nothing else — the fee outputs are
//     surcharges paid by the trader and never come out of the reserve. DO NOT ADD
//     ONE. And note the arithmetic backs it up rather than merely permitting it:
//     dumping 100% of the float into the pool still leaves 4,366 ADA in it
//     (`math_v3.amm_sell_of_the_whole_float_leaves_4366_ada`).
//   • every script parameter. Those facts live in the datum and are frozen by
//     whole-datum reconstruction on every branch (R-5) — see below.
//
// ── R-5 (Critical), stated once so it is not lost in a refactor ───────────────
// Because the pool is unparameterised, `royalty_pub_key`, `creator_pkh`,
// `treasury_pkh`, the fee schedule and now `mode` live in the DATUM. In v2 no
// branch constrained any datum field beyond the reserves
// (`lump_pool.ak:328-379`). Port that shape here and a 10 ADA trade rewrites the
// continuation. EVERY branch that produces a continuation datum therefore asserts
// a WHOLE-DATUM equality against a reconstruction helper. There are TWO, and
// exactly two, because `mode` must change exactly once ever:
//
//     with_reserves(d, new_ada, new_tok) == new_d      Buy, Sell, AmmBuy, AmmSell
//         — two fields move, NINE are frozen, `mode` among them.
//     with_graduation(d) == new_d                      Graduate, and only Graduate
//         — `mode` -> `Amm` and `token_reserve` -> `pool_bag_v3`, both HARDCODED;
//           `ada_reserve` carried; the other nine frozen.
//
// This is non-negotiable: §5.6 says if it is skipped, keep the pool parameterised.
// And `mode` being in the FROZEN set on all four trade branches is what makes the
// flip one-way — see `pool_types.with_reserves`.
//
// ── THE VALUE INVARIANT DEPENDS ON `mode`. BOTH FORMS, ON EVERY BRANCH ───────
//   Bootstrap:  lovelace_of(value) == ada_reserve + pool_floor_v3
//               quantity_of(value, policy_id, asset_name)
//                                 == token_reserve − token_offset_v3
//   Amm:        lovelace_of(value) == ada_reserve            (NO floor)
//               quantity_of(value, policy_id, asset_name)
//                                 == token_reserve           (NO offset)
//   both:       quantity_of(value, policy_id, pool_nft_name) == 1
//               length(flatten(value)) == 3    ← the pool holds NOTHING ELSE
//
// Both substitutions must be applied together and CONSISTENTLY WITH `mode`.
// Applying Bootstrap's substitutions to an Amm pool understates its token balance
// by 142,857,143 and overstates its lovelace by 2,500,000; applying Amm's to a
// Bootstrap pool does the reverse. That is why `value_matches` takes `mode` and
// why the four cross-mode rejects exist.
//
// ── WHAT `authentic` DOES AND DOES NOT PROVE ─────────────────────────────────
// The pool is unparameterised and reads `policy_id` from its own datum, so the
// NFT check proves "this UTxO holds the NFT its OWN datum names" — NOT "this
// UTxO is token X's pool", and NOT "this pool was ever launched by
// `lump_mint_v3`". An earlier version of this header framed that residual purely
// as an off-chain SELECTION problem. It was more than that: arbitrary pools could
// be CREATED at, and traded through, LumpFun's one and only address, with any
// datum config the author liked including a zero platform fee.
//
// `fee_schedule_ok` now pins the PLATFORM side of the schedule at spend time on ALL
// FOUR trade branches, so a self-seeded pool cannot trade here fee-free in either
// half of its life. The creator side stays free by design. Off-chain selection MUST
// STILL match `policy_id` against the registry — §8.3's "recompute, never scan",
// with no fallback to asset matching — because nothing on-chain distinguishes two
// genuine LumpFun tokens from each other at a shared address. See
// `hashes.expected` for the canonical pool hash the recompute needs and the note on
// storing each token's seed OutputReference.
//
// ── AND ONE THING THE IN-PLACE FLIP MAKES *STRONGER* THAN THE SPLASH PATH ────
// Under the Splash design the pool NFT was BURNED at graduation, so
// `authentic` was satisfiable only during the curve's life and the graduated
// venue authenticated itself by Splash's own one-shot NFT. Now the LumpFun NFT is
// NEVER burned (`lump_mint_v3` has no burn path at all) and it authenticates the
// pool for the token's entire life, in both modes, under one address. That is what
// makes §2.1's "one address to give an aggregator" true for the graduated pool too.
// ══════════════════════════════════════════════════════════════════════════════

validator lump_pool_v3 {
  spend(
    datum: Option<PoolDatum>,
    redeemer: PoolRedeemer,
    utxo: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum
    expect PoolDatumV3 {
      policy_id,
      asset_name,
      ada_reserve,
      token_reserve,
      mode,
      ..
    } = d

    expect Some(own_input) =
      list.find(tx.inputs, fn(i) { i.output_reference == utxo })

    expect Credential.Script(own_hash) =
      own_input.output.address.payment_credential

    // R-3 — confine the tx shape on EVERY path. Exactly one pool UTxO may be
    // spent and no other script may be spent alongside it. This matters MORE in
    // v3 than v2: the pool is unparameterised, so every LumpFun token shares one
    // address and two different tokens' pools could otherwise sit in one tx and
    // be satisfied by a single shared treasury/creator output. The existential
    // fee checks in fees_v3 are exact ONLY because of this. It is also what makes
    // the V-1 double-satisfaction shape unconstructible in BOTH modes and on
    // `Graduate` — two pools graduating in one transaction would each release a
    // `pool_floor_v3` bounty against one `sole_continuation` check.
    let shape_ok = tx_shape_ok(tx.inputs, own_hash)

    // The spent UTxO must carry the 1-of-1 pool NFT of the policy its own datum
    // names. Sitting at the pool address and holding a token is NOT proof of
    // being the pool — anyone can park a self-consistent decoy at the shared
    // address, and a buyer routed to it would pay real ADA for nothing with
    // `min_out` quoted from the decoy itself.
    //
    // RESIDUAL, stated honestly: `policy_id` comes from the datum, so this says
    // "this UTxO holds the NFT its datum claims" — NOT "this UTxO is token X's
    // pool", and NOT "this pool was launched by `lump_mint_v3`".
    //
    // The second of those gaps is now partly closed on-chain: `fee_schedule_ok`
    // in all four trade branches pins `treasury_pkh` to the cohort constant and
    // floors the two platform fee levels, so a SELF-SEEDED pool parked at this
    // shared address can no longer trade fee-free in either mode.
    //
    // The FIRST gap is irreducible on-chain and remains: two genuine LumpFun
    // tokens are not distinguishable from each other here. Off-chain selection
    // MUST match `policy_id` against the registry — §8.3's "recompute, never
    // scan", with NO fallback to asset matching. `lump_mint_v3.pool_seeded` pins
    // `d.policy_id` to the minting policy's own id at genesis, and
    // `with_reserves`/`with_graduation` freeze it thereafter, so the genuine pool
    // for policy P always carries `policy_id == P` — for life, now that the NFT is
    // never burned.
    let authentic =
      quantity_of(own_input.output.value, policy_id, pool_nft_name) == 1

    // V-6 — the datum must mirror the pool UTxO's REAL value on the way in, under
    // the invariant its OWN `mode` selects.
    let in_consistent =
      value_matches(
        mode,
        own_input.output.value,
        policy_id,
        asset_name,
        ada_reserve,
        token_reserve,
      )

    let branch_ok =
      when redeemer is {
        Buy { min_out } -> validate_buy(d, min_out, own_input, own_hash, tx)
        Sell { min_out } -> validate_sell(d, min_out, own_input, own_hash, tx)
        Graduate -> validate_graduate(d, own_input, tx)
        AmmBuy { min_out } ->
          validate_amm_buy(d, min_out, own_input, own_hash, tx)
        AmmSell { min_out } ->
          validate_amm_sell(d, min_out, own_input, own_hash, tx)
      }

    shape_ok && authentic && in_consistent && branch_ok
  }

  else(_) {
    fail
  }
}

// ── Shared primitives ─────────────────────────────────────────────────────────

/// ██ THE VALUE INVARIANT, AND THE ONLY PLACE THE TWO OFFSETS APPEAR. ██
///
/// `Bootstrap`: `ada_reserve` EXCLUDES `pool_floor_v3` and `token_reserve` is
/// VIRTUAL, so both offsets appear.
/// `Amm`: BOTH ARE ZERO. That is the entire content of graduation — the pool's
/// balances stop being described in offset terms and start being described
/// directly.
///
/// Written as two literal statements rather than as `ada_reserve + offset(mode)`
/// on purpose. An offset-selector function would put the two substitutions one
/// tuple-position apart, and swapping them silently is worth 10,000,000 lovelace
/// and 142,857,143 tokens. Two arms, four comparisons, nothing to transpose.
fn value_matches(
  mode: PoolMode,
  v: Value,
  policy_id: ByteArray,
  asset_name: ByteArray,
  ada_reserve: Int,
  token_reserve: Int,
) -> Bool {
  when mode is {
    Bootstrap ->
      lovelace_of(v) == ada_reserve + pool_floor_v3 && quantity_of(
        v,
        policy_id,
        asset_name,
      ) == token_reserve - token_offset_v3
    Amm ->
      lovelace_of(v) == ada_reserve && quantity_of(v, policy_id, asset_name) == token_reserve
  }
}

fn at_script(i: Input, hash: ByteArray) -> Bool {
  when i.output.address.payment_credential is {
    Credential.Script(h) -> h == hash
    Credential.VerificationKey(_) -> False
  }
}

/// R-3 — exactly one pool UTxO is spent, and NO other script input exists.
/// Wallet inputs are unrestricted (the trader funds the fee outputs and
/// collateral from their own wallet).
///
/// v2 additionally allowed order_book inputs here. v3 has no order book, so the
/// exception is gone and the rule is simply "one pool, no foreign scripts".
/// Accepted restriction, unchanged from v2: a user trading from a script wallet
/// is blocked, and a pool spend cannot be composed with any other contract.
///
/// THIS IS ALSO THE ANSWER TO V-1 (double satisfaction) ON ALL FIVE BRANCHES.
/// `one_pool == 1` counts inputs at the pool's own script hash, and every LumpFun
/// v3 pool — Bootstrap or Amm, any token — sits at that one hash. So two pools can
/// never appear in one transaction, which is what makes the existential fee checks
/// exact and what stops two graduations sharing one bounty accounting.
fn tx_shape_ok(inputs: List<Input>, own_hash: ByteArray) -> Bool {
  let one_pool = list.count(inputs, fn(i) { at_script(i, own_hash) }) == 1
  let confined =
    list.all(
      inputs,
      fn(i) {
        when i.output.address.payment_credential is {
          Credential.Script(h) -> h == own_hash
          Credential.VerificationKey(_) -> True
        }
      },
    )
  one_pool && confined
}

/// The pool NFT must remain in the continuation output. Without this a trade
/// could carry the NFT out to the trader's wallet, after which the pool UTxO can
/// never be spent again — a cheap way to brick a token permanently. It applies to
/// `Graduate` too: the flip is in place, so the NFT stays.
fn pool_nft_kept(own_output: Output, policy_id: ByteArray) -> Bool {
  quantity_of(own_output.value, policy_id, pool_nft_name) == 1
}

/// Exactly one output at the pool's own PAYMENT CREDENTIAL.
///
/// ── IT FILTERS ON THE CREDENTIAL, NOT THE FULL ADDRESS. DELIBERATE. ─────────
/// This used to filter on `o.address == own_input.output.address`. The production
/// address is an ENTERPRISE script address with no stake part (CIP-19 type 7), so
/// `own_input.output.address` is `Address { Script(h), None }` and an output at
/// `Address { Script(h), Some(Inline(VerificationKey(anything))) }` is a DIFFERENT
/// `Data` value: it was invisible to the filter and could ride along in any
/// transaction. The Splash-path review found and fixed exactly this on G12's
/// "nothing left at the curve script" check; the same correction belongs here,
/// where it now covers all five branches instead of one.
///
/// It only ever SHRINKS the accepted set — no legitimate transaction pays to
/// LumpFun's pool script credential except the continuation itself — and it closes
/// two things at once: junk parked at §2.1's sole on-chain identifier, and a decoy
/// UTxO at the pool credential that an off-chain selector filtering by ADDRESS
/// PREFIX (rather than by NFT) would pick up.
///
/// `continuation_address_exact` below then pins the stake part, so the ONE output
/// at the credential must be at the exact same address the pool was spent from.
/// Splitting the two makes each independently mutable and independently bound.
fn sole_continuation(own_input: Input, tx: Transaction) -> Output {
  expect [own_output] =
    list.filter(
      tx.outputs,
      fn(o) {
        o.address.payment_credential == own_input.output.address.payment_credential
      },
    )
  own_output
}

/// …and that output must be at the EXACT address, staking part included.
///
/// A pool that acquires a stake credential mid-life would earn staking rewards on
/// up to ~16,717 ADA of other people's money for whoever attached it, and would
/// make the curve address non-unique — which §2.1's "one address to give an
/// aggregator" depends on. `lump_mint_v3.bare_address_ok` refuses it at genesis;
/// this refuses it on every spend thereafter, in both modes.
fn continuation_address_exact(own_input: Input, own_output: Output) -> Bool {
  own_output.address == own_input.output.address
}

/// ██ NO REFERENCE SCRIPT ON THE POOL UTxO. EVER, ON ANY BRANCH, IN EITHER MODE. ██
///
/// ── IT USED TO BE ASSERTED IN TWO PLACES AND NEEDED FIVE. ───────────────────
/// `lump_mint_v3.no_ref_script_ok` refuses one on the GENESIS pool output and
/// `validate_graduate` refused one at the FLIP, and those were the only two
/// assertions in the project. The four TRADE branches did not check it, which left
/// the harm the graduation comment already describes fully reachable — and reachable
/// REPEATEDLY, on the branch pair that runs forever.
///
/// WHY IT IS HARM AND NOT UNTIDINESS. Under Conway a transaction is charged
/// `minFeeRefScriptCoinsPerByte` (tier 1 = 15 lovelace/byte, ×1.2 per 25 KiB) over
/// the reference scripts attached to its RESOLVED INPUTS — so the script is welded
/// on by one trader and paid for by the NEXT one, and by every one after them. It
/// also inflates the pool output's own min-UTxO deposit, because `coinsPerUTxOByte`
/// is charged over the serialised output with the reference script inside it. That
/// second effect bites harder in `Amm` mode than on the curve for exactly the reason
/// `value_shape_ok` gives about junk assets: an `Amm` pool's lovelace is pinned to
/// `ada_reserve` with NO `pool_floor_v3` cushion beside it, so a raised min-UTxO can
/// make a large sell UNBUILDABLE at the ledger layer with the reserve still inside.
///
/// IT WAS ONLY EVER "SELF-HEALING" BY THE GRACE OF THE TRANSACTION BUILDER. Nothing
/// on-chain removed it; it merely failed to persist if every subsequent builder
/// happened to omit it. That made LumpFun's own off-chain continuation builder
/// load-bearing — a `{ ...utxo, datum, assets }`-style spread that carries
/// `scriptRef` forward would have made the tax permanent and reproduced precisely
/// the failure `validate_graduate`'s comment calls out. A guard is cheaper than a
/// standing requirement on every future builder, so it is a guard.
///
/// One comparison per branch. It only ever SHRINKS the accepted set: no legitimate
/// pool output has ever carried a reference script in any mode.
fn no_ref_script_kept(own_output: Output) -> Bool {
  own_output.reference_script == None
}

/// The pool UTxO holds EXACTLY three things: lovelace, the curve token, and the
/// pool NFT. Nothing else, in either mode, on any branch.
///
/// `value_matches` pins the lovelace and the curve-token quantity and
/// `pool_nft_kept` pins the NFT, but before this check NOTHING bounded the number
/// of DISTINCT assets in the pool UTxO. An otherwise perfectly legal minimum-size
/// buy could stuff ~100 junk native assets into the continuation, filling the
/// value to the 5,000-byte `maxValSize`. The ledger's min-UTxO deposit on the
/// pool would rise to roughly 22–24 ADA, after which any sell whose continuation
/// would leave the pool below that figure is UNBUILDABLE at the ledger layer —
/// so the last ~12–14 ADA of reserve becomes unsellable, and every subsequent
/// trade carries a permanently larger transaction and script cost.
///
/// It is self-healing on the trade branches (the junk is unpinned on the way out
/// too, so the next trader can drop it and keep it) which is why it was not
/// critical. IT IS NOT SELF-HEALING AFTER GRADUATION IN ONE RESPECT: an `Amm`
/// pool's lovelace is pinned to `ada_reserve` with NO floor, so junk that raises
/// the ledger's min-UTxO above what `ada_reserve` will be after a large sell makes
/// that sell unbuildable — and unlike the curve there is no `pool_floor_v3`
/// cushion sitting beside the reserve. The guard is cheap and it now matters more,
/// not less.
///
/// It is ALSO the check that makes the two `solvency_ok` guards on the AMM
/// branches non-redundant in the other direction: `assets.add(_, _, 0)` is a
/// stdlib NO-OP and `from_lovelace(0)` is `zero`, so a continuation with a zero
/// reserve loses an ENTRY rather than carrying a zero. Both facts are needed to
/// reject it, and `mutverify.sh` binds them as a matched pair.
///
/// ── IT IS APPLIED TO OUTPUTS ONLY, AND THE INPUT SIDE IS COVERED BY INDUCTION ─
/// All five branches pin the CONTINUATION's shape (four call this directly; Graduate
/// pins it via a whole-`Value` equality plus this length check) and
/// `lump_mint_v3.pool_seeded` pins the GENESIS pool to the same three entries. Since
/// a UTxO cannot be mutated in place — only spent — a genuine pool can therefore
/// never come to hold a fourth asset: every state it can reach was produced by a
/// transaction that pinned it. Junk on a SELF-SEEDED input flows to the submitter
/// under the ledger's value-conservation rule and never enters a genuine pool.
///
/// So the asymmetry (five output pins, no input pin) is deliberate. A future
/// reviewer who notices it should not read it as an oversight: an input-side check
/// would be dead code on every reachable genuine state.
fn value_shape_ok(v: Value) -> Bool {
  list.length(flatten(v)) == 3
}

/// No mint or burn under the pool's own policy during a trade.
///
/// ── ITS STATUS CHANGED WHEN `Retire` WAS DELETED. IT STAYS ANYWAY. ──────────
/// Under the Splash path this was load-bearing against a real three-script hazard:
/// a transaction that Bought from a live pool AND burned the pool NFT satisfied
/// BOTH validators (`validate_buy` was happy because the continuation it inspected
/// held the NFT; `lump_mint_v3.Retire` was happy because the pool input held it),
/// and only the LEDGER's value-conservation rule rejected it. `Retire` is gone —
/// `lump_mint_v3` has NO burn path — so that hazard is now unconstructible at the
/// policy level and this check is asserting something already impossible.
///
/// Keeping it is the correct direction. It makes "curve supply is untouchable" a
/// LOCAL property of each branch rather than a fact about another file, so if a
/// future cohort's minting policy ever gains a second mint path — a wrapped
/// version, a migration, a fee-token — the pool branches already refuse to trade
/// alongside it instead of silently becoming exploitable.
fn no_policy_mint(tx: Transaction, policy_id: ByteArray) -> Bool {
  dict.to_pairs(tokens(tx.mint, policy_id)) == []
}

/// ══════════════════════════════════════════════════════════════════════════════
/// THE PLATFORM SIDE OF THE FEE SCHEDULE, PINNED AT SPEND TIME, IN BOTH MODES.
/// ══════════════════════════════════════════════════════════════════════════════
///
/// `lump_pool_v3` is UNPARAMETERISED, so `authentic` proves only "this UTxO holds
/// the NFT its OWN datum names" — it does not prove the pool ever went through
/// `lump_mint_v3`. Every guarantee in `pool_seeded` therefore held only for pools
/// that chose to be launched properly, and the validator had no way to tell.
///
/// The consequence was not merely an off-chain SELECTION problem. Anyone could
/// mint 1e9 of a token under a two-line native script plus one asset named
/// `pool_nft_name`, park a UTxO at LumpFun's one and only address with
/// `creator_pkh = treasury_pkh = themselves, platform_fee_bps: 0,
/// platform_fee_flat: 0`, and TRADE IT THROUGH THE OFFICIAL VALIDATOR paying
/// LumpFun nothing — a counterfeit "LumpFun" token at the official address,
/// indistinguishable to any aggregator or explorer keyed on that address.
///
/// IT IS CALLED ON ALL FOUR TRADE BRANCHES, and that is a change: with the Splash
/// path the post-graduation half of a token's life happened at a FOREIGN address
/// under a foreign validator, so `AmmBuy`/`AmmSell` did not exist and the pin only
/// ever had to cover the curve. Now LumpFun's own AMM is where a graduated token
/// trades forever, which is where most of its lifetime volume — and therefore most
/// of the platform's revenue — actually is. A pin that covered only the curve would
/// have left the larger half unprotected.
///
/// `>=` on the two platform levels, `==` on the recipient: a FUTURE cohort may
/// compile a new minting policy that RAISES the platform fee against this same
/// shared pool (§5.6's stated design goal), but nothing may lower it, and nothing
/// may redirect it. `creator_pkh`, `creator_fee_bps` and `royalty_pub_key` stay
/// free by design — they are the creator's, and a self-seeded pool that cheats
/// only its own creator harms nobody but its author.
///
/// The bps range bounds are defence in depth for the same reason: on a self-
/// seeded pool a NEGATIVE bps makes `sell_net` exceed the gross and makes
/// `creator_fee` negative, at which point `pays_at_least` trivially succeeds
/// against any output. Unreachable on a genuine pool (the rates are pinned at
/// genesis and frozen for life) and free to assert.
fn fee_schedule_ok(
  treasury_pkh: ByteArray,
  creator_fee_bps: Int,
  platform_fee_bps: Int,
  platform_fee_flat: Int,
) -> Bool {
  and {
    treasury_pkh == treasury_pkh_v3,
    platform_fee_bps >= platform_fee_bps_v3,
    platform_fee_flat >= platform_fee_flat_v3,
    creator_fee_bps >= 0,
    creator_fee_bps <= 10_000,
    platform_fee_bps <= 10_000,
  }
}

// ── Buy (BOOTSTRAP) ───────────────────────────────────────────────────────────

fn validate_buy(
  d: PoolDatum,
  min_out: Int,
  own_input: Input,
  own_hash: ByteArray,
  tx: Transaction,
) -> Bool {
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve: old_ada,
    token_reserve: old_tok,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    mode,
    ..
  } = d

  // ██ THE CURVE BRANCHES REJECT A GRADUATED POOL. ██
  //
  // Not cosmetic and not symmetry-for-its-own-sake: `quote_buy` adds
  // `virtual_ada_v3` to the reserve, so applied to an `Amm` pool it prices with a
  // 9,142.86 ADA cushion the pool does not have. It shortchanges the BUYER (higher
  // effective reserve ⇒ less slippage ⇒ fewer tokens per ADA), so this direction
  // costs the trader rather than the pool — measured at an Amm state of
  // (9,467,738,505, 461,203,875), a 1,000 ADA `Buy` yields 23,518,097 tokens where
  // the correct `AmmBuy` yields 44,059,553, i.e. the buyer loses 47% of their fill.
  // `validate_sell`'s mode guard is the one that stops a DRAIN. Both are here.
  let mode_ok = mode == Bootstrap

  let own_output = sole_continuation(own_input, tx)
  expect InlineDatum(raw) = own_output.datum
  expect new_d: PoolDatum = raw
  expect PoolDatumV3 { ada_reserve: new_ada, token_reserve: new_tok, .. } = new_d

  // R-5 — only the two reserve fields may move. Everything else, `mode` included,
  // is frozen.
  let datum_preserved = with_reserves(d, new_ada, new_tok) == new_d

  let ada_in = new_ada - old_ada
  let tokens_out = old_tok - new_tok

  // V-6 on the way out, under the SAME mode (frozen by `datum_preserved`).
  let out_consistent =
    value_matches(
      mode,
      own_output.value,
      policy_id,
      asset_name,
      new_ada,
      new_tok,
    )

  // The curve must still have sellable allocation. Once exhausted the pool is
  // FROZEN — only `Graduate` is possible — so nobody can reopen it in front of
  // a graduation attempt.
  //
  // NOT redundant. From `old_tok == curve_exhausted_token_reserve`, an `ada_in`
  // of ZERO leaves `new_tok == curve_exhausted_token_reserve`: `cap_ok` accepts
  // it (`>=` holds by equality) and `correct_tokens_out` accepts it (the quote
  // of 0 is 0), so that state is rejected only by `open_ok` together with
  // `ada_in_positive`, and `buy_rejects_zero_ada_in_on_a_closed_curve` below is
  // the test that isolates the pair. (A POSITIVE buy from the closed state is
  // caught by `cap_ok` as well; the zero case is what this guard uniquely owns.)
  // This guard is what makes "closed ⇒ frozen" a property of the branch rather
  // than an accident of the arithmetic.
  let open_ok = curve_open(old_tok)

  // TOKEN-SPACE CAP — this is the whole of v2's `cap_ok` replacement. A buy may
  // land exactly on the exhausted reserve but never below it, so the curve can
  // never oversell `sellable_v3` and the pool bag is provably untouchable.
  // There is no ADA threshold, no overshoot and no clamp to deadlock on.
  let cap_ok = new_tok >= curve_exhausted_token_reserve

  // ── NO MINIMUM TRADE SIZE. `size_ok` IS GONE. ────────────────────────────
  //
  // Operator decision, 2026-07-26: any buy size is allowed. See the note on the
  // deleted `min_trade_ada_v3` in `params_v3.ak`.
  //
  // The CLOSING-BUY EXEMPTION went with it, and that is safe rather than merely
  // tidy. The exemption existed only because a minimum could make the final buy
  // illegal — an attacker parked the reserve where the only legal closing buy was
  // smaller than the minimum, `Graduate` became unreachable and the token froze
  // forever (§3.1). With no minimum there is no such state and no deadlock to
  // escape.
  //
  // `ada_in_positive` SURVIVES AND IS NOW THE ONLY SIZE GUARD ON THIS BRANCH. It
  // used to be described as load-bearing "together with `open_ok`" because the
  // exemption could fire at `ada_in == 0` on a closed curve; that route is gone,
  // but a zero-ADA buy must still be rejected on its own terms — it moves no
  // reserve, mints no tokens, and would let a caller pay the flat fee for a no-op
  // (or spam one). `open_ok` independently keeps a closed curve closed.
  let ada_in_positive = ada_in > 0
  let correct_tokens_out = tokens_out == quote_buy(old_ada, old_tok, ada_in)

  // NOTE WHAT `min_out` ACTUALLY CONSTRAINS: the DATUM's reserve delta, not the
  // trader's receipt. Nothing here requires an output paying the buyer anything.
  // That is safe in v3 ONLY because the order book is deleted — the trader builds
  // and signs their own transaction and there is no batcher to defraud them. If a
  // batcher, router or smart-contract-wallet integration is ever allowed to build
  // a pool spend on someone else's behalf, this stops being slippage protection
  // and must be reworked to pin a payout output. THE SAME APPLIES TO THE AMM
  // BRANCHES, and it applies for longer there — a graduated pool trades forever,
  // so it is the surface an aggregator is most likely to want to route through.
  let slippage_ok = tokens_out >= min_out

  // Fees are a SURCHARGE on a buy: `ada_in` is what reaches the reserve, and the
  // trader additionally pays creator + platform to separate outputs. `own_hash`
  // excludes the pool's own continuation from satisfying either check.
  let platform_ok =
    platform_fee_paid(
      tx.outputs,
      treasury_pkh,
      ada_in,
      platform_fee_bps,
      platform_fee_flat,
      own_hash,
    )
  let creator_ok =
    creator_fee_paid(tx.outputs, creator_pkh, ada_in, creator_fee_bps, own_hash)

  and {
    mode_ok,
    datum_preserved,
    continuation_address_exact(own_input, own_output),
    out_consistent,
    fee_schedule_ok(
      treasury_pkh,
      creator_fee_bps,
      platform_fee_bps,
      platform_fee_flat,
    ),
    open_ok,
    cap_ok,
    ada_in_positive,
    correct_tokens_out,
    slippage_ok,
    pool_nft_kept(own_output, policy_id),
    value_shape_ok(own_output.value),
    no_ref_script_kept(own_output),
    no_policy_mint(tx, policy_id),
    platform_ok,
    creator_ok,
  }
}

// ── Sell (BOOTSTRAP) ──────────────────────────────────────────────────────────

fn validate_sell(
  d: PoolDatum,
  min_out: Int,
  own_input: Input,
  own_hash: ByteArray,
  tx: Transaction,
) -> Bool {
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve: old_ada,
    token_reserve: old_tok,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    mode,
    ..
  } = d

  // ██ THIS IS THE CROSS-MODE GUARD THAT STOPS A DRAIN. ██
  //
  // `quote_sell_gross` computes the gross as `effective · tokens_in / (t + tokens_in)`
  // with `effective = ada_reserve + virtual_ada_v3`. On an `Amm` pool the real
  // reserve is `ada_reserve` alone, so the curve formula pays out in the ratio
  // `effective / ada_reserve` — MORE ADA than the constant product allows, out of a
  // pool that has no virtual cushion backing it.
  //
  // MEASURED, at a reachable Amm state of (9,467,738,505, 461,203,875): a
  // 20,000,000-token `Sell` grosses 773,501,488 lovelace where the correct
  // `AmmSell` grosses 393,502,173. That is 1.966× — 380.0 ADA extracted from the
  // pool on one trade — and it is REPEATABLE until the pool is empty. Nothing else
  // in this branch rejects it: `open_ok` passes (461,203,875 > 404,061,018),
  // `cap_ok` passes (481,203,875 <= 1,142,857,143), `correct_gross` passes because
  // the curve quote is exactly what the attacker presented, and the fee outputs are
  // paid in full on the inflated gross. `sell_rejects_an_amm_mode_pool` is the
  // isolating test.
  let mode_ok = mode == Bootstrap

  let own_output = sole_continuation(own_input, tx)
  expect InlineDatum(raw) = own_output.datum
  expect new_d: PoolDatum = raw
  expect PoolDatumV3 { ada_reserve: new_ada, token_reserve: new_tok, .. } = new_d

  let datum_preserved = with_reserves(d, new_ada, new_tok) == new_d

  let tokens_in = new_tok - old_tok
  let ada_gross = old_ada - new_ada

  let out_consistent =
    value_matches(
      mode,
      own_output.value,
      policy_id,
      asset_name,
      new_ada,
      new_tok,
    )

  // A closed curve is frozen on the sell side too. If a 1-token sell could
  // reopen it, anyone could grief every graduation attempt indefinitely.
  let open_ok = curve_open(old_tok)

  // NOW LOAD-BEARING, and isolated by `sell_rejects_zero_tokens_in_isolated`.
  // While `size_ok` existed on this branch it was subsumed (a non-positive
  // `tokens_in` forces `ada_gross <= 0`, which the 10 ADA floor rejected anyway);
  // with that floor gone this is the guard that stops a no-op or negative sell.
  let tokens_in_positive = tokens_in > 0
  let correct_gross = ada_gross == quote_sell_gross(old_ada, old_tok, tokens_in)

  // ════════════════════════════════════════════════════════════════════════════
  // THERE IS DELIBERATELY NO `size_ok` ON THIS BRANCH. DO NOT ADD ONE BACK.
  // ════════════════════════════════════════════════════════════════════════════
  //
  // An earlier v3 draft carried `ada_gross >= min_trade_ada_v3` here "for
  // symmetry with the buy side". That was a live defect, and a nastier one than
  // its own comment suggested.
  //
  // `quote_sell_gross` CAPS the gross at `ada_reserve` (solvency). So the LARGEST
  // gross obtainable from any state is `ada_reserve` itself. The moment
  // `0 < ada_reserve < min_trade_ada_v3`, NO sell of any size can clear the
  // minimum — not a partial exit, not selling 100% of the outstanding float — and
  // the sell side is entirely disabled until somebody happens to submit a ≥10 ADA
  // BUY. On the long tail of tokens that never trade again (§3.5: most v3 tokens
  // are dead forever) that is permanent.
  //
  // It is reachable in TWO ORDINARY TRADES from genesis, verified with exact
  // integer arithmetic:
  //   1. buy 25,000,000 lovelace  → tokens_out 3,116,479, state
  //                                 (25,000,000, 1,139,740,664)
  //   2. sell 2,491,820 tokens    → gross 20,000,001 (legal), state
  //                                 (4,999,999, 1,142,232,484)
  //   … 624,659 tokens still outstanding in other wallets, and
  //   `quote_sell_gross(4,999,999, 1,142,232,484, anything) = 4,999,999 < 10 ADA`.
  // Attacker cost: the ordinary round-trip fees on their own bag, ~1.6%.
  //
  // A SYMMETRIC FULL-DRAIN EXEMPTION (`|| ada_gross == old_ada`) WAS CONSIDERED
  // AND REJECTED. From the state above, the minimum `tokens_in` that reaches the
  // cap is 624,659 — 100.0000% of the float. A holder of half the float grosses
  // 2,500,682 and is still frozen out. The exemption only rescues a holder who
  // owns literally every outstanding token, so it does not fix the defect it was
  // proposed for.
  //
  // The same reasoning applies to `AmmSell`, and for the same reason there is no
  // minimum there either — with one difference worth recording: the AMM's
  // solvency cap can never bind on a genuine pool (100% of the float dumped in
  // still leaves 4,366 ADA), so the trapped-holder state is not even reachable
  // there. Spam on that side is priced by the flat fee alone, and
  // `math_v3.amm_sell_of_one_token_is_priced_out_by_the_flat_fee` measures it.

  // The mirror of the buy branch's `cap_ok`, and it was MISSING. `tokens_in` was
  // bounded only from below, so nothing local stopped a sell driving
  // `token_reserve` above `virtual_token_v3` — above X_c the price model is
  // outside its calibrated domain and the `pool_bag_v3` identity stops describing
  // the pool. It held only by a CROSS-CONTRACT argument (`value_matches` demands
  // the continuation hold `new_tok − token_offset_v3` real tokens, and
  // `lump_mint_v3` guarantees exactly `total_supply_v3` exist for all time). That
  // argument is correct today and evaporates silently if a future cohort's
  // minting policy gains a second mint path — or immediately, on any pool parked
  // at this shared address under a policy that is not `lump_mint_v3`. One
  // comparison, no reachable behaviour change on a genuine pool.
  let cap_ok = new_tok <= virtual_token_v3

  // Fees are DEDUCTED from the gross on a sell — the opposite of the buy branch,
  // where they are a surcharge on top. See fees_v3's header.
  let net_ada =
    sell_net(ada_gross, creator_fee_bps, platform_fee_bps, platform_fee_flat)

  // As on the buy branch: this constrains the DATUM's reserve delta, not the
  // seller's receipt. Safe only because v3 has no batcher.
  let slippage_ok = net_ada >= min_out

  let platform_ok =
    platform_fee_paid(
      tx.outputs,
      treasury_pkh,
      ada_gross,
      platform_fee_bps,
      platform_fee_flat,
      own_hash,
    )
  let creator_ok =
    creator_fee_paid(tx.outputs, creator_pkh, ada_gross, creator_fee_bps, own_hash)

  and {
    mode_ok,
    datum_preserved,
    continuation_address_exact(own_input, own_output),
    out_consistent,
    fee_schedule_ok(
      treasury_pkh,
      creator_fee_bps,
      platform_fee_bps,
      platform_fee_flat,
    ),
    open_ok,
    tokens_in_positive,
    correct_gross,
    cap_ok,
    slippage_ok,
    pool_nft_kept(own_output, policy_id),
    value_shape_ok(own_output.value),
    no_ref_script_kept(own_output),
    no_policy_mint(tx, policy_id),
    platform_ok,
    creator_ok,
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Graduate — THE ONE-WAY FLIP, IN PLACE.
//
// ── WHAT IT DOES, IN FULL ────────────────────────────────────────────────────
//
//   input   at the pool address: `ada_reserve + pool_floor_v3` lovelace,
//           `pool_bag_v3` real tokens, the pool NFT, datum mode `Bootstrap` with
//           `token_reserve == curve_exhausted_token_reserve`.
//   output  at THE SAME address: EXACTLY `ada_reserve` lovelace, EXACTLY
//           `pool_bag_v3` tokens, the SAME pool NFT, datum
//           `with_graduation(d)` — mode `Amm`, `token_reserve == pool_bag_v3`,
//           `ada_reserve` unchanged, everything else frozen.
//   mint    ZERO. Nothing is minted and NOTHING IS BURNED.
//   bounty  `pool_floor_v3` (2.5 ADA) to whoever built the transaction.
//
// NOT ONE TOKEN AND NOT ONE LOVELACE OF THE RESERVE MOVES. The 26.1% of supply in
// `pool_bag_v3` stays exactly where the launch put it; the flip only stops
// describing it through `token_offset_v3`. That is the whole reason there is no
// C-1 surface on this branch at all — compare the Splash path, where the same
// operation had to hand 261,203,875 tokens and ~16,717 ADA to a foreign address and
// where getting the destination wrong was a total loss.
//
// ── THE BOUNTY IS ARITHMETIC, NOT AN ALLOWANCE ───────────────────────────────
// Nothing here grants anybody 10 ADA. `in_consistent` proves the INPUT holds
// `ada_reserve + pool_floor_v3` lovelace and `value_ok` pins the OUTPUT's lovelace
// to exactly `ada_reserve`. The difference is 2.5 ADA and the ledger's
// value-conservation rule sends it wherever the transaction says. So the bounty
// cannot be over-claimed (the output's lovelace is an equality, not a floor) and
// cannot be under-claimed into the pool (same equality). It exists because a closed
// curve is FROZEN — no buy, no sell, only this branch — so somebody has to be paid
// to unfreeze it, and paying them out of the floor rather than out of the reserve
// is what keeps the graduated pool opening at the curve's closing price.
//
// ── PERMISSIONLESS, AND NOT BY OMISSION ──────────────────────────────────────
// Nothing in this branch reads `tx.extra_signatories`, `tx.certificates`,
// `tx.withdrawals`, `tx.votes` or `tx.validity_range`. That is deliberate and it is
// bound by a POSITIVE test (`graduate_accepts_an_incidental_required_signer`) which
// goes RED if anyone adds a signature assert.
//
// An `extra_signatories == []` assert — which the Splash-path draft carried —
// buys ZERO security: it reads the tx body's required-signers field, not the witness
// set, so every ordinary wallet transaction satisfies it. What it DOES do is remove
// valid transactions from the accepted set: any wallet, hardware flow, multisig path
// or builder helper that populates `required_signers` (Lucid's `addSignerKey`, which
// some collateral and multi-witness flows call) would produce a graduation the
// validator rejects with no diagnosable reason — on a one-way door that §8.3 wants
// to be "a button any connected wallet can press". A reject test there would lock
// the availability defect in.
//
// ── MODE MONOTONICITY IS ENFORCED TWICE, AND THE TWO HALVES DIFFER ───────────
//   1. `mode == Bootstrap` HERE, on the INPUT. This is what stops a graduated pool
//      being graduated again — which would release a SECOND `pool_floor_v3` out of
//      the Amm's reserve (the Amm invariant has no floor, so the 10 ADA would come
//      straight out of `ada_reserve`) and would do so repeatedly, 2.5 ADA at a time,
//      until the pool was empty. `with_graduation` alone does NOT stop it: applied
//      to an already-graduated datum it is a FIXED POINT, so the datum equality is
//      satisfied. `pool_types.with_graduation_is_a_fixed_point_on_an_amm_pool`
//      asserts that so nobody deletes this line believing the helper covers it.
//   2. `mode` frozen by `with_reserves` on all four TRADE branches. This is what
//      stops `Amm -> Bootstrap`. There is no expression anywhere in the project that
//      produces `Bootstrap` from an existing datum.
//
// ── WHAT IS STILL NOT PROVEN ON-CHAIN ────────────────────────────────────────
// `lump_pool_v3` is unparameterised, so this branch cannot prove the pool it is
// graduating ever went through `lump_mint_v3`. A self-seeded pool parked at this
// address CAN be graduated — and that is fine: every lovelace and token stays in
// that same pool, and `fee_schedule_ok` on the AMM branches means the result still
// cannot trade at the shared address unless it pays LumpFun. An attacker
// graduating their own junk pool converts their own money into their own locked
// AMM. Nothing of LumpFun's is reachable that way.
// ══════════════════════════════════════════════════════════════════════════════

fn validate_graduate(d: PoolDatum, own_input: Input, tx: Transaction) -> Bool {
  expect PoolDatumV3 { policy_id, asset_name, ada_reserve: x, token_reserve, mode, .. } =
    d

  // ── G-MODE — the pool must be ON THE CURVE. See the banner above. ──────────
  let mode_ok = mode == Bootstrap

  // ── G0 / G3 — the curve is finished, and the bag is the bag we promised ────
  //
  //   G0  token_reserve == curve_exhausted_token_reserve
  //   G3  x >= 1 && pool_bag_v3 == token_reserve − token_offset_v3
  //
  // Delegated to `math_v3` as a pure function so both clauses have direct
  // arithmetic tests that do not have to be routed through a mock transaction —
  // in particular `x = 0`, which is the state that would produce an Amm pool with
  // k = 0, price 0, and 261,203,875 tokens nobody can ever buy.
  //
  // G4 (the `lq0` isqrt bracket) is GONE with the Splash path. `Graduate` carries
  // no redeemer field at all, so there is no caller-supplied number on this branch
  // to check.
  let curve_ok = graduation_curve_checks(x, token_reserve)

  // Exactly one output at the pool's own payment credential, at the exact same
  // address. The flip is IN PLACE, so this is the pool itself — not a destination.
  let own_output = sole_continuation(own_input, tx)

  expect InlineDatum(raw) = own_output.datum
  expect new_d: PoolDatum = raw

  // ── R-5 on this branch — the ONLY place `mode` may move ───────────────────
  //
  // `with_graduation` permits exactly two changes (`mode -> Amm` and
  // `token_reserve -> pool_bag_v3`, BOTH hardcoded), carries `ada_reserve`
  // through unchanged, and freezes the other nine fields. So this single equality
  // is simultaneously:
  //   • THE REBASE. `token_reserve` must become `pool_bag_v3` = 261,203,875.
  //     Keeping `curve_exhausted_token_reserve` = 404,061,018 is REJECTED, and so
  //     is any other value — both are compile-time constants, so it is an exact
  //     equality and not a computation. Getting this wrong by leaving 404,061,018
  //     in place would make the Amm price 404,061,018/261,203,875 = 1.547× too many
  //     tokens against its real balance, i.e. an instant 35.4% discount to the
  //     first buyer, and would break the value invariant on every subsequent spend
  //     (`out_consistent` would demand 404,061,018 real tokens from a pool holding
  //     261,203,875) — so the pool would be unspendable AND mispriced.
  //   • THE ADA FREEZE. `ada_reserve` may not move. Combined with `value_ok`'s
  //     lovelace equality this is what makes the bounty exactly `pool_floor_v3`.
  //   • THE CONFIG FREEZE. Graduation is not a licence to rewrite the fee
  //     schedule, the treasury, the creator or `royalty_pub_key`.
  let datum_ok = with_graduation(d) == new_d

  // ── THE VALUE, EXACTLY. `==`, NEVER "CONTAINS AT LEAST". ──────────────────
  //
  //   lovelace  == x                (the pool_floor_v3 that sat beside it leaves)
  //   token     == pool_bag_v3      (REAL, because Amm runs at offset 0)
  //   NFT       == 1
  //   entries   == 3
  //
  // The whole-`Value` equality is stricter than three separate quantity checks and
  // is used in preference to them. The length check is STILL not redundant: if a
  // hostile datum set `policy_id = asset_name = #""`, `assets.add(#"", #"", y)`
  // would fold into the lovelace entry, both sides would agree, and one of the
  // three slots would go unpinned. `length == 3` closes that — the same reasoning
  // the Splash path's G9 used for its four-entry value, which is worth keeping
  // because the failure mode does not depend on Splash at all.
  //
  // LOOSENING THIS TO "CONTAINS AT LEAST" IS THE REFACTOR TO REFUSE. It is what
  // "let the graduation keep a min-UTxO cushion" looks like in code, and it would
  // let the submitter take an arbitrary amount of the reserve instead of exactly
  // the floor, or weld junk assets into a pool that is then stuck with them for
  // life (see `value_shape_ok` on why junk is NOT self-healing after graduation).
  let expected_value =
    assets.from_lovelace(x)
      |> assets.add(policy_id, asset_name, pool_bag_v3)
      |> assets.add(policy_id, pool_nft_name, 1)
  let value_ok =
    own_output.value == expected_value && value_shape_ok(own_output.value)

  // ── NOTHING IS MINTED AND NOTHING IS BURNED ───────────────────────────────
  //
  // Stronger than `no_policy_mint` (which bounds only this token's own policy):
  // the WHOLE mint field must be empty. There is no `Retire` to satisfy — the pool
  // NFT is never burned and `lump_mint_v3` has no burn path — and no foreign policy
  // has any business in a graduation. It also forecloses the composed shape the
  // Splash path had to reason about: a graduation bundled with a mint under some
  // other policy that an off-chain indexer might mis-attribute to LumpFun.
  let no_mint = tx.mint == assets.zero

  // ── WHY `fee_schedule_ok` IS DELIBERATELY ABSENT FROM THIS BRANCH ──────────
  //
  // It is called on all four TRADE branches and on none of the graduation. That
  // asymmetry is a decision, not an oversight, and it is recorded here so nobody
  // "fixes" it on a ONE-WAY DOOR.
  //
  // Adding it would close nothing. An attacker writing a self-seeded datum is free
  // to name `treasury_pkh_v3` and the exact 100/0/2,000,000 schedule, so the check
  // cannot distinguish a counterfeit pool from a genuine one here any more than
  // `authentic` can. What it WOULD do is remove valid graduations: a pool whose fee
  // schedule is legitimate-but-raised by a future cohort would be refused the flip
  // and frozen at the close with its whole reserve inside, unrecoverably, because
  // `Graduate` is the only branch that can move it.
  //
  // The property is preserved without it. `with_graduation` freezes the entire
  // config half through the flip, and `validate_amm_buy` / `validate_amm_sell` both
  // assert `fee_schedule_ok` on EVERY subsequent spend — so a graduated pool that
  // names a foreign treasury or a zero platform fee simply cannot trade. Its author
  // has converted their own money into their own unspendable pool. The irreducible
  // residual is that two genuine LumpFun tokens are indistinguishable at one shared
  // address, which is why §8.3 mandates recompute-never-scan.

  and {
    mode_ok,
    curve_ok,
    datum_ok,
    continuation_address_exact(own_input, own_output),
    value_ok,
    pool_nft_kept(own_output, policy_id),
    no_mint,
    no_ref_script_kept(own_output),
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// AmmBuy / AmmSell — the permanent pool, offset 0 on BOTH sides.
//
// Same fee schedule as the curve (creator 100 bps, platform 2 ADA flat with a
// 0 bps rate), both pinned in the datum and frozen for life by `with_reserves`.
//
// NO MINIMUM TRADE on either side — `min_trade_ada_v3` is deleted (operator
// decision, 2026-07-26; see `params_v3.ak`). The only size guards are
// `ada_in > 0` on `AmmBuy` and `tokens_in > 0` on `AmmSell`: a zero-size trade
// is a no-op that would grief the permanent pool's UTxO, not a bad trade. Phase 1
// separately proved a SELL-side minimum dust-locks small holders; that reasoning
// predates the deletion of the buy-side minimum and still stands on its own.
//
// WHAT THE AMM BRANCHES DO *NOT* HAVE, and why:
//   • `open_ok` / `cap_ok`-on-tokens-below. There is no exhaustion. The pool is
//     tradable in both directions for life.
//   • any withdraw, redeem, migrate or admin path. See the header banner.
//   • `mode_offset`. Offset 0 means the reserves ARE the balances.
//
// ── ██ `min_out` ON THESE TWO BRANCHES CONSTRAINS THE POOL, NOT THE TRADER. ██ ─
// Read the extended note on `validate_buy`'s `slippage_ok` before building anything
// that spends a graduated pool on someone else's behalf. `slippage_ok` compares the
// DATUM's reserve delta against `min_out`; NEITHER AMM branch pins an output paying
// the trader, so the tokens or ADA leaving the pool may go anywhere the transaction
// says. That is safe today only because the trader builds and signs their own
// transaction and v3 has no batcher or order book.
//
// It is repeated here because the constraint OUTLIVES the product decision that
// makes it safe: a graduated pool trades forever, so any future batcher, DEX
// aggregator, router or smart-contract-wallet integration silently converts
// `slippage_ok` from slippage protection into decoration — the builder would choose
// both `min_out` and the fill's destination. A PINNED PAYOUT OUTPUT is a
// precondition for that work, not a tighter `min_out`.
// ══════════════════════════════════════════════════════════════════════════════

fn validate_amm_buy(
  d: PoolDatum,
  min_out: Int,
  own_input: Input,
  own_hash: ByteArray,
  tx: Transaction,
) -> Bool {
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve: old_ada,
    token_reserve: old_tok,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    mode,
    ..
  } = d

  // ██ THE AMM BRANCHES REJECT A POOL THAT HAS NOT GRADUATED. ██
  //
  // This is the cross-mode direction that STEALS TOKENS, and it is the single most
  // valuable guard on this branch. `amm_quote_buy` prices on `ada_reserve` alone.
  // Applied to a `Bootstrap` pool it omits the 9,142.86 ADA virtual cushion, so
  // slippage is computed against a reserve ~10× too small and the buyer receives
  // vastly more than the curve owes.
  //
  // MEASURED, from the ordinary mid-curve state (1,000,000,000, 1,030,181,086) —
  // i.e. a token that has raised 1,000 ADA:
  //     correct `Buy`   of 1,000 ADA →  92,452,149 tokens
  //     `AmmBuy`        of 1,000 ADA → 515,090,543 tokens   (5.571×)
  // That is 51.51% OF TOTAL SUPPLY for 1,000 ADA, and it is precisely the C-1 claim
  // ("every token outside the pool was bought on the curve") broken in one
  // transaction. Every other guard on this branch passes on that transaction: the
  // continuation is self-consistent under the Bootstrap invariant, the datum is
  // correctly reconstructed with `mode` still `Bootstrap`, both fees are paid in
  // full on `ada_in`, the NFT is kept and the value shape is three entries.
  // `amm_buy_rejects_a_bootstrap_mode_pool` is the isolating test and mutverify
  // proves this line is the only thing rejecting it.
  let mode_ok = mode == Amm

  let own_output = sole_continuation(own_input, tx)
  expect InlineDatum(raw) = own_output.datum
  expect new_d: PoolDatum = raw
  expect PoolDatumV3 { ada_reserve: new_ada, token_reserve: new_tok, .. } = new_d

  // R-5 — two reserves move, nine fields frozen, `mode` among them. FREEZING
  // `mode` HERE IS HALF OF MONOTONICITY: without it an `AmmBuy` of 10 ADA could
  // write `mode: Bootstrap` into the continuation, after which the pool holds
  // `pool_bag_v3`-scale REAL tokens while the curve branches read `token_reserve`
  // as virtual and subtract `token_offset_v3` from it — 142,857,143 tokens of
  // error, in the attacker's favour, on a pool whose whole reserve is at stake.
  let datum_preserved = with_reserves(d, new_ada, new_tok) == new_d

  let ada_in = new_ada - old_ada
  let tokens_out = old_tok - new_tok

  let out_consistent =
    value_matches(
      mode,
      own_output.value,
      policy_id,
      asset_name,
      new_ada,
      new_tok,
    )

  // ── NO MINIMUM. `ada_in > 0` REPLACES IT — THIS IS NOT A DELETION. ───────
  //
  // The removed `size_ok` was `ada_in >= min_trade_ada_v3`, and its own note
  // recorded that it SUBSUMED `ada_in > 0`. Deleting it outright would have left
  // a zero-ADA `AmmBuy` structurally admissible: `amm_quote_buy(_, _, 0)` returns
  // 0, so `tokens_out` is 0, `with_reserves` reconstructs an IDENTICAL datum, the
  // offset-0 value invariant still holds, and every other guard on this branch
  // passes. The result would be an accepted no-op — repeatable, and a way to
  // grief the permanent pool's UTxO for the cost of a fee.
  //
  // Unlike the curve branch there is no `open_ok` here to catch it, so this line
  // is the whole defence.
  let ada_in_positive = ada_in > 0

  let correct_tokens_out = tokens_out == amm_quote_buy(old_ada, old_tok, ada_in)

  // SOLVENCY — the pool must keep at least one token.
  //
  // ██ STRUCTURALLY SHADOWED AS OF v3.2, AND KEPT DELIBERATELY. ██ The quote
  // floors the amount OUT — `tokens_out = ⌊net·T/(A+net)⌋ < T` at EVERY state —
  // so no transaction that passes `correct_tokens_out` can present a zero token
  // reserve, not even against a self-seeded pool graduated at `ada_reserve = 1`
  // (pre-v3.2, 262 ADA emptied that pool's token side; now the entire ADA supply
  // leaves one token — `amm_tiny_k_pool_token_side_cannot_be_emptied`). The
  // guard stays as defence in depth: it costs one comparison, and a future
  // cohort that changes the rounding direction gets it back for free.
  // `mutverify.sh` documents the shadowing (neutering it changes nothing
  // observable) rather than claiming isolation it cannot have.
  let solvency_ok = new_tok >= 1

  let slippage_ok = tokens_out >= min_out

  // Fees are a SURCHARGE on a buy, exactly as on the curve.
  let platform_ok =
    platform_fee_paid(
      tx.outputs,
      treasury_pkh,
      ada_in,
      platform_fee_bps,
      platform_fee_flat,
      own_hash,
    )
  let creator_ok =
    creator_fee_paid(tx.outputs, creator_pkh, ada_in, creator_fee_bps, own_hash)

  and {
    mode_ok,
    datum_preserved,
    continuation_address_exact(own_input, own_output),
    out_consistent,
    fee_schedule_ok(
      treasury_pkh,
      creator_fee_bps,
      platform_fee_bps,
      platform_fee_flat,
    ),
    ada_in_positive,
    correct_tokens_out,
    solvency_ok,
    slippage_ok,
    pool_nft_kept(own_output, policy_id),
    value_shape_ok(own_output.value),
    no_ref_script_kept(own_output),
    no_policy_mint(tx, policy_id),
    platform_ok,
    creator_ok,
  }
}

fn validate_amm_sell(
  d: PoolDatum,
  min_out: Int,
  own_input: Input,
  own_hash: ByteArray,
  tx: Transaction,
) -> Bool {
  expect PoolDatumV3 {
    policy_id,
    asset_name,
    ada_reserve: old_ada,
    token_reserve: old_tok,
    creator_pkh,
    treasury_pkh,
    creator_fee_bps,
    platform_fee_bps,
    platform_fee_flat,
    mode,
    ..
  } = d

  // The mirror of `validate_amm_buy`'s guard. This direction shortchanges the
  // SELLER rather than draining the pool — `amm_quote_sell_gross` on a Bootstrap
  // pool omits the virtual cushion, so the gross is ~10× too small (measured at
  // (2,000,000,000, 937,728,937): 41,765,471 lovelace where the curve owes
  // 232,693,338) — but a validator that lets a trader be paid a tenth of what the
  // pool owes them is not "safe", it is a mis-priced trade an aggregator or a
  // buggy builder can walk a user into. Rejected.
  let mode_ok = mode == Amm

  let own_output = sole_continuation(own_input, tx)
  expect InlineDatum(raw) = own_output.datum
  expect new_d: PoolDatum = raw
  expect PoolDatumV3 { ada_reserve: new_ada, token_reserve: new_tok, .. } = new_d

  let datum_preserved = with_reserves(d, new_ada, new_tok) == new_d

  let tokens_in = new_tok - old_tok
  let ada_gross = old_ada - new_ada

  let out_consistent =
    value_matches(
      mode,
      own_output.value,
      policy_id,
      asset_name,
      new_ada,
      new_tok,
    )

  // NO MINIMUM ON THIS SIDE. Phase 1 established that a sell-side minimum
  // dust-locks small holders; see the extended note in `validate_sell`. This
  // guard is what stops a no-op or negative sell instead.
  let tokens_in_positive = tokens_in > 0
  let correct_gross = ada_gross == amm_quote_sell_gross(old_ada, old_tok, tokens_in)

  // THE MIRROR OF THE CURVE'S SELL-SIDE `cap_ok`, in REAL token space.
  //
  // An `Amm` pool's `token_reserve` IS its balance, and only `total_supply_v3`
  // tokens exist for all time (`lump_mint_v3` is Launch-only, so this is now a
  // structural fact rather than an argument). So a sell may never push the reserve
  // above 1e9. It holds anyway by a CROSS-CONTRACT argument — `out_consistent`
  // demands the pool actually hold `new_tok` real tokens — and that argument
  // evaporates on any pool parked at this shared address under a policy that is not
  // `lump_mint_v3`. One comparison, no reachable behaviour change on a genuine pool,
  // and it keeps the bound local. Note the CURVE's version compares against
  // `virtual_token_v3` (1,142,857,143) because its reserve is virtual; this one
  // compares against `total_supply_v3` (1,000,000,000) because this reserve is real.
  // Those constants differ by exactly `token_offset_v3` and swapping them would
  // silently admit a 142,857,143-token overshoot.
  let cap_ok = new_tok <= total_supply_v3

  // SOLVENCY — the pool must keep at least one lovelace. Same standing as
  // `validate_amm_buy`'s `solvency_ok`: STRUCTURALLY SHADOWED as of v3.2
  // (`gross = ⌊net·A/(T+net)⌋ < A` at every state — dumping 100% of the float
  // leaves 4,376 ADA, and a tiny-k pool's single lovelace can never be
  // extracted, `amm_tiny_k_pool_ada_side_cannot_be_emptied`), and KEPT as
  // defence in depth against a future rounding change.
  let solvency_ok = new_ada >= 1

  // Fees are DEDUCTED from the gross on a sell, exactly as on the curve.
  let net_ada =
    sell_net(ada_gross, creator_fee_bps, platform_fee_bps, platform_fee_flat)
  let slippage_ok = net_ada >= min_out

  let platform_ok =
    platform_fee_paid(
      tx.outputs,
      treasury_pkh,
      ada_gross,
      platform_fee_bps,
      platform_fee_flat,
      own_hash,
    )
  let creator_ok =
    creator_fee_paid(tx.outputs, creator_pkh, ada_gross, creator_fee_bps, own_hash)

  and {
    mode_ok,
    datum_preserved,
    continuation_address_exact(own_input, own_output),
    out_consistent,
    fee_schedule_ok(
      treasury_pkh,
      creator_fee_bps,
      platform_fee_bps,
      platform_fee_flat,
    ),
    tokens_in_positive,
    correct_gross,
    cap_ok,
    solvency_ok,
    slippage_ok,
    pool_nft_kept(own_output, policy_id),
    value_shape_ok(own_output.value),
    no_ref_script_kept(own_output),
    no_policy_mint(tx, policy_id),
    platform_ok,
    creator_ok,
  }
}
// ── Test credentials ──────────────────────────────────────────────────────────
//
// ALL 28 BYTES, like real credentials. They used to be 4 bytes (#"a0a0a0a0" and
// friends), which the pool validator tolerated because it compares credentials by
// equality and length is irrelevant to that — Phase 0 fact (B): the soft-cast
// does NOT check bytestring lengths. The minting-policy suite already used
// realistic lengths because `pool_seeded` asserts them.
//
// Widened ahead of Phase 2, when graduation still targeted Splash and its
// asset-name derivations (`n_lq = sha2_256(H ‖ ser(i) ‖ ser(lq_mint))`) were
// length-sensitive: tested against 4-byte inputs they would pass while producing
// names that were wrong against 28-byte reality. THAT DERIVATION IS GONE — Splash
// was parked on 2026-07-26 and there is no sha2_256 anywhere in v3; the pool NFT
// name is the constant `000643b0504f4f4c`. Realistic lengths are kept anyway
// because `pool_seeded` asserts 28 bytes at launch and the tests should exercise
// the shapes the chain will actually carry.

const t_policy: ByteArray =
  #"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"

/// A realistic 4-byte ticker ("LUMP"). Asset names are not credentials.
const t_name: ByteArray = #"4c554d50"

/// The pool datum's `treasury_pkh` is now PINNED to the cohort constant by
/// `fee_schedule_ok`, so the tests must use the real one — a self-seeded pool
/// naming any other key cannot trade at the shared v3 address.
const t_treasury: ByteArray = treasury_pkh_v3

const t_creator: ByteArray =
  #"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

const t_pool: ByteArray =
  #"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"

const t_owner: ByteArray =
  #"e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0"

/// 32-byte ed25519 royalty key — the field R-5 exists to protect.
const t_royalty: ByteArray =
  #"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"

/// The attacker's key in the R-5 tests.
const t_evil_royalty: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

/// Full-arity datum builder. `PoolDatum` has two constructors, so Aiken forbids
/// record-update syntax (`PoolDatumV3 { ..d, x: y }` is a compile error) and
/// every mutation goes through a named wrapper. Adding a field breaks this
/// function at compile time, so no test can silently keep testing the old shape.
fn dat(
  policy_id: ByteArray,
  asset_name: ByteArray,
  ada_reserve: Int,
  token_reserve: Int,
  creator_pkh: ByteArray,
  treasury_pkh: ByteArray,
  creator_fee_bps: Int,
  platform_fee_bps: Int,
  platform_fee_flat: Int,
  royalty_pub_key: ByteArray,
  mode: PoolMode,
) -> PoolDatum {
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

/// The canonical datum at reserves (a, t) — the config half is always this.
fn pd(a: Int, t: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

// One-config-field mutations, for the R-5 whole-datum-reconstruction rejects.

fn pd_policy(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(x, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

fn pd_name(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, x, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

fn pd_creator(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, t_name, a, t, x, t_treasury, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

fn pd_treasury(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, x, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

fn pd_cbps(a: Int, t: Int, x: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, x, 0, 2_000_000, t_royalty, Bootstrap)
}

fn pd_pbps(a: Int, t: Int, x: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, x, 2_000_000, t_royalty, Bootstrap)
}

fn pd_pflat(a: Int, t: Int, x: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, x, t_royalty, Bootstrap)
}

fn pd_royalty(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, x, Bootstrap)
}

fn p_ref() -> OutputReference {
  oref(#"0000", 0)
}

/// A genuine pool value for datum reserves (a, t): the floor is ADDED to
/// `ada_reserve` and the offset is SUBTRACTED from `token_reserve`.
fn pool_value(a: Int, t: Int) -> Value {
  ada_token(a + pool_floor_v3, t_policy, t_name, t - token_offset_v3)
    |> assets.add(t_policy, pool_nft_name, 1)
}

fn p_in(a: Int, t: Int, d: PoolDatum) -> Input {
  input_of(p_ref(), script_out(t_pool, pool_value(a, t), d))
}

fn p_out(a: Int, t: Int, d: PoolDatum) -> Output {
  script_out(t_pool, pool_value(a, t), d)
}

/// Pool input/output with an ARBITRARY value — for the value-invariant tests,
/// where the whole point is that the value and the datum disagree.
fn p_in_raw(lovelace: Int, real_tokens: Int, nft: Int, d: PoolDatum) -> Input {
  let v =
    ada_token(lovelace, t_policy, t_name, real_tokens)
      |> assets.add(t_policy, pool_nft_name, nft)
  input_of(p_ref(), script_out(t_pool, v, d))
}

fn p_out_raw(lovelace: Int, real_tokens: Int, nft: Int, d: PoolDatum) -> Output {
  let v =
    ada_token(lovelace, t_policy, t_name, real_tokens)
      |> assets.add(t_policy, pool_nft_name, nft)
  script_out(t_pool, v, d)
}

fn base_tx(ins: List<Input>, outs: List<Output>) -> Transaction {
  Transaction { ..transaction.placeholder, inputs: ins, outputs: outs }
}

fn plat(l: Int) -> Output {
  pk_out(t_treasury, l)
}

fn crea(l: Int) -> Output {
  pk_out(t_creator, l)
}

fn wallet_in(tag: ByteArray, lovelace: Int) -> Input {
  input_of(oref(tag, 3), pk_out(t_owner, lovelace))
}

fn spend_pool(d: PoolDatum, r: PoolRedeemer, tx: Transaction) -> Bool {
  lump_pool_v3.spend(Some(d), r, p_ref(), tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// BUY — the canonical genesis trade
//
//   old = (0, 1,142,857,143)          value: 2,500,000 lovelace, 1e9 tokens
//   ada_in = 1,000,000,000
//   new_effective = 9,142,857,144 + 1,000,000,000 = 10,142,857,144
//   new_token_reserve = 10,448,979,594,448,979,592 / 10,142,857,144 = 1,030,181,086
//   tokens_out = 1,142,857,143 − 1,030,181,086 = 112,676,057
//   new = (1,000,000,000, 1,030,181,086)  value: 1,002,500,000 lovelace,
//                                                887,323,943 tokens
//   creator  = 1,000,000,000 × 100 / 10,000 = 10,000,000
//   platform = 2,000,000 (the flat fee is the whole platform take; bps is 0)
// ══════════════════════════════════════════════════════════════════════════════

fn buy_old() -> PoolDatum {
  pd(0, 1_142_857_143)
}

fn buy_new() -> PoolDatum {
  pd(1_000_000_000, 1_030_181_086)
}

fn buy_tx_outs(outs: List<Output>) -> Transaction {
  base_tx([p_in(0, 1_142_857_143, buy_old())], outs)
}

fn buy_good_tx() -> Transaction {
  buy_tx_outs(
    [
      p_out(1_000_000_000, 1_030_181_086, buy_new()),
      plat(2_000_000),
      crea(10_000_000),
    ],
  )
}

test buy_accepts_canonical_genesis_trade() {
  spend_pool(buy_old(), Buy { min_out: 112_000_000 }, buy_good_tx())
}

test buy_rejects_underpay_slippage() fail {
  spend_pool(buy_old(), Buy { min_out: 112_676_058 }, buy_good_tx())
}

/// One token more than the curve owes. The direct path compares the exact quote,
/// so this is caught arithmetically rather than by a k inequality.
test buy_rejects_one_extra_token_out() fail {
  let bad = pd(1_000_000_000, 1_030_181_085)
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [p_out(1_000_000_000, 1_030_181_085, bad), plat(2_000_000), crea(10_000_000)],
    ),
  )
}

/// A no-op "trade" that moves nothing. With `size_ok` deleted,
/// `ada_in_positive` is the ONLY guard rejecting it on an open curve: the quote
/// of 0 is 0 so `correct_tokens_out` passes, the continuation is identical so
/// the datum and value checks pass, `min_out: 0` satisfies `slippage_ok`, the
/// flat platform fee is paid and the creator hatch fires on a zero fee. (This
/// comment used to say `size_ok` fires and the positivity guard was subsumed —
/// that inverted when the minimum was deleted.)
test buy_rejects_zero_ada_in() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 0 },
    buy_tx_outs([p_out(0, 1_142_857_143, buy_old()), plat(2_000_000)]),
  )
}

test buy_rejects_two_pool_continuation_outputs() fail {
  let dup = p_out(1_000_000_000, 1_030_181_086, buy_new())
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs([dup, dup, plat(2_000_000), crea(10_000_000)]),
  )
}

// ── Fees ──────────────────────────────────────────────────────────────────────

test buy_rejects_missing_platform_fee() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs([p_out(1_000_000_000, 1_030_181_086, buy_new()), crea(10_000_000)]),
  )
}

/// One lovelace short. 2,000,000 is the flat platform fee; 1,999,999 is not.
test buy_rejects_platform_fee_one_lovelace_short() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(1_999_999),
        crea(10_000_000),
      ],
    ),
  )
}

test buy_rejects_missing_creator_fee() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs([p_out(1_000_000_000, 1_030_181_086, buy_new()), plat(2_000_000)]),
  )
}

test buy_rejects_creator_fee_one_lovelace_short() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(2_000_000),
        crea(9_999_999),
      ],
    ),
  )
}

/// Paying both fees to the CREATOR does not satisfy the treasury check — which
/// is why `pool_seeded` refuses a launch where the two keys are equal.
test buy_rejects_fees_both_paid_to_the_creator() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs([p_out(1_000_000_000, 1_030_181_086, buy_new()), crea(12_000_000)]),
  )
}

// ── Pool NFT authenticity ─────────────────────────────────────────────────────

test buy_rejects_decoy_input_without_the_nft() fail {
  // a self-consistent UTxO parked at the shared v3 pool address — value and
  // datum agree perfectly, only the 1-of-1 NFT is missing
  let tx =
    base_tx(
      [p_in_raw(2_500_000, 1_000_000_000, 0, buy_old())],
      [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(buy_old(), Buy { min_out: 112_000_000 }, tx)
}

test buy_rejects_nft_carried_out_of_the_pool() fail {
  // dropping the NFT from the continuation bricks the pool forever
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        p_out_raw(1_002_500_000, 887_323_943, 0, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

test buy_rejects_two_nfts_in_the_continuation() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        p_out_raw(1_002_500_000, 887_323_943, 2, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

// ── R-3 tx-shape confinement ──────────────────────────────────────────────────

test buy_accepts_wallet_inputs_alongside_the_pool() {
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, buy_old()), wallet_in(#"1111", 20_000_000)],
      [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(buy_old(), Buy { min_out: 112_000_000 }, tx)
}

test buy_rejects_second_pool_input() fail {
  // v3's pool is UNPARAMETERISED, so two different tokens' pools share one
  // address. Without this guard both could be satisfied by one fee output.
  let other =
    input_of(
      oref(#"0001", 0),
      script_out(t_pool, pool_value(0, 1_142_857_143), buy_old()),
    )
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, buy_old()), other],
      [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(buy_old(), Buy { min_out: 112_000_000 }, tx)
}

test buy_rejects_foreign_script_input() fail {
  let foreign =
    input_of(oref(#"0f0f", 0), script_out(#"0f0f0f0f", ada(5_000_000), 0))
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, buy_old()), foreign],
      [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(buy_old(), Buy { min_out: 112_000_000 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// THE VALUE INVARIANT
//   lovelace_of(value) == ada_reserve + 2,500,000
//   curve tokens       == token_reserve − 142,857,143
//
// Anchor state: (1,000,000,000, 1,030,181,086) ⇒ 1,002,500,000 lovelace and
// 887,323,943 tokens. Each test below breaks exactly one half of it.
//
// The sell they all mutate: 20,000,000 tokens in.
//   effective = 1,000,000,000 + 9,142,857,144 = 10,142,857,144
//   k = 10,142,857,144 × 1,030,181,086
//   new_token_reserve = 1,050,181,086
//   new_effective = k / 1,050,181,086 = 9,949,693,178
//   gross = 10,142,857,144 − 9,949,693,178 = 193,163,966
//   new = (806,836,034, 1,050,181,086) ⇒ 809,336,034 lovelace, 907,323,943 tokens
//   creator  = 193,163,966 × 100 / 10,000 = 1,931,639
//   platform = 2,000,000 (flat; bps is 0)
//   net = 193,163,966 − 1,931,639 − 2,000,000 = 189,232,327
// ══════════════════════════════════════════════════════════════════════════════

fn inv_old() -> PoolDatum {
  pd(1_000_000_000, 1_030_181_086)
}

fn inv_new() -> PoolDatum {
  pd(806_836_034, 1_050_181_086)
}

fn sell_good_tx() -> Transaction {
  base_tx(
    [p_in(1_000_000_000, 1_030_181_086, inv_old())],
    [
      p_out(806_836_034, 1_050_181_086, inv_new()),
      plat(2_000_000),
      crea(1_931_639),
    ],
  )
}

test sell_accepts_canonical_trade() {
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, sell_good_tx())
}

/// v2's value shape: `lovelace == ada_reserve`, with no floor. If v3's invariant
/// were ported without the `+ pool_floor_v3` term this would ACCEPT.
test invariant_rejects_input_without_the_pool_floor() fail {
  let tx =
    base_tx(
      [p_in_raw(1_000_000_000, 887_323_943, 1, inv_old())],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// The token half, ported without the offset: the pool holding `token_reserve`
/// real tokens rather than `token_reserve − token_offset_v3`. That is the shape
/// a v2-derived value check would accept, and it would hand out the pool bag.
test invariant_rejects_input_holding_the_virtual_reserve() fail {
  let tx =
    base_tx(
      [p_in_raw(1_002_500_000, 1_030_181_086, 1, inv_old())],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test invariant_rejects_input_ada_drift_by_one() fail {
  let tx =
    base_tx(
      [p_in_raw(1_002_500_001, 887_323_943, 1, inv_old())],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test invariant_rejects_input_token_drift_by_one() fail {
  let tx =
    base_tx(
      [p_in_raw(1_002_500_000, 887_323_942, 1, inv_old())],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// The output half: the datum says the reserve fell to 806,836,034 but the pool
/// keeps a lovelace more than that. Either direction breaks the invariant.
test invariant_rejects_output_ada_disagreeing_with_datum() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [
        p_out_raw(809_336_035, 907_323_943, 1, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test invariant_rejects_output_tokens_disagreeing_with_datum() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [
        p_out_raw(809_336_034, 907_323_942, 1, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// The buy path enforces the same invariant on the way out: ADA promised in the
/// datum but never actually deposited.
test invariant_rejects_buy_that_never_deposits_the_ada() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        p_out_raw(2_500_000, 887_323_943, 1, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// THE TOKEN-SPACE CAP  (replaces v2's `cap_ok` / `graduation_ada` entirely)
//
// Boundary pair, both from old = (16,000,000,000, 415,584,415):
//   effective = 25,142,857,144 ; k = 25,142,857,144 × 415,584,415
//   ada_in = 717,047,886 ⇒ new_token_reserve = 404,061,018  (EXACTLY exhausted)
//   ada_in = 717,047,950 ⇒ new_token_reserve = 404,061,017  (ONE token over)
// There is no minimum trade, so the ONLY guard that differs between the pair is
// `cap_ok`.
//
// How old = (16,000,000,000, 415,584,415) is reached: one 16,000 ADA genesis
// buy. k / (9,142,857,144 + 16,000,000,000) = 415,584,415.
//   input value: 16,002,500,000 lovelace, 272,727,272 tokens
// ══════════════════════════════════════════════════════════════════════════════

fn cap_old() -> PoolDatum {
  pd(16_000_000_000, 415_584_415)
}

/// tokens_out = 415,584,415 − 404,061,018 = 11,523,397
/// creator  = 717,047,886 × 100 / 10,000 = 7,170,478
/// platform = 2,000,000 (flat)
test cap_accepts_a_buy_landing_exactly_on_exhaustion() {
  let new_d = pd(16_717_047_886, 404_061_018)
  let tx =
    base_tx(
      [p_in(16_000_000_000, 415_584_415, cap_old())],
      [
        p_out(16_717_047_886, 404_061_018, new_d),
        plat(2_000_000),
        crea(7_170_478),
      ],
    )
  spend_pool(cap_old(), Buy { min_out: 11_000_000 }, tx)
}

/// 64 lovelace more, ONE token past the end of the sellable allocation — the
/// buyer would be taking a token out of the pool bag. The platform fee is the
/// same 2,000,000 flat and the creator fee floors to 7,170,479 (paid in full),
/// so `cap_ok` is the only guard that differs from the accept above.
test cap_rejects_a_buy_one_token_past_exhaustion() fail {
  let new_d = pd(16_717_047_950, 404_061_017)
  let tx =
    base_tx(
      [p_in(16_000_000_000, 415_584_415, cap_old())],
      [
        p_out(16_717_047_950, 404_061_017, new_d),
        plat(2_000_000),
        crea(7_170_479),
      ],
    )
  spend_pool(cap_old(), Buy { min_out: 11_000_000 }, tx)
}

/// A 10 ADA buy from one step before the close also overshoots.
///   old = (16,712,047,886, 404,139,159) ⇒ 16,714,547,886 lovelace, 261,282,016 tok
///   ada_in = 10,000,000 ⇒ new_token_reserve = 403,982,908 (78,110 past the end)
///   tokens_out = 156,251 ; creator 100,000 ; platform 2,000,000 (flat)
test cap_rejects_an_ordinary_ten_ada_buy_past_the_end() fail {
  let old_d = pd(16_712_047_886, 404_139_159)
  let new_d = pd(16_722_047_886, 403_982_908)
  let tx =
    base_tx(
      [p_in(16_712_047_886, 404_139_159, old_d)],
      [p_out(16_722_047_886, 403_982_908, new_d), plat(2_000_000), crea(100_000)],
    )
  spend_pool(old_d, Buy { min_out: 100_000 }, tx)
}

/// A closed pool is FROZEN: no buy. `open_ok` (the old reserve is already at the
/// cap) and `cap_ok` (this buy would go past it) both fire.
///
/// ARITHMETIC CORRECTED. This test previously moved the state to
/// `new_tok = 403,982,908`, a number copy-pasted verbatim from
/// `cap_rejects_an_ordinary_ten_ada_buy_past_the_end` above — whose OLD state is
/// different. Re-derived from THIS old state (16,717,047,886, 404,061,018):
///   effective = 25,859,905,030 ; k = effective × 404,061,018
///   new_effective = 25,869,905,030 ⇒ new_token_reserve = 403,904,828
///   tokens_out = 156,190 (not 78,110)
/// With the wrong figure, `correct_tokens_out` fired too, so the test was
/// redundantly rejected and isolated nothing — a mutation sweep kills it with no
/// mutation at all, including `open_ok` and `cap_ok` removed together. It was the
/// ONLY test exercising the Buy path against a curve at exactly
/// `curve_exhausted_token_reserve`, so "a closed curve is frozen on the buy side"
/// was proven by nothing.
test cap_rejects_buying_from_an_already_closed_curve() fail {
  let old_d = pd(16_717_047_886, 404_061_018)
  let new_d = pd(16_727_047_886, 403_904_828)
  let tx =
    base_tx(
      [p_in(16_717_047_886, 404_061_018, old_d)],
      [p_out(16_727_047_886, 403_904_828, new_d), plat(2_000_000), crea(100_000)],
    )
  spend_pool(old_d, Buy { min_out: 1 }, tx)
}

/// A ZERO-ADA buy from an already-closed curve — the state that isolates
/// `open_ok` together with `ada_in_positive`, and NOTHING else.
///
/// With `old_tok == curve_exhausted_token_reserve` and `ada_in == 0`,
/// `new_tok == curve_exhausted_token_reserve`, so `cap_ok` passes (`>=` is
/// satisfied by equality) and `correct_tokens_out` passes — `quote_buy(a, t, 0)`
/// is exactly 0. The continuation datum is identical to the input datum, so
/// `datum_preserved` and `out_consistent` hold too. Only `open_ok` and
/// `ada_in_positive` reject it. (While `size_ok` existed, its closing exemption
/// fired on exactly this state — the exemption is gone with the minimum, and the
/// isolating pair is unchanged.)
///
/// platform_fee(0) = 2,000,000 (the flat component); creator_fee(0) = 0, so the
/// zero-fee hatch legitimately fires and no creator output is needed.
test buy_rejects_zero_ada_in_on_a_closed_curve() fail {
  let d = pd(16_717_047_886, 404_061_018)
  let tx =
    base_tx(
      [p_in(16_717_047_886, 404_061_018, d)],
      [p_out(16_717_047_886, 404_061_018, d), plat(2_000_000)],
    )
  spend_pool(d, Buy { min_out: 0 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// THE CLOSING-BUY BOUNDARY  (formerly §3.1's exemption pair — the minimum is
// deleted, so BOTH cases are now ordinary legal buys)
//
// Pair from old = (16,712,047,886, 404,139,159):
//   effective = 25,854,905,030 ; k = 25,854,905,030 × 404,139,159
//   ada_in = 4,999,994 ⇒ new_token_reserve = 404,061,018 — EXACTLY exhausted.
//                        tokens_out = 78,141.
//   ada_in = 4,999,993 ⇒ new_token_reserve = 404,061,019 — ONE token short of
//                        the close. tokens_out = 78,140.
// One lovelace apart; under the old 10 ADA minimum the first was legal only via
// `size_ok`'s closing exemption and the second was rejected. With no minimum
// there is no exemption to need and no deadlock for it to fix — both accept,
// and the pair now pins that the boundary itself carries no special casing.
// `cap_ok` passes in both; the overshoot cases live in the section above.
//
// fees on both: creator 49,999 (1% floored) ; platform 2,000,000 (flat)
// ══════════════════════════════════════════════════════════════════════════════

fn close_old() -> PoolDatum {
  pd(16_712_047_886, 404_139_159)
}

/// A 4.999994 ADA buy that lands ON the exhausted reserve. This used to require
/// `size_ok`'s CLOSING EXEMPTION to be legal at all — the buy was under the old
/// 10 ADA minimum, and without the exemption the curve could be parked one
/// sub-minimum buy short of the close and frozen forever. With no minimum it is
/// simply an ordinary buy, and the exemption it needed no longer exists.
test closing_buy_accepts_a_small_buy_landing_on_the_close() {
  let new_d = pd(16_717_047_880, 404_061_018)
  let tx =
    base_tx(
      [p_in(16_712_047_886, 404_139_159, close_old())],
      [p_out(16_717_047_880, 404_061_018, new_d), plat(2_000_000), crea(49_999)],
    )
  spend_pool(close_old(), Buy { min_out: 78_000 }, tx)
}

/// …and the buy that stops ONE TOKEN SHORT of the close is now equally legal.
///
/// This was a `fail` test while the 10 ADA minimum existed: 4,999,993 lovelace
/// was sub-minimum and the closing exemption did not apply one token short of
/// the close, so `size_ok` rejected it. With no minimum it is an ordinary buy —
/// inverting the test is the deliberate half of that change, exactly as
/// `sell_accepts_gross_just_under_the_old_minimum` is on the sell side. (Left
/// as a reject it could only have "passed" by underpaying the fees, i.e. for a
/// reason it does not name.)
test closing_buy_accepts_stopping_one_token_short_of_the_close() {
  let new_d = pd(16_717_047_879, 404_061_019)
  let tx =
    base_tx(
      [p_in(16_712_047_886, 404_139_159, close_old())],
      [p_out(16_717_047_879, 404_061_019, new_d), plat(2_000_000), crea(49_999)],
    )
  spend_pool(close_old(), Buy { min_out: 78_000 }, tx)
}

// ██ `size_rejects_a_buy_one_lovelace_under_the_minimum` WAS DELETED HERE. ██
//
// It was a `fail` test asserting that a 9,999,999 lovelace buy is rejected "purely
// on size". With `min_trade_ada_v3` gone that buy is LEGAL, so the test no longer
// describes the validator.
//
// It did not start failing, which is exactly why it had to be removed rather than
// left alone: its fee outputs (549,999 platform) are below the new 2 ADA flat fee,
// so `platform_fee_paid` rejected the transaction and the `fail` expectation kept
// passing FOR THE WRONG REASON. A test that passes for a reason it does not name
// is worse than no test — it reports coverage of a guard that is gone.
// Fee underpayment is already covered by the dedicated fee-underpay rejects.

/// ── NO MINIMUM BUY. A ONE-ADA BUY FROM GENESIS IS ACCEPTED. ──────────────
/// Replaces `size_accepts_a_buy_exactly_at_the_minimum`, which pinned a guard that
/// no longer exists. One ADA is far below the old 10 ADA floor and is now
/// perfectly legal — the 2 ADA flat fee makes it a poor trade, and that is the
/// trader's call, not the validator's.
///   ada_in 1,000,000 -> tokens_out 124,987 ; new_tok 1,142,732,156
test buy_accepts_a_one_ada_buy_with_no_minimum() {
  let new_d = pd(1_000_000, 1_142_732_156)
  let tx =
    buy_tx_outs(
      [p_out(1_000_000, 1_142_732_156, new_d), plat(2_000_000), crea(10_000)],
    )
  spend_pool(buy_old(), Buy { min_out: 124_987 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// R-5 — WHOLE-DATUM RECONSTRUCTION (Critical)
//
// One reject per immutable field on the Buy branch, plus the royalty key again
// on Sell. Every one of these is a canonical 1,000 ADA genesis buy — correct
// arithmetic, correct value movement, correct fees — that additionally rewrites
// ONE config field in the continuation datum. Without
// `with_reserves(d, …) == new_d` every one of them ACCEPTS, and the config
// fields they rewrite — `treasury_pkh`, `creator_pkh`, the three fee fields —
// direct every payout the pool will ever make, for the price of one ordinary
// trade. (This paragraph used to say the first one "steals the creator's
// perpetual Splash royalty". `royalty_pub_key` has had NO on-chain consumer
// since the Splash path was parked on 2026-07-26 — it is now a pinned-at-genesis
// field with no payout attached, and it is kept as the cleanest R-5 canary in the
// datum. The fee and pkh fields below are where the money actually is.)
// ══════════════════════════════════════════════════════════════════════════════

/// A buy that is valid in every respect except the mutated continuation datum.
fn buy_with_new_datum(new_d: PoolDatum) -> Transaction {
  buy_tx_outs(
    [
      script_out(t_pool, pool_value(1_000_000_000, 1_030_181_086), new_d),
      plat(2_000_000),
      crea(10_000_000),
    ],
  )
}

/// THE R-5 CANARY. 1,000 ADA buys 112,676,057 tokens and, in the same
/// transaction, repoints the pool's royalty key at the attacker.
///
/// This was THE exploit while the Splash path existed: that key became field 13
/// of the graduated royaltyPool datum, immutable for the life of the pool, so a
/// single trade took the creator's perpetual 0.50% forever. Splash was parked on
/// 2026-07-26 and `royalty_pub_key` now has no on-chain consumer, so THIS
/// PARTICULAR rewrite is no longer a theft — it is the sharpest available probe
/// of `with_reserves`, because it is the one ByteArray in the datum with no other
/// purpose. If this test ever passes, every other field is rewritable too.
test r5_rejects_rewriting_the_royalty_pub_key() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_royalty(1_000_000_000, 1_030_181_086, t_evil_royalty)),
  )
}

test r5_rejects_rewriting_the_creator_pkh() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_creator(1_000_000_000, 1_030_181_086, t_owner)),
  )
}

test r5_rejects_rewriting_the_treasury_pkh() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_treasury(1_000_000_000, 1_030_181_086, t_owner)),
  )
}

test r5_rejects_rewriting_the_policy_id() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_policy(1_000_000_000, 1_030_181_086, #"deadbeef")),
  )
}

test r5_rejects_rewriting_the_asset_name() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_name(1_000_000_000, 1_030_181_086, #"42414441")),
  )
}

test r5_rejects_zeroing_the_creator_fee_bps() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_cbps(1_000_000_000, 1_030_181_086, 0)),
  )
}

/// §5.6's "the platform fee becomes a per-pool datum fact pinned at genesis and
/// PRESERVED ON EVERY SPEND" — this is the "preserved" half.
///
/// This used to ZERO the field. The cohort's `platform_fee_bps_v3` IS now 0, so
/// writing 0 would reproduce the canonical datum and the test would be a valid
/// trade. The frozen-field defect is re-derived as writing the old 50 bps back —
/// any value other than the input's is what R-5 must refuse.
test r5_rejects_rewriting_the_platform_fee_bps() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_pbps(1_000_000_000, 1_030_181_086, 50)),
  )
}

test r5_rejects_zeroing_the_platform_fee_flat() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_with_new_datum(pd_pflat(1_000_000_000, 1_030_181_086, 0)),
  )
}

/// The Sell branch carries its own reconstruction — one branch getting it right
/// is not enough.
test r5_rejects_royalty_rewrite_on_the_sell_branch() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [
        script_out(
          t_pool,
          pool_value(806_836_034, 1_050_181_086),
          pd_royalty(806_836_034, 1_050_181_086, t_evil_royalty),
        ),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// A NON-CONSTR continuation datum — a Data LIST where a Constr is expected.
///
/// This is what the old `rejects_a_v2_shaped_continuation_datum` ACTUALLY tested:
/// `let v2_shaped: Data = (a, b, c)` encodes as `[_ a, b, c]`, a list, not a
/// v2 `Constr(0, …)`. It is a real (if weak) soft-cast path, so it is kept under
/// an honest name; the genuine tag-and-arity case now lives in
/// `rejects_a_v2_shaped_continuation_datum` further down, built from a real
/// 3-field record with a nullary third field.
test rejects_a_list_shaped_continuation_datum() fail {
  let list_shaped: Data = (1_000_000_000, 1_030_181_086, 0)
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        script_out(t_pool, pool_value(1_000_000_000, 1_030_181_086), list_shaped),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// SELL
// ══════════════════════════════════════════════════════════════════════════════

test sell_rejects_underpay_slippage() fail {
  spend_pool(inv_old(), Sell { min_out: 189_232_328 }, sell_good_tx())
}

/// Taking one lovelace more out of the reserve than the curve owes.
test sell_rejects_over_extracting_ada() fail {
  let new_d = pd(806_836_033, 1_050_181_086)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(806_836_033, 1_050_181_086, new_d), plat(2_000_000), crea(1_931_639)],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// A no-op sell at `min_out: 0`. TWO guards fire together here —
/// `tokens_in_positive` and `slippage_ok` (net is −2,000,000, the flat platform
/// fee on a zero gross) — so this does NOT prove the guard its name implies.
/// `sell_rejects_zero_tokens_in_isolated` below is the one that does.
test sell_rejects_zero_tokens_in() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(1_000_000_000, 1_030_181_086, inv_old()), plat(2_000_000)],
    )
  spend_pool(inv_old(), Sell { min_out: 0 }, tx)
}

test sell_rejects_missing_platform_fee() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(806_836_034, 1_050_181_086, inv_new()), crea(1_931_639)],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test sell_rejects_missing_creator_fee() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(806_836_034, 1_050_181_086, inv_new()), plat(2_000_000)],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test sell_rejects_nft_carried_out_of_the_pool() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [
        p_out_raw(809_336_034, 907_323_943, 0, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// The old sell-size boundary, kept as a pair with the inverted test below.
/// From (1,000,000,000, 1,030,181,086):
///   tokens_in = 1,016,674 ⇒ new_token_reserve = 1,031,197,760
///     new_effective = k / 1,031,197,760 = 10,132,857,142
///     gross = 10,142,857,144 − 10,132,857,142 = 10,000,002  (just over 10 ADA)
///     creator 100,000 ; platform 2,000,000 (flat) ; net 7,900,002
///   new = (989,999,998, 1,031,197,760) ⇒ 992,499,998 lovelace, 888,340,617 tokens
test sell_accepts_gross_just_over_the_minimum() {
  let new_d = pd(989_999_998, 1_031_197_760)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(989_999_998, 1_031_197_760, new_d), plat(2_000_000), crea(100_000)],
    )
  spend_pool(inv_old(), Sell { min_out: 7_900_002 }, tx)
}

/// …and ONE token less produces gross 9,999,992 — eight lovelace under what used
/// to be the sell-side minimum. IT IS NOW ACCEPTED, deliberately.
///
/// This test was `fail` while `validate_sell` carried
/// `ada_gross >= min_trade_ada_v3`. That guard is gone; see the long note at its
/// former site for why (it disabled the entire sell side whenever
/// `0 < ada_reserve < 10 ADA`, a state two ordinary trades from genesis, and a
/// full-drain exemption does not rescue it because reaching the cap needs
/// 100.0000% of the float). Inverting this test is the deliberate half of that
/// change and is what makes the removal visible rather than silent.
///   tokens_in = 1,016,673 ⇒ new_token_reserve = 1,031,197,759, gross 9,999,992
///   creator 99,999 ; platform 2,000,000 (flat) ; net 7,899,993
test sell_accepts_gross_just_under_the_old_minimum() {
  let new_d = pd(990_000_008, 1_031_197_759)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(990_000_008, 1_031_197_759, new_d), plat(2_000_000), crea(99_999)],
    )
  spend_pool(inv_old(), Sell { min_out: 7_899_993 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// THE TRAPPED-HOLDER STATE  (the sell-side `size_ok` defect)
//
// Reached in TWO ordinary trades from genesis:
//   1. buy 25,000,000       → tokens_out 3,116,479, (25,000,000, 1,139,740,664)
//   2. sell 2,491,820       → gross 20,000,001,      (4,999,999, 1,142,232,484)
// 624,659 tokens remain outstanding in other wallets and the curve reserve is
// 4,999,999 lovelace — below the old 10 ADA minimum. Because `quote_sell_gross`
// caps the gross at `ada_reserve`, the largest gross obtainable here is
// 4,999,999, so while the sell branch carried a 10 ADA floor NO sell of any size
// was legal and every holder was frozen out permanently.
//
// Value at (4,999,999, 1,142,232,484): 7,499,999 lovelace, 999,375,341 tokens.
// ══════════════════════════════════════════════════════════════════════════════

fn trapped_old() -> PoolDatum {
  pd(4_999_999, 1_142_232_484)
}

/// A PARTIAL exit from the trapped state. This is the case a symmetric
/// full-drain exemption (`|| ada_gross == old_ada`) would NOT have rescued: the
/// holder sells half the outstanding float and grosses 2,500,682, which is
/// neither ≥10 ADA nor equal to `ada_reserve`.
///   tokens_in = 312,329 ⇒ new_token_reserve = 1,142,544,813
///   effective = 9,147,857,143 ; gross = 2,500,682
///   new = (2,499,317, 1,142,544,813) ⇒ 4,999,317 lovelace, 999,687,670 tokens
///   creator 25,006 ; platform 2,000,000 (flat) ; net 475,676
test sell_accepts_a_partial_exit_from_a_sub_minimum_reserve() {
  let new_d = pd(2_499_317, 1_142_544_813)
  let tx =
    base_tx(
      [p_in(4_999_999, 1_142_232_484, trapped_old())],
      [p_out(2_499_317, 1_142_544_813, new_d), plat(2_000_000), crea(25_006)],
    )
  spend_pool(trapped_old(), Sell { min_out: 475_676 }, tx)
}

/// The FULL drain from the trapped state: all 624,659 outstanding tokens, gross
/// capped at the whole 4,999,999 reserve, leaving `ada_reserve == 0`.
///   new_token_reserve = 1,142,857,143 (= virtual_token_v3 — `cap_ok`'s boundary,
///   satisfied by equality, which is the round-trip back to genesis)
///   new = (0, 1,142,857,143) ⇒ 2,500,000 lovelace, 1e9 tokens
///   creator 49,999 ; platform 2,000,000 (flat) ; net 2,950,000
test sell_accepts_a_full_drain_from_a_sub_minimum_reserve() {
  let new_d = pd(0, 1_142_857_143)
  let tx =
    base_tx(
      [p_in(4_999_999, 1_142_232_484, trapped_old())],
      [p_out(0, 1_142_857_143, new_d), plat(2_000_000), crea(49_999)],
    )
  spend_pool(trapped_old(), Sell { min_out: 2_950_000 }, tx)
}

/// `cap_ok` on the sell branch — the guard that was MISSING entirely. One token
/// past a full round-trip drives `token_reserve` to `virtual_token_v3 + 1`, above
/// X_c, where the price model is outside its calibrated domain. Nothing local
/// rejected this before; it held only by a cross-contract supply argument.
///
///   tokens_in = 624,660 ⇒ new_token_reserve = 1,142,857,144
///   uncapped gross 5,000,007 > ada_reserve, so the cap binds at 4,999,999 and
///   every other guard — `correct_gross`, `out_consistent`, the fees — passes.
///   new = (0, 1,142,857,144) ⇒ 2,500,000 lovelace, 1,000,000,001 tokens
test sell_rejects_pushing_the_reserve_above_the_virtual_token_cap() fail {
  let new_d = pd(0, 1_142_857_144)
  let tx =
    base_tx(
      [p_in(4_999_999, 1_142_232_484, trapped_old())],
      [p_out(0, 1_142_857_144, new_d), plat(2_000_000), crea(49_999)],
    )
  spend_pool(trapped_old(), Sell { min_out: 2_950_000 }, tx)
}

/// `tokens_in_positive` ISOLATED. A no-op sell with `min_out` low enough that
/// `slippage_ok` passes (net = −2,000,000, the flat platform fee on a zero
/// gross), so the ONLY guard that rejects is the positivity check. While the
/// sell branch carried `size_ok` this state was unreachable-in-isolation and the
/// guard was bound by nothing.
test sell_rejects_zero_tokens_in_isolated() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [p_out(1_000_000_000, 1_030_181_086, inv_old()), plat(2_000_000)],
    )
  spend_pool(inv_old(), Sell { min_out: -2_000_000 }, tx)
}

/// A closed pool is FROZEN on the sell side too. If a 1-token sell could reopen
/// the curve, anyone could grief every graduation attempt indefinitely for the
/// price of one trade.
///   old = (16,717,047,886, 404,061,018) ⇒ 16,719,547,886 lovelace, 261,203,875 tok
///   tokens_in = 1,000,000 ⇒ gross 63,841,999, new = (16,653,205,887, 405,061,018)
///   creator 638,419 ; platform 2,000,000 (flat) ; net 61,203,580
test sell_rejects_reopening_a_closed_curve() fail {
  let old_d = pd(16_717_047_886, 404_061_018)
  let new_d = pd(16_653_205_887, 405_061_018)
  let tx =
    base_tx(
      [p_in(16_717_047_886, 404_061_018, old_d)],
      [p_out(16_653_205_887, 405_061_018, new_d), plat(2_000_000), crea(638_419)],
    )
  spend_pool(old_d, Sell { min_out: 61_203_580 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// THE AMM TEST WORLD
//
// Every number below is RE-DERIVED from `params_v3`, and each derivation is
// written beside the test that uses it. NOTHING is ported — not from v2, and not
// from the Splash-path suite this section replaces, whose entire arithmetic
// (`lq0`, `lq_mint`, `n_nft`, `n_lq`, the fifteen-field birth datum) has no
// counterpart here.
//
// ── THE PHASE-1 LESSON THAT SHAPED THIS SECTION ─────────────────────────────
// A previous graduation suite contained a green ACCEPT test that certified a
// transaction spending 16,727,047,886 lovelace and 261,203,875 tokens and
// producing ONE output of 9 ADA to the submitter. 16,718 ADA and the whole pool
// bag were unaccounted for, and the test read as an ordinary happy path. The
// lesson: an accept case that constrains only some guards stays green when the
// missing guards are added, so it certifies nothing.
//
// Therefore EVERY accept case below is a COMPLETE, self-consistent transaction —
// real value, real datum, real fee outputs — and every reject mutates exactly ONE
// property away from it. Where two guards necessarily fire together, the test
// comment says so and `mutverify.sh` binds them as a matched pair rather than
// pretending either is isolated.
//
// ── STANDING STATE: THE CANONICAL GRADUATED POOL ─────────────────────────────
//
//   GA = 16,717,047,886    the two-step close (16,000 ADA genesis buy, then a
//                          717,047,886 lovelace closing buy). One of the two ends
//                          of the reachable range; the other is the one-shot
//                          ceiling 16,717,047,991
//                          (`params_v3.params_max_reachable_close_is_the_one_shot_ceiling`).
//   GT = pool_bag_v3       = 261,203,875. Pinned by the rebase, never computed.
//   k  = GA × GT           = 4,366,557,686,383,758,250
//
//   Bootstrap pool VALUE for datum (a, t):  a + 10,000,000 lovelace
//                                          t − 142,857,143 curve tokens
//                                          + 1 pool NFT
//   Amm       pool VALUE for datum (a, t):  a lovelace
//                                          t curve tokens
//                                          + 1 pool NFT
//   The two differ by exactly (pool_floor_v3, token_offset_v3) and the four
//   cross-mode rejects below are what stop one being read as the other.
// ══════════════════════════════════════════════════════════════════════════════

/// The canonical closing ADA reserve, and the graduated pool's token balance.
const ga: Int = 16_717_047_886

const gt: Int = pool_bag_v3

/// The other end of the reachable range.
const ga_ceiling: Int = 16_717_047_991

// ── Amm-mode datum builders, mirroring the Bootstrap `pd_*` set ───────────────

/// The canonical Amm datum at reserves (a, t) — same config half as `pd`.
fn pdm(a: Int, t: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, Amm)
}

/// A Bootstrap-config datum with an ARBITRARY mode, for the monotonicity rejects.
fn pd_mode(a: Int, t: Int, x: PoolMode) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, x)
}

// One-config-field mutations of `pdm`, for the R-5 rejects on the AMM branches.

fn am_policy(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(x, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, Amm)
}

fn am_name(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, x, a, t, t_creator, t_treasury, 100, 0, 2_000_000, t_royalty, Amm)
}

fn am_creator(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, t_name, a, t, x, t_treasury, 100, 0, 2_000_000, t_royalty, Amm)
}

fn am_treasury(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, x, 100, 0, 2_000_000, t_royalty, Amm)
}

fn am_cbps(a: Int, t: Int, x: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, x, 0, 2_000_000, t_royalty, Amm)
}

fn am_pbps(a: Int, t: Int, x: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, x, 2_000_000, t_royalty, Amm)
}

fn am_pflat(a: Int, t: Int, x: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, x, t_royalty, Amm)
}

fn am_royalty(a: Int, t: Int, x: ByteArray) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_treasury, 100, 0, 2_000_000, x, Amm)
}

// ── Amm value / input / output helpers ────────────────────────────────────────

/// An Amm pool's value: NO floor on the lovelace, NO offset on the tokens.
fn amm_value(a: Int, t: Int) -> Value {
  ada_token(a, t_policy, t_name, t) |> assets.add(t_policy, pool_nft_name, 1)
}

fn am_in(a: Int, t: Int, d: PoolDatum) -> Input {
  input_of(p_ref(), script_out(t_pool, amm_value(a, t), d))
}

fn am_out(a: Int, t: Int, d: PoolDatum) -> Output {
  script_out(t_pool, amm_value(a, t), d)
}

/// Amm pool output with an ARBITRARY value — for the value-invariant rejects,
/// where the whole point is that the value and the datum disagree.
fn am_out_raw(lovelace: Int, real_tokens: Int, nft: Int, d: PoolDatum) -> Output {
  let v =
    ada_token(lovelace, t_policy, t_name, real_tokens)
      |> assets.add(t_policy, pool_nft_name, nft)
  script_out(t_pool, v, d)
}

// ══════════════════════════════════════════════════════════════════════════════
// GRADUATE — the one-way flip.
//
//   input   Bootstrap (ga, curve_exhausted_token_reserve)
//           value: 16,719,547,886 lovelace, 261,203,875 tokens, 1 NFT
//           (16,717,047,886 + 2,500,000 floor ; 404,061,018 − 142,857,143)
//   output  Amm (ga, pool_bag_v3) at THE SAME address
//           value: 16,717,047,886 lovelace, 261,203,875 tokens, 1 NFT
//   bounty  10,000,000 lovelace to whoever built it — the difference between the
//           two lovelace figures, and nothing else
//   mint    zero
//
// NOT ONE TOKEN MOVES: 404,061,018 − 142,857,143 == 261,203,875 == pool_bag_v3
// (`params_v3.params_exhausted_real_balance_is_pool_bag`). The rebase changes the
// NUMBER IN THE DATUM and leaves the balance alone.
// ══════════════════════════════════════════════════════════════════════════════

/// The Bootstrap pool at exact curve exhaustion, ready to graduate.
fn grad_in(a: Int) -> Input {
  p_in(a, curve_exhausted_token_reserve, pd(a, curve_exhausted_token_reserve))
}

/// …at an arbitrary oref, for the double-satisfaction case.
fn grad_in_at(tag: ByteArray, a: Int) -> Input {
  input_of(
    oref(tag, 0),
    script_out(
      t_pool,
      pool_value(a, curve_exhausted_token_reserve),
      pd(a, curve_exhausted_token_reserve),
    ),
  )
}

/// The correct continuation: same address, Amm datum, rebased reserve, exactly
/// `a` lovelace.
fn grad_out(a: Int) -> Output {
  am_out(a, pool_bag_v3, pdm(a, pool_bag_v3))
}

/// The permissionless bounty — `pool_floor_v3` to the submitter's wallet.
fn bounty() -> Output {
  pk_out(t_owner, pool_floor_v3)
}

fn grad_tx(a: Int, outs: List<Output>) -> Transaction {
  base_tx([grad_in(a)], outs)
}

fn grad_good_tx(a: Int) -> Transaction {
  grad_tx(a, [grad_out(a), bounty()])
}

fn grad_spend(a: Int, tx: Transaction) -> Bool {
  spend_pool(pd(a, curve_exhausted_token_reserve), Graduate, tx)
}

// ── The happy path, at both ends of the reachable range ───────────────────────

test graduate_accepts_the_canonical_two_step_close() {
  grad_spend(ga, grad_good_tx(ga))
}

/// The one-shot ceiling — the largest closing reserve any path can reach.
/// `A` is NEVER hardcoded in the validator, so both ends must be accepted.
test graduate_accepts_the_one_shot_ceiling() {
  grad_spend(ga_ceiling, grad_good_tx(ga_ceiling))
}

/// ██ THE FLIP PRODUCES EXACTLY THE UTxO THE AMM BRANCHES CONSUME. ██
///
/// This is the graduation boundary as a STRUCTURAL identity rather than an
/// arithmetic one: the Output that `graduate_accepts_the_canonical_two_step_close`
/// creates is byte-identical to the resolved Output that
/// `amm_buy_accepts_the_canonical_trade` spends. So the pool the flip leaves behind
/// is provably tradable, and there is no gap between "graduation succeeded" and
/// "the AMM works" for a bug to hide in.
///
/// The PRICE half of the continuity claim is proven with exact integers in
/// `math_v3.amm_open_price_matches_the_curve_close_at_the_two_step_close` and its
/// four siblings (residual +1.19e-08% to −2.26e-04%, both signs, and the exact
/// cross-multiplied integers). This is the state half.
test graduate_output_is_the_amm_input() {
  let flipped = grad_out(ga)
  let amm_utxo = am_in(ga, gt, pdm(ga, gt))
  flipped == amm_utxo.output
}

/// A self-seeded pool graduated at the MINIMUM legal reserve of one lovelace.
/// Legal and harmless — the author converts their own money into their own locked
/// AMM — and it is the boundary case for `graduation_curve_checks`' `x >= 1`, at
/// the point where `assets.from_lovelace(x)` still produces a lovelace ENTRY and
/// the three-entry count still holds.
///   in  value: 1 + 2,500,000 = 2,500,001 lovelace, 261,203,875 tokens, NFT
///   out value:                          1 lovelace, 261,203,875 tokens, NFT
///
/// ── ██ THIS IS THE VALIDATOR'S BOUND, NOT THE LEDGER'S. THE TX IS UNBUILDABLE. ██
/// Do not read this test as "a graduated pool may legally hold 1 lovelace". Under
/// Conway's `coinsPerUTxOByte` = 4310, a three-entry TxOut carrying this eleven-field
/// inline datum (two 28-byte hashes, a 32-byte key, six ints, a nullary constr)
/// serialises to roughly 420–460 bytes, so its min-UTxO deposit is ≈1.81–1.98 ADA —
/// call it ~1.9 ADA. The transaction this test certifies is therefore unbuildable at
/// the LEDGER layer by three orders of magnitude.
///
/// So there are TWO lower bounds and only one of them is here: the validator's is
/// `x >= 1` and the ledger's is ~1,900,000. The validator deliberately does not
/// enforce the ledger's — a script must not encode a protocol parameter that can be
/// changed by a hard fork — but a reader reasoning from this test alone would
/// conclude the reachable floor is 1 lovelace. It is not. The state is only reachable
/// on a self-seeded pool at all; a genuine curve always closes near A = 16,717 ADA,
/// and `ada_in_positive` plus `old_ada >= 0` guarantees every reachable close carries
/// A >= 1 (see `math_v3.graduation_curve_checks`).
///
/// The consequence to watch for: if a future retune ever made a low-A close
/// reachable — a smaller `virtual_ada_v3`, or a cohort with a smaller F₀ — this guard
/// would PASS and the graduation would be unsubmittable with no diagnosable reason.
/// The name says "arithmetic minimum" so that stays visible.
test graduate_accepts_the_arithmetic_minimum_reserve_unbuildable_at_the_ledger() {
  grad_spend(1, grad_good_tx(1))
}

/// The submitter funds the transaction from their own wallet and takes change.
/// Wallet inputs are unrestricted; only SCRIPT inputs are confined.
test graduate_accepts_submitter_wallet_inputs_and_change() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [grad_in(ga), wallet_in(#"1111", 5_000_000)],
      outputs: [grad_out(ga), bounty(), pk_out(t_owner, 3_000_000)],
    }
  grad_spend(ga, tx)
}

/// ██ G13 — "PERMISSIONLESS" IS BOUND IN THE POSITIVE DIRECTION. ██
///
/// The branch reads no signature or credential field, so a transaction that
/// happens to populate `extra_signatories` — which Lucid's `addSignerKey` does on
/// some collateral and multi-witness paths, and which hardware and multisig flows
/// do routinely — must still be accepted.
///
/// A REJECT TEST HERE WOULD LOCK IN AN AVAILABILITY DEFECT. An
/// `extra_signatories == []` assert buys zero security (it reads the tx body's
/// required-signers field, not the witness set, so every ordinary wallet
/// transaction satisfies it) while removing valid graduations from the accepted
/// set — on a one-way door §8.3 wants to be "a button any connected wallet can
/// press". This test goes RED if anyone adds one, which is the direction the risk
/// actually lies in.
test graduate_accepts_an_incidental_required_signer() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [grad_in(ga)],
      outputs: [grad_out(ga), bounty()],
      extra_signatories: [t_owner],
    }
  grad_spend(ga, tx)
}

// ── G0 / G3 — the curve must be finished ──────────────────────────────────────

/// ██ THE C-1 SKIM. A LIVE CURVE IS NOT GRADUABLE. ██
///
/// This transaction is fully well-formed in every other respect and it steals
/// 626,120,068 tokens — 62.6% of total supply — for the price of a transaction fee.
///
/// From the ordinary mid-curve state (1,000,000,000, 1,030,181,086) the pool holds
/// 1,030,181,086 − 142,857,143 = 887,323,943 real tokens. `with_graduation`
/// rebases `token_reserve` to `pool_bag_v3` = 261,203,875 REGARDLESS of the input's
/// reserve (`pool_types.with_graduation_ignores_the_input_token_reserve` pins that
/// deliberately), and `expected_value` is built from the same constant. So the
/// continuation is perfectly self-consistent while 887,323,943 − 261,203,875 =
/// 626,120,068 tokens walk out of the pool, plus the 2.5 ADA bounty.
///
/// `curve_ok` — `graduation_curve_checks`' G0 — is the ONLY guard rejecting it.
/// That is why the rebase being unconditional is safe: G0 is what conditions it.
test graduate_rejects_a_live_curve() fail {
  let d = pd(1_000_000_000, 1_030_181_086)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, d)],
      [
        am_out(1_000_000_000, pool_bag_v3, pdm(1_000_000_000, pool_bag_v3)),
        bounty(),
      ],
    )
  spend_pool(d, Graduate, tx)
}

/// ONE TOKEN SHORT of exhaustion, which is the same skim for one token.
///   state (16,717,047,879, 404,061,019) — real balance 261,203,876
///   the flip would hand the Amm 261,203,875 and skim exactly 1
/// Both of `graduation_curve_checks`' clauses fire (G0's equality and G3's bag
/// identity are the same condition — `math_v3` says so rather than implying
/// otherwise), and nothing else does.
test graduate_rejects_a_curve_one_token_short_of_exhaustion() fail {
  let d = pd(16_717_047_879, curve_exhausted_token_reserve + 1)
  let tx =
    base_tx(
      [p_in(16_717_047_879, curve_exhausted_token_reserve + 1, d)],
      [
        am_out(16_717_047_879, pool_bag_v3, pdm(16_717_047_879, pool_bag_v3)),
        bounty(),
      ],
    )
  spend_pool(d, Graduate, tx)
}

/// A closed curve with a ZERO ada reserve. TWO guards fire and the test says so:
/// `graduation_curve_checks`' `x >= 1`, and `value_ok`'s three-entry count —
/// because `assets.from_lovelace(0)` is `zero` in stdlib, so the continuation
/// value has only TWO entries.
///
/// The `x >= 1` clause is isolated at the pure-function level by
/// `math_v3.graduation_checks_reject_an_empty_ada_reserve`, which is where it
/// belongs: what it protects against is an Amm pool with k = 0, price 0, and
/// 261,203,875 tokens nobody can ever buy or sell, and that is an arithmetic
/// property rather than a transaction-shape one.
test graduate_rejects_a_zero_ada_reserve_pool() fail {
  let d = pd(0, curve_exhausted_token_reserve)
  let tx =
    base_tx(
      [p_in(0, curve_exhausted_token_reserve, d)],
      [am_out(0, pool_bag_v3, pdm(0, pool_bag_v3)), bounty()],
    )
  spend_pool(d, Graduate, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// ██  THE TOKEN_RESERVE REBASE. 404,061,018 (VIRTUAL) -> 261,203,875 (REAL).  ██
// ══════════════════════════════════════════════════════════════════════════════

/// ██ THE "FORGOT TO REBASE" BUG. A FLIP THAT KEEPS 404,061,018 IS REFUSED. ██
///
/// This is the single most likely mistake in the whole branch, because 404,061,018
/// is what the field says on the way IN and copying it through is what a
/// record-update spread would have done silently. The datum here is otherwise
/// perfect — mode `Amm`, correct `ada_reserve`, correct config — and the VALUE is
/// correct too, so only `datum_ok` (`with_graduation(d) == new_d`) rejects it.
///
/// WHAT IT WOULD COST. The Amm invariant is `quantity_of(value) == token_reserve`
/// with no offset, so a pool claiming 404,061,018 while holding 261,203,875 fails
/// `in_consistent` on EVERY subsequent spend — `AmmBuy`, `AmmSell`, and the curve
/// branches too (they reject the mode). The pool would be PERMANENTLY UNSPENDABLE
/// with 16,717 ADA and 26.1% of supply locked inside it and no recovery at any
/// layer. And in the counterfactual where the invariant were mode-blind, it would
/// price 404,061,018/261,203,875 = 1.547× too many tokens per ADA — a 35.4%
/// discount handed to the first buyer.
test graduate_rejects_keeping_the_virtual_curve_reserve() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        am_out(ga, pool_bag_v3, pdm(ga, curve_exhausted_token_reserve)),
        bounty(),
      ],
    ),
  )
}

/// …and ANY other value, not merely that one. Both neighbours of `pool_bag_v3`.
/// The rebase target is a compile-time constant on both sides of the equality, so
/// this is exact and admits nothing.
test graduate_rejects_a_token_reserve_one_below_the_pool_bag() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, pdm(ga, pool_bag_v3 - 1)), bounty()]),
  )
}

test graduate_rejects_a_token_reserve_one_above_the_pool_bag() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, pdm(ga, pool_bag_v3 + 1)), bounty()]),
  )
}

/// A plausible WRONG rebase: subtracting the offset twice, i.e.
/// 261,203,875 − 142,857,143 = 118,346,732. Named because "apply `real_tokens`
/// to the already-real balance" is the mirror of the forgot-to-rebase bug and a
/// reviewer reaching for a helper function would reach for exactly that one.
test graduate_rejects_applying_the_token_offset_twice() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        am_out(ga, pool_bag_v3, pdm(ga, pool_bag_v3 - token_offset_v3)),
        bounty(),
      ],
    ),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// ██  MODE MONOTONICITY. Bootstrap -> Amm, ONCE, AND NEVER BACK.              ██
// ══════════════════════════════════════════════════════════════════════════════

/// ██ A GRADUATED POOL CANNOT BE GRADUATED AGAIN — AND `with_graduation` DOES ██
/// ██ NOT STOP IT. THIS IS WHAT `mode == Bootstrap` IS FOR.                   ██
///
/// The trap is that `with_graduation` is a FIXED POINT on an Amm datum
/// (`pool_types.with_graduation_is_a_fixed_point_on_an_amm_pool`), so the R-5
/// equality is SATISFIED by a re-graduation. Something else has to reject it.
///
/// AND THE STATE WHERE IT BITES IS REACHABLE. `graduation_curve_checks` requires
/// `token_reserve == curve_exhausted_token_reserve` = 404,061,018, and an Amm
/// pool's token reserve GROWS on sells: selling exactly `token_offset_v3` =
/// 142,857,143 tokens into the fresh graduated pool lands it on
/// 261,203,875 + 142,857,143 = 404,061,018 exactly.
///   AmmSell 142,857,143 from (16,717,047,886, 261,203,875)
///     k = 4,366,557,686,383,758,250
///     new_tok = 404,061,018 ; new_ada = k / 404,061,018 = 10,806,678,921
///     gross = 16,717,047,886 − 10,806,678,921 = 5,910,368,965
///   ⇒ Amm pool at (10,806,678,921, 404,061,018), holding 404,061,018 REAL tokens.
///
/// From THERE, `Graduate` passes G0 (404,061,018 ✓), passes G3's bag identity
/// (404,061,018 − 142,857,143 == 261,203,875 ✓), passes `x >= 1`, and
/// `with_graduation` produces exactly the datum below — so `datum_ok` passes and
/// `value_ok` passes. The flip would skim 404,061,018 − 261,203,875 =
/// 142,857,143 TOKENS — 14.29% of total supply — out of the pool, and release a
/// SECOND `pool_floor_v3` bounty which, the Amm invariant having no floor, comes
/// straight out of `ada_reserve`. Repeatable every time the reserve is walked back
/// onto 404,061,018.
///
/// `mode == Bootstrap` is the ONLY guard that rejects it. mutverify proves that.
test graduate_rejects_regraduating_an_amm_pool() fail {
  let a = 10_806_678_921
  let d = pdm(a, curve_exhausted_token_reserve)
  let tx =
    base_tx(
      [am_in(a, curve_exhausted_token_reserve, d)],
      [am_out(a, pool_bag_v3, pdm(a, pool_bag_v3)), bounty()],
    )
  spend_pool(d, Graduate, tx)
}

/// The plain form of the same thing, on a FRESH graduated pool. Two guards fire
/// here (`mode_ok` and G0, because a fresh Amm pool's reserve is 261,203,875 and
/// not 404,061,018), which is exactly why the reachable-state version above exists
/// — this one alone would not prove `mode_ok` is load-bearing.
test graduate_rejects_regraduating_a_fresh_amm_pool() fail {
  let d = pdm(ga, gt)
  let tx = base_tx([am_in(ga, gt, d)], [am_out(ga, gt, d), bounty()])
  spend_pool(d, Graduate, tx)
}

/// ██ Amm -> Bootstrap IS UNCONSTRUCTIBLE. ██ Half two of monotonicity: `mode`
/// is in `with_reserves`' FROZEN set, so no trade branch can write `Bootstrap`
/// into a continuation. There is no expression anywhere in the project that
/// produces `Bootstrap` from an existing datum.
///
/// WHAT IT WOULD COST. A pool walked back to `Bootstrap` holds `pool_bag_v3`-scale
/// REAL tokens while the curve branches read `token_reserve` as VIRTUAL and
/// subtract `token_offset_v3` from it. At the canonical graduated state the
/// continuation would be required to hold 261,203,875 − 142,857,143 =
/// 118,346,732 tokens, i.e. 142,857,143 tokens — 14.29% of supply — become
/// unaccounted for in the pool's own invariant and are free for the taking. The
/// pool would also re-open a curve that has already terminated.
///
/// Bound on BOTH trade branches, because `with_reserves` is called from both and a
/// reviewer relaxing one would not necessarily relax the other.
test amm_buy_rejects_flipping_the_mode_back_to_bootstrap() fail {
  let d = pdm(ga, gt)
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [
        am_out(
          ga + 1_000_000_000,
          246_502_534,
          pd_mode(ga + 1_000_000_000, 246_502_534, Bootstrap),
        ),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(d, AmmBuy { min_out: 14_000_000 }, tx)
}

test amm_sell_rejects_flipping_the_mode_back_to_bootstrap() fail {
  let d = pdm(ga, gt)
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [
        am_out(
          12_098_949_302,
          361_203_875,
          pd_mode(12_098_949_302, 361_203_875, Bootstrap),
        ),
        plat(2_000_000),
        crea(46_180_985),
      ],
    )
  spend_pool(d, AmmSell { min_out: 4_500_000_000 }, tx)
}

// ── The bounty is arithmetic: `ada_reserve` frozen, output lovelace pinned ─────

/// The submitter tries to take ONE LOVELACE MORE than the floor by understating
/// the output's lovelace. `value_ok`'s equality — `lovelace == x`, not `>=` —
/// rejects it. The datum is untouched, so this isolates the VALUE half.
test graduate_rejects_one_lovelace_more_than_the_bounty() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out(ga - 1, pool_bag_v3, pdm(ga, pool_bag_v3)), pk_out(t_owner, pool_floor_v3 + 1)],
    ),
  )
}

/// …and the version that would actually be worth doing: take HALF THE RESERVE.
/// 8,358 ADA to the submitter. Same guard, and named separately because "the
/// output's lovelace is an equality, not a floor" is the entire reason the
/// permissionless bounty is safe.
test graduate_rejects_draining_half_the_reserve_as_bounty() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        am_out(ga / 2, pool_bag_v3, pdm(ga, pool_bag_v3)),
        pk_out(t_owner, ga / 2 + pool_floor_v3),
      ],
    ),
  )
}

/// The DATUM half: understating `ada_reserve` while the value is correct.
/// `with_graduation` carries `ada_reserve` through unchanged, so `datum_ok`
/// rejects it. Without the freeze a submitter could write a smaller
/// `ada_reserve` into the datum and then extract the difference on the FIRST
/// `AmmSell`, because `out_consistent` would have been satisfied by a value the
/// datum understated.
test graduate_rejects_understating_the_ada_reserve_in_the_datum() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, pdm(ga - 1, pool_bag_v3)), bounty()]),
  )
}

test graduate_rejects_overstating_the_ada_reserve_in_the_datum() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, pdm(ga + 1, pool_bag_v3)), bounty()]),
  )
}

/// ██ KEEPING THE POOL FLOOR AS A MIN-UTxO CUSHION IS REFUSED. ██
///
/// The well-intentioned version of this branch: "leave the 2.5 ADA in, the pool
/// needs a min-UTxO anyway". It is a TOTAL-LOSS bug. `with_graduation` freezes
/// `ada_reserve` at `x`, so the datum says 16,717,047,886 while the value holds
/// 16,719,547,886 — and the Amm invariant is `lovelace == ada_reserve` with NO
/// floor term, so `in_consistent` fails on every subsequent spend and the pool is
/// permanently unspendable. The cushion is not needed: `value_ok` pins the
/// lovelace to `x`, which is ~16,717 ADA, four orders of magnitude above any
/// min-UTxO, and `math_v3.amm_sell_of_the_whole_float_leaves_4366_ada` shows the
/// arithmetic never lets it fall below 4,366 ADA.
test graduate_rejects_keeping_the_pool_floor_in_the_pool() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        am_out_raw(ga + pool_floor_v3, pool_bag_v3, 1, pdm(ga, pool_bag_v3)),
      ],
    ),
  )
}

// ── The value: exactly three entries, exactly these quantities ───────────────

test graduate_rejects_the_pool_bag_short_by_one_token() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out_raw(ga, pool_bag_v3 - 1, 1, pdm(ga, pool_bag_v3)), bounty()],
    ),
  )
}

test graduate_rejects_the_pool_bag_long_by_one_token() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out_raw(ga, pool_bag_v3 + 1, 1, pdm(ga, pool_bag_v3)), bounty()],
    ),
  )
}

/// ██ SKIMMING THE BAG INTO A WALLET. THE C-1 CLAIM, DIRECTLY. ██
/// Half the pool bag — 130,601,937 tokens, 13.1% of total supply — diverted to the
/// submitter while an otherwise well-formed Amm pool is created. `value_ok`'s
/// whole-`Value` equality refuses it; there is no separate "count the outputs
/// holding the curve token" guard because the equality is stricter than one.
test graduate_rejects_skimming_the_pool_bag_into_a_wallet() fail {
  let keep = pool_bag_v3 / 2
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        am_out_raw(ga, pool_bag_v3 - keep, 1, pdm(ga, pool_bag_v3)),
        pk_out(t_owner, pool_floor_v3),
      ],
    ),
  )
}

/// A fourth asset welded into the pool at the moment it becomes permanent.
/// Rejected by `value_ok` on BOTH halves (the equality and the three-entry count),
/// which is the same reasoning the Splash path used for its four-entry value and
/// which does not depend on Splash at all: after graduation the junk is NOT
/// self-healing, because the Amm's lovelace is pinned to `ada_reserve` with no
/// floor and a raised ledger min-UTxO makes large sells unbuildable.
test graduate_rejects_junk_assets_in_the_graduated_pool() fail {
  let v =
    amm_value(ga, pool_bag_v3)
      |> assets.add(
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          #"4a554e4b",
          1,
        )
  grad_spend(
    ga,
    grad_tx(ga, [script_out(t_pool, v, pdm(ga, pool_bag_v3)), bounty()]),
  )
}

/// The pool NFT carried out to the submitter's wallet. TWO guards fire —
/// `value_ok`'s equality (which pins the NFT quantity to 1) and `pool_nft_kept` —
/// and `pool_nft_kept` is therefore FULLY REDUNDANT on this branch while the
/// equality stands. It is kept for the same reason the entry-count checks are: it
/// is the only thing left pinning the NFT if the equality is ever weakened to
/// "contains at least". `mutverify.sh` binds the two as a matched pair rather than
/// claiming either is isolated.
///
/// Without either, the graduated pool has no authenticator: `authentic` fails on
/// every subsequent spend, so ~16,717 ADA and 26.1% of supply are frozen forever
/// while the NFT sits in a wallet.
test graduate_rejects_the_nft_leaving_the_pool() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        am_out_raw(ga, pool_bag_v3, 0, pdm(ga, pool_bag_v3)),
        pk_out_token(t_owner, pool_floor_v3, t_policy, pool_nft_name, 1),
      ],
    ),
  )
}

test graduate_rejects_two_nfts_in_the_graduated_pool() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out_raw(ga, pool_bag_v3, 2, pdm(ga, pool_bag_v3)), bounty()]),
  )
}

// ── Nothing is minted, and NOTHING IS BURNED ──────────────────────────────────

/// ██ THE OLD `Retire` SHAPE, NOW REFUSED. ██
///
/// Under the Splash path this transaction was MANDATORY: graduation burned the
/// 1-of-1 pool NFT so that the LumpFun-side authenticator was destroyed as the
/// liquidity moved to a foreign venue. `lump_mint_v3.Retire` is deleted and the
/// NFT is never burned — it authenticates the pool for the token's entire life —
/// so the same mint field is now a hard reject.
///
/// This is the regression test for that deletion. If anyone re-adds a burn path to
/// the minting policy, this test is what says the pool branch still refuses to
/// participate.
test graduate_rejects_burning_the_pool_nft() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [grad_in(ga)],
      outputs: [grad_out(ga), bounty()],
      mint: assets.from_asset(t_policy, pool_nft_name, -1),
    }
  grad_spend(ga, tx)
}

/// Minting more of the curve token during the flip — the C-1 break from the mint
/// side. `no_mint` (`tx.mint == zero`) is stronger than `no_policy_mint` and
/// refuses it.
test graduate_rejects_minting_curve_tokens() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [grad_in(ga)],
      outputs: [grad_out(ga), bounty()],
      mint: assets.from_asset(t_policy, t_name, 1_000_000),
    }
  grad_spend(ga, tx)
}

/// A FOREIGN policy's mint riding along. Nothing of LumpFun's is at risk, but a
/// graduation bundled with an unrelated mint is a transaction an off-chain indexer
/// may mis-attribute to LumpFun, and `tx.mint == zero` costs one comparison.
test graduate_rejects_a_foreign_mint_riding_along() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [grad_in(ga)],
      outputs: [grad_out(ga), bounty()],
      mint: assets.from_asset(
        #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        #"4a554e4b",
        1,
      ),
    }
  grad_spend(ga, tx)
}

// ── Where the continuation may sit ────────────────────────────────────────────

/// ██ THE PHASE-1 C-1 DRAIN, in the shape it actually had: ONE output paying the
/// entire pool to the submitter's wallet. ██
///
/// `sole_continuation` finds ZERO outputs at the pool's payment credential and its
/// `expect [own_output]` ABORTS, which is the same rejection at the ledger as
/// returning False. Recorded in the shape it had because the previous version of
/// this branch ACCEPTED it: 16,719,547,886 lovelace and 261,203,875 tokens —
/// 26.1% of total supply, never bought on the curve — to one wallet output.
test graduate_rejects_paying_the_whole_pool_to_a_wallet() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        pk_out_token(
          t_owner,
          ga + pool_floor_v3,
          t_policy,
          t_name,
          pool_bag_v3,
        ),
      ],
    ),
  )
}

/// Moving the pool to ANOTHER script — the shape the Splash path used, and now
/// refused. Same `sole_continuation` abort: nothing sits at the pool's own
/// credential. v3 has no foreign destination for graduation.
test graduate_rejects_moving_the_pool_to_a_foreign_script() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        script_out(
          #"9999999999999999999999999999999999999999999999999999999a",
          amm_value(ga, pool_bag_v3),
          pdm(ga, pool_bag_v3),
        ),
        bounty(),
      ],
    ),
  )
}

/// ██ A STAKE CREDENTIAL ATTACHED AT THE MOMENT THE POOL BECOMES PERMANENT. ██
///
/// The continuation sits at the same script HASH but with a stake part, so
/// `sole_continuation` (which filters on the payment credential) finds it and
/// `continuation_address_exact` rejects it. This is the guard that had to be
/// corrected on the Splash path's G12 — a full-address comparison there missed
/// exactly this case, because the production curve address is an enterprise
/// address (`Address { Script(h), None }`) and `Address { Script(h), Some(...) }`
/// is a different `Data` value.
///
/// It matters MORE here than it did there. On the Splash path the curve UTxO was
/// destroyed, so a stake-part decoy was junk at a dead address. Here the pool
/// SURVIVES: whoever attaches the stake credential collects staking rewards on
/// ~16,717 ADA of other people's money FOR THE LIFE OF THE TOKEN, because the
/// address is then frozen by this same check on every subsequent spend.
test graduate_rejects_a_stake_credential_on_the_graduated_pool() fail {
  let staked =
    script_out_staked(
      t_pool,
      #"5555555555555555555555555555555555555555555555555555555a",
      amm_value(ga, pool_bag_v3),
      pdm(ga, pool_bag_v3),
    )
  grad_spend(ga, grad_tx(ga, [staked, bounty()]))
}

/// ██ THE CASE THAT BINDS `sole_continuation`'s CREDENTIAL FILTER, and the ONLY
/// ██ one that can: a stake-part decoy ALONGSIDE a perfectly correct continuation.
///
/// The test above is rejected either way — with a full-address filter the staked
/// output simply is not found and `expect [own_output]` aborts on an EMPTY list. It
/// therefore proves nothing about WHICH comparison the filter uses.
///
/// Here the correct continuation IS present at `Address { Script(t_pool), None }`,
/// so a full-address filter finds exactly one match and ACCEPTS, leaving a UTxO
/// parked at LumpFun's sole on-chain identifier with a stake credential its author
/// controls. Filtering on the PAYMENT CREDENTIAL finds two and aborts. This is the
/// same defect the Splash review found in G12, and it is the reason the filter was
/// changed rather than the reason it was already right.
test graduate_rejects_a_stake_part_decoy_alongside_the_real_continuation() fail {
  let decoy =
    script_out_staked(
      t_pool,
      #"5555555555555555555555555555555555555555555555555555555a",
      ada(2_000_000),
      pdm(ga, pool_bag_v3),
    )
  grad_spend(ga, grad_tx(ga, [grad_out(ga), decoy, bounty()]))
}

/// A SECOND output at the pool's own credential — a decoy at LumpFun's sole
/// on-chain identifier. `sole_continuation`'s `expect [own_output]` aborts on two
/// matches. An off-chain selector that filters pool UTxOs by ADDRESS and then
/// picks the first would bind the decoy.
test graduate_rejects_a_second_output_at_the_pool_credential() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [
        grad_out(ga),
        script_out(t_pool, ada(2_000_000), pdm(ga, pool_bag_v3)),
        bounty(),
      ],
    ),
  )
}

/// A DATUM HASH instead of an inline datum — the `expect InlineDatum(raw)` arm.
/// A graduated pool whose datum is not inline cannot be read by any spend, so the
/// pool would be dead on arrival with its whole reserve inside.
test graduate_rejects_a_datum_hash_on_the_graduated_pool() fail {
  let hashed =
    Output {
      address: address.from_script(t_pool),
      value: amm_value(ga, pool_bag_v3),
      datum: DatumHash(
        #"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      ),
      reference_script: None,
    }
  grad_spend(ga, grad_tx(ga, [hashed, bounty()]))
}

/// A reference script welded onto the pool at the flip. Under Conway's
/// reference-script fee tiers every trader pays for it — and unlike the curve
/// there is no later state where the pool goes away, so it is a permanent tax on
/// the token's entire post-graduation life.
test graduate_rejects_a_reference_script_on_the_graduated_pool() fail {
  let with_ref =
    Output {
      address: address.from_script(t_pool),
      value: amm_value(ga, pool_bag_v3),
      datum: InlineDatum(pdm(ga, pool_bag_v3)),
      reference_script: Some(
        #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ),
    }
  grad_spend(ga, grad_tx(ga, [with_ref, bounty()]))
}

// ── R-5 on the graduation branch: `with_graduation` freezes the config half ────
//
// Nine of the eleven fields must survive the flip untouched. Each reject below
// mutates exactly one and nothing else, so each isolates `datum_ok`.
//
// `policy_id` and `asset_name` are worth a note: `expected_value` is built from
// the INPUT datum's copies of those fields, so a continuation whose DATUM renames
// them while the VALUE still holds the original assets passes `value_ok` and is
// caught by `datum_ok` alone. That is the isolation those two tests need.

test graduate_rejects_rewriting_the_royalty_pub_key() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out(ga, pool_bag_v3, am_royalty(ga, pool_bag_v3, t_evil_royalty)), bounty()],
    ),
  )
}

test graduate_rejects_rewriting_the_creator_pkh() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out(ga, pool_bag_v3, am_creator(ga, pool_bag_v3, t_owner)), bounty()],
    ),
  )
}

test graduate_rejects_rewriting_the_treasury_pkh() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out(ga, pool_bag_v3, am_treasury(ga, pool_bag_v3, t_owner)), bounty()],
    ),
  )
}

test graduate_rejects_rewriting_the_policy_id() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out(ga, pool_bag_v3, am_policy(ga, pool_bag_v3, #"deadbeef")), bounty()],
    ),
  )
}

test graduate_rejects_rewriting_the_asset_name() fail {
  grad_spend(
    ga,
    grad_tx(
      ga,
      [am_out(ga, pool_bag_v3, am_name(ga, pool_bag_v3, #"42414441")), bounty()],
    ),
  )
}

/// ██ REWRITING THE PLATFORM FEE AT THE FLIP. ██ The graduated pool trades
/// FOREVER, so this is where most of a token's lifetime volume — and most of
/// LumpFun's revenue from it — actually is. Without `with_graduation`'s freeze,
/// whoever pressed the permissionless graduation button could rewrite the fee
/// schedule for the life of the pool.
///
/// This used to ZERO `platform_fee_bps`. The cohort rate IS now 0, so writing 0
/// would reproduce the canonical datum and the flip would be legal; the
/// frozen-field defect is re-derived as writing the old 50 bps back. (A raised
/// bps would even pass `fee_schedule_ok`'s `>=` floors on later trades, so the
/// flip's freeze is the ONLY thing refusing it.)
test graduate_rejects_rewriting_the_platform_fee_bps() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, am_pbps(ga, pool_bag_v3, 50)), bounty()]),
  )
}

test graduate_rejects_zeroing_the_platform_fee_flat() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, am_pflat(ga, pool_bag_v3, 0)), bounty()]),
  )
}

test graduate_rejects_zeroing_the_creator_fee_bps() fail {
  grad_spend(
    ga,
    grad_tx(ga, [am_out(ga, pool_bag_v3, am_cbps(ga, pool_bag_v3, 0)), bounty()]),
  )
}

// ── R-3 / V-1 on the graduation branch ────────────────────────────────────────

/// ██ DOUBLE SATISFACTION, THE V-1 SHAPE: TWO v3 POOLS IN ONE TRANSACTION. ██
///
/// Both inputs are genuine closed pools at LumpFun's one shared address. There is
/// ONE continuation. `sole_continuation` is satisfied by it for BOTH pool spends,
/// `value_ok` is satisfied for both (the two pools have the same reserves here, so
/// the same output is a correct continuation for either), and the whole second
/// pool — 16,719,547,886 lovelace plus 261,203,875 tokens — is unaccounted for and
/// walks out with the submitter.
///
/// `tx_shape_ok`'s `one_pool == 1` is what rejects it, and it rejects it on every
/// branch rather than per-branch, which is why this shape does not need a separate
/// guard in `validate_graduate`. It matters MORE in v3 than in v2 because v3's pool
/// is UNPARAMETERISED: every LumpFun token, in both modes, shares one script hash,
/// so two different tokens' pools genuinely can be co-spent unless this counts
/// them.
test graduate_rejects_a_second_pool_input() fail {
  let tx =
    base_tx(
      [grad_in(ga), grad_in_at(#"9999", ga)],
      [grad_out(ga), bounty()],
    )
  grad_spend(ga, tx)
}

/// A foreign script input bundled with a graduation — `tx_shape_ok`'s `confined`.
/// A graduation cannot be composed with any other contract.
test graduate_rejects_a_foreign_script_input() fail {
  let foreign =
    input_of(oref(#"0f0f", 0), script_out(#"0f0f0f0f", ada(5_000_000), 0))
  let tx = base_tx([grad_in(ga), foreign], [grad_out(ga), bounty()])
  grad_spend(ga, tx)
}

/// A decoy at the pool address WITHOUT the NFT, spent as though it were the pool.
/// The preamble's `authentic` rejects it. In v3 decoys cost nothing to create
/// because the address is shared, and a graduated decoy would be a second
/// "permanent AMM" for a token at LumpFun's sole on-chain identifier.
test graduate_rejects_a_pool_input_without_the_nft() fail {
  let d = pd(ga, curve_exhausted_token_reserve)
  let no_nft =
    input_of(
      p_ref(),
      script_out(
        t_pool,
        ada_token(
          ga + pool_floor_v3,
          t_policy,
          t_name,
          curve_exhausted_token_reserve - token_offset_v3,
        ),
        d,
      ),
    )
  spend_pool(d, Graduate, base_tx([no_nft], [grad_out(ga), bounty()]))
}

// ══════════════════════════════════════════════════════════════════════════════
// ██  THE FOUR CROSS-MODE REJECTS. ██
//
// Each one is a COMPLETE, otherwise-legal transaction in which the ONLY defect is
// that the redeemer belongs to the other half of the pool's life. Every other
// guard on the branch passes — the continuation is self-consistent under the mode
// the datum actually carries, the datum is correctly reconstructed with `mode`
// frozen, both fee outputs are paid in full on the correct base, the NFT is kept,
// the value shape is three entries. `mutverify.sh` proves that neutering the one
// `mode_ok` line is what turns each of these from red to green.
//
// TWO of the four are THEFTS and two are MISPRICINGS, and the asymmetry is worth
// stating because it says which line to be most careful with (v3.2 quotes):
//   AmmBuy on Bootstrap   STEALS TOKENS   514,316,746 vs 92,452,149 (5.563×)
//   Sell   on Amm         STEALS ADA      773,501,488 vs 392,370,589 (1.971×)
//   Buy    on Amm         shortchanges the buyer  23,518,097 vs 43,939,966
//   AmmSell on Bootstrap  shortchanges the seller 41,642,783 vs 232,693,338
// ══════════════════════════════════════════════════════════════════════════════

/// ██ 1 of 4 — `AmmBuy` ON A BOOTSTRAP POOL. 51.5% OF SUPPLY FOR 1,000 ADA. ██
///
/// State: the ordinary mid-curve pool (1,000,000,000, 1,030,181,086) — a token
/// that has raised 1,000 ADA. Value: 1,002,500,000 lovelace, 887,323,943 tokens.
///
/// `amm_quote_buy` prices on `ada_reserve` alone, omitting the 9,142.86 ADA virtual
/// cushion (v3.2 nets the input first and floors the amount out):
///   net = 1,000,000,000 × 9,970 / 10,000 = 997,000,000
///   out = ⌊997,000,000 × 1,030,181,086 / 1,997,000,000⌋ = 514,316,746
/// against the correct curve quote of 92,452,149:
///   effective = 1,000,000,000 + 9,142,857,144 = 10,142,857,144
///   k_curve   = 10,142,857,144 × 1,030,181,086
///   new_tok   = k_curve / 11,142,857,144 = 937,728,937
///   out       = 1,030,181,086 − 937,728,937 = 92,452,149
/// 514,316,746 / 92,452,149 = 5.563×, and 514,316,746 / 1e9 = 51.43% OF TOTAL
/// SUPPLY, in one transaction, for 1,000 ADA plus 12 ADA of fees.
///
/// Continuation (BOOTSTRAP invariant, because `mode` is still Bootstrap and
/// `with_reserves` freezes it): 2,002,500,000 lovelace, 515,864,340 − 142,857,143 =
/// 373,007,197 tokens. Self-consistent. Fees paid in full on `ada_in` = 1e9:
/// creator 10,000,000, platform 2,000,000 (flat).
test amm_buy_rejects_a_bootstrap_mode_pool() fail {
  let d = pd(1_000_000_000, 1_030_181_086)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, d)],
      [
        p_out(2_000_000_000, 515_864_340, pd(2_000_000_000, 515_864_340)),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(d, AmmBuy { min_out: 514_000_000 }, tx)
}

/// ██ 2 of 4 — `Sell` ON AN AMM POOL. 380 ADA OUT OF THE POOL, REPEATABLY. ██
///
/// This is the cross-mode direction that DRAINS. `quote_sell_gross` pays out in
/// the ratio `effective / ada_reserve` where `effective = ada_reserve +
/// virtual_ada_v3` — a cushion the graduated pool does not have.
///
/// State chosen so that EVERY other guard on `validate_sell` passes, which needs
/// `token_reserve > curve_exhausted_token_reserve`. Approximately reachable:
/// selling 200,000,000 tokens into the fresh graduated pool lands on
/// (9,480,071,540, 461,203,875) under the v3.2 quotes — the fixture keeps the
/// nearby pre-fee state, which is every bit as valid an Amm datum:
///   ⇒ Amm pool (9,467,738,505, 461,203,875), and 461,203,875 > 404,061,018 so
///     `open_ok` passes.
/// The `Sell` of 20,000,000 tokens then grosses, on the CURVE formula:
///   effective = 9,467,738,505 + 9,142,857,144 = 18,610,595,649
///   k_curve   = 18,610,595,649 × 461,203,875
///   new_eff   = k_curve / 481,203,875 = 17,837,094,161
///   gross     = 18,610,595,649 − 17,837,094,161 = 773,501,488
/// where the correct `AmmSell` grosses 392,370,589 — 1.971×, i.e. 381.1 ADA
/// extracted on ONE trade, and repeatable until the pool is empty.
/// `cap_ok` passes (481,203,875 <= 1,142,857,143), `correct_gross` passes because
/// the curve quote is exactly what is presented, and both fees are paid on the
/// inflated gross (creator 7,735,014, platform 2,000,000 flat).
test sell_rejects_an_amm_mode_pool() fail {
  let d = pdm(9_467_738_505, 461_203_875)
  let tx =
    base_tx(
      [am_in(9_467_738_505, 461_203_875, d)],
      [
        am_out(8_694_237_017, 481_203_875, pdm(8_694_237_017, 481_203_875)),
        plat(2_000_000),
        crea(7_735_014),
      ],
    )
  spend_pool(d, Sell { min_out: 762_945_970 }, tx)
}

/// ██ 3 of 4 — `Buy` ON AN AMM POOL. THE BUYER LOSES 47% OF THEIR FILL. ██
///
/// Same reachable Amm state as above. `quote_buy` adds the virtual cushion, so
/// slippage is computed against a reserve nearly twice as large and the buyer
/// receives far fewer tokens than the constant product owes:
///   effective = 9,467,738,505 + 9,142,857,144 = 18,610,595,649
///   k_curve   = 18,610,595,649 × 461,203,875
///   new_tok   = k_curve / 19,610,595,649 = 437,685,778
///   out       = 461,203,875 − 437,685,778 = 23,518,097
/// against the correct `AmmBuy` of 43,939,966 — the buyer keeps 53.5% of what the
/// pool owes them and the pool keeps the rest. Not a drain, and rejected anyway: a
/// validator that lets a trader be paid half of what the pool owes is a mis-priced
/// trade any aggregator or buggy builder can walk a user into.
///
/// Every other guard passes: `open_ok` (461,203,875 > 404,061,018), `cap_ok`
/// (437,685,778 >= 404,061,018), `ada_in_positive`, `correct_tokens_out`
/// against the curve quote, and both fees on `ada_in` = 1e9.
test buy_rejects_an_amm_mode_pool() fail {
  let d = pdm(9_467_738_505, 461_203_875)
  let tx =
    base_tx(
      [am_in(9_467_738_505, 461_203_875, d)],
      [
        am_out(10_467_738_505, 437_685_778, pdm(10_467_738_505, 437_685_778)),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(d, Buy { min_out: 23_000_000 }, tx)
}

/// ██ 4 of 4 — `AmmSell` ON A BOOTSTRAP POOL. THE SELLER IS PAID A FIFTH. ██
///
/// State: (2,000,000,000, 937,728,937) — the pool after a 2,000 ADA genesis buy
///   effective = 9,142,857,144 ; k = 9,142,857,144 × 1,142,857,143
///   new_tok   = k / 11,142,857,144 = 937,728,937   (out = 205,128,206)
/// Value: 2,002,500,000 lovelace, 937,728,937 − 142,857,143 = 794,871,794 tokens.
/// Chosen with `token_reserve < total_supply_v3` on purpose, so that
/// `validate_amm_sell`'s `cap_ok` (`new_tok <= 1e9`) also passes and `mode_ok` is
/// the ONLY guard rejecting — a mid-curve state closer to genesis would have
/// tripped the cap as well and the test would not have isolated anything.
///   amm gross (v3.2): net = 20,000,000 × 9,970/10,000 = 19,940,000
///              gross = ⌊19,940,000 × 2,000,000,000 / 957,668,937⌋ = 41,642,783
///              continuation ada = 2,000,000,000 − 41,642,783 = 1,958,357,217
///   curve gross for the same 20,000,000 tokens: 232,693,338
/// The seller is paid 17.9% of what the curve owes. Continuation (Bootstrap
/// invariant): 1,960,857,217 lovelace, 814,871,794 tokens. Fees on the deflated
/// gross: creator 416,427, platform 2,000,000 (flat); net 39,226,356.
test amm_sell_rejects_a_bootstrap_mode_pool() fail {
  let d = pd(2_000_000_000, 937_728_937)
  let tx =
    base_tx(
      [p_in(2_000_000_000, 937_728_937, d)],
      [
        p_out(1_958_357_217, 957_728_937, pd(1_958_357_217, 957_728_937)),
        plat(2_000_000),
        crea(416_427),
      ],
    )
  spend_pool(d, AmmSell { min_out: 39_226_356 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// AMM BUY — the canonical trade
//
//   old = (16,717,047,886, 261,203,875)   value: 16,717,047,886 lovelace,
//                                                261,203,875 tokens, 1 NFT
//   v3.2 quote (net input priced, amount OUT floored; FULL ada_in enters the pool):
//   net = 1,000,000,000 × 9,970 / 10,000 = 997,000,000
//   tokens_out = ⌊997,000,000 × 261,203,875 / 17,714,047,886⌋ = 14,701,341
//   new_ada = 17,717,047,886          (full ada_in — the 0.30% stays in the pool)
//   new_tok = 261,203,875 − 14,701,341 = 246,502,534
//   creator  = 1,000,000,000 × 100 / 10,000 = 10,000,000
//   platform = 2,000,000 (the flat fee is the whole platform take; bps is 0)
// ══════════════════════════════════════════════════════════════════════════════

fn ab_old() -> PoolDatum {
  pdm(ga, gt)
}

fn ab_new() -> PoolDatum {
  pdm(17_717_047_886, 246_502_534)
}

fn ab_tx_outs(outs: List<Output>) -> Transaction {
  base_tx([am_in(ga, gt, ab_old())], outs)
}

fn ab_good_tx() -> Transaction {
  ab_tx_outs(
    [
      am_out(17_717_047_886, 246_502_534, ab_new()),
      plat(2_000_000),
      crea(10_000_000),
    ],
  )
}

test amm_buy_accepts_the_canonical_trade() {
  spend_pool(ab_old(), AmmBuy { min_out: 14_700_000 }, ab_good_tx())
}

test amm_buy_rejects_underpay_slippage() fail {
  spend_pool(ab_old(), AmmBuy { min_out: 14_701_342 }, ab_good_tx())
}

/// One token more than the constant product owes. The branch compares the exact
/// quote, so this is caught arithmetically.
test amm_buy_rejects_one_extra_token_out() fail {
  let bad = pdm(17_717_047_886, 246_502_533)
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out(17_717_047_886, 246_502_533, bad),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// …and one token fewer, which shortchanges the buyer rather than the pool. Also
/// refused: the quote is an equality.
test amm_buy_rejects_one_token_short() fail {
  let bad = pdm(17_717_047_886, 246_502_535)
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out(17_717_047_886, 246_502_535, bad),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// ── THE OLD MINIMUM'S BOUNDARY, KEPT AS AN ACCEPT PAIR ──────────────────────
///
/// While `min_trade_ada_v3` existed this pair was the 10 ADA boundary (accept at
/// exactly the minimum, reject one lovelace under, with no closing exemption on
/// the AMM side). The minimum is deleted, so BOTH sides are ordinary legal
/// trades; the pair stays because the two fixtures straddle the floor-division
/// step and pin `correct_tokens_out` on identical outputs for different inputs.
///
///   ada_in = 10,000,000: net = 9,970,000, tokens_out = 155,688
///                        new_ada = 16,727,047,886, new_tok = 261,048,187
///                        creator 100,000, platform 2,000,000
/// A 10 ADA AmmBuy. It was named for a minimum that no longer exists — the AMM
/// branch now admits any positive size, so this is just an ordinary small trade.
test amm_buy_accepts_a_small_trade() {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 155_688 },
    ab_tx_outs(
      [
        am_out(16_727_047_886, 261_048_187, pdm(16_727_047_886, 261_048_187)),
        plat(2_000_000),
        crea(100_000),
      ],
    ),
  )
}

/// ONE LOVELACE UNDER THE OLD MINIMUM, NOW ACCEPTED. 9,999,999 lovelace buys the
/// SAME 155,688 tokens as 10,000,000 does (the fee-netting and output floor
/// swallow the difference), so `correct_tokens_out` passes and the arithmetic is
/// entirely legal. While `size_ok` existed it was the only guard rejecting this;
/// the guard is deleted, so the test is INVERTED rather than left to "pass" on an
/// underpaid fee output — the same deliberate inversion as
/// `sell_accepts_gross_just_under_the_old_minimum`.
///   net = ⌊9,999,999 × 9,970/10,000⌋ = 9,969,999 ; out = 155,688
///   new_ada = 16,727,047,885 ; new_tok = 261,048,187
///   creator 99,999 ; platform 2,000,000 (flat)
test amm_buy_accepts_one_lovelace_under_the_old_minimum() {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 155_688 },
    ab_tx_outs(
      [
        am_out(16_727_047_885, 261_048_187, pdm(16_727_047_885, 261_048_187)),
        plat(2_000_000),
        crea(99_999),
      ],
    ),
  )
}

test amm_buy_rejects_missing_platform_fee() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs([am_out(17_717_047_886, 246_502_534, ab_new()), crea(10_000_000)]),
  )
}

test amm_buy_rejects_platform_fee_one_lovelace_short() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(1_999_999),
        crea(10_000_000),
      ],
    ),
  )
}

test amm_buy_rejects_missing_creator_fee() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs([am_out(17_717_047_886, 246_502_534, ab_new()), plat(2_000_000)]),
  )
}

test amm_buy_rejects_creator_fee_one_lovelace_short() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(9_999_999),
      ],
    ),
  )
}

/// ██ THE AMM VALUE INVARIANT: NO POOL FLOOR AFTER GRADUATION. ██
///
/// A continuation carrying `new_ada + pool_floor_v3` lovelace — i.e. the Bootstrap
/// invariant applied to a graduated pool. It is the shape a copy-pasted `p_out`
/// produces, and it is exactly the mistake `value_matches`' two literal arms exist
/// to make impossible to write by accident.
///
/// If it were accepted the pool's datum would understate its lovelace by 2.5 ADA
/// forever, and every subsequent spend would fail `in_consistent` — 17,717 ADA
/// frozen.
test amm_buy_rejects_a_stray_pool_floor_in_the_continuation() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out_raw(
          17_717_047_886 + pool_floor_v3,
          246_502_534,
          1,
          ab_new(),
        ),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// …and the CONTROL, which is what makes the test above mean something: the SAME
/// transaction WITHOUT the stray floor is the accept case. Stated as its own test
/// so the pair reads as "the 10 ADA is the only difference".
test amm_buy_accepts_the_same_trade_without_the_stray_floor() {
  spend_pool(ab_old(), AmmBuy { min_out: 14_700_000 }, ab_good_tx())
}

/// ██ AND NO TOKEN OFFSET AFTER GRADUATION. ██ The other half of the same
/// mistake: a continuation holding `new_tok − token_offset_v3` real tokens, which
/// is what the Bootstrap invariant demands. 142,857,143 tokens — 14.29% of total
/// supply — would leave the pool.
test amm_buy_rejects_the_token_offset_applied_to_the_continuation() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out_raw(
          17_717_047_886,
          246_502_534 - token_offset_v3,
          1,
          ab_new(),
        ),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// The value-invariant check on the way IN, for the Amm mode: a pool UTxO whose
/// lovelace includes a floor its Amm datum does not account for. `in_consistent`
/// in the preamble rejects it before any branch runs.
test amm_rejects_an_input_carrying_a_pool_floor() fail {
  let d = pdm(ga, gt)
  let bad_in =
    input_of(
      p_ref(),
      script_out(
        t_pool,
        ada_token(ga + pool_floor_v3, t_policy, t_name, gt)
          |> assets.add(t_policy, pool_nft_name, 1),
        d,
      ),
    )
  spend_pool(
    d,
    AmmBuy { min_out: 14_700_000 },
    base_tx(
      [bad_in],
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// …and one whose token balance has the offset subtracted, i.e. a Bootstrap-shaped
/// value under an Amm datum.
test amm_rejects_an_input_holding_the_offset_reduced_balance() fail {
  let d = pdm(ga, gt)
  let bad_in =
    input_of(
      p_ref(),
      script_out(
        t_pool,
        ada_token(ga, t_policy, t_name, gt - token_offset_v3)
          |> assets.add(t_policy, pool_nft_name, 1),
        d,
      ),
    )
  spend_pool(
    d,
    AmmBuy { min_out: 14_700_000 },
    base_tx(
      [bad_in],
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

// ── Amm structural rejects ────────────────────────────────────────────────────

test amm_buy_rejects_the_nft_carried_out_of_the_pool() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out_raw(17_717_047_886, 246_502_534, 0, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
        pk_out_token(t_owner, 2_000_000, t_policy, pool_nft_name, 1),
      ],
    ),
  )
}

test amm_buy_rejects_junk_assets_in_the_continuation() fail {
  let junk =
    amm_value(17_717_047_886, 246_502_534)
      |> assets.add(
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          #"4a554e4b",
          1,
        )
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        script_out(t_pool, junk, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

test amm_buy_rejects_two_pool_continuation_outputs() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// A stake credential attached to a graduated pool MID-LIFE. Whoever attaches it
/// earns staking rewards on the pool's whole reserve for the rest of the token's
/// life, because `continuation_address_exact` then freezes the new address too.
test amm_buy_rejects_a_stake_credential_on_the_continuation() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        script_out_staked(
          t_pool,
          #"5555555555555555555555555555555555555555555555555555555a",
          amm_value(17_717_047_886, 246_502_534),
          ab_new(),
        ),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// The AMM half of the same case: a stake-part decoy alongside a correct
/// continuation. A full-address filter would ACCEPT this on every trade for the
/// life of the pool, and each accepted trade parks another decoy at LumpFun's sole
/// on-chain identifier. Only the payment-credential filter counts them.
test amm_buy_rejects_a_stake_part_decoy_alongside_the_continuation() fail {
  let decoy =
    script_out_staked(
      t_pool,
      #"5555555555555555555555555555555555555555555555555555555a",
      ada(2_000_000),
      ab_new(),
    )
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        decoy,
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// Minting curve tokens during an AMM trade. `lump_mint_v3` is Launch-only and its
/// seed UTxO is long spent, so this is unconstructible at the policy level — the
/// guard keeps the property LOCAL to the branch anyway, so a future cohort with a
/// second mint path does not silently make it exploitable.
test amm_buy_rejects_minting_curve_tokens() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [am_in(ga, gt, ab_old())],
      outputs: [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
      mint: assets.from_asset(t_policy, t_name, 1_000_000),
    }
  spend_pool(ab_old(), AmmBuy { min_out: 14_700_000 }, tx)
}

/// ██ DOUBLE SATISFACTION ON THE AMM BRANCH — the V-1 shape, post-graduation. ██
/// Two graduated pools at the same shared address in one transaction, one
/// continuation, ONE pair of fee outputs. Without `tx_shape_ok`'s `one_pool == 1`
/// the second pool's entire reserve is unaccounted for, and both trades pay a
/// single 12 ADA fee. This is the shape that matters MOST after graduation,
/// because graduated pools trade forever and there are eventually many of them at
/// one address.
test amm_buy_rejects_a_second_pool_input() fail {
  let second =
    input_of(oref(#"9999", 0), script_out(t_pool, amm_value(ga, gt), ab_old()))
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old()), second],
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(ab_old(), AmmBuy { min_out: 14_700_000 }, tx)
}

test amm_buy_rejects_a_foreign_script_input() fail {
  let foreign =
    input_of(oref(#"0f0f", 0), script_out(#"0f0f0f0f", ada(5_000_000), 0))
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old()), foreign],
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(ab_old(), AmmBuy { min_out: 14_700_000 }, tx)
}

test amm_buy_rejects_a_decoy_input_without_the_nft() fail {
  let d = pdm(ga, gt)
  let no_nft =
    input_of(
      p_ref(),
      script_out(t_pool, ada_token(ga, t_policy, t_name, gt), d),
    )
  spend_pool(
    d,
    AmmBuy { min_out: 14_700_000 },
    base_tx(
      [no_nft],
      [
        am_out(17_717_047_886, 246_502_534, ab_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

// ── R-5 on the AMM branches: `with_reserves` freezes nine fields ──────────────
//
// The graduated pool trades for the REST OF THE TOKEN'S LIFE, so this is where
// R-5 has to hold longest. Each reject mutates exactly one field.

fn amm_buy_with_new_datum(new_d: PoolDatum) -> Transaction {
  ab_tx_outs(
    [
      am_out(17_717_047_886, 246_502_534, new_d),
      plat(2_000_000),
      crea(10_000_000),
    ],
  )
}

test r5_amm_rejects_rewriting_the_royalty_pub_key() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_royalty(17_717_047_886, 246_502_534, t_evil_royalty)),
  )
}

test r5_amm_rejects_rewriting_the_creator_pkh() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_creator(17_717_047_886, 246_502_534, t_owner)),
  )
}

test r5_amm_rejects_rewriting_the_treasury_pkh() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_treasury(17_717_047_886, 246_502_534, t_owner)),
  )
}

test r5_amm_rejects_rewriting_the_policy_id() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_policy(17_717_047_886, 246_502_534, #"deadbeef")),
  )
}

test r5_amm_rejects_rewriting_the_asset_name() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_name(17_717_047_886, 246_502_534, #"42414441")),
  )
}

test r5_amm_rejects_zeroing_the_creator_fee_bps() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_cbps(17_717_047_886, 246_502_534, 0)),
  )
}

/// The cohort bps is 0, so the frozen-field rewrite is a NONZERO rate (the old
/// 50) — writing 0 would reproduce the canonical datum. See the buy-branch twin.
test r5_amm_rejects_rewriting_the_platform_fee_bps() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_pbps(17_717_047_886, 246_502_534, 50)),
  )
}

test r5_amm_rejects_zeroing_the_platform_fee_flat() fail {
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    amm_buy_with_new_datum(am_pflat(17_717_047_886, 246_502_534, 0)),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// AMM SELL — the canonical trade
//
//   old = (16,717,047,886, 261,203,875)
//   tokens_in = 100,000,000 (v3.2: FULL amount enters the pool; quote nets it)
//   net = 99,700,000
//   gross = ⌊99,700,000 × 16,717,047,886 / 360,903,875⌋ = 4,618,098,584
//   new_tok = 361,203,875
//   new_ada = 16,717,047,886 − 4,618,098,584 = 12,098,949,302
//   creator  = 4,618,098,584 × 100 / 10,000 = 46,180,985
//   platform = 2,000,000 (flat; bps is 0)
//   net proceeds = 4,618,098,584 − 46,180,985 − 2,000,000 = 4,569,917,599
// ══════════════════════════════════════════════════════════════════════════════

fn as_new() -> PoolDatum {
  pdm(12_098_949_302, 361_203_875)
}

fn as_good_tx() -> Transaction {
  base_tx(
    [am_in(ga, gt, ab_old())],
    [
      am_out(12_098_949_302, 361_203_875, as_new()),
      plat(2_000_000),
      crea(46_180_985),
    ],
  )
}

test amm_sell_accepts_the_canonical_trade() {
  spend_pool(ab_old(), AmmSell { min_out: 4_569_917_599 }, as_good_tx())
}

test amm_sell_rejects_underpay_slippage() fail {
  spend_pool(ab_old(), AmmSell { min_out: 4_569_917_600 }, as_good_tx())
}

/// One lovelace more gross than the constant product owes.
test amm_sell_rejects_over_extracting_ada() fail {
  let bad = pdm(12_098_949_301, 361_203_875)
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_500_000_000 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(12_098_949_301, 361_203_875, bad),
        plat(2_000_000),
        crea(46_180_985),
      ],
    ),
  )
}

/// ── THERE IS NO SELL-SIDE MINIMUM, AND THAT IS DELIBERATE ───────────────────
/// A minimum dust-locks small holders out of exiting (see `validate_sell`'s
/// extended note), so neither branch has one and neither should gain one.
///
/// ── ██ BUT THE 2 ADA FLAT FEE IS NOW A DE-FACTO FLOOR, AND IT BITES HERE. ██ ─
/// This 1,000-token sell grosses 63,807 lovelace against a platform fee of
/// 2,000,000. The gross CANNOT cover it, so the seller must fund the fee from
/// their own UTxOs and the trade nets −1,936,831 — they pay ~1.94 ADA for the
/// privilege of selling 1,000 tokens.
///
/// THE VALIDATOR STILL ACCEPTS IT, and that is the point of this test.
/// `platform_fee_paid` only requires that SOME output pays the treasury at least
/// the fee; it does not require the money to come out of the gross. So the rule
/// is unchanged — any size is permitted — and the economics are the trader's
/// problem, which is the operator's stated position. What is NOT permitted is a
/// zero-token sell (the next test), because that is a no-op, not a bad trade.
///
/// The practical consequence, stated so nobody reports it as a bug: a holder
/// whose ENTIRE bag grosses less than ~2 ADA cannot exit profitably. That is
/// inherent to a flat fee and v2 behaves identically with its own 2 ADA flat fee,
/// so it is parity, not a regression.
///   net = 997 ; gross = ⌊997 × 16,717,047,886 / 261,204,872⌋ = 63,807
///   new_tok = 261,204,875 ; new_ada = 16,716,984,079
///   creator 1% = 638 ; platform flat = 2,000,000
test amm_sell_accepts_a_dust_sell_with_no_minimum() {
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(16_716_984_079, 261_204_875, pdm(16_716_984_079, 261_204_875)),
        plat(2_000_000),
        crea(638),
      ],
    )
  spend_pool(ab_old(), AmmSell { min_out: -1_936_831 }, tx)
}

/// A zero-token sell — a no-op that would still collect a bounty from nowhere.
/// `tokens_in_positive` is the only guard rejecting it, exactly as on the curve.
test amm_sell_rejects_zero_tokens_in() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: -2_000_000 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [am_out(ga, gt, ab_old()), plat(2_000_000), crea(0)],
    ),
  )
}

/// ██ THE AMM'S TOKEN CAP IS `total_supply_v3`, NOT `virtual_token_v3`. ██
///
/// The curve's mirror guard compares against `virtual_token_v3` = 1,142,857,143
/// because its reserve is VIRTUAL; this one compares against `total_supply_v3` =
/// 1,000,000,000 because this reserve is REAL. The two differ by exactly
/// `token_offset_v3`, so using the curve's constant here would silently admit a
/// 142,857,143-token overshoot — a pool claiming to hold more tokens than exist.
///
/// The largest legal sell is the whole float, `sellable_v3` = 738,796,125, which
/// lands the reserve on exactly 1e9. ONE TOKEN MORE is refused.
///   tokens_in = 738,796,126 ⇒ new_tok = 1,000,000,001
///   net = 736,579,737 ; gross = 12,340,790,715 ; new_ada = 4,376,257,171
///   creator 123,407,907 ; platform 2,000,000 (flat) ; net 12,215,382,808
test amm_sell_rejects_pushing_the_reserve_above_total_supply() fail {
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(4_376_257_171, 1_000_000_001, pdm(4_376_257_171, 1_000_000_001)),
        plat(2_000_000),
        crea(123_407_907),
      ],
    )
  spend_pool(ab_old(), AmmSell { min_out: 12_000_000_000 }, tx)
}

/// …and the CONTROL at exactly the cap: dumping 100% of the float is legal, and it
/// leaves the pool holding 4,376,257,175 lovelace = 4,376.26 ADA (v3.2: MORE than
/// the pre-fee 4,366.56 — the LP fee raises the locked floor). This is the
/// arithmetic behind "liquidity is locked for life" — no volume of selling can
/// empty the pool, so the absence of a withdraw redeemer is backed by the model and
/// not merely by the missing branch.
///   tokens_in = 738,796,125 ⇒ new_tok = 1,000,000,000
///   net = 736,579,736 ; gross = 12,340,790,711 ; new_ada = 4,376,257,175
///   creator 123,407,907 ; platform 2,000,000 (flat) ; net 12,215,382,804
test amm_sell_accepts_dumping_the_entire_float() {
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(4_376_257_175, 1_000_000_000, pdm(4_376_257_175, 1_000_000_000)),
        plat(2_000_000),
        crea(123_407_907),
      ],
    )
  spend_pool(ab_old(), AmmSell { min_out: 12_215_382_804 }, tx)
}

test amm_sell_rejects_missing_platform_fee() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [am_out(12_098_949_302, 361_203_875, as_new()), crea(46_180_985)],
    ),
  )
}

test amm_sell_rejects_missing_creator_fee() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [am_out(12_098_949_302, 361_203_875, as_new()), plat(2_000_000)],
    ),
  )
}

test amm_sell_rejects_the_nft_carried_out_of_the_pool() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out_raw(12_098_949_302, 361_203_875, 0, as_new()),
        plat(2_000_000),
        crea(46_180_985),
        pk_out_token(t_owner, 2_000_000, t_policy, pool_nft_name, 1),
      ],
    ),
  )
}

test amm_sell_rejects_junk_assets_in_the_continuation() fail {
  let junk =
    amm_value(12_098_949_302, 361_203_875)
      |> assets.add(
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          #"4a554e4b",
          1,
        )
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [script_out(t_pool, junk, as_new()), plat(2_000_000), crea(46_180_985)],
    ),
  )
}

test r5_amm_sell_rejects_rewriting_the_royalty_pub_key() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(
          12_098_949_302,
          361_203_875,
          am_royalty(12_098_949_302, 361_203_875, t_evil_royalty),
        ),
        plat(2_000_000),
        crea(46_180_985),
      ],
    ),
  )
}

test r5_amm_sell_rejects_rewriting_the_treasury_pkh() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(
          12_098_949_302,
          361_203_875,
          am_treasury(12_098_949_302, 361_203_875, t_owner),
        ),
        plat(2_000_000),
        crea(46_180_985),
      ],
    ),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// ██ THE AmmSell BRANCH'S OWN COVERAGE — IT WAS THIN AND THIS IS THE THIN HALF ██
//
// AmmBuy carried ~30 tests to AmmSell's 14, and three of the four load-bearing
// lines in `validate_amm_sell`'s and-block were bound by NOTHING: no test and no
// mutation touched `continuation_address_exact` (occurrence 5 of 5), the
// `fee_schedule_ok` CALL SITE (occurrence 4 of 4), or `authentic` as reached through
// this branch. "The guard is shared, so the call site is redundant" is FALSE — a
// shared function proves the function's contract, not that a given branch still
// calls it, and a refactor that drops one call keeps a fully green suite.
//
// AmmSell is the wrong branch to leave uncovered. It is the one that moves ADA OUT
// of a pool that exists for the rest of the token's life, and the file's own banner
// says that is where most lifetime volume — and most of the platform's revenue —
// actually is.
//
// The R-5 field breadth is completed here too: `with_reserves` freezes NINE fields
// and AmmBuy rejected a rewrite of all nine while AmmSell rejected three. Cheap to
// finish, and the gap would have hidden a bespoke inlined reconstruction on this
// branch — a plausible optimisation on the branch that will carry the most volume.
// ══════════════════════════════════════════════════════════════════════════════

/// ██ MID-LIFE STAKE CAPTURE, THROUGH THE ONE BRANCH THAT ALLOWED IT UNBOUND. ██
///
/// The mirror of `amm_buy_rejects_a_stake_credential_on_the_continuation`, and the
/// severe instance: `sole_continuation` filters on the PAYMENT CREDENTIAL only, so a
/// staked output IS the sole continuation and `continuation_address_exact` is the
/// SOLE guard rejecting it. The damage is self-latching in the wrong direction —
/// once a stake credential is attached, the guard on the other four branches pins
/// `own_output.address == own_input.output.address` and FREEZES the new staked
/// address for the life of the token. One unguarded branch is therefore permanent,
/// with no recovery at any layer, and the attacker earns staking rewards on up to
/// ~16,717 ADA of other people's money forever for the price of one ordinary sell.
test amm_sell_rejects_a_stake_credential_on_the_continuation() fail {
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        script_out_staked(
          t_pool,
          #"5555555555555555555555555555555555555555555555555555555a",
          amm_value(12_098_949_302, 361_203_875),
          as_new(),
        ),
        plat(2_000_000),
        crea(46_180_985),
      ],
    )
  spend_pool(ab_old(), AmmSell { min_out: 4_567_481_522 }, tx)
}

/// …and the decoy form, which is what binds `sole_continuation`'s credential filter
/// on this branch: a staked decoy riding ALONGSIDE a correct continuation. A
/// full-address filter accepts this on every sell for the life of the pool, and each
/// accepted sell parks another decoy at LumpFun's sole on-chain identifier.
test amm_sell_rejects_a_stake_part_decoy_alongside_the_continuation() fail {
  let decoy =
    script_out_staked(
      t_pool,
      #"5555555555555555555555555555555555555555555555555555555a",
      ada(2_000_000),
      as_new(),
    )
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old())],
      [
        am_out(12_098_949_302, 361_203_875, as_new()),
        decoy,
        plat(2_000_000),
        crea(46_180_985),
      ],
    )
  spend_pool(ab_old(), AmmSell { min_out: 4_567_481_522 }, tx)
}

/// ██ THE fee_schedule_ok CALL SITE ON AmmSell. ██
///
/// Every other AmmSell test builds its input datum with `pdm`, which carries
/// `t_treasury = treasury_pkh_v3` and 100/0/2,000,000 — so `fee_schedule_ok` was
/// trivially satisfied in all fourteen of them and deleting the call from this
/// and-block left the suite green. (`r5_amm_sell_rejects_rewriting_the_treasury_pkh`
/// does not cover it: that rewrites the CONTINUATION's treasury, which
/// `datum_preserved` catches, and its input datum stays canonical.)
///
/// The live defect a future "the buy branch already pins the schedule, the sell
/// branch is symmetric" refactor would create: a self-seeded counterfeit pool at
/// LumpFun's shared unparameterised address, with a launcher-controlled treasury and
/// a zero platform fee, SELLING through the official validator paying LumpFun
/// nothing, forever, on the half of a token's life that carries most of its volume.
///   d = (ga, gt) with treasury/creator = t_owner and 0/0/0
///   tokens_in 100,000,000 ⇒ gross 4,618,098,584, and with a 0/0/0 schedule the
///   trader owes NO fee outputs at all, so the transaction carries none.
test amm_sell_rejects_a_zero_platform_fee_self_seeded_pool() fail {
  let d = dat(t_policy, t_name, ga, gt, t_owner, t_owner, 0, 0, 0, t_royalty, Amm)
  let new_d =
    dat(
      t_policy,
      t_name,
      12_098_949_302,
      361_203_875,
      t_owner,
      t_owner,
      0,
      0,
      0,
      t_royalty,
      Amm,
    )
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [am_out(12_098_949_302, 361_203_875, new_d), pk_out(t_owner, 2_000_000)],
    )
  spend_pool(d, AmmSell { min_out: 4_618_098_584 }, tx)
}

/// The same call site reached the other way: an on-schedule pool whose datum names a
/// treasury the LAUNCHER controls. Both rates are exactly right and both keys are 28
/// bytes, so nothing but the treasury pin refuses it — and the fee is genuinely PAID,
/// to the wrong key.
test amm_sell_rejects_a_pool_whose_datum_names_a_foreign_treasury() fail {
  let foreign = #"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
  let d = am_treasury(ga, gt, foreign)
  let new_d = am_treasury(12_098_949_302, 361_203_875, foreign)
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [
        am_out(12_098_949_302, 361_203_875, new_d),
        pk_out(foreign, 2_000_000),
        crea(46_180_985),
      ],
    )
  spend_pool(d, AmmSell { min_out: 4_567_481_522 }, tx)
}

/// The pool as its OWN treasury, on the sell side. A script hash is 28 bytes so
/// every length assertion passes; without `pays_at_least`'s pool-address exclusion
/// the continuation — which still holds 12,098 ADA after the sell — satisfies the
/// platform fee check with no fee output in the transaction at all.
test amm_sell_rejects_the_pool_paying_its_own_platform_fee() fail {
  let d = am_treasury(ga, gt, t_pool)
  let new_d = am_treasury(12_098_949_302, 361_203_875, t_pool)
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [am_out(12_098_949_302, 361_203_875, new_d), crea(46_180_985)],
    )
  spend_pool(d, AmmSell { min_out: 4_567_481_522 }, tx)
}

/// THE ACCEPT CONTROL — `fee_schedule_ok` floors the platform levels with `>=`, not
/// `==`, so a future cohort may RAISE them and still sell. Without this the four
/// rejects above would also be satisfied by a mutation that turned the floors into
/// equalities, which would silently freeze every future cohort out of the sell side.
///   platform_fee_bps 100, flat 2,500,000 on gross 4,618,098,584
///   ⇒ 4,618,098,584 × 100/10,000 + 2,500,000 = 46,180,985 + 2,500,000 = 48,680,985
///   creator unchanged at 100 bps = 46,180,985
///   net = 4,618,098,584 − 46,180,985 − 48,680,985 = 4,523,236,614
test amm_sell_accepts_a_future_cohort_that_raises_the_platform_fee() {
  let d =
    dat(t_policy, t_name, ga, gt, t_creator, t_treasury, 100, 100, 2_500_000, t_royalty, Amm)
  let new_d =
    dat(
      t_policy,
      t_name,
      12_098_949_302,
      361_203_875,
      t_creator,
      t_treasury,
      100,
      100,
      2_500_000,
      t_royalty,
      Amm,
    )
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [
        am_out(12_098_949_302, 361_203_875, new_d),
        plat(48_680_985),
        crea(46_180_985),
      ],
    )
  spend_pool(d, AmmSell { min_out: 4_523_236_614 }, tx)
}

/// ██ `authentic`, THROUGH AmmSell. ██
///
/// The only line separating the real pool from a decoy at v3's shared address, in
/// both modes, for the token's ENTIRE life — the NFT is never burned, since
/// `MintRedeemer` has only `Launch`. AmmBuy, Buy and Sell each had a decoy test;
/// AmmSell had none.
///
/// `authentic` is the SOLE rejecter here: the decoy input carries the correct
/// lovelace and token quantities with NO NFT, so `in_consistent`'s Amm arm passes
/// (lovelace == ga, tokens == gt) and every other guard on the branch passes against
/// a canonical continuation.
test amm_sell_rejects_a_decoy_input_without_the_nft() fail {
  let d = pdm(ga, gt)
  let no_nft =
    input_of(p_ref(), script_out(t_pool, ada_token(ga, t_policy, t_name, gt), d))
  spend_pool(
    d,
    AmmSell { min_out: 4_567_481_522 },
    base_tx(
      [no_nft],
      [
        am_out(12_098_949_302, 361_203_875, as_new()),
        plat(2_000_000),
        crea(46_180_985),
      ],
    ),
  )
}

// ── R-5 on AmmSell: the remaining SIX of `with_reserves`' nine frozen fields ────
//
// AmmSell already rejected rewrites of `royalty_pub_key`, `treasury_pkh` and `mode`.
// These complete the set so the branch is covered field-for-field exactly as AmmBuy
// is. Each mutates ONE field of the continuation datum and nothing else, and each is
// caught by `datum_preserved` alone.

fn amm_sell_with_new_datum(new_d: PoolDatum) -> Transaction {
  base_tx(
    [am_in(ga, gt, ab_old())],
    [
      am_out(12_098_949_302, 361_203_875, new_d),
      plat(2_000_000),
      crea(46_180_985),
    ],
  )
}

test r5_amm_sell_rejects_rewriting_the_creator_pkh() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    amm_sell_with_new_datum(am_creator(12_098_949_302, 361_203_875, t_owner)),
  )
}

test r5_amm_sell_rejects_rewriting_the_policy_id() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    amm_sell_with_new_datum(
      am_policy(
        12_098_949_302,
        361_203_875,
        #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      ),
    ),
  )
}

test r5_amm_sell_rejects_rewriting_the_asset_name() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    amm_sell_with_new_datum(
      am_name(12_098_949_302, 361_203_875, #"4841434b"),
    ),
  )
}

test r5_amm_sell_rejects_zeroing_the_creator_fee_bps() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    amm_sell_with_new_datum(am_cbps(12_098_949_302, 361_203_875, 0)),
  )
}

/// The cohort bps is 0, so the frozen-field rewrite is a NONZERO rate (the old
/// 50) — writing 0 would reproduce the canonical datum. See the buy-branch twin.
test r5_amm_sell_rejects_rewriting_the_platform_fee_bps() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    amm_sell_with_new_datum(am_pbps(12_098_949_302, 361_203_875, 50)),
  )
}

test r5_amm_sell_rejects_zeroing_the_platform_fee_flat() fail {
  spend_pool(
    ab_old(),
    AmmSell { min_out: 4_567_481_522 },
    amm_sell_with_new_datum(am_pflat(12_098_949_302, 361_203_875, 0)),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// AMM SOLVENCY — ██ THE TWO `solvency_ok` GUARDS ARE STRUCTURALLY SHADOWED
// AS OF v3.2, AND THE TESTS BELOW DOCUMENT THAT RATHER THAN PRETEND COVERAGE. ██
//
// Pre-v3.2, a SELF-SEEDED pool graduated at the minimum legal `ada_reserve` of
// one lovelace (k = 261,203,875) could have its token side emptied by a 262 ADA
// buy — the retained-reserve floor let `new_tok` reach 0 — and `solvency_ok` +
// `value_shape_ok` were the matched pair rejecting it.
//
// v3.2 floors the amount OUT: `tokens_out = ⌊net·T/(A+net)⌋ < T` for EVERY
// input at EVERY state, and `gross = ⌊net·A/(T+net)⌋ < A` likewise. Measured at
// the worst case below: spending the ENTIRE ADA SUPPLY into the (1, 261,203,875)
// pool leaves one token, and its single lovelace can never be extracted. So no
// transaction that passes `correct_tokens_out`/`correct_gross` can present a
// zero reserve, and NO fixture can make the solvency pair the rejecting guard.
//
// THE GUARDS STAY ANYWAY. Removing a guard because today's arithmetic shadows
// it is how guards die — a future cohort that changes the rounding gets them
// back for free, and they cost two comparisons. `mutverify.sh` asserts the
// shadowing from the other side: neutering BOTH guards changes nothing
// observable (the documenting cases below still pass under the mutation).
// ══════════════════════════════════════════════════════════════════════════════

/// Even the ENTIRE ADA SUPPLY cannot empty a tiny-k pool's token side under the
/// v3.2 quote — the state `solvency_ok` rejects is unpresentable via a correct
/// quote. ⌊net·T/(A+net)⌋ with A = 1: out = 261,203,874 of 261,203,875.
test amm_tiny_k_pool_token_side_cannot_be_emptied() {
  let out = amm_quote_buy(1, gt, 45_000_000_000_000_000)
  and {
    out == 261_203_874,
    gt - out >= 1,
  }
}

/// …and the single lovelace in the same pool can never be extracted: the netted
/// gross floors to 0 at every size.
test amm_tiny_k_pool_ada_side_cannot_be_emptied() {
  and {
    amm_quote_sell_gross(1, gt, 1_000_000_000) == 0,
    amm_quote_sell_gross(1, gt, 45_000_000_000_000_000) == 0,
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// THE AMM SIDE OF THE SELF-SEEDED-POOL SURFACE
//
// `fee_schedule_ok` is called on all four trade branches. It was only ever needed
// on the curve while graduation moved liquidity to a foreign venue; now that the
// graduated pool is where a token trades for the rest of its life, the AMM half is
// the LARGER revenue surface, and a pin that covered only the curve would have left
// it open.
// ══════════════════════════════════════════════════════════════════════════════

/// A counterfeit graduated pool naming a zero platform fee — the whole exploit,
/// after graduation. Before `fee_schedule_ok` covered these branches, an attacker's
/// own policy plus a zero-fee datum traded through LumpFun's official validator at
/// LumpFun's official address, forever, paying nothing.
test amm_buy_rejects_a_zero_platform_fee_self_seeded_pool() fail {
  let d = dat(t_policy, t_name, ga, gt, t_owner, t_owner, 0, 0, 0, t_royalty, Amm)
  let new_d =
    dat(
      t_policy,
      t_name,
      17_717_047_886,
      246_502_534,
      t_owner,
      t_owner,
      0,
      0,
      0,
      t_royalty,
      Amm,
    )
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [am_out(17_717_047_886, 246_502_534, new_d), pk_out(t_owner, 2_000_000)],
    )
  spend_pool(d, AmmBuy { min_out: 14_700_000 }, tx)
}

/// A graduated pool whose datum names a treasury the LAUNCHER controls. The rates
/// are exactly on schedule and both keys are 28 bytes, so nothing but the treasury
/// pin refuses it.
test amm_buy_rejects_a_pool_whose_datum_names_a_foreign_treasury() fail {
  let foreign = #"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
  let d = am_treasury(ga, gt, foreign)
  let new_d = am_treasury(17_717_047_886, 246_502_534, foreign)
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [
        am_out(17_717_047_886, 246_502_534, new_d),
        pk_out(foreign, 2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(d, AmmBuy { min_out: 14_700_000 }, tx)
}

/// A FUTURE COHORT MAY RAISE THE PLATFORM FEE on the AMM side too — `>=`, not `==`.
///   platform_fee_bps 100, flat 2,500,000 ⇒ 1e9 × 100/10,000 + 2,500,000 = 12,500,000
test amm_buy_accepts_a_future_cohort_that_raises_the_platform_fee() {
  let d =
    dat(t_policy, t_name, ga, gt, t_creator, t_treasury, 100, 100, 2_500_000, t_royalty, Amm)
  let new_d =
    dat(
      t_policy,
      t_name,
      17_717_047_886,
      246_502_534,
      t_creator,
      t_treasury,
      100,
      100,
      2_500_000,
      t_royalty,
      Amm,
    )
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [
        am_out(17_717_047_886, 246_502_534, new_d),
        plat(12_500_000),
        crea(10_000_000),
      ],
    )
  spend_pool(d, AmmBuy { min_out: 14_700_000 }, tx)
}

/// The pool as its OWN treasury, after graduation. A script hash is 28 bytes, so
/// every length assertion passes; without `pays_at_least`'s pool-address exclusion
/// the pool's own continuation — which holds ~17,717 ADA — satisfies the platform
/// fee check on every trade forever with no fee output in the transaction at all.
/// The exclusion matters MORE here: an `Amm` pool's continuation always holds the
/// entire reserve with no floor beside it, and it exists for the token's whole life.
test amm_buy_rejects_the_pool_paying_its_own_platform_fee() fail {
  let d = am_treasury(ga, gt, t_pool)
  let new_d = am_treasury(17_717_047_886, 246_502_534, t_pool)
  let tx =
    base_tx(
      [am_in(ga, gt, d)],
      [am_out(17_717_047_886, 246_502_534, new_d), crea(10_000_000)],
    )
  spend_pool(d, AmmBuy { min_out: 14_700_000 }, tx)
}

// ── Datum-shape rejects on the AMM branch ─────────────────────────────────────

/// `ReservedV2Slot` in an AMM continuation. It soft-casts to `PoolDatum` happily,
/// so the guard that stops it is the SECOND `expect PoolDatumV3`.
test amm_buy_rejects_a_reserved_slot_continuation_datum() fail {
  let reserved: Data = ReservedV2Slot
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs(
      [
        script_out(t_pool, amm_value(17_717_047_886, 246_502_534), reserved),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// A DATUM HASH on an AMM continuation — the `expect InlineDatum` arm.
test amm_buy_rejects_a_datum_hash_continuation() fail {
  let hashed =
    Output {
      address: address.from_script(t_pool),
      value: amm_value(17_717_047_886, 246_502_534),
      datum: DatumHash(
        #"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      ),
      reference_script: None,
    }
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs([hashed, plat(2_000_000), crea(10_000_000)]),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// THE FEE-RECIPIENT / SELF-SEEDED-POOL SURFACE
//
// `lump_pool_v3` is unparameterised, so `authentic` proves only "this UTxO holds
// the NFT its own datum names". Everything below was ACCEPTED before
// `fee_schedule_ok` and the `pays_at_least` pool-address exclusion landed.
// ══════════════════════════════════════════════════════════════════════════════

/// Datum whose `treasury_pkh` is the POOL'S OWN SCRIPT HASH. A script hash is 28
/// bytes, so every length assertion passes.
fn pd_pool_as_treasury(a: Int, t: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_creator, t_pool, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

fn pd_pool_as_creator(a: Int, t: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_pool, t_treasury, 100, 0, 2_000_000, t_royalty, Bootstrap)
}

/// ██ THE POOL PAYING ITS OWN PLATFORM FEE. ██
///
/// A canonical 1,000 ADA genesis buy whose outputs are the continuation and the
/// creator fee — and NO TREASURY OUTPUT AT ALL. Before the fix, the continuation
/// (1,002,500,000 lovelace at `Credential.Script(t_pool)`) satisfied
/// `platform_fee_paid` because `pays_at_least` matched Script credentials and did
/// not exclude the pool's own address. A token structurally valid under
/// `lump_mint_v3.Launch` would have paid LumpFun zero for its entire life while
/// producing transactions indistinguishable in shape from a legitimate trade.
///
/// Now rejected twice over: by the `pays_at_least` exclusion AND by
/// `fee_schedule_ok`'s `treasury_pkh == treasury_pkh_v3`.
test buy_rejects_the_pool_paying_its_own_platform_fee() fail {
  let old_d = pd_pool_as_treasury(0, 1_142_857_143)
  let new_d = pd_pool_as_treasury(1_000_000_000, 1_030_181_086)
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, old_d)],
      [p_out(1_000_000_000, 1_030_181_086, new_d), crea(10_000_000)],
    )
  spend_pool(old_d, Buy { min_out: 112_000_000 }, tx)
}

/// The creator half of the same trick — and the half that SURVIVES pinning
/// `treasury_pkh` to a constant, which is why the `pays_at_least` exclusion is
/// the load-bearing fix rather than the belt. No creator output in the tx.
test buy_rejects_the_pool_paying_its_own_creator_fee() fail {
  let old_d = pd_pool_as_creator(0, 1_142_857_143)
  let new_d = pd_pool_as_creator(1_000_000_000, 1_030_181_086)
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, old_d)],
      [p_out(1_000_000_000, 1_030_181_086, new_d), plat(2_000_000)],
    )
  spend_pool(old_d, Buy { min_out: 112_000_000 }, tx)
}

/// …and on the SELL branch, which had no coverage of this class at all.
test sell_rejects_the_pool_paying_its_own_platform_fee() fail {
  let old_d = pd_pool_as_treasury(1_000_000_000, 1_030_181_086)
  let new_d = pd_pool_as_treasury(806_836_034, 1_050_181_086)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, old_d)],
      [p_out(806_836_034, 1_050_181_086, new_d), crea(1_931_639)],
    )
  spend_pool(old_d, Sell { min_out: 189_000_000 }, tx)
}

/// ██ THE COUNTERFEIT POOL. ██
///
/// A self-seeded pool at LumpFun's one and only curve address: the attacker's own
/// policy, both fee keys pointing at themselves, and a ZERO platform fee. It never
/// went through `lump_mint_v3` and nothing on-chain used to notice — it traded
/// through the official validator paying LumpFun nothing, and it was
/// indistinguishable to any aggregator keyed on the address. `fee_schedule_ok`
/// rejects it on all three of `treasury_pkh`, `platform_fee_bps` and
/// `platform_fee_flat`.
fn pd_counterfeit(a: Int, t: Int) -> PoolDatum {
  dat(t_policy, t_name, a, t, t_owner, t_owner, 0, 0, 0, t_royalty, Bootstrap)
}

test buy_rejects_a_zero_platform_fee_self_seeded_pool() fail {
  let old_d = pd_counterfeit(0, 1_142_857_143)
  let new_d = pd_counterfeit(1_000_000_000, 1_030_181_086)
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, old_d)],
      [p_out(1_000_000_000, 1_030_181_086, new_d), pk_out(t_owner, 2_000_000)],
    )
  spend_pool(old_d, Buy { min_out: 112_000_000 }, tx)
}

/// ██ THE SELL-SIDE MIRROR, AND IT EXISTS FOR A MEASURED REASON. ██
///
/// The `fee_schedule_ok` CALL SITE in `validate_sell` was bound by NOTHING, and the
/// obvious candidate — `sell_rejects_the_pool_paying_its_own_platform_fee` — CANNOT
/// bind it: that test names the pool as its own treasury, so `pays_at_least`'s
/// own-hash exclusion rejects it INDEPENDENTLY. mutverify measured exactly that,
/// reporting SURVIVED when the whole call was deleted from the sell branch's
/// and-block while the suite stayed green.
///
/// This case isolates it. A zero-fee counterfeit datum owes NO fee outputs at all —
/// `creator_fee(g, 0) == 0` fires the documented hatch and
/// `platform_fee(g, 0, 0) == 0` is satisfied by any output paying `t_owner` — so
/// every other guard on the branch passes and `fee_schedule_ok` is the only thing
/// left refusing it.
///   old = (1,000,000,000, 1,030,181,086) ; tokens_in = 20,000,000
///   gross = 193,163,966  (math_v3.sell_twenty_million_tokens)
///   new = (806,836,034, 1,050,181,086) ; with 0/0/0 the net IS the gross
test sell_rejects_a_zero_platform_fee_self_seeded_pool() fail {
  let old_d = pd_counterfeit(1_000_000_000, 1_030_181_086)
  let new_d = pd_counterfeit(806_836_034, 1_050_181_086)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, old_d)],
      [p_out(806_836_034, 1_050_181_086, new_d), pk_out(t_owner, 2_000_000)],
    )
  spend_pool(old_d, Sell { min_out: 193_163_966 }, tx)
}

/// A pool naming a FOREIGN treasury — the launcher-supplied-treasury exploit,
/// refused at spend time as well as at genesis. This is the half a
/// minting-policy-only fix would miss on a self-seeded pool.
test buy_rejects_a_pool_whose_datum_names_a_foreign_treasury() fail {
  let foreign = #"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
  let old_d =
    dat(
      t_policy,
      t_name,
      0,
      1_142_857_143,
      t_creator,
      foreign,
      100,
      0,
      2_000_000,
      t_royalty,
      Bootstrap,
    )
  let new_d =
    dat(
      t_policy,
      t_name,
      1_000_000_000,
      1_030_181_086,
      t_creator,
      foreign,
      100,
      0,
      2_000_000,
      t_royalty,
      Bootstrap,
    )
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, old_d)],
      [
        p_out(1_000_000_000, 1_030_181_086, new_d),
        pk_out(foreign, 2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(old_d, Buy { min_out: 112_000_000 }, tx)
}

/// A FUTURE COHORT MAY RAISE THE PLATFORM FEE. `fee_schedule_ok` uses `>=` on
/// both platform levels precisely so a new minting policy can compile a
/// higher-fee cohort against this same shared pool (§5.6's stated design goal).
/// Only LOWERING it, or redirecting it, is forbidden.
///   platform_fee_bps 100, flat 2,500,000 ⇒ 1e9 × 100/10,000 + 2,500,000 = 12,500,000
test buy_accepts_a_future_cohort_that_raises_the_platform_fee() {
  let old_d =
    dat(
      t_policy,
      t_name,
      0,
      1_142_857_143,
      t_creator,
      t_treasury,
      100,
      100,
      2_500_000,
      t_royalty,
      Bootstrap,
    )
  let new_d =
    dat(
      t_policy,
      t_name,
      1_000_000_000,
      1_030_181_086,
      t_creator,
      t_treasury,
      100,
      100,
      2_500_000,
      t_royalty,
      Bootstrap,
    )
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, old_d)],
      [
        p_out(1_000_000_000, 1_030_181_086, new_d),
        plat(12_500_000),
        crea(10_000_000),
      ],
    )
  spend_pool(old_d, Buy { min_out: 112_000_000 }, tx)
}

/// A NEGATIVE creator bps makes `creator_fee` negative, at which point
/// `pays_at_least` succeeds against any output at that credential. Unreachable on
/// a genuine pool (the rates are pinned at genesis) and free to refuse.
test buy_rejects_a_negative_creator_fee_bps() fail {
  let old_d =
    dat(
      t_policy,
      t_name,
      0,
      1_142_857_143,
      t_creator,
      t_treasury,
      -100,
      0,
      2_000_000,
      t_royalty,
      Bootstrap,
    )
  let new_d =
    dat(
      t_policy,
      t_name,
      1_000_000_000,
      1_030_181_086,
      t_creator,
      t_treasury,
      -100,
      0,
      2_000_000,
      t_royalty,
      Bootstrap,
    )
  let tx =
    base_tx(
      [p_in(0, 1_142_857_143, old_d)],
      [
        p_out(1_000_000_000, 1_030_181_086, new_d),
        plat(2_000_000),
        crea(10_000_000),
      ],
    )
  spend_pool(old_d, Buy { min_out: 112_000_000 }, tx)
}

/// The Script arm of `pays_at_least`, pinned in the direction its doc comment
/// claims: a creator MAY route their rev-share to a script they control, as long
/// as that script is not the pool itself. Previously unexercised in either
/// direction, so narrowing or widening the arm would have gone unnoticed.
test buy_accepts_a_creator_fee_paid_to_a_script_address() {
  let fee_out = script_out(t_creator, ada(10_000_000), 0)
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [p_out(1_000_000_000, 1_030_181_086, buy_new()), plat(2_000_000), fee_out],
    ),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// VALUE SHAPE — the pool holds EXACTLY lovelace + curve token + NFT
// ══════════════════════════════════════════════════════════════════════════════

const t_junk_policy: ByteArray =
  #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

/// Junk stuffed into the continuation of an otherwise perfectly legal buy. Before
/// `value_shape_ok`, ~100 of these filled the value to `maxValSize`, raised the
/// pool's ledger min-UTxO to ~22–24 ADA, and made the last ~12–14 ADA of curve
/// reserve unsellable at the ledger layer.
test buy_rejects_extra_assets_in_the_continuation() fail {
  let junk =
    pool_value(1_000_000_000, 1_030_181_086)
      |> assets.add(t_junk_policy, #"4a554e4b", 1)
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [script_out(t_pool, junk, buy_new()), plat(2_000_000), crea(10_000_000)],
    ),
  )
}

test sell_rejects_extra_assets_in_the_continuation() fail {
  let junk =
    pool_value(806_836_034, 1_050_181_086)
      |> assets.add(t_junk_policy, #"4a554e4b", 1)
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [script_out(t_pool, junk, inv_new()), plat(2_000_000), crea(1_931_639)],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// ██ NO REFERENCE SCRIPT ON THE CONTINUATION — ALL FOUR TRADE BRANCHES ██
//
// `reference_script == None` was asserted at GENESIS (`lump_mint_v3`) and at the
// FLIP (`validate_graduate`) and NOWHERE ELSE, so welding one onto the pool during
// an ordinary trade was accepted on all four trade branches. Confirmed by
// inspection before the guard landed: nothing in `validate_buy`, `validate_sell`,
// `validate_amm_buy` or `validate_amm_sell` read the field, and none of the datum,
// value, address or shape checks touches it — `sole_continuation` filters on the
// payment credential and `continuation_address_exact` compares addresses.
//
// THE HARM IS THE ONE `no_ref_script_kept`'s own comment describes, and it is
// SPONSORED BY ONE TRADER AND PAID BY THE NEXT: Conway charges
// `minFeeRefScriptCoinsPerByte` over the reference scripts on a transaction's
// RESOLVED INPUTS, so the griefer pays one ordinary trade's fees and every
// subsequent trader pays the tier. It also raises the pool output's own min-UTxO
// deposit, which matters most in `Amm` mode where the lovelace is pinned to
// `ada_reserve` with no `pool_floor_v3` cushion beside it.
//
// One reject per branch, each mutating ONLY the `reference_script` field away from
// that branch's canonical accept case. `mutverify.sh` neuters each of the five call
// sites by occurrence and expects exactly the matching test to fail.
// ══════════════════════════════════════════════════════════════════════════════

/// The griefing script bytes — any non-`None` value is refused, so the content is
/// irrelevant and 28 bytes of 0xaa mirrors the graduation test at
/// `graduate_rejects_a_reference_script_on_the_graduated_pool`.
const t_ref_script: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

test buy_rejects_a_reference_script_on_the_continuation() fail {
  let with_ref =
    Output {
      address: address.from_script(t_pool),
      value: pool_value(1_000_000_000, 1_030_181_086),
      datum: InlineDatum(buy_new()),
      reference_script: Some(t_ref_script),
    }
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs([with_ref, plat(2_000_000), crea(10_000_000)]),
  )
}

test sell_rejects_a_reference_script_on_the_continuation() fail {
  let with_ref =
    Output {
      address: address.from_script(t_pool),
      value: pool_value(806_836_034, 1_050_181_086),
      datum: InlineDatum(inv_new()),
      reference_script: Some(t_ref_script),
    }
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [with_ref, plat(2_000_000), crea(1_931_639)],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// The AMM half, and the one that matters most: the pool is PERMANENT, so a tier
/// welded on here is charged to every trader for the rest of the token's life.
test amm_buy_rejects_a_reference_script_on_the_continuation() fail {
  let with_ref =
    Output {
      address: address.from_script(t_pool),
      value: amm_value(17_717_047_886, 246_502_534),
      datum: InlineDatum(ab_new()),
      reference_script: Some(t_ref_script),
    }
  spend_pool(
    ab_old(),
    AmmBuy { min_out: 14_700_000 },
    ab_tx_outs([with_ref, plat(2_000_000), crea(10_000_000)]),
  )
}

test amm_sell_rejects_a_reference_script_on_the_continuation() fail {
  let with_ref =
    Output {
      address: address.from_script(t_pool),
      value: amm_value(12_098_949_302, 361_203_875),
      datum: InlineDatum(as_new()),
      reference_script: Some(t_ref_script),
    }
  let tx =
    base_tx(
      [am_in(ga, gt, ab_old())],
      [with_ref, plat(2_000_000), crea(46_180_985)],
    )
  spend_pool(ab_old(), AmmSell { min_out: 4_567_481_522 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// STAKE CAPTURE ON THE CURVE BRANCHES — completing the family
//
// `continuation_address_exact` has FIVE call sites and only Graduate and AmmBuy had
// tests. AmmSell's is the severe gap (the pool is permanent) and is covered above;
// these two complete Buy and Sell so the guard is bound on every branch and
// `mutverify.sh` can neuter each occurrence independently. The harm is smaller on
// the curve only because the curve terminates in ~16,717 ADA of buying — while it
// runs, the staked address is frozen by the guard on every other branch just the
// same.
// ══════════════════════════════════════════════════════════════════════════════

test buy_rejects_a_stake_credential_on_the_continuation() fail {
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        script_out_staked(
          t_pool,
          #"5555555555555555555555555555555555555555555555555555555a",
          pool_value(1_000_000_000, 1_030_181_086),
          buy_new(),
        ),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

test sell_rejects_a_stake_credential_on_the_continuation() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [
        script_out_staked(
          t_pool,
          #"5555555555555555555555555555555555555555555555555555555a",
          pool_value(806_836_034, 1_050_181_086),
          inv_new(),
        ),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// NO MINT OR BURN UNDER THE POOL'S OWN POLICY DURING A TRADE
// ══════════════════════════════════════════════════════════════════════════════

/// Burning the pool NFT during a BUY. Taken in isolation both validators used to
/// be satisfied — `validate_buy` because the continuation it inspects holds the
/// NFT, `lump_mint_v3.Retire` because the pool input holds it — and only the
/// LEDGER's value-conservation rule rejected the transaction. `no_policy_mint`
/// makes it a local property of the trade branch.
test buy_rejects_burning_the_pool_nft_mid_curve() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [p_in(0, 1_142_857_143, buy_old())],
      mint: assets.from_asset(t_policy, pool_nft_name, -1),
      outputs: [
        p_out(1_000_000_000, 1_030_181_086, buy_new()),
        plat(2_000_000),
        crea(10_000_000),
      ],
    }
  spend_pool(buy_old(), Buy { min_out: 112_000_000 }, tx)
}

/// Minting extra curve tokens during a SELL — the C-1 break the mint guard
/// forecloses locally.
test sell_rejects_minting_curve_tokens_mid_curve() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      mint: assets.from_asset(t_policy, t_name, 1_000_000),
      outputs: [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    }
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

// ══════════════════════════════════════════════════════════════════════════════
// SELL-BRANCH ADVERSARIAL SET
//
// The Buy branch had 8 R-5 tests and 3 shape tests; Sell had 1 and 0. A Phase-2
// edit touching only `validate_sell` could have lost tx-shape confinement, NFT
// authenticity or datum reconstruction with the suite staying green.
// ══════════════════════════════════════════════════════════════════════════════

test sell_rejects_decoy_input_without_the_nft() fail {
  let tx =
    base_tx(
      [p_in_raw(1_002_500_000, 887_323_943, 0, inv_old())],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test sell_rejects_second_pool_input() fail {
  let other =
    input_of(
      oref(#"0001", 0),
      script_out(t_pool, pool_value(1_000_000_000, 1_030_181_086), inv_old()),
    )
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old()), other],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test sell_rejects_foreign_script_input() fail {
  let foreign =
    input_of(
      oref(#"0f0f", 0),
      script_out(
        #"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
        ada(5_000_000),
        0,
      ),
    )
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old()), foreign],
      [
        p_out(806_836_034, 1_050_181_086, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test sell_rejects_two_pool_continuation_outputs() fail {
  let dup = p_out(806_836_034, 1_050_181_086, inv_new())
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [dup, dup, plat(2_000_000), crea(1_931_639)],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

test sell_rejects_two_nfts_in_the_continuation() fail {
  let tx =
    base_tx(
      [p_in(1_000_000_000, 1_030_181_086, inv_old())],
      [
        p_out_raw(809_336_034, 907_323_943, 2, inv_new()),
        plat(2_000_000),
        crea(1_931_639),
      ],
    )
  spend_pool(inv_old(), Sell { min_out: 189_000_000 }, tx)
}

/// R-5 on the sell branch, one reject per remaining immutable field. Only
/// `royalty_pub_key` was covered here before.
fn sell_with_new_datum(new_d: PoolDatum) -> Transaction {
  base_tx(
    [p_in(1_000_000_000, 1_030_181_086, inv_old())],
    [
      script_out(t_pool, pool_value(806_836_034, 1_050_181_086), new_d),
      plat(2_000_000),
      crea(1_931_639),
    ],
  )
}

test r5_sell_rejects_rewriting_the_creator_pkh() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(pd_creator(806_836_034, 1_050_181_086, t_owner)),
  )
}

test r5_sell_rejects_rewriting_the_treasury_pkh() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(pd_treasury(806_836_034, 1_050_181_086, t_owner)),
  )
}

test r5_sell_rejects_rewriting_the_policy_id() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(
      pd_policy(806_836_034, 1_050_181_086, t_junk_policy),
    ),
  )
}

test r5_sell_rejects_rewriting_the_asset_name() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(pd_name(806_836_034, 1_050_181_086, #"42414441")),
  )
}

test r5_sell_rejects_zeroing_the_creator_fee_bps() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(pd_cbps(806_836_034, 1_050_181_086, 0)),
  )
}

/// As on the buy branch: the cohort bps is 0, so the rewrite that isolates the
/// freeze is writing a NONZERO rate (the old 50), not writing 0.
test r5_sell_rejects_rewriting_the_platform_fee_bps() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(pd_pbps(806_836_034, 1_050_181_086, 50)),
  )
}

test r5_sell_rejects_zeroing_the_platform_fee_flat() fail {
  spend_pool(
    inv_old(),
    Sell { min_out: 189_000_000 },
    sell_with_new_datum(pd_pflat(806_836_034, 1_050_181_086, 0)),
  )
}

// ══════════════════════════════════════════════════════════════════════════════
// DATUM SHAPE — the surfaces the soft-cast actually guards
// ══════════════════════════════════════════════════════════════════════════════

/// v2's shape, for the reject below: `Constr(0, [Int, Int, Constr(0,[])])`, which
/// is exactly what `contracts/cardano/lib/lumpfun/pool_types.ak`'s
/// `PoolDatum { ada_reserve, token_reserve, mode: PoolMode }` encodes to.
type V2Mode {
  V2Bootstrap
}

type V2Datum {
  V2Pool { ada_reserve: Int, token_reserve: Int, mode: V2Mode }
}

/// A REAL v2-shaped continuation datum.
///
/// THIS TEST USED TO BUILD A TUPLE. `let v2_shaped: Data = (a, b, c)` encodes as
/// the Data LIST `[_ a, b, c]`, NOT a Constr — verified with `cbor.diagnostic` —
/// so it exercised the "a List where a Constr was expected" soft-cast path and
/// said nothing whatsoever about constructor tag or arity, despite a comment
/// claiming it checked both. A mutation sweep killed it with no mutation.
/// The underlying property does hold, and now it is actually tested.
test rejects_a_v2_shaped_continuation_datum() fail {
  let v2_shaped: Data =
    V2Pool {
      ada_reserve: 1_000_000_000,
      token_reserve: 1_030_181_086,
      mode: V2Bootstrap,
    }
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        script_out(t_pool, pool_value(1_000_000_000, 1_030_181_086), v2_shaped),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// `ReservedV2Slot` in the CONTINUATION. It soft-casts to `PoolDatum` happily
/// (it is a legal constructor of the type — see
/// `pool_types.reserved_v2_slot_passes_the_pool_datum_soft_cast`), so the guard
/// that stops it is the SECOND `expect PoolDatumV3`. Untested until now.
test rejects_a_reserved_slot_continuation_datum() fail {
  let reserved: Data = ReservedV2Slot
  spend_pool(
    buy_old(),
    Buy { min_out: 112_000_000 },
    buy_tx_outs(
      [
        script_out(t_pool, pool_value(1_000_000_000, 1_030_181_086), reserved),
        plat(2_000_000),
        crea(10_000_000),
      ],
    ),
  )
}

/// `ReservedV2Slot` as the INPUT datum, for the same reason on the other side.
test rejects_a_reserved_slot_input_datum() fail {
  lump_pool_v3.spend(
    Some(ReservedV2Slot),
    Buy { min_out: 112_000_000 },
    p_ref(),
    buy_good_tx(),
  )
}

/// `datum: None` — the `expect Some(d)` at the top of the spend handler. A pool
/// UTxO with no datum at all was untested on every branch.
test rejects_a_missing_input_datum() fail {
  lump_pool_v3.spend(None, Buy { min_out: 112_000_000 }, p_ref(), buy_good_tx())
}
