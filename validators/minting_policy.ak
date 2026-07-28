use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Credential}
use cardano/assets.{lovelace_of, quantity_of, tokens}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}
use lumpfun/fees_v3.{creator_fee_paid, platform_fee_paid}
use lumpfun/math_v3.{quote_buy}
use lumpfun/params_v3.{
  creator_fee_bps_v3, curve_exhausted_token_reserve, platform_fee_bps_v3,
  platform_fee_flat_v3, pool_floor_v3, total_supply_v3, treasury_pkh_v3,
  virtual_token_v3,
}
use lumpfun/pool_types.{
  Amm, Bootstrap, PoolDatum, PoolDatumV3, PoolMode, pool_nft_name,
}
use lumpfun/types.{Launch, MintRedeemer}
use lumpfun/test_helpers.{input_of, pk_out, script_out, script_out_staked}

// ══════════════════════════════════════════════════════════════════════════════
// LumpFun v3 one-shot minting policy
//
// `one_shot_utxo` must be consumed in the LAUNCH transaction, so the policy id
// derived from this parameterised validator is globally unique and the launch
// can happen exactly once.
//
// ── What v3 fixes relative to v2 ──────────────────────────────────────────────
//
// 1. THE POOL ADDRESS IS PINNED. v2's policy could not check it and said so:
//    "`lump_pool` is parameterised by `policy_id`, and `policy_id` is this
//    policy's own hash, so the dependency is circular"
//    (contracts/cardano/validators/minting_policy.ak:72-76). v3's pool is
//    unparameterised, so `pool_script_hash` is a plain constant here and the
//    circle is gone. The launch tx must seat the supply at THE pool address, not
//    merely at "some output that holds the NFT".
//
// 2. GENESIS ADA IS PINNED TO `pool_floor_v3`. v2 required
//    `d.ada_reserve == lovelace_of(pool.value)` and its own test
//    `mint_accepts_pool_seeded_with_extra_ada` ACCEPTED any genesis ADA — so a
//    creator seeding 8,000 ADA launched at double the intended FDV, on the
//    curve, with their own money already counted as raised. That is a live v2
//    bug. v3 requires `lovelace_of(pool.value) == pool_floor_v3 && d.ada_reserve
//    == 0`, and v2's accepting test INVERTS to a reject case below.
//
// 3. `royalty_pub_key` LENGTH IS ASSERTED AT LAUNCH. Aiken's soft-cast checks
//    Constr arity and constructor tag but NOT bytestring lengths, so this
//    assertion is mandatory and cannot be folded into `expect d: PoolDatum`.
//    (Its original purpose was Splash's field-13 `royaltyPubKey`, which required
//    exactly 32 bytes or the pool was silently dropped. That venue is parked; the
//    field and its assert are retained deliberately — see the extended note on
//    `royalty_pub_key` in `pool_types.ak`.)
//
// 4. `mode` IS PINNED TO `Bootstrap` AT GENESIS. A launch whose datum already
//    said `Amm` would seat 1e9 tokens in a pool that prices on REAL reserves with
//    `token_reserve = virtual_token_v3 = 1,142,857,143` against a real balance of
//    1e9 — a pool claiming 142,857,143 tokens it does not hold, whose first
//    `AmmSell` is a solvency violation the value invariant would reject and whose
//    first `AmmBuy` is priced 14% low. It is one comparison.
//
// ══════════════════════════════════════════════════════════════════════════════
// ██ 5. THERE IS NO BURN PATH. THE POLICY IS LAUNCH-ONLY.                     ██
// ══════════════════════════════════════════════════════════════════════════════
//
// `Retire` — which burned the 1-of-1 pool NFT — WAS DELETED on 2026-07-26 with the
// Splash venue. v3 now graduates by flipping the pool datum IN PLACE, so the pool
// UTxO survives graduation and its NFT keeps authenticating it for the life of the
// token. Nothing is ever retired.
//
// THIS IS A STRICTLY STRONGER C-1 PROPERTY THAN BEFORE, and the strengthening is
// structural rather than argumentative. With `Retire` present, "curve supply is
// untouchable for the life of the token" was a THREE-SCRIPT argument: the NFT is
// 1-of-1, `Retire` requires it in an input at the pool address, `lump_pool_v3`'s
// `pool_nft_kept` means it can never leave that address, and the ledger's
// value-conservation rule forbids burning it in the same transaction as a trade.
// Every link was correct and every link was a link. `lump_pool.no_policy_mint`
// exists precisely because that chain was untested.
//
// Now there is nothing to argue. `mint` has ONE handler; it requires the one-shot
// seed UTxO in an input; that UTxO is consumed by the launch and can never be
// consumed again. So:
//   • total supply is provably immutable at `total_supply_v3` for life,
//   • the pool NFT count is provably immutable at 1 for life,
//   • and NO transaction under this policy can ever succeed a second time,
// each of them from a single premise with no cross-script step. C-1 — "every token
// outside the pool was bought on the curve" — needs only `pool_seeded`'s 100%
// requirement plus that.
//
// `lump_pool.no_policy_mint` is KEPT on every branch anyway. It is now asserting
// something unfalsifiable-by-construction rather than something load-bearing, and
// that is the correct direction: if a future cohort ever adds a second mint path,
// the pool branches already refuse to trade alongside it.
//
// ── THE PIN IS ONLY AS STRONG AS PARAMETER APPLICATION ───────────────────────
// `payment_ok` pins the pool's payment credential to the `pool_script_hash`
// PARAMETER and `bare_address_ok` pins `stake_credential` to None, closing v2's
// circular-dependency hole for real. But NOTHING IN THIS TREE BINDS THE PARAMETER
// TO REALITY: the tests apply a placeholder (`mp_pool = #"d1d1…"`), and parameter
// application happens off-chain where no Aiken test can reach.
//
// A creator who builds their own launch transaction can apply
// `pool_script_hash` = a script THEY control. Every check here passes —
// `one_shot_ok`, `supply_ok`, `pool_seeded` — and the result is a unique,
// canonical-looking one-shot policy that seats 100% of supply in an
// attacker-controlled script, with nothing on-chain to distinguish it.
//
// The defence is entirely off-chain and it is now written down in ONE place:
// `hashes.expected` carries the canonical `lump_pool.lump_pool_v3.spend` hash,
// `./aikcheck.sh build` asserts the build still produces it, and §8.3's
// recompute-and-compare of the policy id from (seed, canonical_pool_hash) must run
// WITH NO FALLBACK to asset matching. `pool-v2.ts:102` currently ships exactly
// such a fallback (`utxos.find(u => u.assets[assetUnit] !== undefined)`), which
// was safe at a per-token v2 address and is a decoy magnet at v3's shared one.
//
// SECOND-ORDER, UNIQUE TO v3: v2's pool was parameterised by `policy_id`, so a
// policy id determined its pool address and verification needed nothing else.
// v3's is not, so verifying a token requires the SEED UTxO as well as the pool
// hash — THE REGISTRY MUST STORE EACH TOKEN'S SEED OutputReference or the §8.3
// recompute cannot be performed at all.
// ══════════════════════════════════════════════════════════════════════════════

validator lump_mint_v3(
  one_shot_utxo: OutputReference,
  pool_script_hash: ByteArray,
) {
  mint(redeemer: MintRedeemer, policy_id: ByteArray, tx: Transaction) {
    // ONE CONSTRUCTOR, SO THERE IS NOTHING TO DISPATCH ON. Aiken warns on a
    // single-clause `when`, and it is right: `Launch` is the only inhabitant of
    // `MintRedeemer` now that `Retire` is deleted, so a match destructures rather
    // than selects. The named type is KEPT rather than replaced with `Data` so the
    // on-chain redeemer stays `Constr(0, [])` — byte-identical to what any existing
    // builder sends — and so a future cohort adding a second handler starts from a
    // type that already has a discriminant.
    let Launch = redeemer

    // Uniqueness + single-mint: the named UTxO must be consumed here. It is what
    // makes the policy id globally unique, what makes the launch happen exactly
    // once — and, now that there is no other handler, what makes EVERY
    // transaction under this policy after the launch impossible.
    let one_shot_ok =
      list.any(tx.inputs, fn(i) { i.output_reference == one_shot_utxo })

    // Fixed supply: EXACTLY two assets under this policy — the curve token
    // at exactly `total_supply_v3`, and the 1-of-1 pool NFT. Anything else
    // (extra supply, a third name, a burn, two NFTs) fails.
    //
    // `dict.to_pairs` yields entries ordered by asset name and names are
    // unique, so matching either position covers both orderings.
    let supply_ok =
      when dict.to_pairs(tokens(tx.mint, policy_id)) is {
        [Pair(n1, q1), Pair(n2, q2)] ->
          if n1 == pool_nft_name {
            q1 == 1 && q2 == total_supply_v3 && pool_seeded(
              tx.outputs,
              policy_id,
              n2,
              pool_script_hash,
            )
          } else if n2 == pool_nft_name {
            q2 == 1 && q1 == total_supply_v3 && pool_seeded(
              tx.outputs,
              policy_id,
              n1,
              pool_script_hash,
            )
          } else {
            False
          }
        _ -> False
      }

    one_shot_ok && supply_ok
  }

  else(_) {
    fail
  }
}

/// The launch tx must seat the ENTIRE supply in a correctly-formed pool UTxO at
/// the pinned pool address.
///
/// Without the 100% requirement the policy constrains only how many tokens
/// EXIST, never where they go — and that is the whole ballgame. A launcher could
/// satisfy the mint, seat the NFT plus ONE token in the pool, keep 999,999,999,
/// and later dump: an outside bag of `D` against pool tokens `T` takes
/// `R·D/(T+D)` of the pool's ADA, so a bag of f% of supply extracts exactly f%.
/// At 1 token in the pool that is ~100%.
///
/// Requiring 100% at genesis makes the protocol's central claim true by
/// construction: EVERY TOKEN OUTSIDE THE POOL WAS BOUGHT ON THE CURVE. A creator
/// who wants an allocation buys it in a second transaction at the same price
/// anyone else pays.
fn pool_seeded(
  outputs: List<Output>,
  policy_id: ByteArray,
  curve_name: ByteArray,
  pool_script_hash: ByteArray,
) -> Bool {
  // Exactly one output may carry the NFT; two would mean two "pools".
  let carriers =
    list.filter(
      outputs,
      fn(o) { quantity_of(o.value, policy_id, pool_nft_name) == 1 },
    )
  when carriers is {
    [pool] -> {
      // The pool ADDRESS, pinned. Aiken's soft-cast does NOT check credential
      // constructors, so the Script match is written out explicitly rather than
      // inferred from a type annotation.
      let payment_ok =
        when pool.address.payment_credential is {
          Credential.Script(h) -> h == pool_script_hash
          Credential.VerificationKey(_) -> False
        }

      // BARE (enterprise) address only. `lump_pool_v3` requires the
      // continuation output to sit at `own_input.output.address` — the FULL
      // address — so whoever attaches a stake credential at launch keeps it for
      // the life of the pool and collects staking rewards on up to ~16,717 ADA
      // of other people's money. It also makes the curve address non-unique,
      // which §2.1's "one address to give an aggregator" depends on.
      let bare_address_ok = pool.address.stake_credential == None

      // Genesis value: the `pool_floor_v3` (2.5 ADA) and NOTHING more, plus 100% of supply,
      // and EXACTLY THREE ENTRIES — lovelace, the curve token, the pool NFT.
      //
      // The three-entry clause was missing. Without it a launcher could seat
      // arbitrary foreign assets in the genesis pool, including a FOREIGN
      // policy's asset named `pool_nft_name`. Blast radius was bounded (the
      // spend path never requires extra assets to be preserved, so the first
      // trader sweeps them as free profit, and the exact-floor pin caps how
      // much can be stuffed in before min-UTxO exceeds the floor) but it is the
      // same "value shape not pinned" class that §5.5's G9 calls the most
      // important comment in the codebase on the Splash side, and it costs one
      // line here. `lump_pool_v3` now applies the identical check to every
      // continuation.
      // ══════════════════════════════════════════════════════════════════════
      // ██ THE GENESIS BUY — v3.1                                            ██
      // ══════════════════════════════════════════════════════════════════════
      //
      // A launch may now carry the creator's first buy IN THE SAME TRANSACTION.
      // Before this, `ada_reserve == 0` and `lovelace == pool_floor_v3` were
      // pinned absolutely, which made one-transaction launch-and-buy not merely
      // unimplemented but IMPOSSIBLE: a buy has to SPEND the pool output, and no
      // transaction can spend an output it creates in the same transaction.
      //
      // ── EVERY NUMBER IS DERIVED FROM THE OUTPUT, NEVER DECLARED ────────────
      // `ada_in` is what the pool output actually holds above the floor, and
      // `tokens_out` is what is actually missing from the supply seated in it.
      // Neither comes from a redeemer or a datum field, so there is nothing for
      // a launcher to misstate — the same discipline as the V-2/R-1 fee work,
      // where deriving fees from an author-controlled `OrderDatum` was the bug.
      //
      // ── AND IT IS THE SAME TRADE `validate_buy` WOULD HAVE ACCEPTED ────────
      // `correct_tokens_out`, `cap_ok`, `ada_in > 0` and both fee checks are the
      // clauses of `validate_buy`, evaluated at the genesis state
      // (`old_ada = 0`, `old_tok = virtual_token_v3`). `open_ok` is omitted only
      // because it is statically true there: `virtual_token_v3` is by
      // construction far above `curve_exhausted_token_reserve`. So a genesis buy
      // is priced, capped and charged EXACTLY as the separate Buy it replaces —
      // there is no cheaper first token, and C-1 survives unchanged, because
      // every token leaving the pool here was bought on the curve at the curve's
      // opening price.
      //
      // ── AND IT CLOSES A REAL WINDOW, NOT JUST TWO SIGNATURES ───────────────
      // With two transactions, anyone watching the mempool can land a buy
      // between the launch and the creator's, ahead of them, at the opening
      // price. Atomic genesis removes that window by construction.
      let ada_in = lovelace_of(pool.value) - pool_floor_v3
      let tokens_out =
        total_supply_v3 - quantity_of(pool.value, policy_id, curve_name)
      let value_ok =
        and {
          // A pure genesis is `ada_in == 0`, and both quantities must move
          // together or not at all — the datum pins below tie them to each other
          // and to the quote.
          ada_in >= 0,
          tokens_out >= 0,
          // Still exactly three entries: lovelace, curve token, NFT. A buy large
          // enough to empty the token side would drop this to two and be
          // rejected here, before `cap_ok` ever runs.
          list.length(assets.flatten(pool.value)) == 3,
        }

      // NO REFERENCE SCRIPT on the pool UTxO. A reference script attached at
      // genesis is charged to EVERY trader who spends the pool under Conway's
      // reference-script fee tiers, for the life of the curve — a permanent tax
      // a launcher could impose on their own token's buyers.
      let no_ref_script_ok = pool.reference_script == None

      let datum_ok =
        when pool.datum is {
          InlineDatum(raw) -> {
            expect d: PoolDatum = raw
            // Every field is destructured, with no `..`. Adding a field to
            // `PoolDatumV3` therefore breaks THIS FUNCTION at compile time,
            // forcing whoever adds it to say what it must be at genesis.
            expect PoolDatumV3 {
              policy_id: d_policy,
              asset_name: d_name,
              ada_reserve,
              token_reserve,
              creator_pkh,
              treasury_pkh,
              creator_fee_bps,
              platform_fee_bps,
              platform_fee_flat,
              royalty_pub_key,
              mode,
            } = d
            and {
              // The datum names THIS policy and THIS asset. `lump_pool_v3`
              // reads `policy_id` from the datum (it is unparameterised), so
              // this is what ties the shared pool address to a specific token.
              d_policy == policy_id,
              d_name == curve_name,
              // ── THE RESERVES ARE PINNED TO THE OUTPUT, NOT TO ZERO ─────────
              // The datum must state exactly the position the output actually
              // holds. `ada_in` is 0 for a plain launch, so this still pins
              // `ada_reserve == 0` and `token_reserve == virtual_token_v3` in
              // that case — the v2 double-FDV bug (a creator seeding 8,000 ADA
              // and launching at twice the intended FDV) stays closed, because
              // any lovelace above the floor is now RESERVE that had to be paid
              // for at the curve price, not a free head start.
              ada_reserve == ada_in,
              token_reserve == virtual_token_v3 - tokens_out,
              // ── THE POOL IS BORN ON THE CURVE, NOT IN THE AMM ─────────────
              // `mode` is the one-way latch that selects which value invariant
              // and which quote function apply. A launch naming `Amm` would seat
              // 1e9 real tokens in a pool whose `token_reserve` says
              // 1,142,857,143 and whose invariant (offset 0) then demands the
              // pool hold 1,142,857,143 — 142,857,143 more than exist. The value
              // check above would reject the first trade, so this is not an
              // exploit; it is an unspendable pool holding 100% of a token's
              // supply with no recovery at any layer, created by one wrong field
              // in a launch datum. Pinned here, and frozen for life by
              // `with_reserves` thereafter.
              mode == Bootstrap,
              // The fee schedule is pinned to this cohort's constants. If it
              // were free-form, a creator building their own launch tx would
              // set `platform_fee_bps` to 0 and pay LumpFun nothing forever —
              // the datum fields exist so a FUTURE cohort can compile a new
              // minting policy with new values, not so a launcher can choose.
              creator_fee_bps == creator_fee_bps_v3,
              platform_fee_bps == platform_fee_bps_v3,
              platform_fee_flat == platform_fee_flat_v3,
              // Length assertions. The soft-cast above checks Constr arity,
              // constructor tag and nested field TYPES — it does NOT check
              // bytestring LENGTHS, so these are mandatory.
              builtin.length_of_bytearray(creator_pkh) == 28,
              builtin.length_of_bytearray(treasury_pkh) == 28,
              // 32 bytes because it is a raw ed25519 public key, and because
              // "pinned at genesis, before the token had a price, and immutable
              // for life" is a property that cannot be retrofitted. It has NO
              // on-chain consumer since Splash was parked — the rationale is no
              // longer "or the pool is dropped by every downstream aggregator at
              // graduation", which is what this comment used to say and which
              // would now argue for DROPPING the field. The recorded decision is
              // KEEP, and the reasoning lives in ONE place: the extended note on
              // `royalty_pub_key` in `pool_types.ak`. Read that before touching it.
              builtin.length_of_bytearray(royalty_pub_key) == 32,
              // ── THE TREASURY IS PINNED TO THE COHORT CONSTANT ─────────────
              // `treasury_pkh` is the recipient of LumpFun's ENTIRE revenue
              // stream and it was the one field in `PoolDatumV3` anchored to
              // nothing. Nine of ten were already correct: policy_id/asset_name
              // to this policy's own id and the minted name, ada_reserve/
              // token_reserve to 0/X_c, the three fee RATES to the params_v3
              // constants, and creator_pkh/royalty_pub_key are by-design
              // creator-owned with explicit length assertions. This one had only
              // "28 bytes and != creator_pkh".
              //
              // Both parameters of `lump_mint_v3` are PUBLIC — `pool_script_hash`
              // is a fixed constant and `one_shot_utxo` is the launcher's own
              // seed — so anyone could apply the published policy to their own
              // seed, build a launch whose genesis datum named a treasury key
              // they control, and `pool_seeded` accepted it in full: correct pool
              // script, bare enterprise address, exactly the floor, 100% of supply,
              // fee schedule exactly on the cohort constants (100/0/2,000,000
              // since 2026-07-26). On-chain the token was
              // indistinguishable from a LumpFun launch. `with_reserves` then
              // made the substitution permanent — R-5 doing its job perfectly and
              // freezing the ATTACKER's key for the life of the pool. Loss: the
              // whole platform-fee stream (now 2 ADA flat/trade), ~100 ADA per graduating
              // token, indefinitely.
              //
              // "Such a token would not be in LumpFun's registry" is a POLICY
              // control, not a contract control, on a permissionless launch path.
              // `lump_pool_v3.fee_schedule_ok` asserts the same equality at spend
              // time so a pool that skipped this policy entirely cannot trade at
              // the shared curve address either.
              treasury_pkh == treasury_pkh_v3,
              // The two fee recipients must differ. Both fee checks in
              // `lump_pool_v3` are existential (`list.any`), so if they were the
              // same key one output would satisfy both and LumpFun would be
              // underpaid on every trade for the life of the pool.
              // `lump_pool_v3`'s `buy_rejects_fees_both_paid_to_the_creator` is
              // the regression test for THIS assertion — see the note on
              // `fees_v3.pays_at_least`, which names this line as a load-bearing
              // precondition. Do not relax one without the other.
              creator_pkh != treasury_pkh,
              // ── NEITHER FEE RECIPIENT MAY BE THE POOL SCRIPT ITSELF ───────
              // A script hash is 28 bytes, so every length assertion above
              // passes for one. `fees_v3.pays_at_least` matches Script
              // credentials as well as VerificationKey, and the pool's own
              // continuation output sits at `Credential.Script(pool_script_hash)`
              // carrying `new_ada + pool_floor_v3` lovelace — vastly more than
              // any fee. Setting either key to the pool hash therefore made the
              // pool's own continuation satisfy that fee check on EVERY trade
              // forever, with NO fee output in the transaction at all.
              //
              // It defeated the "the fee RATES are pinned to the params_v3
              // constants" mitigation verbatim: the rates were pinned and
              // irrelevant, because the RECIPIENT was free. It also silently
              // defeated `creator_pkh != treasury_pkh` above, since the check
              // being evaded was no longer "one output satisfies two checks" but
              // "the pool satisfies its own check". And the creator half SURVIVED
              // pinning the treasury, which is why `pays_at_least` also excludes
              // the pool address structurally — belt and braces, and the braces
              // is the half that binds self-seeded pools.
              creator_pkh != pool_script_hash,
              treasury_pkh != pool_script_hash,
              // ── THE GENESIS BUY, PRICED AND CHARGED LIKE ANY OTHER ────────
              // Inside the datum block because the fee checks need this pool's
              // own `creator_pkh`, which only exists once the datum is cast.
              genesis_buy_ok(
                outputs,
                ada_in,
                tokens_out,
                creator_pkh,
                pool_script_hash,
              ),
            }
          }
          _ -> False
        }

      payment_ok && bare_address_ok && value_ok && no_ref_script_ok && datum_ok
    }
    _ -> False
  }
}

/// The creator's first buy, folded into the launch transaction.
///
/// `ada_in == 0` is a plain launch and must move no tokens. Anything else is a
/// real trade against the opening curve and is held to `validate_buy`'s terms,
/// evaluated at the genesis state `(ada_reserve = 0, token_reserve =
/// virtual_token_v3)`:
///
///   • `tokens_out` is EXACTLY `quote_buy` at that state — recomputed here, not
///     trusted, so there is no cheaper first token than any later buyer gets
///   • `cap_ok`, so a launch cannot also close the curve. Landing exactly on
///     `curve_exhausted_token_reserve` is permitted for the same reason
///     `validate_buy` permits it: the pool is then immediately graduatable,
///     which is a legal state and not a stuck one
///   • both fee outputs, at the cohort rates, to the cohort treasury and this
///     pool's own creator credential
///
/// `open_ok` has no analogue: at genesis the token reserve is
/// `virtual_token_v3`, which is above `curve_exhausted_token_reserve` by
/// construction, so the check would be a constant.
///
/// ── WHY THE FEES CANNOT BE SKIPPED BY SPLITTING THE BUY ──────────────────────
/// A launcher wanting to avoid the flat platform fee could launch plain and buy
/// separately — and pay exactly the same flat fee on that separate buy. There is
/// no configuration in which routing through genesis is cheaper than the two-
/// transaction path it replaces, which is the property that makes this branch
/// purely a UX and front-running improvement rather than an economic change.
fn genesis_buy_ok(
  outputs: List<Output>,
  ada_in: Int,
  tokens_out: Int,
  creator_pkh: ByteArray,
  pool_script_hash: ByteArray,
) -> Bool {
  if ada_in == 0 {
    tokens_out == 0
  } else {
    // Each clause is bound to a NAME on its own line, mirroring `validate_buy`.
    // That is not style: `mutverify.sh` mutates by line, so a guard folded into
    // a multi-line call expression cannot be individually reverted and therefore
    // cannot be proven bound by any test.
    let platform_ok =
      platform_fee_paid(
        outputs,
        treasury_pkh_v3,
        ada_in,
        platform_fee_bps_v3,
        platform_fee_flat_v3,
        pool_script_hash,
      )
    let creator_ok =
      creator_fee_paid(
        outputs,
        creator_pkh,
        ada_in,
        creator_fee_bps_v3,
        pool_script_hash,
      )
    and {
      ada_in > 0,
      tokens_out == quote_buy(0, virtual_token_v3, ada_in),
      virtual_token_v3 - tokens_out >= curve_exhausted_token_reserve,
      platform_ok,
      creator_ok,
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// TESTS — lump_mint_v3
//
// Convention (inherited from v2): every reject case is `test … fail { … }`, so
// it passes when the validator returns False OR aborts via an `expect`. Each
// reject mutates exactly ONE property away from `good_launch_tx`.
//
// EVERY constant below is re-derived for v3. In particular the genesis pool is
// (10,000,000 lovelace, 1,000,000,000 tokens, datum ada_reserve = 0,
// token_reserve = 1,142,857,143) — none of which appears anywhere in v2.
// ══════════════════════════════════════════════════════════════════════════════

const mp_policy: ByteArray = #"b1b1b1b1"

const mp_name: ByteArray = #"4c554d50"

/// The pool script hash this policy pins. 28 bytes, like a real one.
const mp_pool: ByteArray =
  #"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"

/// 28-byte creator / treasury key hashes — the length assertions are real.
const mp_creator: ByteArray =
  #"c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"

/// PINNED to the cohort constant by `pool_seeded` — a launch naming any other
/// treasury key is refused. `mint_rejects_a_foreign_treasury_pkh` is the inverse.
const mp_treasury: ByteArray = treasury_pkh_v3

/// A 28-byte key the LAUNCHER controls — the substitution the treasury pin exists
/// to refuse.
const mp_foreign_treasury: ByteArray =
  #"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"

/// 32-byte ed25519 royalty public key.
const mp_royalty: ByteArray =
  #"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"

fn mp_seed() -> OutputReference {
  OutputReference { transaction_id: #"aaaa", output_index: 0 }
}

fn seed_input(ref: OutputReference) -> Input {
  input_of(ref, pk_out(#"11111111", 2_000_000))
}

fn mint_call(seed: OutputReference, r: MintRedeemer, tx: Transaction) -> Bool {
  lump_mint_v3.mint(seed, mp_pool, r, mp_policy, tx)
}

/// A well-formed launch mint: `total_supply_v3` of the curve token PLUS the
/// 1-of-1 pool NFT, both under this one-shot policy.
fn launch_mint(curve_qty: Int, nft_qty: Int) -> assets.Value {
  assets.from_asset(mp_policy, mp_name, curve_qty)
    |> assets.add(mp_policy, pool_nft_name, nft_qty)
}

/// Full-arity datum builder.
///
/// NOTE ON STYLE: `PoolDatum` has two constructors (index 0 is the reserved v2
/// slot), and Aiken forbids record-UPDATE syntax on multi-constructor types —
/// `PoolDatumV3 { ..d, field: x }` is a compile error. So every mutation below
/// goes through a named one-field wrapper instead. That is more verbose than
/// v2's tests and it is the price of the distinct constructor index, which plan
/// §8.1 requires. It has one benefit: adding a field to `PoolDatumV3` breaks
/// `gd` at compile time, so no test can silently keep testing the old shape.
fn gd(
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

/// The canonical genesis datum: nothing raised, virtual reserve at X_c, this
/// cohort's fee schedule, well-formed keys.
fn genesis_datum() -> PoolDatum {
  gd(
    mp_policy,
    mp_name,
    0,
    virtual_token_v3,
    mp_creator,
    mp_treasury,
    creator_fee_bps_v3,
    platform_fee_bps_v3,
    platform_fee_flat_v3,
    mp_royalty,
    Bootstrap,
  )
}

// One-field mutations of `genesis_datum()`. Each reject test names exactly one.

fn g_policy(x: ByteArray) -> PoolDatum {
  gd(x, mp_name, 0, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_name(x: ByteArray) -> PoolDatum {
  gd(mp_policy, x, 0, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_ada(x: Int) -> PoolDatum {
  gd(mp_policy, mp_name, x, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_tok(x: Int) -> PoolDatum {
  gd(mp_policy, mp_name, 0, x, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_creator(x: ByteArray) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, x, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_treasury(x: ByteArray) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, mp_creator, x, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_cbps(x: Int) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, mp_creator, mp_treasury, x, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_pbps(x: Int) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, x, platform_fee_flat_v3, mp_royalty, Bootstrap)
}

fn g_pflat(x: Int) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, x, mp_royalty, Bootstrap)
}

fn g_royalty(x: ByteArray) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, x, Bootstrap)
}

fn g_mode(x: PoolMode) -> PoolDatum {
  gd(mp_policy, mp_name, 0, virtual_token_v3, mp_creator, mp_treasury, creator_fee_bps_v3, platform_fee_bps_v3, platform_fee_flat_v3, mp_royalty, x)
}

fn pool_out(lovelace: Int, curve_qty: Int, nft_qty: Int, d: PoolDatum) -> Output {
  let v =
    assets.from_lovelace(lovelace)
      |> assets.add(mp_policy, mp_name, curve_qty)
      |> assets.add(mp_policy, pool_nft_name, nft_qty)
  script_out(mp_pool, v, d)
}

/// The canonical well-formed launch output: the 2.5 ADA floor, 100% of supply,
/// genesis datum, bare pool address.
fn good_pool() -> Output {
  pool_out(pool_floor_v3, total_supply_v3, 1, genesis_datum())
}

fn mint_tx(seed: OutputReference, minted: assets.Value) -> Transaction {
  mint_tx_out(seed, minted, [good_pool()])
}

fn mint_tx_out(
  seed: OutputReference,
  minted: assets.Value,
  outs: List<Output>,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [seed_input(seed)],
    mint: minted,
    outputs: outs,
  }
}

/// Launch with a mutated datum, everything else canonical.
fn launch_with_datum(d: PoolDatum) -> Bool {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pool_out(pool_floor_v3, total_supply_v3, 1, d)],
    ),
  )
}

// ── The happy path ────────────────────────────────────────────────────────────

test mint_accepts_canonical_v3_launch() {
  mint_call(mp_seed(), Launch, mint_tx(mp_seed(), launch_mint(total_supply_v3, 1)))
}

// ── One-shot + fixed supply ───────────────────────────────────────────────────

test mint_rejects_without_seed() fail {
  let other = OutputReference { transaction_id: #"bbbb", output_index: 7 }
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(other, launch_mint(total_supply_v3, 1), [good_pool()]),
  )
}

test mint_rejects_wrong_quantity() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx(mp_seed(), launch_mint(total_supply_v3 - 1, 1)),
  )
}

test mint_rejects_over_supply() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx(mp_seed(), launch_mint(total_supply_v3 * 2, 1)),
  )
}

test mint_rejects_without_pool_nft() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx(mp_seed(), assets.from_asset(mp_policy, mp_name, total_supply_v3)),
  )
}

test mint_rejects_two_pool_nfts() fail {
  // two NFTs would allow a second, equally "authentic" decoy pool at the shared
  // v3 pool address — which is far cheaper to exploit than it was in v2
  mint_call(mp_seed(), Launch, mint_tx(mp_seed(), launch_mint(total_supply_v3, 2)))
}

test mint_rejects_third_asset_alongside_nft() fail {
  let minted =
    launch_mint(total_supply_v3, 1) |> assets.add(mp_policy, #"4558545241", 1)
  mint_call(mp_seed(), Launch, mint_tx(mp_seed(), minted))
}

test mint_rejects_zero_mint() fail {
  mint_call(mp_seed(), Launch, mint_tx(mp_seed(), assets.zero))
}

test mint_rejects_burn_under_launch() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx(mp_seed(), assets.from_asset(mp_policy, mp_name, -total_supply_v3)),
  )
}

// ── C-1: 100% of supply seated in the pool ────────────────────────────────────

test mint_rejects_launcher_retaining_a_bag() fail {
  // the C-1 exploit: seat ONE token in the pool, keep 999,999,999
  let pool = pool_out(pool_floor_v3, 1, 1, genesis_datum())
  let keep = pk_out(#"22222222", 2_000_000)
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(mp_seed(), launch_mint(total_supply_v3, 1), [pool, keep]),
  )
}

test mint_rejects_skimming_one_percent() fail {
  // subtler: 99% seated (990,000,000), 1% retained — still a free bag, still
  // rejected. Note that in v3 this fails TWICE over: the pool holds less than
  // `total_supply_v3`, and a self-consistent datum would have to understate
  // `token_reserve`, which is pinned to `virtual_token_v3`.
  let short = total_supply_v3 - total_supply_v3 / 100
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pool_out(pool_floor_v3, short, 1, genesis_datum())],
    ),
  )
}

test mint_rejects_no_pool_output() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pk_out(#"22222222", 2_000_000)],
    ),
  )
}

test mint_rejects_two_nft_carrying_outputs() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [good_pool(), good_pool()],
    ),
  )
}

// ── THE INVERTED v2 TEST ──────────────────────────────────────────────────────
//
// v2's `mint_accepts_pool_seeded_with_extra_ada`
// (contracts/cardano/validators/minting_policy.ak:270) ACCEPTS a launch seeded
// with 50 ADA as long as the datum agrees. Under v3's calibration that creator
// would have launched at 8,000 + 50×(pricing effect) FDV with 50 ADA of "raise"
// they contributed themselves and can sell back down the curve. In v3 it is a
// REJECT, and the two cases below are the same tx v2 accepted.

test mint_rejects_pool_seeded_with_extra_ada() fail {
  // 50 ADA of genesis liquidity, datum honestly reporting it as reserve
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pool_out(50_000_000, total_supply_v3, 1, g_ada(40_000_000))],
    ),
  )
}

test mint_rejects_extra_ada_hidden_from_the_datum() fail {
  // …and hiding it in the value instead does not work either: the pool's
  // lovelace must be EXACTLY the floor
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pool_out(50_000_000, total_supply_v3, 1, genesis_datum())],
    ),
  )
}

test mint_rejects_short_of_the_pool_floor() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pool_out(pool_floor_v3 - 1, total_supply_v3, 1, genesis_datum())],
    ),
  )
}

test mint_rejects_nonzero_genesis_ada_reserve() fail {
  launch_with_datum(g_ada(1))
}

// ── The pool ADDRESS is pinned (the v2 circular-dependency hole) ──────────────

test mint_rejects_pool_at_the_wrong_script() fail {
  let v =
    assets.from_lovelace(pool_floor_v3)
      |> assets.add(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, pool_nft_name, 1)
  let wrong =
    script_out(
      #"9999999999999999999999999999999999999999999999999999999a",
      v,
      genesis_datum(),
    )
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(mp_seed(), launch_mint(total_supply_v3, 1), [wrong]),
  )
}

test mint_rejects_pool_at_a_delegated_address() fail {
  // a stake credential attached at launch is kept for the life of the pool and
  // earns rewards on up to ~16,717 ADA of buyers' money
  let v =
    assets.from_lovelace(pool_floor_v3)
      |> assets.add(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, pool_nft_name, 1)
  let staked =
    script_out_staked(
      mp_pool,
      #"5555555555555555555555555555555555555555555555555555555a",
      v,
      genesis_datum(),
    )
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(mp_seed(), launch_mint(total_supply_v3, 1), [staked]),
  )
}

// ── Genesis datum field pinning ───────────────────────────────────────────────

test mint_rejects_datum_naming_a_foreign_policy() fail {
  launch_with_datum(g_policy(#"deadbeef"))
}

test mint_rejects_datum_naming_a_foreign_asset() fail {
  launch_with_datum(g_name(#"42414441"))
}

test mint_rejects_wrong_genesis_token_reserve() fail {
  // the REAL supply is right but the VIRTUAL reserve is understated, which would
  // make the pool price as if the offset were smaller and let the curve oversell
  launch_with_datum(g_tok(total_supply_v3))
}

test mint_rejects_creator_fee_bps_off_schedule() fail {
  launch_with_datum(g_cbps(200))
}

// ██ `mint_rejects_zeroed_platform_fee_bps` WAS DELETED HERE — IT INVERTED. ██
//
// It asserted that a genesis datum naming `platform_fee_bps = 0` is REJECTED,
// because that was "a creator building their own launch tx paying LumpFun
// nothing, forever". Since 2026-07-26 the cohort's own `platform_fee_bps_v3` IS
// 0 — the platform take is entirely the flat fee — so that datum is now CORRECT
// and `pool_seeded` accepts it. Keeping the test would have asserted the opposite
// of the contract.
//
// THE DEFENCE IT PROVIDED DID NOT DISAPPEAR, IT MOVED. With a zero bps rate, the
// flat component is the whole platform fee, so `mint_rejects_zeroed_platform_fee_flat`
// below is now the entire genesis-side protection of LumpFun's revenue — and
// `fee_schedule_ok`'s `platform_fee_flat >= platform_fee_flat_v3` is its
// spend-time counterpart. Read those two as the pair.

/// The pin still binds in the OTHER direction: `pool_seeded` compares
/// `platform_fee_bps == platform_fee_bps_v3` by EQUALITY, so a launcher cannot
/// invent a percentage rate the cohort does not have — in either direction.
test mint_rejects_a_nonzero_platform_fee_bps() fail {
  launch_with_datum(g_pbps(50))
}

/// ██ THE ONE THAT NOW GUARDS THE WHOLE PLATFORM FEE. ██ Zeroing the flat
/// component is the only remaining way a self-built launch could pay LumpFun
/// nothing for the life of the token.
test mint_rejects_zeroed_platform_fee_flat() fail {
  launch_with_datum(g_pflat(0))
}

// ── Length assertions the soft-cast does NOT make ─────────────────────────────

test mint_rejects_short_royalty_key() fail {
  // 31 bytes. The length is asserted because a raw ed25519 key IS 32 bytes and
  // because the field's whole value is being an immutable pre-price creator
  // commitment — a wrong-length one is a commitment to nothing. It is NOT asserted
  // because "Splash's indexer requires exactly 32", which is what this comment used
  // to say; that venue is parked. See `pool_types.royalty_pub_key`.
  launch_with_datum(
    g_royalty(#"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"),
  )
}

test mint_rejects_long_royalty_key() fail {
  launch_with_datum(
    g_royalty(
      #"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
    ),
  )
}

test mint_rejects_empty_royalty_key() fail {
  launch_with_datum(g_royalty(#""))
}

test mint_rejects_short_creator_pkh() fail {
  launch_with_datum(g_creator(#"c1c1c1c1"))
}

test mint_rejects_short_treasury_pkh() fail {
  launch_with_datum(g_treasury(#"7a7a7a7a"))
}

/// One output would satisfy both existential fee checks in lump_pool_v3.
///
/// Note the direction: the CREATOR is moved onto the treasury key, not the other
/// way round. Moving the treasury would now also trip
/// `treasury_pkh == treasury_pkh_v3`, and the test would stop isolating the
/// inequality it is named for.
test mint_rejects_creator_equal_to_treasury() fail {
  launch_with_datum(g_creator(mp_treasury))
}

// ── The treasury is pinned to the cohort constant ─────────────────────────────

/// ██ THE LAUNCHER-CONTROLLED TREASURY, REFUSED. ██
///
/// The exact inverse of the confirmed exploit: build your own launch transaction
/// (the policy is permissionless — nothing requires a LumpFun signature) with
/// `treasury_pkh` set to a second key you own. `creator_pkh != treasury_pkh` is
/// satisfied because the two keys are genuinely different, every length assertion
/// passes, the fee RATES are exactly on schedule — and before the pin, this
/// launched a token that paid LumpFun nothing for its entire life.
test mint_rejects_a_foreign_treasury_pkh() fail {
  launch_with_datum(g_treasury(mp_foreign_treasury))
}

/// The same, spelled with an obviously-attacker-shaped key, because the exploit
/// as reported used a placeholder like this and it should be a named test.
test mint_rejects_an_attacker_supplied_treasury_pkh() fail {
  launch_with_datum(
    g_treasury(#"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
  )
}

// ── Neither fee recipient may be the pool script itself ───────────────────────

/// ██ THE POOL AS ITS OWN TREASURY, REFUSED AT GENESIS. ██
///
/// `mp_pool` is 28 bytes, so the length assertion passes and the datum looks
/// entirely well-formed. Before this check the pool's own continuation output
/// satisfied `platform_fee_paid` on every trade forever with no fee output in the
/// transaction at all.
test mint_rejects_treasury_pkh_equal_to_the_pool_script_hash() fail {
  launch_with_datum(g_treasury(mp_pool))
}

/// The creator half — the one that survives pinning the treasury.
test mint_rejects_creator_pkh_equal_to_the_pool_script_hash() fail {
  launch_with_datum(g_creator(mp_pool))
}

// ── The genesis pool value shape, and no reference script ─────────────────────

/// A foreign asset seated in the genesis pool. The first buyer would have swept
/// it as free profit; more to the point, the pool's value shape is supposed to be
/// exactly three entries from birth.
test mint_rejects_junk_assets_in_the_genesis_pool() fail {
  let v =
    assets.from_lovelace(pool_floor_v3)
      |> assets.add(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, pool_nft_name, 1)
      |> assets.add(
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          #"4a554e4b",
          1,
        )
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [script_out(mp_pool, v, genesis_datum())],
    ),
  )
}

/// A FOREIGN policy's asset named `pool_nft_name` in the genesis pool. The
/// carrier filter keys on (this policy, this name), so the decoy passed the
/// carrier count and rode along in the value.
test mint_rejects_a_foreign_pool_nft_in_the_genesis_pool() fail {
  let v =
    assets.from_lovelace(pool_floor_v3)
      |> assets.add(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, pool_nft_name, 1)
      |> assets.add(
          #"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          pool_nft_name,
          1,
        )
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [script_out(mp_pool, v, genesis_datum())],
    ),
  )
}

/// A reference script attached to the pool output at genesis. Under Conway's
/// reference-script fee tiers every trader who spends the pool pays for it, for
/// the life of the curve.
test mint_rejects_a_reference_script_on_the_pool_output() fail {
  let v =
    assets.from_lovelace(pool_floor_v3)
      |> assets.add(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, pool_nft_name, 1)
  let with_ref =
    Output {
      address: address.from_script(mp_pool),
      value: v,
      datum: InlineDatum(genesis_datum()),
      reference_script: Some(
        #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ),
    }
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(mp_seed(), launch_mint(total_supply_v3, 1), [with_ref]),
  )
}

/// A pool output whose datum is a DATUM HASH rather than inline — the `_ -> False`
/// arm of `datum_ok`, previously untested.
test mint_rejects_a_non_inline_pool_datum() fail {
  let v =
    assets.from_lovelace(pool_floor_v3)
      |> assets.add(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, pool_nft_name, 1)
  let hashed =
    Output {
      address: address.from_script(mp_pool),
      value: v,
      datum: transaction.DatumHash(
        #"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      ),
      reference_script: None,
    }
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(mp_seed(), launch_mint(total_supply_v3, 1), [hashed]),
  )
}

/// A two-entry Launch mint where NEITHER name is `pool_nft_name` — the inner
/// `else False` of `supply_ok`, previously untested.
test mint_rejects_two_assets_neither_being_the_pool_nft() fail {
  let minted =
    assets.from_asset(mp_policy, mp_name, total_supply_v3)
      |> assets.add(mp_policy, #"4558545241", 1)
  mint_call(mp_seed(), Launch, mint_tx(mp_seed(), minted))
}

// ── `mode` is pinned to Bootstrap at genesis ──────────────────────────────────

/// ██ A LAUNCH THAT CLAIMS TO BE ALREADY GRADUATED, REFUSED. ██
///
/// Every other field is canonical: the 2.5 ADA floor, 100% of supply, correct pool
/// address, correct fee schedule, correct treasury, well-formed keys. Only `mode`
/// says `Amm`.
///
/// Without the pin this launches a pool that is UNSPENDABLE FOREVER holding 100%
/// of a token's supply. `lump_pool_v3`'s Amm value invariant is
/// `quantity_of(value) == token_reserve` with no offset, and this datum pairs
/// `token_reserve = virtual_token_v3 = 1,142,857,143` with a real balance of
/// `total_supply_v3 = 1,000,000,000`. The gap is exactly `token_offset_v3`, so
/// `in_consistent` fails on EVERY subsequent spend of that UTxO — `AmmBuy`,
/// `AmmSell`, and `Buy`/`Sell` too (they reject the mode). Nothing can move it.
/// The creator's ADA is not at risk because no ADA has been raised yet; the
/// token's entire supply is, permanently, from one wrong field.
test mint_rejects_a_launch_claiming_amm_mode() fail {
  launch_with_datum(g_mode(Amm))
}

/// The control: the SAME datum with `mode = Bootstrap` is the canonical launch and
/// is accepted. Without this, `mint_rejects_a_launch_claiming_amm_mode` could be
/// passing because `g_mode` is malformed in some other way.
test mint_accepts_the_explicit_bootstrap_mode() {
  launch_with_datum(g_mode(Bootstrap))
}

// ══════════════════════════════════════════════════════════════════════════════
// ██ THE GENESIS BUY — v3.1                                                   ██
// ══════════════════════════════════════════════════════════════════════════════
//
// The launch may carry the creator's first buy. These vectors hold it to exactly
// `validate_buy`'s terms at the genesis state, so there is no cheaper first
// token here than a separate Buy would have produced.
//
// THE EXPECTED QUANTITIES ARE LITERALS, NOT CALLS TO `quote_buy`. Computing the
// fixture with the same function the validator uses would make every accept test
// tautological — it would pass against a `quote_buy` broken in any way that is
// self-consistent. `genesis_buy_fixture_matches_quote_buy` is the ONE place the
// two are tied together, deliberately and visibly.

/// 100 ADA of first buy, and what the opening curve owes for it.
const gb_ada_in: Int = 100_000_000

const gb_tokens_out: Int = 12_364_761

/// `virtual_token_v3 - gb_tokens_out`.
const gb_new_tok: Int = 1_130_492_382

/// Fees on 100 ADA at this cohort: flat 2 ADA platform, 1% creator.
const gb_platform_fee: Int = 2_000_000

const gb_creator_fee: Int = 1_000_000

/// The one place the literals above are tied to the arithmetic. If `quote_buy`
/// or any curve constant moves, this fails and every vector below has to be
/// re-derived deliberately rather than silently tracking the change.
test genesis_buy_fixture_matches_quote_buy() {
  and {
    gb_tokens_out == quote_buy(0, virtual_token_v3, gb_ada_in),
    gb_new_tok == virtual_token_v3 - gb_tokens_out,
    gb_platform_fee == platform_fee_flat_v3,
    gb_creator_fee == gb_ada_in * creator_fee_bps_v3 / 10_000,
  }
}

fn gb_datum(ada_reserve: Int, token_reserve: Int) -> PoolDatum {
  gd(
    mp_policy,
    mp_name,
    ada_reserve,
    token_reserve,
    mp_creator,
    mp_treasury,
    creator_fee_bps_v3,
    platform_fee_bps_v3,
    platform_fee_flat_v3,
    mp_royalty,
    Bootstrap,
  )
}

/// A launch carrying a first buy. Every argument is separately mutable so each
/// reject below moves exactly one thing.
fn genesis_buy_call(
  ada_in: Int,
  tokens_out: Int,
  datum_ada: Int,
  datum_tok: Int,
  platform: Int,
  creator: Int,
) -> Bool {
  let pool =
    pool_out(
      pool_floor_v3 + ada_in,
      total_supply_v3 - tokens_out,
      1,
      gb_datum(datum_ada, datum_tok),
    )
  let outs =
    when (platform > 0, creator > 0) is {
      (True, True) ->
        [pool, pk_out(mp_treasury, platform), pk_out(mp_creator, creator)]
      (True, False) -> [pool, pk_out(mp_treasury, platform)]
      (False, True) -> [pool, pk_out(mp_creator, creator)]
      (False, False) -> [pool]
    }
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(mp_seed(), launch_mint(total_supply_v3, 1), outs),
  )
}

/// The canonical genesis buy: reserve, supply, datum and both fees all agree.
test mint_accepts_a_genesis_buy() {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    gb_ada_in,
    gb_new_tok,
    gb_platform_fee,
    gb_creator_fee,
  )
}

/// ONE token more than the curve owes. This is the whole reason `tokens_out` is
/// recomputed rather than read: without it a launcher writes their own price.
test mint_rejects_a_genesis_buy_taking_one_extra_token() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out + 1,
    gb_ada_in,
    gb_new_tok - 1,
    gb_platform_fee,
    gb_creator_fee,
  )
}

/// One token FEWER is refused too. The quote is an equality, not a ceiling — a
/// launch that under-takes would leave the datum disagreeing with the value and
/// every later trade rebuilding from a reserve the pool does not hold.
test mint_rejects_a_genesis_buy_taking_one_token_fewer() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out - 1,
    gb_ada_in,
    gb_new_tok + 1,
    gb_platform_fee,
    gb_creator_fee,
  )
}

/// ██ THE v2 DOUBLE-FDV BUG, IN NEW CLOTHES. ██ A creator seats 100 ADA beside
/// the floor and takes NO tokens, hoping the reserve simply counts as raised.
/// `quote_buy` owes 12,364,761 tokens for that ADA, so a zero `tokens_out`
/// cannot match and the launch is refused.
test mint_rejects_seeded_ada_that_buys_nothing() fail {
  genesis_buy_call(
    gb_ada_in,
    0,
    gb_ada_in,
    virtual_token_v3,
    gb_platform_fee,
    gb_creator_fee,
  )
}

/// The mirror: tokens leaving the pool for NO ada. `ada_in == 0` is the plain
/// launch branch and it requires `tokens_out == 0`.
test mint_rejects_free_tokens_at_genesis() fail {
  genesis_buy_call(0, gb_tokens_out, 0, gb_new_tok, 0, 0)
}

/// The datum must state the position the OUTPUT holds. Understating the reserve
/// while banking the ADA would open the curve below its own price.
test mint_rejects_a_genesis_buy_whose_datum_understates_the_reserve() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    0,
    gb_new_tok,
    gb_platform_fee,
    gb_creator_fee,
  )
}

/// …and the token side of the same lie.
test mint_rejects_a_genesis_buy_whose_datum_overstates_the_token_reserve() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    gb_ada_in,
    virtual_token_v3,
    gb_platform_fee,
    gb_creator_fee,
  )
}

/// No platform fee. The flat 2 ADA is LumpFun's entire take on a trade, and
/// routing a first buy through genesis must not be a way to avoid it.
test mint_rejects_a_genesis_buy_with_no_platform_fee() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    gb_ada_in,
    gb_new_tok,
    0,
    gb_creator_fee,
  )
}

/// One lovelace short — `pays_at_least` is a bound, and this is the boundary
/// rather than a token gesture at it.
test mint_rejects_a_genesis_buy_underpaying_the_platform_fee_by_one() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    gb_ada_in,
    gb_new_tok,
    gb_platform_fee - 1,
    gb_creator_fee,
  )
}

/// No creator fee. The creator is the one being paid, so the launcher has every
/// incentive to include it — but "the beneficiary would not skip it" is not an
/// on-chain guarantee, and the datum names a fee-accumulator SCRIPT, not them.
test mint_rejects_a_genesis_buy_with_no_creator_fee() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    gb_ada_in,
    gb_new_tok,
    gb_platform_fee,
    0,
  )
}

test mint_rejects_a_genesis_buy_underpaying_the_creator_fee_by_one() fail {
  genesis_buy_call(
    gb_ada_in,
    gb_tokens_out,
    gb_ada_in,
    gb_new_tok,
    gb_platform_fee,
    gb_creator_fee - 1,
  )
}

/// ── cap_ok AT GENESIS ────────────────────────────────────────────────────────
/// A launch may buy right up to the curve's exhaustion point but not past it.
/// The one-shot ceiling lands EXACTLY on `curve_exhausted_token_reserve`, which
/// is legal for the same reason `validate_buy` allows it: the pool is then
/// immediately graduatable, which is a live state and not a stuck one.
test mint_accepts_a_genesis_buy_landing_exactly_on_exhaustion() {
  genesis_buy_call(
    16_717_047_991,
    738_796_125,
    16_717_047_991,
    curve_exhausted_token_reserve,
    platform_fee_flat_v3,
    16_717_047_991 * creator_fee_bps_v3 / 10_000,
  )
}

/// One lovelace more and the curve would close inside its own launch.
test mint_rejects_a_genesis_buy_that_closes_the_curve() fail {
  genesis_buy_call(
    16_717_047_992,
    738_796_126,
    16_717_047_992,
    curve_exhausted_token_reserve - 1,
    platform_fee_flat_v3,
    16_717_047_992 * creator_fee_bps_v3 / 10_000,
  )
}

/// The floor is still exact. A pool one lovelace under it makes `ada_in`
/// negative, and `value_ok` refuses it before anything else runs.
test mint_rejects_a_pool_below_the_floor() fail {
  mint_call(
    mp_seed(),
    Launch,
    mint_tx_out(
      mp_seed(),
      launch_mint(total_supply_v3, 1),
      [pool_out(pool_floor_v3 - 1, total_supply_v3, 1, genesis_datum())],
    ),
  )
}
