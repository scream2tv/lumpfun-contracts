#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# mutverify.sh — prove every fix is BOUND by a test.
#
# For each fix: revert it with a surgical text mutation, run ONLY the tests that
# are supposed to catch it, and require that they FAIL. A fix whose tests still
# pass after the revert is not tested, and the mutation is reported as SURVIVED.
#
# This is the discipline the v2 history demands: 135 green Aiken checks found
# none of v2's real defects, because nothing checked that the guards were bound.
#
# NOTE ON LINE ENDINGS: the .ak files on this Windows mount have CRLF endings, so
# every multi-line perl pattern below uses `\r?\n`. A bare `\n` silently matches
# nothing and the mutation reports SURVIVED for the wrong reason. That happened on
# the first run of this script and is exactly the class of false-green this whole
# exercise exists to catch.
#
# Usage: ./mutverify.sh    (restores the tree from .mutbak on every exit)
# ══════════════════════════════════════════════════════════════════════════════
cd "$(dirname "$0")" || exit 1
AIKEN="$HOME/bin/aiken"
BAK=".mutbak"
LOCK=".mutverify.lock"

# ── ██ THIS SCRIPT REWRITES lib/ AND validators/ IN PLACE. ██ ─────────────────
#
# It snapshots the tree, mutates it, and restores from the snapshot before EVERY
# case. So any edit made to a source file WHILE IT IS RUNNING is silently
# DISCARDED by the next restore — and, worse, an `aiken build` racing it can emit a
# plutus.json compiled from a MUTATED source and a script hash that corresponds to
# no committed code. Both of those happened during the Phase 2 build: a test added
# mid-run vanished with no error anywhere, and the hash gate reported a mismatch
# against bytes nobody wrote.
#
# The lock makes that loud instead of silent. If it trips, the run in progress owns
# the tree: wait for it, or kill it and `cp -r .mutbak/lib .mutbak/validators .`
# to restore by hand before doing anything else. NEVER `aiken build` while it runs.
if [ -e "$LOCK" ]; then
  echo "REFUSING TO RUN: $LOCK exists (pid $(cat "$LOCK" 2>/dev/null))."
  echo "  Another mutverify.sh owns lib/ and validators/, or a previous run was"
  echo "  killed mid-mutation. If no run is active, VERIFY THE TREE FIRST:"
  echo "      diff -r .mutbak/lib lib && diff -r .mutbak/validators validators"
  echo "  then remove $LOCK. Do not edit sources or build while it is held."
  exit 2
fi
echo $$ > "$LOCK"

rm -rf "$BAK"; mkdir -p "$BAK"
cp -r lib validators "$BAK"/
restore() { rm -rf lib validators; cp -r "$BAK"/lib "$BAK"/validators .; }
cleanup() { restore; rm -f "$LOCK"; }
# INT/TERM as well as EXIT: a bare `trap restore EXIT` does not fire on SIGKILL, and
# a run killed from outside leaves the tree mutated with no warning.
trap cleanup EXIT INT TERM

pass=0; fail=0

# run_case <label> <test-match> <FAILS|PASSES> <perl-script> <file>...
run_case() {
  local label="$1" match="$2" expect="$3" sedscript="$4"; shift 4
  restore
  local before after
  before=$(cat "$@" | md5sum)
  for f in "$@"; do
    perl -0777 -pi -e "$sedscript" "$f" || { echo "  MUTATE-ERROR    $label"; fail=$((fail+1)); return; }
  done
  after=$(cat "$@" | md5sum)
  if [ "$before" = "$after" ]; then
    # ONE RETRY, for the same DRVFS reason as the compile path below: the v31 run
    # hit 'cp: Cannot allocate memory' during a restore, the tree was briefly
    # missing, and two perfectly good patterns were reported as PATTERN-NO-OP
    # (cat of a missing file hashes the same empty input twice). A genuinely
    # stale pattern is deterministic and no-ops on the retry too.
    restore
    before=$(cat "$@" | md5sum)
    for f in "$@"; do
      perl -0777 -pi -e "$sedscript" "$f" >/dev/null 2>&1
    done
    after=$(cat "$@" | md5sum)
    if [ "$before" = "$after" ]; then
      echo "  PATTERN-NO-OP   $label   <<< the mutation changed nothing"
      fail=$((fail+1)); return
    fi
  fi

  # ══════════════════════════════════════════════════════════════════════════
  # COMPILE DETECTION — MEASURED, NOT GUESSED. TWO WRONG VERSIONS PRECEDED IT.
  # ══════════════════════════════════════════════════════════════════════════
  #
  # WRONG VERSION 1 was `grep -qE "Error|error:"` over the whole log. It is a
  # latent false-positive generator: Aiken's help text for an ordinary
  # unused-variable WARNING contains "They will not produce any side-effect (such
  # as error calls)", and most `let x = <guard>` -> `let x = True` mutations leave
  # something unused. It survived because that sentence has no capital E and no
  # colon — but it is one wording change away from flagging every such mutation.
  #
  # WRONG VERSION 2 read the error count out of Aiken's `Summary` line. That is
  # WORSE, and it failed loudly on the first case: ██ AIKEN COUNTS A FAILING TEST
  # AS AN "error" IN THAT LINE. ██ Measured on this project, 2026-07-26:
  #
  #   compiles, `fail` test stops failing   Summary 1 check, 1 error, 1 warning
  #   compiles, ACCEPT test breaks          Summary 1 check, 1 error, 0 warnings
  #   DOES NOT COMPILE                      Summary          1 error, 0 warnings
  #   clean                                 Summary 1 check, 0 errors, 0 warnings
  #
  # So the error count cannot distinguish "did not compile" from "the mutation was
  # KILLED" — which is the one distinction this function exists to make. Reading it
  # turned every kill into a COMPILE-ERROR.
  #
  # WRONG VERSION 3 was `grep -q '×'`. That is ALSO wrong, and it was measured
  # failing too: `×` is not exclusively an error marker. Aiken uses it as the BULLET
  # in the clause-by-clause breakdown it prints when an `and { … }` test fails —
  #
  #     │ FAIL [mem: 8350, cpu: 2277465] pool_mode_wire_shape
  #     │ × expected
  #     │ │ False
  #     │ × and
  #     │ │ True
  #     │ × to all be true
  #
  # — so every KILL of a multi-clause pure-function test emits five or six of them.
  # Most tests in `pool_types`, `math_v3` and `params_v3` are exactly that shape.
  #
  # THE ACTUAL DISCRIMINATOR, measured across all seven reachable shapes:
  #
  #                                          "N tests |" lines     "×" count
  #   compiles, `fail` test stops failing           1                  0
  #   compiles, ACCEPT test breaks (single Bool)    1                  0
  #   compiles, `and { }` test fails                1                  5
  #   compiles, `fail` test passes via a crash      1                  0
  #   clean                                         1                  0
  #   DOES NOT COMPILE                              0                  1
  #   pattern matches no test                       0                  0
  #
  # ONLY the per-module "N tests |" line separates them: Aiken prints it whenever it
  # RAN tests, and never when compilation stopped first. `×` is then just the tie-
  # break between "did not compile" and "matched nothing", both of which have no
  # such line. No prose, no error counts, no marker overloading.
  #
  # ONE RETRY on the compile path, because the tree lives on a Windows DRVFS mount:
  # `restore` does `rm -rf lib validators; cp -r ...` of ~5,000 lines and then
  # compiles immediately, and a WSL service blip mid-run (one was observed during
  # this very session, and it produced exactly one spurious COMPILE-ERROR under
  # version 1) can leave a short read behind. A genuine compile error is
  # deterministic and survives the retry; a filesystem flake does not.
  local attempt=1
  while :; do
    script -qfec "NO_COLOR=1 $AIKEN check -m '$match'" /tmp/mv.log >/dev/null 2>&1
    sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' /tmp/mv.log > /tmp/mv.clean
    # Ran tests at all? Then it compiled, whatever else the log says.
    grep -qE '[0-9]+ tests \|' /tmp/mv.clean && break
    # No tests ran. A `×` diagnostic means compilation stopped; no `×` means the
    # pattern simply matched nothing, which the ntests check below reports.
    grep -q '×' /tmp/mv.clean || break
    if [ "$attempt" = "2" ]; then
      echo "  COMPILE-ERROR   $label   (mutation did not compile, twice)"
      fail=$((fail+1)); return
    fi
    attempt=2
    # re-apply from the snapshot in case the first copy was short
    restore
    for f in "$@"; do
      perl -0777 -pi -e "$sedscript" "$f" >/dev/null 2>&1
    done
  done

  # SUM the per-module summary lines. `tail -1` was WRONG and it produced a FALSE
  # SURVIVED: `aiken check -m <pat>` prints one "N tests | N passed | N failed"
  # line PER MODULE, so as soon as a pattern matched tests in two modules the
  # parser read the LAST module's count and ignored the one that actually failed.
  # That is exactly what happened to the `wire_shape` case once splash_v3.ak
  # arrived with a second test whose name contains that substring: the mutation was
  # being KILLED (v3_datum_wire_shape_is_constr_one_with_ten_fields failed) while
  # this script reported "SURVIVED <<< FIX IS NOT BOUND". A harness that
  # under-reports kills is worse than no harness, because it invites deleting the
  # guard it just failed to credit.
  local nfailed ntests
  nfailed=$(grep -oE "[0-9]+ failed" /tmp/mv.clean | grep -oE "^[0-9]+" \
            | awk '{s+=$1} END {print s+0}')
  ntests=$(grep -oE "[0-9]+ tests" /tmp/mv.clean | grep -oE "^[0-9]+" \
           | awk '{s+=$1} END {print s+0}')
  [ -z "$nfailed" ] && nfailed=0
  [ -z "$ntests" ] && ntests=0

  if [ "$ntests" = "0" ]; then
    echo "  NO-TESTS-MATCHED $label  (pattern '$match')"
    fail=$((fail+1)); return
  fi

  if [ "$expect" = "FAILS" ]; then
    if [ "$nfailed" -gt 0 ]; then
      echo "  KILLED    $label  ($nfailed/$ntests failed under mutation)"
      pass=$((pass+1))
    else
      echo "  SURVIVED  $label  ($ntests tests, none failed) <<< FIX IS NOT BOUND"
      fail=$((fail+1))
    fi
  else
    if [ "$nfailed" = "0" ]; then
      echo "  OK        $label  ($ntests still pass, as expected)"
      pass=$((pass+1))
    else
      echo "  UNEXPECTED $label  ($nfailed failed but should have passed)"
      fail=$((fail+1))
    fi
  fi
}

echo "── fees_v3: pays_at_least pool-address exclusion ─────────────────────────"
run_case "pays_at_least drops the pool exclusion (creator half, isolated)" \
  "buy_rejects_the_pool_paying_its_own_creator_fee" FAILS \
  's/h != pool_hash && h == pkh/h == pkh/' lib/lumpfun/fees_v3.ak

run_case "pays_at_least drops the exclusion + treasury pin (platform half, both branches)" \
  "rejects_the_pool_paying_its_own_platform_fee" FAILS \
  's/h != pool_hash && h == pkh/h == pkh/; s/treasury_pkh == treasury_pkh_v3/True/' \
  lib/lumpfun/fees_v3.ak validators/lump_pool.ak

echo
echo "── lump_pool: fee_schedule_ok (self-seeded / counterfeit pools) ──────────"
run_case "treasury not pinned at spend time" \
  "buy_rejects_a_pool_whose_datum_names_a_foreign_treasury" FAILS \
  's/treasury_pkh == treasury_pkh_v3/True/' validators/lump_pool.ak

run_case "platform bps + flat floors removed" \
  "buy_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  's/platform_fee_bps >= platform_fee_bps_v3/True/; s/platform_fee_flat >= platform_fee_flat_v3/True/; s/treasury_pkh == treasury_pkh_v3/True/' \
  validators/lump_pool.ak

run_case "bps range bounds removed" \
  "buy_rejects_a_negative_creator_fee_bps" FAILS \
  's/creator_fee_bps >= 0,/True,/' validators/lump_pool.ak

echo
echo "── lump_pool: value_shape_ok (junk assets in the continuation) ───────────"
run_case "value_shape_ok removed from both trade branches" \
  "rejects_extra_assets_in_the_continuation" FAILS \
  's/value_shape_ok\(own_output\.value\),/True,/g' validators/lump_pool.ak

echo
echo "── lump_pool: no_policy_mint (mid-curve mint or burn) ────────────────────"
run_case "no_policy_mint removed from both trade branches" \
  "mid_curve" FAILS \
  's/no_policy_mint\(tx, policy_id\),/True,/g' validators/lump_pool.ak

echo
echo "── lump_pool: sell-branch cap_ok (token_reserve above X_c) ───────────────"
run_case "sell cap_ok removed" \
  "sell_rejects_pushing_the_reserve_above_the_virtual_token_cap" FAILS \
  's/let cap_ok = new_tok <= virtual_token_v3/let cap_ok = True/' \
  validators/lump_pool.ak

echo
# ── ██ THE min_trade_ada_v3 CASES ARE DELETED, NOT BROKEN. ██ ─────────────────
# Six cases here used to re-introduce the deleted minimum-trade guard (three
# `SELL_AND` sell-side restorations, two AmmBuy `size_ok` mutations, and one
# AmmSell-gains-a-minimum). `min_trade_ada_v3` was DELETED from `params_v3` on
# 2026-07-26, so those mutations either no longer compile (the constant is gone)
# or pattern-match code that no longer exists — v31 reported them as
# COMPILE-ERROR / PATTERN-NO-OP. The behaviour they guarded is now bound by the
# ACCEPT tests directly: `sell_accepts_a_partial_exit_from_a_sub_minimum_reserve`,
# `sell_accepts_a_full_drain_from_a_sub_minimum_reserve`,
# `sell_accepts_gross_just_under_the_old_minimum`,
# `amm_buy_accepts_one_lovelace_under_the_old_minimum`,
# `closing_buy_accepts_stopping_one_token_short_of_the_close` and
# `amm_sell_accepts_a_dust_sell_with_no_minimum` — any re-introduced minimum
# breaks them at `aiken check` time, with no mutation needed.
echo "── lump_pool: tokens_in_positive is now genuinely bound ──────────────────"
run_case "sell tokens_in_positive removed" \
  "sell_rejects_zero_tokens_in_isolated" FAILS \
  's/^    tokens_in_positive,\r?$/    True,/m' validators/lump_pool.ak

echo
echo "── lump_pool: open_ok + ada_in_positive on an already-closed curve ───────"
run_case "buy open_ok AND ada_in_positive both removed" \
  "buy_rejects_zero_ada_in_on_a_closed_curve" FAILS \
  's/let open_ok = curve_open\(old_tok\)/let open_ok = True/; s/let ada_in_positive = ada_in > 0/let ada_in_positive = True/' \
  validators/lump_pool.ak

run_case "buy open_ok alone (the PAIR binds; this must survive)" \
  "buy_rejects_zero_ada_in_on_a_closed_curve" PASSES \
  's/let open_ok = curve_open\(old_tok\)/let open_ok = True/' \
  validators/lump_pool.ak

echo
echo "── lump_pool: the CORRECTED closed-curve buy test binds open_ok+cap_ok ───"
run_case "buy open_ok AND cap_ok both removed" \
  "cap_rejects_buying_from_an_already_closed_curve" FAILS \
  's/let open_ok = curve_open\(old_tok\)/let open_ok = True/; s/let cap_ok = new_tok >= curve_exhausted_token_reserve/let cap_ok = True/' \
  validators/lump_pool.ak

echo
echo "══ PHASE 3 — MODE, GRADUATE (in place) and the PERMANENT AMM ══════════════"
echo "   REJECT tests: FAILS means the mutation made the validator ACCEPT a"
echo "   transaction it must refuse — i.e. the guard WAS the only thing rejecting"
echo "   it, so the guard is bound. PASSES means another guard also covers that"
echo "   case; where that is the design, the label says so."
echo
echo "   ── ON THE COUNTING SUBSTITUTIONS ──────────────────────────────────────"
echo "   Five branches now share several identical guard lines (\`mode_ok\`,"
echo "   \`with_reserves(...) == new_d\`, \`continuation_address_exact\`,"
echo "   \`value_shape_ok\`, \`pool_nft_kept\`, \`slippage_ok\`). A plain s/// would"
echo "   silently patch only the FIRST and the case would credit the wrong branch."
echo "   Every per-branch mutation below therefore uses perl's /ge with a counter"
echo "   and names the occurrence index. File order is:"
echo "     1 validate_buy   2 validate_sell   3 validate_graduate"
echo "     4 validate_amm_buy   5 validate_amm_sell"
echo "   A PATTERN-NO-OP or a wrong-branch credit shows up as NO-TESTS-MATCHED or"
echo "   an unexpected PASSES, so a stale index cannot pass quietly."

# ── Per-branch mode_ok neuters, by occurrence index ──────────────────────────
MODE_BOOT_BUY='my $i=0; s/(let mode_ok = mode == Bootstrap)/++$i == 1 ? "let mode_ok = True" : $1/ge'
MODE_BOOT_SELL='my $i=0; s/(let mode_ok = mode == Bootstrap)/++$i == 2 ? "let mode_ok = True" : $1/ge'
MODE_BOOT_GRAD='my $i=0; s/(let mode_ok = mode == Bootstrap)/++$i == 3 ? "let mode_ok = True" : $1/ge'
MODE_AMM_BUY='my $i=0; s/(let mode_ok = mode == Amm)/++$i == 1 ? "let mode_ok = True" : $1/ge'
MODE_AMM_SELL='my $i=0; s/(let mode_ok = mode == Amm)/++$i == 2 ? "let mode_ok = True" : $1/ge'

echo
echo "── ██ THE FOUR CROSS-MODE REJECTS. ██ ────────────────────────────────────"
echo "   Each mutation removes ONE branch's mode guard and nothing else. Every"
echo "   other guard on that branch passes on the test transaction, so a KILL here"
echo "   means the mode guard is the sole thing standing between the two halves of"
echo "   a pool's life. Two of the four are thefts:"
echo "     AmmBuy on Bootstrap  515,090,543 vs 92,452,149 tokens  (5.571x)"
echo "     Sell   on Amm        773,501,488 vs 393,502,173 lovelace (1.966x)"

run_case "validate_buy mode_ok removed — a Buy priced on an AMM pool is accepted" \
  "buy_rejects_an_amm_mode_pool" FAILS \
  "$MODE_BOOT_BUY" validators/lump_pool.ak

run_case "validate_sell mode_ok removed — THE DRAIN: 1.966x gross out of an AMM pool" \
  "sell_rejects_an_amm_mode_pool" FAILS \
  "$MODE_BOOT_SELL" validators/lump_pool.ak

run_case "validate_amm_buy mode_ok removed — THE THEFT: 51.5% of supply for 1,000 ADA" \
  "amm_buy_rejects_a_bootstrap_mode_pool" FAILS \
  "$MODE_AMM_BUY" validators/lump_pool.ak

run_case "validate_amm_sell mode_ok removed — a seller paid 17.9% of what is owed" \
  "amm_sell_rejects_a_bootstrap_mode_pool" FAILS \
  "$MODE_AMM_SELL" validators/lump_pool.ak

echo
echo "   ...and each mutation is scoped to ITS OWN branch: removing the buy-side"
echo "   guard must NOT make the amm-side reject pass, or the four cases above"
echo "   would be crediting one shared guard four times."
run_case "  validate_buy mode_ok removed — the AmmBuy cross-mode reject is unaffected" \
  "amm_buy_rejects_a_bootstrap_mode_pool" PASSES \
  "$MODE_BOOT_BUY" validators/lump_pool.ak

run_case "  validate_amm_buy mode_ok removed — the Buy cross-mode reject is unaffected" \
  "buy_rejects_an_amm_mode_pool" PASSES \
  "$MODE_AMM_BUY" validators/lump_pool.ak

echo
echo "── ██ MODE MONOTONICITY, HALF ONE: a graduated pool cannot re-graduate. ██"
echo "   The reachable state is an AMM pool with exactly 142,857,143 tokens sold"
echo "   into it, whose token_reserve is then EXACTLY curve_exhausted_token_reserve"
echo "   — so G0 passes, G3's bag identity passes, with_graduation is a FIXED POINT"
echo "   so the datum equality passes, and the value equality passes. The flip"
echo "   would skim 142,857,143 tokens (14.29% of supply) and release a second"
echo "   10 ADA bounty out of a reserve that has no floor beside it."
run_case "validate_graduate mode_ok removed — an AMM pool at 404,061,018 re-graduates" \
  "graduate_rejects_regraduating_an_amm_pool" FAILS \
  "$MODE_BOOT_GRAD" validators/lump_pool.ak

run_case "  ...and on a FRESH amm pool G0 also fires, so that one must survive" \
  "graduate_rejects_regraduating_a_fresh_amm_pool" PASSES \
  "$MODE_BOOT_GRAD" validators/lump_pool.ak

echo
echo "── ██ MODE MONOTONICITY, HALF TWO: Amm can never return to Bootstrap. ██ ──"
echo "   Enforced by \`mode\` being in with_reserves' FROZEN set. The mutation puts"
echo "   the WRONG constant in that position — Bootstrap instead of the carried"
echo "   value — which is precisely the direction that permits Amm -> Bootstrap."
WR_MODE_BOOT='s/    royalty_pub_key,\r?\n    mode,\r?\n  \}\r?\n\}\r?\n\r?\n\/\/\/ ══/    royalty_pub_key,\n    mode: Bootstrap,\n  }\n}\n\n\/\/\/ ══/'
run_case "with_reserves writes Bootstrap instead of carrying mode — the flip un-flips" \
  "rejects_flipping_the_mode_back_to_bootstrap" FAILS \
  "$WR_MODE_BOOT" lib/lumpfun/pool_types.ak

run_case "  ...the same edit ALSO breaks every AMM accept, so the field is read" \
  "amm_buy_accepts_the_canonical_trade" FAILS \
  "$WR_MODE_BOOT" lib/lumpfun/pool_types.ak

echo
echo "── PoolMode's WIRE ORDER — the latch's encoding ───────────────────────────"
echo "   Bootstrap MUST be Constr(0,[]) and Amm Constr(1,[]). Swap them and every"
echo "   already-deployed Bootstrap pool decodes as graduated."
run_case "PoolMode constructors swapped" \
  "pool_mode_wire_shape" FAILS \
  's/pub type PoolMode \{\r?\n  Bootstrap\r?\n  Amm\r?\n\}/pub type PoolMode {\n  Amm\n  Bootstrap\n}/' \
  lib/lumpfun/pool_types.ak

echo
echo "══ ██ THE token_reserve REBASE. 404,061,018 (VIRTUAL) -> 261,203,875 (REAL) ██"
echo "   with_graduation hardcodes the target, so the mutation is a wrong constant"
echo "   in that one position. The 404,061,018 case is the 'forgot to rebase' bug:"
echo "   the pool would claim 1.547x the tokens it holds, fail in_consistent on"
echo "   every subsequent spend, and be unspendable with 16,717 ADA inside it."
REBASE_KEEP='s/    token_reserve: pool_bag_v3,/    token_reserve: 404_061_018,/'
REBASE_OFF_BY_ONE='s/    token_reserve: pool_bag_v3,/    token_reserve: pool_bag_v3 + 1,/'

run_case "with_graduation keeps the VIRTUAL reserve (404,061,018)" \
  "graduate_rejects_keeping_the_virtual_curve_reserve" FAILS \
  "$REBASE_KEEP" lib/lumpfun/pool_types.ak

run_case "  ...and the canonical graduation then stops being satisfiable at all" \
  "graduate_accepts_the_canonical_two_step_close" FAILS \
  "$REBASE_KEEP" lib/lumpfun/pool_types.ak

run_case "with_graduation rebases to pool_bag_v3 + 1 — ANY other value is refused" \
  "graduate_rejects_a_token_reserve_one_above_the_pool_bag" FAILS \
  "$REBASE_OFF_BY_ONE" lib/lumpfun/pool_types.ak

run_case "  ...and the pure-function contract for the rebase goes red too" \
  "with_graduation_flips_mode_and_rebases_the_token_reserve" FAILS \
  "$REBASE_OFF_BY_ONE" lib/lumpfun/pool_types.ak

echo
echo "   THE FLIP ITSELF: with_graduation's mode target is hardcoded to Amm. Put"
echo "   Bootstrap there and graduation becomes a 10-ADA bounty that changes"
echo "   nothing — bound in the POSITIVE direction, because the accept case is what"
echo "   requires the flip to actually happen."
run_case "with_graduation writes mode: Bootstrap — the flip does not flip" \
  "graduate_accepts" FAILS \
  's/    mode: Amm,/    mode: Bootstrap,/' lib/lumpfun/pool_types.ak

run_case "  ...and the pure-function contract catches it as well" \
  "with_graduation_flips_mode_and_rebases_the_token_reserve" FAILS \
  's/    mode: Amm,/    mode: Bootstrap,/' lib/lumpfun/pool_types.ak

echo
echo "══ GRADUATE — guard by guard ═════════════════════════════════════════════"

echo
echo "── G0 / G3 via graduation_curve_checks ───────────────────────────────────"
GRAD_ARITH='s/  let curve_ok = graduation_curve_checks\(x, token_reserve\)/  let curve_ok = True/'
run_case "curve_ok removed — a LIVE curve is graduable (the C-1 skim, 62.6% of supply)" \
  "graduate_rejects_a_live_curve" FAILS \
  "$GRAD_ARITH" validators/lump_pool.ak

run_case "curve_ok removed — one token short of exhaustion becomes graduable" \
  "graduate_rejects_a_curve_one_token_short_of_exhaustion" FAILS \
  "$GRAD_ARITH" validators/lump_pool.ak

echo
echo "   The x = 0 case is a MATCHED PAIR with value_ok's entry count, because"
echo "   assets.from_lovelace(0) is \`zero\` in stdlib so a zero-reserve"
echo "   continuation loses an ENTRY rather than carrying a zero:"
VALUE_LEN_OFF='s/    own_output\.value == expected_value && value_shape_ok\(own_output\.value\)/    own_output.value == expected_value/'
run_case "  curve_ok alone (value_ok's length still fires: PASSES)" \
  "graduate_rejects_a_zero_ada_reserve_pool" PASSES \
  "$GRAD_ARITH" validators/lump_pool.ak

run_case "  value_ok's length alone (curve_ok still fires: PASSES)" \
  "graduate_rejects_a_zero_ada_reserve_pool" PASSES \
  "$VALUE_LEN_OFF" validators/lump_pool.ak

run_case "  BOTH removed — a zero-reserve pool graduates into a k = 0 AMM" \
  "graduate_rejects_a_zero_ada_reserve_pool" FAILS \
  "$GRAD_ARITH; $VALUE_LEN_OFF" validators/lump_pool.ak

echo
echo "── R-5 on the graduation branch (with_graduation's whole-datum equality) ──"
GRAD_DATUM='s/  let datum_ok = with_graduation\(d\) == new_d/  let datum_ok = True/'
run_case "datum_ok removed — the royalty key is rewritten at the flip" \
  "graduate_rejects_rewriting_the_royalty_pub_key" FAILS \
  "$GRAD_DATUM" validators/lump_pool.ak

run_case "datum_ok removed — the treasury is rewritten at the flip" \
  "graduate_rejects_rewriting_the_treasury_pkh" FAILS \
  "$GRAD_DATUM" validators/lump_pool.ak

run_case "datum_ok removed — the platform fee is rewritten for the pool's whole life" \
  "graduate_rejects_rewriting_the_platform_fee_bps" FAILS \
  "$GRAD_DATUM" validators/lump_pool.ak

run_case "datum_ok removed — the rebase is skipped" \
  "graduate_rejects_keeping_the_virtual_curve_reserve" FAILS \
  "$GRAD_DATUM" validators/lump_pool.ak

run_case "datum_ok removed — ada_reserve is understated in the datum" \
  "graduate_rejects_understating_the_ada_reserve_in_the_datum" FAILS \
  "$GRAD_DATUM" validators/lump_pool.ak

run_case "datum_ok removed — the offset is applied twice" \
  "graduate_rejects_applying_the_token_offset_twice" FAILS \
  "$GRAD_DATUM" validators/lump_pool.ak

echo
echo "── ██ value_ok — THE BOUNTY IS ARITHMETIC, NOT AN ALLOWANCE. ██ ───────────"
echo "   The output's lovelace is an EQUALITY, not a floor. That single '==' is"
echo "   what makes a permissionless graduation safe: the submitter's take is the"
echo "   difference between two pinned figures and cannot be chosen."
VALUE_EQ_OFF='s/    own_output\.value == expected_value && value_shape_ok\(own_output\.value\)/    value_shape_ok(own_output.value)/'
run_case "value_ok's equality removed — the submitter drains HALF THE RESERVE (8,358 ADA)" \
  "graduate_rejects_draining_half_the_reserve_as_bounty" FAILS \
  "$VALUE_EQ_OFF" validators/lump_pool.ak

run_case "value_ok's equality removed — one lovelace more than the bounty" \
  "graduate_rejects_one_lovelace_more_than_the_bounty" FAILS \
  "$VALUE_EQ_OFF" validators/lump_pool.ak

run_case "value_ok's equality removed — the pool floor is kept as a min-UTxO cushion" \
  "graduate_rejects_keeping_the_pool_floor_in_the_pool" FAILS \
  "$VALUE_EQ_OFF" validators/lump_pool.ak

run_case "value_ok's equality removed — the pool bag is skimmed into a wallet (13.1%)" \
  "graduate_rejects_skimming_the_pool_bag_into_a_wallet" FAILS \
  "$VALUE_EQ_OFF" validators/lump_pool.ak

run_case "value_ok's equality removed — the bag is short by one token" \
  "graduate_rejects_the_pool_bag_short_by_one_token" FAILS \
  "$VALUE_EQ_OFF" validators/lump_pool.ak

echo
echo "   ── ██ MEASURED, AND THE FIRST LABEL HERE WAS WRONG. ██ ─────────────────"
echo "   The first version of this section asserted that the whole-Value equality"
echo "   was the load-bearing half for JUNK ASSETS and that the three-entry count"
echo "   was belt-and-braces. mutverify reported SURVIVED and it was right: a"
echo "   fourth asset breaks the equality AND the length, so removing either one"
echo "   alone leaves the other rejecting. They are a MATCHED PAIR for this case."
echo "   The claim is corrected rather than the case deleted, because 'the equality"
echo "   subsumes the count' is exactly the reasoning that would justify dropping"
echo "   the count — and for the #\"\" / #\"\" datum-folding case it does not."
VALUE_OK_OFF='s/    own_output\.value == expected_value && value_shape_ok\(own_output\.value\)/    True/'
run_case "  value_ok's length alone removed — junk still caught by the equality" \
  "graduate_rejects_junk_assets_in_the_graduated_pool" PASSES \
  "$VALUE_LEN_OFF" validators/lump_pool.ak

run_case "  value_ok's equality alone removed — junk still caught by the length" \
  "graduate_rejects_junk_assets_in_the_graduated_pool" PASSES \
  "$VALUE_EQ_OFF" validators/lump_pool.ak

run_case "  BOTH halves removed — junk IS then welded into the permanent pool" \
  "graduate_rejects_junk_assets_in_the_graduated_pool" FAILS \
  "$VALUE_OK_OFF" validators/lump_pool.ak

echo
echo "── pool_nft_kept on Graduate: a MATCHED PAIR with the value equality ─────"
echo "   Fully redundant while the equality stands (which pins the NFT quantity to"
echo "   1). Kept as the only thing left pinning the NFT if the equality is ever"
echo "   weakened to 'contains at least'."
NFT_GRAD_OFF='my $i=0; s/(pool_nft_kept\(own_output, policy_id\),)/++$i == 3 ? "True," : $1/ge'
echo "   MEASURED: it is a TRIPLE, not a pair. A continuation holding ZERO of the"
echo "   NFT does not carry a zero — stdlib's add(_,_,0) is a no-op, so the entry"
echo "   VANISHES and the value has two entries. So value_ok's LENGTH half fires"
echo "   alongside its equality half. All three must go before the NFT can leave."
run_case "  pool_nft_kept alone on Graduate (value_ok covers it: PASSES)" \
  "graduate_rejects_the_nft_leaving_the_pool" PASSES \
  "$NFT_GRAD_OFF" validators/lump_pool.ak

run_case "  pool_nft_kept + value_ok's EQUALITY (its length half still fires: PASSES)" \
  "graduate_rejects_the_nft_leaving_the_pool" PASSES \
  "$NFT_GRAD_OFF; $VALUE_EQ_OFF" validators/lump_pool.ak

run_case "  pool_nft_kept AND BOTH value_ok halves — the NFT walks out and bricks it" \
  "graduate_rejects_the_nft_leaving_the_pool" FAILS \
  "$NFT_GRAD_OFF; $VALUE_OK_OFF" validators/lump_pool.ak

echo
echo "── tx.mint == zero: NOTHING IS MINTED AND NOTHING IS BURNED ───────────────"
echo "   The old Splash graduation REQUIRED a Retire burn of the pool NFT. It is"
echo "   now a hard reject, and this is the regression test for that deletion."
NO_MINT_OFF='s/  let no_mint = tx\.mint == assets\.zero/  let no_mint = True/'
run_case "no_mint removed — the pool NFT is burned at the flip (the old Retire shape)" \
  "graduate_rejects_burning_the_pool_nft" FAILS \
  "$NO_MINT_OFF" validators/lump_pool.ak

run_case "no_mint removed — curve tokens are minted at the flip" \
  "graduate_rejects_minting_curve_tokens" FAILS \
  "$NO_MINT_OFF" validators/lump_pool.ak

run_case "no_mint removed — a foreign mint rides along" \
  "graduate_rejects_a_foreign_mint_riding_along" FAILS \
  "$NO_MINT_OFF" validators/lump_pool.ak

echo
echo "   (The Graduate-only \`let no_ref_script = …\` case that used to sit here is"
echo "    GONE because the line is gone: it was extracted into the shared"
echo "    \`no_ref_script_kept\` and is now bound as occurrence 3 of 5 in the"
echo "    reference-script section below, alongside the four branches that never"
echo "    had the guard at all.)"

echo
echo "── ██ sole_continuation FILTERS ON THE PAYMENT CREDENTIAL. ██ ─────────────"
echo "   Reverting it to the FULL-ADDRESS comparison is the defect the Splash"
echo "   review found in G12, generalised to all five branches. The production"
echo "   address is an enterprise script address, so Address{Script(h),Some(stake)}"
echo "   is a different Data value and was invisible to the filter."
FULL_ADDR='s/        o\.address\.payment_credential == own_input\.output\.address\.payment_credential/        o.address == own_input.output.address/'
run_case "sole_continuation compares the FULL address — a stake-part decoy rides along" \
  "graduate_rejects_a_stake_part_decoy_alongside_the_real_continuation" FAILS \
  "$FULL_ADDR" validators/lump_pool.ak

run_case "  ...and the same on the AMM branch, on every trade for the pool's life" \
  "amm_buy_rejects_a_stake_part_decoy_alongside_the_continuation" FAILS \
  "$FULL_ADDR" validators/lump_pool.ak

run_case "  ...while the SOLE-staked-output case is rejected either way (PASSES)" \
  "graduate_rejects_a_stake_credential_on_the_graduated_pool" PASSES \
  "$FULL_ADDR" validators/lump_pool.ak

run_case "  ...and on the AmmSELL branch, which had no decoy test at all before" \
  "amm_sell_rejects_a_stake_part_decoy_alongside_the_continuation" FAILS \
  "$FULL_ADDR" validators/lump_pool.ak

echo
echo "── continuation_address_exact — the stake part, pinned separately ─────────"
echo
echo "   ██ ALL FIVE CALL SITES, INDIVIDUALLY. ██ Only occurrences 3 (Graduate) and"
echo "   4 (AmmBuy) were bound; 1 (Buy), 2 (Sell) and 5 (AmmSell) were covered by"
echo "   NOTHING — no test, no mutation. AmmSell was the severe one, and it is severe"
echo "   in a way an ordinary coverage hole is not: sole_continuation deliberately"
echo "   filters on the PAYMENT CREDENTIAL, so a staked output IS the sole"
echo "   continuation and this guard is the only thing rejecting it. Worse, the"
echo "   damage LATCHES — once a stake credential is attached, the guard on the other"
echo "   four branches pins the continuation to the new staked address for the life"
echo "   of the token. One unguarded branch is permanent, and AmmSell is the branch"
echo "   that runs forever."
ADDR_EXACT='my $i=0; s/(continuation_address_exact\(own_input, own_output\),)/++$i == $N ? "True," : $1/ge'
run_case "continuation_address_exact removed on Buy (occurrence 1 of 5)" \
  "buy_rejects_a_stake_credential_on_the_continuation" FAILS \
  "my \$N=1; $ADDR_EXACT" validators/lump_pool.ak

run_case "continuation_address_exact removed on Sell (occurrence 2 of 5)" \
  "sell_rejects_a_stake_credential_on_the_continuation" FAILS \
  "my \$N=2; $ADDR_EXACT" validators/lump_pool.ak

run_case "continuation_address_exact removed on Graduate (occurrence 3 of 5)" \
  "graduate_rejects_a_stake_credential_on_the_graduated_pool" FAILS \
  "my \$N=3; $ADDR_EXACT" validators/lump_pool.ak

run_case "continuation_address_exact removed on AmmBuy (occurrence 4 of 5)" \
  "amm_buy_rejects_a_stake_credential_on_the_continuation" FAILS \
  "my \$N=4; $ADDR_EXACT" validators/lump_pool.ak

run_case "██ continuation_address_exact removed on AmmSell (occurrence 5 of 5) — PERMANENT stake capture" \
  "amm_sell_rejects_a_stake_credential_on_the_continuation" FAILS \
  "my \$N=5; $ADDR_EXACT" validators/lump_pool.ak

echo
echo "── ██ no_ref_script_kept — THE GUARD THAT DID NOT EXIST ON FOUR BRANCHES. ██"
echo
echo "   \`reference_script == None\` was asserted at GENESIS and at the FLIP and"
echo "   nowhere else, so any Buy/Sell/AmmBuy/AmmSell could WELD a reference script"
echo "   onto the pool. Conway charges minFeeRefScriptCoinsPerByte over the reference"
echo "   scripts on a tx's RESOLVED INPUTS, so one griefer pays one trade and every"
echo "   later trader pays the tier; it also inflates the pool's min-UTxO, which in"
echo "   Amm mode has no pool_floor cushion beside it. The inline let in"
echo "   validate_graduate is now a shared function called on all five branches."
REF_KEPT='s/fn no_ref_script_kept\(own_output: Output\) -> Bool \{\r?\n  own_output\.reference_script == None\r?\n\}/fn no_ref_script_kept(own_output: Output) -> Bool {\n  own_output.reference_script == None || True\n}/'
echo "   First the FUNCTION BODY, which neuters all five at once. Note the mutation"
echo "   NEUTRALISES rather than deletes (\`x || True\`) — Aiken refuses an \`and { }\`"
echo "   chain of fewer than two expressions, and a bare \`True\` body would leave"
echo "   own_output unused and change the compile outcome rather than the logic."
run_case "no_ref_script_kept body neutered — every branch admits a reference script" \
  "rejects_a_reference_script_on_the" FAILS \
  "$REF_KEPT" validators/lump_pool.ak

echo "   ...then each CALL SITE independently, because a shared body proves the"
echo "   function's contract and NOT that a branch still calls it — the same"
echo "   distinction the fee_schedule_ok call-site cases exist for."
REF_CALL='my $i=0; s/(no_ref_script_kept\(own_output\),)/++$i == $N ? "True," : $1/ge'
run_case "no_ref_script_kept removed on Buy (occurrence 1 of 5)" \
  "buy_rejects_a_reference_script_on_the_continuation" FAILS \
  "my \$N=1; $REF_CALL" validators/lump_pool.ak

run_case "no_ref_script_kept removed on Sell (occurrence 2 of 5)" \
  "sell_rejects_a_reference_script_on_the_continuation" FAILS \
  "my \$N=2; $REF_CALL" validators/lump_pool.ak

run_case "no_ref_script_kept removed on Graduate (occurrence 3 of 5)" \
  "graduate_rejects_a_reference_script_on_the_graduated_pool" FAILS \
  "my \$N=3; $REF_CALL" validators/lump_pool.ak

run_case "██ no_ref_script_kept removed on AmmBuy (occurrence 4 of 5) — PERMANENT pool" \
  "amm_buy_rejects_a_reference_script_on_the_continuation" FAILS \
  "my \$N=4; $REF_CALL" validators/lump_pool.ak

run_case "██ no_ref_script_kept removed on AmmSell (occurrence 5 of 5) — PERMANENT pool" \
  "amm_sell_rejects_a_reference_script_on_the_continuation" FAILS \
  "my \$N=5; $REF_CALL" validators/lump_pool.ak

echo
echo "── R-3 / V-1: DOUBLE SATISFACTION, in both modes and on Graduate ──────────"
echo "   Two v3 pools in one transaction. v3's pool is UNPARAMETERISED, so every"
echo "   token in both modes shares one script hash and two pools genuinely can be"
echo "   co-spent unless one_pool counts them."
run_case "tx_shape_ok one_pool removed — two pools per tx, on every branch" \
  "second_pool_input" FAILS \
  's/  let one_pool = list\.count\(inputs, fn\(i\) \{ at_script\(i, own_hash\) \}\) == 1/  let one_pool = True/' \
  validators/lump_pool.ak

run_case "tx_shape_ok confined removed — a foreign script rides along on every branch" \
  "foreign_script_input" FAILS \
  's/          Credential\.VerificationKey\(_\) -> True\r?\n        \}\r?\n      \},\r?\n    \)\r?\n  one_pool && confined/          Credential.VerificationKey(_) -> True\n        }\n      },\n    )\n  one_pool || confined/' \
  validators/lump_pool.ak

echo
echo "══ THE PERMANENT AMM ═════════════════════════════════════════════════════"

echo
echo "── the value invariant's Amm arm: NO floor, NO offset ────────────────────"
echo
echo "   ██ TWO KINDS OF MUTATION HERE, AND THE DIFFERENCE WAS MEASURED. ██"
echo
echo "   SHIFTING the arm — writing the Bootstrap substitutions into the Amm arm,"
echo "   which is what a copy-pasted continuation builder produces — cannot bind"
echo "   the REJECT tests, and the first version of this section wrongly expected"
echo "   it to. \`value_matches\` is called on BOTH sides: once on the INPUT by the"
echo "   preamble's in_consistent and once on the CONTINUATION. A shifted arm"
echo "   breaks the input check too, so the transaction is still rejected — just"
echo "   for the wrong reason. mutverify reported SURVIVED and was correct."
echo "   The shift cases are KEPT, expecting the ACCEPT case to break: that is a"
echo "   real and important binding (write the Bootstrap invariant here and NO AMM"
echo "   trade is possible at all), it is simply a positive one."
echo
echo "   DROPPING a clause is what isolates the reject tests, because it loosens"
echo "   both sides at once instead of moving them."
AMM_ARM_FLOOR='s/      lovelace_of\(v\) == ada_reserve && quantity_of\(v, policy_id, asset_name\) == token_reserve/      lovelace_of(v) == ada_reserve + pool_floor_v3 \&\& quantity_of(v, policy_id, asset_name) == token_reserve/'
AMM_ARM_OFFSET='s/      lovelace_of\(v\) == ada_reserve && quantity_of\(v, policy_id, asset_name\) == token_reserve/      lovelace_of(v) == ada_reserve \&\& quantity_of(v, policy_id, asset_name) == token_reserve - token_offset_v3/'
AMM_ARM_NO_LOVELACE='s/      lovelace_of\(v\) == ada_reserve && quantity_of\(v, policy_id, asset_name\) == token_reserve/      quantity_of(v, policy_id, asset_name) == token_reserve/'
AMM_ARM_NO_TOKEN='s/      lovelace_of\(v\) == ada_reserve && quantity_of\(v, policy_id, asset_name\) == token_reserve/      lovelace_of(v) == ada_reserve/'

run_case "Amm arm's lovelace clause DROPPED — the stray-floor continuation is accepted" \
  "amm_buy_rejects_a_stray_pool_floor_in_the_continuation" FAILS \
  "$AMM_ARM_NO_LOVELACE" validators/lump_pool.ak

run_case "Amm arm's token clause DROPPED — 142,857,143 tokens leave the pool" \
  "amm_buy_rejects_the_token_offset_applied_to_the_continuation" FAILS \
  "$AMM_ARM_NO_TOKEN" validators/lump_pool.ak

run_case "Amm arm's lovelace clause DROPPED — an input carrying a floor is accepted" \
  "amm_rejects_an_input_carrying_a_pool_floor" FAILS \
  "$AMM_ARM_NO_LOVELACE" validators/lump_pool.ak

run_case "Amm arm's token clause DROPPED — a Bootstrap-shaped input value is accepted" \
  "amm_rejects_an_input_holding_the_offset_reduced_balance" FAILS \
  "$AMM_ARM_NO_TOKEN" validators/lump_pool.ak

echo
echo "   ...and the SHIFT cases, bound in the positive direction:"
run_case "  Amm arm demands a pool_floor — no AMM trade is satisfiable at all" \
  "amm_buy_accepts_the_same_trade_without_the_stray_floor" FAILS \
  "$AMM_ARM_FLOOR" validators/lump_pool.ak

run_case "  Amm arm subtracts token_offset — no AMM trade is satisfiable at all" \
  "amm_buy_accepts_the_canonical_trade" FAILS \
  "$AMM_ARM_OFFSET" validators/lump_pool.ak

echo
echo "── ...and the BOOTSTRAP arm, which moved into the same function ───────────"
echo "   Its two clauses carry pool_floor_v3 and token_offset_v3 — the two"
echo "   substitutions the whole v3 datum convention rests on."
echo
echo "   ██ THESE CANNOT BE BOUND BY A REJECT TEST, AND HERE IS WHY. ██ MEASURED:"
echo "   \`value_matches\` is called TWICE per spend — on the INPUT by in_consistent"
echo "   and on the CONTINUATION by out_consistent — with the SAME arm. Dropping a"
echo "   term therefore loosens the input check and the output check TOGETHER, and"
echo "   the invariant reject tests each break only ONE side while leaving the other"
echo "   canonical. So the mutation still rejects, for the other side's reason."
echo "   (The first version of this section expected FAILS on those tests and"
echo "   mutverify reported SURVIVED. Correct, and the fix is the right binding,"
echo "   not a weaker guard.)"
echo
echo "   Bound in the POSITIVE direction instead: drop either term and NO curve"
echo "   trade is satisfiable at all, because a canonical continuation carries the"
echo "   floor and the offset."
run_case "Bootstrap arm's pool_floor term dropped — no curve trade is satisfiable" \
  "buy_accepts_canonical_genesis_trade" FAILS \
  's/lovelace_of\(v\) == ada_reserve \+ pool_floor_v3/lovelace_of(v) == ada_reserve/' \
  validators/lump_pool.ak

run_case "Bootstrap arm's token_offset term dropped — no curve trade is satisfiable" \
  "buy_accepts_canonical_genesis_trade" FAILS \
  's/\) == token_reserve - token_offset_v3/) == token_reserve/' \
  validators/lump_pool.ak

echo "   ...and the reject tests still reject under the same mutations, which is"
echo "   the measurement that justifies the paragraph above rather than asserting it:"
run_case "  ...the input-floor reject still rejects (the output side fires: PASSES)" \
  "invariant_rejects_input_without_the_pool_floor" PASSES \
  's/lovelace_of\(v\) == ada_reserve \+ pool_floor_v3/lovelace_of(v) == ada_reserve/' \
  validators/lump_pool.ak

run_case "  ...the input-offset reject still rejects (the output side fires: PASSES)" \
  "invariant_rejects_input_holding_the_virtual_reserve" PASSES \
  's/\) == token_reserve - token_offset_v3/) == token_reserve/' \
  validators/lump_pool.ak

echo
echo "── AMM arithmetic ────────────────────────────────────────────────────────"
run_case "AmmBuy correct_tokens_out removed" \
  "amm_buy_rejects_one_extra_token_out" FAILS \
  's/  let correct_tokens_out = tokens_out == amm_quote_buy\(old_ada, old_tok, ada_in\)/  let correct_tokens_out = True/' \
  validators/lump_pool.ak

run_case "AmmSell correct_gross removed" \
  "amm_sell_rejects_over_extracting_ada" FAILS \
  's/  let correct_gross = ada_gross == amm_quote_sell_gross\(old_ada, old_tok, tokens_in\)/  let correct_gross = True/' \
  validators/lump_pool.ak

echo
echo "   (The AmmBuy size_ok and AmmSell-gains-a-minimum cases that sat here are"
echo "    DELETED with min_trade_ada_v3 — see the note at the top of the file's"
echo "    sell-side section. The no-minimum behaviour is bound by ACCEPT tests.)"

TOKENS_IN_AMM='my $i=0; s/(^    tokens_in_positive,$)/++$i == 2 ? "    True," : $1/gme'
run_case "AmmSell tokens_in_positive removed — a no-op sell is accepted" \
  "amm_sell_rejects_zero_tokens_in" FAILS \
  "$TOKENS_IN_AMM" validators/lump_pool.ak

echo
echo "── ██ THE AMM'S TOKEN CAP IS total_supply_v3, NOT virtual_token_v3. ██ ────"
echo "   The two differ by exactly token_offset_v3, so the constant swap silently"
echo "   admits a 142,857,143-token overshoot: a pool claiming more tokens than"
echo "   exist. This is the specific mutation the doc comment warns about."
run_case "AmmSell cap_ok removed" \
  "amm_sell_rejects_pushing_the_reserve_above_total_supply" FAILS \
  's/  let cap_ok = new_tok <= total_supply_v3/  let cap_ok = True/' \
  validators/lump_pool.ak

run_case "AmmSell cap_ok uses the CURVE's virtual_token_v3 constant instead" \
  "amm_sell_rejects_pushing_the_reserve_above_total_supply" FAILS \
  's/  let cap_ok = new_tok <= total_supply_v3/  let cap_ok = new_tok <= virtual_token_v3/' \
  validators/lump_pool.ak

run_case "  ...and dumping the entire float must STILL be legal at the cap (PASSES)" \
  "amm_sell_accepts_dumping_the_entire_float" PASSES \
  's/  let cap_ok = new_tok <= total_supply_v3/  let cap_ok = new_tok <= virtual_token_v3/' \
  validators/lump_pool.ak

echo
echo "── AMM slippage, per branch ───────────────────────────────────────────────"
SLIP_AMMBUY='my $i=0; s/(let slippage_ok = tokens_out >= min_out)/++$i == 2 ? "let slippage_ok = True" : $1/ge'
SLIP_AMMSELL='my $i=0; s/(let slippage_ok = net_ada >= min_out)/++$i == 2 ? "let slippage_ok = True" : $1/ge'
run_case "AmmBuy slippage_ok removed" \
  "amm_buy_rejects_underpay_slippage" FAILS \
  "$SLIP_AMMBUY" validators/lump_pool.ak

run_case "AmmSell slippage_ok removed" \
  "amm_sell_rejects_underpay_slippage" FAILS \
  "$SLIP_AMMSELL" validators/lump_pool.ak

echo
echo "── ██ THE TWO AMM solvency_ok GUARDS: STRUCTURALLY SHADOWED AS OF v3.2. ██ ─"
echo "   The v3.2 quotes floor the amount OUT, so tokens_out < T and gross < A at"
echo "   EVERY state — even a self-seeded ada_reserve=1 pool cannot be emptied"
echo "   through a correct quote, and no fixture can make the solvency pair the"
echo "   rejecting guard. The guards STAY as defence in depth (a future cohort"
echo "   that changes the rounding gets them back for free). These two cases"
echo "   DOCUMENT the shadowing: neutering BOTH guards changes nothing observable"
echo "   — if either case ever flips to FAILS, the guards became load-bearing"
echo "   again and need real isolation cases, not this pair."
SOLV_BUY='s/  let solvency_ok = new_tok >= 1/  let solvency_ok = True/'
SOLV_SELL='s/  let solvency_ok = new_ada >= 1/  let solvency_ok = True/'
VSHAPE_AMMBUY='my $i=0; s/(value_shape_ok\(own_output\.value\),)/++$i == 3 ? "True," : $1/ge'
VSHAPE_AMMSELL='my $i=0; s/(value_shape_ok\(own_output\.value\),)/++$i == 4 ? "True," : $1/ge'

run_case "  AmmBuy solvency pair removed — SHADOWED by the v3.2 quote (documents)" \
  "amm_tiny_k_pool_token_side_cannot_be_emptied" PASSES \
  "$SOLV_BUY; $VSHAPE_AMMBUY" validators/lump_pool.ak

run_case "  AmmSell solvency pair removed — SHADOWED by the v3.2 quote (documents)" \
  "amm_tiny_k_pool_ada_side_cannot_be_emptied" PASSES \
  "$SOLV_SELL; $VSHAPE_AMMSELL" validators/lump_pool.ak

echo
echo "── fee_schedule_ok now covers the AMM half — the LARGER revenue surface ───"
echo "   A graduated pool trades forever, so most of a token's lifetime volume is"
echo "   here. A pin that covered only the curve would have left it open."
run_case "treasury not pinned at spend time — a counterfeit AMM pool trades fee-free" \
  "amm_buy_rejects_a_pool_whose_datum_names_a_foreign_treasury" FAILS \
  's/treasury_pkh == treasury_pkh_v3/True/' validators/lump_pool.ak

run_case "platform bps + flat floors removed — a zero-fee graduated pool trades" \
  "amm_buy_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  's/platform_fee_bps >= platform_fee_bps_v3/True/; s/platform_fee_flat >= platform_fee_flat_v3/True/; s/treasury_pkh == treasury_pkh_v3/True/' \
  validators/lump_pool.ak

echo "   ...and the SAME clauses reached through AmmSell, which is the branch that"
echo "   moves ADA OUT of a permanent pool. Both cases above neuter the clauses"
echo "   INSIDE the shared function, so they were satisfied by AmmBuy's tests alone"
echo "   and said nothing about the sell side."
run_case "treasury not pinned — a counterfeit AMM pool SELLS fee-free" \
  "amm_sell_rejects_a_pool_whose_datum_names_a_foreign_treasury" FAILS \
  's/treasury_pkh == treasury_pkh_v3/True/' validators/lump_pool.ak

run_case "platform floors removed — a zero-fee graduated pool SELLS fee-free" \
  "amm_sell_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  's/platform_fee_bps >= platform_fee_bps_v3/True/; s/platform_fee_flat >= platform_fee_flat_v3/True/; s/treasury_pkh == treasury_pkh_v3/True/' \
  validators/lump_pool.ak

echo
echo "── ██ THE fee_schedule_ok CALL SITES, NOT ITS CLAUSES. ██ ─────────────────"
echo "   Every case above neuters something INSIDE the shared function. None of them"
echo "   proves a given branch still CALLS it — and deleting the whole 6-line call"
echo "   from AmmSell's and-block left the suite fully green before the AmmSell"
echo "   fee tests existed. 'The buy branch pins it, the sell branch is symmetric'"
echo "   is exactly the refactor that would have done it."
FEE_CALL='my $i=0; s/(fee_schedule_ok\(\r?\n      treasury_pkh,\r?\n      creator_fee_bps,\r?\n      platform_fee_bps,\r?\n      platform_fee_flat,\r?\n    \),)/++$i == $N ? "True," : $1/ge'
run_case "fee_schedule_ok CALL deleted from validate_buy (occurrence 1 of 4)" \
  "buy_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  "my \$N=1; $FEE_CALL" validators/lump_pool.ak

echo "   ██ NOTE ON THE SELL-SIDE CASE. ██ It first pointed at"
echo "   sell_rejects_the_pool_paying_its_own_platform_fee and mutverify reported"
echo "   SURVIVED — correctly. That test names the POOL as its own treasury, so"
echo "   pays_at_least's own-hash exclusion refuses it independently of"
echo "   fee_schedule_ok, and deleting the call changed nothing. Re-pointed at the"
echo "   zero-fee counterfeit, where a 0/0/0 schedule owes no fee outputs at all and"
echo "   fee_schedule_ok is the SOLE rejecter. This is the same 'the obvious test"
echo "   does not isolate the guard' trap the pool_nft_kept and solvency pairs hit."
run_case "fee_schedule_ok CALL deleted from validate_sell (occurrence 2 of 4)" \
  "sell_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  "my \$N=2; $FEE_CALL" validators/lump_pool.ak

run_case "  ...while the pool-as-own-treasury sell is refused either way (PASSES)" \
  "sell_rejects_the_pool_paying_its_own_platform_fee" PASSES \
  "my \$N=2; $FEE_CALL" validators/lump_pool.ak

run_case "fee_schedule_ok CALL deleted from validate_amm_buy (occurrence 3 of 4)" \
  "amm_buy_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  "my \$N=3; $FEE_CALL" validators/lump_pool.ak

run_case "██ fee_schedule_ok CALL deleted from validate_amm_sell (occurrence 4 of 4)" \
  "amm_sell_rejects_a_zero_platform_fee_self_seeded_pool" FAILS \
  "my \$N=4; $FEE_CALL" validators/lump_pool.ak

echo
echo "── ██ authentic — THE ONLY LINE SEPARATING THE POOL FROM A DECOY. ██ ──────"
echo "   v3's pool is UNPARAMETERISED: every LumpFun token in both modes shares one"
echo "   address, decoys cost nothing to park there, and the NFT is NEVER burned, so"
echo "   this one line is the sole discriminator for the token's ENTIRE life. It had"
echo "   no mutverify case at all."
AUTH_OFF='s/    let authentic =\r?\n      quantity_of\(own_input\.output\.value, policy_id, pool_nft_name\) == 1/    let authentic = True/'
run_case "authentic removed — a decoy BUY input without the NFT is accepted" \
  "buy_rejects_decoy_input_without_the_nft" FAILS \
  "$AUTH_OFF" validators/lump_pool.ak

run_case "authentic removed — a decoy SELL input without the NFT is accepted" \
  "sell_rejects_decoy_input_without_the_nft" FAILS \
  "$AUTH_OFF" validators/lump_pool.ak

run_case "authentic removed — a decoy AmmBuy input without the NFT is accepted" \
  "amm_buy_rejects_a_decoy_input_without_the_nft" FAILS \
  "$AUTH_OFF" validators/lump_pool.ak

run_case "authentic removed — a decoy AmmSell input without the NFT is accepted" \
  "amm_sell_rejects_a_decoy_input_without_the_nft" FAILS \
  "$AUTH_OFF" validators/lump_pool.ak

run_case "authentic removed — a graduation of a pool without the NFT is accepted" \
  "graduate_rejects_a_pool_input_without_the_nft" FAILS \
  "$AUTH_OFF" validators/lump_pool.ak

echo
echo "── AMM structural guards ──────────────────────────────────────────────────"
NFT_AMMBUY='my $i=0; s/(pool_nft_kept\(own_output, policy_id\),)/++$i == 4 ? "True," : $1/ge'
echo "   pool_nft_kept on the TRADE branches is a MATCHED PAIR with value_shape_ok,"
echo "   for the same stdlib reason as the solvency guards: a continuation with ZERO"
echo "   of the NFT does not carry a zero, it LOSES the entry, so length == 3 fires"
echo "   too. The first version of this case expected pool_nft_kept to be isolated"
echo "   and mutverify reported SURVIVED. Corrected to the pair it actually is —"
echo "   and pool_nft_kept still earns its place, because it is what keeps 'the NFT"
echo "   never leaves' true if a future branch ever admits a fourth asset."
run_case "  pool_nft_kept alone on AmmBuy (value_shape_ok co-fires: PASSES)" \
  "amm_buy_rejects_the_nft_carried_out_of_the_pool" PASSES \
  "$NFT_AMMBUY" validators/lump_pool.ak

run_case "  value_shape_ok alone on AmmBuy (pool_nft_kept co-fires: PASSES)" \
  "amm_buy_rejects_the_nft_carried_out_of_the_pool" PASSES \
  "$VSHAPE_AMMBUY" validators/lump_pool.ak

run_case "  BOTH removed — the NFT walks out of a graduated pool and bricks it" \
  "amm_buy_rejects_the_nft_carried_out_of_the_pool" FAILS \
  "$NFT_AMMBUY; $VSHAPE_AMMBUY" validators/lump_pool.ak

run_case "value_shape_ok removed on AmmBuy — junk welded into a permanent pool" \
  "amm_buy_rejects_junk_assets_in_the_continuation" FAILS \
  "$VSHAPE_AMMBUY" validators/lump_pool.ak

run_case "value_shape_ok removed on AmmSell — junk welded into a permanent pool" \
  "amm_sell_rejects_junk_assets_in_the_continuation" FAILS \
  "$VSHAPE_AMMSELL" validators/lump_pool.ak

echo
echo "── R-5 on the AMM branches — the frozen fields, for the REST of the life ──"
WR_AMMBUY='my $i=0; s/(let datum_preserved = with_reserves\(d, new_ada, new_tok\) == new_d)/++$i == 3 ? "let datum_preserved = True" : $1/ge'
WR_AMMSELL='my $i=0; s/(let datum_preserved = with_reserves\(d, new_ada, new_tok\) == new_d)/++$i == 4 ? "let datum_preserved = True" : $1/ge'
run_case "AmmBuy datum_preserved removed — the royalty key is captured post-graduation" \
  "r5_amm_rejects_rewriting_the_royalty_pub_key" FAILS \
  "$WR_AMMBUY" validators/lump_pool.ak

run_case "AmmBuy datum_preserved removed — the treasury is redirected post-graduation" \
  "r5_amm_rejects_rewriting_the_treasury_pkh" FAILS \
  "$WR_AMMBUY" validators/lump_pool.ak

run_case "AmmBuy datum_preserved removed — the platform fee is rewritten post-graduation" \
  "r5_amm_rejects_rewriting_the_platform_fee_bps" FAILS \
  "$WR_AMMBUY" validators/lump_pool.ak

run_case "AmmSell datum_preserved removed — the royalty key is captured on a sell" \
  "r5_amm_sell_rejects_rewriting_the_royalty_pub_key" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

echo "   ...and the SIX fields AmmSell did not previously reject. \`with_reserves\`"
echo "   freezes NINE; AmmBuy rejected a rewrite of all nine and AmmSell of only"
echo "   three, so a bespoke inlined reconstruction on this branch — a plausible"
echo "   optimisation on the branch that will carry the most volume — would have been"
echo "   caught for royalty_pub_key, treasury_pkh and mode and MISSED for the rest."
run_case "AmmSell datum_preserved removed — the creator is redirected on a sell" \
  "r5_amm_sell_rejects_rewriting_the_creator_pkh" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

run_case "AmmSell datum_preserved removed — the policy_id is rewritten on a sell" \
  "r5_amm_sell_rejects_rewriting_the_policy_id" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

run_case "AmmSell datum_preserved removed — the asset_name is rewritten on a sell" \
  "r5_amm_sell_rejects_rewriting_the_asset_name" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

run_case "AmmSell datum_preserved removed — the creator fee is zeroed on a sell" \
  "r5_amm_sell_rejects_zeroing_the_creator_fee_bps" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

run_case "AmmSell datum_preserved removed — the platform bps is rewritten on a sell" \
  "r5_amm_sell_rejects_rewriting_the_platform_fee_bps" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

run_case "AmmSell datum_preserved removed — the platform flat is zeroed on a sell" \
  "r5_amm_sell_rejects_zeroing_the_platform_fee_flat" FAILS \
  "$WR_AMMSELL" validators/lump_pool.ak

echo
echo "── math_v3: the AMM quotes must NOT carry the curve's virtual offset ──────"
echo "   'Reuse quote_buy for the AMM' is the obvious simplification and it is the"
echo "   whole defect: the offset is what makes the two halves price differently."
run_case "amm_quote_buy given virtual_ada_v3 — the AMM prices like the curve" \
  "amm_buy_" FAILS \
  's/  ada_in_net \* token_reserve \/ \( ada_reserve \+ ada_in_net \)/  ada_in_net * token_reserve \/ ( ada_reserve + virtual_ada_v3 + ada_in_net )/' \
  lib/lumpfun/math_v3.ak

run_case "amm_quote_sell_gross given virtual_ada_v3" \
  "amm_sell_" FAILS \
  's/  let gross = tokens_in_net \* ada_reserve \/ \( token_reserve \+ tokens_in_net \)/  let gross = tokens_in_net * ( ada_reserve + virtual_ada_v3 ) \/ ( token_reserve + tokens_in_net )/' \
  lib/lumpfun/math_v3.ak

echo
echo "── ██ v3.2: THE LP FEE MUST BE BOUND, PER QUOTE, PER CONSTANT. ██ ─────────"
echo "   'Drop the netting' is the one-line simplification that silently refunds"
echo "   the 0.30% to the trader and stops the pool growing; zeroing the constant"
echo "   is the same defect via params_v3. Each must be killed INDEPENDENTLY —"
echo "   a shared kill would let a refactor drop one side's netting unseen."
run_case "amm_quote_buy netting dropped — the buy prices the FULL input" \
  "amm_buy_" FAILS \
  's/  let ada_in_net = ada_in \* \( 10_000 - amm_lp_fee_bps_v3 \) \/ 10_000/  let ada_in_net = ada_in/' \
  lib/lumpfun/math_v3.ak

run_case "amm_quote_sell_gross netting dropped — the sell prices the FULL input" \
  "amm_sell_" FAILS \
  's/  let tokens_in_net = tokens_in \* \( 10_000 - amm_lp_fee_bps_v3 \) \/ 10_000/  let tokens_in_net = tokens_in/' \
  lib/lumpfun/math_v3.ak

run_case "amm_lp_fee_bps_v3 zeroed in params — every AMM vector moves" \
  "amm_buy_" FAILS \
  's/pub const amm_lp_fee_bps_v3: Int = 30/pub const amm_lp_fee_bps_v3: Int = 0/' \
  lib/lumpfun/params_v3.ak

run_case "amm_lp_fee_bps_v3 zeroed — the k-direction test is bound to the fee" \
  "amm_buy_k_strictly_increases" FAILS \
  's/pub const amm_lp_fee_bps_v3: Int = 30/pub const amm_lp_fee_bps_v3: Int = 0/' \
  lib/lumpfun/params_v3.ak

echo
echo "── ██ THE DEPTH STEP AT THE FLIP IS MEASURED, NOT ASSUMED. ██ ─────────────"
echo "   Marginal price is continuous at the flip; DEPTH IS NOT — k falls to 41.78%"
echo "   and slippage per ADA rises 1.547x. The only test of this used a 10 ADA buy,"
echo "   where the whole effect is 33 tokens out of 156,190 (+0.021%) and a"
echo "   regression is invisible. The new vectors carry 100/1,000/5,000 ADA, where"
echo "   the penalty is +0.211% / +2.036% / +8.861%, plus a sell-side mirror."
echo "   Giving the AMM the curve's offset collapses the step to zero, which the"
echo "   strict inequalities must catch:"
run_case "amm_quote_buy given the curve's offset — the depth step vanishes" \
  "amm_depth_step_by_trade_size" FAILS \
  's/  ada_in_net \* token_reserve \/ \( ada_reserve \+ ada_in_net \)/  ada_in_net * token_reserve \/ ( ada_reserve + virtual_ada_v3 + ada_in_net )/' \
  lib/lumpfun/math_v3.ak

run_case "amm_quote_sell_gross given the curve's offset — the sell-side step vanishes" \
  "amm_depth_step_on_the_sell_side" FAILS \
  's/  let gross = tokens_in_net \* ada_reserve \/ \( token_reserve \+ tokens_in_net \)/  let gross = tokens_in_net * ( ada_reserve + virtual_ada_v3 ) \/ ( token_reserve + tokens_in_net )/' \
  lib/lumpfun/math_v3.ak

echo "   ...and the k RATIO is a fact about the CONSTANTS, so moving the pool bag"
echo "   must move it. This is what stops the 2.39296 identity becoming a fact about"
echo "   literals — the failure mode that let the deleted '~64 lovelace' drift claim"
echo "   survive as long as it did."
run_case "pool_bag_v3 off by one — the depth-step k ratio moves" \
  "amm_depth_step_k_ratio" FAILS \
  's/pub const pool_bag_v3: Int = 261_203_875/pub const pool_bag_v3: Int = 261_203_876/' \
  lib/lumpfun/params_v3.ak

run_case "pool_bag_v3 off by one — the locked-fraction identity moves too" \
  "amm_sell_of_the_whole_float_leaves_4376_ada" FAILS \
  's/pub const pool_bag_v3: Int = 261_203_875/pub const pool_bag_v3: Int = 261_203_876/' \
  lib/lumpfun/params_v3.ak

echo
echo "── ██ THE CONTINUITY PROOF IS BOUND TO THE CONSTANTS. ██ ──────────────────"
echo "   The graduation price step is a fact about pool_bag_v3, virtual_ada_v3,"
echo "   token_offset_v3 and curve_exhausted_token_reserve. Move any of them and"
echo "   the exact cross-multiplied residuals must go red — otherwise the proof is"
echo "   a fact about literals, which is how the deleted '~64 lovelace' claim"
echo "   survived as long as it did."
run_case "pool_bag_v3 off by one — the continuity residuals change" \
  "amm_open_price_matches_the_curve_close" FAILS \
  's/pub const pool_bag_v3: Int = 261_203_875/pub const pool_bag_v3: Int = 261_203_876/' \
  lib/lumpfun/params_v3.ak

run_case "virtual_ada_v3 off by one — the zero-gap reserve moves" \
  "amm_zero_gap_reserve_is_not_an_integer" FAILS \
  's/pub const virtual_ada_v3: Int = 9_142_857_144/pub const virtual_ada_v3: Int = 9_142_857_143/' \
  lib/lumpfun/params_v3.ak

run_case "curve_exhausted_token_reserve off by one — the close-price side moves" \
  "amm_open_price_matches_the_curve_close_at_the_ceiling" FAILS \
  's/pub const curve_exhausted_token_reserve: Int = 404_061_018/pub const curve_exhausted_token_reserve: Int = 404_061_019/' \
  lib/lumpfun/params_v3.ak

echo
echo "── minting_policy: mode is pinned to Bootstrap at genesis ─────────────────"
run_case "genesis mode not pinned — a launch may claim to be already graduated" \
  "mint_rejects_a_launch_claiming_amm_mode" FAILS \
  's/              mode == Bootstrap,/              True,/' \
  validators/minting_policy.ak

echo
echo "── minting_policy: genesis datum pinning ─────────────────────────────────"
run_case "treasury_pkh not pinned at genesis" \
  "mint_rejects_a_foreign_treasury_pkh" FAILS \
  's/              treasury_pkh == treasury_pkh_v3,/              True,/' \
  validators/minting_policy.ak

run_case "creator_pkh != pool_script_hash removed" \
  "mint_rejects_creator_pkh_equal_to_the_pool_script_hash" FAILS \
  's/              creator_pkh != pool_script_hash,/              True,/' \
  validators/minting_policy.ak

run_case "treasury_pkh != pool_script_hash removed" \
  "mint_rejects_treasury_pkh_equal_to_the_pool_script_hash" FAILS \
  's/              treasury_pkh != pool_script_hash,/              True,/; s/              treasury_pkh == treasury_pkh_v3,/              True,/' \
  validators/minting_policy.ak

echo
echo "── minting_policy: genesis value shape + reference script ────────────────"
run_case "genesis flatten == 3 removed" \
  "genesis_pool" FAILS \
  's/          list.length\(assets.flatten\(pool.value\)\) == 3,/          True,/' \
  validators/minting_policy.ak

run_case "reference_script == None removed" \
  "mint_rejects_a_reference_script_on_the_pool_output" FAILS \
  's/let no_ref_script_ok = pool.reference_script == None/let no_ref_script_ok = True/' \
  validators/minting_policy.ak

echo
echo "── minting_policy: THE ONE-SHOT SEED IS NOW THE WHOLE OF C-1 ──────────────"
echo "   With Retire deleted there is ONE handler, so one_shot_ok is the single"
echo "   premise behind 'supply is immutable at 1e9 for life' and 'the pool NFT"
echo "   count is immutable at 1 for life'. It used to be one link of a four-link"
echo "   cross-script chain; it is now the whole argument, so it is bound here."
run_case "one_shot_ok removed — the launch is no longer once-only" \
  "mint_rejects_without_seed" FAILS \
  's/    let one_shot_ok =\r?\n      list\.any\(tx\.inputs, fn\(i\) \{ i\.output_reference == one_shot_utxo \}\)/    let one_shot_ok = True/' \
  validators/minting_policy.ak

echo
echo "── pool_types: the constructor index is pinned on the wire ───────────────"
run_case "a second reserved constructor pushes PoolDatumV3 to index 2" \
  "v3_datum_wire_shape_is_constr_one_with_eleven_fields" FAILS \
  's/^  ReservedV2Slot\r?$/  ReservedV2Slot\n  ReservedExtraSlot/m' \
  lib/lumpfun/pool_types.ak

echo "   ...and the same shift is caught for the Amm form, so a graduated pool's"
echo "   datum cannot silently move to a different tag either:"
run_case "  ...the Amm-mode wire shape catches the same shift" \
  "v3_amm_datum_has_the_identical_wire_shape" FAILS \
  's/^  ReservedV2Slot\r?$/  ReservedV2Slot\n  ReservedExtraSlot/m' \
  lib/lumpfun/pool_types.ak

echo
echo "   THE ARITY HALF (ten -> eleven fields) IS NOT MUTATION-TESTABLE and saying"
echo "   so is better than faking a case for it: adding or removing a field of"
echo "   PoolDatumV3 breaks \`dat\`, \`gd\`, \`with_reserves\`, \`with_graduation\` and"
echo "   \`pool_seeded\` at COMPILE time — which is the designed behaviour and the"
echo "   reason \`mode\` became a deliberate decision. The test reads the ACTUAL"
echo "   encoded arity, so the only thing left to protect is the EXPECTED number,"
echo "   and a mutation of that is a mutation of the test itself."

echo
echo "── math_v3 / params_v3: the de-tautologised tests depend on the curve ────"
run_case "virtual_ada_v3 mispriced to 9_000_000_000 (launch price 7.875)" \
  "buy_genesis_price_is_just_above_eight" FAILS \
  's/pub const virtual_ada_v3: Int = 9_142_857_144/pub const virtual_ada_v3: Int = 9_000_000_000/' \
  lib/lumpfun/params_v3.ak

run_case "virtual_ada_v3 off by one — the FDV test catches even that" \
  "params_launch_fdv_is_exactly_8000_ada" FAILS \
  's/pub const virtual_ada_v3: Int = 9_142_857_144/pub const virtual_ada_v3: Int = 9_142_857_143/' \
  lib/lumpfun/params_v3.ak

echo
echo "   graduation_curve_checks is now TWO clauses (G4's isqrt bracket went with"
echo "   the Splash path — Graduate carries no witness field at all). \`ada_reserve"
echo "   >= 1\` changed job with it: it used to stop isqrt_ok(0,0,y) accepting a"
echo "   zero witness; it now stops a graduated AMM pool having k = 0, price 0, and"
echo "   261,203,875 tokens nobody can ever buy. It is isolated for the first time."
run_case "graduation checks: ada_reserve >= 1 removed (now ISOLATED, was a pair)" \
  "graduation_checks_reject_an_empty_ada_reserve" FAILS \
  's/  let g3 = ada_reserve >= 1 && pool_bag_v3 == token_reserve - token_offset_v3/  let g3 = pool_bag_v3 == token_reserve - token_offset_v3/' \
  lib/lumpfun/math_v3.ak

run_case "graduation checks: the bag identity removed (G0 covers it: PASSES)" \
  "graduation_checks_reject_off_by_one_token_reserves" PASSES \
  's/  let g3 = ada_reserve >= 1 && pool_bag_v3 == token_reserve - token_offset_v3/  let g3 = ada_reserve >= 1/' \
  lib/lumpfun/math_v3.ak

run_case "graduation checks: G0 removed (the bag identity covers it: PASSES)" \
  "graduation_checks_reject_off_by_one_token_reserves" PASSES \
  's/  let g0 = token_reserve == curve_exhausted_token_reserve/  let g0 = True/' \
  lib/lumpfun/math_v3.ak

run_case "graduation checks: BOTH G0 and the bag identity removed" \
  "graduation_checks_reject_off_by_one_token_reserves" FAILS \
  's/  let g0 = token_reserve == curve_exhausted_token_reserve/  let g0 = True/; s/  let g3 = ada_reserve >= 1 && pool_bag_v3 == token_reserve - token_offset_v3/  let g3 = ada_reserve >= 1/' \
  lib/lumpfun/math_v3.ak

echo
echo "── minting_policy: THE GENESIS BUY (v3.1) ─────────────────────────────────"
#
# `pool_seeded` accepts a launch carrying the creator's first trade. Every clause
# of that acceptance is somewhere a launcher could otherwise write their own
# price, so each gets a mutation and a test that has to catch it. Without these
# the branch is fifteen green tests proving nothing about whether its guards are
# load-bearing — which is the whole failure this script exists to detect.

run_case "genesis buy: the quote is not recomputed — a launcher prices their own fill" \
  "mint_rejects_a_genesis_buy_taking_one_extra_token" FAILS \
  's/      tokens_out == quote_buy\(0, virtual_token_v3, ada_in\),/      True,/' \
  validators/minting_policy.ak

run_case "genesis buy: cap_ok removed — a launch closes the curve inside itself" \
  "mint_rejects_a_genesis_buy_that_closes_the_curve" FAILS \
  's/      virtual_token_v3 - tokens_out >= curve_exhausted_token_reserve,/      True,/' \
  validators/minting_policy.ak

run_case "genesis buy: platform fee not required — a first buy would earn LumpFun nothing" \
  "mint_rejects_a_genesis_buy_with_no_platform_fee" FAILS \
  's/      platform_ok,/      True,/' \
  validators/minting_policy.ak

run_case "genesis buy: creator fee not required" \
  "mint_rejects_a_genesis_buy_with_no_creator_fee" FAILS \
  's/      creator_ok,/      True,/' \
  validators/minting_policy.ak

run_case "genesis buy: the ada_in == 0 arm stops requiring tokens_out == 0 — FREE TOKENS" \
  "mint_rejects_free_tokens_at_genesis" FAILS \
  's/^    tokens_out == 0\r?$/    True/m' \
  validators/minting_policy.ak

run_case "genesis buy: ada_reserve no longer pinned to the output — v2's double-FDV bug returns" \
  "mint_rejects_a_genesis_buy_whose_datum_understates_the_reserve" FAILS \
  's/              ada_reserve == ada_in,/              True,/' \
  validators/minting_policy.ak

run_case "genesis buy: token_reserve no longer pinned to the fill" \
  "mint_rejects_a_genesis_buy_whose_datum_overstates_the_token_reserve" FAILS \
  's/              token_reserve == virtual_token_v3 - tokens_out,/              True,/' \
  validators/minting_policy.ak

echo
echo "═════════════════════════════════════════════════════════════════════════"
echo "  killed / expected-survivals OK : $pass"
echo "  problems                       : $fail"
echo "═════════════════════════════════════════════════════════════════════════"
restore
[ "$fail" = "0" ]
