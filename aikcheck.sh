#!/usr/bin/env bash
# aiken renders COMPILE-ERROR diagnostics only to a real TTY — they vanish when
# stdout is piped or redirected (Windows and WSL alike). Run through `script` so
# a PTY exists, then strip the ANSI escapes for a readable log.
#   ./aikcheck.sh          -> aiken check
#   ./aikcheck.sh build    -> aiken build, THEN verify script hashes
#   ./aikcheck.sh hashes   -> verify script hashes only (needs a prior build)
cd "$(dirname "$0")" || exit 1
CMD="${1:-check}"

# Resolve aiken from PATH so a clone works for someone who is not the author;
# a hardcoded ~/bin/aiken only ever existed on one machine.
AIKEN="$(command -v aiken || true)"
if [ -z "$AIKEN" ] && [ -x "$HOME/bin/aiken" ]; then AIKEN="$HOME/bin/aiken"; fi
if [ -z "$AIKEN" ]; then
  echo "aikcheck: aiken not found on PATH — see https://aiken-lang.org/installation-instructions" >&2
  exit 127
fi

# ── The hash gate ─────────────────────────────────────────────────────────────
# `aiken check` CANNOT assert a script hash: an Aiken test cannot read
# plutus.json and a validator cannot hash itself. So a stdlib bump, a
# `plutus = "v3"` change, a compiler-flag change or an accidental edit would leave
# every check green while plutus.json quietly carried different bytes. That is the
# D-1/D-2 off-chain-to-on-chain seam the V2 report says every real defect lived
# in, so it is enforced here, at build time, and not in prose.
#
# ── THE H_fail RECOMPUTE WAS REMOVED ON 2026-07-26 ───────────────────────────
# This function used to independently recompute `blake2b-224(0x03 ‖ compiledCode)`
# for `lumpfun_dao_fail.lumpfun_dao_fail.else` and compare it against a hardcoded
# 22c9a103… — because that hash was named IMMUTABLY at field 11 of every graduated
# Splash royaltyPool datum and being wrong about it was unrecoverable. The Splash
# path is PARKED and both `validators/lumpfun_dao_fail.ak` and
# `lib/lumpfun/splash_v3.ak` are deleted, so there is no always-fail script to
# recompute and no foreign datum naming it. The recompute is gone with them rather
# than left comparing a hash of nothing. See the banner in validators/lump_pool.ak.
#
# The `pool_script_hash` gate below is UNAFFECTED and is now the whole of this
# function's job — and it is the more load-bearing of the two, because
# `lump_mint_v3` takes that hash as a PARAMETER and nothing inside the Aiken tree
# can bind parameter application.
verify_hashes() {
  local expected="hashes.expected" bad=0 title want got rec
  if [ ! -f plutus.json ]; then
    echo "HASH GATE: plutus.json missing — run ./aikcheck.sh build first"
    return 1
  fi
  if [ ! -f "$expected" ]; then
    echo "HASH GATE: $expected missing"
    return 1
  fi
  echo "── hash gate ─────────────────────────────────────────────────────────"
  while read -r title want; do
    case "$title" in ''|\#*) continue ;; esac
    [ -z "$want" ] && continue
    # `title` comes out of a data file, so it is passed as an ARGUMENT and never
    # interpolated into the program text: a crafted hashes.expected must not be
    # able to run code in whoever verifies this repository.
    got=$(python3 -c '
import json,sys
d=json.load(open("plutus.json"))
for v in d["validators"]:
    if v["title"]==sys.argv[1]:
        print(v.get("hash","")); sys.exit(0)
print("MISSING")
' "$title")
    if [ "$got" = "$want" ]; then
      printf '  ok        %-45s %s\n' "$title" "$got"
    else
      printf '  MISMATCH  %-45s\n            expected %s\n            got      %s\n' \
        "$title" "$want" "$got"
      bad=1
    fi
  done < "$expected"

  # Independently RECOMPUTE the pool hash from the compiled bytes rather than
  # trusting the blueprint's own `hash` field: blake2b-224 over
  # (0x03 language tag ‖ CBOR). The blueprint's `hash` is produced by the same
  # compiler run that produced the bytes, so comparing only that would not catch a
  # blueprint-writer bug — and this is the value `lump_mint_v3`'s `pool_script_hash`
  # PARAMETER is applied from off-chain, which nothing in the Aiken tree can bind.
  #
  # (This replaces the H_fail recompute, deleted with the Splash path on
  # 2026-07-26 — see the note above. The recompute discipline was worth keeping;
  # only its subject changed.)
  rec=$(python3 -c '
import json,hashlib,sys
d=json.load(open("plutus.json"))
for v in d["validators"]:
    if v["title"]==sys.argv[1]:
        print(hashlib.blake2b(bytes.fromhex("03")+bytes.fromhex(v["compiledCode"]),digest_size=28).hexdigest())
        break
' 'lump_pool.lump_pool_v3.spend')
  want_pool=$(awk '$1=="lump_pool.lump_pool_v3.spend"{print $2}' "$expected")
  if [ -n "$rec" ] && [ "$rec" = "$want_pool" ]; then
    echo "  ok        pool hash recomputed from compiledCode (blake2b-224, V3 tag)"
  else
    echo "  MISMATCH  pool hash recomputed = $rec"
    echo "            expected                = $want_pool"
    echo "            The blueprint's own 'hash' field and an independent"
    echo "            blake2b-224 over the bytes disagree, or the pin is stale."
    bad=1
  fi

  if [ "$bad" = "0" ]; then
    echo "  HASH GATE PASSED"
    return 0
  fi
  echo "  HASH GATE FAILED"
  return 1
}

if [ "$CMD" = "hashes" ]; then
  verify_hashes
  exit $?
fi

# Private temp files. A fixed /tmp path is something another user on the machine
# can pre-create as a symlink, which would redirect these writes.
LOG="$(mktemp "${TMPDIR:-/tmp}/aikcheck.XXXXXXXX")" || exit 1
CLEAN="$(mktemp "${TMPDIR:-/tmp}/aikcheck.XXXXXXXX")" || exit 1
trap 'rm -f "$LOG" "$CLEAN"' EXIT

if script -qfec true /dev/null >/dev/null 2>&1; then
  script -qfec "NO_COLOR=1 $AIKEN $CMD" "$LOG" >/dev/null 2>&1
  RC=$?
else
  NO_COLOR=1 "$AIKEN" "$CMD" >"$LOG" 2>&1
  RC=$?
fi
sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$LOG" > "$CLEAN"
if grep -q "Error\|error:" "$CLEAN"; then
  cat "$CLEAN"
else
  grep -E "FAIL|Summary|tests \|" "$CLEAN"
fi

if [ "$CMD" = "build" ] && [ "$RC" = "0" ]; then
  verify_hashes || RC=1
fi

exit $RC
