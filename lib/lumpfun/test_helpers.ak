// ── Shared mock-transaction constructors for v3 validator spend-path tests ────
//
// Validator handlers can only be called from within their own module, so the
// accept/reject tests live inside each validator file. These builders keep those
// tests terse: a test then only has to express the ONE thing it mutates away
// from the happy path.
//
// Ported structurally from contracts/cardano/lib/lumpfun/test_helpers.ak. NO
// ARITHMETIC IS PORTED — every number in a v3 test is re-derived from
// params_v3, because a v2 constant that happens to compile makes a reject test
// pass for the wrong reason.

use cardano/address.{Address, Credential}
use cardano/assets.{Value}
use cardano/transaction.{InlineDatum, Input, NoDatum, Output, OutputReference}

/// A UTxO reference from a short tag and an index (length is irrelevant to the
/// validators — they compare references by equality only).
pub fn oref(tag: ByteArray, ix: Int) -> OutputReference {
  OutputReference { transaction_id: tag, output_index: ix }
}

/// value = only lovelace.
pub fn ada(lovelace: Int) -> Value {
  assets.from_lovelace(lovelace)
}

/// value = lovelace + `qty` of a single native asset.
pub fn ada_token(
  lovelace: Int,
  policy: ByteArray,
  name: ByteArray,
  qty: Int,
) -> Value {
  assets.from_lovelace(lovelace) |> assets.add(policy, name, qty)
}

/// An output at a BARE (enterprise) script address carrying an inline datum.
/// v3's `pool_seeded` requires the pool address have no stake credential, so
/// this is the shape a genuine pool output has.
pub fn script_out(script_hash: ByteArray, value: Value, datum: Data) -> Output {
  Output {
    address: address.from_script(script_hash),
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// A script output WITH a stake credential attached — used to prove
/// `pool_seeded` rejects a delegated pool address (whoever sets the stake part
/// at launch keeps it for the life of the pool, and would earn staking rewards
/// on ~16,717 ADA of other people's money).
pub fn script_out_staked(
  script_hash: ByteArray,
  stake_hash: ByteArray,
  value: Value,
  datum: Data,
) -> Output {
  Output {
    address: Address {
      payment_credential: Credential.Script(script_hash),
      stake_credential: Some(
        address.Inline(Credential.VerificationKey(stake_hash)),
      ),
    },
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// An output paying a verification-key (wallet) address `lovelace`, no datum.
pub fn pk_out(pkh: ByteArray, lovelace: Int) -> Output {
  Output {
    address: address.from_verification_key(pkh),
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

/// An output paying a verification-key address `lovelace` + `qty` of one token.
pub fn pk_out_token(
  pkh: ByteArray,
  lovelace: Int,
  policy: ByteArray,
  name: ByteArray,
  qty: Int,
) -> Output {
  Output {
    address: address.from_verification_key(pkh),
    value: ada_token(lovelace, policy, name, qty),
    datum: NoDatum,
    reference_script: None,
  }
}

/// Wrap an output as a resolved input at `ref`.
pub fn input_of(ref: OutputReference, out: Output) -> Input {
  Input { output_reference: ref, output: out }
}
