// ── LumpFun v3 — shared on-chain types ───────────────────────────────────────
//
// v3 is a FORK, not an evolution (§8.1). Everything v2 carried here that v3 does
// not have is deliberately absent, not "not yet ported":
//
//   • `CurveDatum` / `CurveRedeemer` — the v1 bonding_curve is frozen forever.
//   • `OrderAction` / `OrderDatum` / `OrderRedeemer` — v3 has NO ORDER BOOK.
//     Deleting it deletes D-2's whole defect class ("orders against a graduated
//     pool"), the R-1/R-2 gross-volume fee reconstruction, and `fee_accumulator`
//     (§5.6).
//
// The pool datum and redeemer live in `lumpfun/pool_types`.

/// Redeemer for `lump_mint_v3` (§5.2).
///
/// ══════════════════════════════════════════════════════════════════════════════
/// ONE CONSTRUCTOR. LAUNCH ONLY. THERE IS NO BURN PATH AT ALL.
/// ══════════════════════════════════════════════════════════════════════════════
///
/// `Retire` — which burned the 1-of-1 pool NFT at graduation — WAS DELETED on
/// 2026-07-26 when the Splash venue was parked. v3 graduates by flipping the pool
/// datum IN PLACE, so the pool UTxO survives graduation and the NFT keeps
/// authenticating it for the life of the token. There is nothing to retire.
///
/// This is a STRICTLY STRONGER C-1 property than the version with `Retire`:
/// previously "curve supply is untouchable" was an argument about `Retire` being
/// satisfiable exactly once (the NFT is 1-of-1 and the burn destroys it), which is
/// a three-script argument spanning `lump_mint_v3`, `lump_pool_v3.pool_nft_kept`
/// and the ledger's value-conservation rule. Now it is a ONE-LINE STRUCTURAL fact:
/// the only handler in the policy requires the one-shot seed UTxO in an input, that
/// UTxO is consumed at launch and can never be consumed again, and no other handler
/// exists. Total supply is provably immutable at `total_supply_v3` for life, and
/// the pool NFT count is provably immutable at 1.
///
/// A single-constructor enum still encodes as `Constr(0, [])`, so the wire form of
/// `Launch` is unchanged and no off-chain builder has to move.
pub type MintRedeemer {
  /// Token creation, and the only thing this policy will ever do. Mints exactly
  /// `total_supply_v3` of the curve token plus exactly one `pool_nft_name`,
  /// consumes the one-shot seed UTxO, and seats 100% of supply in a
  /// correctly-formed pool UTxO at the pinned pool address.
  Launch
}
