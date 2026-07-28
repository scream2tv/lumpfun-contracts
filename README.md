# LumpFun v3 Contracts

The Aiken smart contracts behind [LumpFun](https://www.lumpfun.com) (token
launches on a bonding curve) and [LumpSwap](https://swap.lumpfun.com) (trading
for graduated pools), deployed on Cardano **mainnet**.

This repository exists so anyone can verify that the scripts holding user funds
are exactly the code published here. Nothing in it is required to *use* the
protocol — it is the source of truth for what the protocol *is*.

## Design

One pool validator serves a token's entire life. A launch mints the token's
whole supply plus a 1-of-1 pool NFT under a **one-shot** minting policy and
seats 100% of both in a genesis pool UTxO:

- **Bootstrap** — the bonding-curve phase. Constant-product pricing over
  virtual reserves, 8,000 → 64,000 ADA FDV.
- **Graduate** — a permissionless, one-way, in-place flip. The pool UTxO stays
  where it is; only `mode` and the token-reserve rebase change. The measured
  mainnet price gap across graduation is **+0.0000161%**.
- **Amm** — a permanent constant-product AMM on the real reserves (offset 0 on
  both sides). **Liquidity is locked for life: no withdraw redeemer exists.**

Fees (1% to the creator, 2 ADA flat to the platform) are pinned by the minting
policy at genesis and frozen by the validator on every subsequent spend — they
are compiled constants, not datum fields a launcher can choose.

## Structure

```
validators/lump_pool.ak       pool spending validator — Buy, Sell, Graduate, AmmBuy, AmmSell
validators/minting_policy.ak  one-shot mint — Launch is the ONLY redeemer
lib/lumpfun/params_v3.ak      protocol constants (supply, curve, fees, treasury)
lib/lumpfun/math_v3.ak        bonding-curve arithmetic
lib/lumpfun/fees_v3.ak        fee arithmetic
lib/lumpfun/pool_types.ak     datum / redeemer / pool-NFT types
lib/lumpfun/types.ak          shared types
lib/lumpfun/test_helpers.ak   test scaffolding
hashes.expected               the pinned script hashes the build must reproduce
aikcheck.sh                   build + independent hash verification
mutverify.sh                  mutation-testing harness for the test suite
plutus.json                   the committed blueprint (CI artifact of `aiken build`)
```

## Deployed script hashes (mainnet)

| Cohort | Validator | blake2b-224 script hash |
| --- | --- | --- |
| **v3.1** (current — this source) | `lump_pool.lump_pool_v3.spend` | `e81825bb5f0b784e1080a4903ee0472f9d148e07861da83f6aeeef8e` |
| **v3.1** (current — this source) | `minting_policy.lump_mint_v3.mint` (unapplied) | `f1c0f9d9dfa1396118592a8c5fbd8fdc1b578fce8b241a022685c2fd` |
| v3.0 (frozen) | `minting_policy.lump_mint_v3.mint` (unapplied) | `a3a5e6a64460c2690ff8e2276e49242e0f12f6255bdc6667a92adb31` |

The pool validator is **unparameterised**, so every v3 pool for every token
lives at the one shared address derived from the pool hash:

```
addr1w85psfdmtu9hsnssszjfq0hqguhe69ywq7rpm2pldthwlrs8pqvl0
```

v3.0 and v3.1 share **byte-identical pool bytes** — the cohorts differ only in
the minting policy (v3.1 allows the creator's first buy in the launch
transaction itself). Tokens launched under v3.0 keep trading through exactly the
bytes they launched under; a cohort bump costs future policy ids, nothing else.

A token's **policy id** is not the unapplied mint hash: it is the mint validator
applied to `(one_shot_utxo, pool_script_hash)` — the token's seed
`OutputReference` and the pool hash above, in that order — then hashed. Applying
the parameters in the wrong order yields a valid-looking but wrong policy id.

## Building and verifying

Prerequisites: [Aiken](https://aiken-lang.org) **v1.1.17** (the compiler
version is pinned in `aiken.toml`; a different compiler produces different
bytes and different hashes).

```bash
aiken build          # writes plutus.json
./aikcheck.sh build  # build + verify every pin in hashes.expected two ways
```

`aikcheck.sh` compares each pinned hash against the blueprint's own `hash`
field **and** independently recomputes `blake2b-224(0x03 ‖ compiledCode)` from
the emitted bytes — the blueprint's `hash` field was written by the same
compiler run that produced the bytes, so agreeing with it alone proves nothing.

To verify a specific token, apply the mint parameters yourself:

1. Take the token's seed `OutputReference` (the UTxO consumed at launch).
2. Apply `(seed, e81825bb…)` to the unapplied `lump_mint_v3` CBOR from
   `plutus.json`.
3. `blake2b-224(0x03 ‖ appliedCbor)` is the token's policy id. The pool NFT is
   that policy id with asset name `000643b0504f4f4c` (CIP-67 label 100 +
   `"POOL"`), and the authentic pool is the UTxO at the shared address holding
   that NFT.

Do **not** identify a pool as "the UTxO at the pool address holding token X" —
the address is shared, so anyone can seat a decoy UTxO there. Authenticate by
the pool NFT, recomputed from the seed. LumpFun's own clients enforce exactly
this rule.

## Protocol parameters

| Constant | Value |
| --- | --- |
| `total_supply_v3` | 1,000,000,000 (0 decimals, fixed for life — the mint is one-shot) |
| `virtual_ada_v3` | 9,142,857,144 lovelace |
| `virtual_token_v3` | 1,142,857,143 |
| `token_offset_v3` | 142,857,143 |
| `sellable_v3` | 738,796,125 (curve-phase float) |
| `pool_bag_v3` | 261,203,875 (pre-allocated; becomes the permanent AMM liquidity) |
| `pool_floor_v3` | 2,500,000 lovelace (min-UTxO the pool always retains in Bootstrap) |
| `creator_fee_bps_v3` | 100 (1%, every trade, both phases, forever) |
| `platform_fee_bps_v3` | 0 |
| `platform_fee_flat_v3` | 2,000,000 lovelace per trade |

Launch FDV is 8,000 ADA; the curve completes at 64,000 ADA FDV with roughly
16,717 ADA raised, all of which is locked in the pool at graduation.

## Testing

```bash
aiken check       # the full unit + property + adversarial suite
./mutverify.sh    # mutation testing: mutates the validators and requires the suite to notice
```

The suite includes adversarial reject tests for every redeemer path (decoy
NFTs, fee omissions, datum lies, reference-script welding, cross-mode quoting,
zero-value no-ops), and the mutation harness exists because a test suite that
cannot detect a mutated validator proves nothing about the real one.

## Security model, briefly

- **One-shot supply.** The only mint redeemer requires consuming the seed UTxO,
  which can happen once. Total supply and the 1-of-1 pool NFT are immutable for
  life; there is no burn handler.
- **Genesis is validated on chain.** `pool_seeded` requires the entire supply
  and the NFT seated in a genesis pool whose datum matches the output's real
  value — free allocations are structurally impossible; every token outside the
  pool was bought on the curve at the same quote anyone gets.
- **Nothing is trusted from a datum or redeemer** where the UTxO's address and
  value can prove it. Quotes are recomputed on chain.
- **No withdraw path.** Graduated liquidity is locked in the pool forever.
- **Fees are compiled in.** A different fee schedule is a different script hash
  — visibly a different protocol.

## Audit status

These contracts have **not** received a third-party audit. They have been
through repeated internal adversarial review, a mutation-tested suite, and full
lifecycle rehearsals on mainnet (launch → trade → graduate → AMM trade) before
public launch. Read the source and judge for yourself — that is what this
repository is for.

## License

[GPL-3.0](LICENSE)
