# F1 — Diversified-address linkability via vk-only secret derivation

- **File:** `F1-diversified-address-linkability.md`
- **Violated invariant:** `f1_diversifierUnlink` (`ZecLight.qnt`)
  `¬(advAddr(alice.1) ∧ advAddr(alice.2) ∧ kttOf(alice.1) = kttOf(alice.2))`
- **Finding (PROTOCOL.md §9 F1):** the article says the wallet "derives secrets
  `s, r, dsk` from their viewing key" without specifying the diversifier as an
  input. Under that reading, every diversified address of a wallet shares
  `(G_r, S_r, K_TT, D)`, so any two senders can link the addresses.
- **Model encoding:** scenario flag `divSep = false` makes `base(a) = walletOf(a)`,
  so the constructor terms `KttOf(base)` / `GrOf(base)` are *equal* for
  `alice.1` and `alice.2` — term equality is derived-value equality.

## Trace (scripted run `t_F1_diversifiedLinkable`, passes 10 000/10 000)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(divSep = false, piBinding = true, retainsIndex = true)` | genesis; `alice.1`/`bob.1` registered at `ds1` |
| 1 | `sendTx("p1", "alice.1")` | tx to diversified address #1 in epoch 1; p1 now holds `(K_TT, G_r)` of `alice.1` |
| 2 | `sendTx("p2", "alice.2")` | tx to diversified address #2; p2 holds components of `alice.2` |
| 3 | `senderCollude("p1")` | `advAddr += alice.1` |
| 4 | `senderCollude("p2")` | `advAddr += alice.2` — the two senders compare notes |

**Violating state:**

```
kttOf("alice.1") == kttOf("alice.2")   // KttOf("alice") == KttOf("alice")
grOf("alice.1") == grOf("alice.2")     // GrOf("alice")  == GrOf("alice")
```

The two addresses are linkable *by mere component comparison*; no server or
authority compromise involved. Random simulation (`quint run --invariant
f1_diversifierUnlink`) also finds it (see `raw/f1_diversifierUnlink.txt`).

## Fixed variant holds

`t_F1b_perDiversifierUnlinkable` runs the identical collusion with
`divSep = true` (per-diversifier derivation): the terms differ
(`KttOf("alice.1") ≠ KttOf("alice.2")`), tags differ, addresses stay
unlinkable. No counterexample in 50 000 random runs (`f1b_perDivUnlinkable`).
(Apalache cannot encode the sum-type terms, so this half is
simulation + scripted-run evidence only.)

## Interpretation

Not an attack on the mixing machinery — a **spec bug** (F1/F6 family). The fix
is cheap: derive `s, r, dsk` as domain-separated PRF outputs of
`(vk, diversifier)`. Same root cause links "redundancy addresses" (one per
detection server), since those would share `K_TT` and `D`.
