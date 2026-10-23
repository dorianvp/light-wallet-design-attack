# F7 — Malicious DS silently withholds notes (liveness/completeness break)

- **File:** `F7-liveness-completeness.md`
- **Violated invariant:** `p10_noSilentDrop` (`withheld = ∅`)
- **Claim (P10):** "Wallets receive (and authenticate) all their notes via DS."
- **Model encoding:** `dsWithhold(s, a, e)` — a compromised DS that holds a
  non-empty bucket for `(a, e)` may answer a query with a strict subset of the
  indexed `C^L`. The wallet *authenticates* what it gets (injected/forged notes
  fail the note-commitment check — modeled by `mixSoundness` holding and by
  there being no action that fabricates a valid note), but authentication says
  nothing about *completeness*.

## Trace (scripted run `t_F7_withhold`, passes 10 000/10 000)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(true, true, true)` | genesis |
| 1 | `sendTx("p1", "alice.1")` | epoch 1: alice receives 1 note |
| 2 | `advanceEpoch` | mix; ds1 index: `T(alice.1,1) ↦ {C^L}` |
| 3 | `compromiseDS("ds1")` | ds1 malicious |
| 4 | `dsWithhold("ds1", "alice.1", 1)` | the epoch-1 answer drops the note |

**Violating state:** `withheld = {(ds1, alice.1, 1)}` — the wallet's fast path
returns nothing for an epoch in which it received funds. Balance appears lost
until a full rescan via trial decryption (`§7.1`), which is exactly the
expensive operation the light-wallet design exists to avoid.

Confirmed by random simulation (`raw/p10_noSilentDrop.txt`) and an exhaustive
Apalache counterexample within 10 steps.

## Interpretation

Detection is a *service*, not a protocol guarantee: the DS can censor
selectively per (tag, epoch) with zero cryptographic trace. The MA-side twin
(injecting post-mix entries) is the weaker form — injection fails note
authentication at the wallet but still inflates per-tag bucket counts (count
pollution), which the model separates from validity: forged entries never
produce tx records, so `mixSoundness`/authentication hold while the *count*
channel (F4) gets noisier. Mitigation would need the wallet to cross-check DS
answers against the signed post-mix lists (k-anonymity style proofs of
completeness), which the design does not include.
