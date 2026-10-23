# F8 — Delegation scalar x = dsk + PRF^D(K_TT, e) escalates to permanent dsk

- **File:** `F8-delegation-scalar-escalation.md`
- **Violated invariants:** `p6b_limitedDelegation` (primary),
  `p5_bothNeeded` (same trace)
- **Claim (P6, "granular delegation"):** the fallback server "is only granted
  detection authority for a limited number of epochs" — here, exactly epoch 1.
- **Model encoding:** `delegateScalar(a, e, s)` puts `{addr, e, server}` into
  the permanent delegation log. The adversary derives
  `advDskKnown(a) ≜ ∃ deleg(s,a,e) ∈ log: s compromised ∧ a ∈ advAddr`
  (server computes `dsk = x − PRF^D(K_TT, e)` using the leaked components),
  hence `advDstarKnown(a, e') = dsk + PRF^D(K_TT, e')` for **every** e′.

## Trace (scripted run `t_F8_delegationEscalation`, passes 10 000/10 000)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(true, true, true)` | genesis; `alice.1` registered (indexed) at **ds1** |
| 1 | `sendTx("p1", "alice.1")` | epoch 1 — p1 necessarily holds alice's full address |
| 2 | `advanceEpoch` | mix of epoch 1 |
| 3 | `delegateScalar("alice.1", 1, "ds2")` | ds1 down; fallback: ds2 receives x₁ = dsk + PRF^D(K_TT,1) |
| 4 | `compromiseDS("ds2")` | ds2 joins the adversary pool |
| 5 | `senderCollude("p1")` | address components (K_TT!) leak; ds2 computes **dsk = x₁ − PRF^D(K_TT,1)** |
| 6 | `sendTx("p2", "alice.1")` | epoch 2 — victim keeps receiving, delegation long past |
| 7 | `advanceEpoch` | mix of epoch 2 |
| 8 | `compromiseMA("ma1")` | pre-mix ↔ post-mix mapping leaks (retroactively) |

**Violating state:**

```
advDskKnown("alice.1")                     // scalar custody broken: dsk recovered
advDstarKnown("alice.1", 2)                // detection authority for epoch 2...
¬∃deleg(alice.1, 2, ·)                     // ...which was NEVER delegated  → p6b violated
advAttrib("alice.1", 2)                    // exact tx attribution of epoch 2
"ds1" ∉ compDS                             // the victim's indexing DS stayed honest → p5 violated
```

From step 5 on, ds2 can silently trial-decrypt every `C^D` of every epoch,
retroactively and prospectively, with **no further queries** by the victim —
the delegation was a one-time epoch-1 event.

## Sound baseline

`t_P6b_honestDelegationScoped`: same delegation to a compromised ds2 but *no*
address leak (`advAddr = ∅`) — then `advDstarKnown(a, 1) = true` and
`advDstarKnown(a, 2) = false`: the delegation really is epoch-scoped while
`K_TT` stays secret. The escalation needs the colluding sender — and every
sender is a *forced* holder of `K_TT`.

Confirmed by random simulation (`raw/p6b_limitedDelegation.txt`,
`raw/p5_bothNeeded.txt`) and exhaustive Apalache counterexamples within 10
steps. (The random `p5` run also shows a weaker violation shape: attribution of
an address that never registered anywhere, via a delegated epoch + MA.)

## Interpretation

The non-indexed path hands out `dsk + PRF^D(K_TT,e)` — an additive one-time-pad
share whose pad is known to every past sender. One colluding counterparty (or
any future address leak against a server that retained x) strips the pad.
Fixing this needs an epoch-secret that the *server* cannot combine with
`K_TT` (e.g. opaque blinded detection keys, or per-epoch dsk derivations with
wallet-side cooperation), which the protocol does not have. Also breaks P5's
"you need both servers compromised" framing: here the *indexing* DS is honest.
