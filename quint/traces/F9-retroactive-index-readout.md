# F9 — Retroactive full-index readout: retained index + later address leak

- **File:** `F9-retroactive-index-readout.md`
- **Violated invariant:** `p6c_indexPath` (and general `p6c_noCrossDayLink`)
- **Claim (P6, second half):** "after full state leak, attacker can group
  per-day but ... cannot ... connect the groups from different days."
- **Model encoding:** `K_TT` is epoch-independent (`kttOf(a) = KttOf(base(a))`,
  no epoch input), so an address leak yields the tag of *every* epoch at once;
  `retainsIndex = true` models the realistic DS that keeps its full private
  index `T ↦ {C^L}` while processing each epoch. Delegation/query logs and the
  index are never garbage-collected in the default scenario.

## Trace (scripted run `t_F9_retroCrossDayLink`, passes 10 000/10 000)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(true, true, retainsIndex = true)` | genesis |
| 1 | `sendTx("p1", "alice.1")` | epoch 1: alice receives 1 note |
| 2 | `advanceEpoch` | mix of epoch 1; `buckets += (ds1, alice.1, e1, count=1)` |
| 3 | `sendTx("p2", "alice.1")` | epoch 2: alice receives 1 note |
| 4 | `advanceEpoch` | mix of epoch 2; `buckets += (ds1, alice.1, e2, count=1)` |
| 5 | `compromiseDS("ds1")` | *now* the adversary reads the retained index |
| 6 | `senderCollude("p1")` | *now* the address components leak: `advAddr += alice.1` |

**Violating state:**

```
advCountViaIndexAtCompDS(alice.1, 1) = true
advCountViaIndexAtCompDS(alice.1, 2) = true
advCrossDay("alice.1")               = true    // both daily groups connected
advAttrib(alice.1, 1)                = false   // (no MA: counts, not which — P3 intact)
```

Both leaks happen strictly *after* both epochs: nothing was observable in real
time. Confirmed by random simulation (`raw/p6c_indexPath.txt`) and by an
exhaustive Apalache counterexample within 10 steps.

## The countermeasure that does work here

`t_F9_deletionDisciplineHolds` repeats the attack with
`retainsIndex = false` (footnote-1 deletion discipline: index entries die at the
next mix). The retroactive readout of epoch 1 then fails
(`advCountViaIndexAtCompDS(alice.1, 1) = false`, `advCrossDay = false`).

## Interpretation

"Cannot connect the groups from different days" is a **behavioral** property
(index deletion), not a cryptographic one: `K_TT` is a permanent linking
identifier, and the DS necessarily builds the per-epoch index while processing.
A single future leak (one colluding counterparty suffices — every sender holds
the full address) retroactively de-anonymizes *all* retained daily groups.
Deletion cannot be enforced against a live compromise (see F5).
