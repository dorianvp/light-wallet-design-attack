# F4 — Session volume/duration leaks exact received counts (P1 break)

- **File:** `F4-volume-duration-leak.md`
- **Violated invariant:** `p1_noCountLeak` (`gpaCount = ∅`)
- **Claim (P1):** "GPA observing encrypted traffic learns *nothing* about
  when/how many transactions the wallet receives."
- **Model encoding:** `queryTag` / `delegateScalar` answers are delivered "using
  a constant-bandwidth protocol (fixed-size packets at regular intervals)" —
  the *number* of packets (= session duration and total volume) is proportional
  to the bucket size, so each such action records an observation
  `{wallet, e, count}` in `gpaCount`.

## Trace (scripted run `t_F4_p1_countLeak`, passes 10 000/10 000)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(true, true, true)` | genesis; `alice.1`, `bob.1` registered at `ds1` |
| 1 | `sendTx("p1", "alice.1")` | epoch 1: alice receives 2 notes total |
| 2 | `sendTx("p2", "alice.1")` |  |
| 3 | `sendTx("p1", "bob.1")` | bob receives 1 note |
| 4 | `advanceEpoch` | mix of epoch 1; `ds1` index: `T(alice.1,1) ↦ 2`, `T(bob.1,1) ↦ 1` |
| 5 | `queryTag("alice.1", 1, "ds1")` | π_query OK; answer = 2 packets. GPA records `{alice, 1, 2}` |
| 6 | `queryTag("bob.1", 1, "ds1")` | GPA records `{bob, 1, 1}` |

**Violating state:**

```
gpaCount = { {wallet: "alice", e: 1, count: 2}, {wallet: "bob", e: 1, count: 1} }
```

The GPA distinguishes 2 vs 1 notes *exactly*, and the query time also reveals
*when* the wallet cared about epoch 1. Confirmed by random simulation
(`raw/p1_noCountLeak.txt`: found after ~500 traces; there the leak even happens
via `delegateScalar` on the non-indexed path) and by an exhaustive Apalache
counterexample within 10 steps.

## Interpretation

Encryption hides *content*, not *length*. Padding to the worst case (max bucket
size, every epoch, every user) would restore P1 but destroys the performance
goal — the article's own trilemma paragraph concedes the tension; the headline
claim P1 ("learns nothing") is false as stated. Any network observer
(not just the DS) gets the counts.
