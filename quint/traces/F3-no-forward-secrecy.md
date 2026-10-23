# F3 — No forward secrecy of K_TT (future address leak links past epochs)

- **File:** `F3-no-forward-secrecy.md`
- **Violated invariant:** `p6c_noCrossDayLink` / `p6c_indexPath` — same trace as
  F9; this file records the *forward-secrecy* reading of it.
- **Claim (P6):** "... cannot ... connect the groups from different days."
- **Root cause:** `K_TT = H(s)` is derived once and never changes; the tag of
  epoch e is `TagOf((KttOf(base), GrOf(base), e))` — the epoch is mixed in by
  the PRF, but `K_TT` itself is a stable cross-epoch identifier in the
  adversary's hands the moment the address leaks.

## Trace

Identical to the F9 trace (see `F9-retroactive-index-readout.md`): the address
leak at step 6 is *voluntary and late* — the wallet may have considered epochs
1–2 long past. Because `kttOf(a)` has no epoch (or time) input, the adversary
computes `tagOf(a, e)` for **every past epoch** and reads each epoch's group
out of any retained index or live server state.

The scripted run `t_F9_retroCrossDayLink` demonstrates exactly the "future
leak, past epochs" order: epochs close first (steps 2 and 4), compromise and
leak happen last (steps 5–6), and `advCrossDay("alice.1")` still becomes true.

## Deletion-discipline caveat

With `retainsIndex = false` the *retained-index* readout is blocked
(`t_F9_deletionDisciplineHolds`). That is a mitigation of the F9 channel only:
F3 is about `K_TT` itself. Any *live* server state that ever saw a tag
(a query log entry, a delegated scalar) is equally linkable across epochs, and
nothing in the protocol expires `K_TT`. The article's footnote-1 deletion
discipline is a behavioral assumption, not cryptography.

## Interpretation

Forward secrecy would require per-epoch secrets (e.g. `K_TT,e =
H(s, e)`), which conflicts with the address being static and the sender
needing to compute tags offline from a published address. The protocol as
specified therefore offers no forward secrecy for daily groups; P6's
cross-day-unlinkability clause survives only under the deletion discipline and
only against non-live adversaries.
