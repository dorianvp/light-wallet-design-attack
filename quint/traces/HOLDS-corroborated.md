# HOLDS — corroborated sound parts (no counterexample found)

Evidence per property: scripted near-miss runs (`ZecLightTests` module), random
simulation (`quint run`, 50 000 samples each), and — except where sum-type
terms block Apalache — exhaustive bounded proof (`quint verify`, ≤ 10 steps).

| Property | Scripted demo | Random sim (50k) | Apalache (≤10 steps) |
|---|---|---|---|
| `p3_countsNotWhich` — attribution needs an MA | `t_P3_countsNotWhich` | no CEX | **proved** |
| `p4_maAloneLearnsNothing` — MA alone learns nothing | (vacuous-guard demo) | no CEX | **proved** |
| `p6a_granularCrypto` — indexed path epoch-scoped | `t_P6a_granularIndexed` | no CEX | **proved** |
| `p8b_bindingBlocks` — π binding kills the oracle | `t_P8_bindingBlocksOracle` | no CEX | **proved** |
| `mixSoundness` — dedup + AD block replays | `t_mix_replaysBlocked` | no CEX | **proved** |
| `f1b_perDivUnlinkable` — per-div derivation unlinkable | `t_F1b_perDiversifierUnlinkable` | no CEX | n/a (sum types) |
| footnote-1 deletion vs F9 readout | `t_F9_deletionDisciplineHolds` | — | — |
| honest delegation is epoch-scoped | `t_P6b_honestDelegationScoped` | — | — |

## Notes and honest caveats

- **`p3_countsNotWhich`** (`advAttrib ⇒ compMA ≠ ∅`): in the model, attribution
  is *by construction* only reachable through the pre-mix↔post-mix mapping, so
  Apalache's proof corroborates that no *other modeled channel* (index, dsk,
  queries, traffic) pins transactions. The conceded half of P3 (counts without
  an MA) is real and demonstrated by `t_P3_countsNotWhich` — see F2.
- **`p4_maAloneLearnsNothing`**: with `compDS = advAddr = ∅`, no knowledge
  predicate can fire — the MA's mapping alone is useless, as the article
  claims. Tautology-adjacent in the model, but it pins the boundary: *one* MA
  compromise is harmless **only while nothing else leaks**.
- **`p6a_granularCrypto`**: `T = TagOf((Ktt, Gr, e))` is epoch-separable
  (`t_P6a_granularIndexed` also asserts `tagOf(a,1) ≠ tagOf(a,2)`), and no
  derivation rule connects tags across epochs, so a compromised server's
  *cryptographic* detection is confined to queried epochs. The claim dies at
  the network layer instead (F5) and via retained state (F9).
- **`mixSoundness`**: holds *by construction of the abstraction* — only
  `advanceEpoch` writes `postmix`, always as the canonical deduplicated set;
  the replay actions (`replayRepitition`, `replayCrossEpoch`) are no-ops beyond
  a counter. This encodes N_c/N_d (dedup blocks repetition tagging, AD
  `"mix"||e` blocks cross-epoch replay) rather than testing them.
- **`f1b_perDivUnlinkable`** could not be given to Apalache: the 0.62.1
  translation rejects sum-type constructor terms (`TagOf((KttOf(Str), ...))`),
  so this half is simulation-level only.
