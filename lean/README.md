# zecbreak — Lean 4 formalization of the attack analysis

Core Lean 4 only (no mathlib). Toolchain: Lean 4.21.0.

Targets the protocol of "Making Zcash Light Wallets Faster and More Private"
(Taylor Hornby, Defuse Security, March 2023), as formalized in `../PROTOCOL.md`.
Findings F1–F9 and the verified non-breaks correspond to the shared campaign
vocabulary; this directory proves their formal cores in an abstract
Dolev–Yao model.

> **Post-review correction (see `../defense/FORMAL-DEFENSE.md`, machine-checked in
> `../defense/vacuity-check.lean`):** the `Derived` knowledge predicate has no
> base-case constructor, so the five break theorems that hypothesize `Derived …`
> (`thm_F2_senderCollusion`, `thm_F2_crossEpochLinkage`, `thm_F2_addrLeakLinkage`,
> `thm_F2_indexReadout`, `thm_F8_dskRecovery`) are vacuously true, as are the
> premise-free F5 theorems. They are modeling scaffolding, not evidence. The
> load-bearing evidence for F2/F8 is `../sim/` + `../quint/` reachability + the
> defense-side algebra verification. The soundness theorems (`thm_Nb/Nc/Nd`),
> `thm_F1_diversifierLink`, and `thm_F4_trilemma` stand as documented below.

## Build

```sh
cd lean
PATH=$HOME/.elan/bin:$PATH lake build
```

Exits 0; prints an axiom audit for every theorem (via `#print axioms` in
`src/Zecbreak.lean`).

## Layout

| File | Contents |
|---|---|
| `src/Model.lean` | Opaque identifiers, symbolic `Value` term algebra, protocol derivations (`ktt`, `gr`, `TagOf`, `EpochDKey`, diversified variants), the `Derived` adversary-computation closure, `Fact`/`Sem` vocabulary, `indexHas`/`ServerIndexes` honest-server index, cancellation & tag-injectivity lemmas, and the only two axioms (`piVerified`, `pi_sound`). |
| `src/Breaks.lean` | Formal cores of findings F1, F2, F4, F5, F8. |
| `src/Soundness.lean` | Formal cores of the non-breaks N-b (π base binding), N-c (AD replay block), N-d (dedup). |
| `src/Zecbreak.lean` | Root module + axiom audit of every theorem. |

## Theorems ↔ findings

### Breaks (`src/Breaks.lean`)

| Theorem | Finding | One-line statement |
|---|---|---|
| `thm_F2_senderCollusion` | F2 | Whoever knows `K_TT` and `G_r` (any past sender) computes the victim's tag for *every* epoch: `∀ e, Derived (TagOf w e)`. |
| `thm_F2_crossEpochLinkage` | F2/F3/F9 | From one address, any two epochs' tags are simultaneously computable — per-day detection groups are cross-epoch linked (`groupLinked w e1 e2`). |
| `thm_F2_addrLeakLinkage` | F2 | Same, phrased via the `knowsAddr` fact (`Sem`). |
| `thm_F2_indexReadout` | F2/F9 | With the server's retained index (`indexHas`), every tx ever indexed under the victim's tag — in any epoch — is read out by any address holder. |
| `thm_F8_dskRecovery` | F8 | One delegated scalar `x = dsk + PRF^D(K_TT, e)` plus one sender's `K_TT` yields `dsk` itself, hence the epoch detection key for *every* `e'` — "limited-epoch delegation" fails. Uses the proved cancellation lemma `vAdd_cancel_left` (Model.lean). |
| `thm_F1_diversifierLink` | F1 | Naive viewing-key derivation ignoring the diversifier makes any two diversified addresses of one wallet literally equal (linkable by any common sender; `rfl`). |
| `thm_F1_diversifierLink_decide` | F1 | That linkage is decidable — demonstrated by `decide ... = true` on concrete handles. |
| `thm_F1_kttD_distinct` / `thm_F1_diversifiedDistinct` | F1 (fix) | Under the labeled injectivity hypothesis on the derivation PRF, distinct diversifiers give distinct tagging keys / distinct (unlinkable) addresses. |
| `thm_F4_volumeDistinguisher` | F4 | If session volume separates two counts, an explicit recovery function recovers the count from the observation. |
| `thm_F4_padding` | F4 | Perfectly count-independent observations force `vol 0 = vol n` for all `n`: zero-receive wallets download worst-case volume. |
| `thm_F4_trilemma` | F4/P1 | Distinguishable-or-padded dichotomy: no third option; P1 "learns nothing" forces worst-case padding. |
| `thm_F5_ipLink` | F5 | Same network identity querying two epochs' tags ⇒ server links the per-day groups (`ServerLinksEpochs`). |
| `thm_F5_liveMerge` | F5 | Same, as a server-level group merge (`ServerMerges`). |
| `thm_F5_linksIpWallet` | F5 | Same hypotheses realize the `linksIpWallet` fact of the vocabulary. |

### Non-breaks (`src/Soundness.lean`)

| Theorem | Non-break | One-line statement |
|---|---|---|
| `thm_Nb_piBindsBase` | N-b (P8) | Under π-soundness, a context whose `epk` base ≠ the victim's `G_r` can never be π-indexed under the victim's tag — the sender→server identification oracle is blocked. |
| `thm_Nb_oracleBlocked` | N-b | `¬ ∃ ctx, epkBase ctx.epk ≠ gr w ∧ ServerIndexes ctx (TagOf w e) e`. |
| `thm_Nc_adBlocksReplay` | N-c | A pre-mix ciphertext from epoch `e` fails the AD check `"mix"∥e'` for any `e' ≠ e` (constructor equality). |
| `thm_Nc_replayRejected` | N-c | Same via the `acceptedAt` predicate. |
| `thm_Nd_dedup` | N-d | Re-encrypting an already-present post-mix value `k` extra times leaves the deduplicated list unchanged (`dedup (l ++ rep x k) = dedup l`). |
| `thm_Nd_noMultiplicity` / `thm_Nd_lengthInvariant` | N-d | Any two repetition counts give identical lists / identical lengths — no multiplicity signal. |

## Axioms (the only ones; both declared in `src/Model.lean`)

- `piVerified : Value → Value → Epoch → Prop` — opaque verifier *interface*
  constant for the sender proof π.
- `pi_sound` — **IDEAL-CRYPTO ASSUMPTION**: ZK soundness of π ("same-base
  binding"): any verifying `(T, epk)` satisfies `T = PRF^T(K_TT, b, e)` and
  `epk = [esk] b` for the *same* base `b`.

All other security properties are modeled *structurally*: `H`, `GroupHash`,
`PRF^T`, `PRF^D`, `PRF^S`, `Enc` are opaque constructors with no inversion
rules in the `Derived` closure (hash/PRF/PKE security, key privacy), and
scalar addition is cancellative (`vAdd_cancel_left/right`, proved), which is
what licenses the adversary's subtraction rules `Derived.cancelL/cancelR`.

Axiom audit (from the build log):

- Every F1/F2/F4/F5/F8 break theorem and every N-c/N-d non-break theorem is
  axiom-free, except `thm_Nd_*` (standard `propext` from core list lemmas).
- `thm_F2_addrLeakLinkage`, `thm_F2_indexReadout`, `thm_F5_linksIpWallet`
  list `piVerified` only because their statements go through the `Sem` /
  `indexHas` vocabulary, whose *definition* mentions the verifier interface;
  the axiom is not used in any of those proofs.
- `thm_Nb_*` use `piVerified` + `pi_sound` — exactly the protocol's own
  assumption being leveraged, never the conclusion.

## Modeling notes / compromises

- **Symbolic, not computational.** Values are terms; "adversary can compute"
  is the inductive closure `Derived`. Real-world runtime/probabilistic
  arguments are out of scope; each theorem's hypotheses name the concrete
  collusion (e.g. "any past sender knows `K_TT`, `G_r`").
- **Free addition.** `+` on scalars is a free binary constructor, so
  cancellation (`vAdd_cancel_left/right`) is provable and subtraction is
  uniquely determined — this is what F8 needs; no other algebra is assumed.
- **Tag/`K_TT` injectivity** holds definitionally (constructor injectivity of
  `PRF^T`/`H`), the symbolic stand-in for collision resistance.
- **F1's fix is conditional** on the labeled hypothesis `hinj` (symbolic PRF
  domain separation), as the task requires; the naive-derivation break is
  unconditional (`rfl`).
- **F4** treats the session-volume function `vol` as a parameter and proves
  both trilemma directions for arbitrary `vol`; the link to concrete padding
  schemes (packet counts, session duration) is informal.
- **F5** models π_query soundness as: valid queries are always tied to an
  honest (wallet, tag) pair (`QueriesTag`); the linkage itself is the
  same-IP observation, which the server merges deterministically.
- `rep` is a local `List.replicate` stand-in (avoids core-API naming churn).
- `Sem (observesVolume)` is `True` (reserved vocabulary); volume is analyzed
  in `thm_F4_*` with the volume function as an explicit parameter.
