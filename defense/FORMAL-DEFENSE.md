# FORMAL-DEFENSE — adversarial audit of the formal artifacts

Referee: formal-methods audit, 2026-10-23. Scope: `lean/` (Model, Breaks, Soundness,
Zecbreak), `quint/ZecLight.qnt` + `quint/VERIFICATION.md` + `quint/traces/`, and the
"Confirmed by" citations in `../FINDINGS.md`. Everything below was re-executed where
feasible: `lake build` passes (replayed, axiom audit output reproduced),
`quint test --match '^t_'` = 17/17 pass, `quint verify --invariant p1_noCountLeak`
re-finds the counterexample live (5.0 s), `verify-results/*.json` statuses match
VERIFICATION.md's table. A machine-checked vacuity proof for the central Lean finding
is included as `vacuity-check.lean` (this directory; compiles clean via
`cd lean && PATH=$HOME/.elan/bin:$PATH lake env lean ../defense/vacuity-check.lean`).

---

## 0. Executive verdict

1. **The Lean "break" theorems about adversary derivations (F2 ×4, F8) are vacuously
   true.** The Dolev-Yao closure `Derived` has **no base-case constructor**: every
   constructor demands a prior `Derived` premise, so `¬ Derived v` is provable for
   every `v` (proved in `vacuity-check.lean`). Every theorem hypothesizing
   `Derived (ktt w)`, `Derived (EpochDKey w e)`, or `Sem (Fact.knowsAddr w)` assumes
   a false premise and proves its conclusion by explosion. The intended reading
   ("hypotheses = granted knowledge") is not what the statements say.
2. **The F5 Lean theorems are free of content in the dual way**: `QueriesTag` has a
   premise-free constructor, so `ServerLinksEpochs`/`ServerMerges` are unconditionally
   true — the "attack" cannot fail in the model (`vacuity-check.lean`, bottom two
   examples).
3. **Most Quint "violated" verdicts are violated-by-construction or
   definitional-inference + reachable-preconditions**; only the multi-step orderings
   (F8 escalation, F9 retroactive readout) carry real model-checking content, and
   that content is *precondition reachability*, not attack validity.
4. **All six Apalache "proved" (holds) results are tautological or near-tautological
   in the model** — `p3`, `p4`, `p6a` are propositional consequences of the knowledge
   predicates' definitions; `p8b` and `mixSoundness` are by-construction; `v_f1b_divInputsDiffer`
   literally proves `st.divSep ⇒ "alice.1" ≠ "alice.2"` (a string inequality).
   VERIFICATION.md §4 admits most of this; FINDINGS.md does not carry the caveat.
5. **No formal artifact proves anything cryptographic.** All crypto appears either as
   *absence of inversion rules* (Lean) or as *definitions of the adversary's knowledge*
   (Quint). Nothing needs crypto: every "break" runs entirely on public-evaluation
   (forward) rules, so the symbolic proofs were never going to be hard — the entire
   epistemic weight rests on the **interpretive modeling decisions** (does the article's
   derivation really ignore diversifiers? do senders really hold `K_TT`? is volume
   really proportional to count?), which are exegesis, not theorems.
6. The **honest core** that survives: Quint's reachability results for multi-step
   attacks and the honest baselines (`t_F9_deletionDisciplineHolds`,
   `t_P6b_honestDelegationScoped`); Lean's `thm_Nb_*` (a clean conditional under the
   labeled `pi_sound` axiom), `thm_Nd_*` (genuine elementary list lemmas), and
   `thm_F1_diversifierLink` (an honest `rfl` that makes the naive-derivation reading
   vivid). VERIFICATION.md's own §4/§6 caveats are unusually candid and are, on
   re-audit, accurate — the problem is FINDINGS.md's citations outrun them.

---

## 1. LEAN — theorem-by-theorem

Classification key: **[S]** substantive, **[D]** definitional/unwrapping (true by
construction of the definitions), **[T]** trivial, **[V]** vacuous (hypotheses
unsatisfiable), **[A]** axiom-carried.

Build: passes. Axiom audit (reproduced) contradicts `Zecbreak.lean`'s own header
comment ("The break theorems (F*) and N-c/N-d use NEITHER [axiom]"):
`thm_F2_addrLeakLinkage`, `thm_F2_indexReadout`, `thm_F5_linksIpWallet` all depend on
`Zecbreak.piVerified`. The dependency is definitional contagion (their statements/proofs
unfold `Sem`/`indexHas`, whose other match arms mention `piVerified`) — the axiom's
*content* is not used — but the audit sentence as written is false.

### 1.1 The vacuity defect (the load-bearing finding)

`Derived` (Model.lean L212–227): constructors `hash, groupHash, prfT, prfD, prfS, addV,
cancelL, cancelR, enc, epk` — **every one requires at least one `Derived` premise**.
An inductive family with no zero-premise constructor denotes the empty relation:

```lean
theorem derived_empty (v : Value) : ¬ Derived v   -- proved in defense/vacuity-check.lean
```

Consequences (all mechanically checked in `vacuity-check.lean`):

| Theorem | Hypotheses | Status |
|---|---|---|
| `thm_F2_senderCollusion` | `Derived (ktt w)`, `Derived (gr w)` | **[V]** |
| `thm_F2_crossEpochLinkage` | same | **[V]** |
| `thm_F2_addrLeakLinkage` | `Sem (Fact.knowsAddr w)` = conjunction of `Derived` | **[V]** |
| `thm_F2_indexReadout` | `Derived` pair + `indexHas` | **[V]** |
| `thm_F8_dskRecovery` | `Derived (EpochDKey w e)`, `Derived (ktt w)` | **[V]** |

To be precise about what this does and does not mean:

- It does **not** mean the intended inferences are wrong. "From `ktt`, `gr` one
  computes every epoch's tag" and "from `x = dsk + PRF^D(K_TT,e)` and `K_TT` one
  computes `dsk`" are true statements about the real protocol's *public* algebra.
- It **does** mean the Lean file fails to state them. The intended statement —
  *given* base facts Γ, the closure derives X — requires `Derived` to be
  parameterized by an assumption context (e.g. `inductive Derived (Γ : Value → Prop)`
  with `| hyp (v) (h : Γ v) : Derived Γ v`), then `Derived {ktt w, gr w} (TagOf w e)`.
  As written, the theorems are true *only* because their hypotheses are false, and a
  proof of e.g. `thm_F2_senderCollusion` would go through unchanged even if the
  `prfT` inference rule were deleted from the model — the hallmark of a vacuous
  statement.

### 1.2 The two axioms

- `piVerified : Value → Value → Epoch → Prop` — an opaque interface relation. Harmless
  as a stub; its only assumed property is `pi_sound`.
- `pi_sound` — "π verifies ⇒ ∃ k esk b, T = vPrfT k b e ∧ epk = vEpk esk b". This is a
  faithful symbolic idealization of the article's own relation
  (`T = PRF^T(K_TT, G_r∥e) ∧ epk = [esk]G_r`, same `G_r`). It is doing **all** the
  cryptographic work for `thm_Nb_*` — and that is the *correct* division of labor for
  a symbolic proof: the theorem shows the indexing rule inherits base-binding from
  the (assumed) soundness of π. **But**: it is an axiom, so `thm_Nb_*` proves
  "IF ZK soundness holds in this idealized form, THEN wrong-base ciphertexts are never
  indexed" — it proves nothing about the actual SNARK, and nothing about case (b)
  (`π_query` / GroupHash preimage resistance — absent from Lean entirely).

### 1.3 Per-theorem epistemic assessment

| Theorem | Class | What it actually establishes |
|---|---|---|
| `thm_F2_senderCollusion` | **[V][D]** | Nothing as stated. Intended: the `prfT` rule has no epoch bound — the tag algebra is a *public, epoch-unbounded* function of address components. That observation is real and is the root of F2/F3/F9, but it is visible by reading the `prfT` constructor; the theorem adds explosion on top. |
| `thm_F2_crossEpochLinkage` | **[V][D]** | Same, packaged as `groupLinked` (defined as the conjunction of two `Derived`s — the "linkage" predicate is the hypothesis shape restated). |
| `thm_F2_addrLeakLinkage` | **[V][D]** | `Sem (knowsAddr w)` unfolds to the hypotheses of part 1; pure unwrapping. |
| `thm_F2_indexReadout` | **[V][D]** | `Readout` is defined as `indexHas ∧ Derived` — the conclusion IS the hypotheses repackaged through a definitional left-inverse. No theorem shows the index gets *built* or that the readout is *attainable*. |
| `thm_F8_dskRecovery` | **[V][D]** | The cancellation lemma `vAdd_cancel_left` is constructor injectivity of a free binary constructor — definitional (`injection`). The adversary's right to subtract (`Derived.cancelL`) is *assumed as an inference rule* — a sound assumption about real scalar arithmetic, but it means the "algebra proved" is: *the model was given the rule that makes the attack work, then the attack works* (vacuously, per §1.1). The nontrivial real-world content — `PRF^D` deterministic and publicly computable from `K_TT`, `K_TT` sender-known, delegation scalar handed over verbatim — is all hypothesis or definition. |
| `thm_F1_diversifierLink` | **[D]** (not vacuous — no hypotheses) | `rfl`: a function ignoring `d` returns equal values. Genuinely proves *the naive-derivation reading yields identical sender-visible tuples* — and nothing about whether the article's prose commits to that reading (that is exegesis of "derives secrets from their viewing key"). Honest and vivid, but a one-line definitional fact. |
| `thm_F1_diversifierLink_decide` | **[T]** | `rfl` on concrete numerals. |
| `thm_F1_kttD_distinct`, `thm_F1_diversifiedDistinct` | **[D]** | Constructor-injectivity unwrapping of the *hypothesis* `hinj` (derivation injectivity = the symbolic PRF-domain-separation assumption). Shows the fix works at term level *given* injectivity; does not prove injectivity (correctly not claimed). |
| `thm_F4_volumeDistinguisher` | **[T]** | Elementary lemma about an *arbitrary* function `vol : Nat → Nat`: injective on two points ⇒ explicit partial inverse on those two points. Zero protocol content: no theorem connects `vol` to sessions, packets, or the DS. The protocol mapping exists only in prose. |
| `thm_F4_padding` | **[T]** | `hconst 0 n` — instantiating a ∀. |
| `thm_F4_trilemma` | **[T]** | `by_cases` on decidable equality of two naturals, i.e. excluded middle on `vol n1 = vol n2`, packaging the two lemmas. As a "trilemma" it is a dressed-up tautology; the *interesting* claim (P1 forces the second disjunct) is interpretation, not proved — nothing in Lean says the protocol's `vol` satisfies either disjunct. |
| `thm_F5_ipLink`, `thm_F5_liveMerge`, `thm_F5_linksIpWallet` | **[T]** | `QueriesTag.mk` has no premises, so all hypotheses are free and — stronger — the *conclusions* are unconditionally true (checked in `vacuity-check.lean`). The model cannot express the mitigation (fresh network identity per epoch), so the "attack" is a packaging convention, not a result. |
| `thm_Nb_piBindsBase`, `thm_Nb_oracleBlocked` | **[A][S−]** | The closest thing to a real theorem: under `pi_sound`, a wrong-base context cannot be indexed under the victim's tag. All crypto is in the axiom; the proof contributes quantifier juggling plus `vPrfT`-injectivity (which is where "same base" becomes contradiction with `hnb`). Legitimate symbolic-security shape, correctly labeled as an assumption in Soundness.lean — but its evidential value is exactly the value you assign the axiom. |
| `thm_Nc_adBlocksReplay`, `thm_Nc_replayRejected` | **[D]** | `decryptsAD` is *defined* as AD-equality; the theorem is constructor-injectivity on `vAdMix`. The AEAD fidelity (real AEAD rejects wrong AD) is the idealization. Tautological wrt the definition; value = documentation. |
| `thm_Nd_dedup` (with `memB_iff`, `dedupAux_snoc`, `dedup_rep`) | **[S−]** | The only place Lean does real inductive work: an implemented dedup over lists, with a genuine key lemma (`dedup_snoc`) and induction on repetition count. Content: if one honest copy is present, `k` adversarial duplicates leave the published list unchanged. Elementary, but honest proof obligations. The protocol mapping ("post-mix list = dedup of opened values") is definitional; note the abstraction silently assumes the attacker's fresh re-encryptions decrypt to the *same* term `x` — true in the real protocol (same plaintext), but assumed, not derived. |
| `payloadTag_postMix`, `epkBase_epk` | **[T]** | `rfl`. |

### 1.4 Answer to the audit's direct question

**Does any Lean theorem prove something FINDINGS needs crypto for? No.**

- Every F* theorem uses only *forward* (public evaluation) inference; the ideal-crypto
  assumptions exist in the model as *absence of inversion rules* and are never
  exercised — no break theorem needs to invert `H`, `PRF`, or `Enc`. So the symbolic
  proofs were never carrying cryptographic weight; they carry (at best) structural
  bookkeeping.
- The attack *works* in the informal sense only under hypotheses (`Derived (ktt w)`,
  etc.) whose attainability Lean never establishes — attainability is either a
  definitional fact about "address" (senders hold it because it is the address:
  argued in prose, modeled directly in Quint's `senderCollude`) or an assumed leak.
  What Lean proves is at most: *IF you grant the inference rules and the knowledge,
  THEN the adversary infers* — and per §1.1, currently not even that.

---

## 2. QUINT — invariant-by-invariant

Classification key: **[XC]** violated-by-construction (an adversary action's effect is
literally the violation; the invariant could not hold in any run where the action is
enabled); **[XF]** falsifiable-in-model (the adversary could have failed — real
model-checking content, even if the final inference step is definitional);
**[PV]** proved-but-vacuous (unfalsifiable for boring reasons — the invariant is a
propositional consequence of the definitions); **[BC]** by-construction hold.

The model's shape matters for all of this: adversary "knowledge" is not accumulated by
inference steps but *defined* as deterministic predicates (`advDskKnown`, `advCount`,
`advAttrib`, …) over base facts (`advAddr`, `compDS`, `compMA`, `deleg`, `queries`,
`buckets`). The only thing the state machine does is make base facts reachable. So
every "violated" verdict decomposes into (a) is the defining inference sound? (a
modeling judgment, not a result) and (b) are the base facts co-reachable? (the actual
model-checking question).

| Invariant | Class | Assessment |
|---|---|---|
| `p1_noCountLeak` | **[XC]** | `queryTag`/`delegateScalar` *themselves write* `{wallet, e, count = recvCount}` into `gpaCount` when the count is positive. The leak is hardwired into the action; no padding mechanism exists in the model, so P1 *cannot* hold. The Apalache CEX confirms a 2-step action sequence is reachable — weight ≈ 0. VERIFICATION §4.1(c) concedes exactly this ("the verdict 'violated' is by construction, not discovered"). |
| `p3_countsNotWhich` | **[PV]** | `advAttrib := mappingLeaked ∧ advCount` and `mappingLeaked := compMA.size() > 0`. The invariant `advAttrib ⇒ compMA > 0` is a tautology of the definitions — *no* rule could violate it even in principle. Apalache "proved" = 11 s–minutes confirming propositional logic. VERIFICATION §4.2 admits ("definitional"). |
| `p4_maAloneLearnsNothing` | **[PV]** | Every disjunct of `advCount` requires a compromised DS (`b.server ∈ compDS` / `compDS.contains(q.server)` / `compDS.contains(d.server)`); under `compDS = ∅` the conclusion is definitionally false (the `advAddr = ∅` conjunct is not even needed). Tautology. |
| `p5_bothNeeded` | **[XF] (half) + [PV] (half)** | The `compMA` conjunct is the p3 tautology. The violated conjunct (attribution without the *indexing* DS compromised) is a genuine reachability question: the F8 path must order send → delegate-to-ds2 → compromise-ds2 → collude → send → advanceEpoch → compromise-MA across 8 steps within guard constraints (`e < st.epoch`, non-empty buckets). Apalache's CEX plus `t_F8_delegationEscalation` legitimately show this ordering is feasible and that no guard blocks it. This is the best Quint result in the repo — while the terminal inference (`dsk = x − PRF^D`) remains a definition. |
| `p6a_granularCrypto` | **[PV]** | `serverTagKnown := addrLeaked ∨ query-seen`; the invariant is disjunctive syllogism on that definition (`serverDetects ∧ ¬addrLeaked ⇒ query`). Tautology. |
| `p6b_limitedDelegation` | **[XF]** | `advDskKnown` is *defined* as `delegation-to-compromised-DS ∧ addressLeaked` — the scalar cancellation is definitional (§4.1(b) admits: "sound over-approximation"). Real content: (i) the preconditions are co-reachable in the right order; (ii) the honest baseline `t_P6b_honestDelegationScoped` shows the violation is *not* unconditional — without the leak, authority stays epoch-scoped. That counterfactual is what makes the violation meaningful rather than definitional noise. |
| `p6c_noCrossDayLink` | **[XF]** | Same pattern: definitional inference, real co-reachability of the two-epoch knowledge conjunction. (Sampled CEXs were "degenerate near-empty logs" per VERIFICATION §3 — the curated traces carry the substance; honest.) |
| `p6c_indexPath` | **[XF]** | Isolates the retained-bucket path; needs `retainsIndex = true` plus cross-epoch buckets plus a leak — Apalache's CEX genuinely had to find that conjunction. The counterfactual `t_F9_deletionDisciplineHolds` (retainsIndex=false blocks epoch-1 readout) is real model content, though "deleting buckets deletes buckets" is close to definitional too. |
| `p6c_ipPath` | **[XC]-ish** | `ipOf` is a *static* table (constant per wallet); no action can change a wallet's IP, so the mitigation space (fresh Tor circuit per epoch) is **inexpressible**. Once two same-wallet queries at a compromised server exist — two freely-enabled actions — the link fires definitionally. The trace `t_F5_ipLinksDiversified`'s only non-definitional aspect is the flag combination (`divSep = true`: crypto did not link them), which is itself flag semantics. |
| `p8_oracleBlocked` | **[XC]** (both directions) | `oracleProbe`'s effect is guarded by `¬piBinding ∧ target-is-registered-DS ∧ sender-sent-to-address`. Violated iff the flag is off; holds iff on. Both verdicts by construction; VERIFICATION §4.1(e) concedes ("scenario-flag assertions, not derivations"). The model does honestly register the necessity precondition (prober must hold the address). |
| `p8b_bindingBlocks` | **[BC]** | `piBinding ⇒ oracleHits = ∅`: the *only* writer of `oracleHits` is guarded by `¬piBinding`. The Apalache proof's sole content is "no other action writes `oracleHits`" — an action-system fact, weak but not strictly zero. |
| `mixSoundness` | **[BC]** | `postmix` is written only by `advanceEpoch`, always as the canonical deduplicated set; the two replay actions are observable no-ops (they increment a counter and do nothing else). The invariant is a tautology of the abstraction — VERIFICATION §4.1(f) says so in exactly these words ("tautology … no evidential weight beyond type-checking the design intent"). 5.7 min of Apalache time to confirm it. |
| `f1_diversifierUnlink` | **[XC]** (given the reading) | Under `divSep = false`, `base(a) = walletOf(a)` makes `kttOf("alice.1") = kttOf("alice.2")` a *static fact*; the "attack" is two freely-enabled `senderCollude` actions plus a flag. Everything rests on the interpretive claim that the article's underspecified derivation ignores diversifiers — which is the actual (contested) content of F1, and it is exegesis, not model checking. |
| `f1b_perDivUnlinkable` / `v_f1b_divInputsDiffer` | **[PV]** | `v_f1b_divInputsDiffer` is `st.divSep ⇒ "alice.1" ≠ "alice.2"` — a proof of a *string inequality*. Completely vacuous. (`f1b` proper was only sampled; Apalache rejects ADT equality — documented, and the substitution is fair, but the substituted statement is a constant.) |
| `p10_noSilentDrop` | **[XC]** | `dsWithhold`'s effect IS the violation (`withheld ≠ ∅`); guards (compromised DS + non-empty bucket) are realistic, but no detection/fraud-proof mechanism is modeled, so the property cannot hold in any run where a compromised DS with a bucket chooses to act. The interesting real question — could the wallet *detect* withholding? — is outside the abstraction. |
| `sanity_tagsEpochDistinct` | **[PV]** | Static constructor-injectivity fact. |

### 2.1 Trace audit (`quint test`, 17/17 reproduced)

No `assert(true)`-style placeholders; every `expect` asserts a real state predicate.
But several assert **what the last action wrote by definition** — self-confirmation of
the model's own encoding rather than derived consequences:

- `t_F7_withhold`: asserts `withheld.contains(…)` immediately after `dsWithhold` wrote
  exactly that. The trace proves the action is *enabled* under realistic preconditions;
  nothing else.
- `t_F4_p1_countLeak`: asserts `gpaCount` equals what `queryTag` wrote — and the
  written count is by definition `recvCount` (the true count from `txLog`). The trace
  documents the mechanism (accurate counts + timing); it cannot fail.
- `t_mix_replaysBlocked`: asserts `mixSoundness` (tautological) plus exact bucket
  contents after no-op replay actions. Cannot fail by construction.

The genuinely derived ones: `t_F9_retroCrossDayLink` (asserts the *conjunction* of
both epochs' readouts and `¬advAttrib` — the ordering is forced by `e < st.epoch`
guards), `t_F8_delegationEscalation` (asserts authority for a never-delegated epoch
and `ds1 ∉ compDS`), `t_P6a_granularIndexed` (asserts `¬serverDetects` for the
unqueried epoch — a real negative). Overall the curated traces are best described as
**executable documentation with regression value**, which is how VERIFICATION §3
frames them ("narrated versions") — but FINDINGS cites them as confirmation.

### 2.2 Apalache-proved set: meaningful or unfalsifiable?

`p3` **unfalsifiable** (definition-entailed). `p4` **unfalsifiable**. `p6a`
**unfalsifiable**. `p8b` by-construction (only-writer fact). `mixSoundness`
by-construction (tautology). `v_f1b_divInputsDiffer` **vacuous** (string inequality).
VERIFICATION.md §4.2/§6 already concedes the essentials ("definitional",
"by-construction", "tautology") — the re-audit confirms those concessions are
accurate. The nontrivial residual content of the p3/p4/p6a proofs is exactly what
§4.2 says it is: *no other modeled action breaks them* — i.e., the action grammar
contains no unintended attribution/counting channel. That is a check on the model's
own hygiene, not on the protocol.

---

## 3. Cross-artifact: FINDINGS.md citations that oversell

| FINDINGS location | Citation as written | What the artifact actually gives | Suggested rewording |
|---|---|---|---|
| Verdict table F1 + L73–75 | "Lean `thm_F1_diversifierLink`" / "proved: Lean thm_F1_diversifierLink (equality of sender-visible tuples ⇒ linkage; per-diversifier injection ⇒ inequality)" | An assumption-free `rfl`: the diversifier-ignoring function returns equal values; distinctness is hypothesis-conditional on injectivity. All weight is on the *reading* of the article's prose. | "Lean `thm_F1_diversifierLink` (definitional: under the naive-derivation **reading** of the article's prose, the tuples are equal — `rfl`; the reading itself is interpretive)" |
| Verdict table F2 | "Lean `thm_F2_senderCollusion`/`indexReadout`" | Both **vacuous** (`Derived` hypotheses unsatisfiable — §1.1). | Drop the Lean citation, or first repair `Derived` (§5) and re-cite as "symbolic closure derives all-epoch tags from granted address components" |
| L107 | "Lean `thm_F2_senderCollusion`, `thm_F2_crossEpochLinkage`, `thm_F2_indexReadout` (∀-epoch tag derivability, cross-epoch linkage, **full index readout from a single address leak**)" | Vacuous conditionals; "from a single address leak" is the *hypothesis*, not a conclusion; `indexReadout` presumes `indexHas` (that the index exists and maps the tag) as a hypothesis. | "Structural observation (no non-vacuous Lean statement yet): the tag formula is public and epoch-unbounded in `(K_TT, G_r)`; Quint `t_P3`/`t_P5` show the base facts are reachable in the action model" |
| Verdict table F4 + L176 "Formally (Lean …)" + L192 | "Lean `thm_F4_trilemma` + `thm_F4_volumeDistinguisher`" | Elementary lemmas about an arbitrary `Nat → Nat` function; zero Lean content connects `vol` to the protocol; the trilemma is a case split on decidable equality. | "Elementary counting argument (Lean `thm_F4_*` formalizes the function lemma only; the identification of `vol` with session volume is argued in prose and demonstrated in `sim A_F4`)" |
| Verdict table F8 + L274 | "algebra proved: Lean `thm_F8_dskRecovery` (∀-epoch key derivability from `x_e + KTT`)" | Vacuous; the cancellation is an assumed inference rule over a free constructor; injectivity is `injection`, i.e. definitional. | "Scalar cancellation is definitional in the symbolic model (vacuous as stated — see FORMAL-DEFENSE §1.1); the operational demonstration is `sim A_F8` + Quint `t_F8_delegationEscalation` (reachability of the 8-step precondition chain)" |
| Verdict table F5 | "Quint `p6c_ipPath` trace" | Link is a definitional consequence of a *static* `ipOf` table; mitigation inexpressible in the model. Acceptable as demonstration, not as discovery. | "Quint `t_F5_*` (executable demonstration; the model fixes IPs per wallet, so the link fires definitionally once queries exist — the trilemma Tor/fresh-circuit tradeoff is argued in prose)" |
| Verdict table F7 | "Quint `p10_noSilentDrop` trace" | Violated-by-construction: the `dsWithhold` action's effect is the violation; detection mechanisms unmodeled. | "Quint `t_F7_withhold` (by-construction demonstration that a compromised DS with a non-empty bucket can withhold; no detection mechanism is modeled or exists in the design)" |
| Verdict table verified-sound row | "… Apalache-proved `p8b`, Lean `thm_Nb/Nc/Nd`" | `p8b` by-construction; `thm_Nb` genuinely conditional on the `pi_sound` axiom; `thm_Nc` definitional; `thm_Nd` real-but-elementary list lemmas. The row also asserts case (b) (`π_query` preimage resistance), for which **no Lean theorem exists**. | "… `thm_Nb_*` (under the labeled `pi_sound` axiom), `thm_Nc` (definitional on the AD-check idealization), `thm_Nd` (proved dedup lemmas); case (b) is sim-only (`N_b`, `N_f`)" |
| Headline L11–14 | "`p3`, `p4`, `p6a`, `p8b` are **proved** by bounded exhaustive model checking" | Accurate but without the VERIFICATION.md caveat that all four are tautological or by-construction in the model. | "… 'proved' — note these four are definitional/by-construction in the model (VERIFICATION.md §4); the proofs check model hygiene, not protocol resistance" |

Citations that survive audit unchanged: F3/F9 row (sim + Quint traces, correctly
framed), F5's `sim A_F5`, the `thm_Nb` description at L310 ("under ZK soundness…" —
exactly right), and the external-literature rows (out of scope here).

---

## 4. What the formal work DOES and DOES NOT establish

**DOES establish (honestly):**

1. *Quint, reachability*: within a 3-epoch/2-DS/2-MA/3-address/2-sender abstraction,
   the base-fact conjunctions required by each multi-step attack (F8 escalation;
   F9 retroactive readout; F5 same-IP; F1 shared-tuple) are reachable, with the
   required action orderings, under all 8 scenario-flag combinations, exhaustively
   to depth 10 (longest curated attack: 8 steps). The honest baselines — deletion
   discipline blocks the retained-index path; delegation without an address leak
   stays epoch-scoped — were also checked and behave as the FINDINGS fix-directions
   claim.
2. *Quint, hygiene*: no *unintended* action path grants attribution without an MA,
   counts without a compromised DS, or detection of unqueried epochs — i.e., the
   action grammar matches the intended adversary surface (this is the entire content
   of the "proved" p3/p4/p6a; it is a check on the model, and it passed).
3. *Lean, conditional mechanism*: under the labeled `pi_sound` idealization, π's
   same-base binding propagates to the honest indexing rule (N-b); a concrete dedup
   implementation provably suppresses repetition multiplicity (N-d); AD-equality
   acceptance provably rejects cross-epoch ciphertexts (N-c, definitional on the
   idealization); the naive (diversifier-ignoring) derivation provably equalizes
   sender-visible tuples (F1, `rfl`).
4. *Both*, discipline: no `sorry`, no `native_decide`, axioms enumerated and (mostly)
   correctly scoped; VERIFICATION.md's self-critique (§4, §6) is accurate on every
   point I re-checked.

**DOES NOT establish:**

1. **Any cryptographic statement.** No reduction, no probability, no adversary
   efficiency, no computational assumption is *used* by any break result — crypto
   exists in the artifacts only as absent inversion rules (Lean) or as definitions
   (Quint). The breaks are arguments that the protocol's *public algebra and system
   structure* defeat its privacy claims, and the formal artifacts choreograph those
   arguments; they do not secure them.
2. **Any non-vacuous adversary-derivation theorem.** The five `Derived`-hypothesis
   theorems are vacuously true (§1.1); the F5 conclusions are unconditionally true.
   As they stand, the Lean break theorems would survive arbitrary mutilation of the
   inference rules — the signature of proving nothing.
3. **The interpretive premises.** Each headline break is conditional on a modeling
   judgment that is exegesis of ambiguous prose: `divSep = false` (does "derives
   secrets from their viewing key" ignore diversifiers? — F1), senders-necessarily-
   hold-`K_TT` (F2), IP constancy (F5), volume ∝ count with no padding (F4 — the
   article's own trilemma paragraph makes this reading defensible, which is why F4's
   *prose* argument is strong even though its Lean support is trivial). The formal
   artifacts add precision *after* these choices, not evidence *for* them.
4. **Attainability of knowledge hypotheses.** Nothing formal shows addresses,
   delegation scalars, or indices leak with any frequency; "every counterparty is a
   walking address leak" is a definitional fact about addresses plus a trust-model
   argument, carried entirely by prose.
5. **F6, F10–F13** (admitted), MA-side F7, cross-server IP correlation, and any
   quantitative anonymity statement (F12 is literature-backed argument only).

**Net assessment.** The campaign's real analytical work — the structural observations
behind F1/F2/F4/F8/F11 — appears sound and is well argued in prose and competently
simulated, but the *formal* layer currently adds much less than FINDINGS.md's
citations imply: the Lean break theorems are vacuous, the F4/F5 Lean support is
trivial, the Quint "violated" verdicts mostly codify the attacks they were built
around, and the Quint "proved" verdicts are tautologies. The exceptions — the
multi-step reachability results with honest counterfactual baselines (F8, F9), and
`thm_Nb` as a cleanly-labeled conditional — are modest, real, and citable as such.

---

## 5. Recommended repairs (in order of leverage)

1. **Repair `Derived` (removes the vacuity).** Parameterize by an assumption context:
   `inductive Derived (Γ : Value → Prop) : Value → Prop` with a base constructor
   `| hyp (v) (h : Γ v) : Derived Γ v`. Restate `thm_F2_senderCollusion` as
   `Derived Γ (ktt w) → Derived Γ (gr w) → ∀ e, Derived Γ (TagOf w e)` and
   `thm_F8_dskRecovery` analogously. Mechanical change; converts five vacuous
   theorems into the statements FINDINGS claims they are. (`vacuity-check.lean` in
   this directory documents the defect and compiles against the current model.)
2. **Fix the axiom-audit comment** in `Zecbreak.lean` (three F-theorems depend on
   `piVerified` via definitional contagion through `Sem`/`indexHas` — or eliminate
   the contagion by not threading `indexHas` through `Sem`).
3. **Reword FINDINGS.md citations** per the table in §3 — most importantly F2/F8 Lean
   citations (vacuous), F4's "Formally (Lean …)", and the "proved" headline caveat.
4. **Label every Quint verdict** with its class from §2 (by-construction vs
   reached-preconditions vs tautological) in FINDINGS's one-line summary, matching
   what VERIFICATION.md already says in §4–§6.
5. Optional, for genuine content: add a `QueriesTag`-style premise structure that
   lets the F5 model *fail* (per-epoch fresh identities as an honest action), and a
   padding mechanism that lets `p1` *hold* — then the violations would be discoveries
   rather than encodings. Absent that, present the Quint model as what it is: an
   executable spec of the attacks with machine-checked precondition reachability.

---

## Appendix A — reproduction log (2026-10-23)

- `cd lean && PATH=$HOME/.elan/bin:$PATH lake build` → success; axiom audit output
  matches §1 header (three `piVerified` dependencies among F-theorems).
- `lake env lean ../defense/vacuity-check.lean` → no errors: `derived_empty` proved;
  `ServerLinksEpochs`/`ServerMerges` proved unconditionally.
- `quint test --main ZecLightTests ZecLight.qnt --match '^t_' --seed=1` → 17/17.
- `quint verify --main ZecLight --invariant p1_noCountLeak --max-steps 10` →
  `[violation] found a counterexample` (4996 ms).
- `verify-results/*.json` statuses: violation ×8 (p1, p5, p6b, p6c×3, p8, p10) +
  `v_f1_sharedBaseLeak`; ok ×6 (p3, p4, p6a, p8b, mixSoundness, `v_f1b_divInputsDiffer`);
  failure ×2 (f1, f1b proper — Apalache ADT-fragment error, as documented). Matches
  VERIFICATION.md §2 exactly.
