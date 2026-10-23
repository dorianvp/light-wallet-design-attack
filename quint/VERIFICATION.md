# VERIFICATION — `quint/ZecLight.qnt`

Verification agent re-run, 2026-10-23. Everything below was executed from this directory
against `ZecLight.qnt` **as committed after the fixes listed in §5**.

- Quint `0.33.0` (`../node_modules/.bin/quint`), backend `rust` for simulation, Apalache
  `0.62.1` (bundled at `~/.quint/`) for bounded verification.
- Spec source of truth: `../PROTOCOL.md` (P1–P10, F1–F13). Findings narrative: `../FINDINGS.md`.

## 1. Commands (reproduce everything)

```sh
cd quint

# (a) curated deterministic attack traces (17 tests) — NOTE the --match:
#     quint 0.33.0 only auto-discovers definitions ending in "Test",
#     so `quint test` WITHOUT --match silently runs ZERO tests.
../node_modules/.bin/quint test --main ZecLightTests ZecLight.qnt --match '^t_' --seed=1

# (b) random sampling per invariant (console -> traces/raw/<inv>.txt, JSON -> .out)
./rerun-sampling.sh            # = quint run --main ZecLight --invariant <inv> \
                                #   --max-samples 10000 --max-steps 25 --seed=0x5ecc1a2b

# (c) exhaustive bounded model checking (Apalache), one invariant at a time
./verify-all.sh                # = quint verify --main ZecLight --invariant <inv> \
                                #   --max-steps 10 --out verify-results/<inv>.json
                                # (includes the v_f1_* restatements; f1/f1b proper
                                #  hit Apalache's ADT fragment limit — see VERIFICATION.md §4.4)
```

Artifacts: `traces/raw/*.{txt,out}` (sampling), `verify-results/*.json` +
`PROGRESS.log` (Apalache — the `.json` is authoritative; `verify-results/*.txt` are
empty because `--out` suppresses console output), `_apalache-out/server/*/detailed.log`
(raw Apalache server logs).

## 2. Per-property verdict table

"**proved**" = Apalache `NoError` over all states up to 10 steps, all 8 scenario-flag
combinations (see §4.3). "**counterexample (proved)**" = Apalache found a violating
execution. "**sampled only**" = `quint run` evidence only.

| Invariant | Claim / Finding | Sampling (`quint run`, 10⁴×25) | Apalache (`quint verify`, depth 10) | Verdict |
|---|---|---|---|---|
| `p1_noCountLeak` | P1 — GPA learns nothing | violated | **counterexample** | **violated** (F4)* |
| `p3_countsNotWhich` | P3 — DS: how many, not which | holds | **NoError (proved)** | holds* |
| `p4_maAloneLearnsNothing` | P4 — MA alone learns nothing | holds | **NoError (proved)** | holds* |
| `p5_bothNeeded` | P5 — attribution needs *both* servers | violated | **counterexample** | **violated** (F8/F2) |
| `p6a_granularCrypto` | P6 — epoch-granular indexed detection | holds | **NoError (proved)** | holds* |
| `p6b_limitedDelegation` | P6 — delegation limited to epoch e | violated | **counterexample** | **violated** (F8) |
| `p6c_noCrossDayLink` | P6 — no cross-day linking | violated | **counterexample** | **violated** (F3/F5/F8/F9) |
| `p6c_indexPath` | F3/F9 — retained-index retroactive link | violated | **counterexample** | **violated** (F3/F9) |
| `p6c_ipPath` | F5 — same-IP cross-epoch link | violated | **counterexample** | **violated** (F5) |
| `p8_oracleBlocked` | P8 — identification oracle blocked | violated (π-less variant) | **counterexample** (π-less variant) | violated iff π-fix absent (by construction) |
| `p8b_bindingBlocks` | P8 — π binding kills oracle | holds | **NoError (proved)** | holds (by construction) |
| `mixSoundness` | P7 — AD+dedup block replays | holds | **NoError (proved)** | holds **by construction** (tautology) |
| `f1_diversifierUnlink` | F1 — diversified addresses unlinkable | violated | fragment error → restatement `v_f1_sharedBaseLeak`: **counterexample** | **violated** (F1) |
| `f1b_perDivUnlinkable` | F1 fix — per-diversifier unlinkable | holds | fragment error → restatement `v_f1b_divInputsDiffer`: **NoError (proved)** | holds |
| `p10_noSilentDrop` | P10/F7 — DS cannot silently drop | violated | **counterexample** | **violated** (F7) |

Timings: proofs 11 s – 5.7 min (`mixSoundness`); counterexample searches 4–9 s each.
`verify-results/PROGRESS.log` has the full run log; each `verify-results/<inv>.json`
holds the Apalache verdict (and, for violations, the ITF counterexample trace).

Curated deterministic traces (`quint test --match '^t_'`): **17/17 pass**, each asserting
the finding's mechanism directly (see §3).

\* see §4.1 — "holds" for p3/p4/p6a is w.r.t. the model's *definition* of adversarial
knowledge; the model-checker contribution is proving no *unintended* protocol path
breaks them.

## 3. Trace ↔ finding correspondence (all 17 curated tests)

| Test | Finding | What the trace demonstrates |
|---|---|---|
| `t_F4_p1_countLeak` | F4/P1 | 2 notes vs 1 note ⇒ GPA observes sessions {alice:2},{bob:1}; "when" (epoch) leaks too |
| `t_F9_retroCrossDayLink` | F3/F9 | receive in e1,e2; **only then** DS compromise + one colluding sender (K_TT epoch-independent) ⇒ both daily groups read from retained index; no attribution without MA |
| `t_F9_deletionDisciplineHolds` | F3 mitigation | same attack with footnote-1 deletion discipline (`retainsIndex=false`) ⇒ retroactive readout of e1 fails |
| `t_F5_liveIpCrossDayLink` | F5 | live-compromised DS links (ipA,e1),(ipA,e2) queries; **no address leak needed** |
| `t_F5_ipLinksDiversified` | F5 | same IP links two diversified addresses that cryptography did *not* link (`divSep=true`, K_TT differs) |
| `t_F8_delegationEscalation` | F8/P5/P6b | one delegation of epoch 1 + one colluding sender ⇒ `dsk` recovered ⇒ detection authority for never-delegated epoch 2 + MA ⇒ exact attribution while indexing DS ds1 stays honest |
| `t_P6b_honestDelegationScoped` | P6b sanity | delegation without address leak ⇒ authority for epoch 1 only |
| `t_F1_diversifiedLinkable` | F1 | `divSep=false`: two senders to alice.1/alice.2 compare equal (K_TT, G_r) |
| `t_F1b_perDiversifierUnlinkable` | F1 fix | `divSep=true`: same collusion, terms differ (tags differ too) |
| `t_P8_bindingBlocksOracle` | P8 fix | π binding on ⇒ probes at true and false server both yield nothing |
| `t_P8_piLessOracleWorks` | P8 break | π binding off ⇒ probe at the true server identifies it |
| `t_P3_countsNotWhich` | P3 | compromised DS + colluding sender ⇒ counts, but no attribution without MA |
| `t_P5_concededAttribution` | P5 | DS + MA + tag knowledge (via sender) ⇒ exact attribution (article's concession, sharpened by F2: "compromise" replaced by one past counterparty) |
| `t_P6a_granularIndexed` | P6a | server queried for e1 cannot detect e2 (tags of different epochs are distinct terms) |
| `t_mix_replaysBlocked` | P7 soundness | repetition + cross-epoch replay attempts leave post-mix list canonical and bucket counts unchanged |
| `t_F7_withhold` | F7 | malicious DS silently withholds a non-empty bucket |
| `t_sanity` | — | tags epoch-distinct; canonical postmix; initial registrations |

Sampled counterexamples (`traces/raw/*.txt`) were spot-audited: each final state
realizes the stated attack (e.g. `p6c_indexPath` fires only with `retainsIndex=true`
and cross-epoch buckets; `p6b` fires only with delegation+leak+compromised
delegation-server). Two sampled traces (`p5`, `p6c_noCrossDayLink`) reach their
violation with degenerate (near-empty) logs; the substantive mechanism is carried by
the curated `t_F8_delegationEscalation` / `t_F9_retroCrossDayLink` traces instead.

The **Apalache counterexamples** are minimal (3–7 states) and share that minimalism:
they establish the *capability* (e.g. `advDstarKnown` for a never-delegated epoch
with zero transactions — the F8 authority escalation; a two-query same-IP log with
no transactions — the F5 link). The model's knowledge predicates are
capability-semantics, so these are genuine violations; the curated traces above are
the narrated, transaction-carrying versions of the same attacks. Spot-checks:
`p6c_indexPath`'s Apalache CE needs `retainsIndex=true` + two retained buckets +
address leak (pure F3/F9); `p1`'s CE is one tx + one query ⇒ `gpaCount` nonempty
(pure F4); `v_f1_sharedBaseLeak`'s CE is both alice addresses leaked under
`divSep=false` (pure F1).

## 4. Fidelity audit

### 4.1 Faithful

- **(a) Tag derivation (F2/F3 root).** `tagOf(a,e) = TagOf((KttOf(base(a)), GrOf(base(a)), e))`
  — `K_TT` (and `G_r`, `dsk`) are epoch-independent; the epoch enters only as the
  third constructor argument. Term equality ≡ derived-value equality, so:
  same (address, epoch) ⇒ same tag (F2 root); different epochs ⇒ different tags
  (`sanity_tagsEpochDistinct`, asserted in `t_sanity`); no rule derives e2's tag from
  e1's — exactly the F3 forward-secrecy failure surface.
- **(b) Non-indexed delegation (F8).** The cancellation `x − PRF^D(K_TT,e) = dsk` is
  modeled as the derived predicate `advDskKnown = deleg-to-compromised-DS ∧ addressLeaked`,
  and escalation as `advDskKnown ⇒ advDstarKnown(a,e′) ∀e′`. This is a sound
  over-approximation of the attacker (the scalar algebra is exact in the real protocol);
  delegation events are retained forever (matches server log retention), so retroactive
  escalation after a *later* leak is covered.
- **(c) Volume ∝ count (F4).** `queryTag`/`delegateScalar` sessions add
  `{wallet, e, count = recvCount}` to `gpaCount` when the count is positive.
  Caveat (strawman, defender-side): the leak is *built into* the actions; no padding
  mechanism exists in the model, so P1 cannot possibly hold. This matches the
  article's own trilemma concession (F4 says the leak is inherent), but the verdict
  "violated" is by construction, not discovered — the trace evidences the *content*
  of the leak (exact counts + timing), not its inevitability.
- **(d) Same-IP linking (F5).** `queries` records `(server, ip, addr, e)` with
  `ipOf` constant per wallet; `ipCrossDayLink`/`ipLinksDiversified` require a
  *compromised* (live) server, matching F5's adversary. Limitation: both queries must
  hit the *same* server; cross-server GPA IP+timing correlation is not modeled
  (explicitly out of the model's scope, consistent with F5's "live malicious DS" framing).
- **(e) π same-base binding (P8).** `oracleProbe` succeeds iff `!piBinding` ∧ the
  target server is the address's registered DS ∧ the prober previously sent to the
  address (senders necessarily hold the address — matches F2). Both directions are
  *scenario-flag assertions*, not derivations: `p8_oracleBlocked` violated and
  `p8b_bindingBlocks` holding are both by construction. The model's value here is
  registering the necessity condition (must hold the address) and the fix/broken
  contrast, not proving the ZK soundness argument.
- **(f) Mix AD + dedup (P7 soundness).** `postmix` is written only by `advanceEpoch`,
  as the canonical deduplicated set; the two replay actions are observables no-ops.
  `mixSoundness` is therefore a **tautology** — "holds" carries no evidential weight
  beyond type-checking the design intent. The real content (AEAD AD check, sort+dedup
  against multiplicity tagging) lives outside the term abstraction. Reported as
  holds-by-construction.

### 4.2 Model too weak for the attacker (gaps — none fixed, documented)

- **F6 (r=s catastrophic derivation) is not modeled.** Registration never confers tag
  knowledge on the registered DS; a third scenario flag (`noDomSep`: registered server
  can derive `K_TT` from `r`) would violate `p6a` "for free". Out of the audited scope
  (a)–(f); flagged for any future model revision.
- **P7 "self-created transaction" exclusion**: a colluding sender can recognize *their
  own* post-mix entry without an MA (they know their own ciphertext); the model's
  `advAttrib` is all-or-nothing per (address, epoch) and misses this partial
  attribution. Does not affect any P3/P5 verdict (the sender already knows their own tx).
- **F7 MA half** (censorship / injected post-mix entries ⇒ count pollution) is not
  modeled; only the DS-withholding half is (`p10_noSilentDrop`).
- **p3/p4/p6a "holds" are definitional**: `advAttrib` is *defined* as
  `mappingLeaked ∧ advCount`, and no acquisition path for the pre-mix↔post-mix mapping
  other than `compMA` exists in the model. Apalache proves no *other* modeled action
  (queries, delegation, leaks, replays, withholding) breaks them — that is the actual
  content of the "proved" verdicts.

### 4.3 Scenario flags & bounds

`init` chooses `divSep`, `piBinding`, `retainsIndex` nondeterministically — Apalache
covers all 8 combinations; `quint run` samples them. Static bounds: 3 epochs, 2 DSes,
2 MAs, 3 addresses (2 diversified of one wallet + 1 control), 2 senders, 6 tx ids.
Depth-10 exhaustive runs cover every curated attack (longest needs 8 steps).
Vacuity: every "holds" invariant's antecedent is reachable (e.g. `t_P5_concededAttribution`
witnesses `advAttrib`; `t_P6a_granularIndexed` witnesses `p6a`'s antecedent).

### 4.4 Apalache fragment limitation (why f1/f1b need restatements)

Apalache 0.62.1 rejects ADT-constructor equality inside invariants
(`MonotypeLanguagePred` error, visible in `_apalache-out/server/*/detailed.log`;
the previous agent hit the same wall at 18:44). Invariants comparing `kttOf(...)`
terms (`f1`, `f1b`) therefore **error out** — the `exit=1` must not be read as a
counterexample. Equivalent restatements over derivation inputs (`base(a)`, plain
strings) were added: `v_f1_sharedBaseLeak`, `v_f1b_divInputsDiffer`.

## 5. Fixes applied by this verification pass

1. **`quint test` ran zero tests before.** quint 0.33.0 auto-discovers only
   definitions ending in `Test`; the 17 curated traces are named `t_*`. Nothing was
   ever executed by `quint test` (exit 0, empty pass list). Fixed by documenting and
   using `--match '^t_'` (all 17 pass).
2. **Zero-count queries now leak counts.** `advCountViaIndexAtCompDS` gained the
   disjunct "server answered a query for (a,e)" — a compromised DS that answers a
   query observes the returned bucket *including the empty one*, i.e. learns the count
   even when it is 0. The pure retained-bucket path was split out as
   `advCountViaRetainedIndex` so `p6c_indexPath` keeps isolating the F3/F9 mechanism.
   No verdict flipped (p3/p4/p6a/p8b still hold; the violated set is unchanged —
   `p6c_noCrossDayLink` merely gains an additional, real violation route).
3. **`p6c_indexPath` path isolation bug (self-inflicted, fixed):** the invariant body
   was initially left on the query-inclusive helper; repointed at
   `advCountViaRetainedIndex`. Its sampled counterexample now requires
   `retainsIndex=true` + cross-epoch retained buckets, as F3/F9 intends.
4. **`README.md` referenced by the model header does not exist** — this file is the
   replacement; the model header comment was the only documentation.

## 6. Honest verification-strength statement

- **Proved by exhaustive bounded model checking** (Apalache, all states ≤ 10 steps,
  all 8 scenario-flag combinations): `p3_countsNotWhich`, `p4_maAloneLearnsNothing`,
  `p6a_granularCrypto`, `p8b_bindingBlocks`, `mixSoundness`, `v_f1b_divInputsDiffer`
  (F1-fix restatement). Of these, `mixSoundness` and `p8b_bindingBlocks` are
  by-construction (§4.1 e/f) — the proofs only confirm the construction is airtight
  in the abstraction; `p3`/`p4`/`p6a` are definitional-but-nontrivial (§4.2): the
  proof shows no modeled action outside the intended adversary paths breaks them.
- **Violated with machine-checked counterexample (Apalache):** `p1_noCountLeak`,
  `p5_bothNeeded`, `p6b_limitedDelegation`, `p6c_noCrossDayLink`, `p6c_indexPath`,
  `p6c_ipPath`, `p8_oracleBlocked` (π-less variant), `p10_noSilentDrop`,
  `v_f1_sharedBaseLeak` (F1 restatement). Each corresponds to findings F4, F8/F2,
  F8, F3/F5/F8/F9, F3/F9, F5, P8-pi-less, F7, F1 respectively. Caveats: the P8
  violation and the volume-leak half of P1 are by-construction (§4.1 c/e).
- **Sampled only (`quint run`), plus deterministic curated traces (`quint test`):**
  the ADT-term formulations `f1_diversifierUnlink` / `f1b_perDivUnlinkable`
  themselves (Apalache rejects ADT equality; the equivalent restatements above were
  verified instead). Everything else has both sampling and Apalache evidence.
- **By construction (no evidential weight):** `mixSoundness` (P7), both directions
  of P8, and the volume-leak half of `p1_noCountLeak`.
- **Not covered by this model at all:** F6 mechanism, F11–F13 (covered by `../sim/`
  and `../analysis/f11_witness_leak.py`), MA-side F7, cross-server IP correlation.

**Bottom line:** every break claimed in `../FINDINGS.md` that this model targets
(F1, F3/F9, F4, F5, F7-DS, F8, plus the P5 weakening via F2) has a machine-checked
counterexample at depth 10; every "holds" claim the model targets (P3, P4, P6a,
F1-fix) is proved at depth 10 within the documented definitional caveats. Depth 10
exceeds the longest curated attack (8 steps).
