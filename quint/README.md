# Quint model — Zcash light-wallet detection protocol (ZecSec)

State-machine model of the protocol proposed in
["Making Zcash Light Wallets Faster and More Private"](https://defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm)
(Taylor Hornby / Defuse Security, March 2023), built to attack the claimed
properties P1–P10 and confirm/refute the hypotheses F1–F9 of `../PROTOCOL.md`.

- **Tool:** Quint 0.33.0 (`../node_modules/.bin/quint`; plain `quint` is NOT on
  PATH), rust simulator backend, Apalache 0.62.1 (bundled under `~/.quint`).
- **Spec:** `ZecLight.qnt` — two modules: `ZecLight` (protocol + adversary +
  property invariants) and `ZecLightTests` (scripted `run` traces). Quint 0.33
  cannot import across files (`import ... from "..."` fails to load), so both
  modules live in one file.

## How the model works

- **No real crypto.** Secrets are opaque; derivations are *uninterpreted but
  deterministic* constructor terms: `K_TT = KttOf(base)`, `G_r = GrOf(base)`,
  `T = TagOf((KttOf(base), GrOf(base), e))`, `D* = DsOf((DskOf(base), KttOf(base), e))`.
  Term equality = derived-value equality. `base` is the address under the
  per-diversifier derivation (`divSep = true`) or the wallet under the
  underspecified vk-only reading (`divSep = false`) — F1.
- **Knowledge-based adversary** = pool of the GPA (traffic observations), all
  compromised DSs (index, query log with IPs, delegation scalars), all
  compromised MAs (retroactive pre-mix↔post-mix mapping), and every leaked
  address (senders *necessarily* hold the full address — F2). Knowledge is a
  *derived* predicate over these base facts, so counterexamples never depend on
  the simulator choosing an "inference" step. Scenario flags fixed at `init`:
  `divSep`, `piBinding` (π same-base binding on/off — P8), `retainsIndex`
  (footnote-1 deletion discipline on/off — F3/F9).
- **State:** one record `st` (Quint's effect system requires all `any` branches
  to update the same variables): epoch, tx log, post-mix lists (sets ⇒
  sorted+dedup), registrations, per-server index buckets `T ↦ {C^L}` (as
  `(server, addr, epoch, count)`), permanent delegation and query logs,
  adversary facts, withheld answers, replay counter.
- **Actions:** `register`, `sendTx`, `advanceEpoch` (mix + index build),
  `queryTag` (indexed; π_query, records IP↔tag + traffic volume),
  `delegateScalar` (non-indexed fallback; hands out `dsk + PRF^D(K_TT,e)`,
  records volume), `leakAddress`, `senderCollude`, `compromiseDS`,
  `compromiseMA`, `oracleProbe` (P8), `dsWithhold` (F7), `replayRepitition` /
  `replayCrossEpoch` (N_c/N_d), plus nondeterministic `do*` wrappers for
  random simulation.

## Commands (all run from this directory)

```sh
Q=../node_modules/.bin/quint

# syntax + types
$Q parse ZecLight.qnt && $Q typecheck ZecLight.qnt

# scripted attack/corroboration traces (17 runs; attacks "pass" == invariant violated)
$Q test --main ZecLightTests ZecLight.qnt --match "t_.*"

# random simulation of every invariant (50 000 runs, 25 steps each)
for inv in p1_noCountLeak p3_countsNotWhich p4_maAloneLearnsNothing p5_bothNeeded \
           p6a_granularCrypto p6b_limitedDelegation p6c_noCrossDayLink p6c_indexPath \
           p6c_ipPath p8_oracleBlocked p8b_bindingBlocks mixSoundness \
           f1_diversifierUnlink f1b_perDivUnlinkable p10_noSilentDrop; do
  $Q run --main ZecLight ZecLight.qnt --max-samples 50000 --max-steps 25 \
         --invariant $inv          # console shows the trace when violated
done
# (the runs behind the table below are reproducible with the commands above;
# the raw blobs are written to traces/raw/ and verify-results/ — both are
# gitignored as regenerable machine output)

# exhaustive bounded model checking (Apalache; invariants without sum-type terms)
$Q verify --main ZecLight ZecLight.qnt --invariant mixSoundness --max-steps 10   # etc.
```

Note: `quint verify` first attempt seemed to hang because the Apalache server
startup is silent for ~10 s; with `~/.quint/apalache-dist-0.62.1` present it
runs fine (5 s – 6 min per invariant at `--max-steps 10`).

`rerun-sampling.sh` is a helper added elsewhere in the campaign; it re-runs the
sampling sweep with a fixed seed — note its `--out` flag suppresses console
output, so it writes JSON blobs and empty `.txt` files.

## Results

VIOLATED = real counterexample trace; scripted run + random sim (+ exhaustive
Apalache CEX ≤ 10 steps where encodable). HELD = no counterexample in 50 000
random runs + (where encodable) Apalache **proof** ≤ 10 steps.

| Invariant | Property / finding | Result |
|---|---|---|
| `p1_noCountLeak` | P1 vs **F4** | **VIOLATED** — `traces/F4-volume-duration-leak.md` |
| `p3_countsNotWhich` | P3 "not which" | **HELD** (Apalache proved) — conceded counts half shown in `traces/F2-sender-collusion-equivalence.md` |
| `p4_maAloneLearnsNothing` | P4 | **HELD** (Apalache proved) |
| `p5_bothNeeded` | P5 "attribution needs both compromises" vs **F8** | **VIOLATED** — `traces/F8-delegation-scalar-escalation.md` |
| `p6a_granularCrypto` | P6a (crypto granularity, indexed) | **HELD** (Apalache proved); network-layer break is F5 |
| `p6b_limitedDelegation` | P6b vs **F8** | **VIOLATED** — `traces/F8-delegation-scalar-escalation.md` |
| `p6c_noCrossDayLink` | P6 cross-day unlink vs **F3/F9/F5** | **VIOLATED** — `traces/F9-retroactive-index-readout.md`, `traces/F3-no-forward-secrecy.md`, `traces/F5-live-DS-IP-linking.md` |
| `p6c_indexPath` | F3/F9 flavor | **VIOLATED** — `traces/F9-retroactive-index-readout.md` (deletion discipline blocks it: `t_F9_deletionDisciplineHolds`) |
| `p6c_ipPath` | F5 flavor | **VIOLATED** — `traces/F5-live-DS-IP-linking.md` |
| `p8_oracleBlocked` | P8, π-less variant | **VIOLATED** (trace shows `piBinding = false`) — oracle dead with binding: `t_P8_bindingBlocksOracle` |
| `p8b_bindingBlocks` | P8 with π binding | **HELD** (Apalache proved) |
| `mixSoundness` | N_c/N_d (dedup + AD) | **HELD** (Apalache proved; by construction of the abstraction) |
| `f1_diversifierUnlink` | F1, vk-only derivation | **VIOLATED** (`divSep = false`) — `traces/F1-diversified-address-linkability.md` |
| `f1b_perDivUnlinkable` | F1, per-diversifier fix | **HELD** (sim only; Apalache rejects sum-type terms) |
| `p10_noSilentDrop` | P10 vs **F7** | **VIOLATED** — `traces/F7-liveness-completeness.md` |

Details of the sound parts: `traces/HOLDS-corroborated.md`. Raw simulator
outputs: `traces/raw/`.

## Honest scope statement

- Random simulation is **not** exhaustive; the exhaustive claims above are only
  those explicitly marked *Apalache proved* (bounded: ≤ 10 steps, 3 epochs, 2
  senders, 6 tx ids, 2 DSs, 2 MAs — the full model within those bounds).
- `mixSoundness` and `p4` are close to true-by-construction: the abstraction
  has no rule by which replays could poison the post-mix set or by which an MA
  alone could learn counts. They corroborate the design intent rather than
  stress it.
- P8 is modeled at the level of "the oracle succeeds iff the same-base binding
  is absent" (flag `piBinding`); the trace pair shows both sides, but the
  cryptographic *reason* the binding blocks the oracles is taken as an axiom of
  the model (it is listed as verified-sound in `../PROTOCOL.md`).
- What the model does NOT capture: timing/latency side channels beyond session
  volume, multi-DS registration churn, malicious sorted-list disagreement
  between MAs, and the constant-time sorting footnote.
