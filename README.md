# Security Analysis: "Making Zcash Light Wallets Faster and More Private"

A complete attempt to break the Zcash light-wallet privacy protocol proposed by
Taylor Hornby (Defuse Security / ZecSec) on March 2, 2023 —
https://defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm —
which ends with the author's invitation: *"If you are a cryptographer, please try to
break the protocol!"*

**Verdict: the cryptographic machinery is sound where its author claims it is. The
protocol fails structurally: every privacy guarantee that matters is conditioned on
an address that is by construction in every counterparty's hands, and on delegation
values that never expire.** Full report: [`FINDINGS.md`](FINDINGS.md).

All results below are final, having survived an adversarial defense pass (four
independent defender agents attacked this analysis itself, followed by referee
adjudication — see [`ADJUDICATION.md`](ADJUDICATION.md), [`defense/`](defense/)).

## The protocol analyzed (see [PROTOCOL.md](PROTOCOL.md))

Daily epochs; senders attach per-epoch tags `T = PRF^T(K_TT, G_r∥e)` and layer
ciphertexts `(C^T, C^D, C^L)` inside encryptions to a permissioned set of **Mix
Authorities** (sort + dedup batch shuffle at epoch end); **Detection Servers**
decrypt `C^T` via a diversified-key trick (`S_r = [ssk]GroupHash(r)`) without
learning which user a tag belongs to; wallets retrieve notes by proving knowledge of
`(s, r)` (indexed) or by delegating a per-epoch scalar `dsk + PRF^D(K_TT, e)`
(non-indexed); everything is authenticated against the note-commitment tree.

## Headline results

| # | Finding | Severity |
|---|---------|----------|
| **F2** | **Sender-collusion attribution.** A malicious (not breached) Detection Server + **one colluding past counterparty** falsifies the article's *"Only if both a Mix Authority and the wallet's Detection Server are compromised…"*: per-epoch counts for all live and future epochs (plus the retention window), exact on-chain attribution with one MA added. "Address secrecy from the DS" is an antecedent a payment-receiving wallet cannot keep — the DS can manufacture counterparty status for one fee | **High** |
| **F8** | **`dsk` recovery.** The non-indexed delegation scalar is a linear function of the master detection key: any address holder computes `dsk = x − PRF^D(K_TT,e)` ⇒ **permanent, silent, all-epoch detection**, irreversible across server switches. Every textual reading of the delegation sentence either leaks or breaks the service; the only escape is the article's own future-work note (IBE) — a redesign | **High** |
| **F4** | **Volume side channel.** The article's *"Only the Detection Server observes this leakage, **not a global passive adversary**"* is false — fixed-rate delivery leaks session duration/total ∝ received-count. Passive variant is cheaply fixable (fixed-K padding, ~29 kB/day); the false sentence, over-cap wallets, and active dust-inflation defeats any fixed K | **Medium** |
| **F3/F9** | **No forward secrecy of detection history.** `K_TT` never rotates and the service must retain (or can rebuild) its index: a later address disclosure links all retained daily groups, and a leaked `ssk` rebuilds the entire history from public post-mix lists regardless of any deletion discipline (12/12 epochs, every policy tested) | **Medium** |
| **F11** | **Witness-update exclusion leak — implementer trap.** The article unreconciledly both mandates full commitment-set download (leak-free, ~3–14 MB/day) and says witnesses update "as usual" (the selective-fetch idiom every real light wallet implements). Under selective fetching, **one epoch of sibling downloads pins a new wallet's note position exactly** — tags/mixing/ZK irrelevant, spam-immune. Matches the dichotomy the author proved in general in Apr 2024 without connecting it back | **Medium** |
| **F1** | Under-specified derivation: vk-only reading links all of a wallet's addresses by tuple equality — but the article explicitly surrenders address-unlinkability for Option-2 wallets; specification must bind the diversifier | **Low** |
| **F5** | Live DS links daily groups by network identity; article prescribes Tor-per-lookup. Residue: tags are persistent pseudonyms (5% re-query rate re-links 64% of wallets over 20 epochs) | **Low** |
| **F7** | DS can silently withhold notes (detected only by full rescan); forgeries fail authentication but inflate the victim's count signal upward at one fee each | **Low** |
| **F10** | `π` doesn't bind the epoch | **Low** |
| **F6 / F12 / F13** | Derivation domain-separation hygiene / honest-output anonymity floor wording / cover-traffic + delivery caveats | **Note** |
| ✓ | **Verified sound**: π same-base binding kills the server-identification oracles; mix AD + dedup kill replay/repetition tagging; no `epk` base-equality test exists (the core anonymity trick is sound, computationally); rogue registration, garbage `C^L`, `dsk`-from-`D` all fail — each with a negative control | ✅ |

**Re-framing (from the Quint model):** exact attribution = *(tag knowledge) ×
(index-or-`dsk` access) × (MA mapping)*. A single past sender supplies factor 1; the
F8 scalar supplies factor 2; "both servers compromised" is neither necessary nor
sufficient as the article states.

**External validation** ([research/EXTERNAL.md](research/EXTERNAL.md)): no prior
public analysis of this design exists; the author's own later statements corroborate
the count-leak, the "break in once, detect forever" property (= F8's shape), and the
witness dichotomy (= F11's substance). Novel results here: **F2 and F8** (High), the
deletion-discipline insufficiency (F3b), the refuted GPA sentence (F4), and the
quantified witness trap (F11).

## Repository layout

| Path | Contents |
|------|----------|
| `PROTOCOL.md` | Formalization: parties, algebra, flows, the article's claimed properties P1–P10, hypothesis registry |
| `FINDINGS.md` | **The final report** — every finding at final severity with corrected claims and evidence |
| `ADJUDICATION.md` | The adversarial review record: defender arguments, referee rulings, reconciliation |
| `defense/` | Four defender reports (textual / cryptographic / formal / empirical), counter-experiments, machine-checked audit of the campaign's own Lean proofs |
| `sim/` | Executable protocol simulation (real group arithmetic, DH-AEAD, prover-oracle ZK): 9 attack scenarios reproduce, 8 blocked attacks correctly blocked (17/17), each with negative controls |
| `analysis/` | `f11_witness_leak.py` — witness-exclusion intersection attack (six wallet strategies, sound inference rules only) |
| `quint/` | Quint state-machine model: 15 property invariants — 8 violated with counterexample traces, honest baselines for the rest; bounded exhaustive checking where encodable |
| `lean/` | Lean 4 soundness theorems (`thm_Nb/Nc/Nd`), `thm_F4_trilemma`, `thm_F1_diversifierLink`; zero `sorry`, two labeled crypto axioms. (The F2/F8/F5 break theorems were found vacuous by the defense audit and are retained only as modeling scaffolding — see `lean/README.md`) |
| `research/` | `EXTERNAL.md` — verified external context: the #288/#6756 lineage, ZIP status (314 still a Reserved stub), mixnet/PIR/FMD literature, novelty assessment |

## Reproduce everything

```sh
# 1. Simulation: 9 attacks BREAK, 8 non-breaks BLOCKED
cd sim && python3 run_all.py

# 2. Witness-exclusion intersection attack (F11)
cd .. && python3 analysis/f11_witness_leak.py

# 3. Quint: 17 scripted traces — NOTE the required flags
../node_modules/.bin/quint test quint/ZecLight.qnt --main ZecLightTests --match '^t_'
#    random simulation of every invariant (violated => prints a counterexample trace)
../node_modules/.bin/quint run --main ZecLight quint/ZecLight.qnt \
    --max-samples 50000 --max-steps 25 --invariant p6b_limitedDelegation
#    bounded exhaustive checking (Apalache, ~5s–6min per invariant)
../node_modules/.bin/quint verify --main ZecLight quint/ZecLight.qnt \
    --invariant p8b_bindingBlocks --max-steps 10

# 4. Lean: compiles clean, zero sorry
cd lean && PATH=$HOME/.elan/bin:$PATH lake build

# 5. Defense counter-experiments
cd ../defense && python3 run_all.py
```

Tooling: Quint 0.33.0 (`npm install` in repo root), Lean 4.21.0 via elan,
Python 3 stdlib only.

## Caveats and honesty notes

- The Quint model is abstract (uninterpreted derivations, knowledge-closure
  adversary); its violated invariants prove attack-precondition reachability within
  the model, while the concrete exploitation is demonstrated in `sim/` using real
  (128-bit) group arithmetic and faithful protocol mechanics. Several of its
  "proved" invariants are tautological in the abstraction and corroborate
  construction intent only (`quint/VERIFICATION.md` classifies each).
- The Lean break theorems were proven vacuous by the defense audit (uninhabited
  premise; `defense/vacuity-check.lean`); the load-bearing evidence for F2/F8 is the
  simulation, the Quint reachability, and the defense side's independent re-derivation
  of the algebra. The Lean soundness theorems stand.
- The simulation's ZK proofs are idealized (prover-oracle with enforced soundness),
  matching the article's assumption that real ZK proofs exist; N_e-style anonymity
  claims are computational (DDH) in real groups.
- F1/F6 are specification-precision findings, not attacks on the intended design.
- External facts (ZIP numbers, forum threads, the Apr 2024 comment) were verified by
  fetching each source; see `research/EXTERNAL.md` for URLs.
