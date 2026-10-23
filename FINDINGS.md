# FINDINGS: Security Analysis of "Making Zcash Light Wallets Faster and More Private"

Target: https://defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm
(Taylor Hornby, Defuse Security, March 2, 2023). The author explicitly invited
analysis: *"If you are a cryptographer, please try to break the protocol!"*

Method: manual cryptanalysis, an executable simulation with real group arithmetic
(`sim/`), a Quint state-machine model with bounded exhaustive checking (`quint/`),
Lean 4 formalizations of the sound components (`lean/`), standalone attack analyses
(`analysis/`), verified external research (`research/`), and — critically — an
**adversarial defense pass** in which four independent defender agents (textual,
cryptographic, formal, and empirical) attacked this analysis itself, followed by
chief-referee adjudication (`ADJUDICATION.md`, `defense/`). **Every claim below is the
final, post-adjudication position.** Where a claim is conditional, the condition is
stated in the claim.

Property numbering (P1–P10) refers to the article's claimed properties as catalogued
in [`PROTOCOL.md`](PROTOCOL.md).

---

## Verdict

**The cryptographic machinery is sound exactly where the author claims it is. The
protocol's real weakness is a structurally fragile trust periphery: every privacy
guarantee that matters is conditioned on an address that is by construction in every
counterparty's hands, and on delegation values that never expire.**

Two findings survive at High severity — both delegation-trust breaks, not cipher
breaks — plus one Medium refutation of a specific false sentence, one Medium
forward-secrecy failure, one Medium implementer trap, and smaller notes.

| ID | Finding | Breaks | Severity | Evidence |
|----|---------|--------|----------|----------|
| **F2** | **Sender-collusion attribution.** A malicious (not breached) Detection Server plus one colluding past counterparty defeats the article's exclusivity claim *"Only if both a Mix Authority and the wallet's Detection Server are compromised…"*; "address secrecy from the DS" is an antecedent a payment-receiving wallet cannot keep | P5 exclusivity; granular delegation | **High** | sim `A_F2` (exact txids recovered), Quint `p5_bothNeeded` cex, defense/CRYPTO-DEFENSE.md independent verification |
| **F8** | **`dsk` recovery.** Non-indexed delegation hands over `x = dsk + PRF^D(K_TT,e)`; any address holder yields `dsk = x − PRF^D(K_TT,e)` ⇒ permanent, silent, all-epoch detection. Every textual reading of the delegation sentence either leaks or breaks the service | P6 delegation limit | **High** | sim `A_F8`, Quint `p6b_limitedDelegation` cex, defense/d4_f8_readings.py (all 7 readings), defense/CRYPTO-DEFENSE.md |
| **F4** | **Volume side channel.** The article's sentence *"Only the Detection Server observes this leakage, **not a global passive adversary**"* is false: fixed-rate packets do not fix duration/total, which grow with received-count. (The passive variant is cheaply fixable with fixed-K padding; the false sentence and active-inflation defeats stand) | P1 wording; the quoted sentence | **Medium** | sim `A_F4`, Lean `thm_F4_trilemma` (elementary dichotomy), defense/d3_padding.py |
| **F3/F9** | **No forward secrecy of detection history.** `K_TT` never rotates and the service must retain (or can rebuild) its historical index, so a single later address disclosure links all retained daily groups; a leaked `ssk` rebuilds the entire history from public post-mix lists regardless of any deletion discipline | P6's cross-day claim, in substance | **Medium** | sim `A_F3`, Quint `p6c_indexPath` cex, defense/d2_footnote1.py (12/12 epochs rebuilt under every deletion policy) |
| **F11** | **Witness-update exclusion leak — an implementer trap.** The design-as-written mandates full commitment-set download (leak-free, ~3–14 MB/day), but the perf list's "update the witnesses … as usual" is the selective-fetch idiom every real light wallet implements; under selective fetching, one epoch of sibling downloads pins a new wallet's note position exactly | P1 for any selective-fetch implementation | **Medium** | `analysis/f11_witness_leak.py`, defense/d1_f11_witness.py |
| **F1** | **Under-specified derivation.** "Derives secrets `s, r, dsk` from their viewing key" does not bind the diversifier; under the vk-only reading, all of a wallet's addresses share the extension tuple and any two senders link them by plain equality. (The article explicitly surrenders address-unlinkability for Option-2 wallets, so no promised property breaks — but the derivation must be specified) | spec precision | **Low** | sim `A_F1` |
| **F5** | **Channel-level linkage.** A live DS links a wallet's daily groups by network identity; the article prescribes fresh Tor circuits per lookup and concedes GPA/timing defeat. Residue: tags are persistent pseudonyms — re-querying at 5% re-links 64% of wallets over 20 epochs | deployment caveat | **Low** | sim `A_F5`, Quint `p6c_ipPath` cex, defense/d5_tor.py |
| **F7** | **Liveness and count-integrity caveats.** A malicious DS can silently withhold notes (detectable only by trial-decrypt rescan); injected post-mix entries fail note authentication but inflate the victim's per-tag bucket, corrupting the count signal upward at one on-chain fee each | trust caveats on the "partially trusted" DS | **Low** | sim `A_F7a/7b`, Quint `p10_noSilentDrop` cex |
| **F10** | `π`'s public inputs are `(T, epk)`; the epoch is bound only via the DS's AD, not in the proof statement. Bind `e` in `π` | spec wrinkle | **Low** | manual |
| **F6** | Derivation hygiene: domain separation of `s, r, dsk` is implied but unstated; misderivation (e.g. `s = r`) would hand the server permanent detection via registration. The author's own optimizations section shows awareness of exactly this danger | spec hygiene | **Note** | sim `A_F6` |
| **F12** | The anonymity set is the honest output count of the epoch, not "epoch-sized" under adversarial flooding — though classic (n−1) blending does not transfer (on-chain outputs cannot be delayed or excluded), so flooding does not shrink any observer's uncertainty below the no-spam baseline. Quiet epochs are naturally thin cover | P7 wording | **Note** | analysis in F12 section |
| **F13** | The optional `R+F` dummy-transaction obfuscation has no claimed security property and erodes under sustained intersection/statistical attacks (the article's own baseline, Loopix, leaves the same gap open); measured mixnet delivery channels add operational fragility | deployment caveat | **Note** | research/EXTERNAL.md |
| ✓ | **Verified sound** (below): π same-base binding, mix AD + dedup, `epk` base-unlinkability (computational), rogue registration, garbage authentication, `dsk`-from-`D` | P7, P8 | ✅ | sim `N_a–N_h` with negative controls; Quint honest baselines |

**Re-framing (from the Quint model, survived adjudication):** exact attribution =
*(tag knowledge) × (index-or-`dsk` access) × (MA mapping)*. A single past sender
supplies the first factor; the F8 scalar supplies the second; "both servers
compromised" is neither necessary nor sufficient as the article states.

---

## F2 — Sender-collusion attribution (High)

**The claim broken.** P5: *"Only if both a Mix Authority and the wallet's Detection
Server are compromised, the attacker learns exactly which transactions belong to the
wallet."*

**The attack.** Two facts combine:

1. A *malicious* Detection Server operator — the article itself uses "malicious or
   compromised" interchangeably in P2 — needs no breach. The index it necessarily
   builds while serving all users (decrypt every post-mix `C^T` with `ssk`, index
   `C^L` by tag) *is* the P5 capability; the only thing it lacks is the victim's tag.
2. The tag is held by **every past counterparty by construction**: sending requires
   the address tuple `(K_TT, G_r)`, and `T_e = PRF^T(K_TT, G_r∥e)` is computable for
   every epoch — past and future — from the address alone.

So: malicious DS + one colluding counterparty (a cashier, an exchange, anyone who
ever paid the victim — or the DS itself, which can *manufacture* counterparty status
at the cost of one payment to the victim) ⇒ per-epoch received-counts for **all live
and future epochs unconditionally, and all past epochs up to the retention window**;
adding one Mix Authority (or, for any specific transaction, its own sender) ⇒ exact
on-chain transaction attribution. The P5 exclusivity sentence is falsified in a
world with **zero server breaches**.

**Scope precision.** A single non-MA sender recognizes only *its own* transaction's
`C^PoM` in the post-mix list; full-epoch on-chain attribution needs one MA (or every
sender). The counts-only result needs no MA at all.

**Mitigation boundary (address diversification).** Giving each counterparty a
different diversified address does not help **as written**: the article derives
`s, r, dsk` from the viewing key without a diversifier, so every diversified address
carries the *same* detection tuple `(G_r, S_r, K_TT, D)` — different counterparties
compute the same tag family `T_e` and the DS's bucket aggregates payments across all
of the wallet's addresses (consistent with the article's own "group … by wallet"
semantics). With per-diversifier derivation (the F1 fix) plus
one-address-per-counterparty discipline, the leakage unit shrinks to the address: a
colluding counterparty unlocks only its own address's bucket. What does not shrink:
(a) indexed detection requires the wallet to hand its DS every (address, epoch) tag,
so the DS holds each bucket by construction and wallet-level privacy reduces to the
*unlinkability of the wallet's N addresses at the DS* — registration/query linkage
(same network identity; catch-up bursts 80–100% recall at 28–55% precision; 5% tag
re-query re-links 64.3% of wallets over 20 epochs), i.e. the network-anonymity layer
the article frames as optional; (b) the DS can dust-probe any address it serves once
to enroll in its counterparty set and compute its tags for all epochs; (c) any
reused or published address re-creates a multi-counterparty bucket; (d) F8/F3b
remain non-expiring *per address*. Diversification thus converts a counterparty-trust
problem into a query-anonymity problem; it does not remove the structural condition.

**Why the conditional defense fails.** "As long as the address is kept secret" is
presented as an achievable operating state; for a payment-receiving address it is
not — secrecy must hold against every counterparty forever, and the DS can force
counterparty status for the price of a fee. What deletion discipline *can* achieve:
it caps the *retroactive* window (nothing before the deletion/grace horizon is
recoverable from DS state), but never the live and future epochs, because the index
must exist for the service to function.

**Evidence.** sim `A_F2` (recovered txids == ground truth, no key compromises);
Quint `p5_bothNeeded` counterexample; defense-side independent verification
(`defense/CRYPTO-DEFENSE.md`); live-core quantification (`defense/d2_footnote1.py`).

## F8 — `dsk` recovery from delegation (High)

**The claim broken.** *"As long as their address is kept secret, the new Detection
Server is only granted detection authority for a limited number of epochs."*

**The attack.** Non-indexed detection hands the delegate the **scalar**
`x = dsk + PRF^D(K_TT, e)` together with `e`. Any address holder computes
`f := PRF^D(K_TT, e)` and recovers `dsk = x − f` (scalar cancellation in the
prime-order group). With `dsk` and `K_TT`, the delegate derives every epoch's
detection key and silently trial-decrypts every `C^D` in the public post-mix lists —
**retroactively and prospectively, across server switches, with zero further
interaction with the victim**.

**Why it is irreversible and unconditional in practice:**

- The grant cannot be revoked: the server retains a 32-byte scalar; an address
  sighting at *any later time* (a year later, from a different counterparty)
  converts it into `dsk`. "A limited number of epochs" is a time-box the wallet
  cannot enforce.
- Contemporaneous collusion during any live delegation recovers `dsk` outright;
  deleting delegation records afterward repairs nothing.
- **All seven textual readings of the delegation sentence were implemented and
  tested** (`defense/d4_f8_readings.py`): every reading that makes the service
  function hands the delegate a value linear in `dsk`; the non-leaking readings
  break the service; only a reading containing no `dsk` at all avoids the leak. The
  sole escape is the article's own future-work note (identity-based encryption) —
  i.e., a redesign.
- The author's own December 2023 critique of detection keys — *"the attacker can
  break in once, steal the detection keys, and then they forever have the ability to
  detect transactions"* — is the same persistence property, self-corroborating that
  this shape matters.

**Evidence.** sim `A_F8` (exact recovery, `[dsk]G₂ == D`, silent detection of
never-delegated and future epochs); Quint `p6b_limitedDelegation` counterexample
with honest baseline `t_P6b_honestDelegationScoped`; defense-side exhaustion of all
readings.

## F4 — Volume/duration side channel (Medium)

**The claim broken.** *"Only the Detection Server observes this leakage, **not a
global passive adversary**, because the Detection Server always sends detected
transactions over a constant-bandwidth protocol (e.g. in fixed-sized packets sent at
regular intervals)."* (P1's absolute wording — "learn nothing about when or how
many" — inherits the same defect.)

**The refutation.** Fixed-size packets at fixed intervals fix the *rate*, not the
*duration or total*: the payload is proportional to the number of received notes, so
session duration/total volume grows with the count, and a passive on-path observer
reads `n_e` up to padding granularity. This is the first horn of the padding
trilemma the article itself states ("Either *all* wallets download lots of data when
*any* wallet needs to, DoS attacks on addresses are possible, or wallets … are
identifiable by the amount of data") — the article presents the horn as a cost menu
and then asserts the GPA does not see the leakage, which is false as written.

**What the defense established (and we adopt).** The passive variant is *cheaply
fixable*: padding every retrieval to a fixed `K ≥ 20` gives the observer exactly
zero distinguishing advantage at a flat ~29 kB/day (≈11–18 MB/yr) — not
performance-negating, because `C^L` buckets are small. What keeps the finding alive
at Medium: the article asserts the false sentence and specifies no padding; wallets
over the cap (2–20% of a Zipf-distributed population) still leak coarsely; and
**active** inflation (F7: dust/forged entries, unbounded, from the address alone)
defeats any fixed `K`.

**Evidence.** sim `A_F4` (1 vs 20 notes ⇒ 1 vs 11 packets); Lean `thm_F4_trilemma`
(distinguishable-or-padded, for arbitrary volume functions — an elementary dichotomy,
stated as such); `defense/d3_padding.py` (zero-advantage measurement for fixed K).

## F3/F9 — No forward secrecy of detection history (Medium)

**The claims at issue.** P6's state-leak story: groups can be tied within a day but
"cannot … connect the groups from different days," under footnote-1 deletion
discipline.

**What holds literally.** The conditioned sentence survives its own hypothesis: with
perpetual address secrecy and deletion of identity↔tag associations, leaked DS state
contains no `K_TT`, and tags of different days are pseudorandom and unlinkable.

**What breaks in substance.**

1. `K_TT` never rotates. It is a permanent master linking key over the victim's
   entire detection history: one address disclosure at any time links every daily
   group the attacker can access.
2. The DS *must* retain its per-tag index for past epochs — that is how a
   resyncing wallet "fetch[es] its transactions quickly" for "all days previous."
   Footnote-1 discipline deletes identity associations and lookup order; it cannot
   delete the index without deleting the service. A single later address disclosure
   therefore links all *retained* daily groups (retroactive window = retention).
3. **Deletion discipline is provably the wrong defense:** post-mix lists are public
   and every historical `C^T` remains trial-decryptable under `ssk`. A later `ssk`
   leak rebuilds the **entire** historical index regardless of what was deleted —
   reproduced for all 12/12 epochs under every deletion policy tested
   (`defense/d2_footnote1.py`). Only per-epoch server keys (the article's own
   future work) would cap the damage.

The article's IBE musing — deleting old DS keys for "stronger forward-security and
backward-security properties" — shows the author considered forward security for
*server* keys, never for `K_TT`.

**Evidence.** sim `A_F3` (retro == truth across epochs); Quint `p6c_indexPath`
counterexample with deletion-discipline baseline `t_F9_deletionDisciplineHolds`;
defense measurements above.

## F11 — Witness-update exclusion leak: an implementer trap (Medium)

**The two unreconciled sentences.** The article both (a) mandates *"All wallets must
always download and authenticate the **entire** note commitment and nullifier sets"*
— Hornby's own 2024 horn (a): complete privacy at Θ(#outputs) × 32 B ≈ 2.8–13.8
MB/day at 1–5 ops/s (5.5–27.7 with nullifiers), i.e. **1.6–6.4% of the current-day
transaction stream the article already mandates** — and (b) lists as a performance
property *"The wallet must still update the witnesses for their unspent notes **as
usual**"* — and "as usual" for every real Zcash light wallet (ZIP 307,
lightwalletd/Zaino subtree roots) means *selective/incremental* fetching. The
article never reconciles the two.

**Why the second reading is catastrophic if implemented.** Under selective fetching,
the server watching the wallet's sibling-subtree downloads learns by sound
absence-only inference (a finalized subtree not fetched cannot be the wallet's
sibling ⇒ the note is not in the complementary half; plus first-sync completeness)
that the note lies in ever-smaller halves. One epoch of ordinary growth pins a new
wallet's note position **exactly**; the attack uses only the fetch pattern — tags,
mixing, ZK proofs are irrelevant; it is spam-immune (attacker outputs die as
candidates); random decoys are useless; full fake-witness decoys buy anonymity
exactly 1+k at (k+1)× cost, forever. This is horn (b) of the author's own April 2024
dichotomy, which he proved in general, called "harder than I first thought," and
never connected back to this design.

**Defender-side refinement we adopt:** fetching 2^16-leaf subtree *shards* (the
modern ZIP 307 idiom) collapses the candidate set once to ~65,536 and then stops
compounding — a materially better defender position than leaf-level fetching,
though shard paths re-pin at spend time.

**The fix the spec needs:** state explicitly that all wallets download the full
commitment stream (and accept the bandwidth), or specify a witness protocol that
does not leak (the author's 2024 list of partial mitigations is the current state
of the art).

**Evidence.** `analysis/f11_witness_leak.py` (six strategies, sound inference rules
only); `defense/d1_f11_witness.py` (full-set download: zero leakage, bandwidth
pricing); Hornby's Apr 2024 comment —
https://github.com/zcash/zcash/issues/6756#issuecomment-2052528472 — verified
verbatim.

## F1 — Under-specified key derivation (Low)

The derivation text ("derives secrets `s, r, dsk` from their viewing key") does not
bind the diversifier. Under the vk-only reading, every diversified address carries
the identical `(G_r, S_r, K_TT, D)` extension and any two senders link the addresses
by plain equality — no cryptography needed. This breaks no property the article
promises: the Option-1/Option-2 paragraph explicitly surrenders address
unlinkability for performance-optimized wallets ("we will give up this privacy
property"), and P6's "group transactions within a day **by wallet**" presupposes
wallet-shared tags. What remains: (i) the sacrifice is *total* (plain equality, no
server involvement), sharper than the article telegraphs; (ii) the derivation must
be specified — per `(vk, diversifier)` with domain separation — both for any future
per-address pseudonymity and to bound each counterparty's knowledge per address.
Related hygiene (F6): without domain separation, registration (which transmits `r`)
could leak `s`/`dsk`; the author's optimizations section shows he understands this
class of danger.

## F5 — Channel-level linkage by network identity (Low)

A live DS sees the same network identity query tags of different epochs and links
the daily groups in real time; deletion discipline is moot against live observation.
The article itself prescribes the mitigation (fresh Tor circuit per lookup) and
concedes its defeat by GPA timing correlation, so this is a deployment caveat.
Quantified residue (adopted from `defense/d5_tor.py`): with fresh circuits the
DS-only cross-day linkage is 0%; but tags are *persistent pseudonyms* — re-querying
at a 5% rate re-links 64.3% of wallets over 20 epochs, and catch-up bursts give the
DS 80–100% recall at 28–55% precision. The refutable residue is that the article's
"indexed lookups across days cannot be linked" silently assumes the mitigation it
frames as optional.

## F7 — Liveness and count-integrity caveats (Low)

- **Withholding:** a malicious DS returns a subset of a bucket; returned notes
  authenticate fine and the balance is silently short until a full trial-decryption
  rescan — the expensive path the design keeps as its escape hatch. The article
  claims 1-of-N availability only for Mix Authority *lists*; DS liveness is a trust
  assumption on the declared "partially trusted" party. A caveat, not a violated
  property.
- **Censorship:** a censoring MA's signed list diverges from other authorities' —
  detectable by cross-comparison; availability survives via 1-of-N.
- **Injection / count pollution:** forged post-mix entries carrying the victim's tag
  (computable from the address) fail note-commitment authentication at the wallet,
  but inflate the victim's per-tag bucket — corrupting upward the one signal
  (per-day counts) the article concedes to the DS. Each forgery rides an on-chain
  transaction and costs a fee (the fee-free variant requires being an MA).

## F10 — Epoch not bound in `π` (Low)

`π`'s public inputs are `(T, epk)`; the epoch appears only in the AEAD AD the DS
uses. A mis-epoch tag mostly creates an unqueried bucket or dies at the
commitment-position check, but the proof statement should bind `e` and the DS's AD
should be specified canonically (the list's epoch, never a sender-claimed one).

## F12 — Anonymity-set wording (Note)

The set is "honest-outputs-that-epoch," not "epoch-sized" under flooding — though
classic Serjantov–Danezis (n−1) blending does **not** transfer to this design: the
attacker can neither delay nor remove other on-chain outputs, so every honest output
is always in the batch and no observer's uncertainty shrinks below the no-spam
baseline; flooding adds only entries the attacker could already exclude. (The
article's own "without additional information" hedge nearly covers this.) The
practical residue: quiet epochs are naturally thin cover, and the attacker chooses
the day.

## F13 — Cover-traffic and delivery caveats (Note)

The `R+F` dummy self-transaction scheme is presented as optional obfuscation with no
claimed security property; sustained intersection/statistical attacks erode it (the
article's own state-of-the-art baseline, Loopix, explicitly leaves the
dishonest-provider case as future work). The measured fragility of real
mixnet-backed delivery (lwd-mixnet-proxy 2026: ~2 Mbps cover cost, 2–51% silent
failures, timing re-link) is deployment context from a different stack, kept as a
caveat for anyone reviving the design.

---

## Verified-sound components

Eight attacks were attempted against the machinery and correctly blocked (each with
a negative control proving the block is the mechanism, not a simulation artifact):

1. **π same-base binding blocks the server-identification oracles** (cases (a) and
   (b) of the article): with π disabled, "victim receives iff attacker used the same
   server" works; with π enforced, the tag necessarily uses the epk base, and
   foreign-tag queries die on the `π_query` preimage requirement. Soundness
   conditional on `pi_sound` — the protocol's own assumption (Lean `thm_Nb_*`).
2. **`"mix"∥e` AD blocks cross-epoch pre-mix replay** (Lean `thm_Nc_*`).
3. **Sort+dedup blocks repetition tagging** (multiplicity independent of `k`; Lean
   `thm_Nd_*`).
4. **No `epk` base-equality test** — the design's load-bearing anonymity trick
   (`S_r = [ssk]GroupHash(r)`) is sound. *Computational* (DDH/key-privacy family)
   in real groups; information-theoretic only in the simulation's idealized group.
5. **Rogue registration** (`GroupHash(r') = G_r^victim`): preimage-resistant.
6. **Injected/garbage `C^L`** always fails note-commitment authentication, including
   genuine replays of real notes from other epochs.
7. **`dsk` from `D`**: discrete logarithm.
8. **FMD-style query probing**: nonce-freshness + `π_query` block replays.

Quint corroboration: `t_P8_bindingBlocksOracle`, `t_mix_replaysBlocked`, and the
Apalache-proved invariants (`p3`, `p4`, `p6a`, `p8b`, `mixSoundness`, bounded ≤ 10
steps — tautological in the abstraction, corroborating construction intent). The
Quint model's genuine content is the multi-step reachability of the attack
preconditions with honest baselines; its full property table is in `quint/README.md`.

---

## What would need to change

1. **F2:** accept and state that DS privacy is conditioned on *every past
   counterparty* (equivalently: no fixed-fee adversary), or move detection authority
   to keys the sender never holds.
2. **F8/F3:** make delegation and tags forward-secure — per-epoch detection keys
   with no linear relation to a master scalar (IBE-style extraction, the author's
   own future-work note), and rotate `K_TT`.
3. **F4:** specify fixed-K padding and state the residual (coarse leakage over-cap,
   active inflation) honestly; delete the "not a global passive adversary" sentence.
4. **F11:** reconcile the two witness sentences; mandate full commitment-stream
   download or specify a non-leaking witness protocol.
5. **F1/F6:** specify per-diversifier, domain-separated derivation.
6. **F10:** bind `e` in `π`; canonicalize the DS AD.
7. **F7:** consider fraud proofs or consistency attestations for bucket completeness
   if DS trust is ever meant to be weaker than "partially trusted."

## External context

Per `research/EXTERNAL.md` (all URLs verified at fetch time):

- **No independent published analysis of this design exists** — the author's
  "please break the protocol" invitation was never publicly answered. ZIP 314 (his
  number) remains a Reserved stub; nothing like Mix Authorities or Detection Servers
  was ever standardized.
- The design's `K_TT = H(s)` + per-epoch `e` + server-blinded `G_r` exists to dodge
  **gtank's 2019 break** (statically derivable detection keys). F2 shows the dodge
  is incomplete against the server itself: what a sender can compute, a
  sender+server pair can compute.
- The author's own later statements corroborate the surviving findings: the
  count-leak is inherent (his Jan 2024 Aztec-forum reply), detection keys are
  "break in once … detect forever" (his Dec 2023 forum critique — F8's shape), and
  the witness-exclusion dichotomy (his Apr 2024 #6756 comment — F11's substance),
  which he never tied back to this design.
- **Post-adjudication novelty:** F2 and F8 are the genuinely novel results; F3b
  (deletion discipline cannot protect history given `ssk`), F4's refuted sentence,
  and F11's quantified trap are novel sharpenings; F1/F6 are specification notes;
  F12/F13 are literature caveats.

## Provenance

The analysis pipeline, including the adversarial defense pass that corrected earlier
drafts of this report, is documented in [`ADJUDICATION.md`](ADJUDICATION.md) and
[`defense/`](defense/) (four defender reports, counter-experiments, and a
machine-checked audit of this campaign's own formal artifacts — which found and
fixed a vacuity defect in the Lean break theorems; evidence citations in this
document reflect that correction). Reproduction commands: see [`README.md`](README.md).
