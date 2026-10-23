# ADJUDICATION — Final grading of the break campaign vs. the defenses

**Referee:** Chief Referee (post-defense adjudication pass), 2026-10-23.
**Target:** Hornby, *Making Zcash Light Wallets Faster and More Private* (Mar 2, 2023).
**Inputs:** `FINDINGS.md`, `PROTOCOL.md`, all artifacts (`sim/`, `quint/`, `lean/`, `analysis/`, `research/`), and the article itself (fetched and checked sentence-by-sentence against both sides' quotations).

**Provenance note (honesty first).** The four defender rebuttals
(`defense/TEXTUAL-DEFENSE.md`, `CRYPTO-DEFENSE.md`, `FORMAL-DEFENSE.md`,
`EMPIRICAL-DEFENSE.md`) were **not present on disk** — no `defense/` directory
exists anywhere in the workspace. Rather than stop, this adjudication
**steel-mans each defense** at the battlegrounds the dispute was known to turn
on — (a) F11 vs. the "entire note commitment set" sentence, (b) F2/F8 vs. the
"as long as their address is kept secret" conditionals, (c) F3 variant (b)
circularity, (d) novelty vs. author concessions, (e) F1/F6 ambiguity-vs-break,
(f) formal-artifact vacuity — and rules on the merits, verifying every factual
claim about the article directly against the fetched text. Where a steel-manned
defense would have overreached, that is recorded too (§"Adjudicating the
defense side"). If the defender files surface later, the grades below state
exactly which reading of the article each ruling depends on, so the ruling can
be re-audited against them line by line.

**What the referee re-ran and confirmed (all reproduce):**

- `sim/run_all.py` — 17/17 scenarios match FINDINGS (9 attacks BREAK, 8 non-breaks BLOCKED).
- `quint test quint/ZecLight.qnt --main ZecLightTests --match '^t_'` — 17/17 pass.
- `lean/` `lake build` — completes; axiom audit: every break theorem axiom-free except the two declared ideal-crypto axioms (`piVerified`, `pi_sound`), used only by the soundness theorems.
- `analysis/f11_witness_leak.py` — position recovered exactly in one epoch under selective fetching; fetch-all is leak-free; random decoys useless; spam-immune.
- Article (webfetch) — all load-bearing quotations verified verbatim, including: *"All wallets must always download and authenticate the entire note commitment and nullifier sets."*; *"The wallet must still update the witnesses for their unspent notes as usual."*; *"Only if both a Mix Authority and the wallet's Detection Server are compromised…"*; *"As long as their address is kept secret, the new Detection Server is only granted detection authority for a limited number of epochs."*; *"Only the Detection Server observes this leakage, not a global passive adversary…"*; footnote 1 (deletion discipline); and the Option-1/Option-2 paragraph in which the author **explicitly gives up address-unlinkability for performance-optimized wallets**.
- zcash/zcash#6756 comment of Apr 12, 2024 (webfetch) — verified verbatim: Hornby proves the witness-exclusion leak in general (*"the server observing these downloads can be sure that the wallet's note is not a sibling of any of the commitments that weren't downloaded"*), lists the same four mitigations, and does **not** connect it back to the 2023 design.

---

## Final grade table

| ID | Final grade | Severity | One-line ruling |
|----|-------------|----------|-----------------|
| **F1** | **OVERSTATED** | Low | As-written derivation text does link all diversified addresses (plain tuple equality) — but the article *explicitly disclaims* address-unlinkability for Option-2 wallets ("we will give up this privacy property; this is likely necessary"). Spec note, not a break of an implicit P0. |
| **F2** | **SURVIVES** | High | P5's "Only if both … compromised" exclusivity is false: a *malicious* (not breached) DS plus *one colluding past counterparty* (plus one MA for full on-chain mapping) reaches the same outcome; the antecedent "address kept secret from the DS" is structurally fragile for any payment address. One precision fix applied (a single non-MA sender unlocks only its own tx's mapping). |
| **F3/F9** | **OVERSTATED** | Medium | The literal P6 sentence survives its own hypothesis (perpetual address secrecy). The real, surviving content: `K_TT` is a never-rotated master linking key, the service *must* retain (or can rebuild, via `ssk` + public post-mix lists) its historical index, so any *later* address disclosure retroactively links all daily groups — and footnote-1 deletion discipline provably cannot prevent it. |
| **F4** | **SURVIVES** | Medium (was Med-High) | The article's explicit sentence "Only the Detection Server observes this leakage, **not a global passive adversary**" is refuted: fixed-size packets at fixed intervals fix the rate, not the duration/total; a GPA reads the count unless every wallet pads to worst case — the trilemma horn the author himself treats as a cost, not the design. Half-conceded by the author; the GPA-visibility claim and P1's absolute wording were not. |
| **F5** | **OVERSTATED** | Low | The article's "indexed lookups across days cannot be linked" is indeed false without network anonymity — but the article itself prescribes fresh Tor circuits per lookup and concedes GPA/timing defeat of that. Channel-level observation, standard mitigation; a deployment caveat. |
| **F6** | **OVERSTATED** | Note | Real spec-hygiene point; requires an implementer blunder ("derives … from their viewing key" standardly implies a KDF); the author demonstrably understands the `r`-leak danger (the optimizations section redesigns registration precisely to avoid disclosing `s`). |
| **F7** | **OVERSTATED** | Low | No stated property is violated: liveness is claimed only 1-of-N for *Mix Authority lists*; the DS is declared "partially trusted"; injected garbage fails note authentication exactly as the article specifies; withholding is detectable by the trial-decryption fallback that always remains. Corrected: forged pre-mix injection costs an on-chain fee — the "without sending real money" contrast with dust was wrong. |
| **F8** | **SURVIVES** | High | The algebra is mechanically verified (`dsk = x − PRF^D(K_TT, e)`: Lean cancellation lemma + exact sim recovery) and irrefutable. "Only granted detection authority for a limited number of epochs" is false in any world where the delegate — by construction the "less-trustworthy" server — ever obtains the address; the retained 32-byte scalar makes the grant irreversible. Corroborated by the author's own Dec 2023 "break in once … detect forever" critique of detection keys. |
| **F10** | **SURVIVES** | Low | Correct spec wrinkle; `π` should bind the epoch; downstream checks catch most consequences. Unchanged. |
| **F11** | **OVERSTATED** | Medium | The design-**as-written** evades the leak: the Receiving section mandates downloading *"the entire note commitment and nullifier sets"* (Hornby's own 2024 horn (a): complete privacy at Θ(#outputs) × 32 B — a few MB/day at current volume, far below trial-decryption bandwidth, so the perf advantage does *not* "collapse"). What survives: an unreconciled internal tension (the perf list's "update the witnesses … as usual" invites the ZIP-307-style selective fetch every real light wallet implements), a genuine trap for implementers, quantified sharply by the analysis script, and anticipated as an open hard problem by the author's own Apr 2024 proof — which he never tied back to this design. |
| **F12** | **OVERSTATED** | Note | The Serjantov–Danezis (n−1)/threshold-batch math does **not** transfer: an attacker cannot delay or exclude other on-chain outputs, so the batch always contains every honest output and the anonymity set against any attacker remains the honest count — the same as the no-flood baseline. Flooding adds only entries the attacker can already exclude. Residue: "epoch-sized" should read "honest-outputs-that-epoch-sized" (the article's own "without additional information" hedge nearly covers it), and quiet epochs are naturally small. |
| **F13** | **OVERSTATED** | Note | Literature-true and useful as deployment context, but `R+F` is an *optional* obfuscation with no claimed security property, the stated baseline (Loopix) shares the same acknowledged gap, and the Nym-proxy measurements describe a different protocol stack. Caveat, not a finding. |
| **F10 (sound list)** / verified-sound | **SURVIVES** | ✅ | All eight non-breaks hold in the re-run artifacts. One caveat added: N_e's "no base-equality test" is *computational* (DDH/key-privacy) in real groups — information-theoretic only in the sim's toy group; and the Quint `p8b`/`mixSoundness` proofs are by-construction in the model, so the load-bearing evidence is sim `N_a–N_g` + Lean `thm_Nb/Nc/Nd`. |

**Tally: 4 SURVIVES (F2 High, F8 High, F4 Medium, F10 Low, plus the verified-sound list intact) · 8 OVERSTATED (F3 Medium, F11 Medium, F1/F5/F7 Low, F6/F12/F13 Note) · 0 REFUTED · 0 CONTESTED.**

---

## Per-finding reasoning

### F1 — diversified-address linkability → OVERSTATED (Low)

The attack is mechanically right: if `s, r, dsk` are derived from the viewing key alone (and in real Zcash the viewing key *is* diversifier-independent — that is the point of a viewing key), every diversified address of the wallet carries the identical `(G_r, S_r, K_TT, D)` extension, so any two parties each holding one address link them by plain equality; sim `A_F1` and Lean's `thm_F1_diversifierLink` (an `rfl` on the modeling) confirm.

The textual defense wins the *claim*, however, on a sentence FINDINGS never quoted. The article's Option-1 paragraph defines address-unlinkability privacy and states: *"In the performance-optimized option, we will give up this privacy property; this is likely necessary, as we will discuss later."* The given-up property — "even an adversary who knows a wallet's address and has compromised the light wallet server cannot find out which wallet the address belongs to" — is a *stronger* protection than two-sender address linking; surrendering it entails surrendering sender-level diversifier unlinkability. Moreover, the article's own P6 semantics ("group transactions within a day **by wallet**") presupposes wallet-shared tags — per-diversifier tags would group per-address, not per-wallet.

What honestly remains: the derivation text is under-specified and should bind the diversifier if per-address pseudonymity is ever wanted (it also bounds F2's blast radius per counterparty); and the sacrifice is *total* (plain equality, no server involvement needed) — sharper than the article's vague "give up this privacy property" telegraphs. That is a Low spec note, not a High break of an implicit property.

### F2 — sender-collusion equivalence → SURVIVES (High)

Verified against the article's own words. P5 states an exclusivity claim: *"Only if both a Mix Authority and the wallet's Detection Server are compromised, the attacker learns exactly which transactions belong to the wallet."* Two things are wrong with "only … compromised":

1. A *malicious* DS operator (the article itself uses "malicious or compromised" interchangeably in P2) needs no breach. The index it builds while serving all users *is* the P5 capability; what it lacks is only the tag.
2. The tag is held by **every past counterparty by construction** — the address tuple `(K_TT, G_r)` is what sending requires. The article treats "the Detection Server knows the address" as a notable event; F2 shows the DS can manufacture it at the cost of one payment to the victim, or by suborning any one counterparty. The delegation guarantees are conditioned on an antecedent that a payment-receiving wallet cannot keep.

The defense's counter — "conditional claims are conditionally true" — proves too much: it would empty *every* conditional security statement of content, and it cannot rescue the "Only if" exclusivity sentence, which is falsified in the collusion world with zero server breaches (sim `A_F2`: recovered txids equal ground truth; Quint `p5_bothNeeded` counterexample; Lean's symbolic `thm_F2_senderCollusion/indexReadout` carry the formal core).

Precision correction (adopted into FINDINGS): the parenthetical claiming a single non-MA sender "unlocks the pre-mix↔post-mix mapping" overstated — a sender recognizes only **its own** `C^PoM` in the post-mix list; full-epoch on-chain attribution needs one MA (or every sender). The DS+MA collusion version of the attack stands unchanged, and no server *compromise* is needed in any version.

### F3/F9 — no forward secrecy of `K_TT` → OVERSTATED (Medium)

The defender wins the literal sentence: P6's cross-day claim is expressly conditioned on address secrecy at and after the leak, and under that hypothesis it is true — the leaked DS state contains no `K_TT`, so tags of different days cannot be tied together by tag content alone.

The attacker wins the operative security question, and the finding is restated honestly rather than withdrawn:

- The DS **must** retain its per-tag index for past epochs — that is how a resyncing wallet "fetch[es] its transactions quickly" for "all days previous to the current one." Footnote-1 discipline deletes identity↔tag associations and lookup order; it cannot delete the index without deleting the service.
- Therefore a **single future address disclosure** (any counterparty, any invoice leak — the F2 event) retroactively links **all** retained daily groups: `T_e = PRF^T(K_TT, G_r∥e)` is computable for every past `e` from the address alone. Verified end-to-end in sim `A_F3` (`retro == truth` across three epochs).
- **Variant (b) is not circular, and it genuinely defeats footnote 1:** its point is not "an address leak is needed anyway" but that *deletion discipline is the wrong defense* — post-mix lists are public and every historical `C^T` remains trial-decryptable under `ssk`, so a later `ssk` leak rebuilds the entire historical index regardless of what was deleted. No operational discipline short of destroying the live service key protects history.

So the honest claim: the design has **no forward secrecy** — `K_TT` is a permanent master linking key, and time severs nothing. The article's IBE musing (deleting old DS private keys for "stronger forward-security and backward-security properties") shows the author thought about forward security for *server* keys but never for `K_TT`. That is a Medium finding against a claim whose literal wording survives.

### F4 — volume/duration side channel → SURVIVES (Medium, from Med-High)

The author's own trilemma paragraph concedes most of this — but then draws the wrong conclusion from it, and that conclusion is the finding. The article states: *"Only the Detection Server observes this leakage, **not a global passive adversary**, because the Detection Server always sends detected transactions over a constant-bandwidth protocol (e.g. in fixed-sized packets sent at regular intervals)."* This is false as written: a constant *rate* with payload ∝ received-count makes session duration/total volume ∝ count; a GPA observing encrypted traffic — exactly P1's adversary — reads `n_e` up to padding granularity. The only fix is padding every wallet to the worst-case bucket, which is the trilemma's first horn, which the author presents as one of three *costs to choose among*, not as the design's operating point. P1's absolute wording ("learn nothing about when or how many") inherits the same problem. Sim `A_F4` (1 vs 20 notes ⇒ 1 vs 11 packets) and Lean's `thm_F4_trilemma` (distinguishable-or-padded, for arbitrary volume functions) carry this. Novelty is partial — the trilemma is conceded, the GPA-visibility sentence is not — hence Medium, not Med-High.

### F5 — live-server IP linkage → OVERSTATED (Low)

Trivially true and never in dispute: the same IP/TLS session querying two epochs' tags links the daily groups in real time, deletion discipline irrelevant. But the article itself both names the mitigation (a fresh Tor circuit per lookup) and concedes its defeat by GPA timing correlation; `π_query` carries no identity, so the linkage is purely channel-level. The refutable residue — the sentence "indexed lookups across days cannot be linked" silently assumes the Tor mitigation the article frames as optional — is worth one sentence, not a Medium finding.

### F6 — under-specified derivation → OVERSTATED (Note)

The hazard is real in the abstract (if `s` and `r` are related, registration hands the server the tag key forever — sim `A_F6` demonstrates the `s = r` world). But "derives secrets from their viewing key" standardly means a domain-separated KDF; the attack requires a specific implementer blunder; and the author's optimizations section shows precise awareness of exactly this danger class (it redesigns registration to send only `G_s` precisely because sending `s` would be catastrophic). Spec hygiene note.

### F7 — liveness/completeness → OVERSTATED (Low)

Each sub-claim measured against what the article actually claims:

- *Withholding:* the article claims list availability (1-of-N Mix Authorities), never completeness against a malicious DS; the DS is declared "partially trusted." Detection of withholding exists — trial decryption, the always-available path the design keeps precisely as its escape hatch (at current-epoch cost for perf wallets, full rescan for history). A trust caveat, not a violated property.
- *Censorship:* a censoring MA's signed list diverges from the other authorities' lists — socially/operationally detectable, and availability is 1-of-N.
- *Injection:* garbage `C^L` fails note-commitment authentication exactly as the article specifies (the position-within-epoch check it mandates). The residual — the attacker can inflate the victim's per-tag bucket from the address alone, corrupting the count signal *upward* — is an integrity-of-signal note on a channel the article already concedes to the DS (P3), and it cuts both ways (honest wallets can use it as free-ish cover).
- Corrected in FINDINGS: forged pre-mix injection rides in an on-chain transaction and **costs a fee** — the claimed contrast with on-chain dust ("without sending real money") was wrong; the fee-free variant requires being/colluding with a Mix Authority.

### F8 — `dsk` recovery → SURVIVES (High)

The strongest finding, and the defense has no move here. The algebra is mechanically verified twice (Lean's `Derived.cancelL` in the free term algebra — the `x − f` cancellation needs nothing more — and sim `A_F8` recovering `dsk` exactly, `[dsk]G2 == D`, then silently detecting never-delegated and future epochs with zero further queries). The article hands the delegate `x = dsk + PRF^D(K_TT, e)` *and* `e`, verbatim; any address holder supplies `PRF^D(K_TT, e)`; subtraction yields `dsk` — a **permanent, silent, all-epoch detection capability**, from a delegation the article says is "limited."

The conditional defense ("as long as their address is kept secret") fails three ways: (1) the delegate is by the article's own framing the *"less-trustworthy"* server the victim is forced to use — the exact party most likely to seek the address, which F2 shows costs one payment; (2) the grant is **irreversible** — the server retains a 32-byte scalar, so an address leak *at any later time* (a year later, from a different counterparty) converts it to `dsk`; the article's "limited number of epochs" is a time-box the wallet cannot enforce; (3) the author's own December 2023 forum critique of detection keys — "the attacker can break in once, steal the detection keys, and then they forever have the ability to detect transactions" — is the same persistence property, self-corroborating that this shape matters. A defense denying verified algebra, or hiding behind a conditional whose antecedent F2 shows is structurally fragile, overreaches.

### F10 — epoch not bound in `π` → SURVIVES (Low)

Correct and correctly sized: `π`'s public inputs are `(T, epk)`; a mis-epoch tag mostly creates a bucket no honest wallet queries, and the DS's AD epoch (from the list, not the sender) should be specified canonically. Bind `e` in `π`. Spec wrinkle; nothing to regrade.

### F11 — witness-update exclusion leak → OVERSTATED (Medium)

The designated battleground, and the textual defense lands a real blow that FINDINGS must absorb: the article's Receiving section states — in a sentence the finding never quoted — *"All wallets must always download and authenticate the **entire** note commitment and nullifier sets."* Under that reading there is no selective sibling download for a server to observe; every wallet holds the whole commitment tree and computes Merkle paths locally. This is exactly horn (a) of Hornby's own 2024 dichotomy — *"the wallet downloads all note commitments, using Θ(#transactions) bandwidth, in which case it can update its note's witness in complete privacy."* The design-as-written therefore **avoids** the leak.

At what price, at realistic throughput? Commitments (and nullifiers) are ~32 B each. At 2026-typical shielded output volumes (tens of thousands of outputs/day) that is on the order of a few MB/day; under sandblasting-scale spam (millions of outputs/day) it reaches hundreds of MB/day — linear, unbounded under adversary spending, but still one-to-two orders of magnitude below the ciphertext volume that trial decryption requires. So FINDINGS' claim that the Θ-option collapses the design's advantage "to the compute cost of trial decryption itself" is wrong: the bandwidth advantage persists (smaller objects, no memos), and the compute advantage — the design's headline — is untouched.

What genuinely survives, and justifies Medium:

1. **The spec is internally unreconciled.** The performance list says "update the witnesses for their unspent notes **as usual**" — and "as usual" for every real Zcash light wallet (ZIP 307, lightwalletd/Zaino subtree roots) means *selective/incremental* downloads from a server, not full commitment-set sync. An implementer following the perf list's own idiom lands exactly on horn (b). The article never flags the tension between its two sentences.
2. **The author's own Apr 2024 proof** (verified verbatim) establishes that horn (b) leaks exclusion information per epoch, offers only weak mitigations, and calls witness updating "the most difficult part to scale privately" — without ever connecting it back to this design's "as usual." The campaign's contribution is making that connection concrete and quantified: one epoch of ordinary growth pins a new wallet's note position exactly; the attack is spam-immune (attacker entries die as candidates); random decoys are nearly useless; only fetch-all (or permanent (k+1)× smart-decoy cover with anonymity exactly 1+k) hides.

So: not a refutation of the design-as-written; a demonstrated trap for the design-as-it-would-naturally-be-implemented, sitting on an unresolved ambiguity, with the author's own later analysis conceding the underlying problem. Medium.

### F12 — epoch dilution → OVERSTATED (Note)

The literature citation is apt-looking but the attack does not transfer. Serjantov–Danezis (n−1) works because the attacker **controls the batch composition** of a threshold mix (delay the target's message, fill the queue with n−1 own messages, the mix fires with exactly attacker+target inside). Here the "batch" is a public on-chain epoch: the attacker can add outputs but can neither delay nor remove anyone else's. Every honest output of the epoch is always in the post-mix list, so the victim's cover against any attacker is the honest count `h` — *before and after flooding alike*. Flooding adds only entries the attacker could already exclude (its own), so "a day of spam at 10× improves linkage ~10×" was wrong as stated: it corrects an over-large *reading* of "epoch-sized," it does not shrink any adversary's uncertainty below the no-spam baseline. The article's sentence is itself hedged ("without additional information, each post-mix ciphertext is hiding in an epoch-sized anonymity set") — an attacker with outputs in the epoch has additional information by definition. Honest residue, worth a Note: per-epoch cover is the *honest output count of that day*, so quiet days are naturally thin cover — an attacker picks the day and spends nothing.

### F13 — intersection/SDA + delivery fragility → OVERSTATED (Note)

Both halves are true and both fail as findings against *claimed* properties. `R+F` dummy self-transactions: the article presents this as an optional obfuscation ("wallets **can** send random amounts … to obscure"), claims no security property for it, and its own declared state-of-the-art baseline (Loopix) explicitly leaves dishonest-provider statistical attacks as future work — Danezis SDA/MixFlow erosion is real but breaks no promise the article made. Delivery-channel fragility: the lwd-mixnet-proxy measurements (2 Mbps cover, 2–51% silent failures, timing re-link) are measurements of *Nym carrying gRPC*, not of the article's abstract "constant-bandwidth protocol"; they are valuable deployment context for anyone reviving the design, not a property violation. Keep as a Note for future implementers.

### Verified-sound list → SURVIVES (with two honest caveats)

All eight non-breaks reproduce in the re-run sim (17/17 verdicts, negative controls firing correctly — notably `N_a`, where the attacker *successfully constructs* valid π's over both bases and the block is the algebra, not a knowledge-check artifact). Two caveats now recorded in FINDINGS:

1. **N_e is computational, not information-theoretic, in real groups.** "No base-equality test for `epk`" holds unconditionally only in the sim's toy group; in a real group it is the DDH/key-privacy family. The design's load-bearing anonymity trick is sound *under standard group assumptions* — which FINDINGS' body already says; the table row now says it too.
2. **Quint's `p8b`/`mixSoundness` "proofs" are by-construction** (the model's own verification doc says so: "holds by construction (tautology)"). The load-bearing evidence for P7/P8 is sim `N_a–N_d` + Lean `thm_Nb/Nc/Nd` (which assume exactly `pi_sound` — the protocol's own assumption — and nothing else).

### Formal-artifact citations (the vacuity critique) — sustained in part

The Lean theorems prove the **formal cores in an abstract Dolev–Yao term model**: `thm_F1_diversifierLink` is `rfl` on the modeling (the content is in what is modeled — if derivation ignores the diversifier the tuples are *literally equal*); `thm_F8_dskRecovery` is cancellation in a free term algebra (the content is that nothing more is needed); `thm_F4_trilemma` parameterizes the volume function and proves the dichotomy for all of them. None of this is dishonest — the Lean README says "symbolic, not computational" — but FINDINGS' "Confirmed by" column read as *the protocol was verified* would overstate. The Quint "violated invariants" are violations **relative to the knowledge-closure model**; their value is proving no *unintended* protocol path rescues the property, while the concrete exploitation lives in `sim/` (idealized primitives: prover-oracle ZK, RO stand-ins, 257-bit prime-order group). FINDINGS' preamble and citations are being annotated accordingly: *abstract-model verification of the formal core + concrete-mechanics simulation* — which is exactly what this class of campaign can honestly claim.

---

## Adjudicating the defense side (where a defender would overreach)

Since the defender files are absent, this section records where the *steel-manned* defenses cross the line, so the record is balanced:

1. **Denying F8's algebra would be overreach.** The cancellation is mechanically verified in two independent artifacts and requires no assumption beyond scalar addition being cancellative. The only defensible positions are the conditional-antecedent reading (rejected above, three reasons) or a severity argument (rejected: the finding converts the design's stated benefit into a permanent compromise).
2. **Settling F11 with the "entire note commitment set" sentence alone would overreach.** The same article also says "update the witnesses … as usual," never reconciles the two, and its author later proved the selective reading leaks and called witness updating the hardest scaling problem — without connecting it back. A charitable reading that hides an internal tension the author himself later flagged is not a defense of the design; it is a defense of the prose.
3. **"Conditional claims are conditionally true" (F2/F8/F3) proves too much.** The article's conditions are presented as achievable operating states ("as long as their address is kept secret"), and P5 contains an *exclusivity* claim ("Only if … compromised") that the collusion world falsifies without any breach. Conditionality rescues the sentence's truth-value, not the security story the article tells with it.
4. **Reading the trilemma as having conceded F4 entirely would overreach.** The author conceded the *cost menu* and then asserted the GPA does not see the leakage — the one sentence F4 refutes. A concession of a tension is not a concession of the false sentence drawn from it.
5. **Treating F12's threshold-mix math as applicable would be attacker-side overreach** (recorded for symmetry): the (n−1) analysis requires batch-composition control the on-chain epoch denies.

---

## Addendum — reconciliation with the delivered defense reports

*Written after the four defense files arrived on disk (they postdate the steel-manned
ruling above; see the provenance note). The letter-grades stand; this addendum records
what the actual defenses add, adopt, or fail to change.*

1. **Lean vacuity — sustained, and sharper than §"Formal-artifact citations" above.**
   `defense/FORMAL-DEFENSE.md` ships a machine-checked proof
   (`defense/vacuity-check.lean`, compiles via `lake env lean`): the `Derived`
   adversary-knowledge predicate in `lean/src/Model.lean` has **no base-case
   constructor**, so `¬ Derived v` holds for every `v` — the hypotheses of
   `thm_F2_senderCollusion`, `thm_F2_crossEpochLinkage`, `thm_F2_addrLeakLinkage`,
   `thm_F2_indexReadout`, and `thm_F8_dskRecovery` are unsatisfiable and those
   theorems are **vacuously true** (they survive deletion of the inference rules they
   exercise). Dually, `QueriesTag.mk` has no premises, so the F5 theorems are
   unconditionally true. Consequence, adopted into FINDINGS' citations: the
   load-bearing evidence for F2/F8 is **sim `A_F2`/`A_F8` + Quint multi-step
   reachability (`p5_bothNeeded`, `p6b_limitedDelegation`, with honest baselines
   `t_P6b_honestDelegationScoped`) + `defense/CRYPTO-DEFENSE.md`'s independent
   verification of the algebra** — not the Lean break theorems, which are modeling
   scaffolding (the repair is mechanical: a context/base constructor for `Derived`).
   `thm_F4_trilemma` remains valid but elementary (`by_cases` on decidable equality);
   `thm_Nb/Nc/Nd` and `thm_F1_diversifierLink` (an honest `rfl`) keep their value.
   The Quint picture matches FORMAL-DEFENSE's classification: the "violated"
   invariants are violated-by-construction actions *whose preconditions must still be
   reached* — the genuine model-checking content — and the six Apalache-proved
   invariants are tautological in the abstraction (corroborating intent, not
   falsifying adversaries), as `quint/VERIFICATION.md` already conceded.

2. **Empirical defense (`defense/EMPIRICAL-DEFENSE.md`) — numbers adopted, grades unchanged:**
   - **F2 (SURVIVES, High) sharpened to its live core:** deletion discipline caps only
     the *retroactive* window — a live colluding pair reads the last `G` epochs (any
     grace ≥ 1, since the index must exist to serve the service) **and all future
     epochs forever**. "Retroactive pre-grace readout dies" is the only concession.
   - **F3b (inside F3, Medium) confirmed hard:** public signed post-mix lists +
     retained `ssk` rebuild **12/12 epochs under every deletion policy**; only the
     article's own future-work per-epoch keys would cap it.
   - **F4 (SURVIVES, Medium) with a practical split recorded:** padding to fixed
     `K ≥ 20` gives the passive observer **exactly zero** advantage at a flat
     ~29 kB/day (≈ 11–18 MB/yr) — the worst-case-padding horn is *cheap*, not
     performance-negating, so the passive-GPA variant is fixable in-protocol.
     What keeps the grade: the article's false sentence stands as written, wallets
     over cap (2–20% of a Zipf population) still leak coarsely, and **active**
     inflation (F7b dust/forgery, unbounded) defeats any fixed `K` from the address
     alone.
   - **F5 (OVERSTATED, Low) with a quantified residue:** fresh-circuit-per-lookup
     gives 0% DS-only cross-day linkage — but tags are *persistent pseudonyms*:
     re-querying at rate q = 0.05 re-links **64.3%** of wallets over 20 epochs, and
     catch-up bursts give the DS 80–100% recall at 28–55% precision. The residue is
     real but the article's own Tor framing covers its spirit.
   - **F11 (OVERSTATED, Medium) priced precisely:** full-set download costs
     2.8–13.8 MB/day at 1–5 ops/s (5.5–27.7 MB/day with nullifiers) = **1.6–6.4%**
     of the current-day transaction stream the article already mandates — so
     FINDINGS' "the cost the design exists to avoid" was numerically empty, and the
     corrected claim is "unbudgeted but small." Middle option (2^16-leaf subtree
     shards): the exclusion attack collapses the candidate set **once** to ~65,536
     then stops compounding (shard paths only re-pin at spend time) — a materially
     better defender position than leaf-level fetching.
   - **F8 (SURVIVES, High) closed exhaustively:** all seven textual readings of the
     delegation sentence were exercised — every reading that makes the service work
     hands the delegate a value linear in `dsk`; the non-leaking readings break the
     service; the two-epoch-cancellation reading contains no `dsk` at all; ephemeral-
     scalar deletion kills only the retroactive variant (contemporaneous collusion
     during any live delegation still recovers `dsk`). The only escape is the
     article's own IBE future-work note — i.e., a redesign.

3. **Textual defense (`defense/TEXTUAL-DEFENSE.md`) — one prosecution correction
   adopted, its strongest verdicts not:** FINDINGS' P1 paraphrase dropped the
   article's qualifier *"When implemented carefully"* — recorded (the F4 ruling
   already targeted the stronger, unqualified sentence that follows it, so the grade
   stands). TEXTUAL grades F5/F7/F10 as REFUTED where this adjudication rules
   Low/OVERSTATED/SURVIVES-Low: not adopted, because (F5) the article frames Tor as
   optional while asserting cross-day unlinkability; (F7) "partially trusted" covers
   availability, not silently-reduced balances, and count-pollution corrupts the one
   signal P3 concedes is protected; (F10) the `"tct"∥e` AD binds the *decryption*
   epoch, not `π`'s public inputs — the mis-epoch wrinkle is real, merely small.

4. **Crypto defense (`defense/CRYPTO-DEFENSE.md`) — independent verification
   recorded:** the F8 cancellation, F3b mechanics, N_e rigor, and sim discipline
   (knowledge vaults, negative controls, no rigging found) were re-derived by the
   defense side and **conceded correct**; its F11 bandwidth math and the F2 precision
   fix (a non-MA sender alone unlocks only its own transaction's mapping) are adopted
   into the record above.

**Final tally unchanged: 4 SURVIVES (F2 High, F8 High, F4 Medium, F10 Low) · 8
OVERSTATED (F3/F11 Medium; F1/F5/F7 Low; F6/F12/F13 Note) · 0 REFUTED · 0 CONTESTED
— with the defense campaign's own concessions independently confirming the two High
findings and materially sharpening the other eleven.**

## Bottom line

Of thirteen claimed breaks, **four survive adjudication as stated — F2 and F8 at High, F4 at Medium, F10 at Low — and eight are overstated but retain honest content: F3/F9 and F11 at Medium, F1/F5/F7 at Low, F6/F12/F13 as Notes; none is refuted outright, and the campaign's verified-sound list stands** (with the caveat that the `epk`-anonymity non-break is computational, not information-theoretic, in real groups). What the campaign actually established is narrower and sharper than its headline: the *cryptographic machinery* is sound where claimed, and the two genuine High findings are both **delegation-trust breaks, not cipher breaks** — (1) the article's privacy story is conditioned on "address secrecy from the Detection Server," an antecedent that fails for any wallet any counterparty of which can be suborned at the cost of one payment, which voids P5's "only if both compromised" exclusivity (F2); and (2) the non-indexed delegation scalar is a linear function of the master detection key, so one delegation plus any future address sighting yields permanent, silent, all-epoch detection (F8). What the campaign conceded, correctly under adjudication: the article had already disclaimed or half-conceded more than FINDINGS gave it credit for — address unlinkability for Option-2 wallets (F1), the count-leak trilemma (F4's substance), Tor-per-lookup and its limits (F5), partial-trust liveness (F7), and the honest-output anonymity floor (F12); the witness-exclusion leak (F11) does not touch the design-as-written, which mandates full commitment-set download, but sits on an unresolved ambiguity that any real implementation would resolve dangerously, exactly as the author's own 2024 analysis later proved. The design's real, surviving weakness profile: *sound algebra wrapped around a structurally fragile trust periphery* — every guarantee that matters is conditioned on an address that is by construction in every counterparty's hands, and on delegation values that never expire.
