# CRYPTO-DEFENSE.md — Referee report on the F1–F13 attack campaign

**Role:** cryptographic defender / referee. Mission: try to *disproving* the attack
**mechanics** — find mathematical, protocol-mechanical, or simulation-fidelity errors.
**Method:** read the article (fetched 2026-10-23), re-derive every load-bearing equation,
re-run `sim/run_all.py` and `analysis/f11_witness_leak.py` (both reproduce FINDINGS's
verdicts byte-for-byte), and instrument the F11 simulation to characterize its candidate
sets. Article citations below use the fetched text of
`defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm`.

**One-line result.** The campaign's *cryptography* is essentially flawless — F2/F3/F8
algebra and the F11 exclusion rules all check out. The defense wins on **relevance and
framing**, not on math: F11 is refuted *as an attack on the article as written* (the
article mandates exactly the leak-free behavior F11 assumes is avoided), F2's
"zero compromises" equivalence claim and F3/F8's "breaks P6" verdicts overstate
conditioned claims whose premises (not implications) are attacked, and F4 is
instantiation-dependent.

## Verdict table

| ID | Verdict | One-line reason |
|---|---|---|
| F1 | **SURVIVES** | Textually faithful reading; real spec gap; honestly labeled "fixable". |
| F2 | **OVERSTATED** | Mechanics verified end-to-end; but exact-tx attribution still needs the MA's decode map (= the MA compromise P5 posits). "Zero compromises" holds only for the counts component. |
| F3/F9 | **SURVIVES** (framing corrected) | K_TT is static; retained-or-rebuilt index verified; variant (b) is sound and *not* circular. But it breaks P6's *premise* (durable address secrecy), not the conditioned implication. |
| F4 | **CONTESTED** | Volume/latency leak is real for session-shaped delivery and intermittent-online wallets; the article's "fixed-size packets at regular intervals" admits an always-on cover reading that reduces F4 to the author's own conceded trilemma. |
| F5 | **SURVIVES** (minor) | Trivially real; author already names it and its mitigations/limits. |
| F6 | **SURVIVES** (as hazard) | Not a break of specified behavior — the article specifies nothing; correctly labeled "High *if misderived*". |
| F7 | **SURVIVES** | Withholding/pollution verified; no fraud-proof in spec; fair severity. |
| F8 | **SURVIVES** | Scalar cancellation is algebraically airtight (verified against published D, all-epoch derivation, prospective + retroactive variants). Conditional-premise caveat noted. |
| F10 | **SURVIVES** (minor) | Spec wrinkles are real. |
| F11 | **REFUTED as written** | The article *mandates* full commitment+nullifier set download for every wallet ("All wallets must always download and authenticate the entire note commitment and nullifier sets" — twice). Under the design as specified there is no per-wallet sibling-fetch pattern; F11's "option (b)" is the campaign's own unstated optimization. Math itself sound; see concessions. |
| F12 | **SURVIVES** (minor) | Standard (n−1)/dilution math correctly applied; P7's absolute wording is indeed wrong. |
| F13 | **CONTESTED** | SDA/intersection principle correctly invoked; hinges on external 2026 measurements not re-verifiable here; labeled caveat, not protocol bug. |

---

## 1. F2 — sender-collusion attribution: mechanics verified, framing overstated

### 1.1 Mechanics re-derived against the article (all check out)

* **Do DSs index the victim's post-mix ciphertexts?** Yes. The article: DSs obtain the
  (public, signed) post-mix list and "for each C^PoM_i … use their secret key ssk to try
  to decrypt C^T_i. If this works, they obtain T and π, and after checking π, they enter
  C^L_i into their database indexed on T." They *attempt* every ciphertext and succeed on
  all addressed to their own registered S_r's — which includes the victim, since the
  victim registered there. The victim's DS necessarily holds `T_e ↦ {C^L}` for every
  epoch the victim receives. FINDINGS's phrasing ("covering all of its users") is exact.
* **Is the tag epoch-independent in its keys?** Yes: `T = PRF^T(K_TT, G_r‖e)` — only the
  *input* varies with e; `K_TT` and `G_r` are static address elements. One-time
  disclosure of `(K_TT, G_r)` yields `T_e` for every past and future epoch. The author
  concedes the consequence himself: "knowing G_r, K_TT, it can re-compute the address's
  tags for each epoch."
* **Must a sender know K_TT?** Yes — the address is `(addr, G_r, S_r, K_TT, D)`; steps
  2–7 of sending consume `G_r` (epk base), `S_r` (C^T recipient), `K_TT` (tag and D\*),
  `D` (D\*). There is no sending path that withholds them.
* **Could the intended design have per-epoch K_TT that the campaign missed?** No. Tags
  must be computable by *arbitrary* senders from *static* address data. Any static,
  sender-derivable tag seed is functionally a static K_TT; per-epoch secrets would have
  to be either shipped in the unbounded address or derived from public data + e, which
  is exactly `PRF^T(K_TT, G_r‖e)`. No missed reading exists in the article's text.

### 1.2 Where the campaign overstates

* **"Equiv. to 'both servers compromised' … with zero server compromises."** The
  counts-only outcome (per-day receipt counts, retroactive, zero victim queries)
  genuinely needs only a malicious DS + one colluding counterparty — that part is
  correct and is the sharp observation. But **exact on-chain transaction attribution
  additionally requires the pre-mix↔post-mix mapping**, i.e. the Mix Authority's decode
  work product (the sim uses `mas[0].reveal_pre_post_map`, documented "COLLUSION
  ONLY"). An MA handing an attacker its decode map *is* the MA compromise that P5's
  "a Mix Authority … compromised" contemplates, in every sense but the word. A single
  colluding sender can map only its *own* transactions, not the victim's others.
  Correct statement: **F2 removes the DS-compromise half of P5's conjunction; the
  MA half is unchanged.**
* Note also that a malicious DS operator is already inside P3/P5's adversary
  ("compromised Detection Server"); what F2 truly adds is that the *address* — the one
  secret the granular-delegation properties lean on — reaches the DS without any breach
  of the DS, via any one counterparty. That structural point is correct and important,
  and the author's text never states it.

**Verdict: OVERSTATED** (mechanics SURVIVE; the P5-equivalence/"zero compromises"
claim must be qualified as above).

---

## 2. F3/F9 — no forward secrecy of K_TT

### 2.1 Variant (a) — retained index + later address leak

Mechanically sound and article-faithful: the DS's "database indexed on T" is functional
service state; footnote 1 mandates deleting only the *identity↔tag* association and
lookup-order traces — not the buckets. Registration log `(IP, r, G_r)` is in-spec (the
wallet "sends r to the Detection Server"). Sim `A_F3` variant (a) reproduces counts
exactly and ties back to the registering IP.

### 2.2 Variant (b) — ssk leak ⇒ post-hoc rebuild from public lists

Mechanically verified:

* Post-mix lists are public authenticated data (MAs "publish and sign" them; anyone,
  including a GPA, can archive them forever).
* Every historical C^T remains openable by `[ssk]epk` — that is the article's own
  decryption trick; AD `"tct"‖e` is derivable from the list's epoch.
* The sim conservatively gives the attacker a *fresh* server holding **only** `ssk`
  (no reglog, no index) and rebuilds the full historical index; counts match ground
  truth.

**Is variant (b) circular or weaker than stated?** Neither, but its delta over (a)
should be stated precisely:

* (a) needs: retained index + address.
* (b) needs: ssk + address + archived public lists — and *defeats the footnote-1
  deletion defense*: a disciplined server that purged everything still leaks `ssk`
  under P6's own adversary ("even if the private state of all … Detection Servers
  leaks"), and the index is reconstructible from public data. So (b) is strictly
  stronger against deletion discipline, at the cost of the ssk assumption (which P6's
  adversary grants). It is not circular — it assumes strictly less retained state.
* Both variants still need the address (`K_TT`); neither gives identity tie-back
  without the registration log. The sim models this honestly.

### 2.3 Framing correction

P6's sentence is explicitly conditioned: *"when addresses are kept secret, even if the
private state of all Mix Authorities and Detection Servers leaks, the attacker can …
not connect the groups from different days."* Without `K_TT`, per-epoch tags are PRF
outputs — cross-day buckets are cryptographically unlinkable, retained index or not.
So F3/F9 do **not** refute the conditioned implication; they demonstrate that its
premise ("addresses are kept secret" as a durable state) is structurally fragile —
held by every counterparty, and a single later disclosure *retroactively and
irreversibly* converts the leaked state into full history. The honest verdict label is
"breaks P6's premise," not "Breaks P6." FINDINGS's own body text mostly says this;
the verdict-table cell overstates.

**Verdict: SURVIVES** (mechanics, incl. variant (b)); table framing should be
"P6-premise break."

---

## 3. F8 — dsk cancellation

### 3.1 Algebra (all confirmed)

Article, verbatim: the wallet "constructs its epoch detection secret key
dsk + PRF^D(K_TT, e) and provides it and the epoch number e to the new Detection
Server." In a prime-order group (order q), the delegation value is the scalar
`x_e = dsk + f_e mod q`, `f_e = PRF^D(K_TT, e) mod q`. Given `K_TT` (any address
holder — a colluding sender suffices, F2's structural fact) and `e` (handed over):

```
dsk = x_e − f_e  (mod q)
```

Confirmed in sim `A_F8`: recovered scalar satisfies `[dsk]G_2 == D` against the
*published* D — the algebra is checked against an independent public value, not
against the sim's own bookkeeping. The sender supplies `K_TT` in the address; no
other secret is needed.

**Does dsk yield all epochs' keys?** Yes. For any epoch e′ (past, never-delegated, or
future): `x_{e′} = dsk + PRF^D(K_TT, e′)`, and C^D opens under `[x_{e′}]epk` since
`D* = D + [PRF^D(K_TT,e)]G_2 = [x_e]G_2` and the Enc shared secret is symmetric:
`[esk]D* = [esk·x_e]G_2 = [x_e][esk]G_2 = [x_e]epk`. The sim demonstrates epochs 1–4
including a never-delegated past epoch and a future epoch, with zero further victim
queries; the retroactive variant (retained `x_e` row + later address leak) follows
identically. Sim note: the only scalar handover is the in-spec delegation point
(`V.delegate_scalar` → `ds1.learn(x)`); the address disclosure is a separate, labeled
collusion point — fidelity is clean.

**Could a corrected design hand over something non-linear without changing the text?**
No — the text pins the mechanism: the delegate must *use* the handed value to open
D\*-ciphertexts, which in DH-land means a scalar that is affine in dsk by construction
of D\*. Independent per-epoch detection keypairs are impossible without breaking
sender-side derivation of D\* from the static address. The only in-article escape is
the author's own IBE note ("the non-indexed case can probably be improved so that it
does not rely on address secrecy") — i.e., the author *knew* this case rests on address
secrecy; F8 makes the failure mode precise and shows it is worse than "detection for
the requested epochs."

### 3.2 Honest qualifications (not refutations)

1. The attacked sentence is *conditioned*: "As long as their address is kept secret,
   the new Detection Server is only granted … limited … epochs." F8 requires that
   condition to fail. FINDINGS's body quotes the condition in full; the verdict-table
   cell ("Breaks P6") again elides premise-vs-implication.
2. Marginal-novelty note: on address disclosure, the *indexed* path already gives the
   index-holding DS perpetual detection (author-conceded). F8 is strictly stronger
   because (i) it binds to `dsk`, which works from **public post-mix lists** with no
   index and no ssk, so *any* server the victim ever delegated one epoch to — not just
   its current DS — acquires the capability; (ii) it survives DS switches (D travels
   with the address; old DS's lose C^T access but C^D detection persists); (iii) it is
   retroactive from a retained 32-byte row. These points *are* in FINDINGS; they
   should be headlined as the delta over the conceded case.

**Verdict: SURVIVES** (as a premise-conditional escalation; algebra airtight).

---

## 4. F11 — witness-exclusion leak: **REFUTED as an attack on the article as written**

### 4.1 The article's own text mandates the leak-free behavior

F11's premise is that the performance-optimized wallet fetches *only its needed
siblings*, creating a wallet-specific fetch stream for a watching server to read. The
article says the opposite, twice:

* Performance list, bullet 1: "**The wallet must authenticate and sync the note
  commitment and nullifier sets.**"
* Receiving Transactions, opening sentence: "**All wallets must always download and
  authenticate the entire note commitment and nullifier sets.**"

Under the design as specified, *every* wallet downloads *every* note commitment —
which is exactly the "fetch-all" strategy that the campaign's own simulation shows is
leak-free ("zero positional information"). There is no wallet-specific commitment
fetch pattern for any server to observe; two additional reinforcing points:

1. Witness/sibling data is generic consensus data — servable by *any* full node, not
   only the Detection Server; nothing in the article routes witness fetches through
   the DS. "Update the witnesses … as usual" in Zcash practice means *local* incremental
   updates from block data the wallet already has (because it synced the full
   commitment set), not per-wallet remote fetches.
2. FINDINGS's parenthetical "(a) download all note commitments each epoch — Θ(#outputs)
   bandwidth, i.e. **the very cost the protocol was designed to eliminate**" is
   factually wrong about the article: the design *keeps* Θ(#outputs) commitment
   download as a stated requirement. What it eliminates is Θ(#outputs) *transaction
   ciphertext* download plus *trial-decryption compute* over history. The campaign's
   own `research/EXTERNAL.md` repeats the error ("the article never resolves how
   witness siblings are obtained privately") — it is resolved, by mandating full
   download.

### 4.2 The bandwidth computation (why the mandated fetch-all is consistent)

Realistic parameters: Orchard note commitment = 32 B; nullifier = 32 B; throughput
50–100 shielded outputs/min.

| Outputs/min | Outputs/day | Commitments | + Nullifiers (≈1:1) | Sustained |
|---|---|---|---|---|
| 50  | 72,000  | 2.3 MB/day | ≈ 4.6 MB/day | 53 B/s |
| 75  | 108,000 | 3.5 MB/day | ≈ 6.9 MB/day | 80 B/s |
| 100 | 144,000 | 4.6 MB/day | ≈ 9.2 MB/day | 107 B/s |

Contrast with what the design avoids: output ciphertext for trial decryption
(≈700 B/output Orchard action ciphertext, excluding proofs/tx overhead) is
50–101 MB/day, plus the compute. So:

* The mandated full commitment sync costs **~2–9 MB/day (53–107 B/s)** — entirely
  consistent with the article's performance claims, and in fact *cheaper per output*
  (32 B vs 116 B) than today's ZIP 307 compact blocks that light wallets already
  tolerate.
* The sibling-only optimization F11 attacks would save at most ~2–5 MB/day — a
  rounding error (~5–10% of the avoided ciphertext volume) that no implementer would
  trade receiving privacy for. The optimization is not proposed by the article and is
  implausible on its own economics.

**Conclusion: F11 must be requalified** — it is a valid analysis of an *unstated
optimization variant*, not of the protocol the article specifies. Against the design
as written (all wallets, full commitment set, identical fetch patterns), there is no
positional side channel in the witness channel.

### 4.3 The simulation itself: rules audited and (mostly) conceded

I re-derived and instrumented `analysis/f11_witness_leak.py`:

* **Absence rule is sound**: if the wallet's note were inside the sibling range of an
  in-window finalized block (l,i), a correct witness requires fetching (l,i); hence
  "not fetched ⇒ note not in sibling(i)'s range." The code correctly does *not* use
  "fetched ⇒ not in range" (decoys may cover the note).
* **First-sync completeness is sound** for the fetch-exact model: a wallet building
  its first witness must fetch every sibling finalized to date, so any candidate whose
  pre-existing sibling set is not contained in the first observed fetch set is
  excluded.
* **My one correction runs against the defense's favor**: the "8193 candidates stuck"
  headline in the pre-synced regime looked like a concession of weakness. It is not.
  Instrumentation shows the surviving set is exactly `[0, 8191] ∪ {p_true}` — the
  *frontier note is still pinned to a single position* (every other in-window
  position is excluded by its own finalized-and-unfetched leaf sibling); the 8192
  survivors are the pre-surveillance history, which no in-window observation can
  differentiate. The script's printed verdict ("frontier region pinned; only
  pre-watch history stays ambiguous") is accurate. So *within its model*, F11 is
  strong even pre-synced for notes created after surveillance begins.
* Concessions that survive the requalification: if any future ZIP adopted
  sibling-only fetching from a watching server, the math here is correct and severe,
  and the author's own Apr 2024 comment (zcash/zcash#6756) is genuine corroboration
  of the general principle. The finding is a useful *hazard annotation* for
  implementers — but it is not a break of the 2023 text.

**Verdict: REFUTED as written** (requalify to "applies only to an optimization the
article does not propose; the article's stated requirements are the leak-free ones").

---

## 5. sim/ fidelity re-audit (task items)

Ran `sim/run_all.py`: 17/17 verdicts match FINDINGS. Spot-audits:

* **(a) A_F2's MA mapping.** Yes — the exact-attribution step consumes the colluding
  MA's decode map (`reveal_pre_post_map`, honestly labeled "COLLUSION ONLY" in
  `protocol.py`). FINDINGS's body discloses this ("Add any single
  colluding/compromised Mix Authority") but the headline ("zero compromises",
  "P5 equivalence") obscures it → see §1.2. The counts-only component is genuinely
  compromise-free beyond a malicious DS.
* **(b) A_F8 handover points.** Verified: the only scalar handover is the in-spec
  delegation; the address disclosure is a separately labeled collusion point; the
  article's condition sentence is quoted in full in FINDINGS F8's body. Clean.
* **(c) N_e's information-theoretic claim — rigorous.** For uniform independent esk
  in a prime-order group: for *any* base X = [a]G, esk·a is uniform ⇒ epk uniform;
  [ssk]epk is a bijection of a uniform value ⇒ uniform; the "shares my base"
  predicate is degenerate (every element is a multiple of every base). Zero mutual
  information between the ciphertext transcript and the base, information-theoretically.
  Caveats (implementation-bias in esk, encoding side channels) are correctly excluded
  as non-protocol failures. The toy-group enumeration confirms exactness.
* **Other checks, faithful**: π same-base binding enforced at the DS against the
  *opened* (T, epk); AD epochs from the post-mix list's epoch, never sender-claimed;
  dedup on decoded C^PoM bytes; note authentication against the *claimed* epoch's
  tree; attack code never touches `_`-private fields or the ground-truth oracle
  except for verdicts; every BLOCKED verdict carries a working negative control.
  A_F7b's forged C^PoM carries a *valid* π (the attacker legitimately holds the
  address) — a genuine, non-rigged count-pollution path.
* **Process observation (not a mechanics flaw)**: per `sim/VERIFICATION.md` §1, the
  sim was rebuilt from scratch at verification time — the artifacts now exist and
  reproduce FINDINGS, but the "Confirmed by" column of FINDINGS was written before
  them.

---

## 6. Remaining findings (briefer)

* **F1 — SURVIVES.** "Derives secrets s, r, dsk from their viewing key" textually
  omits the diversifier; under that (most direct) reading the extension tuple is
  identical across diversified addresses and sender-linkage is plain equality. Fair
  caveat: a charitable author could include the diversifier in the derivation base;
  the article does not say so, and the campaign labels the finding a fixable spec
  bug. The redundancy-address corollary holds under the naive derivation.
* **F4 — CONTESTED.** The trilemma is the author's own; what is new is choosing the
  instantiation. "Fixed-size packets sent at regular intervals" plausibly denotes an
  always-on cover channel, under which byte-volume is constant by construction and
  the GPA learns nothing *while the wallet is online* — at the author's conceded
  "all wallets download lots of data" cost. The campaign's sim models the
  session-shaped reading (bucket-sized session) without testing the always-on one.
  That said, light wallets are intermittently online by nature; catch-up bursts after
  downtime re-introduce volume ∝ backlog, and delivery latency ∝ count is a residual
  channel observable through post-receipt behavior. Real tension, overstated
  universality ("P1 … unachievable").
* **F5 — SURVIVES (minor).** A live server sees IPs; the author already proposes
  fresh Tor circuits and already concedes GPA/timing defeats. Restatement with
  emphasis.
* **F6 — SURVIVES (as hazard).** The article specifies no derivation; the finding
  correctly conditions on a mis-instantiation and demonstrates the catastrophe in the
  `s := r` and `ivk` modes. Not a break of specified behavior.
* **F7 — SURVIVES.** Withholding is silent and detection-free in-spec (no fraud
  proofs); count pollution via valid-π forged C^PoM at zero on-chain cost is real and
  correctly separated from the authenticated-garbage non-break N_g.
* **F10 — SURVIVES.** π not binding e is a genuine spec wrinkle; consequences
  correctly bounded (bucket-not-queried / commitment-position check).
* **F12 — SURVIVES (minor).** Threshold-batch dilution math is standard and correctly
  applied; fees bound the attack; P7's "epoch-sized anonymity set" wording is indeed
  wrong (it is "honest-outputs-per-epoch"). Bibliographic attributions not re-verified
  here.
* **F13 — CONTESTED.** SDA/intersection erosion of constant-shape R+F cover is a
  correct application of known results; the 2026 lwd-mixnet-proxy measurements come
  from the campaign's own external research and were not re-verified here. Honestly
  labeled "realistic-deployment caveats rather than protocol-logic bugs."

---

## 7. Corrections demanded of the campaign

1. **FINDINGS F11**: delete/replace "(a) … the very cost the protocol was designed to
   eliminate" — the article's Performance Properties *require* syncing the entire
   commitment and nullifier sets; requalify F11 as applying to a sibling-fetch
   optimization the article does not propose (bandwidth table in §4.2 above).
2. **FINDINGS F2**: replace "zero compromises / P5 equivalence" with "removes the
   DS-compromise half of P5; exact attribution still requires MA collusion (the MA
   half of P5)." The counts-only component may keep the strong claim.
3. **FINDINGS F3/F8 verdict table**: "Breaks P6" → "breaks P6's premise (durable
   address secrecy); the conditioned implication is not contradicted." Both finding
   bodies already contain the correct conditional language.
4. **research/EXTERNAL.md**: "the article never resolves how witness siblings are
   obtained privately" is contradicted by the article's mandated full download; amend.
5. **FINDINGS F4**: state that the always-on cover reading of "constant-bandwidth" is
   not modeled in A_F4, and that the trilemma is quoted from the author.

## 8. Honest concessions (where the mechanics are simply correct)

* F2's tag derivation, sender knowledge, and index readout: every step verified
  against the article's text; the author's own concessions corroborate the mechanism.
* F3 variant (b): sound, conservative (attacker modeled with ssk only), and it
  defeats the footnote-1 deletion discipline under P6's own adversary.
* F8: the scalar cancellation is airtight; the capability is retroactive and
  prospective, works from public lists, needs no index/ssk, and survives DS switches;
  verified against the published D.
* F11's internal mathematics: both inference rules are sound; and contrary to my
  initial reading of the "8193 candidates" output, the pre-synced regime *does* pin
  in-window note positions exactly (survivors = 8192 pre-watch positions + the true
  one). The flaw is relevance, not correctness.
* The simulation suite is unusually well-disciplined (knowledge vaults, negative
  controls on every BLOCKED verdict, collusion points as explicit `learn()` calls,
  ground-truth oracle used only for verdicts). No rigging was found.

**Overall judgment.** As cryptanalysis of the protocol's algebra: campaign wins
everywhere it matters (F2, F3, F8 mechanics are correct and the author's concessions
support the reading). As a refutation of the *article's stated claims*: the campaign
overclaims — P6/P1/delegation statements are conditioned, and the conditions are
attacked rather than the implications; and F11, the campaign's self-described
"strongest novel finding," does not apply to the design as specified, whose mandated
wallet behavior is the leak-free one.
