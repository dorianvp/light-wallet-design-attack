# Textual Defense: "Making Zcash Light Wallets Faster and More Private" (Hornby, Mar 2023)

**Role.** Adversarial defense counsel for the protocol author. Task: test every finding
F1–F13 in `FINDINGS.md` against the **exact text of the article**
(https://defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm,
fetched and quoted verbatim below), on the principle that a "break" must violate a
claim **the article actually makes, under the assumptions the article actually
states**. Where the campaign's break genuinely survives the article's own text, it is
conceded.

**Method note.** The campaign's `PROTOCOL.md`/`FINDINGS.md` are the attackers'
framing. Two material misquotes/omissions were found and are flagged below
(§Global Defenses, G4): the campaign's P1 drops the article's "When implemented
carefully" qualifier, and the campaign's F11 ignores a sentence its own
formalization reproduces ("All wallets must always download and authenticate the
entire note commitment and nullifier sets").

---

## 0. Global defenses (apply across findings)

**G1 — The article self-identifies as a pre-spec sketch, not a spec.** Exact text:

> "I'm going to **sketch** changes to the Zcash protocol…"

> "***Warning:** There are almost certainly security bugs in the protocol described
> below that I haven't caught, so please don't implement this without careful thought!*"

> "The next steps for me are to … **think more carefully about the protocol design**
> to see if it can be simplified and optimized and to ensure there aren't any
> vulnerabilities, and … **collect feedback and write a ZIP**."

Findings that attack *under-specification* (F1, F6, F10) attack a document that
declares itself under-specified and forbids implementation. An omitted derivation
detail in a sketch is ZIP-work item, not a "spec bug" — there is no spec yet, by the
author's own words. ("If you are a cryptographer, please try to break the protocol!"
invites exactly this feedback — as contribution, not as refutation.)

**G2 — The design is explicitly two-option, and Option 2's weaker posture is stated.**

> Option 1: "The wallet is careful to always download every transaction … As a
> result, the externally-visible behavior of the wallet reveals no information about
> how many transactions it is receiving."

> "This option is for users who need extra-strong privacy guarantees, including
> *address unlinkability privacy*, where even an adversary who **knows a wallet's
> address** and has compromised the light wallet server cannot find out which wallet
> the address belongs to. **In the performance-optimized option, we will give up this
> privacy property; this is likely necessary, as we will discuss later.**"

> "Although the performance-optimized protocol **intentionally trades-off privacy**
> and adds a dependency on '1-of-2' trusted servers for the sake of performance, its
> privacy properties are still **much better than the reality today** where the light
> wallet server can learn precisely which transactions belong to which wallets…"

Findings that punish Option 2 for being weaker than Option 1 (F2, F5, parts of F4,
F13) punish a tradeoff the article announces in its second section. The design's
stated bar is *better than status-quo light wallets*, not *perfect*.

**G3 — The author's own concession inventory is extensive.** The article itself
concedes, in its own Security Analysis:

- DS-knows-address ⇒ user identification by IP ("Address Unlinkability" section).
- The DoS/volume trilemma, verbatim: "Either *all* wallets download lots of data
  when *any* wallet needs to, DoS attacks on addresses are possible, or wallets with
  addresses that receive lots of transactions are **identifiable by the amount of
  data the Detection Server sends to them**."
- Bucket inflation by the DS: "the Detection Server can send many transactions to
  the known address and watch which 'bucket' grows."
- Perpetual tag recomputation from the address: "knowing `G_r, K_TT`, it can
  re-compute the address's tags for each epoch."
- Sender self-linkage: pre-mix↔post-mix linkage holds "unless either you can decrypt
  a message encrypted to a Mix Authority's public key … **or you created the
  transaction yourself**."
- Non-post-quantum privacy, count data "vulnerable to being leaked" (conclusion),
  Tor/timing-correlation weakness, and — in Optimizations — that IBE with key
  deletion "**would provide stronger forward-security and backward-security
  properties**" (i.e., the base design has less).

Findings whose mechanism appears in this list are re-badging concessions as breaks.

**G4 — Campaign misquotes/omissions (referee's honesty check on the prosecution).**

1. `PROTOCOL.md` P1 states the headline property as "GPA observing encrypted traffic
   learns *nothing* about when/how many" — **omitting the article's opening
   qualifier "When implemented carefully."** That qualifier is load-bearing for F4.
2. F11 argues the wallet "fetches only the `C^L` … while 'updating witnesses as
   usual' requires downloading note-commitment siblings." The article's Receiving
   section opens: "**All wallets must always download and authenticate the entire
   note commitment and nullifier sets.**" The campaign's own `PROTOCOL.md` §7
   reproduces this sentence — and F11 then ignores it. See F11 below.
3. F2 characterizes address knowledge as "treated as an exceptional event." The
   article devotes two full subsections to the known-address case and calls it
   "always possible for **any design**" — the opposite of exceptional.

---

## F1 — Diversified-address linkability

**Campaign claim.** "Derives secrets `s, r, dsk` from their viewing key" ⇒ under the
naive reading (derivation from `vk` only), every diversified address shares
`(G_r, S_r, K_TT, D)` ⇒ any two senders link the addresses. High severity.

**Defense.**

1. **The article's text is underdetermined, and the naive reading is not the
   mandated one.** The exact sentence: "the wallet first generates **all of the
   usual components of an address as normal**, then derives secrets `s, r, dsk`
   from their viewing key." In Zcash, "the usual components of an address" are the
   diversified address components (ZIP 316), and in ZIP 32 practice every key
   derived from a viewing key is derived **per diversifier** — the diversifier is an
   input to child-key derivation. For a Zcash cryptographer (the author audited
   zecwallet-lite-cli, YWallet, ZGo, Free2Z, the Ledger app), "derives secrets from
   their viewing key" is one-line shorthand for exactly the per-diversifier,
   domain-separated derivation the campaign demands as its "fix." The campaign's
   reading — a global derivation ignoring the diversifier — describes **no wallet
   that exists** and is arguably a strawman.
2. **The author's independence intent is demonstrable from his own text.** The
   Optimization section: "`s` and `r` can be combined by using `G_s = GroupHash(s)`
   … the wallet only sends `G_s` to the server **(so that it doesn't disclose
   `s`)**." This passage is incoherent unless `s` and `r` are independent secrets —
   the author manifestly treats them as such.
3. **No article property is violated.** The campaign's target is an "implicit P0"
   imported from ZIP 32/316. The article claims receiver-side properties against
   servers and GPAs; it nowhere promises sender-side cross-address unlinkability for
   Option 2 — and for Option 1 it treats "address unlinkability privacy" as an
   *extra-strong* property, signaling awareness that it is not automatic.
4. **G1 applies**: the sketch explicitly forbids implementation pending "careful
   thought," and the campaign's own Lean result proves the one-line fix works
   ("per-diversifier injection ⇒ inequality") — i.e., this is an implementation
   detail, not a design flaw.

**What survives.** A fair documentation point: the future ZIP should say
"per-diversifier, domain-separated derivation" in so many words.

**Verdict: OVERSTATED → Low (spec-clarification note).** Not a High "spec bug":
there is no spec; the natural Zcash reading is unbroken; no stated property fails.

---

## F2 — "One past sender + DS = both-servers-compromised"

**Campaign claim.** Every sender holds `(addr, G_r, S_r, K_TT, D)`; one colluding
counterparty hands the DS `K_TT, G_r` ⇒ all-epoch tags; add a colluding MA (or the
sender's own tx knowledge) ⇒ exact attribution "equivalent to P5" without any server
compromise. High severity; "address secrecy is structurally void."

**Defense.**

1. **The core mechanism is the author's own published concession.** Exact text
   (Granular Delegation section):

   > "When the user's chosen Detection Server knows their wallet's address, it can
   > **perpetually find out which `C^L` belong to the wallet. This is because,
   > knowing `G_r, K_TT`, it can re-compute the address's tags for each epoch.**
   > This is always possible for **any design** that allows the Detection Server to
   > 'bucket' transactions for future retrieval by wallets … As long as the Mix
   > Authorities are secure, even a Detection Server that knows a wallet's address
   > will only learn *how many* transactions the wallet receives each day."

   F2's steps 1–2 (derive `T_e` for every epoch from `K_TT, G_r`; read the DS index)
   are this paragraph, executed. The campaign's "novel" observation — that the
   address can reach the DS via a *sender* rather than directly — is a change of
   courier, not of mechanism. And the article's stated condition is "when addresses
   are kept secret **from the Detection Server**": a counterparty voluntarily
   delivering the address is precisely that condition failing.
2. **The exact-attribution half is also conceded.** P5's outcome requires DS-side
   info *and* MA-side info. The author states the MA-side carve-out himself:
   linkage is possible "unless either you can decrypt a message encrypted to a Mix
   Authority's public key … **or you created the transaction yourself**" — a sender
   knows their own pre-mix↔post-mix correspondence, in the author's own words. And
   the article's inference "MA insecure + DS knows the address ⇒ more than counts"
   is entailed by the quoted paragraph ("**As long as** the Mix Authorities are
   secure, even a Detection Server that knows a wallet's address will **only** learn
   how many…").
3. **"Colluding" vs. "compromised" is a distinction without a difference in the
   article's own adversary naming.** P2: "**When a malicious or compromised
   Detection Server** knows one of its users' wallet's addresses…" — *malicious* is
   in the author's adversary set from the outset. A DS that accepts an address from
   a colluding sender is a malicious DS within P2's framing.
4. **The campaign's own model output concedes the structure of P5.** `FINDINGS.md`:
   exact attribution "requires the *product* (tag knowledge × index-or-`dsk` access
   × MA mapping)" — i.e., **both** server-side factors, which is exactly what P5
   decomposes ("Only if both a Mix Authority and the wallet's Detection Server …").
   F2 confirms the author's information-flow decomposition while relabeling how
   factor 1 is acquired.
5. **G2 applies.** The article *explicitly gives up* address-based unlinkability for
   Option 2 and offers Option 1 ("even an adversary who **knows a wallet's
   address** and has compromised the light wallet server cannot find out which
   wallet the address belongs to") for users who need it.

**What survives.** A fair threat-model gloss, worth one sentence in the ZIP:
"address kept secret from the DS" includes "no past counterparty ever discloses" —
a strong assumption for a payment address, which the article should say out loud.
That is a realism note about a *stated assumption*, not a break of a stated claim.

**Verdict: OVERSTATED → Medium (threat-model realism note).** Every mechanism is in
the article's own text; the "equivalence to both-servers-compromised" framing
inflates a relabeled concession into a High break.

---

## F3/F9 — No forward secrecy of `K_TT`; retroactive cross-epoch linkage

**Campaign claim.** A live/retentive server (or one that merely keeps its functional
index plus registration log), combined with any *later* `K_TT` disclosure, links the
victim's entire history of daily groups retroactively. Variant (b): a
deletion-disciplined server's later `ssk` leak allows rebuilding the whole
historical index from public post-mix lists, after which one address leak links
everything. P6 ("cannot … connect the groups from different days") fails.

**Defense of the main variant.**

1. **The attacked claim is explicitly conditional, and the condition is exactly what
   the attack breaks.** Exact text: "**Notably, when addresses are kept secret**,
   even if the private state of all Mix Authorities and Detection Servers leaks, the
   attacker can group transactions within a day by wallet, but they still cannot tie
   those groups to wallets' identities[^1] or **connect the groups from different
   days**." F3's main attack requires "the moment `K_TT` becomes known" — i.e., the
   address is *not* kept secret. No article sentence promises post-disclosure
   forward secrecy; the campaign refutes a claim the article never makes.
2. **The deletion discipline is not smuggled in — it is the article's stated
   assumption, in the claim's own footnote.** Footnote 1, verbatim:

   > "Assuming the Detection Server never logs users' IP addresses along with the
   > tags users look up, and that the Detection Server's database retains no trace
   > of the order in which tags are looked up."

   The campaign's complaint that this is "behavioral, not cryptographic" is a
   complaint about operational assumptions as a category. Security claims scoped to
   stated operational assumptions are the norm; a live-compromised server *is* the
   "state leak" scenario's well-operated-server premise failing, and P2 already
   concedes what malicious DSs learn.
3. **The "registration log" leg adds nothing not already conceded.** Registration
   sends `r`; the server learns `(IP, r)`; `G_r = GroupHash(r)` is public. Tying a
   later-leaked `G_r` back to the registering IP is an instance of P2's conceded
   "it can find out which user it is (i.e. identified by their IP address)."
4. **The author flags the missing forward secrecy himself** (Optimizations):
   "Identity-Based encryption could also potentially be used … old private keys can
   be deleted … This would provide **stronger forward-security and
   backward-security** properties in case a well-operated Detection Server is
   compromised." One cannot concede a gap more clearly than by naming the property
   as an improvement the base design lacks.

**Concession on variant (b).** The referee concedes the `ssk`-retention/history-
rebuild variant survives the article's text, in this precise sense: footnote 1
offers deletion as *the* discipline that guards the claim, but the disciplined
server must retain `ssk` (the live service key), and the post-mix lists are public
and permanently trial-decryptable under `ssk`. Hence the entire historical index is
rebuildable *post hoc* by anyone who ever holds `ssk`, and one much-later address
sighting then links all history — no matter how faithfully the server deleted tag
logs. The article never states this consequence; its footnote gives comfort its own
architecture does not deliver ("history is hostage to `K_TT` forever, and `ssk`
cannot be time-severed"). The author's IBE/forward-security musing shows awareness
of the gap without closing or even articulating it. This is a genuine finding.

**Verdict: CONTESTED → fair severity Medium.** Main (live/retentive-server) variant:
scoped out by the article's own conditional + footnote 1 — not a break. Variant (b)
survives as a real, unacknowledged forward-secrecy absence worth a design note.

---

## F4 — Volume/duration side channel vs. P1

**Campaign claim.** Response payload ∝ notes received; fixed-size packets at fixed
rate fix the rate, not the total; a GPA learns the count up to padding; P1's
"learns nothing about when or how many" is unachievable without worst-case padding.
Medium-High.

**Defense.**

1. **The campaign re-proves the author's own trilemma.** Exact text ("Address
   Unlinkability" section):

   > "Either *all* wallets download lots of data when *any* wallet needs to, DoS
   > attacks on addresses are possible, or wallets with addresses that receive lots
   > of transactions are identifiable by **the amount of data the Detection Server
   > sends to them**."

   F4's Lean "trilemma theorem" (injective volume ⇒ count leaks; constant volume ⇒
   worst-case download) is this paragraph formalized. The article does not
   "half-concede the tension" — it states the bind as a named three-way tradeoff and
   immediately poses:

   > "*Open Question:* Can we prove that this limitation applies to **all possible
   > protocols**?"

   i.e., the author's position is that the volume limitation is *universal*, a
   design-independent impossibility — the exact thesis F4 claims as its refutation.
2. **P1 carries a qualifier the campaign's formalization drops.** The property is:
   "**When implemented carefully**, even global passive adversaries … learn nothing
   about when or how many…" (`PROTOCOL.md` P1 omits the qualifier — misquote G4.1).
   "When implemented carefully" is precisely the padding-regime caveat; read
   together with the trilemma, the article never promises the impossible corner.
3. **Scope of the leakage is stated as DS-only, with the mechanism named.** "Only
   the Detection Server observes this leakage, not a global passive adversary,
   because the Detection Server always sends detected transactions over a
   constant-bandwidth protocol (e.g. in fixed-sized packets sent at regular
   intervals)." The campaign's genuine delta is narrow: *duration* of a fixed-rate
   stream is itself an amount-signal, so this sentence's "not a global passive
   adversary" holds only if "constant-bandwidth" means constant *total* (the
   trilemma's horn 1), not constant *rate*. That is a one-clause correction to one
   sentence — not a refutation of a headline, given the trilemma and the Open
   Question sit in the same article, and given Option 1 exists for users who need
   the strong property ("always download every transaction … reveals no information
   about how many").

**Verdict: OVERSTATED → Medium (wording/documentation: reconcile P1's absolute
phrasing with the article's own trilemma; sharpen the constant-bandwidth sentence to
constant-total).** The substance is the author's own stated bind; the campaign's
table itself concedes "the author's own trilemma paragraph concedes the tension."

---

## F5 — Live-DS cross-epoch linkage by network identity (IP)

**Campaign claim.** A live malicious DS sees the same IP query per-epoch tags and
links all daily groups in real time, address secrecy notwithstanding. Medium.

**Defense.**

1. **No stated property is violated.** The real-time delegation claim is: "the
   Detection Server is unable to reliably **detect transactions for the wallet in
   epochs other than the ones explicitly requested** by the wallet." F5's DS links
   exactly the **requested** epochs — the ones the wallet chose to reveal to its own
   chosen server. Nothing unrequested is detected. The post-hoc claim ("cannot
   connect the groups from different days") is scoped by footnote 1's "never logs
   users' IP addresses along with the tags users look up" — a live malicious DS
   violates that assumption by existing; the claim was never about it. The gap-cell
   F5 occupies (malicious DS, address unknown, live observation) carries no article
   promise at all.
2. **The author supplies the mitigation and its weakness himself.** Optimizations:
   "wallets can perform each lookup over a fresh Tor circuit to further obfuscate
   the number of transactions their wallet receives over time. **This would be
   vulnerable to global passive adversaries and to timing correlation attacks,
   however.**" The campaign's F5 "mitigation defeated" paragraph is this caveat
   restated.
3. **Perspective (G2).** The residue — "your chosen server sees the span of epochs
   you fetch, tied to your connection" — is strictly less than the status quo the
   article set out to fix ("the light wallet server can learn precisely which
   transactions belong to which wallets"). Calling a strict improvement over the
   declared baseline a "break" inverts the article's claim structure.

**Verdict: REFUTED (as a property break) → residual Low operational note** (make
Tor-per-lookup the default recommendation rather than an optimization — which the
article already suggests).

---

## F6 — Under-specified derivation of `s, r, dsk`

**Campaign claim.** If the derivation is not domain-separated (e.g., `s = r`, or
`dsk` computable from `r`), registration — which transmits `r` — hands the server
`K_TT` or the detection scalar. "High if misderived."

**Defense.**

1. **The article's own Optimization passage proves the author treats these as
   independent secrets and knows exactly what registration must not disclose:**

   > "`s` and `r` can be combined by using `G_s = GroupHash(s)` instead of
   > `G_r = GroupHash(r)`. However, to do this, the address registration process
   > must be modified so that the wallet only sends `G_s` to the server **(so that
   > it doesn't disclose `s`)**, and the wallet must prove in zero knowledge that
   > `G_s = GroupHash(s)` (otherwise the registration API becomes a **decryption
   > oracle**!)."

   An author who writes a parenthetical about not disclosing `s` at registration,
   and who flags a registration-API decryption oracle, has the disclosure hazard
   front-of-mind. The "naive `s = r` variant" the campaign simulates (`A_F6`)
   contradicts the only internal evidence the article gives about the relation
   between `s` and `r`.
2. **"Derives secrets `s, r, dsk`" reads naturally as three distinct derivations** —
   in ZIP 32 practice, distinct secrets from a key are distinct labeled derivations
   (and, per the F1 defense, per-diversifier). The catastrophic reading requires an
   implementer to *collapse* secrets the text names separately — squarely inside
   "please don't implement this without careful thought" (G1).
3. Note the campaign's own hedge: "High **if misderived**." A conditional finding
   against a derivation the article never specified cannot be a bug in the article;
   at most it is a ZIP checklist item (use domain-separated PRF labels).

**Verdict: OVERSTATED → Low (implementation-discipline note).**

---

## F7 — Liveness/completeness (DS withholding, MA censorship, injection)

**Campaign claim.** DS can silently withhold `C^L`; MA can censor or inject;
injected garbage inflates per-tag buckets (count pollution). Medium.

**Defense.**

1. **The article never claims completeness against malicious servers.** The servers
   are "partially-trusted" by design (stated twice: "a set of **partially-trusted**
   Mix Authority servers as well as a **partially-trusted** Detection Server"). The
   campaign's P10 ("wallets receive all their notes via DS — honest parties") is the
   campaign's own test-target gloss, not an article sentence. Punishing the design
   for lacking a property its trust model explicitly declines to promise is a
   category error.
2. **The fallback the campaign calls "the exact expensive operation the protocol
   exists to avoid" is the design's stated safety net:** "the wallet can use its
   viewing key to trial-decrypt the regular note ciphertext `C` as is done
   currently. **This remains possible even if all of the Mix Authorities and
   Detection Servers go offline.**" Withholding is therefore detectable and
   recoverable by design — at documented cost — which is the standard
   partially-trusted-server contract.
3. **MA censorship is bounded by the article's own 1-of-N liveness rule** ("As long
   as *at least one* Mix Authority is online, the post-mix ciphertexts will become
   available"; every authority publishes and signs the same sorted, deduplicated
   list, so omission is cross-checkable between signed lists).
4. **Injection is dead on arrival by the campaign's own verification** — "Verified
   sound" list: "Injected post-mix garbage: fails note-commitment authentication at
   the wallet." The surviving residue (bucket/count inflation) is a fee-free variant
   of the **author's own conceded attack**: "the Detection Server can always send
   thousands of transactions to the address … watch which 'bucket' grows," and the
   trilemma's DoS horn. The article never claims the per-day count is
   integrity-protected in either direction — P3 concedes the count *is* observed.

**Verdict: REFUTED (as property violations) → residual Low design notes** (a future
ZIP should specify list-consistency checks and fraud proofs — standard spec
maturity items).

---

## F8 — `dsk` recovery from non-indexed delegation

**Campaign claim.** Non-indexed detection hands a server `x_e = dsk + PRF^D(K_TT, e)`.
Any address holder (one colluding sender, or a later leak) supplies `f := PRF^D(K_TT,
e)`, and `dsk = x_e − f` — converting the limited grant into a silent, permanent,
all-epoch detection capability with zero further victim interaction.

**Article text at issue.**

> "In the non-indexed case, the Detection Server learns `dsk + PRF^D(K_TT, e)`.
> **Without knowing `K_TT`, they cannot recover `dsk`** or any of the other
> per-epoch detection secret keys. … As long as their address is kept secret, the
> new Detection Server is **only granted detection authority for a limited number of
> epochs**."

and the stated purpose of granular delegation:

> "the design also lets wallets granularly delegate detection authority, i.e. only
> grant detection authority for certain days, which **further limits the effects of
> any server compromise that is detected and corrected**."

**Defense raised, and why it does not fully succeed.**

- The article *does* state the exact security boundary: recovery of `dsk` requires
  `K_TT`; the "limited number of epochs" claim is conditioned on "their address is
  kept secret." Strictly read, the attack violates no sentence — it needs the
  condition to fail, and F2 shows every past counterparty holds the condition's
  negation.
- But the referee concedes the finding, for three reasons grounded in the article's
  own text. (1) The delegation is sold by its **purpose** — "further limits the
  effects of any server compromise that is detected and corrected" — and the
  cancellation defeats that purpose outright: detection and correction are
  meaningless when a single later address sighting retroactively upgrades the old,
  detected, corrected server's one-bad-day grant into permanent `dsk`-level power
  with **no further queries to observe**. (2) The phrase "only granted detection
  authority for a limited number of epochs" describes an *ephemerality the mechanism
  does not possess* once the (structurally fragile, per F2) secrecy condition
  fails; a reader is given no warning that delegation permanence is hostage to the
  address forever, including retroactively via the 32-byte retained row `x_e`. (3)
  The linear structure is the design's own choice: the article publishes `D =
  [dsk]G_2` and blinds per epoch precisely to avoid exposing `dsk` — the
  non-indexed path then hands out `dsk + f(e)`, a textbook cancellable masking. The
  author's next-steps item ("eliminate the **address secrecy requirement** for
  granular delegation in the non-indexed detection case" via IBE) shows he knew
  this case rested on the weakest beam — without ever stating the cancellation
  consequence.

**What is fairly conceded.** The algebra is real and unacknowledged; the escalation
(permanent, retroactive, zero-interaction capability from a limited grant) is
genuine and dominates F3.

**What remains defense residue.** Severity is *conditional* — the attack needs one
colluding counterparty or any later address leak, i.e., the failure of the author's
explicitly stated precondition. An unconditional "High" overstates it.

**Verdict: SURVIVES → fair severity Medium-High (conditional on address exposure;
breaks the delegation mechanism's stated purpose, not its literal conditional
sentence).**

---

## F10 — Minor spec gaps (epoch not bound in `π`; AD specification; `r` in clear)

**Campaign point 1 refuted on the article's text.** The campaign asserts mis-epoch
tags are "caught downstream only by the note-commitment position check." But the
epoch **is** bound, twice, at the DS's indexing step: the tag ciphertext is
constructed as `C^T = Enc(S_r, T||π, "tct"||e, G_r, esk, epk)` — the associated
data `"tct"||e` makes a stale-epoch `C^T` fail AEAD-open when the DS processes the
list for epoch `e' ≠ e`, so the tag never enters the index; and `T =
PRF^T(K_TT, G_r||e)` makes distinct epochs yield distinct public tags, so a
mis-epoch tag is never queried by the victim. There is no oracle; the campaign
itself concedes "nothing catastrophic." The remaining advice ("specify that the DS
uses the list's epoch for AD, never sender-claimed ones") is a one-line
implementation note — exactly the "careful thought" G1 reserves for the ZIP.

**Points 2 and 3** (attest the same-base relation in `π`; blind registration as
default) are likewise ZIP-polish. Point 3's substance — the server learns
`(IP, r)` at registration, useful only in combination with a later address sighting
— is P2's conceded cell (see F3 defense, item 3).

**Verdict: REFUTED (as a break; the epoch is already bound by the `"tct"||e` AD)
→ residual Low editorial items.**

---

## F11 — Witness-update exclusion leak

**Campaign claim.** Fast-path wallets fetching only `C^L` while "updating witnesses
as usual" must download note-commitment siblings; the download pattern is a
per-epoch exclusion oracle pinning the wallet's note positions — High, independent
of the tag machinery, refuting the performance-optimized path's privacy goal.

**Defense — this one falls on the article's own first sentence of Receiving:**

> "**All wallets must always download and authenticate the entire note commitment
> and nullifier sets.**"

and the performance list agrees:

> "The wallet must **authenticate and sync the note commitment and nullifier
> sets**." … "The wallet must still update the witnesses for their unspent notes
> **as usual**."

1. **Under the design as written, there is no witness-fetch channel to leak.**
   Every wallet downloads *every* note commitment (and nullifier), uniformly, every
   epoch; witnesses are updated "as usual" — and "as usual" in Zcash light wallets
   (zecwallet-lite, YWallet — both audited by the author) means maintaining the
   commitment tree locally from the synced set, **not** requesting selective Merkle
   paths from a server. Where every client's download pattern is identical by
   construction, the differential signal F11 needs ("which commitments the wallet's
   requested paths touch — and which they do not") does not exist. The campaign's
   own `PROTOCOL.md` §7 formalizes the full-set rule ("All wallets download +
   authenticate the full note-commitment and nullifier sets") and F11 then posits
   the selective-fetch regime its own formalization excludes — an internal
   inconsistency in the prosecution's documents (misquote G4.2).
2. **The bandwidth cost is modest and expressly budgeted.** Note commitments are
   ~32 bytes per shielded output. Even a heavy 100k-output epoch is ~3.2 MB/day of
   commitments; 10k outputs ≈ 320 KB/day. This is a *stated* performance property
   ("must authenticate and sync the note commitment and nullifier sets"), small
   against the avoided cost — downloading and trial-decrypting every transaction of
   every past day (note ciphertexts alone are hundreds of bytes each, before
   transaction overhead). The article's performance story survives full-set sync
   intact: the win is never "download nothing"; it is "trial-decrypt at most the
   current day, and fetch small `C^L`s for past days."
3. **The leak is real only for a variant the article never proposes.** F11's option
   (b) — "download only the siblings it needs" — is the campaign's hypothetical
   optimization of the article's design. The author's April 2024 result
   (zcash/zcash#6756) proves the exclusion leak for designs that *do* selective
   witness fetching; its existence is a reason the 2023 article's full-set rule is
   the safe reading, not evidence the 2023 design is broken. (That the author did
   not cross-reference his own later finding back to this sketch is a bibliography
   note, not a vulnerability.)

**Verdict: REFUTED as against the article's design as written.** Requalified: "the
exclusion leak applies to a hypothetical selective-fetch optimization the article
does not propose; if a future ZIP contemplates one, it must confront
zcash/zcash#6756." As filed (High, breaking the article's path), it does not stand.

---

## F12 — Epoch dilution / blending

**Campaign claim.** "Epoch-sized anonymity set" is spam-dilutable; the honest set is
the real anonymity set (Serjantov–Danezis (n−1) math). Medium.

**Defense.**

1. **The article's claim is twice-qualified, and the qualifiers are exactly the
   dilution attack's preconditions.** Exact text: "**without additional
   information**, each post-mix ciphertext is hiding in an epoch-sized anonymity set
   of shielded outputs," and: "it is impossible to link a pre-mix ciphertext to a
   post-mix ciphertext unless either you can decrypt a message encrypted to a Mix
   Authority's public key … **or you created the transaction yourself**." A
   flooding attacker *has* additional information — they created their own
   transactions, and the article says so, in the carve-out, in advance. Their
   outputs were never cover for the victim *against that attacker* by the article's
   own words; the "epoch-sized" phrasing was never an (n−1)-resistance claim.
2. **The attack is generic to every threshold/timed batch mix** — the campaign's
   own citation (Serjantov–Danezis, "From a Trickle to a Flood") establishes this as
   a 2002-era property of the *category*, not a defect of this design. The
   campaign's own verdict concedes the floor: "the 'honest outputs per epoch' floor
   survives."
3. **The article's baseline defense is stated and survives**: the attacker "cannot
   *remove* other ciphertexts from the on-chain epoch list" — the campaign
   acknowledges this ("is real, but…").

**Verdict: OVERSTATED → Low** (a note on absolute phrasing for the ZIP; the
guarantee as conditioned in the text already excludes attacker-created outputs).

---

## F13 — Intersection/SDA on `R+F` cover; delivery-channel fragility

**Campaign claim.** The `R+F` dummy-transaction scheme is constant-shape cover
erodible by statistical disclosure attacks; real mixnet-backed channels (2026
measurements) undercut "constant-bandwidth delivery." Medium, "realistic-deployment
caveats rather than protocol-logic bugs" (campaign's own words).

**Defense.**

1. **The article claims "obscure," not intersection-resistance.** Exact text: "As
   long as the Mix Authorities are secure, wallets can send random amounts of
   transactions to themselves **to obscure** the total number of transactions that
   they receive … they would see the distribution `R + F` …" — followed immediately
   by the author's own statement of the scheme's operational costs and limits:
   "This would **require wallets to be online daily** … or they could **delegate the
   task to a third-party service by providing their address**" (itself a privacy
   cost, stated). No claim of long-horizon statistical indistinguishability is made
   anywhere; SDA erosion defeats a claim not advanced.
2. **The author's caveat pattern shows the limits are on his radar.** The same
   article, on its own suggested cover/mitigation regime: Tor per lookup "would be
   **vulnerable to global passive adversaries and to timing correlation attacks,
   however**." And the cover-traffic concept is explicitly borrowed from Loopix
   ("loop cover" and "drop cover" traffic), whose literature carries these limits.
3. **The deployment critique is a category error against a 2023 protocol sketch.**
   Measured 2026 proxy teething (bandwidth cost, silent failures, timing re-link
   rules) characterizes one implementation of a transport channel the article
   mentions only by example ("e.g. in fixed-sized packets sent at regular
   intervals"). It is evidence about engineering maturity, not about protocol logic
   — and the campaign concedes as much.

**Verdict: OVERSTATED → Low** (deployment caveats; no protocol claim violated).

---

## Scorecard

| ID | Campaign severity | Verdict | Fair severity after textual defense |
|----|-------------------|---------|--------------------------------------|
| F1 | High | **OVERSTATED** | Low — spec-clarification (per-diversifier, domain-separated derivation); naive reading is a strawman vs. ZIP 32 practice; no article property promises cross-address sender unlinkability for Option 2 |
| F2 | High | **OVERSTATED** | Medium — threat-model realism note ("address secret from DS" ⊇ "no counterparty ever discloses"); every mechanism is the author's own published concession ("re-compute the address's tags for each epoch"; "or you created the transaction yourself"; "malicious or compromised" DS is the author's named adversary) |
| F3/F9 | High | **CONTESTED** | Medium — main live/retentive-server variant is scoped out by the article's own conditional + footnote 1; **variant (b) (`ssk` retention ⇒ post-hoc history rebuild from public lists) survives**, conceded; author's IBE passage flags the missing forward secrecy |
| F4 | Medium-High | **OVERSTATED** | Medium/Low — substance is the author's own trilemma + Open Question; P1 carries "When implemented carefully" (dropped in campaign's formalization); genuine delta is one clause (duration vs. rate) in one sentence |
| F5 | Medium | **REFUTED** | Low note — no unrequested-epoch detection occurs; footnote 1 excludes live IP↔tag association; author's own Tor/timing caveat; strictly better than the declared status-quo baseline |
| F6 | High (if misderived) | **OVERSTATED** | Low — the author's own "(so that it doesn't disclose `s`)" passage proves independence intent; "High if misderived" against an unspecified derivation in a no-implementation sketch is a checklist item |
| F7 | Medium | **REFUTED** | Low notes — "partially-trusted" servers; trial-decryption fallback by design; injection dies at commitment authentication (campaign's own verification); count inflation = author's own conceded bucket/DoS attacks |
| F8 | High | **SURVIVES** | **Medium-High (conditional)** — `dsk = x_e − PRF^D(K_TT, e)` cancellation is real and unacknowledged; defeats granular delegation's stated purpose ("limits the effects of any server compromise that is detected and corrected") given one colluding counterparty or any later address leak |
| F10 | Low | **REFUTED** (main point) | Low editorial — epoch *is* bound by the `"tct"||e` AD at DS indexing; remainder is ZIP polish |
| F11 | High | **REFUTED** | Requalified — "All wallets must always download and authenticate the entire note commitment and nullifier sets" eliminates the differential download pattern the leak requires; applies only to a hypothetical selective-fetch variant the article never proposes; full-set sync ≈ 32 B/output/day is a stated, budgeted cost |
| F12 | Medium | **OVERSTATED** | Low — "without additional information" + "or you created the transaction yourself" already carve out the (n−1) attacker; generic threshold-mix property; campaign concedes the honest floor |
| F13 | Medium | **OVERSTATED** | Low — "obscure" ≠ intersection-proof; author states cover costs and flags GPA/timing limits; 2026 channel measurements are deployment observations, not protocol breaks (campaign self-describes them as caveats) |

### Honest bottom line for the referee

- **Claims that truly survive the article's own text: 1 of 12 entries — F8** (the
  `dsk` cancellation), plus **one surviving variant inside F3/F9** (the
  `ssk`-retention/history-rebuild consequence). Both reduce, in the end, to one
  structural theme the campaign correctly identified: *address-derived key material
  (`K_TT`, and derivably `dsk`) is a permanent master key over detection history,
  and "address secrecy" is a fragile condition for a payment address.* That theme is
  worth a ZIP-author's attention and is the campaign's real contribution.
- **Every other finding** either (a) re-badges the author's own published
  concessions (F2, F4, F7, F12), (b) attacks outside the article's stated
  assumptions or adversary cells (F3 main, F5, F7), (c) attacks an underspecified
  corner of a self-declared sketch (F1, F6, F10), or (d) attacks a variant the
  article does not contain (F11, and F13's deployment critique).
- **Severity ledger on the campaign's six High ratings (F1, F2, F3/F9, F6, F8,
  F11):** after textual defense — 1 conditional survivor at Medium-High (F8), 1
  contested at Medium (F3/F9), 2 downgraded to Medium/Low threat-model or wording
  notes (F2, F4), 2 downgraded to Low spec notes (F1, F6), 1 refuted outright (F11).
  Zero unconditional Highs stand.
- **Both ways:** the campaign's cryptography appears competently executed (its
  verified-sound list correctly confirms the parts the author claimed sound), and
  its F8/F3(b) findings are genuine. But its headline — that the protocol's stated
  properties are broken at scale — does not survive contact with the article's own
  qualifiers, footnotes, concessions, and its explicitly two-option, intentionally
  tradeoff-bearing structure.
