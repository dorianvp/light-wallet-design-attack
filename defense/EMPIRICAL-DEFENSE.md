# EMPIRICAL DEFENSE — strongest defender readings vs the F1–F13 campaign

Role: **EMPIRICAL DEFENDER**. Mission: implement the strongest defender-side
behaviors and protocol readings that the article's text plausibly permits,
run them against the campaign's findings (../FINDINGS.md, simulations in
../sim, ../analysis), and measure which findings die. Everything here is
new code under `defense/`; no existing file was modified. The campaign's own
audited simulator is reused unmodified (imported, subclassed, wrapped) —
defender behaviors are subclasses, never edits to attack code.

Article under test: Taylor Hornby, *"Making Zcash Light Wallets Faster and
More Private"*, Mar 2 2023 (defuse.ca/zecsec/...). Environment: Python 3.14,
stdlib only, fully deterministic (seeded RNGs), total runtime ~13 s.

**Anti-rigging discipline (mirroring the campaign's):** every experiment
leads with a *positive control* — the campaign's attack re-run first and
shown to reproduce — before any defense is applied. A defense verdict that
cannot first reproduce the attack it claims to kill would be suspect.

---

## Verdict table

| Finding | Campaign severity | Defender reading applied | Verdict | New severity / scope |
|---|---|---|---|---|
| **F11** witness exclusion leak | High | "All wallets must always download and authenticate the entire note commitment and nullifier sets" (letter of §Receiving) | **WEAKENS** | High → **Medium-Low**: dies vs the letter of the text at 2.8–13.8 MB/day (0.8–3.2% of the article's own current-day tx stream); survives only vs the fetch-only-siblings ("as usual", lightwalletd-style) reading; subtree-sharded middle option floors at 65,536-anonymity |
| **F2** sender-collusion equivalence | High | footnote-1 discipline + grace-G bucket deletion | **SURVIVES (live core)** | unchanged for live epochs: last-G + **all future** epochs readable while the pair is live; retroactive readout of pre-grace epochs dies |
| **F3a/F9** retroactive index readout | High | same + registration-log TTL 0 | **WEAKENS** | High → **Medium**: "all past daily groups" collapses to "the last G days"; identity tie-back (bucket→registering IP) dies |
| **F3b** `ssk`-leak history rebuild | High | deletion discipline (any G) | **SURVIVES** | unchanged: public signed post-mix lists + static `ssk` rebuild **all** history, deletion powerless; the article's own per-epoch-key optimization (future work, not the protocol) caps it at G days |
| **F5** live-DS IP linkage | Medium | "perform each lookup over a fresh Tor circuit" (article's own optimization) | **WEAKENS** | Medium → **Medium-Low**: DS-only cross-day linkage = 0%; residuals quantified (tag re-query, catch-up bursts, GPA timing — the two latter are the article's own conceded caveats) |
| **F4** volume/duration leak (P1) | Medium-High | pad-to-K + idle cover (the article's "constant-bandwidth protocol" sentence given a parameter K) | **WEAKENS** | Medium-High → **Medium-Low**: advantage(1-note vs 20-note) = **exactly 0** for K ≥ 20; worst-case padding costs 29–50 kB/day flat (≈ 11–18 MB/yr), *not* performance-negating; residual = over-cap wallets + attacker dust/forgery inflation + F13 multi-epoch SDA |
| **F8** `dsk` scalar cancellation | High | every textual reading of the handover | **SURVIVES — CONCEDED in full** | unchanged: all functioning readings leak `dsk` linearly; readings that would not leak break the service; ephemeral-`x` deletion kills only the retroactive variant |

Not re-tested here (no new defense exists beyond the campaign's own text):
F1/F6 (the campaign *is* the fix — per-diversifier domain separation, which
the article omits), F7 (liveness — no fraud-proof mechanism exists in the
text), F10 (spec wrinkles), F12 (dilution — fee-bounded, unaffected by any
defender behavior tested here), F13 (SDA/deployment — cross-referenced
below where it bounds the F4/F5 defenses).

---

## D1 — F11: the letter of the text avoids the witness leak, at a small,
measurable price  (`d1_f11_witness.py`)

**Campaign premise:** the perf-optimized wallet "updates the witnesses for
their unspent notes as usual" by fetching only needed siblings; a watching
server applies *sound exclusion rules* ("unfetched finalized block ⇒ note
not in that block's sibling range") and pins the note's tree position.

**Defender readings tested** (same tree model and sound-only rule set as
`analysis/f11_witness_leak.py`; tree init 200k notes, +216k/epoch ≈ 2.5
shielded outputs/s, 6 epochs):

1. **fetch-all — the letter of the text.** The article's §Receiving opens:
   *"All wallets must always download and authenticate the entire note
   commitment and nullifier sets"* (and performance bullet 1 says the
   same). A wallet that has every commitment computes witnesses locally;
   there is nothing selective to observe.
2. **fetch-exact — the campaign's reading** (positive control).
3. **subtree-sharded middle option** — fetch only consensus-finalized
   2^16-leaf subtree roots (`GetSubtreeRoots`-style), never leaf-level
   data: `shard-path` (path sibling roots only, witness completion
   deferred to spend) and `shard-full` (+ carry the note's whole own
   subtree, one-time ~2 MiB).

**Results** (candidate set for the note's position, sound-only inference —
a *fetched* block is never evidence, the conservative rule set favors the
attacker):

| strategy | candidates after epochs 1..6 | exact pin? | bytes fetched (6 ep) |
|---|---|---|---|
| fetch-exact (campaign reading) | 1 1 1 1 1 1 | **YES** (control) | 640 B |
| fetch-all (letter of text) | 416,000 — **never shrinks** | no | 41.47 MB |
| shard-path (2^16 roots only) | 65,536 65,536 65,536 65,536 65,536 65,536 | no | **128 B** |
| shard-full (+ own subtree) | 65,536 … 65,536 | no | 2.10 MB |

* fetch-all gives the exclusion attack **zero information**, first-sync
  completeness included (the first-sync fetch is the entire set, uniform
  across wallets).
* Sharding leaks **strictly less** than the campaign's leaf-level reading:
  candidates collapse **once** to a single 2^16-leaf subtree (65,536
  positions — anonymity floor 2^16) after the first frontier crossing and
  then **stop**: coarser 2^17+ fetch events never resolve which subtree of
  a pair the note is in, and the note's own subtree root is never fetched
  as a sibling (shard-path defers it; shard-full computes it locally).
  Per-epoch shrink at 65,536-leaf granularity: one 2×10⁵→6.6×10⁴ collapse,
  then constant — vs. compounding-to-1 at leaf granularity.
  Caveats kept honest: `shard-path` re-introduces an **exact pin at spend
  time** (a one-shot full-witness completion fetch identifies the position:
  only p shares p's complete sibling set); `shard-full` avoids that by
  carrying 2 MiB; a wallet whose note sits in the frontier subtree pays
  fetch-all prices until that subtree completes.

**The real-world price of the letter-of-text defense** (32 B/commitment,
nullifiers also ~32 B; "current-day txs" = the trial-decryption stream the
article's own performance bullet mandates at launch and per epoch):

| ops/s | leaves/day | commitments MB/d | + nullifiers MB/d | tx bytes | current-day txs MB/d | overhead |
|---|---|---|---|---|---|---|
| 1.0 | 86,400 | 2.76 | 5.53 | 1 kB / 2 kB / 4 kB | 86.4 / 172.8 / 345.6 | 6.4 / 3.2 / 1.6 % |
| 2.5 | 216,000 | 6.91 | 13.82 | 〃 | 216 / 432 / 864 | 6.4 / 3.2 / 1.6 % |
| 5.0 | 432,000 | 13.82 | 27.65 | 〃 | 432 / 864 / 1728 | 6.4 / 3.2 / 1.6 % |

**Honest verdict.** The article *as written* avoids F11 completely, and the
cost — 5.5–27.7 MB/day with nullifiers — is 1.6–6.4 % of the current-day
transaction stream those same wallets already download and trial-decrypt.
The campaign's claim that the only leak-free option costs "Θ bandwidth —
the cost the design exists to avoid" is true asymptotically but numerically
empty: the constant is 32 bytes per output, and what the design eliminates
is trial-decrypting all *history*, not the commitment stream. Two genuine
residuals keep F11 alive at reduced severity: (i) relative to the
quiet-wallet ideal (~kB/day of C^L), fetch-all is a 100–1000× regression of
the fast path, and "authenticate the whole set each epoch" is beyond the
article's text; (ii) the article also says "update the witnesses … as
usual", which for real light wallets *means* selective sibling fetching —
the text is self-contradictory, and F11's real contribution is exposing
that contradiction. **F11: WEAKENS, High → Medium-Low.**

---

## D2 — F2/F3/F5/F9: what a footnote-1-compliant server actually saves
(`d2_footnote1.py`)

**Defender server** (`DisciplinedServer`, subclassing the campaign's):
deletes (identity, tag) query links at serve time (footnote 1: "never logs
users' IP addresses along with the tags users look up … retains no trace of
the order"); deletes epoch buckets after a **grace window G** (the article:
the server "only ever needs ephemeral access to the tags wallets request" —
but it also promises "for all days previous to the current one, the wallet
can fetch its transactions quickly", so G ≥ 1 is forced: G = 0 deletes
buckets before any catch-up query can be served, breaking the service);
deletes the registration log (ip, r, G_r) immediately (TTL 0 — the
decryption trick is stateless, the server never needs r again).

Timeline: 12 epochs, victim counts `1 2 0 1 3 0 1 2 1 0 2 1` among a noise
wallet; one colluding sender discloses the address at epoch 10; server
state leaks at epoch 12.

| server policy | F2 live (past, at ep 10) | F2 live future | F3a/F9 post-hoc | F3b ssk static | F3b per-epoch keys | F5 live | F5 post-hoc log | reglog tieback |
|---|---|---|---|---|---|---|---|---|
| retentive (baseline) | **9/9** | 3/3 | **12/12** | 12/12 | 12/12 | YES | 11 rows | 10.0.0.9 |
| disciplined G=1 | 1/9 | 3/3 | 1/12 | **12/12** | 1/12 | YES | 0 rows | none |
| disciplined G=3 | 3/9 | 3/3 | 3/12 | **12/12** | 3/12 | YES | 0 rows | none |
| disciplined G=7 | 7/9 | 3/3 | 7/12 | **12/12** | 7/12 | YES | 0 rows | none |
| disciplined G=30 | 9/9 | 3/3 | 12/12 | **12/12** | 12/12 | YES | 0 rows | none |
| retain buckets, delete links+reglog | 9/9 | 3/3 | 12/12 | **12/12** | 12/12 | YES | 0 rows | none |

(All count-readouts verified equal to ground truth; "n/12" counts epochs
whose counts the attacker recovers.)

**Honest read-out.**

* **F2 live SURVIVES unchanged in its core.** While the colluding pair is
  live, the attacker reads the last G closed epochs **plus every future
  epoch as it closes** — for *any* G ≥ 1, because the index necessarily
  exists in-service while the victim is a live user. Deletion discipline
  destroys history; it cannot shrink the live window below "now + G", and
  exact attribution (bucket + MA work product) needs only the live window.
  The campaign's semantic point — address secrecy is structurally void
  against one counterparty — is untouched by any deletion policy.
* **F3a/F9 (retained-index retroactive readout) WEAKEN to the G-day
  window**: "one later address leak links the victim's entire history"
  becomes "links the last G days". With registration-log TTL 0 the
  bucket→registering-IP join dies too, so surviving groups stay anonymous
  *unless* the attacker has an independent identity signal. The 30-day
  grace that a realistic catch-up service needs, however, already gives
  the attacker a month — and G=30 ≈ the retentive baseline for anyone
  attacking within a month of the leak.
* **F3b (ssk leak) SURVIVES deletion entirely** under the protocol as
  specified: the post-mix lists are public and signed forever; anyone
  holding the (single, static, live-service) `ssk` re-indexes **all**
  history from public data. No operational discipline short of destroying
  `ssk` — which is the service — helps. The article's *own optimization
  paragraph* (per-epoch detection keys, "old private keys can be deleted",
  IBE-flavored forward/backward security) caps the rebuild at the same
  G-day window, confirming the author eventually saw the hole — but it is
  future work, not the protocol.
* **F5 live SURVIVES any policy** (the query is observed on the wire as it
  happens; deletion is by definition post-hoc). **F5 post-hoc dies** under
  discipline (0 rows retained).

**Composite: F2 SURVIVES (live), F3a/F9 WEAKEN (High → Medium), F3b
SURVIVES (High).** The single most defensible server the text permits
still leaks: every live epoch to a colluding counterparty pair, the last G
epochs retroactively, and — on any `ssk` leak — everything, forever.

---

## D3 — F4: pad-to-K is cheap enough that "P1 is unachievable without
worst-case padding" stops being the right framing  (`d3_padding.py`)

Defender behavior: every bucket fetch padded to K ciphertexts + a cover
fetch every idle epoch (the article's own "constant-bandwidth protocol
(fixed-sized packets sent at regular intervals)" given an actual parameter,
plus its R+F self-transaction idea in bandwidth-only form). Received-count
distributions: Zipf over 1..50 (s = 1.0/1.2/1.5/2.0) and a uniform control.
|C^L| = 580 B (Orchard note-ciphertext scale; 1 kB sensitivity shown).

Positive control: unpadded 1-note vs 20-note sessions differ ⇒ advantage 1
(campaign A_F4 reproduces).

Key rows (full tables in `results.txt`):

| padding | adv(1 v 20) | wallets hidden (n ≤ K) | bandwidth mult | kB/day @580B | bits leaked about n |
|---|---|---|---|---|---|
| unpadded | 1 | 0% | 1.0× | 1.6–6.4 | H(n) (full count) |
| K=10 | 1 (20 > K) | 65–95% | 1.4–3.8× | 6.1–8.9 | 0.5–2.7 of H |
| **K=20** | **0** | **80–98%** | 2.0–7.3× | 11.7–13.1 | 0.2–1.7 of H |
| **K=50 (=max)** | **0** | **100%** | 4.5–18× | **29.0 (flat)** | **0.00** |

(across the Zipf family; e.g. Zipf s=1.2: E[n]=8.48, H(n)=4.12 bits;
K=20 hides 86.4% at 2.56× = 12.6 kB/day, leaking 1.23 bits; K=50 leaks
exactly 0 bits at a flat 29 kB/day. Zipf s=2.0 — "most wallets get 1–2
payments/day" — K=20 hides 98.2%.)

**Honest verdict.**

* (a) The observer's distinguishing advantage between a 1-note and a
  20-note victim is **exactly 0** for fixed K ≥ 20 and for K = per-epoch
  max: every padded session is byte-identical, so the campaign's
  demonstrated attack (1 vs 11 packets) dies.
* (b) Worst-case padding is **not** catastrophic: a flat 29 kB/day
  (50 kB/day at 1 kB C^L) covers every wallet every epoch forever —
  ~11–18 MB/year against the 86–1700 MB/day current-day transaction stream
  the article already imposes. A modest K=20 hides 80–98% of Zipf receive
  counts at 12–13 kB/day. The trilemma's "all wallets download lots of
  data" horn is real but its magnitude is tens of kB/day, not the design's
  actual bandwidth budget.
* (c) The count channel doesn't fully close below max: at K=20 the
  observer still learns ~0.2–1.7 bits (mostly "over-cap or not" + tail
  shape); at K=50, exactly 0.
* (d) Residuals padding cannot close: wallets with n > K stand out (2–20%
  of Zipf wallets at K=20, 60% under the adversarial uniform control); an
  attacker holding the address can push any victim over any cap with
  fee-paid dust or ~free forged post-mix entries (F7b) — padding bounds
  the *amplification* (honest wallets' padding bill caps at K) but not the
  *distinguishability* of flooded victims; and constant-shape cover is
  precisely what F13's intersection/SDA attacks erode across epochs (an
  offline day is a missing fetch — padding fixes per-epoch shape, not
  multi-epoch statistics).

**F4: WEAKENS, Medium-High → Medium-Low.** The formal point stands (P1's
absolute wording requires choosing a padding parameter, and the exact
count survives up to any sub-max cap in the tail), but the engineering
claim that forces it — "worst-case padding negates the performance goal" —
is refuted by the numbers.

---

## D4 — F8: no reading of the text patches the scalar handover — CONCEDED
(`d4_f8_readings.py`)

The text: *"it constructs its epoch detection secret key `dsk +
PRF^D(K_TT, e)` and provides it and the epoch number `e` to the new
Detection Server. The Detection Server uses this key to trial-decrypt each
C^D in the epoch"* — with step 6 of sending `D* = D + [PRF^D(K_TT,e)]G_2`.

Every reading, exercised on the real group/AEAD arithmetic of the
campaign's simulator:

| reading | service works? | dsk recovered by delegate ⊕ one address-holder? | silent all-epoch detection? |
|---|---|---|---|
| R1 literal scalar x = dsk + PRF^D(K_TT,e) | yes | **yes** | **yes** |
| R2 aggregate (x_e, e) for several epochs | yes | **yes** | **yes** |
| R3 hand over only PRF^D(K_TT,e) | **NO — service broken** (C^D is encrypted to D\*=D+[f]G_2; opening needs dsk) | — | — |
| R4 hand over group element D* (no scalar) | **NO — service broken** (trial-decryption computes [x]epk: needs the scalar; no pairing decryption in the text; dlog protects dsk from D*) | — | — |
| R5 blind x with fresh nonce b | **NO — service broken** (server cannot unblind) | — | — |
| R6 two-epoch cancellation x₁−x₂ | (no address needed) | contains **no dsk** (x₁−x₂ = f₁−f₂ exactly — verified) | dead end for the attacker |
| R7 ephemeral-x (delete x after serving — defender policy, not in text) | yes | retroactive variant: **no** (x gone before any later leak); contemporaneous colluding sender **while delegation is live: yes** | yes (contemporaneous) |

Every reading that preserves the non-indexed service hands the delegate a
value **linear in dsk**; the linear structure is load-bearing. The
article's only escape hatch is its own future-work note ("Using
Identity-Based Encryption, the non-indexed case can probably be improved so
that it does not rely on address secrecy… I am currently investigating") —
i.e., a redesign, not a reading.

**F8: SURVIVES — conceded in full, High severity unchanged.** Best-effort
defense (immediate deletion of x after serving) narrows only the
retroactive variant; the contemporaneous variant (one colluding
counterparty during any live delegation — the same weak condition F2
needs) converts a one-day grant into permanent, silent, zero-query
all-epoch detection regardless.

---

## D5 — F5: fresh Tor per lookup kills the DS-only attack; the article's
own caveats are the surviving attack surface  (`d5_tor.py`)

Defender behavior (verbatim from the article's optimizations): *"wallets
can perform each lookup over a fresh Tor circuit … This would be vulnerable
to global passive adversaries and to timing correlation attacks, however."*
300 wallets, 21 epochs, daily sync, 20% of wallets go offline 5 days then
catch up.

| condition | result |
|---|---|
| (a) same-IP sync (campaign A_F5) | 57,000/57,000 cross-day pairs linked — **F5 reproduces** [control] |
| (b) fresh circuit per lookup, each tag queried exactly once | **0%** cross-day linkage by the DS alone — no persistent identifier exists; remaining signal is bucket content (P3-conceded counts), not linkage |
| (c) tag re-query (reinstall/failover/re-verify) at probability q per tag | q=0.05 → **64.3%** of wallets identity-re-linked over 20 epochs; q=0.20 → 99.0%; q=0.50 → 100%. The tag itself is a cross-day pseudonym; "query each tag exactly once, ever" is stated nowhere |
| (d) catch-up bursts (D=5 queries, 2–8 s apart, D fresh circuits) | naive time-window clustering: recall 79.8–100%, precision 28–55% (improvable with a burst-shape classifier). The DS doesn't need the IP — only the clock |
| (e) GPA timing (M concurrent queriers/hour, jitter U[0,J]) | M=10: 85–99% uniquely+correctly linked (J=2–60 s); M=100: 19.5–94.6%; M=1000: 0.05–57.3%. Single-hour, single-epoch figures — per-wallet cadence fingerprints compound across days (not simulated) |

**F5: WEAKENS, Medium → Medium-Low.** The finding as demonstrated
(same-IP linkage by a live DS) dies under the article's own mitigation;
what survives is exactly what the article conceded (GPA + timing), plus two
understated residuals quantified here: tag-value persistence under
re-queries, and catch-up burst correlation.

---

## Cross-cutting conclusions (the true strength of the campaign)

1. **The campaign's three highest-severity structural findings are
   defense-proof within the text**: F2-live (one counterparty + live DS =
   current + all-future per-epoch counts and, with any MA, exact
   attribution), F3b (any `ssk` leak rebuilds all history from public
   lists), F8 (the non-indexed handover is a linear `dsk` disclosure). No
   reading, deletion policy, or padding parameter touches these; each is a
   property of the algebra or of public data, not of server behavior.
2. **The campaign's three "wording/perf" findings have real in-text
   defenses it under-weighted**: F11 (the letter of the text — download
   the whole commitment set — kills the leak at 1.6–6.4% overhead over the
   article's own mandated stream), F4 (pad-to-K ≥ 20 gives exactly-zero
   distinguishing advantage at a flat 29 kB/day), F5 (fresh circuits give
   0% DS-only linkage). In each case the article contains the defense
   *sentence* but never the defense *parameter* — the honest residual
   finding is "the spec is self-contradictory or silent at the point where
   the defense must be pinned down" (F11's "as usual" vs "entire set";
   F4's K; F5's "exactly once, ever" + who bears burst discipline).
3. **Defender wins here are reading-dependent; attacker wins are
   algebraic.** Everything the defender achieved relies on choosing
   favorable readings of ambiguous text (and one behavior — registration-
   log deletion — that the article never states). Everything the attacker
   kept holds under every reading. On balance the campaign's bottom line
   survives this defense campaign with F2/F3b/F8 intact, F3a/F9/F5
   reduced in scope, and F11/F4 reduced to spec-ambiguity findings with
   cheap quantified fixes.

## Reproduce

```sh
/opt/homebrew/bin/python3 defense/run_all.py          # ~13 s, stdlib only
# individual experiments:
/opt/homebrew/bin/python3 defense/d1_f11_witness.py
/opt/homebrew/bin/python3 defense/d2_footnote1.py
/opt/homebrew/bin/python3 defense/d3_padding.py
/opt/homebrew/bin/python3 defense/d4_f8_readings.py
/opt/homebrew/bin/python3 defense/d5_tor.py
```

Captured log: `defense/results.txt`. All runs deterministic (seeded RNGs).

## Files

| file | contents |
|---|---|
| `common.py` | path setup; `DisciplinedServer` (footnote-1-compliant: serve-time link deletion, grace-G bucket purge, reglog TTL, ephemeral handover) and helpers |
| `d1_f11_witness.py` | F11 defense: fetch-all + 2^16 subtree-sharded strategies, sound-only exclusion engine (interval arithmetic), bandwidth price table |
| `d2_footnote1.py` | F2/F3/F5/F9 vs deletion discipline: grace sweep, live/post-hoc matrix, `ssk`-rebuild + per-epoch-key variants |
| `d3_padding.py` | F4 defense: pad-to-K + idle cover over Zipf/uniform receive counts; advantage, hiding fraction, bandwidth multiplier, leaked bits |
| `d4_f8_readings.py` | F8: seven textual readings of the handover exercised on the real group arithmetic; concession analysis |
| `d5_tor.py` | F5 defense: fresh-circuit-per-lookup; tag re-sighting, burst clustering, GPA timing-correlation residuals |
| `run_all.py` | runs everything, writes `results.txt` |
| `results.txt` | captured output of all five experiments |
