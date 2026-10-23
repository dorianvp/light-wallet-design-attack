# F2 — Sender-collusion equivalence: every sender holds the full address

- **File:** `F2-sender-collusion-equivalence.md`
- **Invariants exercised:** `p3_countsNotWhich` (holds — this trace is the
  *conceded* half of it), `p5_bothNeeded` context; no new violation beyond
  F3/F5/F8/F9 — F2 is the *enabler* that turns "compromise both servers" into
  "compromise one MA + one past counterparty".
- **Claim (P5 as stated):** "DS+MA both compromised: learns exactly which
  transactions belong to the wallet."
- **Model encoding:** `senderCollude(p)` adds every address `p` ever sent to
  into `advAddr` — modeling that a sender *necessarily* holds
  `(addr, G_r, S_r, K_TT, D)`. Tag knowledge for **all** epochs is
  `addrLeaked(a)`.

## Trace A — DS + colluding sender, honest MAs: per-day counts, NOT which
(scripted `t_P3_countsNotWhich`, passes 10 000/10 000)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(true, true, true)` | genesis |
| 1 | `sendTx("p1", "alice.1")` | epoch 1 |
| 2 | `advanceEpoch` | mix; ds1 index gets `T(alice.1,1) ↦ {C^L}` |
| 3 | `compromiseDS("ds1")` | index readable |
| 4 | `senderCollude("p1")` | K_TT, G_r leak ⇒ adversary computes T for every epoch |

**Resulting state:** `advCount(alice.1, 1) = true`,
`advAttrib(alice.1, 1) = false`, `compMA = ∅` — the DS+sender coalition gets
*how many per day* (for all days! `tagOf` is derivable for every epoch) but
cannot pin transactions without the pre-mix↔post-mix mapping. This is exactly
P3's concession, and it needs **no server break-in at all** if the DS is
merely live-cooperative — collusion with one past sender replaces "the DS
knows the address".

## Trace B — plus one MA: exact attribution (scripted `t_P5_concededAttribution`)

Steps 0–4 as above, then `compromiseMA("ma1")`:
`advAttrib(alice.1, 1) = true` — MA mapping (tx ↔ post-mix entry) × DS index
(entry ↔ tag) × sender leak (tag ↔ wallet) = exact transaction attribution.

**Model observation on P5:** even with both DS and MA compromised, attribution
still required the tag↔wallet binding — in the model that is a sender-side
leak (or a query; see F9/F5). The DS alone never learns `K_TT` from
registration (it learns only `r`, hence `G_r` — `K_TT = H(s)` and `s` never
leaves the wallet; this is `serverTagKnown`). So the *faithful* statement of
P5 is: **(any tag knowledge, e.g. one colluding counterparty) + DS index
access + one MA = exact attribution** — a strictly weaker adversary than
"compromise both servers", and with F8 even the DS-index access is replaceable.

## Interpretation

Every counterparty is a walking address-book leak. The protocol's real
attribution boundary is `(K_TT knowledge) × (index or dsk access) × (MA
mapping)` — none of which is "compromise the wallet's DS" specifically.
Deletion discipline and address secrecy are the only friction, and both fall
to one curious sender.
