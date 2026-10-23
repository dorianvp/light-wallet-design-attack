# Formal Specification: "Making Zcash Light Wallets Faster and More Private"

Source: https://defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm
(Taylor Hornby / Defuse Security, March 2, 2023 — ZecSec project.)

> Author's own warning: "There are almost certainly security bugs in the protocol described
> below that I haven't caught, so please don't implement this without careful thought!"
> And the closing line: "If you are a cryptographer, please try to break the protocol!"

This document is a rigorous, self-contained formalization used as the shared source of
truth for the attack campaign in this repository (simulations in `sim/`, Quint model in
`quint/`, Lean 4 theorems in `lean/`, findings in `FINDINGS.md`).

---

## 1. Parties

| Symbol | Role |
|---|---|
| `W_v` | Receiver wallet (victim or honest user) with viewing key `vk` |
| `P`   | Sender (any wallet constructing a transaction to some address) |
| `DS_A` | Detection Server `A`, keypair `(ssk_A, S_A = [ssk_A]G_1)` |
| `MA_i` | Mix Authority `i`, public key `M_i` published via consensus rules |
| `GPA` | Global passive adversary (observes all encrypted network traffic + chain) |
| `CH`  | The blockchain, partitioned into daily **epochs** `e = 1, 2, ...` |

Trust assumptions (as stated in the article):
- The list of Mix Authorities is permissioned (maintained by ECC/ZF with community input).
- Availability requires **at least one** honest-ish (online) Mix Authority.
- Mapping secrecy (pre-mix ↔ post-mix) requires **all** Mix Authorities uncompromised.
- The Detection Server is "partially trusted".

## 2. Cryptographic primitives (abstract)

- Cyclic groups `G_1, G_2, G_3` of prime order `q` (pairing-friendly layout implied,
  `S ∈ G_1`, `D ∈ G_2`, Orchard-style `Enc` uses `G_3`). Scalar mult `[k]X`.
- `GroupHash : Bytes -> G_1` — modeled as a random oracle into the group,
  preimage-resistant.
- `H : Bytes -> Bytes` — collision-resistant hash, used as `K_TT = H(s)`.
- `PRF^T(key, input)`, `PRF^D(key, input)` — collision-resistant PRFs (pseudorandom).
- `Enc(pk, ptxt, ad, base, esk, epk)` — DH-based key-private authenticated PKE with
  associated data. Shared secret between sender holding `(esk, pk)` and receiver holding
  the scalar for `pk` w.r.t. `base`: `DH = [esk]pk = [sk_rcv]epk`. AEAD authentication
  fails if `ad` does not match. Randomized: fresh `esk` per encryption.
- Zero-knowledge proofs:
  - `π_reg`: DS proves `S_r = [ssk]GroupHash(r)` w.r.t. published `S = [ssk]G_1`.
  - `π` (sender, in-transaction): public `(T, epk)`, witness `(K_TT, G_r, esk)`:
    `T = PRF^T(K_TT, G_r ∥ e)` AND `epk = [esk]G_r`. Crucially: **the tag base and the
    epk base are the same group element**, and neither `K_TT` nor `G_r` is revealed.
  - `π_query`: wallet proves for public `(e, n, T)` knowledge of `(s, r)` with
    `T = PRF^T(H(s), GroupHash(r) ∥ e)` (i.e., knowledge of *preimages*, not merely of
    `K_TT`/`G_r`).
- Note-commitment tree (Merkle) with authenticated positions per epoch; nullifier set.
  Notes are authenticated by recomputing the note commitment and checking membership in
  the authenticated tree at a position within the claimed epoch.

## 3. Address generation

1. Wallet generates the usual address components; then **"derives secrets `s, r, dsk`
   from their viewing key"** (derivation function unspecified in the article — this is
   Finding F1/F6 material).
2. Registration with chosen Detection Server `DS_A`:
   a. `DS_A` publishes `S_A = [ssk_A]G_1`; users cross-check consistency (public forum /
      hard-coded) to prevent rogue-key partitioning.
   b. Wallet sends `r` to `DS_A` (server thereby learns `(IP, r)` at registration time).
   c. `DS_A` returns `G_r = GroupHash(r)`, `S_r = [ssk_A]G_r`, plus `π_reg`.
   d. Wallet verifies `π_reg`.
3. Wallet computes:
   - Transaction tagging key `K_TT = H(s)`.
   - Detection public key `D = [dsk]G_2`.
4. Address = `(addr, G_r, S_r, K_TT, D)`.
5. Privacy-optimized wallets put uniformly random (type-valid) values in
   `(G_r, S_r, K_TT, D)` and never register.

**Decryption trick (heart of the design):** a ciphertext `Enc(S_r, ·, ·, G_r, esk, epk)`
can be decrypted by `DS_A` computing `[ssk_A]epk`, for *any* `S_r` derived through
registration, **without** the server learning which `S_r`/`G_r` was used: there is no
efficient test that two ephemeral keys `[esk_1]G_r, [esk_2]G_r` share a base, since any
two group elements stand in that relation for suitable scalars.

## 4. Sending a transaction (epoch `e`)

Sender knows recipient address `(addr, G_r, S_r, K_TT, D)`:

1. `C` — usual note ciphertext; `C^L` — additional note ciphertext of the same note with
   a **fresh ephemeral key** (ZIP 212 formatting caveat in footnote 3).
2. Ephemeral pair: `esk ←$`, `epk = [esk]G_r`.
3. Tag: `T = PRF^T(K_TT, G_r ∥ e)`.   ← **constant per (address, epoch)**: every sender
   to the same address in the same epoch computes the *same* tag.
4. Proof `π` as above (same-base binding).
5. `C^T = Enc(S_r, T ∥ π, "tct" ∥ e, G_r, esk, epk)`.
6. Epoch detection key: `D* = D + [PRF^D(K_TT, e)]G_2`.
7. `C^D = Enc(D*, "true", "dct" ∥ e)`.
8. Post-mix ciphertext `C^PoM = (C^T, C^D, C^L)`.
9. Pre-mix ciphertexts `C^PrM_i = Enc(M_i, C^PoM, "mix" ∥ e)` for every authority `i`.

On-chain note ciphertext: `(C, {C^PrM_i})`. Everything else as usual.

## 5. Mixing (end of epoch)

Each `MA_i` independently: collect all `C^PrM_{i,j}` of the epoch from the chain,
decrypt with `M_i` (AD `"mix" ∥ e` rejects cross-epoch replays), then **publish and
sign the sorted, deduplicated list of post-mix ciphertexts**.

- Sorting: canonical order (must be constant-time — author's note).
- Deduplication: prevents "tagging by repetition" (an attacker re-encrypting the same
  `C^PoM` to `M_i` repeatedly to recognize it by multiplicity in the output).
- Availability: any single online authority suffices (lists should agree).
- Secrecy of the pre-mix ↔ post-mix correspondence: holds iff **all** authorities
  uncompromised. (Strengthenable via onion/mixnet, future work.)

## 6. Detection Server indexing

Every Detection Server fetches ≥1 signed post-mix list. For each post-mix
`C^PoM_j = (C^T_j, C^D_j, C^L_j)` it computes `[ssk]epk_j` and attempts AEAD-open of
`C^T_j`. On success (only ciphertexts sent to its own registered `S_r`'s open) it obtains
`(T, π)`, verifies `π`, and indexes `C^L_j` under tag `T`.

The server thereby maintains a private index `T ↦ {C^L}` covering **all of its users**,
without knowing which `S_r`/`G_r`/user each tag belongs to — until the user queries, or
the address leaks.

## 7. Receiving

All wallets download + authenticate the full note-commitment and nullifier sets.

1. **Trial decryption** (always available): trial-decrypt on-chain `C` with the viewing
   key. Performance-optimized wallets do this only for the *current* epoch.
2. **Indexed detection** (fast path): wallet obtains fresh nonce `n` from its server,
   sends `π_query` for public `(e, n, T_e)` proving knowledge of `(s, r)`. Server checks
   nonce freshness + proof, returns all `C^L` indexed under `T_e` "using a
   constant-bandwidth protocol (e.g. fixed-sized packets sent at regular intervals)".
3. **Non-indexed detection** (server-down fallback): wallet hands a *different* server
   the scalar `dsk + PRF^D(K_TT, e)` and `e`; that server trial-decrypts every `C^D` of
   the epoch with it and returns matching `C^L` over constant-bandwidth transfer.

The wallet decrypts each returned `C^L` and **authenticates** the note by recomputing
its commitment and checking membership in the authenticated commitment tree at a
position within the expected epoch. Unauthenticated `C^L` are discarded (they do,
however, still inflate the per-tag bucket seen by the server).

## 8. Claimed properties (test targets)

| # | Claim (quoted/paraphrased) | Adversary |
|---|---|---|
| P1 | GPA observing encrypted traffic learns *nothing* about when/how many transactions the wallet receives | GPA |
| P2 | DS that knows the address can identify the owner (by IP) — conceded | malicious DS |
| P3 | Compromised DS + honest MAs: learns *how many* transactions per day, *not which* | malicious DS |
| P4 | Compromised MA + honest DS: learns *nothing* about tx↔wallet mapping | malicious MA |
| P5 | DS+MA both compromised: learns *exactly* which transactions belong to the wallet | DS+MA |
| P6 | Address secrecy ⇒ granular delegation: DS cannot detect epochs not explicitly requested; after full state leak, attacker can group per-day but cannot tie groups to identities nor connect groups across days | state-leak adversary |
| P7 | Pre-mix↔post-mix unlinkability unless MA key compromised or self-created tx | everyone |
| P8 | `π` + `π_query` block sender→server identification oracles (cases (a) and (b)) | malicious senders |
| P9 | Liveness if ≥1 MA online | availability |
| P10 | Wallets receive (and authenticate) all their notes via DS | honest parties |

## 9. Attack surface identified in pre-analysis (to be confirmed/refuted by models)

*This section is the hypothesis registry as formulated before modeling. It is
preserved unchanged for traceability; where the final adjudicated result differs,
`FINDINGS.md` is authoritative.*

- **F1 diversified-address linkability**: `s, r, dsk` are "derived from the viewing key";
  if the derivation ignores the diversifier, all of a wallet's diversified addresses
  share `(G_r, S_r, K_TT, D)` — any two senders link the addresses. Breaks Zcash's
  diversifier unlinkability. Same root cause: two redundancy addresses (one per DS)
  share `K_TT` and `D` ⇒ linkable.
- **F2 sender-collusion equivalence**: every sender necessarily holds the full address
  `(K_TT, G_r)` ⇒ any past sender + the DS reconstruct all per-epoch tags
  `T_e = PRF^T(K_TT, G_r∥e)` and, with the DS index or live access, get per-day counts;
  adding any MA gives exact transaction attribution (P5 equivalence with a much weaker
  collusion than "compromise both servers" — no server *compromise* needed, just one
  past counterparty).
- **F3 no forward secrecy of `K_TT`**: `K_TT` is epoch-independent; a *future* address
  leak + retained (live) index retroactively links **all** past daily groups —
  contradicting the "cannot connect the groups from different days" part of P6 except
  under footnote-1 deletion discipline (a behavioral, not cryptographic, assumption).
- **F4 volume/duration leak**: returned data ∝ #received notes; fixed-size packets at
  fixed rate do not fix session *duration/total volume*; padding to worst case negates
  the performance goal (the article's own trilemma paragraph concedes the tension, but
  headline P1 claims zero leakage).
- **F5 live-DS cross-epoch linking by network identity (IP)**: even with address
  secrecy, a *live* malicious DS sees the same IP query tags of different epochs —
  connecting daily groups in real time; deletion discipline is moot against live
  compromise. Mitigated only by fresh Tor circuits (GPA+timing defeats).
- **F6 under-specified key derivation**: if `s, r, dsk` are not domain-separated PRF
  outputs (e.g. `r = s`), registration (which reveals `r`) hands the server `K_TT`
  and/or detection across all epochs — catastrophic. Spec bug.
- **F7 liveness/completeness**: malicious DS can withhold `C^L` (silent balance loss
  until full rescan); malicious MA can censor (omit) or inject post-mix entries
  (injection fails commitment authentication but inflates per-tag buckets = count
  pollution).
- **F8 `dsk` recovery from non-indexed delegation + colluding sender**: in non-indexed
  detection the wallet hands a server the scalar `x = dsk + PRF^D(K_TT, e)`. Any past
  sender (who by necessity holds the address, hence `K_TT` and `e`) lets that server
  compute `dsk = x − PRF^D(K_TT, e)`. With `dsk` and `K_TT`, the server derives the
  epoch detection key `dsk + PRF^D(K_TT, e')` for **every** epoch `e'` and silently
  trial-decrypts all `C^D` forever — retroactively and prospectively, with **no further
  queries** by the victim. Breaks the claim "the new Detection Server is only granted
  detection authority for a limited number of epochs". Same escalation applies
  retroactively if the address ever leaks after the server retained `x` (forward-secrecy
  break of delegation).
- **F9 retroactive full-index readout (indexed path)**: the DS necessarily builds and can
  retain its full private index `T ↦ {C^L}` for *all* users while processing each epoch.
  A *later* leak of the address (any sender) lets it compute the victim's tag for **every
  past epoch** and read that epoch's bucket out of retained state — "cannot connect the
  groups from different days" (P6) fails against any live/retentive server the moment
  one counterparty or log leaks; it survives only the footnote-1 deletion discipline.
- **F11 witness-update exclusion leak**: the performance list requires wallets to
  "update the witnesses for their unspent notes as usual" while fetching only `C^L`.
  Incremental witness maintenance downloads finalized sibling subtree roots; a
  watching server learns (sound, absence-only inference) that the wallet's note is in
  neither any *unfetched* finalized subtree nor its complementary half, and (first-sync
  completeness) that pre-existing siblings were fetched at first sync. One epoch of
  ordinary growth pins a new wallet's note position exactly; spam dilution (F12) does
  not slow it (the attack ignores the anonymity set). Only fetch-all (Θ bandwidth —
  the cost the design exists to avoid) or permanent k-fold fake witnesses (anonymity
  exactly 1+k at (k+1)× cost) mitigate. Independently confirmed by the author's own
  later general proof (zcash/zcash#6756, Apr 2024 comment). Demo:
  `analysis/f11_witness_leak.py`.
- **F12 epoch dilution / blending**: "epoch-sized anonymity set" is really
  "honest-outputs-per-epoch"; attacker outputs dilute it at one fee each
  (Serjantov–Danezis threshold-batch math). Sort+dedup stop replay tagging, not
  volume dilution.
- **F13 intersection/SDA on `R+F` cover + delivery-channel fragility**: constant-shape
  dummy cover erodes across epochs (Danezis SDA, MixFlow); measured mixnet channels
  (lwd-mixnet-proxy 2026) undercut constant-bandwidth delivery operationally.
- **Verified sound (non-breaks)**: π-fix blocks oracle (a)/(b); AD `"mix"∥e` blocks
  cross-epoch pre-mix replay; dedup blocks repetition tagging; no base-equality test
  for `epk`s (unforgeable anonymity of the decryption trick); DLP protects `dsk` given
  `D`; GroupHash preimage resistance blocks rogue-`r` registration; injected `C^PoM`
  fails note-commitment authentication.
