# sim/ — executable specification + attack scenarios

Executable model of the protocol of `../PROTOCOL.md` plus every attack
scenario and verified non-break referenced by `../FINDINGS.md`
(scenario IDs `A_F1..A_F8`, `N_a..N_g`, supplementary `N_h`).
See `VERIFICATION.md` for provenance and the full fidelity audit.

## Run

```sh
# from the repo root:
/opt/homebrew/bin/python3 sim/run_all.py            # pretty output + summary table
/opt/homebrew/bin/python3 sim/run_all.py > sim/results.txt   # captured run log
```

Or from `sim/`: `python3 run_all.py`. No third-party dependencies (stdlib
only). Deterministic (seeded RNGs — `random.Random("zecsec/<scenario-id>")`).
Writes machine-readable `results.json` next to it; the committed
`results.txt` is a captured run log. Exit code 0 always — verdicts are
findings, not test failures.

## Result summary (17 scenarios, 0 mismatches vs FINDINGS.md)

Verdict vocabulary: `A_*` attacks → `BREAK` (goal achieved; covers both
"breaks" and "leaks") / `NO_BREAK`; `N_*` non-breaks → `BLOCKED` / `BROKEN`.
Every `BLOCKED` comes with a **negative control**: the same attack re-run
with exactly one mechanism disabled, which then *succeeds* — so a BLOCKED
verdict cannot be an artifact of the simulation.

| ID | Target (property tested) | Verdict | Demonstrated result |
|----|---------------------------|---------|---------------------|
| A_F1 | Diversified-address unlinkability | **BREAK** | naive vk-only derivation ⇒ identical `(G_r,S_r,K_TT,D)` on every diversified address (and identical `(K_TT,D)` across redundancy servers) ⇒ senders link by plain equality; per-diversifier domain-separated derivation breaks the link |
| A_F2 | P3/P5 framing ("attribution needs both servers compromised") | **BREAK** | ONE colluding past sender discloses `(K_TT,G_r)` ⇒ DS computes every epoch's tag and reads exact counts + (with one MA's work product) exact on-chain tx attribution — **zero key compromises** |
| A_F3 | P6 "cannot connect groups from different days" | **BREAK** | one *later* address leak + the DS's own retained index ⇒ retroactive linkage of all past daily groups (`retro==truth`) + IP tie-back via registration log; index even rebuildable from *public* post-mix lists after an ssk leak |
| A_F4 | P1 (GPA learns nothing about when/how many) | **BREAK** | 1 vs 20 received notes ⇒ 1 vs 11 fixed-size packets (1 s vs 11 s at fixed rate) — session length/duration distinguishes; pad-to-worst-case restores equality at 11× download overhead (the author's own trilemma) |
| A_F5 | P6 delegation clause (live server) | **BREAK** | wallet syncs epochs 1..3 from one IP ⇒ live DS groups all daily groups by network identity in real time, address secrecy notwithstanding (fresh circuit per lookup mitigates) |
| A_F6 | Key-derivation under-specification | **BREAK** | `s := r` instantiation: registration (which transmits `r`) hands the server `K_TT = H(r)` ⇒ all tags forever from the registration log alone; domain separation blocks it |
| A_F7a | P10 completeness/liveness | **BREAK** | malicious DS withholds one `C^L`: everything returned authenticates (silent loss); only a full trial-decryption rescan recovers the missing note |
| A_F7b | P3 count integrity ("how many") | **BREAK** | forged `C^PoM` with the victim's tag and a *valid* π (attacker holds the address) inflates the per-tag bucket 2×→observed at zero on-chain cost; wallet discards the note but the DS-observed count is polluted |
| A_F8 | P6 "only granted detection authority for limited epochs" | **BREAK** | `dsk = x_e − PRF^D(K_TT,e)` (linear scalar cancellation from one non-indexed delegation + one colluding sender) ⇒ silent per-epoch detection for all past **and future** epochs with zero further victim queries |
| N_a | P8 case (a): sender→server oracle | BLOCKED | π's same-base binding: openability at attacker's own `S_r*` forces the tag base `G_r*` ⇒ tag ≠ victim's. Control: π disabled ⇒ planting succeeds (oracle live) |
| N_b | P8 case (b): querying a foreign tag | BLOCKED | π_query demands preimages `(s,r)`, not `(K_TT,G_r)`. Control: π_query disabled ⇒ bucket handed to attacker |
| N_c | Cross-epoch pre-mix replay | BLOCKED | AD `"mix"∥e` fails the MA's AEAD-open in `e'≠e`. Control: epoch-free-AD variant ⇒ replayed entry appears in epoch-2 list |
| N_d | Repetition tagging | BLOCKED | decode-then-dedup on canonical post-mix bytes: k=5 fresh re-encryptions ⇒ 1 output. Control: dedup off ⇒ multiplicity 5 |
| N_e | Base-equality test on `epk`s (decryption-trick anonymity) | BLOCKED | exact enumeration on an order-53 group: `epk` distribution is uniform and *base-independent*, `[ssk]epk` still uniform — information-theoretic given uniform esk (no toggle exists) |
| N_f | Rogue-`r` registration | BLOCKED | `GroupHash` preimage resistance: 0/20000 attempts; toy 53-group hits at ≈1/53 exactly as the RO assumption predicts |
| N_g | Injected/replayed `C^L` | BLOCKED | note-commitment membership **in the claimed epoch's tree** discards even a genuine replayed real note. Control: auth disabled ⇒ double-counted |
| N_h | `dsk` from published `D` | BLOCKED | discrete-log assumption (toy group shows recovery is exactly as hard as the group size) |

## Files

| File | Contents |
|---|---|
| `primitives.py` | Group (prime-order subgroup of `F_p*`, 256-bit safe prime), `H`, `PRF^T/D`, `GroupHash` RO, AEAD `Enc` with AD binding, idealized ZK proofs (`pi`, `pi_query`, `pi_reg`) — prover-oracle style: mintable only over *true* statements by parties holding the witness (`learn()` vaults) |
| `protocol.py` | Honest flows: registration, send (§4), mixing (§5), DS indexing (§6), indexed + non-indexed receiving, note-commitment authentication (§7); documented adversarial/retention config knobs for the attack scenarios (`withhold`, `inject`, `retain_lists`, `record_handovers`, `purge`, derivation `mode`s `naive/fixed/s_eq_r/ivk`) |
| `attacks.py` | All scenarios; each `N_*` carries a negative control |
| `run_all.py` | Entry point; prints verdict table, compares against FINDINGS.md expectations |
| `VERIFICATION.md` | Provenance note + fidelity audit (spec ⇄ code), bugs found during audit, honest limitations |
| `results.txt` / `results.json` | Captured run log / machine-readable verdicts |

## Modeling assumptions (summary)

- ZK proofs are idealized: sound by construction (the prover functions refuse
  false statements — forging is impossible without the witness), zero-
  knowledge (witnesses never appear in proof objects; verification re-derives
  the statement). Knowledge is modeled via per-party vaults; every collusion
  or disclosure in an attack is an explicit `learn()` call at that narrative
  step.
- `GroupHash`/`H` are random-oracle/HMAC stand-ins; no inversion functions
  exist in the code — that absence *is* the preimage-resistance assumption.
- The Merkle tree is abstracted as a per-epoch committed set authenticated by
  consensus; membership check = authenticated proof.
- MA list "signatures" are unforgeable by construction (identity-bound hash
  of the list bytes); a *malicious* MA signs whatever it publishes, which is
  exactly the A_F7b threat.
- Attack code never reads other parties' vaults, proofs' hidden witnesses, or
  `EncRecord` private fields; `ground_truth()` is a verdict oracle only.
