# VERIFICATION — sim/ attack-campaign simulation

Verification agent run: 2026-10-23. Entry point: `python3 run_all.py`
(interpreter used: `/opt/homebrew/bin/python3`, Python 3.14.7, stdlib only).

## 1. Provenance — important

**The simulation this report was asked to re-run did not exist.** At
verification time the repository contained only `PROTOCOL.md`, `FINDINGS.md`,
`package.json`, `package-lock.json`, `node_modules/`. There was no `sim/`,
no `quint/`, no `lean/` (both also referenced by FINDINGS.md), no git
repository, no stash, no worktrees, and no copy anywhere on the machine
(Spotlight + `find` over the workspace, `/Users/dorian/projects/zcash/`, and
the agent temp dirs). The previous agent's claimed simulation was never
persisted.

What was done instead: **`sim/` was rebuilt from scratch against
`../PROTOCOL.md`** (the authoritative spec), implementing every scenario ID
that `../FINDINGS.md` claims (`A_F1..A_F8` incl. `A_F7a/7b`, `N_a..N_g`, plus
supplementary `N_h`), then audited and re-run. Nothing here verifies prior
code; this file verifies the code now in `sim/`, and cross-checks its
verdicts against FINDINGS.md's claims.

## 2. What was run

```sh
cd sim && /opt/homebrew/bin/python3 run_all.py
```

Runs all 17 scenarios, prints per-scenario detail + verdict table, writes
`results.json`. Deterministic: two consecutive runs produce byte-identical
`results.json` (seeded RNGs; hardcoded 256-bit safe-prime group constants).

## 3. Verdict table

| ID | Target (per FINDINGS.md) | Verdict | Expected | Key evidence (`notes` fields) |
|---|---|---|---|---|
| A_F1 | diversifier unlinkability | **BREAK** | BREAK | naive tuples equal (`naive_linked=True`), redundancy `(K_TT,D)` equal, per-diversifier fix makes them unequal |
| A_F2 | P3/P5 "both servers compromised" framing | **BREAK** | BREAK | DS+one colluding sender+one MA: recovered txids `['tx0000','tx0001'] / ['tx0003','tx0004']` == ground truth, zero key compromises; MA-alone check confirms P4 still holds |
| A_F3 | P6 cross-day linkage | **BREAK** | BREAK | after epoch 3, one address disclosure reconstructs all past groups (`retro={1:1,2:3,3:2}` == truth); reglog ties back to IP; **variant (b)**: even a deletion-disciplined server is fully re-indexed from public post-mix lists once `ssk` leaks |
| A_F4 | P1 "learns nothing about when/how many" | **BREAK** | BREAK | 1-note wallet session (1 pkt) vs 20-note (11 pkts); pad-to-max equalizes at 11x overhead (trilemma) |
| A_F5 | P6 delegation clause (live server) | **BREAK** | BREAK | one IP queries tags of epochs 1,2,3 during sync; fresh-circuit mitigation defeats IP grouping (GPA timing out of scope) |
| A_F6 | derivation under-specification | **BREAK** | BREAK | `s:=r`: server computes `K_TT=H(r)` from registration alone; all tags match, buckets readable; domain-separated variant blocked |
| A_F7a | P10 completeness/liveness | **BREAK** | BREAK | DS returns 2 of 3; everything returned authenticates; only full rescan recovers the third |
| A_F7b | P3 count integrity | **BREAK** | BREAK | forged `C^PoM` with victim tag (valid pi — attacker holds the address) ⇒ bucket count 2 vs true 1; wallet accepts exactly the 1 real note |
| A_F8 | P6 "limited number of epochs" | **BREAK** | BREAK | `dsk = x − PRF^D(K_TT,e)` recovered exactly (`[dsk]G2 == D`); silent detection of epochs 1–4 (incl. never-delegated 1 and future 4), zero further queries |
| N_a | P8 oracle (a) | **BLOCKED** | BLOCKED | `planted_with_pi=False`, `planted_without_pi=True`; `no_witness=True` with attacker able to construct *valid* pi over either base — no witness satisfies both relations on *different* bases |
| N_b | P8 oracle (b) | **BLOCKED** | BLOCKED | address holder cannot construct `pi_query` (needs preimages `(s,r)`); with proof check off, bucket is returned |
| N_c | cross-epoch pre-mix replay | **BLOCKED** | BLOCKED | AD `"mix"‖e` open fails in epoch 2; epoch-free-AD *protocol variant* control: replay appears |
| N_d | repetition tagging | **BLOCKED** | BLOCKED | multiplicity 1 with dedup vs 5 without |
| N_e | epk base-equality test | **BLOCKED** | BLOCKED | exact enumeration on order-53 group: `P[epk|base]` uniform & base-independent; `[ssk]epk` uniform; "shares base" predicate degenerate |
| N_f | rogue registration | **BLOCKED** | BLOCKED | 0/20000 hits; toy group hits at 1/53 rate (pure RO-preimage security) |
| N_g | injected/replayed `C^L` | **BLOCKED** | BLOCKED | replayed real `C^L` decrypts fine but its cm sits in the epoch-1 tree ⇒ discarded; auth-off control accepts it (would double-count) |
| N_h | `dsk` from `D` (supplementary) | **BLOCKED** | BLOCKED | assumption-labeled (DLP); toy-group control shows nothing but group size protects it |

**17/17 match FINDINGS.md.** No verdict flipped.

## 4. Fidelity audit (spec ⇄ code)

The three questions posed to this verification, plus the other load-bearing
modeling choices:

- **pi binding ("tag base = epk base") — faithful.**
  `ProofPi` (primitives.py) carries witness `(K_TT, G_r, esk)` and verifies
  `T == PRF^T(K_TT, G_r‖e) ∧ epk == [esk]G_r` with the **same** `G_r` in
  both relations. The DS binds the proof to the ciphertext it opened
  (`proof.T == T ∧ proof.epk == C_T.epk`, protocol.py `process_epoch`).
  Crucially the model is **not** strawmanned: in `N_a` the attacker
  *successfully constructs* valid proofs (it legitimately holds the address
  and its own `esk`) — one over the victim's base, one over its own — and
  the block comes from the algebra (no single witness satisfies both
  relations on different bases), not from a knowledge-check artifact. The
  π-disabled control then shows the plant succeeds. Verified end-to-end
  through the full honest pipeline (send → chain → mix → DS index).
- **AD epoch binding — faithful.** `e8(e)` canonical 8-byte encoding inside
  `"tct"‖e`, `"dct"‖e`, `"mix"‖e`. AEAD keys derive from
  `(shared_secret, ad)`, so an AD mismatch is an authentication failure.
  The DS uses the **post-mix list's** epoch for AD, never a sender-claimed
  one (the F10 wrinkle). `N_c`'s control models the full epoch-free-AD
  protocol variant (senders *and* MA), not a one-sided relaxation — the
  first attempt at the control relaxed only the MA side and (correctly)
  failed, which is how it was caught.
- **Dedup on post-mix ciphertexts — faithful.** `MixAuthority.mix` first
  AEAD-opens every pre-mix entry (`[sk]epk`, AD `"mix"‖e`), then
  deduplicates on the **canonical serialization of the decoded `C^PoM`** —
  never on the pre-mix wrapper (which is freshly randomized per
  encryption). `N_d` proves it matters: k fresh re-encryptions collapse to
  multiplicity 1; with dedup off, multiplicity k.
- **Knowledge modeling.** Every party has a vault; ideal proof constructors
  raise unless the prover holds the witness; every collusion/disclosure is
  an explicit `learn()` at the narrative point (searchable: "collusion
  point", "disclosure point", "state-leak point"). Attackers' own ephemeral
  keys are learned by their generators — the block is never "attacker
  missing its own key".
- **Attack worlds are not weakened.** Attacks reuse the honest
  `run_epoch`/`Sender.send`/`process_epoch` code paths with mechanism flags
  only used for *negative controls* (`verify_pi`, `dedup`,
  `bind_epoch_ad`, `require_proof`, `authenticate`,
  `epoch_free_mix_ad`). The main (unflagged) runs are the spec as written.
- **Note authentication.** Abstract Merkle tree = per-epoch committed set;
  `receive_bucket` checks membership in the **claimed epoch's** tree, which
  is exactly what catches a *real* note replayed into a later epoch
  (`C^L`'s AD is epoch-free because the spec gives it none — modeled
  honestly rather than inventing a stronger protocol).
- **Group instantiation.** Prime-order subgroup of `F_p^*` (257-bit safe
  prime) instead of pairing groups: preserves every relation used
  (`[esk]S_r = [ssk]epk` decryption trick, `D* = D + [f]G_2`, F8's scalar
  subtraction, DH). Pairing-specific properties are not exercised by any
  P1–P10 claim; noted as a limitation anyway.

## 5. Bugs found and fixed during verification

Found while building/auditing (all now fixed; each is visible in the
scenario's control logic):

1. **A_F7b double-indexing (rigged attack world).** A stale duplicated
   `send`+`run_epoch` block processed epoch 2 twice, inflating the bucket to
   4 with the same real note thrice-accepted. Restructured to a single
   end-of-epoch pipeline run.
2. **A_F8 stale ground truth.** Epoch-4 detection was compared against a
   ground-truth snapshot taken before epoch 4 existed. Recomputed after.
3. **N_a control was rigged (caught by its own control firing False).** In
   the π-disabled control world the attacker was not registered at that
   world's DS, so its ciphertext was unopenable *there* — the "blocked"
   verdict was unproven. Fixed by registering the attacker; control now
   fires True.
4. **N_c control one-sided (also caught by its control).** Relaxing the AD
   only on the MA side cannot succeed because the honest sender bound
   `"mix"‖1`; the control now models the full epoch-free-AD protocol
   variant.
5. **A_F4 padding overhead computed on single ciphertext, not bucket.**
   `worst` was max `|C^L|` instead of max bucket size, understating the
   trilemma overhead as 1x; corrected (11x for the 1-note wallet).
6. **Knowledge-vault gaps.** Honest senders and attackers did not `learn()`
   their own `esk`, so the ideal-π constructor (correctly) rejected them;
   fixed at every construction site rather than weakening the check.

## 6. Honest limitations

- ZK proofs are idealized (sound by construction; serialization through an
  unforgeable global table). Real-world malleability/snark bugs are out of
  scope.
- `GroupHash`/`H` are RO/HMAC stand-ins; preimage resistance is modeled by
  the *absence* of an inversion function (and quantified on a toy group).
  N_f/N_h are assumption-labeled, not unconditional; only N_e is
  information-theoretic.
- No real signatures, network stack, or timing: A_F4 measures volume only
  (FINDINGS' F4 also concedes timing); A_F5's GPA timing correlation is out
  of scope; the Tor mitigation demo is link-layer only.
- F10 (epoch not bound in π's public inputs) is intentionally modeled as
  the spec writes it (π verifies over `(T, epk)` only); it is not
  simulated as a separate attack (FINDINGS lists it as manual).

## 7. Discrepancies vs FINDINGS.md

- None in verdicts.
- **One strengthening**: A_F3 variant (b) shows FINDINGS' F3 statement
  ("survives only under the footnote-1 deletion discipline") is *generous*:
  since post-mix lists are public and the DS must retain `ssk` to function,
  a later state leak re-creates the entire historical index even for a
  deletion-disciplined server. The retroactive break is irreparable short
  of destroying `ssk` (which breaks registered addresses). FINDINGS.md may
  want to absorb this.
- `N_h` is supplementary (FINDINGS' verified-sound item 8 had no sim ID).
