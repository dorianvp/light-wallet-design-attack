import Model
import Breaks
import Soundness

/-!
# zecbreak

Root module of the Lean 4 formalization of the attack analysis of
"Making Zcash Light Wallets Faster and More Private"
(Taylor Hornby, Defuse Security, March 2023).  See `../PROTOCOL.md` and
`../FINDINGS.md`.

- `Model`    — abstract Dolev-Yao model (values, derivations, adversary
               closure, fact vocabulary, and the two labeled ideal-crypto
               axioms `piVerified` / `pi_sound`).
- `Breaks`   — formal cores of findings F1, F2, F4, F5, F8.
- `Soundness`— formal cores of the non-breaks N-b, N-c, N-d.

Build: `PATH=$HOME/.elan/bin:$PATH lake build` (core Lean 4.21.0, no mathlib).
-/

/-! ## Axiom audit

Every theorem in this development is proved in core Lean 4 (no mathlib, no
`native_decide`, no `sorry`).  The only nonstandard axioms are the two
labeled ideal-crypto assumptions of `Model.lean`:

- `Zecbreak.piVerified` — opaque verifier interface for the sender proof π;
- `Zecbreak.pi_sound`   — ZK soundness of π ("same-base binding").

The break theorems (F*) and N-c/N-d use NEITHER: they are axiom-free modulo
Lean's standard axioms.  Only the N-b theorems use `pi_sound`, which is
exactly the protocol's own assumption being leveraged, not the conclusion. -/

#print axioms Zecbreak.thm_F2_senderCollusion
#print axioms Zecbreak.thm_F2_crossEpochLinkage
#print axioms Zecbreak.thm_F2_addrLeakLinkage
#print axioms Zecbreak.thm_F2_indexReadout
#print axioms Zecbreak.thm_F8_dskRecovery
#print axioms Zecbreak.thm_F1_diversifierLink
#print axioms Zecbreak.thm_F1_diversifierLink_decide
#print axioms Zecbreak.thm_F1_kttD_distinct
#print axioms Zecbreak.thm_F1_diversifiedDistinct
#print axioms Zecbreak.thm_F4_volumeDistinguisher
#print axioms Zecbreak.thm_F4_padding
#print axioms Zecbreak.thm_F4_trilemma
#print axioms Zecbreak.thm_F5_ipLink
#print axioms Zecbreak.thm_F5_liveMerge
#print axioms Zecbreak.thm_F5_linksIpWallet
#print axioms Zecbreak.thm_Nb_piBindsBase
#print axioms Zecbreak.thm_Nb_oracleBlocked
#print axioms Zecbreak.thm_Nc_adBlocksReplay
#print axioms Zecbreak.thm_Nc_replayRejected
#print axioms Zecbreak.thm_Nd_dedup
#print axioms Zecbreak.thm_Nd_noMultiplicity
#print axioms Zecbreak.thm_Nd_lengthInvariant
