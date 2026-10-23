import Zecbreak

/-!
  # Adversarial audit scratch: is `Derived` inhabited anywhere?

  Hypothesis under test: every constructor of `Derived` has at least one
  `Derived` premise, so as an inductive family it denotes the EMPTY relation.
  If so, every theorem whose hypotheses include `Derived _` is vacuously true.
-/

namespace Zecbreak

/-- If provable, `Derived v` is false for EVERY value: the adversary can
actually derive nothing in this model without externally supplied base facts,
and no such base-fact mechanism exists. -/
theorem derived_empty (v : Value) : ¬ Derived v := by
  intro d
  induction d with
  | hash x h ih => exact ih
  | groupHash x h ih => exact ih
  | prfT k g e hk hg ihk _ihg => exact ihk
  | prfD k e hk ih => exact ih
  | prfS k d hk ih => exact ih
  | addV a b ha _hb iha _ihb => exact iha
  | cancelL hsum _hb ihsum _ihb => exact ihsum
  | cancelR hsum _ha ihsum _iha => exact ihsum
  | enc k p _ad hk _hp _had ihk _ihp _ihad => exact ihk
  | epk esk b he _hb ihe _ihb => exact ihe

/-- Consequence 1: the hypotheses of `thm_F2_senderCollusion`,
`thm_F2_crossEpochLinkage`, `thm_F2_indexReadout`, `thm_F8_dskRecovery`
are unsatisfiable, so those theorems hold vacuously. -/
example {w : WalletId} : ¬ Derived (ktt w) := derived_empty _
example {w : WalletId} : ¬ Derived (gr w) := derived_empty _
example {w : WalletId} {e : Epoch} : ¬ Derived (EpochDKey w e) := derived_empty _
example (v : Value) : ¬ Derived (Value.vAdd v v) := derived_empty _

/-- Consequence 2 (dual failure): `QueriesTag` has a premise-free constructor,
so its existential conclusions are unconditionally true — the F5 "attack"
cannot fail in the model. -/
example (w : WalletId) (e1 e2 : Epoch) : ServerLinksEpochs w e1 e2 :=
  ⟨⟨0⟩, QueriesTag.mk _ _ _, QueriesTag.mk _ _ _⟩

example (e1 e2 : Epoch) : ServerMerges e1 e2 :=
  ⟨⟨0⟩, ⟨0⟩, QueriesTag.mk _ _ _, QueriesTag.mk _ _ _⟩

end Zecbreak
