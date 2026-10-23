import Model

/-!
# Verified non-breaks (N-b, N-c, N-d)

The mechanism the protocol DOES get right, proved sound in the model:
- N-b: π binds the tag base to the epk base, blocking the sender→server
  identification oracle (P8, cases (a)/(b));
- N-c: the associated data "mix"∥e blocks cross-epoch pre-mix replay;
- N-d: deduplication removes the multiplicity (repetition-tagging) signal.

Only N-b uses an axiom (`pi_sound`, the labeled ZK-soundness assumption).
-/

namespace Zecbreak

/-! ## N-b: π binds the tag base to the epk base -/

/-- **N-b.**  Take a context whose epk was generated over a base different
from the victim's `G_r`.  Then π-verification on `(TagOf w, ctx.epk)` is
IMPOSSIBLE: by π-soundness, a verifying proof would force the tag's base to
equal the epk's base.  Consequently the honest-server indexing rule never
indexes a wrong-base ciphertext under the victim's tag: the sender→server
identification oracle is blocked. -/
theorem thm_Nb_piBindsBase {w : WalletId} {e : Epoch} {ctx : Ctx}
    (hnb : epkBase ctx.epkV ≠ gr w)
    (hidx : ServerIndexes ctx (TagOf w e) e) : False := by
  have hsound := pi_sound (TagOf w e) ctx.epkV e hidx
  cases hsound with
  | intro k hs1 =>
    cases hs1 with
    | intro esk hs2 =>
      cases hs2 with
      | intro b hs3 =>
        cases hs3 with
        | intro hT hepk =>
          -- hT : TagOf w e = vPrfT k b e ; hepk : ctx.epkV = vEpk esk b
          have hT' : Value.vPrfT (ktt w) (gr w) e = Value.vPrfT k b e := hT
          injection hT' with _h1 h2 _h3
          -- h2 : gr w = b
          have hb : epkBase ctx.epkV = b := by
            rw [hepk, epkBase_epk]
          exact hnb (hb.trans h2.symm)

/-- **N-b (oracle statement).**  No transaction context whose epk base
differs from the victim's `G_r` is ever indexed under the victim's tag. -/
theorem thm_Nb_oracleBlocked {w : WalletId} {e : Epoch} :
    ¬ ∃ ctx : Ctx, epkBase ctx.epkV ≠ gr w ∧ ServerIndexes ctx (TagOf w e) e := by
  intro h
  cases h with
  | intro ctx h2 =>
    cases h2 with
    | intro hnb hidx => exact thm_Nb_piBindsBase hnb hidx

/-! ## N-c: the AD "mix" ∥ e blocks cross-epoch replay -/

/-- Acceptance of ciphertext `c` at epoch `e'`: AEAD-open succeeds under the
associated data `"mix" ∥ e'`. -/
def acceptedAt (c : Value) (e' : Epoch) : Prop := decryptsAD (Value.vAdMix e') c

/-- **N-c.**  A pre-mix ciphertext created for epoch `e` is NOT accepted in
a different epoch `e'`: the associated-data check fails on concrete
constructor equality (`"mix" ∥ e ≠ "mix" ∥ e'` for `e ≠ e'`).  No cross-epoch
replay of pre-mix ciphertexts into another day's mixing. -/
theorem thm_Nc_adBlocksReplay {i : Nat} {pom : Value} {e e' : Epoch} (h : e ≠ e') :
    ¬ decryptsAD (Value.vAdMix e') (preMix i pom e) := by
  intro hacc
  have heq : Value.vAdMix e' = Value.vAdMix e := hacc
  injection heq with he
  exact h he.symm

theorem thm_Nc_replayRejected {i : Nat} {pom : Value} {e e' : Epoch} (h : e ≠ e') :
    ¬ acceptedAt (preMix i pom e) e' :=
  thm_Nc_adBlocksReplay h

/-! ## N-d: dedup removes the multiplicity signal -/

/-- Boolean membership (via the derived `DecidableEq Value`). -/
def memB (x : Value) : List Value → Bool
  | [] => false
  | y :: ys => (decide (x = y)) || memB x ys

theorem memB_iff (x : Value) : ∀ l : List Value, memB x l = true ↔ x ∈ l := by
  intro l
  induction l with
  | nil =>
    constructor
    · intro h
      have h' : false = true := h
      exact Bool.noConfusion h'
    · intro h
      nomatch h
  | cons y ys ih =>
    constructor
    · intro h
      have h' : ((decide (x = y)) || memB x ys) = true := h
      cases (Bool.or_eq_true _ _).mp h' with
      | inl hd => exact List.mem_cons.mpr (Or.inl (of_decide_eq_true hd))
      | inr hm => exact List.mem_cons.mpr (Or.inr (ih.mp hm))
    · intro h
      cases List.mem_cons.mp h with
      | inl he =>
        rw [he]
        show (decide (y = y) || memB y ys) = true
        rw [decide_eq_true (rfl : y = y), Bool.true_or]
      | inr hm =>
        show (decide (x = y) || memB x ys) = true
        rw [ih.mpr hm, Bool.or_true]

/-- Left-to-right scanning dedup that keeps first occurrences. -/
def dedupAux : List Value → List Value → List Value
  | _, [] => []
  | seen, x :: xs =>
      if memB x seen then dedupAux seen xs else x :: dedupAux (x :: seen) xs

/-- The published post-mix list: sorted, deduplicated. -/
def dedup (l : List Value) : List Value := dedupAux [] l

theorem dedupAux_snoc (x : Value) : ∀ (l seen : List Value),
    (x ∈ seen ∨ x ∈ l) → dedupAux seen (l ++ [x]) = dedupAux seen l := by
  intro l
  induction l with
  | nil =>
    intro seen h
    have hb : memB x seen = true := by
      cases h with
      | inl h1 => exact (memB_iff x seen).mpr h1
      | inr h2 => nomatch h2
    show (if memB x seen then dedupAux seen [] else x :: dedupAux (x :: seen) []) = []
    exact if_pos hb
  | cons y ys ih =>
    intro seen h
    by_cases hb : memB y seen = true
    · have hcond : x ∈ seen ∨ x ∈ ys := by
        cases h with
        | inl h1 => exact Or.inl h1
        | inr h2 =>
          cases List.mem_cons.mp h2 with
          | inl he => exact Or.inl (by rw [he]; exact (memB_iff y seen).mp hb)
          | inr hm => exact Or.inr hm
      show (if memB y seen then dedupAux seen (ys ++ [x])
            else y :: dedupAux (y :: seen) (ys ++ [x]))
          = (if memB y seen then dedupAux seen ys
             else y :: dedupAux (y :: seen) ys)
      rw [if_pos hb, if_pos hb, ih seen hcond]
    · have hcond : x ∈ y :: seen ∨ x ∈ ys := by
        cases h with
        | inl h1 => exact Or.inl (List.mem_cons.mpr (Or.inr h1))
        | inr h2 =>
          cases List.mem_cons.mp h2 with
          | inl he => exact Or.inl (List.mem_cons.mpr (Or.inl he))
          | inr hm => exact Or.inr hm
      show (if memB y seen then dedupAux seen (ys ++ [x])
            else y :: dedupAux (y :: seen) (ys ++ [x]))
          = (if memB y seen then dedupAux seen ys
             else y :: dedupAux (y :: seen) ys)
      rw [if_neg hb, if_neg hb, ih (y :: seen) hcond]

/-- Clean key lemma: appending one MORE copy of an already-present value
leaves the deduplicated list unchanged. -/
theorem dedup_snoc (x : Value) {l : List Value} (h : x ∈ l) :
    dedup (l ++ [x]) = dedup l :=
  dedupAux_snoc x l [] (Or.inr h)

/-- `rep x k` : `k` copies of `x` (a local `List.replicate` stand-in, to stay
independent of core list API naming). -/
def rep (x : Value) : Nat → List Value
  | 0 => []
  | k + 1 => x :: rep x k

theorem dedup_rep (x : Value) : ∀ (k : Nat) (l : List Value), x ∈ l →
    dedup (l ++ rep x k) = dedup l := by
  intro k
  induction k with
  | zero =>
    intro _l _h
    exact congrArg dedup (List.append_nil _l)
  | succ k ih =>
    intro l h
    have hsplit : l ++ rep x (k + 1) = (l ++ [x]) ++ rep x k := by
      calc l ++ rep x (k + 1)
          = l ++ (x :: rep x k) := rfl
        _ = l ++ ([x] ++ rep x k) := rfl
        _ = (l ++ [x]) ++ rep x k := (List.append_assoc l [x] (rep x k)).symm
    have h' : x ∈ l ++ [x] := List.mem_append.mpr (Or.inl h)
    rw [hsplit, ih (l ++ [x]) h', dedup_snoc x h]

/-- **N-d (dedup blocks repetition tagging).**  If the adversary re-encrypts
the same post-mix value `x` to a mix authority `k` times, while one honest
copy of `x` is present anyway, the signed post-mix list is UNCHANGED:
repetitions carry no signal. -/
theorem thm_Nd_dedup {l : List Value} {x : Value} (h : x ∈ l) (k : Nat) :
    dedup (l ++ rep x k) = dedup l :=
  dedup_rep x k l h

/-- **N-d (multiplicity independence).**  Any two repetition counts produce
the identical published list. -/
theorem thm_Nd_noMultiplicity {l : List Value} {x : Value} (h : x ∈ l) (k1 k2 : Nat) :
    dedup (l ++ rep x k1) = dedup (l ++ rep x k2) := by
  rw [thm_Nd_dedup h, thm_Nd_dedup h]

/-- **N-d (length invariance).**  The length of the published list is
independent of the number of repetitions. -/
theorem thm_Nd_lengthInvariant {l : List Value} {x : Value} (h : x ∈ l) (k : Nat) :
    (dedup (l ++ rep x k)).length = (dedup l).length :=
  congrArg List.length (thm_Nd_dedup h k)

end Zecbreak
