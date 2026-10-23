import Model

/-!
# The breaks (formal cores of findings F1, F2, F4, F5, F8)

Each theorem below is proved in the abstract Dolev-Yao model of `Model.lean`,
with adversary knowledge taken as explicit hypotheses (no ideal-crypto axioms
are used in this file; see the `#print axioms` audit in `Zecbreak.lean`).
-/

namespace Zecbreak

/-! ## F2: sender collusion is equivalent to server compromise -/

/-- **F2 (part 1).**  Whoever holds the two address components `K_TT` and
`G_r` — in particular ANY past sender, which necessarily received the full
address — can compute the victim's tag for EVERY epoch.  A single leak of the
address covers all past and future epochs. -/
theorem thm_F2_senderCollusion {w : WalletId}
    (hK : Derived (ktt w)) (hG : Derived (gr w)) :
    ∀ e : Epoch, Derived (TagOf w e) :=
  fun e => Derived.prfT (ktt w) (gr w) e hK hG

/-- **F2 (part 2, cross-epoch linkage).**  From the two address components
(the knowledge any single sender has), the tags of ANY two epochs — hence the
corresponding per-day detection groups held by the server — are simultaneously
computable.  This is the engine behind F2, F3 and F9. -/
theorem thm_F2_crossEpochLinkage {w : WalletId}
    (hK : Derived (ktt w)) (hG : Derived (gr w)) :
    ∀ e1 e2 : Epoch, groupLinked w e1 e2 :=
  fun e1 e2 => ⟨thm_F2_senderCollusion hK hG e1, thm_F2_senderCollusion hK hG e2⟩

/-- **F2 (part 2, address-leak phrasing).**  Any holder of the full address
of `w` (the `knowsAddr` fact) obtains the cross-epoch linkage above. -/
theorem thm_F2_addrLeakLinkage {w : WalletId} (hA : Sem (Fact.knowsAddr w)) :
    ∀ e1 e2 : Epoch, groupLinked w e1 e2 :=
  thm_F2_crossEpochLinkage (knowsAddr_ktt hA) (knowsAddr_gr hA)

/-- **F2 / F9 (retroactive full-index readout).**  Combining part 1 with the
server's retained private index: every transaction EVER indexed under the
victim's tag — in any epoch — is read out by whoever holds the address. -/
theorem thm_F2_indexReadout {w : WalletId}
    (hK : Derived (ktt w)) (hG : Derived (gr w)) :
    ∀ (e : Epoch) (tx : TxId), indexHas (TagOf w e) tx → Readout (TagOf w e) tx :=
  fun e tx hIdx =>
    Readout.read (TagOf w e) tx hIdx (thm_F2_senderCollusion hK hG e)

/-! ## F8: `dsk` recovery from a single non-indexed delegation -/

/-- **F8.**  Suppose a server obtains the non-indexed-delegation scalar for
ONE epoch, `x = dsk + PRF^D(K_TT, e)` (hypothesis `hx`), and any past sender
supplies the address, hence `K_TT` (hypothesis `hK`).  Then the server
recovers `dsk` itself, and can compute the epoch detection key of EVERY epoch
`e'` — retroactively and prospectively, with no further action by the victim.
The claim "the new Detection Server is only granted detection authority for a
limited number of epochs" fails. -/
theorem thm_F8_dskRecovery {w : WalletId} {e : Epoch}
    (hx : Derived (EpochDKey w e)) (hK : Derived (ktt w)) :
    Derived (dsk w) ∧ ∀ e' : Epoch, Derived (EpochDKey w e') := by
  have hprf : Derived (Value.vPrfD (ktt w) e) := Derived.prfD (ktt w) e hK
  have hx' : Derived (Value.vAdd (dsk w) (Value.vPrfD (ktt w) e)) := hx
  exact ⟨Derived.cancelL hx' hprf,
    fun e' => Derived.addV (dsk w) (Value.vPrfD (ktt w) e')
      (Derived.cancelL hx' hprf) (Derived.prfD (ktt w) e' hK)⟩

/-! ## F1: diversified-address linkability -/

/-- Linkability of two addresses by a common sender, worst case: the
sender-visible parts coincide, so the two addresses are indistinguishable
and trivially linked. -/
def Linkable (a1 a2 : AddrV) : Prop := a1 = a2

/-- **F1 (naive derivation).**  If `s, r, dsk` are derived from the viewing
key ignoring the diversifier, the sender-visible parts of ANY two
diversified addresses of the same wallet are literally EQUAL — every sender
of both links them; diversifier unlinkability is void. -/
theorem thm_F1_diversifierLink (w : WalletId) (d1 d2 : Diversifier) :
    Linkable (AddrExt w d1) (AddrExt w d2) :=
  rfl

/-- The linkage is not merely propositional: a common sender can DECIDE it
(demonstrated on concrete handles — the ignored diversifier cannot influence
the outcome of the equality test). -/
theorem thm_F1_diversifierLink_decide :
    decide (AddrExt (⟨0⟩ : WalletId) (⟨0⟩ : Diversifier)
          = AddrExt (⟨0⟩ : WalletId) (⟨1⟩ : Diversifier)) = true :=
  rfl

/-- **F1 (fixed derivation, key level).**  With domain-separated
per-diversifier derivation, INJECTIVITY OF THE DERIVATION (`hinj`: distinct
diversifiers yield distinct derived secrets — the symbolic form of PRF domain
separation) implies distinct diversifiers give distinct tagging keys. -/
theorem thm_F1_kttD_distinct {w : WalletId} {d1 d2 : Diversifier}
    (hinj : ∀ (w : WalletId) (d1 d2 : Diversifier), sD w d1 = sD w d2 → d1 = d2)
    (hne : d1 ≠ d2) : kttD w d1 ≠ kttD w d2 := by
  intro h
  have h' : Value.vH (sD w d1) = Value.vH (sD w d2) := h
  injection h' with h2
  exact hne (hinj w d1 d2 h2)

/-- **F1 (fixed derivation, address level).**  Under the same injectivity
hypothesis, distinct diversifiers yield DISTINCT (unlinkable) addresses. -/
theorem thm_F1_diversifiedDistinct {w : WalletId} {d1 d2 : Diversifier}
    (hinj : ∀ (w : WalletId) (d1 d2 : Diversifier), sD w d1 = sD w d2 → d1 = d2)
    (hne : d1 ≠ d2) : AddrExtD w d1 ≠ AddrExtD w d2 := by
  intro h
  have h' : AddrV.mk (kttD w d1) (grD w d1) (dstarD w d1)
          = AddrV.mk (kttD w d2) (grD w d2) (dstarD w d2) := h
  injection h' with hk _hgr _hd
  exact thm_F1_kttD_distinct hinj hne hk

/-! ## F4: the volume/padding trilemma -/

/-- **F4 (leak direction).**  If the observed session volume separates two
received-counts (`vol n1 ≠ vol n2`), the count is RECOVERED from the
observation: there is an explicit recovery function `f` with `f (vol n) = n`
for every `n` in the two-point domain.  (The "constant-bandwidth protocol"
of §7.2 of the article leaks the count unless it also pads the total.) -/
theorem thm_F4_volumeDistinguisher (vol : Nat → Nat) (n1 n2 : Nat)
    (hinj : vol n1 ≠ vol n2) :
    ∃ f : Nat → Nat, ∀ n, (n = n1 ∨ n = n2) → f (vol n) = n := by
  refine ⟨fun v => if v = vol n1 then n1 else n2, fun n hn => ?_⟩
  cases hn with
  | inl h =>
    show (if vol n = vol n1 then n1 else n2) = n
    rw [h]
    exact if_pos rfl
  | inr h =>
    show (if vol n = vol n1 then n1 else n2) = n
    rw [h]
    exact if_neg (fun hh => hinj hh.symm)

/-- **F4 (padding direction).**  If the observation is perfectly
count-independent (the reading of P1 under which "nothing" leaks), then a
wallet that received NOTHING downloads exactly what a wallet that received
`n` transactions downloads — for every `n`.  Perfect privacy forces
worst-case padding, negating the performance goal. -/
theorem thm_F4_padding (vol : Nat → Nat) (hconst : ∀ n m : Nat, vol n = vol m) :
    ∀ n : Nat, vol 0 = vol n :=
  fun n => hconst 0 n

/-- **F4 (trilemma).**  For any volume function and any two distinct counts:
either the observation DISTINGUISHES the two counts (they map to different
volumes AND an explicit recovery function exists), or the two observations
are EQUAL despite the counts differing (the two cases must be padded to the
same, hence worst-case, volume).  There is no third option; headline P1
("the GPA learns nothing about when/how many") forces the second disjunct. -/
theorem thm_F4_trilemma (vol : Nat → Nat) (n1 n2 : Nat) (hne : n1 ≠ n2) :
    (vol n1 ≠ vol n2 ∧ ∃ f : Nat → Nat, ∀ n, (n = n1 ∨ n = n2) → f (vol n) = n)
      ∨ (vol n1 = vol n2 ∧ n1 ≠ n2) := by
  by_cases h : vol n1 = vol n2
  · exact Or.inr ⟨h, hne⟩
  · exact Or.inl ⟨h, thm_F4_volumeDistinguisher vol n1 n2 h⟩

/-! ## F5: live-server cross-epoch linking by network identity -/

/-- **F5.**  If the same network identity (IP) queries the wallet's tag in
two different epochs, a live server concludes both per-epoch detection
groups belong to one wallet: the groups are merged across days, in real
time.  Index-deletion discipline is moot against a live server; only fresh
network identities per epoch (e.g. fresh Tor circuits) would help. -/
theorem thm_F5_ipLink {ip : NetId} {w : WalletId} {e1 e2 : Epoch}
    (h1 : QueriesTag ip w e1) (h2 : QueriesTag ip w e2) :
    ServerLinksEpochs w e1 e2 :=
  ⟨ip, h1, h2⟩

/-- **F5 (server-level merge).**  Same hypotheses, phrased as the merge of
the two per-epoch groups into one cross-day group. -/
theorem thm_F5_liveMerge {ip : NetId} {w : WalletId} {e1 e2 : Epoch}
    (h1 : QueriesTag ip w e1) (h2 : QueriesTag ip w e2) :
    ServerMerges e1 e2 :=
  ⟨w, ip, h1, h2⟩

/-- **F5 (fact vocabulary).**  The same hypotheses realize the
`linksIpWallet` fact of the model. -/
theorem thm_F5_linksIpWallet {ip : NetId} {w : WalletId} {e1 e2 : Epoch}
    (h1 : QueriesTag ip w e1) (h2 : QueriesTag ip w e2) :
    Sem (Fact.linksIpWallet ip w) :=
  ⟨e1, e2, h1, h2⟩

end Zecbreak
