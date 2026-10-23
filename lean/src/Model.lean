/-
  Abstract Dolev-Yao-style model of the detection protocol from
  "Making Zcash Light Wallets Faster and More Private"
  (Taylor Hornby, Defuse Security, March 2023).  See ../PROTOCOL.md.

  Conventions
  - Values are symbolic terms (`Value`); cryptographic primitives are opaque
    constructors.  There are NO computation rules that invert H, GroupHash,
    PRF^T, PRF^D, PRF^S or Enc: that structural absence is the symbolic form
    of the ideal-crypto assumptions (hash/PRF/PKE security, key privacy).
  - `Derived v` is the adversary's deductive closure ("can compute v"),
    always relative to knowledge hypotheses supplied by the theorems.
  - The only `axiom`s in the whole development are `piVerified` (an opaque
    verifier interface) and `pi_sound` (the IDEAL-CRYPTO assumption of ZK
    soundness / same-base binding of the sender proof π), both below.
-/

namespace Zecbreak

/-! ## Opaque identifiers -/

structure WalletId where
  val : Nat
  deriving DecidableEq

structure ServerId where
  val : Nat
  deriving DecidableEq

structure TxId where
  val : Nat
  deriving DecidableEq

structure NetId where
  val : Nat
  deriving DecidableEq

structure Diversifier where
  val : Nat
  deriving DecidableEq

/-- Epochs are the protocol's daily time slices, numbered. -/
abbrev Epoch := Nat

/-! ## Symbolic values -/

/-- Symbolic values in the Dolev-Yao term algebra. -/
inductive Value where
  /-- wallet secret `s` (tagging-key preimage), "derived from the viewing key" -/
  | vS (w : WalletId)
  /-- registration secret `r`, sent to the detection server at registration -/
  | vR (w : WalletId)
  /-- detection secret key `dsk` -/
  | vDsk (w : WalletId)
  /-- detection-server secret key `ssk` -/
  | vSsk (a : ServerId)
  /-- mix-authority secret key -/
  | vMix (i : Nat)
  /-- `H(x)`: collision-resistant hash (opaque) -/
  | vH (x : Value)
  /-- `GroupHash(x)`: random-oracle group hash (opaque) -/
  | vGh (x : Value)
  /-- `PRF^T(k, g ∥ e)`: the per-(address, epoch) tag -/
  | vPrfT (k g : Value) (e : Epoch)
  /-- `PRF^D(k, e)`: per-epoch detection blinding -/
  | vPrfD (k : Value) (e : Epoch)
  /-- `PRF^S(k, d)`: domain-separated diversifier derivation -/
  | vPrfS (k : Value) (d : Diversifier)
  /-- scalar addition (free construction; see the cancellation lemmas) -/
  | vAdd (a b : Value)
  /-- `Enc(k, ptxt, ad)`: key-private AEAD (opaque) -/
  | vEnc (k p ad : Value)
  /-- `epk = [esk] b`: ephemeral key over base `b` -/
  | vEpk (esk b : Value)
  /-- associated data `"mix" ∥ e` -/
  | vAdMix (e : Epoch)
  /-- fixed generator of G_2 -/
  | vG2
  deriving DecidableEq

/-! ## Protocol derivations (opaque public functions on values) -/

def ssk (a : ServerId) : Value := .vSsk a
def mixKey (i : Nat) : Value := .vMix i

/-- `K_TT = H(s)` — transaction tagging key (address component). -/
def ktt (w : WalletId) : Value := .vH (.vS w)

/-- `G_r = GroupHash(r)` — registration group element (address component). -/
def gr (w : WalletId) : Value := .vGh (.vR w)

/-- `dsk` — detection secret key. -/
def dsk (w : WalletId) : Value := .vDsk w

/-- `D = [dsk] G_2` — detection public key (address component). -/
def dstar (w : WalletId) : Value := .vEpk (.vDsk w) .vG2

/-- `T = PRF^T(K_TT, G_r ∥ e)` — the tag of `w` for epoch `e`.  Constant per
(address, epoch): every sender to the same address in the same epoch computes
this same tag. -/
def TagOf (w : WalletId) (e : Epoch) : Value := .vPrfT (ktt w) (gr w) e

/-- `x = dsk + PRF^D(K_TT, e)` — the epoch detection scalar delegated to a
server in *non-indexed* detection (§7.3 of the article). -/
def EpochDKey (w : WalletId) (e : Epoch) : Value := .vAdd (dsk w) (.vPrfD (ktt w) e)

/-! ## Diversified derivations -/

/-- Domain-separated derivation of `s` for diversifier `d`. -/
def sD (w : WalletId) (d : Diversifier) : Value := .vPrfS (.vS w) d

def kttD (w : WalletId) (d : Diversifier) : Value := .vH (sD w d)
def grD (w : WalletId) (d : Diversifier) : Value := .vGh (.vPrfS (.vR w) d)
def dstarD (w : WalletId) (d : Diversifier) : Value := .vEpk (.vPrfS (.vDsk w) d) .vG2

/-- Sender-visible part of an address. -/
structure AddrV where
  kttV : Value
  grV : Value
  dstarV : Value
  deriving DecidableEq

/-- Naive derivation from the viewing key that IGNORES the diversifier (F1). -/
def AddrExt (w : WalletId) (_d : Diversifier) : AddrV :=
  ⟨ktt w, gr w, dstar w⟩

/-- Domain-separated per-diversifier derivation (the fixed version). -/
def AddrExtD (w : WalletId) (d : Diversifier) : AddrV :=
  ⟨kttD w d, grD w d, dstarD w d⟩

/-! ## Ciphertexts and associated data -/

/-- `C^PrM_i = Enc(M_i, C^PoM, "mix" ∥ e)`. -/
def preMix (i : Nat) (pom : Value) (e : Epoch) : Value :=
  .vEnc (mixKey i) pom (.vAdMix e)

/-- AEAD acceptance: ciphertext `c` opens under associated data `ad` iff `c`
is an encryption carrying exactly that associated data (the AD check). -/
def decryptsAD (ad : Value) : Value → Prop
  | .vEnc _ _ ad' => ad = ad'
  | _ => False

/-- Stand-in for a post-mix ciphertext: a value deterministically carrying
its tag (only used for the `Fact` vocabulary, never in a theorem). -/
def postMixPayload (T : Value) : Value := .vAdd T (.vH T)

/-- The tag carried by a post-mix payload (definitional left inverse). -/
def payloadTag : Value → Value
  | .vAdd T _ => T
  | v => v

theorem payloadTag_postMix (T : Value) : payloadTag (postMixPayload T) = T := rfl

/-- Handle for a post-mix ciphertext (its tag). -/
structure PostMixId where
  tagV : Value
  deriving DecidableEq

/-- An on-chain transaction; only the first pre-mix layer matters here. -/
structure Tx where
  preMixFirst : Value

/-- A transaction context as processed by a detection server. -/
structure Ctx where
  tx : TxId
  epkV : Value
  epoch : Epoch

/-! ## The sender proof π: abstract verifier + ZK-soundness axiom -/

/-- Opaque verification relation for the sender proof π on public `(T, epk)`
in epoch `e`.  (Interface constant; its only assumed property is `pi_sound`.) -/
axiom piVerified : Value → Value → Epoch → Prop

/-- IDEAL-CRYPTO ASSUMPTION — ZK soundness of π ("same-base binding").

    If π verifies on `(T, epk)` at epoch `e`, then `T` and `epk` were produced
    over the SAME base `b`:  `T = PRF^T(K_TT, b, e)`  and  `epk = [esk] b`.
    Real-world counterpart: SNARK knowledge soundness of the relation
    `T = PRF^T(K_TT, G_r ∥ e) ∧ epk = [esk] G_r`. -/
axiom pi_sound : ∀ (T epk : Value) (e : Epoch), piVerified T epk e →
  ∃ (k esk b : Value), T = Value.vPrfT k b e ∧ epk = Value.vEpk esk b

/-- The base an epk was generated over (symbolically recoverable). -/
def epkBase : Value → Value
  | .vEpk _ b => b
  | v => v

theorem epkBase_epk (esk b : Value) : epkBase (Value.vEpk esk b) = b := rfl

/-- Honest-server indexing rule: index the `C^L` of `ctx` under tag `T` (at
epoch `e`) only after π verifies on `(T, ctx.epk)`. -/
def ServerIndexes (ctx : Ctx) (T : Value) (e : Epoch) : Prop :=
  piVerified T ctx.epkV e

/-- The server's private index maps tag `T` to transaction `tx` iff some
context carrying `tx` was indexed under `T` (at that context's epoch). -/
def indexHas (T : Value) (tx : TxId) : Prop :=
  ∃ ctx : Ctx, ctx.tx = tx ∧ ServerIndexes ctx T ctx.epoch

/-! ## Adversary computation (Dolev-Yao closure) -/

/-- `Derived v`: the adversary can compute the value `v`, given whatever
knowledge the surrounding theorem assumes.

    Deliberately ABSENT (that absence is the ideal-crypto assumption of
    hash/PRF/PKE security in this model): any rule inverting `vH`, `vGh`,
    `vPrfT`, `vPrfD`, `vPrfS`, or opening `vEnc` without its key.
    Present: public evaluation of the primitives, and cancellation of scalar
    addition (sound because scalar subtraction is efficiently computable and
    the solution is unique — see `vAdd_cancel_left/right`). -/
inductive Derived : Value → Prop where
  | hash (x : Value) (h : Derived x) : Derived (.vH x)
  | groupHash (x : Value) (h : Derived x) : Derived (.vGh x)
  | prfT (k g : Value) (e : Epoch) (hk : Derived k) (hg : Derived g) :
      Derived (.vPrfT k g e)
  | prfD (k : Value) (e : Epoch) (hk : Derived k) : Derived (.vPrfD k e)
  | prfS (k : Value) (d : Diversifier) (hk : Derived k) : Derived (.vPrfS k d)
  | addV (a b : Value) (ha : Derived a) (hb : Derived b) : Derived (.vAdd a b)
  /-- Left-cancellation: `a = (a + b) − b`; sound because the solution of
      `c + b = sum` is unique (`vAdd_cancel_left`). -/
  | cancelL {a b : Value} (hsum : Derived (.vAdd a b)) (hb : Derived b) : Derived a
  /-- Right-cancellation: `b = (a + b) − a`; see `vAdd_cancel_right`. -/
  | cancelR {a b : Value} (hsum : Derived (.vAdd a b)) (ha : Derived a) : Derived b
  | enc (k p ad : Value) (hk : Derived k) (hp : Derived p) (had : Derived ad) :
      Derived (.vEnc k p ad)
  | epk (esk b : Value) (he : Derived esk) (hb : Derived b) : Derived (.vEpk esk b)

/-! ## Algebra of the free addition construction -/

/-- Cancellation lemma (left summand).  Addition is a free binary constructor,
so the equation `c + a = c + b` has the unique solution `a = b`; this is what
makes the adversary's `Derived.cancelL` rule sound. -/
theorem vAdd_cancel_left {c a b : Value} (h : Value.vAdd c a = Value.vAdd c b) :
    a = b :=
  (Value.vAdd.inj h).2

/-- Cancellation lemma (right summand). -/
theorem vAdd_cancel_right {c a b : Value} (h : Value.vAdd a c = Value.vAdd b c) :
    a = b :=
  (Value.vAdd.inj h).1

/-- Tags are as injective as their inputs: the tags of two (wallet, epoch)
pairs coincide only in the trivial case. -/
theorem tag_eq {w1 w2 : WalletId} {e1 e2 : Epoch} (h : TagOf w1 e1 = TagOf w2 e2) :
    w1 = w2 ∧ e1 = e2 := by
  have h' : Value.vPrfT (ktt w1) (gr w1) e1 = Value.vPrfT (ktt w2) (gr w2) e2 := h
  injection h' with hk _hg he
  have hk' : Value.vH (Value.vS w1) = Value.vH (Value.vS w2) := hk
  injection hk' with hk1
  injection hk1 with hk2
  exact ⟨hk2, he⟩

theorem tag_epoch_inj {w : WalletId} {e1 e2 : Epoch} (h : TagOf w e1 = TagOf w e2) :
    e1 = e2 :=
  (tag_eq h).2

/-! ## Observation and linkage vocabulary -/

/-- `QueriesTag ip w e`: the wallet/owner `w` produced a valid π_query from
network identity `ip` for the tag `TagOf w e` of epoch `e`.  That valid
queries are always tied to an honest (wallet, tag) pair is the π_query
knowledge-soundness idealization; the fact itself is raw server-side
observation. -/
inductive QueriesTag : NetId → WalletId → Epoch → Prop where
  | mk (ip : NetId) (w : WalletId) (e : Epoch) : QueriesTag ip w e

/-- Cross-epoch linkage of one wallet: both epoch tags are computable by the
same adversary (e.g. any single past sender, or the server after one address
leak). -/
def groupLinked (w : WalletId) (e1 e2 : Epoch) : Prop :=
  Derived (TagOf w e1) ∧ Derived (TagOf w e2)

/-- Live-server conclusion: one network identity queried `w`'s tag in both
epochs, so the server merges the two per-day groups. -/
def ServerLinksEpochs (w : WalletId) (e1 e2 : Epoch) : Prop :=
  ∃ ip : NetId, QueriesTag ip w e1 ∧ QueriesTag ip w e2

/-- Server-level merge of two per-epoch detection groups. -/
def ServerMerges (e1 e2 : Epoch) : Prop :=
  ∃ (w : WalletId) (ip : NetId), QueriesTag ip w e1 ∧ QueriesTag ip w e2

/-- Vocabulary of adversary knowledge and linkage observations. -/
inductive Fact where
  /-- the adversary holds the full address of `w` (as any sender does) -/
  | knowsAddr (w : WalletId)
  | knowsKTT (w : WalletId)
  | knowsGr (w : WalletId)
  | knowsSsk (a : ServerId)
  | knowsMixKey (i : Nat)
  | knowsTag (w : WalletId) (e : Epoch)
  | knowsDsk (w : WalletId)
  /-- the server's private index maps `T` to `tx` -/
  | knowsIndexEntry (T : Value) (tx : TxId)
  /-- the adversary can connect on-chain pre-mix `tx` to post-mix `pom` -/
  | linksPrePost (tx : Tx) (pom : PostMixId)
  /-- two post-mix ciphertexts belong to one wallet -/
  | sameWalletGroup (pom1 pom2 : PostMixId)
  /-- network identity `ip` queries on behalf of wallet `w` -/
  | linksIpWallet (ip : NetId) (w : WalletId)
  /-- the adversary observes session volume `vol` for wallet `w` -/
  | observesVolume (w : WalletId) (vol : Nat)

/-- Reading a transaction out of the (retained) server index: the tag is
computable by the adversary AND the index maps it. -/
inductive Readout : Value → TxId → Prop where
  | read (T : Value) (tx : TxId) (hIdx : indexHas T tx) (hD : Derived T) :
      Readout T tx

/-- Semantics of the knowledge/linkage facts. -/
def Sem : Fact → Prop
  | .knowsAddr w => Derived (ktt w) ∧ Derived (gr w) ∧ Derived (dstar w)
  | .knowsKTT w => Derived (ktt w)
  | .knowsGr w => Derived (gr w)
  | .knowsSsk a => Derived (ssk a)
  | .knowsMixKey i => Derived (mixKey i)
  | .knowsTag w e => Derived (TagOf w e)
  | .knowsDsk w => Derived (dsk w)
  | .knowsIndexEntry T tx => indexHas T tx
  | .linksPrePost tx pom =>
      ∃ (i : Nat) (e : Epoch),
        tx.preMixFirst = Value.vEnc (mixKey i) (postMixPayload pom.tagV) (Value.vAdMix e)
          ∧ Derived (mixKey i)
  | .sameWalletGroup pom1 pom2 =>
      ∃ (w : WalletId) (e1 e2 : Epoch), pom1.tagV = TagOf w e1 ∧ pom2.tagV = TagOf w e2
  | .linksIpWallet ip w => ∃ (e1 e2 : Epoch), QueriesTag ip w e1 ∧ QueriesTag ip w e2
  -- observesVolume is reserved vocabulary: session-volume analysis is
  -- thm_F4_* in Breaks.lean, where the volume function is a parameter.
  | .observesVolume _ _ => True

theorem knowsAddr_ktt {w : WalletId} (h : Sem (Fact.knowsAddr w)) : Derived (ktt w) :=
  h.1

theorem knowsAddr_gr {w : WalletId} (h : Sem (Fact.knowsAddr w)) : Derived (gr w) :=
  h.2.1

end Zecbreak
