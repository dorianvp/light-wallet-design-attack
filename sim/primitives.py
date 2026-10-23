"""Cryptographic primitives for the executable specification of
"Making Zcash Light Wallets Faster and More Private" (see ../PROTOCOL.md).

Modeling rules (audited in VERIFICATION.md):
  * Group G_1 = G_2 (abstractly distinct in the spec) is instantiated as the
    prime-order-q subgroup of F_p^*, p = 2q+1 safe prime. Scalar mult is
    modexp; point "addition" is multiplication mod p. This preserves every
    algebraic relation the protocol uses (DH, [esk]S_r = [ssk]epk trick,
    D* = D + [f]G_2, scalar subtraction in F8) without external deps.
  * GroupHash is a random oracle into the group (forward direction only:
    there is deliberately NO inversion function -- that is the preimage
    resistance we assume).
  * H / PRF^T / PRF^D are HMAC-SHA256 constructions (collision-resistant /
    pseudorandom by instantiation).
  * Enc is DH-based AEAD. The MAC key is derived from (shared_secret, ad),
    so authentication fails iff ad or shared secret mismatches -- faithful
    to "AEAD authentication fails if ad does not match".
  * Zero-knowledge proofs are idealized: a proof object can only be
    constructed by a party whose vault contains the witness ("knowledge"
    modeling), and verification re-derives the statement from the witness
    ("soundness by construction"). Serialization is via a global unforgeable
    table: a byte string that no honest prover produced deserializes to None.
"""

from __future__ import annotations

import hashlib
import hmac
import random

# ---------------------------------------------------------------------------
# Hashes / PRFs
# ---------------------------------------------------------------------------

def H(data: bytes) -> bytes:
    """H : Bytes -> Bytes (collision-resistant hash)."""
    return hashlib.sha256(b"zecsec/H/" + data).digest()

def PRF_T(key: bytes, data: bytes) -> bytes:
    """PRF^T(key, input) -- tag PRF."""
    return hmac.new(key, b"zecsec/PRF-T/" + data, hashlib.sha256).digest()

def PRF_D(key: bytes, data: bytes) -> bytes:
    """PRF^D(key, input) -- epoch detection blinding PRF."""
    return hmac.new(key, b"zecsec/PRF-D/" + data, hashlib.sha256).digest()

def scalar_from_bytes(b: bytes, q: int) -> int:
    return int.from_bytes(b, "big") % q

def e8(e: int) -> bytes:
    """Canonical epoch encoding used in every AD string (binds epochs)."""
    return int(e).to_bytes(8, "big")

def tag(K_TT: bytes, G_r: int, e: int) -> bytes:
    """T = PRF^T(K_TT, G_r || e) -- PROTOCOL.md section 4 step 3."""
    return PRF_T(K_TT, G_r.to_bytes(34, "big") + e8(e))

# ---------------------------------------------------------------------------
# Group: prime-order subgroup of F_p^*  (P = 2Q+1, Q 256-bit prime)
# ---------------------------------------------------------------------------

Q = 109485823722545393357907885888912041970410104737832648909403976672173932460801
P = 218971647445090786715815771777824083940820209475665297818807953344347864921603
G1 = 4     # generator of the order-Q subgroup  ("G_1" base)
G2 = 64    # independent base ("G_2" base; = [3]G1, still order Q)

assert pow(G1, Q, P) == 1 and pow(G2, Q, P) == 1 and G1 != G2

def smul(k: int, X: int) -> int:
    """[k]X scalar multiplication in the subgroup."""
    return pow(X % P, k % Q, P)

def padd(A: int, B: int) -> int:
    """'Point addition' A + B in multiplicative notation."""
    return (A * B) % P

def GroupHash(r: bytes) -> int:
    """Random-oracle hash into the group. Forward direction only: there is
    intentionally no inverse -- finding r' with GroupHash(r') == X is the
    preimage-resistance assumption (N_f)."""
    t = scalar_from_bytes(H(b"zecsec/GroupHash/" + r), Q)
    return smul(t, G1)

def rand_scalar(rng: random.Random) -> int:
    return rng.randrange(1, Q)

def elem_to_bytes(X: int) -> bytes:
    return (X % P).to_bytes(34, "big")

# ---------------------------------------------------------------------------
# AEAD-style Enc with associated data
# ---------------------------------------------------------------------------

def _keystream(key: bytes, length: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(key + ctr.to_bytes(8, "big")).digest()
        ctr += 1
    return out[:length]

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class EncRecord:
    """A ciphertext of Enc(pk, ptxt, ad, base, esk, epk).

    PUBLIC fields (everything any party can see): epk, ct, mac, and the
    serialized form. PRIVATE fields (leading underscore) are bookkeeping for
    the simulator's introspection; protocol-participant code must never read
    them for another party's ciphertext. They are kept so that verification
    code can confirm algebraic relations (e.g. the decryption trick) without
    trusting the parties.
    """
    __slots__ = ("epk", "ct", "mac", "_ad", "_base", "_esk", "_pk", "_shared")

    def __init__(self, epk: int, ct: bytes, mac: bytes, ad: bytes, base: int,
                 esk: int, pk: int, shared: int):
        self.epk, self.ct, self.mac = epk, ct, mac
        self._ad, self._base, self._esk, self._pk, self._shared = ad, base, esk, pk, shared

    def serialize(self) -> bytes:
        return (b"ENC" + elem_to_bytes(self.epk)
                + len(self.ct).to_bytes(4, "big") + self.ct
                + len(self.mac).to_bytes(2, "big") + self.mac)

    @staticmethod
    def deserialize(blob: bytes) -> "EncRecord":
        assert blob[:3] == b"ENC"
        epk = int.from_bytes(blob[3:37], "big")
        n = int.from_bytes(blob[37:41], "big")
        ct = blob[41:41 + n]
        m = int.from_bytes(blob[41 + n:43 + n], "big")
        mac = blob[43 + n:43 + n + m]
        rec = EncRecord.__new__(EncRecord)
        rec.epk, rec.ct, rec.mac = epk, ct, mac
        rec._ad = rec._base = rec._esk = rec._pk = rec._shared = None
        return rec

def encrypt(pk: int, ptxt: bytes, ad: bytes, base: int, esk: int) -> EncRecord:
    """Sender-side Enc: shared = [esk]pk, epk = [esk]base."""
    shared = smul(esk, pk)
    ms = H(b"zecsec/aead/" + elem_to_bytes(shared) + ad)
    k_enc, k_mac = ms[:16], ms[16:]
    ct = _xor(ptxt, _keystream(k_enc, len(ptxt)))
    mac = hmac.new(k_mac, ct, hashlib.sha256).digest()
    epk = smul(esk, base)
    return EncRecord(epk, ct, mac, ad, base, esk, pk, shared)

def open_ct(rec: EncRecord, shared: int, ad: bytes) -> bytes | None:
    """AEAD-open given the DH shared secret and the RECEIVER'S view of ad.
    Fails (returns None) iff shared secret or ad mismatch. Note the opener
    uses its own ad (derived from context, e.g. the post-mix list's epoch),
    never the sender's private annotation."""
    ms = H(b"zecsec/aead/" + elem_to_bytes(shared % P) + ad)
    k_enc, k_mac = ms[:16], ms[16:]
    if not hmac.compare_digest(hmac.new(k_mac, rec.ct, hashlib.sha256).digest(), rec.mac):
        return None
    return _xor(rec.ct, _keystream(k_enc, len(rec.ct)))

# ---------------------------------------------------------------------------
# Parties + knowledge vaults
# ---------------------------------------------------------------------------

def _canon(v):
    return ("i", v) if isinstance(v, int) and not isinstance(v, bool) else ("b", v)

class KnowledgeError(Exception):
    """Raised when a proof is constructed by a party that does not know the
    witness. This is how the simulator models 'knowledge' soundness."""

class Party:
    """A protocol participant. `vault` holds every secret VALUE the party
    legitimately knows (derived, received, or explicitly disclosed to it by
    a colluding party via learn()). Audit rule: attack code may only call
    learn() at a point where the attack narrative says a disclosure happens."""
    def __init__(self, name: str):
        self.name = name
        self.vault: set = set()

    def learn(self, *vals) -> None:
        for v in vals:
            self.vault.add(_canon(v))

    def knows(self, v) -> bool:
        return _canon(v) in self.vault

    def __repr__(self):
        return f"<{type(self).__name__} {self.name}>"

# ---------------------------------------------------------------------------
# Idealized zero-knowledge proofs
# ---------------------------------------------------------------------------

_PROOF_TABLE: list = []   # index i <=> the only valid serialization of proof i

def _register_proof(proof) -> bytes:
    _PROOF_TABLE.append(proof)
    i = len(_PROOF_TABLE) - 1
    return b"PI" + i.to_bytes(8, "big")

def _lookup_proof(blob: bytes):
    if len(blob) != 10 or blob[:2] != b"PI":
        return None
    i = int.from_bytes(blob[2:], "big")
    return _PROOF_TABLE[i] if 0 <= i < len(_PROOF_TABLE) else None

class ProofPi:
    """pi (sender, in-transaction). Statement (public): (T, epk).
    Witness: (K_TT, G_r, esk) with  T = PRF^T(K_TT, G_r || e)  AND  epk = [esk]G_r
    -- the SAME G_r in both relations (same-base binding, PROTOCOL.md section 2).
    Faithful to the spec as written: e is NOT a public input (F10 wrinkle);
    the verifier binds the proof to the (T, epk) it holds via .T/.epk fields.
    """
    def __init__(self, prover: Party, T: bytes, epk: int, K_TT: bytes, G_r: int,
                 esk: int, e: int):
        if not (prover.knows(K_TT) and prover.knows(G_r) and prover.knows(esk)):
            raise KnowledgeError(
                f"{prover.name} constructed pi without knowing the full witness")
        if T != tag(K_TT, G_r, e) or epk != smul(esk, G_r):
            # Prover-oracle soundness: a proof object can only be minted over a
            # TRUE statement. Adversarial code cannot forge (N_a/N_b): to get
            # pi over (T, epk) it must actually know (K_TT, G_r, esk) that
            # SATISFY both relations, incl. the same-base binding.
            raise KnowledgeError(
                f"{prover.name} tried to mint pi over a FALSE statement")
        self.T, self.epk = T, epk
        self._w = (K_TT, G_r, esk, e)
        self.blob = _register_proof(self)

    def verify(self, T: bytes, epk: int) -> bool:
        K_TT, G_r, esk, e = self._w
        return T == tag(K_TT, G_r, e) and epk == smul(esk, G_r)

    def serialize(self) -> bytes:
        return self.blob

    @staticmethod
    def deserialize(blob: bytes):
        return _lookup_proof(blob)

class ProofPiQuery:
    """pi_query (wallet -> server). Public inputs (e, n, T).
    Witness (s, r): T = PRF^T(H(s), GroupHash(r) || e) -- knowledge of
    PREIMAGES, not of K_TT/G_r (PROTOCOL.md section 2)."""
    def __init__(self, prover: Party, e: int, T: bytes, s: bytes, r: bytes):
        if not (prover.knows(s) and prover.knows(r)):
            raise KnowledgeError(
                f"{prover.name} constructed pi_query without knowing (s, r)")
        if T != tag(H(s), GroupHash(r), e):
            # Prover-oracle soundness: pi_query can only be minted for the tag
            # actually derived from the witness preimages (s, r).
            raise KnowledgeError(
                f"{prover.name} tried to mint pi_query over a FALSE statement")
        self.e, self.T = e, T
        self._w = (s, r)
        self.blob = _register_proof(self)

    def verify(self, e: int, T: bytes) -> bool:
        s, r = self._w
        return e == self.e and T == tag(H(s), GroupHash(r), e)

    def serialize(self) -> bytes:
        return self.blob

    @staticmethod
    def deserialize(blob: bytes):
        return _lookup_proof(blob)

class ProofPiReg:
    """pi_reg (DS -> wallet at registration): S_r = [ssk]GroupHash(r) w.r.t.
    published S = [ssk]G_1."""
    def __init__(self, prover: Party, S: int, S_r: int, G_r: int, ssk: int):
        if not prover.knows(ssk):
            raise KnowledgeError(f"{prover.name} constructed pi_reg without ssk")
        if S_r != smul(ssk, G_r) or S != smul(ssk, G1):
            raise KnowledgeError(
                f"{prover.name} tried to mint pi_reg over a FALSE statement")
        self.S, self.S_r, self.G_r = S, S_r, G_r
        self._ssk = ssk
        self.blob = _register_proof(self)

    def verify(self, S: int, S_r: int, G_r: int) -> bool:
        return (S_r == smul(self._ssk, G_r)) and (S == smul(self._ssk, G1))

    def serialize(self) -> bytes:
        return self.blob

    @staticmethod
    def deserialize(blob: bytes):
        return _lookup_proof(blob)
