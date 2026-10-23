"""Executable honest protocol flows (PROTOCOL.md sections 3-7).

Every function here is the HONEST reading of the spec; attacks live in
attacks.py and operate only by choosing inputs / colluding parties, never by
re-implementing a weakened pipeline. Fidelity-critical points, marked with
[FIDELITY] comments:

  * pi verification at the DS binds the proof to the (T, epk) of the C^T it
    opened, and pi itself binds tag-base == epk-base (same G_r in both
    relations) -- this is what N_a exercises.
  * All AD strings embed the epoch canonically ("tct"||e, "dct"||e, "mix"||e);
    the DS uses the POST-MIX LIST's epoch for AD, never a sender-claimed one.
  * Mixing decrypts pre-mix ciphertexts FIRST, then dedups on the canonical
    serialization of the decoded POST-MIX ciphertext (not on the pre-mix
    wrappers, which differ under re-encryption) -- this is what N_d exercises.
  * C^L uses no epoch in its AD (spec gives it none); the defense against
    replayed C^L is the note-commitment membership check in the CLAIMED
    epoch's tree -- this is what N_g exercises.
"""

from __future__ import annotations

import random
from collections import defaultdict

from primitives import (EncRecord, G1, G2, GroupHash, H, KnowledgeError, Party,
                        PRF_D, ProofPi, ProofPiQuery, ProofPiReg, Q, e8,
                        elem_to_bytes, encrypt, open_ct, padd, rand_scalar,
                        scalar_from_bytes, smul, tag)

# ---------------------------------------------------------------------------
# Notes, transactions, chain
# ---------------------------------------------------------------------------

class Note:
    __slots__ = ("recipient_note_pk", "value", "rho")

    def __init__(self, recipient_note_pk: int, value: int, rho: bytes):
        self.recipient_note_pk = recipient_note_pk
        self.value = value
        self.rho = rho

    def serialize(self) -> bytes:
        return (elem_to_bytes(self.recipient_note_pk)
                + self.value.to_bytes(8, "big") + self.rho)

    def cm(self) -> bytes:
        return H(b"zecsec/cm/" + self.serialize())

    @staticmethod
    def deserialize(b: bytes) -> "Note":
        return Note(int.from_bytes(b[:34], "big"),
                    int.from_bytes(b[34:42], "big"), b[42:])

class Tx:
    __slots__ = ("txid", "epoch", "C", "pre_mix", "cm")

    def __init__(self, txid: str, epoch: int, C: EncRecord,
                 pre_mix: dict, cm: bytes):
        self.txid, self.epoch, self.C, self.pre_mix, self.cm = txid, epoch, C, pre_mix, cm

class Chain:
    """Holds on-chain transactions and per-epoch note-commitment trees.
    Abstracts the Merkle tree as a per-epoch committed set (the set itself is
    authenticated by consensus); membership check == authenticated proof."""

    def __init__(self):
        self.txs: list[Tx] = []
        self.trees: dict[int, dict[bytes, str]] = {}   # epoch -> {cm: txid}

    def add_tx(self, epoch: int, C: EncRecord, pre_mix: dict, cm: bytes) -> Tx:
        txid = f"tx{len(self.txs):04d}"
        tx = Tx(txid, epoch, C, pre_mix, cm)
        self.txs.append(tx)
        self.trees.setdefault(epoch, {})[cm] = txid
        return tx

    def txs_of(self, epoch: int) -> list[Tx]:
        return [t for t in self.txs if t.epoch == epoch]

# ---------------------------------------------------------------------------
# Post-mix ciphertext container + canonical serialization
# ---------------------------------------------------------------------------

class PoM:
    """C^PoM = (C^T, C^D, C^L)."""
    __slots__ = ("C_T", "C_D", "C_L")

    def __init__(self, C_T: EncRecord, C_D: EncRecord, C_L: EncRecord):
        self.C_T, self.C_D, self.C_L = C_T, C_D, C_L

    def serialize(self) -> bytes:
        return (b"POM" + self.C_T.serialize() + self.C_D.serialize()
                + self.C_L.serialize())

    @staticmethod
    def deserialize(blob: bytes) -> "PoM":
        assert blob[:3] == b"POM"
        i = 3
        recs = []
        while i < len(blob):
            assert blob[i:i + 3] == b"ENC"
            epk_len = 34
            ct_len = int.from_bytes(blob[i + 3 + epk_len: i + 7 + epk_len], "big")
            mac_off = i + 7 + epk_len + ct_len
            mac_len = int.from_bytes(blob[mac_off:mac_off + 2], "big")
            end = mac_off + 2 + mac_len
            recs.append(EncRecord.deserialize(blob[i:end]))
            i = end
        assert len(recs) == 3
        return PoM(*recs)

# ---------------------------------------------------------------------------
# Mix Authority (PROTOCOL.md section 5)
# ---------------------------------------------------------------------------

class MixAuthority(Party):
    def __init__(self, idx: int, rng: random.Random, inject_poms: list | None = None,
                 censor: int = 0):
        super().__init__(f"MA{idx}")
        self.idx = idx
        self.sk = rand_scalar(rng)
        self.pk = smul(self.sk, G1)
        self.learn(self.sk)
        self.lists: dict[int, list[PoM]] = {}
        self._decode_maps: dict[int, dict[bytes, str]] = {}   # epoch -> {pom_bytes: txid}
        # [F7b] adversarial configuration: inject crafted post-mix entries
        # into the signed list, and/or censor (omit) real ones.
        self.inject_poms = inject_poms or []
        self.censor = censor
        self.last_stats: dict[str, int] = {}

    def mix(self, chain: Chain, e: int, dedup: bool = True,
            bind_epoch_ad: bool = True):
        """Collect this authority's C^PrM for epoch e, decrypt with AD
        "mix"||e, publish the sorted, DEDUPLICATED post-mix list.

        [FIDELITY] Dedup operates on the canonical bytes of the DECODED
        post-mix ciphertext (post-decryption), never on the pre-mix wrapper
        (which is freshly randomized per encryption)."""
        ad = b"mix" + e8(e) if bind_epoch_ad else b"mix"
        decoded: list[tuple[bytes, str]] = []
        for tx in chain.txs_of(e):
            rec = tx.pre_mix[self.idx]
            pt = open_ct(rec, smul(self.sk, rec.epk), ad)
            if pt is None:
                continue          # cross-epoch replay / wrong AD -> rejected
            decoded.append((pt, tx.txid))
        uniq_bytes = sorted({b for b, _ in decoded}) if dedup else sorted(b for b, _ in decoded)
        poms = [PoM.deserialize(b) for b in uniq_bytes]
        # [F7b] malicious authority modifies its OWN signed publication:
        if self.censor:
            poms = poms[:max(0, len(poms) - self.censor)]
        if self.inject_poms:
            poms = poms + list(self.inject_poms)
        self.lists[e] = poms
        self._decode_maps[e] = {b: txid for b, txid in decoded}
        self.last_stats = {"submitted": len(chain.txs_of(e)),
                           "decoded": len(decoded),
                           "published": len(self.lists[e])}
        return self.lists[e]

    def sign_list(self, e: int) -> bytes:
        """'Signature' over the canonical list bytes (abstracts the MA's
        publish-and-sign step; unforgeable by construction)."""
        blob = b"".join(p.serialize() for p in self.lists[e])
        return H(b"sig/" + self.name.encode() + e8(e) + blob)

    def reveal_pre_post_map(self, e: int) -> dict[int, str]:
        """COLLUSION ONLY (F2/F3): the authority's work product links each
        post-mix entry to the on-chain tx it came from."""
        out = {}
        for i, pom in enumerate(self.lists[e]):
            txid = self._decode_maps[e].get(pom.serialize())
            if txid is not None:
                out[i] = txid
        return out

# ---------------------------------------------------------------------------
# Detection Server (PROTOCOL.md sections 3, 6, 7)
# ---------------------------------------------------------------------------

class DetectionServer(Party):
    def __init__(self, name: str, rng: random.Random, withhold: int = 0,
                 inject_c_l: list | None = None, retain_lists: bool = False,
                 record_handovers: bool = False):
        super().__init__(name)
        self.ssk = rand_scalar(rng)
        self.S = smul(self.ssk, G1)
        self.learn(self.ssk)
        self._rng = rng
        self.users: list[bytes] = []                    # registered r values
        self.reglog: list[tuple[str, bytes, int]] = []  # (ip, r, G_r)  [F3]
        self.index: dict[tuple[int, bytes], list[EncRecord]] = {}  # (e,T) -> [C^L]
        self._nonces: set[bytes] = set()
        self.query_log: list[tuple[str, int, bytes]] = []   # (ip, e, T)  [F5]
        # ---- adversarial / retention configuration (documented deviations) ----
        self.withhold = withhold          # [F7a] malicious: drop N C^L from replies
        self.inject_c_l = inject_c_l or []  # [F7b] malicious: append fake C^L to replies
        self.retain_lists = retain_lists  # [F8] keep post-mix lists beyond the epoch
        self.record_handovers = record_handovers  # [F8] keep non-indexed scalars
        self.archived_lists: dict[int, list[PoM]] = {}
        self.handovers: list[tuple[int, int]] = []   # (e, x) [F8 retroactive variant]

    def issue_nonce(self) -> bytes:
        """Fresh query nonce for a wallet (section 7 step 2)."""
        while True:
            n = self._rng.randbytes(16)
            if n not in self._nonces:
                return n

    def purge(self, e: int) -> None:
        """[F3/F9] Footnote-1 deletion discipline: destroy epoch-e state.
        Behavioral defense only -- and it breaks late wallet queries."""
        self.index = {k: v for k, v in self.index.items() if k[0] != e}
        self.archived_lists.pop(e, None)

    # ---- registration (section 3) ----
    def register(self, wallet: Party, r: bytes, ip: str) -> tuple[int, int, ProofPiReg]:
        """Wallet sends r; server returns (G_r, S_r, pi_reg). Server thereby
        learns (ip, r) -- recorded in reglog (this is in-spec, section 3b)."""
        G_r = GroupHash(r)
        S_r = smul(self.ssk, G_r)
        proof = ProofPiReg(self, self.S, S_r, G_r, self.ssk)
        self.users.append(r)
        self.reglog.append((ip, r, G_r))
        wallet.learn(G_r, S_r)
        return G_r, S_r, proof

    # ---- indexing (section 6) ----
    def process_epoch(self, e: int, postmix_list: list[PoM],
                      verify_pi: bool = True) -> None:
        """For each post-mix entry: decryption trick [ssk]epk, AEAD-open C^T
        with AD "tct"||e where e is the LIST's epoch [FIDELITY: never a
        sender-claimed epoch], then verify pi bound to the opened (T, epk),
        then index C^L under T."""
        for pom in postmix_list:
            rec = pom.C_T
            pt = open_ct(rec, smul(self.ssk, rec.epk), b"tct" + e8(e))
            if pt is None:
                continue            # not addressed to any of this server's S_r
            T, proof_blob = pt[:32], pt[32:]
            proof = ProofPi.deserialize(proof_blob)
            if verify_pi:
                if proof is None or proof.T != T or proof.epk != rec.epk \
                        or not proof.verify(T, rec.epk):
                    continue
            self.index.setdefault((e, T), []).append(pom.C_L)
        if self.retain_lists:
            self.archived_lists[e] = postmix_list

    # ---- indexed query path (section 7 step 2) ----
    def query_indexed(self, wallet: Party, e: int, T: bytes, nonce: bytes,
                      proof: ProofPiQuery | None, ip: str,
                      require_proof: bool = True) -> list[EncRecord] | None:
        """Wallet presents (e, n, T, pi_query); server checks nonce freshness
        + proof, returns the C^L bucket. Records (ip, e, T) -- in-spec
        behavior of any network server [F5]."""
        self.query_log.append((ip, e, T))
        if nonce in self._nonces:
            return None
        self._nonces.add(nonce)
        if require_proof:
            if proof is None or not proof.verify(e, T):
                return None
        bucket = list(self.index.get((e, T), []))
        # [F7a/F7b] malicious-server output manipulation (configuration):
        if self.withhold and len(bucket) > self.withhold:
            bucket = bucket[:len(bucket) - self.withhold]
        if self.inject_c_l:
            bucket = bucket + list(self.inject_c_l)
        return bucket

    # ---- non-indexed fallback (section 7 step 3) ----
    def nonindexed_scan(self, e: int, x_scalar: int,
                        postmix_list: list[PoM]) -> list[EncRecord]:
        """Wallet hands over scalar x = dsk + PRF^D(K_TT, e) and e; server
        trial-decrypts every C^D of the epoch with [x]epk."""
        if self.record_handovers:            # [F8] retained delegation scalar
            self.handovers.append((e, x_scalar))
        out = []
        for pom in postmix_list:
            rec = pom.C_D
            if open_ct(rec, smul(x_scalar, rec.epk), b"dct" + e8(e)) is not None:
                out.append(pom.C_L)
        return out

# ---------------------------------------------------------------------------
# Wallet (PROTOCOL.md sections 3, 7)
# ---------------------------------------------------------------------------

class Wallet(Party):
    def __init__(self, name: str, rng: random.Random, ip: str):
        super().__init__(name)
        self.vk = rng.randbytes(32)
        self.note_sk = rand_scalar(rng)
        self.note_pk = smul(self.note_sk, G1)
        self.rho_ctr = 0
        self.ip = ip
        self.learn(self.vk, self.note_sk)
        self.addresses: dict[bytes, dict] = {}   # diversifier -> material

    def _derive_secrets(self, diversifier: bytes, mode: str) -> tuple[bytes, bytes, int]:
        """[FIDELITY] The article says only 'derives secrets s, r, dsk from
        their viewing key' -- derivation unspecified (F1/F6 material).
        mode 'naive'  : ignores the diversifier, no domain separation choices.
        mode 'fixed'  : per-diversifier domain-separated (F1 fix; default).
        mode 's_eq_r' : naive AND s := r (F6 K_TT catastrophe).
        mode 'ivk'    : s = r = dsk = ivk -- the fully naive derivation the
                        article permits (F6 full catastrophe: registration
                        hands the server K_TT *and* dsk)."""
        if mode == "naive":
            s = H(self.vk + b"|s|")
            r = H(self.vk + b"|r|")
            dsk = scalar_from_bytes(H(self.vk + b"|dsk|"), Q)
        elif mode == "fixed":
            s = H(self.vk + b"|s|" + diversifier)
            r = H(self.vk + b"|r|" + diversifier)
            dsk = scalar_from_bytes(H(self.vk + b"|dsk|" + diversifier), Q)
        elif mode == "s_eq_r":
            r = H(self.vk + b"|r|")
            s = r
            dsk = scalar_from_bytes(H(self.vk + b"|dsk|"), Q)
        elif mode == "ivk":
            s = self.vk
            r = self.vk
            dsk = scalar_from_bytes(self.vk, Q)
        else:
            raise ValueError(mode)
        return s, r, dsk

    def register_address(self, diversifier: bytes, server: DetectionServer,
                         mode: str = "fixed") -> dict:
        s, r, dsk = self._derive_secrets(diversifier, mode)
        K_TT = H(s)
        G_r, S_r, proof = server.register(self, r, self.ip)
        assert proof.verify(server.S, S_r, G_r), "pi_reg must verify"
        D = smul(dsk, G2)
        self.learn(s, r, dsk, K_TT)
        mat = dict(div=diversifier, s=s, r=r, dsk=dsk, K_TT=K_TT, G_r=G_r,
                   S_r=S_r, D=D, server=server)
        self.addresses[diversifier] = mat
        return mat

    # ---- receiving (section 7) ----
    def receive_bucket(self, e: int, c_l_list: list[EncRecord], chain: Chain,
                       authenticate: bool = True) -> tuple[list[Note], int]:
        """Decrypt each returned C^L with the note key, then AUTHENTICATE by
        recomputing the commitment and checking membership in the CLAIMED
        epoch's tree. Returns (accepted_notes, discarded_count)."""
        accepted, discarded = [], 0
        for rec in c_l_list:
            pt = open_ct(rec, smul(self.note_sk, rec.epk), b"lct")
            if pt is None:
                discarded += 1
                continue
            note = Note.deserialize(pt)
            if authenticate:
                if note.cm() not in chain.trees.get(e, {}):
                    discarded += 1
                    continue
            accepted.append(note)
        return accepted, discarded

    def query_tag(self, e: int, mat: dict, nonce: bytes,
                  require_proof: bool = True) -> list[EncRecord] | None:
        """Indexed detection: (e, n, T_e, pi_query) over the wallet's own
        knowledge."""
        T = tag(mat["K_TT"], mat["G_r"], e)
        proof = ProofPiQuery(self, e, T, mat["s"], mat["r"])
        return mat["server"].query_indexed(self, e, T, nonce, proof,
                                           self.ip, require_proof)

    def delegate_scalar(self, mat: dict, e: int) -> int:
        """Non-indexed fallback scalar x = dsk + PRF^D(K_TT, e)."""
        f = scalar_from_bytes(PRF_D(mat["K_TT"], e8(e)), Q)
        return (mat["dsk"] + f) % Q

    def trial_decrypt(self, chain: Chain) -> list[tuple[int, str, Note]]:
        """Full trial-decryption rescan of every on-chain C with the viewing
        key (section 7 step 1) -- the expensive fallback path."""
        out = []
        for tx in chain.txs:
            pt = open_ct(tx.C, smul(self.note_sk, tx.C.epk),
                         b"nct" + e8(tx.epoch))
            if pt is not None:
                out.append((tx.epoch, tx.txid, Note.deserialize(pt)))
        return out

# ---------------------------------------------------------------------------
# Sending (PROTOCOL.md section 4)
# ---------------------------------------------------------------------------

class Sender(Party):
    """Any wallet constructing a transaction to some address. Learns the
    full address tuple by necessity (F2's structural observation)."""

    def __init__(self, name: str, rng: random.Random):
        super().__init__(name)
        self.rng = rng
        self.payment_addr: bytes = rng.randbytes(32)
        self.last_pom_bytes: bytes | None = None

    def learn_address(self, mat: dict) -> None:
        """Receiving an address == learning (G_r, S_r, K_TT, D) in full."""
        self.learn(mat["G_r"], mat["S_r"], mat["K_TT"], mat["D"])

    def send(self, mat: dict, e: int, chain: Chain, mas: list[MixAuthority],
             value: int = 1, note_pk_of_receiver: int | None = None,
             epoch_free_mix_ad: bool = False) -> Tx:
        """Honest send flow. note_pk_of_receiver: in the real protocol the
        payment address 'addr' carries the note public key implicitly; the
        detection extension does NOT add it, so senders know G_r,S_r,K_TT,D
        plus the opaque payment address. We pass the receiver's note_pk only
        through the opaque payment-address channel (modeled honestly here:
        the sender must be able to encrypt C and C^L -- that is what 'addr'
        is for -- but never learns secrets).
        epoch_free_mix_ad: NEGATIVE-CONTROL-ONLY flag modeling the protocol
        variant without the epoch in the "mix" AD (used by N_c's control)."""
        assert note_pk_of_receiver is not None
        K_TT, G_r, S_r, D = mat["K_TT"], mat["G_r"], mat["S_r"], mat["D"]
        rng = self.rng

        esk_T = rand_scalar(rng)
        self.learn(esk_T)                                     # own ephemeral key
        epk_T = smul(esk_T, G_r)                              # step 2
        T = tag(K_TT, G_r, e)                                 # step 3
        proof = ProofPi(self, T, epk_T, K_TT, G_r, esk_T, e)  # step 4 (same-base)
        C_T = encrypt(S_r, T + proof.serialize(), b"tct" + e8(e), G_r, esk_T)  # step 5

        f = scalar_from_bytes(PRF_D(K_TT, e8(e)), Q)
        D_star = padd(D, smul(f, G2))                         # step 6
        esk_D = rand_scalar(rng)
        C_D = encrypt(D_star, b"true", b"dct" + e8(e), G2, esk_D)              # step 7

        rho = rng.randbytes(16)
        note = Note(note_pk_of_receiver, value, rho)
        esk_L = rand_scalar(rng)                              # fresh key (step 1)
        C_L = encrypt(note_pk_of_receiver, note.serialize(), b"lct", G1, esk_L)
        C = encrypt(note_pk_of_receiver, note.serialize(), b"nct" + e8(e),
                    G1, rand_scalar(rng))

        pom = PoM(C_T, C_D, C_L)                              # step 8
        pom_bytes = pom.serialize()
        mix_ad = b"mix" if epoch_free_mix_ad else b"mix" + e8(e)
        pre_mix = {ma.idx: encrypt(ma.pk, pom_bytes, mix_ad, G1,
                                   rand_scalar(rng))
                   for ma in mas}                             # step 9
        return chain.add_tx(e, C, pre_mix, note.cm())

# ---------------------------------------------------------------------------
# World plumbing
# ---------------------------------------------------------------------------

def run_epoch(chain: Chain, mas: list[MixAuthority], servers: list[DetectionServer],
              e: int, dedup: bool = True, bind_epoch_ad: bool = True,
              verify_pi: bool = True) -> None:
    """End-of-epoch pipeline: every MA mixes; every DS fetches MA0's signed
    list and indexes it."""
    for ma in mas:
        ma.mix(chain, e, dedup=dedup, bind_epoch_ad=bind_epoch_ad)
    for ds in servers:
        ds.process_epoch(e, mas[0].lists[e], verify_pi=verify_pi)

def ground_truth(chain: Chain, wallet: Wallet) -> dict[int, list[str]]:
    """Which on-chain txs actually carry notes for wallet (oracle for
    verdicts only; no party can call this)."""
    out: dict[int, list[str]] = {}
    for tx in chain.txs:
        pt = open_ct(tx.C, smul(wallet.note_sk, tx.C.epk), b"nct" + e8(tx.epoch))
        if pt is not None:
            out.setdefault(tx.epoch, []).append(tx.txid)
    return out
