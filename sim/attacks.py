"""Attack and non-break scenarios (IDs match ../FINDINGS.md).

Anti-rigging discipline (see VERIFICATION.md):
  * Every "BLOCKED" verdict for N_a..N_g comes with a NEGATIVE CONTROL: the
    same attack re-run with exactly one mechanism disabled, which then
    SUCCEEDS. A blocked verdict without a successful control would be
    suspect of being an artifact of the simulation.
  * Attack code never touches private `_`-fields of other parties' records
    and never calls the ground-truth oracle for anything but verdict checks.
  * Every disclosure of secrets is an explicit `learn()` call at the point
    the attack narrative says a party colludes/discloses.
"""

from __future__ import annotations

import hashlib
import random

from primitives import (G1, G2, GroupHash, H, KnowledgeError, Party, PRF_D,
                        ProofPi, ProofPiQuery, Q, e8, encrypt, elem_to_bytes,
                        open_ct, padd, rand_scalar, scalar_from_bytes, smul,
                        tag)
from protocol import (Chain, DetectionServer, MixAuthority, Note, PoM,
                      Sender, Wallet, ground_truth, run_epoch)

PACKET_BYTES = 256          # A_F4: fixed-size packet
PACKET_INTERVAL_S = 1       # A_F4: fixed rate


def _R(seed: str) -> random.Random:
    return random.Random("zecsec/" + seed)


def _result(sid, target, verdict, mechanism, control="", notes=""):
    return dict(id=sid, target=target, verdict=verdict, mechanism=mechanism,
                control=control, notes=notes)


# ===========================================================================
# Attacks (expected: BREAK)
# ===========================================================================

def A_F1():
    """F1: diversified addresses of one wallet are sender-linkable when the
    derivation of (s, r, dsk) ignores the diversifier ('naive' reading of
    'derives secrets from the viewing key')."""
    rng = _R("A_F1")
    ds = DetectionServer("DS_A", rng)
    ds_b = DetectionServer("DS_B", rng)
    w = Wallet("V", rng, ip="10.0.0.9")

    m1 = w.register_address(b"div-1", ds, mode="naive")
    m2 = w.register_address(b"div-2", ds, mode="naive")
    t1 = (m1["G_r"], m1["S_r"], m1["K_TT"], m1["D"])
    t2 = (m2["G_r"], m2["S_r"], m2["K_TT"], m2["D"])
    naive_linked = t1 == t2

    # Redundancy corollary: r1 registered at DS_A, r2 at DS_B, same vk.
    mb = w.register_address(b"div-1", ds_b, mode="naive")
    redundancy_linked = (mb["K_TT"], mb["D"]) == (m1["K_TT"], m1["D"])

    # Fix: per-diversifier domain-separated derivation.
    s1, r1_, dsk1 = w._derive_secrets(b"div-1", "fixed")
    s2, r2_, dsk2 = w._derive_secrets(b"div-2", "fixed")
    fixed_linked = (GroupHash(r1_), H(s1), smul(dsk1, G2)) == \
                   (GroupHash(r2_), H(s2), smul(dsk2, G2))

    verdict = "BREAK" if naive_linked else "NO_BREAK"
    return _result(
        "A_F1", "diversifier unlinkability (implicit P0)", verdict,
        "plain tuple equality: naive derivation => identical (G_r,S_r,K_TT,D) "
        "on every diversified address"
        + (" and identical (K_TT,D) across redundancy servers" if redundancy_linked else ""),
        control=f"per-diversifier derivation => tuples equal? {fixed_linked} "
                "(fix blocks the link)",
        notes=f"naive_linked={naive_linked} redundancy_linked={redundancy_linked} "
              f"fixed_linked={fixed_linked}")


def A_F2():
    """F2: one colluding past sender + the victim's DS (+ one MA for exact
    on-chain attribution) equals the P5 'both servers compromised' outcome,
    with zero key compromises."""
    rng = _R("A_F2")
    chain = Chain()
    mas = [MixAuthority(i, rng) for i in range(2)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    W1 = Wallet("W1", rng, ip="10.0.0.10")
    W2 = Wallet("W2", rng, ip="10.0.0.11")
    S1 = Sender("S1-colluding", rng)     # colluding counterparty
    S2 = Sender("S2", rng)
    S3 = Sender("S3", rng)
    S4 = Sender("S4", rng)

    vm = V.register_address(b"divA", ds0, mode="naive")
    w1m = W1.register_address(b"divA", ds0, mode="naive")
    w2m = W2.register_address(b"divA", ds0, mode="naive")
    S1.learn_address(vm); S2.learn_address(vm); S3.learn_address(w1m)
    S4.learn_address(w2m)

    S1.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    S1.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    S3.send(w1m, 1, chain, mas, note_pk_of_receiver=W1.note_pk)
    run_epoch(chain, mas, [ds0], 1)
    S1.send(vm, 2, chain, mas, note_pk_of_receiver=V.note_pk)
    S2.send(vm, 2, chain, mas, note_pk_of_receiver=V.note_pk)   # honest 2nd sender
    S4.send(w2m, 2, chain, mas, note_pk_of_receiver=W2.note_pk)
    run_epoch(chain, mas, [ds0], 2)

    gt = ground_truth(chain, V)

    # --- attack: S1 discloses the address it necessarily holds ---
    ds0.learn(vm["K_TT"], vm["G_r"])           # [collusion point]
    counts, attributed = {}, {}
    for e in (1, 2):
        T_e = tag(vm["K_TT"], vm["G_r"], e)
        bucket = ds0.index.get((e, T_e), [])
        counts[e] = len(bucket)
        # exact attribution with one MA's work product
        txids = set()
        for c_l in bucket:
            for idx, pom in enumerate(mas[0].lists[e]):
                if pom.C_L.serialize() == c_l.serialize():
                    txids.add(mas[0].reveal_pre_post_map(e).get(idx))
        attributed[e] = sorted(t for t in txids if t)

    ok_counts = counts == {e: len(v) for e, v in gt.items()}
    ok_attr = attributed == {e: sorted(v) for e, v in gt.items()}

    # --- contrast: MA alone learns nothing about V (no tags, no index) ---
    # The MA's view: pre-mix ctots of every tx + its decode map. Without a
    # tag there is nothing to select V's entries with.
    ma_alone_possible = mas[0].knows(vm["K_TT"]) or mas[0].knows(vm["G_r"])

    verdict = "BREAK" if (ok_counts and ok_attr) else "NO_BREAK"
    return _result(
        "A_F2", "P3/P5 framing (attribution needs 'both servers compromised')",
        verdict,
        "address necessarily held by every sender => DS derives all T_e from "
        "disclosed (K_TT,G_r); its own index gives counts; + one MA work "
        "product gives exact tx attribution. No key compromise.",
        control=f"MA alone attributes? {ma_alone_possible} (MA knows no tag "
                "material: P4 holds); DS alone (no disclosure) sees only "
                "anonymous buckets: P3's count clause holds",
        notes=f"counts_ok={ok_counts} attribution_ok={ok_attr} "
              f"recovered={attributed} truth={ {e: sorted(v) for e, v in gt.items()} }")


def A_F3():
    """F3/F9: no forward secrecy of K_TT. A LATER single address leak +
    retained (in-spec functional) index retroactively links all past daily
    groups. Also the stronger variant: even a deletion-disciplined server is
    re-indexable from public post-mix lists once its ssk leaks."""
    rng = _R("A_F3")
    chain = Chain()
    mas = [MixAuthority(i, rng) for i in range(2)]
    ds0 = DetectionServer("DS_A-retains", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    W = Wallet("W", rng, ip="10.0.0.10")
    S1 = Sender("S1", rng)
    Sc = Sender("Sc", rng)

    vm = V.register_address(b"divA", ds0, mode="naive")
    wm = W.register_address(b"divA", ds0, mode="naive")
    S1.learn_address(vm); Sc.learn_address(wm)

    for e, n_v, n_w in ((1, 1, 2), (2, 3, 1), (3, 2, 2)):
        for _ in range(n_v):
            S1.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)
        for _ in range(n_w):
            Sc.send(wm, e, chain, mas, note_pk_of_receiver=W.note_pk)
        run_epoch(chain, mas, [ds0], e)

    gt = ground_truth(chain, V)

    # --- variant (a): address leaks after epoch 3; DS retained its index ---
    ds0.learn(vm["K_TT"], vm["G_r"])           # [disclosure point: one past sender]
    retro = {}
    for e in (1, 2, 3):
        T_e = tag(vm["K_TT"], vm["G_r"], e)
        retro[e] = len(ds0.index.get((e, T_e), []))
    a_ok = retro == {e: len(v) for e, v in gt.items()}
    # identity tie-back via registration log (in-spec: server saw (ip,r,G_r))
    ip_leak = next((ip for ip, r, G_r in ds0.reglog if G_r == vm["G_r"]), None)

    # --- variant (b): disciplined server deleted index+logs at epoch close;
    # later FULL state leak (ssk) + the same address leak => rebuild index
    # from PUBLIC signed post-mix lists. ---
    ds_leaked = DetectionServer("DS_A-stateleak", rng)
    ds_leaked.ssk = ds0.ssk                    # [state-leak point]
    ds_leaked.learn(ds0.ssk)
    rebuilt = {}
    for e in (1, 2, 3):
        ds_leaked.process_epoch(e, mas[0].lists[e])
        T_e = tag(vm["K_TT"], vm["G_r"], e)
        rebuilt[e] = len(ds_leaked.index.get((e, T_e), []))
    b_ok = rebuilt == retro and a_ok

    verdict = "BREAK" if (a_ok and b_ok) else "NO_BREAK"
    return _result(
        "A_F3", "P6 ('cannot connect the groups from different days')", verdict,
        "K_TT is epoch-independent: one later address leak => T_e for every "
        "past epoch => retained (or rebuilt-from-public-lists) index readout "
        "links all daily groups",
        control="deletion discipline does NOT help if ssk ever leaks: public "
                "post-mix lists + ssk re-create the whole index",
        notes=f"retro_counts_ok={a_ok} rebuilt_after_state_leak_ok={b_ok} "
              f"retro={retro} truth={ {e: len(v) for e, v in gt.items()} } "
              f"reglog_ip_tieback={ip_leak}")


def A_F4():
    """F4: retrieval volume/duration is proportional to notes received, so a
    passive observer of the (fixed-rate, fixed-size-packet) session learns
    'how many' -- P1 as stated is unachievable without worst-case padding."""
    rng = _R("A_F4")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V1 = Wallet("V1-1note", rng, ip="10.0.0.9")
    V2 = Wallet("V2-20notes", rng, ip="10.0.0.10")
    S = Sender("S", rng)
    m1 = V1.register_address(b"d", ds0, mode="naive")
    m2 = V2.register_address(b"d", ds0, mode="naive")
    S.learn_address(m1); S.learn_address(m2)
    S.send(m1, 1, chain, mas, note_pk_of_receiver=V1.note_pk)
    for _ in range(20):
        S.send(m2, 1, chain, mas, note_pk_of_receiver=V2.note_pk)
    run_epoch(chain, mas, [ds0], 1)

    def session(bucket):
        nbytes = sum(len(c.serialize()) for c in bucket)
        packets = max(1, -(-nbytes // PACKET_BYTES))
        return packets, packets * PACKET_INTERVAL_S

    b1 = V1.query_tag(1, m1, b"nonce1")
    b2 = V2.query_tag(1, m2, b"nonce2")
    s1, s2 = session(b1), session(b2)
    distinguishable = s1 != s2

    # padded variant: server pads every bucket to the epoch max BUCKET size
    worst = max((sum(len(c.serialize()) for c in bucket)
                 for bucket in ds0.index.values()), default=0)
    def padded_session(_bucket):
        packets = -(-worst // PACKET_BYTES)
        return packets, packets * PACKET_INTERVAL_S
    p1, p2 = padded_session(b1), padded_session(b2)
    padded_equal = p1 == p2
    overhead = p1[0] / s1[0]

    verdict = "BREAK" if distinguishable else "NO_BREAK"
    return _result(
        "A_F4", "P1 (GPA learns nothing about when/how many)", verdict,
        "response volume = ceil(notes * |C^L| / packet) packets at fixed rate "
        "=> session length/duration reveals the note count",
        control=f"pad-to-max makes profiles equal ({p1} == {p2}) at "
                f"{overhead:.0f}x download overhead for the 1-note wallet "
                "(the author's own trilemma)",
        notes=f"V1 session={s1} V2 session={s2} distinguishable={distinguishable}")


def A_F5():
    """F5: a live DS links a wallet's daily groups by network identity: the
    wallet itself queries all past epochs from the same IP/session."""
    rng = _R("A_F5")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A-live", rng)
    V = Wallet("V", rng, ip="93.184.216.34")
    S = Sender("S", rng)
    vm = V.register_address(b"d", ds0, mode="naive")
    S.learn_address(vm)
    for e in (1, 2, 3):
        S.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)
        run_epoch(chain, mas, [ds0], e)

    # sync: wallet queries every past epoch -- in-spec wallet behavior
    for e in (1, 2, 3):
        assert V.query_tag(e, vm, f"n{e}".encode()) is not None

    by_ip = {}
    for ip, e, T in ds0.query_log:
        by_ip.setdefault(ip, set()).add((e, T))
    groups = by_ip.get(V.ip, set())
    linked = {e for e, T in groups}
    ok = linked == {1, 2, 3}

    # mitigation demo: fresh circuit per lookup
    ds_tor = DetectionServer("DS_A-tor", rng)
    for e in (1, 2, 3):
        T = tag(vm["K_TT"], vm["G_r"], e)
        pr = ProofPiQuery(V, e, T, vm["s"], vm["r"])
        ds_tor.query_indexed(V, e, T, f"t{e}".encode(), pr, ip=f"exit-{e}")
    tor_groups = _group(ds_tor.query_log)
    tor_linkable = any(len(v) > 1 for v in tor_groups.values())

    verdict = "BREAK" if ok else "NO_BREAK"
    return _result(
        "A_F5", "P6 delegation clause (live-server reading)", verdict,
        "wallet queries each past epoch's tag from the same IP during sync; "
        "the live DS groups them by network identity -- no address needed",
        control=f"fresh circuit per lookup defeats IP grouping "
                f"(linkable={tor_linkable}); GPA timing correlation remains "
                "(out of simulation scope)",
        notes=f"ip_groups={sorted(groups)} truth=epochs 1..3")


def _group(query_log):
    out = {}
    for ip, e, T in query_log:
        out.setdefault(ip, set()).add((e, T))
    return out


def A_F6():
    """F6: 'derives s, r, dsk from the viewing key' is under-specified. In
    the s := r instantiation, registration (which sends r to the server)
    hands the server K_TT = H(s) = H(r): all tags, forever, no collusion."""
    rng = _R("A_F6")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V-badderive", rng, ip="10.0.0.9")
    S = Sender("S", rng)

    vm = V.register_address(b"d", ds0, mode="s_eq_r")
    S.learn_address(vm)
    for e in (1, 2):
        S.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)
        run_epoch(chain, mas, [ds0], e)

    # server-side: r was received at registration (in-spec); s = r
    r_received = ds0.users[0]
    K_TT_guess = H(r_received)
    tags_match = all(
        tag(K_TT_guess, vm["G_r"], e) == tag(vm["K_TT"], vm["G_r"], e)
        for e in (1, 2, 3, 10))
    bucket_ok = all(
        len(ds0.index.get((e, tag(K_TT_guess, vm["G_r"], e)), [])) ==
        len(ground_truth(chain, V).get(e, []))
        for e in (1, 2))

    # control: domain-separated derivation blocks it
    V2 = Wallet("V-goodderive", rng, ip="10.0.0.8")
    vm2 = V2.register_address(b"d", ds0, mode="naive")   # s != r, but both from vk
    r2 = ds0.users[1]
    sep_blocked = H(r2) != vm2["K_TT"] and not ds0.knows(vm2["s"])

    verdict = "BREAK" if (tags_match and bucket_ok) else "NO_BREAK"
    return _result(
        "A_F6", "granular delegation / basic privacy (spec under-specification)",
        verdict,
        "s := r (no domain separation): registration transmits r => server "
        "computes K_TT = H(r) => every epoch's tag from the registration log "
        "alone",
        control=f"domain-separated derivation: H(r) != K_TT and s unknown to "
                f"server => blocked={sep_blocked}",
        notes=f"tags_match={tags_match} buckets_readable={bucket_ok}")


def A_F7a():
    """F7a: malicious DS withholds C^L. Returned notes authenticate, so the
    loss is silent until a full rescan (no fraud-proof mechanism in spec)."""
    rng = _R("A_F7a")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A-withhold", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    S = Sender("S", rng)
    vm = V.register_address(b"d", ds0, mode="naive")
    S.learn_address(vm)
    for _ in range(3):
        S.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    run_epoch(chain, mas, [ds0], 1)

    T = tag(vm["K_TT"], vm["G_r"], 1)
    full = ds0.index[(1, T)]
    withheld = full[:-1]                                  # [malice point]
    ds0.index[(1, T)] = withheld
    bucket = V.query_tag(1, vm, b"n1")
    accepted, discarded = V.receive_bucket(1, bucket, chain)
    gt = ground_truth(chain, V)

    silent = (len(accepted) == 2 and discarded == 0
              and all(n.cm() in chain.trees[1] for n in accepted))
    rescan_finds = len(gt[1]) == 3

    verdict = "BREAK" if (silent and len(accepted) < len(gt[1])) else "NO_BREAK"
    return _result(
        "A_F7a", "P10 completeness/liveness", verdict,
        "server returns a subset; everything returned authenticates, so the "
        "wallet cannot detect the omission locally; only a full trial-"
        "decryption rescan recovers the missing note",
        control=f"full rescan recovers {len(gt[1])} notes (rescan_finds="
                f"{rescan_finds}) -- exactly the cost the protocol exists to "
                "avoid",
        notes=f"received={len(accepted)} truth={len(gt[1])} "
              f"all_returned_authenticate={silent}")


def A_F7b():
    """F7b: count pollution. Anyone holding the address (any past sender)
    can inject C^PoM carrying the victim's epoch tag with a garbage C^L;
    the victim discards it at authentication but its per-tag bucket (the
    count the DS observes, P3's 'how many') is inflated for free."""
    rng = _R("A_F7b")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    Att = Sender("Attacker-knows-address", rng)

    vm = V.register_address(b"d", ds0, mode="naive")
    Att.learn_address(vm)
    Att.learn(V.note_pk)                       # payment address channel
    e = 2
    S0 = Sender("S0", rng)
    S0.learn_address(vm)
    S0.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)   # 1 real note

    # attacker injects its forged pre-mix DURING the same epoch (mixing
    # happens end-of-epoch), so the single honest pipeline run below indexes
    # both the real and the forged entry exactly once.
    T = tag(vm["K_TT"], vm["G_r"], e)
    esk = rand_scalar(rng)
    Att.learn(esk)                            # attacker knows its own esk
    epk = smul(esk, vm["G_r"])
    proof = ProofPi(Att, T, epk, vm["K_TT"], vm["G_r"], esk, e)   # VALID: Att
    #  holds the address (it is a legitimate sender) -- pi does not block this.
    C_T = encrypt(vm["S_r"], T + proof.serialize(), b"tct" + e8(e), vm["G_r"], esk)
    f = scalar_from_bytes(PRF_D(vm["K_TT"], e8(e)), Q)
    D_star = padd(vm["D"], smul(f, G2))            # public formula from address
    C_D = encrypt(D_star, b"true", b"dct" + e8(e), G2, rand_scalar(rng))
    fake_note = Note(V.note_pk, 10**9, b"garbage-rho")     # unbacked note
    C_L = encrypt(V.note_pk, fake_note.serialize(), b"lct", G1, rand_scalar(rng))
    pom = PoM(C_T, C_D, C_L)
    pre_mix = {ma.idx: encrypt(ma.pk, pom.serialize(), b"mix" + e8(e), G1,
                               rand_scalar(rng)) for ma in mas}
    chain.add_tx(e, encrypt(V.note_pk, b"", b"nct" + e8(e), G1, rand_scalar(rng)),
                 pre_mix, H(b"garbage-cm"))        # fee-only tx, no real note
    run_epoch(chain, mas, [ds0], e)

    bucket = ds0.index[(e, T)]
    polluted_count = len(bucket)                   # 2 observed vs 1 true
    wallet_bucket = V.query_tag(e, vm, b"n2")
    accepted, discarded = V.receive_bucket(e, wallet_bucket, chain)

    ok = polluted_count == 2 and len(accepted) == 1 and discarded == 1
    verdict = "BREAK" if ok else "NO_BREAK"
    return _result(
        "A_F7b", "P3 count integrity ('how many') / count pollution", verdict,
        "forged C^PoM with the victim's tag (computable from the address, "
        "with a VALID pi) inflates the per-tag bucket at zero on-chain cost; "
        "wallet discards the note but the DS-observed count is polluted",
        control="victim's accepted notes unaffected (cross-ref N_g: "
                "commitment authentication discards the garbage)",
        notes=f"observed_count={polluted_count} true=1 accepted={len(accepted)} "
              f"discarded={discarded}")


def A_F8():
    """F8: dsk recovery. Non-indexed delegation hands a server the scalar
    x = dsk + PRF^D(K_TT, e). One colluding sender (or any later address
    leak) lets the server subtract f back out and detect every epoch, past
    and future, with zero further queries."""
    rng = _R("A_F8")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A-down", rng)
    ds1 = DetectionServer("DS_B-delegate", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    S1 = Sender("S1-colluding", rng)

    vm = V.register_address(b"d", ds0, mode="naive")
    S1.learn_address(vm)
    for e in (1, 2, 3):
        S1.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)
        run_epoch(chain, mas, [ds0, ds1], e)

    gt = ground_truth(chain, V)

    # victim's server down => non-indexed fallback for epoch 2 only
    x = V.delegate_scalar(vm, 2)                # wallet hands over the scalar
    ds1.learn(x)                                # [delegation point: in-spec]
    got = ds1.nonindexed_scan(2, x, mas[0].lists[2])
    service_works = len(got) == len(gt[2])

    # later: one counterparty discloses the address to DS_B
    ds1.learn(vm["K_TT"], vm["G_r"], vm["D"])   # [collusion point]
    f2 = scalar_from_bytes(PRF_D(vm["K_TT"], e8(2)), Q)
    dsk_rec = (x - f2) % Q
    key_recovered = dsk_rec == vm["dsk"] and smul(dsk_rec, G2) == vm["D"]

    # silent all-epoch detection with zero further queries by V
    detected = {}
    for e in (1, 2, 3):
        x_e = (dsk_rec + scalar_from_bytes(PRF_D(vm["K_TT"], e8(e)), Q)) % Q
        detected[e] = len(ds1.nonindexed_scan(e, x_e, mas[0].lists[e]))

    # prospective: a future epoch the victim never touches again
    S1.send(vm, 4, chain, mas, note_pk_of_receiver=V.note_pk)
    run_epoch(chain, mas, [ds0, ds1], 4)
    x4 = (dsk_rec + scalar_from_bytes(PRF_D(vm["K_TT"], e8(4)), Q)) % Q
    detected[4] = len(ds1.nonindexed_scan(4, x4, mas[0].lists[4]))

    gt = ground_truth(chain, V)   # recomputed: now includes epoch 4
    all_ok = key_recovered and all(
        detected[e] == len(gt.get(e, [])) for e in detected)

    verdict = "BREAK" if all_ok else "NO_BREAK"
    return _result(
        "A_F8", "P6 ('only granted detection authority for a limited number "
                "of epochs')", verdict,
        "x_e - PRF^D(K_TT,e) = dsk (linear scalar cancellation); from dsk "
        "the delegate derives every epoch's key and silently trial-decrypts "
        "all C^D forever",
        control="delegation itself functions correctly (service_works="
                f"{service_works}); the break needs only ONE counterparty or "
                "address leak at any later time",
        notes=f"dsk_recovered={key_recovered} detected={detected} "
              f"truth={ {e: len(v) for e, v in gt.items()} }")


# ===========================================================================
# Non-breaks (expected: BLOCKED, with negative control)
# ===========================================================================

def N_a():
    """Case (a) identification oracle: plant a ciphertext in the VICTIM's
    tag bucket while encrypting C^T to the ATTACKER's own S_r*. Blocked by
    pi's same-base binding (tag base == epk base)."""
    rng = _R("N_a")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    Att = Wallet("Att", rng, ip="10.0.0.66")      # attacker registered at same DS
    S_oracle = Sender("S", rng)

    vm = V.register_address(b"d", ds0, mode="naive")
    am = Att.register_address(b"d", ds0, mode="naive")
    Att.learn(vm["G_r"], vm["S_r"], vm["K_TT"], vm["D"])   # knows victim's address

    e = 1
    T_v = tag(vm["K_TT"], vm["G_r"], e)

    # --- with pi: try every witness the attacker legitimately knows ---
    esk_a = rand_scalar(rng)
    Att.learn(esk_a)                          # attacker knows its own esk
    epk_own_base = smul(esk_a, am["G_r"])
    # witness over victim base => tag matches, epk does not:
    p1 = ProofPi(Att, T_v, smul(esk_a, vm["G_r"]), vm["K_TT"], vm["G_r"], esk_a, e)
    p1_passes_for_own_epk = p1.verify(T_v, epk_own_base)
    # witness over own base => epk matches, tag does not:
    T_own = tag(vm["K_TT"], am["G_r"], e)
    p2 = ProofPi(Att, T_own, epk_own_base, vm["K_TT"], am["G_r"], esk_a, e)
    p2_tag_is_victim = p2.T == T_v
    no_witness = (not p1_passes_for_own_epk) and (not p2_tag_is_victim)

    # attacker sends the best it can (own-S_r ciphertext + victim tag, junk proof)
    C_T = encrypt(am["S_r"], T_v + b"x" * 10, b"tct" + e8(e), am["G_r"], esk_a)
    C_D = encrypt(smul(rand_scalar(rng), G2), b"true", b"dct" + e8(e), G2,
                  rand_scalar(rng))
    marker = encrypt(Att.note_pk, Note(Att.note_pk, 1, b"m").serialize(),
                     b"lct", G1, rand_scalar(rng))
    pom = PoM(C_T, C_D, marker)
    pre_mix = {ma.idx: encrypt(ma.pk, pom.serialize(), b"mix" + e8(e), G1,
                               rand_scalar(rng)) for ma in mas}
    chain.add_tx(e, encrypt(Att.note_pk, b"", b"nct" + e8(e), G1, rand_scalar(rng)),
                 pre_mix, H(b"attacker-cm"))
    run_epoch(chain, mas, [ds0], 1, verify_pi=True)
    planted_with_pi = marker.serialize() in \
        [c.serialize() for c in ds0.index.get((e, T_v), [])]

    # --- negative control: pi disabled => the oracle works ---
    chain2 = Chain()
    ds1 = DetectionServer("DS_A-nopi", rng)
    mas2 = [MixAuthority(0, rng)]
    vm2 = V.register_address(b"d2", ds1, mode="naive")
    am2 = Att.register_address(b"d2c", ds1, mode="naive")   # attacker MUST be
    #  registered at THIS world's server, else its ciphertext is unopenable
    #  there and the control would be rigged.
    Att.learn(vm2["G_r"], vm2["S_r"], vm2["K_TT"], vm2["D"])
    T_v2 = tag(vm2["K_TT"], vm2["G_r"], 1)
    esk_c = rand_scalar(rng)
    Att.learn(esk_c)
    C_T2 = encrypt(am2["S_r"], T_v2 + b"x" * 10, b"tct" + e8(1), am2["G_r"],
                   esk_c)
    marker2 = encrypt(Att.note_pk, Note(Att.note_pk, 1, b"m").serialize(),
                      b"lct", G1, rand_scalar(rng))
    pom2 = PoM(C_T2,
               encrypt(smul(rand_scalar(rng), G2), b"true", b"dct" + e8(1), G2,
                       rand_scalar(rng)),
               marker2)
    chain2.add_tx(1, encrypt(Att.note_pk, b"", b"nct" + e8(1), G1, rand_scalar(rng)),
                  {ma.idx: encrypt(ma.pk, pom2.serialize(), b"mix" + e8(1), G1,
                                   rand_scalar(rng)) for ma in mas2},
                  H(b"attacker-cm2"))
    run_epoch(chain2, mas2, [ds1], 1, verify_pi=False)
    planted_no_pi = marker2.serialize() in \
        [c.serialize() for c in ds1.index.get((1, T_v2), [])]

    blocked = no_witness and not planted_with_pi
    return _result(
        "N_a", "P8 case (a): sender->server identification oracle", 
        "BLOCKED" if blocked else "BROKEN",
        "pi binds the tag's G_r to the epk's base: openability at the "
        "attacker's own S_r* forces epk-base = G_r*, so the tag must use "
        "G_r* too and can never be the victim's",
        control=f"pi disabled => attacker plants into victim bucket: "
                f"{planted_no_pi} (oracle works); valid-witness check: "
                f"no_witness={no_witness} -- note the attacker CAN construct "
                "valid pi (it holds the address); it just cannot satisfy both "
                "relations on different bases",
        notes=f"planted_with_pi={planted_with_pi} planted_without_pi={planted_no_pi}")


def N_b():
    """Case (b): a sender holding the address cannot QUERY the victim's tag:
    pi_query demands preimages (s, r), not (K_TT, G_r)."""
    rng = _R("N_b")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    Att = Sender("Att-sender", rng)
    vm = V.register_address(b"d", ds0, mode="naive")
    Att.learn_address(vm)
    S = Sender("S", rng)
    S.learn_address(vm)
    S.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    run_epoch(chain, mas, [ds0], 1)

    T_v = tag(vm["K_TT"], vm["G_r"], 1)
    proof = None
    try:
        proof = ProofPiQuery(Att, 1, T_v, vm["s"], vm["r"])
    except KnowledgeError:
        pass                                   # attacker lacks preimages
    forged = None
    try:
        forged = ProofPiQuery(Att, 1, T_v, b"fake-s", b"fake-r")
        forged_ok = forged.verify(1, T_v)
    except KnowledgeError:
        forged_ok = False
    resp = ds0.query_indexed(Att, 1, T_v, b"n1", proof, ip="10.0.0.66",
                             require_proof=True)
    blocked = proof is None and not forged_ok and resp is None

    # negative control: pi_query disabled
    ds0._nonces.clear()
    resp_nopf = ds0.query_indexed(Att, 1, T_v, b"n2", None, ip="10.0.0.66",
                                  require_proof=False)
    control_ok = resp_nopf is not None and len(resp_nopf) == 1

    return _result(
        "N_b", "P8 case (b): querying another wallet's tag", 
        "BLOCKED" if blocked else "BROKEN",
        "pi_query proves knowledge of (s, r) with GroupHash(r) = G_r and "
        "H(s) = K_TT: preimage resistance means address holders (who only "
        "have K_TT, G_r) cannot construct it",
        control=f"pi_query disabled => bucket returned to attacker: "
                f"{control_ok}",
        notes=f"proof_constructed={proof is not None} forged_verifies="
              f"{forged_ok} query_rejected={resp is None}")


def N_c():
    """Cross-epoch pre-mix replay is blocked by AD 'mix'||e."""
    rng = _R("N_c")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    S = Sender("S", rng)
    vm = V.register_address(b"d", ds0, mode="naive")
    S.learn_address(vm)
    tx1 = S.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    run_epoch(chain, mas, [ds0], 1)
    captured = tx1.pre_mix[0]                  # public on-chain bytes

    # replay: attacker embeds the SAME pre-mix ciphertext in an epoch-2 tx
    chain.add_tx(2, encrypt(V.note_pk, b"", b"nct" + e8(2), G1, rand_scalar(rng)),
                 {0: captured}, H(b"replay-cm"))
    mas[0].mix(chain, 2, bind_epoch_ad=True)
    pom1_bytes = PoM.deserialize(
        open_ct(captured, smul(mas[0].sk, captured.epk), b"mix" + e8(1))
    ).serialize()
    list2 = [p.serialize() for p in mas[0].lists[2]]
    blocked = pom1_bytes not in list2

    # negative control: the protocol VARIANT without the epoch in the "mix"
    # AD (senders AND authority both epoch-free) -- replay then succeeds.
    chain3 = Chain()
    ds3 = DetectionServer("DS_A-noad", rng)
    mas3 = [MixAuthority(0, rng)]
    V3 = Wallet("V3", rng, ip="10.0.0.9")
    S3 = Sender("S3", rng)
    vm3 = V3.register_address(b"d", ds3, mode="naive")
    S3.learn_address(vm3)
    tx3 = S3.send(vm3, 1, chain3, mas3, note_pk_of_receiver=V3.note_pk,
                  epoch_free_mix_ad=True)      # variant: AD = b"mix" only
    mas3[0].mix(chain3, 1, bind_epoch_ad=False)
    captured3 = tx3.pre_mix[0]
    pom3_bytes = PoM.deserialize(
        open_ct(captured3, smul(mas3[0].sk, captured3.epk), b"mix")).serialize()
    chain3.add_tx(2, encrypt(V3.note_pk, b"", b"nct" + e8(2), G1,
                             rand_scalar(rng)), {0: captured3}, H(b"replay-cm3"))
    mas3[0].mix(chain3, 2, bind_epoch_ad=False)
    list3b = [p.serialize() for p in mas3[0].lists[2]]
    control_ok = pom3_bytes in list3b

    return _result(
        "N_c", "cross-epoch replay of pre-mix ciphertexts",
        "BLOCKED" if blocked else "BROKEN",
        "the MA opens epoch-2 pre-mix entries with AD 'mix'||2; the replayed "
        "ciphertext was authenticated under 'mix'||1 => AEAD open fails => "
        "the entry never reaches the epoch-2 post-mix list",
        control=f"epoch-free-AD protocol variant => replayed entry appears "
                f"in epoch-2 list: {control_ok}",
        notes=f"in_list_with_ad={pom1_bytes in list2} "
              f"in_list_without_ad_variant={control_ok}")


def N_d():
    """Repetition tagging (same C^PoM re-encrypted k times) is collapsed by
    dedup on the DECODED post-mix ciphertext."""
    rng = _R("N_d")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    Att = Sender("Att", rng)
    vm = V.register_address(b"d", ds0, mode="naive")
    Att.learn_address(vm)
    S = Sender("S", rng)
    S.learn_address(vm)
    S.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    run_epoch(chain, mas, [ds0], 1)
    target_pom = mas[0].lists[1][0].serialize()   # attacker's own tx below

    # attacker's own pom to track:
    esk = rand_scalar(rng)
    Att.learn(esk)                            # attacker knows its own esk
    att_note_pk = smul(rand_scalar(rng), G1)  # attacker's own opaque target
    e = 1
    T_a = tag(vm["K_TT"], vm["G_r"], e)  # any tag; multiplicity is the point
    epk = smul(esk, vm["G_r"])
    proof = ProofPi(Att, T_a, epk, vm["K_TT"], vm["G_r"], esk, e)
    C_T = encrypt(vm["S_r"], T_a + proof.serialize(), b"tct" + e8(e), vm["G_r"], esk)
    C_D = encrypt(padd(vm["D"], smul(scalar_from_bytes(PRF_D(vm["K_TT"], e8(e)), Q), G2)),
                  b"true", b"dct" + e8(e), G2, rand_scalar(rng))
    C_L = encrypt(att_note_pk, Note(att_note_pk, 1, b"x").serialize(), b"lct",
                  G1, rand_scalar(rng))
    pom_bytes = PoM(C_T, C_D, C_L).serialize()

    k = 5
    for i in range(k):                          # fresh re-encryption each time
        pre = {ma.idx: encrypt(ma.pk, pom_bytes, b"mix" + e8(e), G1,
                               rand_scalar(rng)) for ma in mas}
        chain.add_tx(e, encrypt(att_note_pk, b"", b"nct" + e8(e), G1,
                                rand_scalar(rng)), pre, H(b"dup-cm-%d" % i))
    mas[0].mix(chain, 1, dedup=True)
    mult_dedup = [p.serialize() for p in mas[0].lists[1]].count(pom_bytes)
    blocked = mult_dedup == 1

    mas[0].mix(chain, 1, dedup=False)           # negative control
    mult_nodedup = [p.serialize() for p in mas[0].lists[1]].count(pom_bytes)
    control_ok = mult_nodedup == k

    return _result(
        "N_d", "tagging by repetition via duplicate pre-mix entries",
        "BLOCKED" if blocked else "BROKEN",
        "the MA decrypts every pre-mix entry FIRST and dedups on the "
        "canonical post-mix bytes; k re-encryptions of the same C^PoM "
        "decode to the same bytes => one output entry",
        control=f"dedup disabled => multiplicity {mult_nodedup} == k "
                f"(={k}): {control_ok}",
        notes=f"multiplicity_with_dedup={mult_dedup} "
              f"multiplicity_without={mult_nodedup}")


def N_e():
    """No base-equality test for epks: the decryption trick's anonymity.
    Exact enumeration on a toy group shows P[epk | base] is uniform and
    independent of the base, so no test distinguishes bases."""
    # toy group: order-53 subgroup of F_107^*
    p_t, q_t = 107, 53
    g_t = pow(2, 2, p_t)                    # 4 has order 53 mod 107
    assert pow(g_t, q_t, p_t) == 1

    def smul_t(k, X): return pow(X % p_t, k % q_t, p_t)
    elems = {smul_t(k, g_t) for k in range(q_t)}
    assert len(elems) == q_t

    h_t = smul_t(7, g_t)                    # a second, independent base
    dist_g, dist_h = {}, {}
    for esk in range(q_t):
        dist_g[smul_t(esk, g_t)] = dist_g.get(smul_t(esk, g_t), 0) + 1
        dist_h[smul_t(esk, h_t)] = dist_h.get(smul_t(esk, h_t), 0) + 1
    uniform = {x: 1 for x in elems}
    identical = dist_g == dist_h == uniform

    # [ssk]epk is a bijection applied to a uniform value => still uniform
    ssk_t = 11
    dist_shared = {}
    for esk in range(q_t):
        v = smul_t(ssk_t, smul_t(esk, g_t))
        dist_shared[v] = dist_shared.get(v, 0) + 1
    shared_uniform = dist_shared == uniform

    # 'shares my base' is degenerate: every element is a multiple of every base
    a, b = smul_t(13, g_t), smul_t(29, h_t)
    degenerate = any(smul_t(x, g_t) == a for x in range(q_t)) and \
                 any(smul_t(x, g_t) == b for x in range(q_t))

    blocked = identical and shared_uniform and degenerate
    return _result(
        "N_e", "anonymity of the S_r decryption trick (no base test)",
        "BLOCKED" if blocked else "BROKEN",
        "with uniform esk, epk is exactly uniform over the whole (prime-"
        "order) group for EVERY base, and [ssk]epk is a bijection of it: "
        "the joint distribution carries zero base information (exact "
        "enumeration on a 53-element group)",
        control="no toggle exists: this is information-theoretic given "
                "uniform esk; the only failure mode would be biased esk "
                "generation, which is an implementation bug, not a protocol "
                "mechanism",
        notes=f"dists_identical_and_uniform={identical} "
              f"shared_uniform={shared_uniform} predicate_degenerate={degenerate}")


def N_f():
    """Rogue registration (find r' with GroupHash(r') = victim's G_r) is
    blocked by GroupHash preimage resistance."""
    rng = _R("N_f")
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    vm = V.register_address(b"d", ds0, mode="naive")
    G_target = vm["G_r"]

    hits = sum(1 for i in range(20000)
               if GroupHash(b"rogue-%d" % i) == G_target)

    # scaling check on a toy group (order 53): RO hits at rate 1/|G|
    p_t, q_t = 107, 53
    g_t = pow(2, 2, p_t)
    def gh_t(r: bytes):
        t = int.from_bytes(hashlib.sha256(r).digest(), "big") % q_t
        return pow(g_t, t, p_t)
    target_t = gh_t(b"victim")
    toy_hits = sum(1 for i in range(5300) if gh_t(b"rogue-%d" % i) == target_t)
    toy_rate = toy_hits / 5300

    blocked = hits == 0
    return _result(
        "N_f", "rogue-r registration", 
        "BLOCKED" if blocked else "BROKEN",
        "GroupHash is a random oracle; without an inversion function the "
        "attacker's hit probability is attempts/|G| ~ 20000/2^256",
        control=f"toy order-53 group: empirical hit rate {toy_rate:.3f} ~= "
                f"1/53 = {1/53:.3f} -- security is exactly the RO preimage "
                "assumption, no more, no less",
        notes=f"hits={hits}/20000 toy_hits={toy_hits}/5300")


def N_g():
    """Injected/replayed C^L is discarded by note-commitment authentication
    (membership in the CLAIMED epoch's tree)."""
    rng = _R("N_g")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    S = Sender("S", rng)
    Att = Sender("Att", rng)

    vm = V.register_address(b"d", ds0, mode="naive")
    S.learn_address(vm); Att.learn_address(vm)
    S.send(vm, 1, chain, mas, note_pk_of_receiver=V.note_pk)
    run_epoch(chain, mas, [ds0], 1)
    real_c_l = mas[0].lists[1][0].C_L        # public post-mix bytes

    # epoch 2: attacker replays the victim's REAL epoch-1 C^L under the
    # epoch-2 tag (computable from the address) -- worst case: the C^L is
    # genuinely the victim's, decrypts fine; only the commitment check can
    # catch the epoch shift.
    e = 2
    S.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)   # 1 real note
    esk = rand_scalar(rng)
    Att.learn(esk)                            # attacker knows its own esk
    T = tag(vm["K_TT"], vm["G_r"], e)
    epk = smul(esk, vm["G_r"])
    proof = ProofPi(Att, T, epk, vm["K_TT"], vm["G_r"], esk, e)
    C_T = encrypt(vm["S_r"], T + proof.serialize(), b"tct" + e8(e), vm["G_r"], esk)
    f = scalar_from_bytes(PRF_D(vm["K_TT"], e8(e)), Q)
    C_D = encrypt(padd(vm["D"], smul(f, G2)), b"true", b"dct" + e8(e), G2,
                  rand_scalar(rng))
    pom = PoM(C_T, C_D, real_c_l)
    chain.add_tx(e, encrypt(V.note_pk, b"", b"nct" + e8(e), G1, rand_scalar(rng)),
                 {ma.idx: encrypt(ma.pk, pom.serialize(), b"mix" + e8(e), G1,
                                  rand_scalar(rng)) for ma in mas},
                 H(b"replay-cm-n"))
    run_epoch(chain, mas, [ds0], e)
    # run_epoch re-mixes epoch 1 too? No: only epoch e passed. OK.

    bucket = V.query_tag(e, vm, b"n1")
    accepted, discarded = V.receive_bucket(e, bucket, chain, authenticate=True)
    blocked = len(accepted) == 1 and discarded == 1

    # negative control: authentication disabled => replayed note accepted
    accepted2, discarded2 = V.receive_bucket(e, bucket, chain, authenticate=False)
    control_ok = len(accepted2) == 2

    return _result(
        "N_g", "injected/replayed post-mix garbage", 
        "BLOCKED" if blocked else "BROKEN",
        "the replayed C^L decrypts to a REAL note (AEAD fine, epoch-free "
        "C^L AD), but its commitment sits in the epoch-1 tree, not the "
        "claimed epoch-2 tree => membership-in-claimed-epoch check discards "
        "it",
        control=f"authentication disabled => wallet accepts the replayed "
                f"note (double-counts it): {control_ok}",
        notes=f"accepted={len(accepted)} discarded={discarded} "
              f"accepted_without_auth={len(accepted2)} "
              f"(count pollution remains -- see A_F7b)")


def N_h():
    """dsk recovery from D = [dsk]G_2 is blocked by the discrete log
    assumption (supplementary; FINDINGS verified-sound item 8)."""
    rng = _R("N_h")
    ds0 = DetectionServer("DS_A", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    vm = V.register_address(b"d", ds0, mode="naive")
    D_pub = vm["D"]
    # The simulator provides NO discrete-log function on the 256-bit group
    # (structural stand-in for DLP hardness).
    no_dlog = True

    # toy group: DLP is easy by brute force there => recovery trivial,
    # showing the guarantee is exactly the group assumption.
    p_t, q_t = 107, 53
    g_t = pow(2, 2, p_t)
    dsk_t = 17
    D_t = pow(g_t, dsk_t, p_t)
    rec = next(k for k in range(q_t) if pow(g_t, k, p_t) == D_t)
    toy_recovers = rec == dsk_t

    blocked = no_dlog
    return _result(
        "N_h", "dsk from published D", 
        "BLOCKED" if blocked else "BROKEN",
        "recovering dsk from D requires a discrete log in the 256-bit "
        "group; the protocol's security here is assumption-based (DLP), as "
        "the article concedes (classically secure, not post-quantum)",
        control=f"toy order-53 group: brute-force dlog recovers dsk "
                f"({toy_recovers}) -- i.e. nothing but group size protects "
                "this branch",
        notes="assumption-labeled: unconditional claims are limited to N_e")


ALL = [A_F1, A_F2, A_F3, A_F4, A_F5, A_F6, A_F7a, A_F7b, A_F8,
       N_a, N_b, N_c, N_d, N_e, N_f, N_g, N_h]
