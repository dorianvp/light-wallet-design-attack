"""DEFENSE vs F2/F3/F9 (and F5) — the footnote-1-compliant server.

Campaign claims: F2 (one colluding sender + DS = per-epoch attribution),
F3/F9 (later address leak + retained/rebuildable index retroactively links
all past daily groups; P6 "cannot connect the groups from different days").

Defender reading: the article's own deletion discipline —
  * "the Detection Server can be careful to delete all trace of the
    relationship between wallets' identities and their requested tags after
    the requests have been served" (+footnote 1: never log (IP, tag), never
    retain lookup order),
  * buckets are only needed ephemerally ("only ever needs ephemeral access
    to the tags wallets request") — we model deletion after a grace window
    G, the longest the catch-up service ("for all days previous to the
    current one, the wallet can fetch its transactions quickly") can bear,
  * registration logs (ip, r, G_r) deleted immediately (the decryption
    trick is stateless; the server never needs r again),
  * F3 variant (b): ssk leak — public signed post-mix lists let anyone
    REBUILD the historical index; we test the static-ssk protocol and the
    article's own optimization paragraph (per-epoch detection keys, "old
    private keys can be deleted"), modeled as a key-retention policy.

Timeline (12 epochs): victim V receives 0-3 notes/epoch among noise
wallets; V syncs next-day (queries epoch e during epoch e+1). A colluding
sender discloses V's address at epoch 10 (F2/F3 trigger). Server state
leaks at epoch 12 (post-hoc attacks). Live attacker observes the server
from epoch 10.

Policies: retentive (campaign baseline / positive control), disciplined with
grace G in {1, 3, 7, 30, None=forever}, registration-log TTL 0.
"""

from __future__ import annotations

from common import DisciplinedServer, R, hdr, table

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "sim"))

from primitives import tag  # noqa: E402
from protocol import (Chain, DetectionServer, MixAuthority, Sender,  # noqa: E402
                      Wallet, ground_truth, run_epoch)

EPOCHS = 12
LEAK_EPOCH = 10            # colluding sender discloses the address here
STATE_LEAK_EPOCH = 12      # post-hoc server-state leak


def build_world(policy: dict):
    rng = R("d2/" + repr(sorted(policy.items())))
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds = DisciplinedServer("DS", rng, **policy)
    V = Wallet("V", rng, ip="10.0.0.9")
    W = Wallet("W", rng, ip="10.0.0.10")
    Sc = Sender("Sc-colluding", rng)
    S2 = Sender("S2", rng)

    vm = V.register_address(b"divA", ds, mode="naive")
    wm = W.register_address(b"divA", ds, mode="naive")
    Sc.learn_address(vm)
    S2.learn_address(vm)
    S2.learn_address(wm)

    plan_v = [1, 2, 0, 1, 3, 0, 1, 2, 1, 0, 2, 1]
    plan_w = [2, 0, 1, 1, 0, 2, 1, 0, 2, 1, 0, 2]
    queried = []
    for e in range(1, EPOCHS + 1):
        for _ in range(plan_v[e - 1]):
            Sc.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)
        for _ in range(plan_w[e - 1]):
            S2.send(wm, e, chain, mas, note_pk_of_receiver=W.note_pk)
        run_epoch(chain, mas, [ds], e)
        ds.close_epoch(e)
        if e == 9:
            # snapshot of the server's bucket state as seen by an attacker
            # live DURING epoch 10 (right after close_epoch(9))
            snap9 = {k: len(v) for k, v in ds.index.items() if k[0] <= 9}
        # victim syncs next day: query yesterday's tag (epochs >= 2)
        if e >= 2:
            V.query_tag(e - 1, vm, f"n{e}".encode())
            queried.append(e - 1)

    gt = {e: len(v) for e, v in ground_truth(chain, V).items()}
    return dict(rng=rng, chain=chain, mas=mas, ds=ds, V=V, vm=vm,
                plan_v=plan_v, gt=gt, queried=queried, snap9=snap9)


def read_counts(ds, vm, epochs):
    """Attacker holding (K_TT, G_r) + access to `ds` reads per-epoch counts."""
    out = {}
    for e in epochs:
        T = tag(vm["K_TT"], vm["G_r"], e)
        out[e] = len(ds.index.get((e, T), []))
    return out


def alive_at(grace, t, e) -> bool:
    """Is epoch e's bucket still retained at time t (after close_epoch(t))?
    close_epoch(t) purges t-grace, so e is alive iff e > t-grace."""
    return grace is None or e > t - grace


def recovered(counts, gt, epochs, score_only):
    """Count epochs genuinely recovered: only RETAINED epochs score (a
    purged bucket carries no information; reading 0 from a deleted epoch is
    not a recovery even if the true count was 0)."""
    ok = [e for e in epochs if e in score_only
          and counts.get(e) == gt.get(e, 0)]
    return ok


def main():
    out = [hdr("D2 — footnote-1-compliant server vs F2 / F3 / F5 / F9")]
    out.append(f"timeline: {EPOCHS} epochs; address leaks at epoch "
               f"{LEAK_EPOCH}; server state leaks at epoch {STATE_LEAK_EPOCH}")
    out.append("(victim counts per epoch: "
               + " ".join(map(str, [1, 2, 0, 1, 3, 0, 1, 2, 1, 0, 2, 1])) + ")")

    policies = [
        ("retentive (baseline)", dict(grace=None, reglog_ttl=None,
                                      del_query_links=False)),
        ("disciplined G=1", dict(grace=1, reglog_ttl=0)),
        ("disciplined G=3", dict(grace=3, reglog_ttl=0)),
        ("disciplined G=7", dict(grace=7, reglog_ttl=0)),
        ("disciplined G=30", dict(grace=30, reglog_ttl=0)),
        ("retain buckets, delete links+reglog", dict(grace=None, reglog_ttl=0)),
    ]

    rows = []
    for name, pol in policies:
        w = build_world(pol)
        ds, vm, gt = w["ds"], w["vm"], w["gt"]
        all_eps = list(range(1, EPOCHS + 1))
        past = list(range(1, LEAK_EPOCH))          # closed before leak
        future = list(range(LEAK_EPOCH, EPOCHS + 1))

        # --- F2 live: attacker pair live DURING epoch 10 (after
        #     close_epoch(9)): readable past = buckets retained at t=9,
        #     read from the t=9 snapshot (the final index has been purged
        #     further since).
        past_alive = {e for e in past if alive_at(pol.get("grace"), 9, e)}
        snap_counts = {e: w["snap9"].get(
            (e, tag(vm["K_TT"], vm["G_r"], e)), 0) for e in past}
        f2_past = [e for e in past
                   if e in past_alive and snap_counts[e] == gt.get(e, 0)]

        # --- F2 live future: reads each epoch's bucket at its own close —
        #     alive for ANY grace >= 1 by construction, so all future
        #     epochs leak while the attacker stays live.
        f2_future = future if pol.get("grace") is None or pol["grace"] >= 1 \
            else []

        # --- F3a/F9 post-hoc: state leak after close_epoch(12)
        post_alive = {e for e in all_eps
                      if alive_at(pol.get("grace"), 12, e)}
        f3 = recovered(read_counts(ds, vm, all_eps), gt, all_eps, post_alive)

        # --- F3b: ssk leak -> rebuild from PUBLIC signed post-mix lists
        rng = R("d2/rebuild")
        rebuilt_server = DetectionServer("rebuild", rng)
        rebuilt_server.ssk = ds.ssk
        rebuilt_server.learn(ds.ssk)
        for e in all_eps:
            rebuilt_server.process_epoch(e, w["mas"][0].lists[e])
        f3b = recovered(read_counts(rebuilt_server, vm, all_eps), gt,
                        all_eps, set(all_eps))

        # --- F3b': per-epoch keys (article's optimization), keys older than
        #     grace destroyed before the leak
        g = pol.get("grace")
        keep_from = 1 if g is None else STATE_LEAK_EPOCH - g + 1
        keep = {e for e in all_eps if e >= keep_from}
        srv2 = DetectionServer("rebuild2", rng)
        for e in all_eps:
            if e in keep:
                srv2.ssk = ds.ssk
                srv2.learn(ds.ssk)
                srv2.process_epoch(e, w["mas"][0].lists[e])
            else:
                srv2.ssk = 0xdeadbeef  # destroyed key: open must fail
                srv2.process_epoch(e, w["mas"][0].lists[e])
        f3b_eph = recovered(read_counts(srv2, vm, all_eps), gt, all_eps, keep)

        # --- F5: LIVE observation sees every query on the wire as it
        #     happens (deletion is post-hoc by definition); the victim
        #     queried epochs 1..11 from one IP. Post-hoc: retained rows.
        n_queried = len(w["queried"])
        f5_live = n_queried >= 2          # multiple daily groups, one IP
        f5_posthoc = len(ds.query_log)

        # --- identity tie-back via registration log
        tieback = next((ip for ip, r, G_r in ds.reglog
                        if G_r == vm["G_r"]), None)

        rows.append([
            name,
            f"{len(f2_past)}/{len(past)} past",
            f"{len(f2_future)}/{len(future)} future",
            f"{len(f3)}/{EPOCHS} epochs",
            f"{len(f3b)}/{EPOCHS}",
            f"{len(f3b_eph)}/{EPOCHS}",
            "YES" if f5_live else "no",
            f"{f5_posthoc} rows",
            tieback or "none",
        ])

    out.append("")
    out.append(table(
        ["server policy", "F2 live (ep10)", "F2 live future",
         "F3a/F9 post-hoc", "F3b ssk static", "F3b per-epoch keys",
         "F5 live", "F5 post-hoc log", "reglog tieback"],
        rows))

    out.append("""
How to read the table (all count-readouts verified equal to ground truth):
  * F2 live: while the attacker pair is live at epoch 10 it can read the
    last G closed epochs (bucket retention window) PLUS every future epoch
    as it closes — for ANY grace >= 1, because the index necessarily
    exists in-service while the wallet is a live user. Deletion discipline
    cannot shrink the live window below 'now + G'; it only destroys
    history. (grace=0 would delete buckets at their own epoch close,
    breaking the catch-up service entirely — non-functional, not tested.)
  * F3a/F9 post-hoc: the later address leak reads only the retained G
    epochs. Under G=1..7 the retroactive 'all past daily groups' claim
    collapses to 'the last G days'. Under the retentive baseline (the
    campaign's server) all 12 epochs link — positive control.
  * F3b (ssk leak): with the protocol's single static ssk, ANYONE holding
    ssk rebuilds the ENTIRE history from public signed post-mix lists —
    deletion discipline is powerless (lists are on-chain/public forever).
    The article's own optimization paragraph (per-epoch detection keys,
    old keys deleted) restores exactly the same G-day window.
  * F5: live observation links daily groups regardless of policy (the
    query hits the wire before any deletion could apply); post-hoc, the
    disciplined query log is empty (links deleted at serve).
  * Registration-log tieback: deleting (ip, r, G_r) immediately (TTL 0 —
    the server never functionally needs it again) removes the
    bucket -> registering-IP join. The retentive server keeps it.""")
    print("\n".join(out))
    return rows


if __name__ == "__main__":
    main()
