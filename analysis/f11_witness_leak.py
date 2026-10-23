#!/usr/bin/env python3
"""
F11 — Witness-update exclusion leak: standalone demonstration (v3).

The 2023 protocol's performance list says wallets "must still update the witnesses for
their unspent notes as usual" while the fast path fetches only the C^L ciphertexts for
the wallet's tag. But maintaining an incremental Merkle witness downloads subtree roots,
and the server watching the fetch stream learns:

  positive: fetched subtree b          => note not in range(b)
  negative: finalized b NOT fetched    => note not in sibling(b)   (the other half
                                          of b's parent)
  first-sync completeness (new wallet): every sibling subtree that finalized BEFORE
                                          the wallet's first observed sync must have
                                          been fetched AT that sync (or the note did
                                          not exist yet / is not held at all)

— which is the author's own later general statement (zcash/zcash#6756, comment of Apr
12, 2024): "the server observing these downloads can be sure that the wallet's note is
not a sibling of any of the commitments that weren't downloaded."

Simulated wallet strategies:
  fetch-exact    — fetch only finalized path siblings ("as usual")
  fetch-all      — fetch every new commitment (Theta bandwidth, no leak)
  decoys-random  — path siblings + k random finalized subtrees
  decoys-smart   — also maintain FULL fake witness paths for k decoy positions

Two observation regimes:
  new-wallet     — the server watches from the wallet's first-ever sync (natural when
                   the wallet registers with the Detection Server at epoch 1)
  pre-synced     — wallet synced before the server watched (first-sync completeness
                   unavailable; only in-window constraints apply) — the weaker attack

Usage: python3 f11_witness_leak.py   (stdlib only, deterministic)
"""
import random

random.seed(20261023)

INITIAL_NOTES = 10_000
PER_EPOCH     = 1_000
EPOCHS        = 6
SPAM_PER_EPOCH = 9_000          # F12 dilution attempt
N_RANDOM_DECOYS = 8
N_SMART_DECOYS  = 2

P_TRUE = random.randrange(INITIAL_NOTES, INITIAL_NOTES + PER_EPOCH)
# decoy positions must be plausible (real recent frontier notes)
SMART_DECOY_POS = random.sample(range(INITIAL_NOTES, INITIAL_NOTES + PER_EPOCH),
                                N_SMART_DECOYS)


def levels(n):
    return max(1, (max(n, 1) - 1).bit_length())


def block_range(i, l):
    return (i << l, (i + 1) << l)


def finalized_blocks(n1, n2):
    out = []
    for l in range(levels(n2) + 1):
        for i in range(0, n2 >> l):
            start, end = block_range(i, l)
            if end <= n2 and n1 < end:
                out.append((l, i, start, end))
    return out


def path_siblings(p, n1, n2):
    """Sibling subtrees of p finalized in (n1, n2]."""
    out = set()
    for l in range(levels(max(n2, p + 1)) + 1):
        s = (p >> l) ^ 1
        start, end = block_range(s, l)
        if n1 < end <= n2:
            out.add((l, s))
    return out


def all_siblings_finalized_by(p, n):
    """Every sibling subtree of p finalized at tree size <= n (needed at first sync)."""
    out = set()
    for l in range(levels(max(n, p + 1)) + 1):
        s = (p >> l) ^ 1
        start, end = block_range(s, l)
        if end <= n:
            out.add((l, s))
    return out


def exclude(cands, a, b):
    cands -= set(range(a, b))


def run(strategy, regime="new-wallet", spam=0, decoys=0, smart=0, label=""):
    n = INITIAL_NOTES
    cands = None
    first_n1 = None
    lines = []
    for e in range(1, EPOCHS + 1):
        n1, n2 = n, n + PER_EPOCH + spam
        n = n2
        if first_n1 is None:
            first_n1 = n1
        fin = [(l, i) for (l, i, s, t) in finalized_blocks(n1, n2)]
        fin_set = set(fin)

        if strategy == "fetch-all":
            fetched = None
        else:
            # in-window path siblings (the ongoing "as usual" update)...
            fetched = path_siblings(P_TRUE, n1, n2)
            if regime == "new-wallet" and e == 1:
                # ...plus, at the FIRST-ever sync, every sibling finalized before the
                # window (the wallet must build its full initial witness)
                fetched |= {(l, i) for (l, i) in all_siblings_finalized_by(P_TRUE, n1)}
            if strategy == "decoys-random" and fetched is not None:
                pool = [b for b in fin if b not in fetched]
                fetched |= set(random.sample(pool, min(decoys, len(pool))))
            if strategy == "decoys-smart":
                for q in SMART_DECOY_POS:
                    fetched |= path_siblings(q, n1, n2)
                    if regime == "new-wallet" and e == 1:
                        fetched |= {(l, i) for (l, i) in all_siblings_finalized_by(q, n1)}

        if cands is None:
            cands = set(range(n))
            if fetched is not None and regime == "new-wallet":
                # first-sync completeness: any held note's pre-existing siblings must
                # appear in the very first observed fetch set
                for q in list(cands):
                    if not all_siblings_finalized_by(q, first_n1) <= fetched:
                        cands.discard(q)

        if fetched is not None:
            # SOUND RULES ONLY (a wallet may fetch anything, e.g. decoy ranges that
            # cover its true note — so "fetched" implies nothing). What the server
            # MAY infer: a subtree finalized in-window but NOT fetched cannot be the
            # wallet's level-sibling (witness correctness would have required the
            # fetch), hence the note is not in the complementary half of its parent.
            for (l, i) in fin:
                if (l, i) not in fetched:
                    s, t = block_range(i ^ 1, l)
                    exclude(cands, s, t)

        lines.append((e, "ALL" if fetched is None else len(fetched), len(cands)))
        if fetched is not None and len(cands) <= max(1, N_SMART_DECOYS) and e >= 1 \
           and strategy == "decoys-smart":
            break
    exact = len(cands) == 1 and P_TRUE in cands
    ambiguous = len(cands) > 1 and P_TRUE in cands
    fooled = P_TRUE not in cands
    print(f"\n=== {label} ===")
    print(f"p_true={P_TRUE} (secret); +{PER_EPOCH:,}/epoch"
          + (f", +{spam:,} attacker notes/epoch (F12)" if spam else ""))
    for (e, f, c) in lines:
        print(f"  epoch {e}: fetched {f:>4}, surviving candidates {c:>8,}")
    verdict = ("*** POSITION RECOVERED EXACTLY ***" if exact else
               f"ambiguous: {len(cands):,} candidates" if ambiguous else
               "server fooled (truth wrongly excluded)")
    if strategy == "decoys-smart" and ambiguous:
        verdict += f" [real anonymity here = {len(cands)}: truth + {N_SMART_DECOYS} decoys]"
    print(f"  -> {verdict}")
    return len(cands), P_TRUE in cands


def main():
    print("F11 witness-update exclusion leak — intersection attack (v3)")
    run("fetch-exact", regime="new-wallet",
        label="1a) fetch-exact, new wallet (server watches first-ever sync)")
    run("fetch-exact", regime="pre-synced",
        label="1b) fetch-exact, pre-synced wallet (weaker attack, no first-sync info)")
    run("fetch-exact", regime="new-wallet", spam=SPAM_PER_EPOCH,
        label="1c) fetch-exact under F12 spam dilution (9x attacker volume)")
    run("fetch-all",
        label="2) fetch-all (Theta bandwidth — zero positional information)")
    run("decoys-random", decoys=N_RANDOM_DECOYS,
        label=f"3) random decoys k={N_RANDOM_DECOYS}")
    run("decoys-smart",
        label=f"4) smart decoys: full fake witness for {N_SMART_DECOYS} positions")
    print("""
Verdict (F11):
  * A passive server watching one epoch of ordinary witness updates pins a
    new-wallet's note position EXACTLY (1a) - tags, mixing, ZK proofs all irrelevant.
  * F12 spam dilution does not slow the attack (1c): attacker notes have their own
    fetch-inconsistent paths and die as candidates; the attack never uses the
    anonymity set, only the wallet's fetch pattern.
  * Even in the weak regime (1b) the frontier region is pinned to a single position;
    only pre-watch history stays ambiguous.
  * Random decoys (3) are useless: they almost never overlap the true path.
  * Smart decoys (4) buy anonymity = 1+k at (k+1)x fetch bandwidth AND require
    maintaining fake witnesses forever - one missed fetch for a decoy position
    collapses the cover. (Hornby 2024: "privacy properties would not be that great".)
  * fetch-all (2) is the only leak-free option, at Theta(#commitments)/epoch - the
    exact cost the protocol was invented to avoid.
LEAKED: witness updating alone defeats the receiving privacy of the
performance-optimized wallet.""")


if __name__ == "__main__":
    main()
