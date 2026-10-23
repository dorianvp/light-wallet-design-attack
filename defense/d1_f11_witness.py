"""DEFENSE vs F11 (witness-update exclusion leak).

The campaign's F11 premise: the performance-optimized wallet "updates the
witnesses for their unspent notes as usual" by fetching ONLY the needed
sibling commitments, and a watching server pins the note's tree position via
sound exclusion rules (analysis/f11_witness_leak.py).

Defender readings of the article tested here:

  D1-a  fetch-all (LETTER OF THE TEXT).  "All wallets must always download
        and authenticate the entire note commitment and nullifier sets"
        (section "Receiving Transactions", first sentence; performance
        bullet 1).  The wallet downloads every new commitment each epoch and
        computes witnesses locally => zero positional information.

  D1-b  subtree-sharded fetching (middle option).  Fetch consensus-finalized
        2^16-leaf subtree roots only (zcashd GetSubtreeRoots style), never
        leaf-level data.  Variants:
          shard-path : only the path's sibling subtree roots (+ the
                       first-sync pre-existing ones).  Witness completion
                       deferred to spend time.
          shard-full : additionally maintain the full content of the note's
                       own 2^16-leaf subtree (one-time ~2 MiB at 32 B/leaf),
                       so witnesses are complete without any intra-subtree
                       path fetch.

Measured: per-epoch candidate-set size for the note's position under
SOUND-ONLY inference (the campaign's own conservative rule set: a fetched
block implies nothing; an unfetched finalized block excludes its sibling
range), defender bandwidth, and the real-world MB/day price of fetch-all at
1 / 2.5 / 5 shielded outputs/s vs the article's own current-day transaction
download.

Positive control: fetch-exact (leaf-level path siblings, the campaign's
reading) must pin the position exactly — reproducing F11.
"""

from __future__ import annotations

from common import hdr, table

SUBTREE_LEVEL = 16                      # 2^16-leaf subtrees (GetSubtreeRoots)
CM_BYTES = 32                           # per task: commitments ~32 bytes
INITIAL_NOTES = 200_000
PER_EPOCH = 216_000                     # 2.5 shielded outputs/s sustained
EPOCHS = 6


def levels(n: int) -> int:
    return max(1, (max(n, 1) - 1).bit_length())


def block_range(i: int, l: int) -> tuple[int, int]:
    return (i << l, (i + 1) << l)


def finalized_blocks(n1: int, n2: int, min_level: int = 0):
    out = []
    for l in range(min_level, levels(n2) + 1):
        for i in range(0, n2 >> l):
            start, end = block_range(i, l)
            if end <= n2 and n1 < end:
                out.append((l, i, start, end))
    return out


def path_siblings(p: int, n1: int, n2: int, min_level: int = 0) -> set:
    out = set()
    for l in range(min_level, levels(max(n2, p + 1)) + 1):
        s = (p >> l) ^ 1
        start, end = block_range(s, l)
        if n1 < end <= n2:
            out.add((l, s))
    return out


def all_siblings_finalized_by(p: int, n: int, min_level: int = 0) -> set:
    out = set()
    for l in range(min_level, levels(max(n, p + 1)) + 1):
        s = (p >> l) ^ 1
        start, end = block_range(s, l)
        if end <= n:
            out.add((l, s))
    return out


# ---- interval-set candidate bookkeeping -----------------------------------

def exclude_interval(cands: list[tuple[int, int]], a: int, b: int):
    out = []
    for (s, t) in cands:
        if t <= a or s >= b:
            out.append((s, t))
            continue
        if s < a:
            out.append((s, a))
        if b < t:
            out.append((b, t))
    return out


def intersect_intervals(A, B):
    """Intersect two sorted disjoint interval lists."""
    out = []
    i = j = 0
    while i < len(A) and j < len(B):
        s = max(A[i][0], B[j][0])
        t = min(A[i][1], B[j][1])
        if s < t:
            out.append((s, t))
        if A[i][1] <= B[j][1]:
            i += 1
        else:
            j += 1
    return out


def cand_size(cands) -> int:
    return sum(t - s for (s, t) in cands)


def first_sync_intervals(n1: int, n2: int, ffs: set, min_level: int,
                         p: int) -> list[tuple[int, int]]:
    """Positions q passing the first-sync completeness rule, computed with
    interval arithmetic (equivalent to the per-position filter: at every
    level l, q's sibling block must be either unfinalized (index >= M_l)
    or exactly the wallet's own allowed sibling block)."""
    cands = [(0, n2)]
    for l in range(min_level, levels(max(n1, p + 1)) + 2):
        M = n1 >> l                                   # finalized block count
        if M == 0:
            continue                                  # nothing finalized
        base = M + (M & 1)                            # first j with j^1 >= M
        allowed = [(base << l, n2)]
        s_allowed = (p >> l) ^ 1
        if s_allowed < M and (l, s_allowed) in ffs:   # the wallet's own block
            allowed.append((min(s_allowed << l, n2),
                            min((s_allowed + 1) << l, n2)))
        allowed.sort()
        cands = intersect_intervals(cands, allowed)
        if not cands:
            break
    return cands


# ---- strategies -----------------------------------------------------------

def run(strategy: str, label: str):
    from common import R
    rng = R("d1/" + strategy)
    p_true = INITIAL_NOTES + rng.randrange(PER_EPOCH)   # note lands in epoch 1
    n = INITIAL_NOTES
    cands: list[tuple[int, int]] | None = None
    log = []
    bytes_fetched = 0
    subtree_lo = (p_true >> SUBTREE_LEVEL) << SUBTREE_LEVEL
    subtree_hi = subtree_lo + (1 << SUBTREE_LEVEL)
    subtree_done = False

    for e in range(1, EPOCHS + 1):
        n1, n2 = n, n + PER_EPOCH
        n = n2
        min_lvl = 0 if strategy == "fetch-exact" else (
            SUBTREE_LEVEL if strategy.startswith("shard") else None)

        if strategy == "fetch-all":
            fetched = None
            bytes_fetched += PER_EPOCH * CM_BYTES
        else:
            fetched = path_siblings(p_true, n1, n2, min_lvl)
            if e == 1:
                fetched |= {(l, i) for (l, i)
                            in all_siblings_finalized_by(p_true, n1, min_lvl)}
            if strategy == "shard-full" and not subtree_done:
                lo = max(subtree_lo, n1)
                hi = min(subtree_hi, n2)
                if hi > lo:
                    bytes_fetched += (hi - lo) * CM_BYTES
                if subtree_hi <= n2:
                    subtree_done = True
            bytes_fetched += len(fetched) * CM_BYTES

        if cands is None:
            if fetched is None:                       # fetch-all: uniform
                cands = [(0, n2)]
            else:
                cands = first_sync_intervals(n1, n2, fetched, min_lvl, p_true)

        if fetched is not None:
            top = levels(n2)
            for l in range(min_lvl, top + 1):
                for i in range(max(0, (n1 >> l) - 1), (n2 >> l) + 1):
                    start, end = i << l, (i + 1) << l
                    if not (end <= n2 and n1 < end):
                        continue
                    if (l, i) in fetched:
                        continue
                    a = (i ^ 1) << l
                    cands = exclude_interval(cands, a, a + (1 << l))

        log.append((e, cand_size(cands)))

    exact = cand_size(cands) == 1 and any(s <= p_true < t for (s, t) in cands)
    return dict(strategy=strategy, label=label, p=p_true, log=log,
                bytes_fetched=bytes_fetched, exact_pin=exact,
                final_cands=cand_size(cands), truth_in_cands=any(
                    s <= p_true < t for (s, t) in cands))


# ---- real-world bandwidth price of fetch-all ------------------------------

def bandwidth_rows():
    rows = []
    for ops in (1.0, 2.5, 5.0):
        leaves = int(ops * 86_400)
        cm_mb = leaves * CM_BYTES / 1e6
        cm_nf_mb = 2 * cm_mb            # + nullifier set (also ~32 B each)
        for tx_bytes in (1_000, 2_000, 4_000):
            day_tx_mb = leaves * tx_bytes / 1e6
            rows.append([f"{ops}", f"{leaves:,}", f"{cm_mb:.2f}",
                         f"{cm_nf_mb:.2f}", f"{tx_bytes:,}", f"{day_tx_mb:.1f}",
                         f"{100 * cm_nf_mb / day_tx_mb:.2f}%"])
    return rows


def main():
    out = [hdr("D1 — DEFENSE vs F11 (witness-update exclusion leak)")]
    out.append(f"tree: init {INITIAL_NOTES:,} notes, +{PER_EPOCH:,}/epoch "
               f"(2.5 outputs/s), {EPOCHS} epochs, sound-only inference")

    results = [
        run("fetch-exact", "campaign: leaf-level path siblings only"),
        run("fetch-all", "DEFENDER letter-of-text: entire commitment set"),
        run("shard-path", "middle: 2^16 subtree roots, path-only"),
        run("shard-full", "middle: subtree roots + full own subtree"),
    ]

    out.append("")
    out.append(table(
        ["strategy", "candidates after epoch 1..6", "final", "exact pin?",
         "fetched over 6 ep"],
        [[r["label"],
          " ".join(f"{c:,}" for (_, c) in r["log"]),
          f"{r['final_cands']:,}",
          "YES" if r["exact_pin"] else "no",
          f"{r['bytes_fetched'] / 1e6:.2f} MB"] for r in results]))
    out.append(f"(truth always in candidate set: "
               f"{all(r['truth_in_cands'] for r in results)})")

    out.append("""
Reading the trajectory:
  * fetch-exact (campaign's premise, 'witnesses as usual' = fetch only the
    needed leaf-level siblings): position pinned EXACTLY — F11 reproduces
    against this reading. Positive control passes.
  * fetch-all (the article's literal sentence 'All wallets must always
    download and authenticate the entire note commitment and nullifier
    sets'): the candidate set NEVER shrinks — zero positional information,
    first-sync rule included (the first-sync fetch is the whole set,
    uniform across wallets).
  * shard-* (2^16-leaf subtree roots): candidates collapse ONCE to a single
    2^16-leaf subtree (65,536 positions) after the first frontier crossing
    and then STOP — no per-epoch compounding. Reason: coarser (2^17+) fetch
    events never resolve which subtree of a pair the note is in, and the
    note's own subtree root is never fetched as a sibling (shard-path
    defers it, shard-full computes it locally). 65,536-anonymity forever.
    shard-path still re-introduces an exact pin at SPEND time (a one-shot
    full-witness completion fetch); shard-full avoids that by carrying the
    note's whole subtree (~2 MiB one-time).""")

    out.append("")
    out.append("Real-world price of the letter-of-text defense "
               "(32 B/commitment, nullifiers 32 B):")
    out.append(table(
        ["ops/s", "leaves/day", "commit MB/d", "+nullf MB/d", "tx B",
         "current-day txs MB/d", "overhead"],
        bandwidth_rows()))
    out.append("""
Verdict material for F11:
  * Article as written avoids F11 entirely: zero information.
  * Price: 2.8 / 6.9 / 13.8 MB/day of commitments at 1 / 2.5 / 5 outputs/s
    (5.5 / 13.8 / 27.6 MB/day with nullifiers) = 0.8%-3.2% (1.6%-6.4% with
    nullifiers) of the current-day transaction stream the same wallets
    already download and trial-decrypt (the article's own performance
    bullet). Consistent with the article's performance story: the design
    eliminates trial-decrypting ALL HISTORY, not the 32-byte commitment
    stream.
  * Caveat: vs the QUIET-wallet ideal (~kB/day of C^L) this is a 100-1000x
    regression of the fast path; 'authenticate' the whole set each epoch is
    also beyond the article's text.
  * Middle option: sharding leaks strictly less than the campaign's
    leaf-level reading — floor 65,536 candidates instead of 1, reached in
    ~1 epoch, then constant; steady-state cost a few 32-B subtree roots per
    day (2 MiB one-time for shard-full).
""")
    print("\n".join(out))
    return results


if __name__ == "__main__":
    main()
