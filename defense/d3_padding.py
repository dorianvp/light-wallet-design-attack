"""DEFENSE vs F4 (volume/duration side channel on P1).

Campaign claim (F4): retrieval volume is proportional to notes received, so
P1 ("learn nothing about when or how many") is unachievable "without
worst-case padding", and worst-case padding "negates the performance goal".

Defender reading: the article already specifies a "constant-bandwidth
protocol (e.g. fixed-sized packets sent at regular intervals)" for delivery
and its own count-obfuscation paragraph (R+F). We implement the strongest
defensible version: pad every fetch-bucket to K ciphertexts AND perform a
cover fetch every epoch even when idle (constant shape per epoch).

Test matrix:
  (a) observer's distinguishing advantage between a 1-note and a 20-note
      victim at K in {none, 5, 10, 20, 50, per-epoch max}: should be 0 for
      any fixed K >= 20, and 0 for K = observed max.
  (b) bandwidth multiplier vs unpadded under realistic received-count
      distributions: Zipf-ish (s in {1.0, 1.2, 1.5}) over 1..50 and a
      uniform control; |C^L| = 580 B (Orchard-note-ciphertext scale;
      1 kB sensitivity).
  (c) information-theoretics: how many bits about n does the observer
      still learn at cap K (observer sees max(n, K) packets)?
  (d) the residual: >K wallets stand out; attacker dust (F7b/free forgery
      or fee-paid) inflates a bucket above any cap — the trilemma horn
      padding cannot close.

Positive control: unpadded sessions of 1 vs 20 notes are distinguishable
(campaign A_F4 reproduces).
"""

from __future__ import annotations

import math

from common import hdr, table

C_L_BYTES = 580            # Orchard note ciphertext scale
PACKET_BYTES = 256         # A_F4's fixed packet size


def zipf_pmf(s: float, n_max: int = 50) -> list[float]:
    w = [1.0 / (k ** s) for k in range(1, n_max + 1)]
    z = sum(w)
    return [x / z for x in w]


def stats(pmf: list[float]):
    n_max = len(pmf)
    mean = sum((i + 1) * p for i, p in enumerate(pmf))
    H = -sum(p * math.log2(p) for p in pmf if p > 0)
    return mean, H, n_max


def pad_metrics(pmf: list[float], K: int | None):
    """K=None -> unpadded; else session carries max(n, K) ciphertexts."""
    n_max = len(pmf)
    mean_n = sum((i + 1) * p for i, p in enumerate(pmf))
    if K is None:
        exp_vol = mean_n
        hidden = 0.0
        resid_H = 0.0            # observer learns n exactly
    else:
        exp_vol = sum(max(i + 1, K) * p for i, p in enumerate(pmf))
        hidden = sum(pmf[i] for i in range(min(K, n_max)))   # P(n <= K)
        # residual uncertainty: seeing K packets -> n uniform-ish over 1..K;
        # seeing >K -> n known exactly.
        p_at_cap = hidden
        cond_H = 0.0
        if p_at_cap > 0:
            # H(n | n <= K)
            sub = [pmf[i] for i in range(min(K, n_max))]
            z = sum(sub)
            cond_H = -sum((p / z) * math.log2(p / z) for p in sub if p > 0)
        resid_H = p_at_cap * cond_H
    return dict(mult=exp_vol / mean_n, hidden=hidden, resid_H=resid_H,
                exp_vol=exp_vol)


def adv_pair(n1: int, n2: int, K: int | None) -> float:
    """Distinguishing advantage from session volume between n1 and n2."""
    if K is None:
        v1, v2 = n1, n2
    else:
        v1, v2 = max(n1, K), max(n2, K)
    return 0.0 if v1 == v2 else 1.0


def main():
    out = [hdr("D3 — pad-to-K defense vs F4 (P1 volume leak)")]

    dists = [("Zipf s=1.0 (heavy tail)", zipf_pmf(1.0)),
             ("Zipf s=1.2", zipf_pmf(1.2)),
             ("Zipf s=1.5 (steep)", zipf_pmf(1.5)),
             ("Zipf s=2.0 (most wallets get 1-2/day)", zipf_pmf(2.0)),
             ("uniform 1..50 (control)", [1 / 50] * 50)]

    for name, pmf in dists:
        mean_n, H, n_max = stats(pmf)
        out.append(f"\n--- {name}: E[n]={mean_n:.2f} notes/epoch, "
                   f"H(n)={H:.2f} bits, support 1..{n_max}")
        rows = []
        for K in [None, 5, 10, 20, 50, "epoch-max"]:
            Kv = n_max if K == "epoch-max" else K
            m = pad_metrics(pmf, Kv)
            rows.append([
                "unpadded" if K is None else
                (f"K={K}" if K != "epoch-max" else "K=epoch-max(50)"),
                f"{adv_pair(1, 20, Kv):.0f}",
                f"{adv_pair(1, 5, Kv):.0f}",
                f"{100 * m['hidden']:.1f}%",
                f"{m['mult']:.2f}x",
                f"{m['exp_vol'] * C_L_BYTES / 1000:.1f} kB/d",
                f"{m['exp_vol'] * 1000 / 1000:.1f} kB/d",
                f"{H - m['resid_H']:.2f} / {H:.2f} bits",
            ])
        out.append(table(
            ["padding", "adv(1v20)", "adv(1v5)", "wallets hidden (n<=K)",
             "bandwidth mult", "@580B/CL", "@1kB/CL", "bits leaked about n"],
            rows))

    out.append("""
Reading the tables:
  * Positive control: unpadded, 1 vs 20 notes give different session
    volumes => advantage 1 (campaign A_F4 reproduces).
  * (a) Distinguishing advantage(1-note vs 20-note victim) is EXACTLY 0 for
    every fixed cap K >= 20 and for K = epoch-max — all padded sessions are
    byte-identical. At K=10 the (1,20) pair separates again (20 > K), but
    1 vs 5 (both under the cap) stays 0.
  * (b) The multiplier is the honest cost, and it is SMALL in absolute
    terms. Pad-to-epoch-max (K=50) costs 4.5-9.1x the honest volume for
    Zipf receive counts = a flat 29 kB/day at 580 B per C^L (50 kB/day at
    1 kB) for EVERY wallet, every day, forever covered — ~11-18 MB/year,
    vs the 86-1700 MB/day current-day transaction stream the same wallets
    already download and trial-decrypt. A MODEST cap K=20 hides 80-97% of
    Zipf receive counts (40% even in the adversarial uniform control) at
    1.2-3.8x honest volume = 12-13 kB/day. Worst-case padding is NOT
    catastrophic for performance; F4's 'P1 unachievable without worst-case
    padding' is true only if one refuses to set any padding parameter at
    all — the article's own 'constant-bandwidth protocol' sentence is a
    padding mandate waiting for a K.
  * (c) Bits leaked about n at cap K = H(n) - H(n|see max(n,K)): at K=20,
    Zipf s=1.2: 4.12 bits -> 1.23 bits (only 'over-cap vs not' + tail
    shape survives); at K=50: exactly 0 bits.
  * (d) Residual the defense cannot close: wallets with n > K remain
    identifiable as busy (under Zipf: 20% at s=1.0, 13.6% at s=1.2, 6.9%
    at s=1.5, ~3% at s=2.0 — uniform: 60%), and an attacker who knows the
    address can push the victim's bucket above any cap at fee cost per
    dust note or ~zero cost via forged post-mix entries (F7b), forcing
    visible >K volume: the DoS horn of the author's own trilemma. Padding
    bounds the AMPLIFICATION (the padding bill caps at K for honest
    wallets) but not the distinguishability of flooded victims.
  * Idle-cover: a fetch every epoch (even with 0 notes) at cap K makes the
    'when' channel constant too; cost = the same K x |C^L| per epoch —
    already included in the kB/day column. Constant-shape cover is,
    however, exactly what F13's intersection attacks erode across epochs
    (offline days stand out) — padding fixes the per-epoch shape, not the
    multi-epoch statistical leak.
""")
    print("\n".join(out))


if __name__ == "__main__":
    main()
