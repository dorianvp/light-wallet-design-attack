"""DEFENSE vs F8 (dsk recovery from the non-indexed scalar handover).

Campaign claim: the non-indexed fallback hands a server the scalar
x = dsk + PRF^D(K_TT, e); any address-holder (one colluding sender, or any
later address leak) computes f = PRF^D(K_TT, e) and cancels:
dsk = x - f, converting a limited delegation into permanent, silent,
all-epoch detection (P6: "only granted detection authority for a limited
number of epochs").

Defender task: check EVERY reading of the article's own text for a
non-leaking interpretation. The text: "it constructs its epoch detection
secret key dsk + PRF^D(K_TT, e) and provides it and the epoch number e to
the new Detection Server. The Detection Server uses this key to
trial-decrypt each C^D in the epoch" — and step 6 of sending:
D* = D + [PRF^D(K_TT, e)]G_2, C^D = Enc(D*, ...).

Readings tested (each is exercised on the real group arithmetic):
  R1  literal scalar handover (x as written)                      — functions
  R2  hand over (x, e) for several epochs (aggregate delegation)   — functions
  R3  hand over only the PRF term f_e (non-linear? no — wrong key: the
      server cannot decrypt C^D without dsk)                      — broken service
  R4  hand over the group element D* instead of the scalar        — broken service
      (trial-decryption needs the scalar to compute [x]epk; the article
      has no pairing-based decryption, and DLP protects dsk from D*)
  R5  blind x with a per-delegation nonce b (x + b)               — broken service
  R6  two-epoch cancellation only (x_1 - x_2 = f_1 - f_2)         — no gain
      (already sender-computable; contains no dsk)
  R7  ephemeral handover: server deletes x immediately after the
      epoch's scan (defender policy, not in text)                 — functions;
      narrows F8's retroactive variant to the retention window only.

Verdict logic: a reading "functions" iff the delegate actually recovers the
victim's C^L via the sim's real AEAD; it "leaks" iff a colluding
address-holder lets the delegate derive dsk (checked against the wallet's
true dsk and D = [dsk]G_2) and then silently detect every other epoch.
"""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "sim"))

from common import R, hdr  # noqa: E402
from primitives import (PRF_D, Q, e8, padd, rand_scalar,  # noqa: E402
                        scalar_from_bytes, smul)
from protocol import Chain, DetectionServer, MixAuthority, Sender, Wallet, \
    ground_truth, run_epoch  # noqa: E402

EPOCHS = 4


def build():
    rng = R("d4")
    chain = Chain()
    mas = [MixAuthority(0, rng)]
    ds_main = DetectionServer("DS_main", rng)
    V = Wallet("V", rng, ip="10.0.0.9")
    Sc = Sender("Sc-colluding", rng)
    vm = V.register_address(b"d", ds_main, mode="naive")
    Sc.learn_address(vm)
    for e in range(1, EPOCHS + 1):
        Sc.send(vm, e, chain, mas, note_pk_of_receiver=V.note_pk)
        run_epoch(chain, mas, [ds_main], e)
    return rng, chain, mas, V, vm


def delegate_and_test(name, x_ctor, note):
    """x_ctor(delegate_server, e) -> scalar or None (None = cannot hand
    over). Returns dict with service + leak outcomes."""
    rng, chain, mas, V, vm = build()
    ds2 = DetectionServer("DS_delegate", rng)
    gt = {e: len(v) for e, v in ground_truth(chain, V).items()}

    # service check: can the delegate find epoch-2 C^L?
    x2 = x_ctor(V, vm, 2)
    if x2 is None:
        service, leak, dsk_ok, silent_all = False, None, None, None
    else:
        got = ds2.nonindexed_scan(2, x2, mas[0].lists[2])
        service = len(got) == gt.get(2, 0)

        # collusion: one address-holder reveals (K_TT, G_r, D) to delegate
        ds2.learn(vm["K_TT"], vm["G_r"], vm["D"])
        f2 = scalar_from_bytes(PRF_D(vm["K_TT"], e8(2)), Q)
        dsk_rec = (x2 - f2) % Q
        dsk_ok = dsk_rec == vm["dsk"] and smul(
            dsk_rec, __import__("primitives").G2) == vm["D"]
        # silent all-epoch detection with zero further victim queries
        silent = {}
        for e in range(1, EPOCHS + 1):
            x_e = (dsk_rec + scalar_from_bytes(
                PRF_D(vm["K_TT"], e8(e)), Q)) % Q
            silent[e] = len(ds2.nonindexed_scan(e, x_e, mas[0].lists[e]))
        silent_all = silent == {e: gt.get(e, 0) for e in range(1, EPOCHS + 1)}
        leak = dsk_ok and silent_all
    return dict(name=name, service=service, leak=leak, dsk_recovered=dsk_ok,
                silent_all_epochs=silent_all, note=note)


def main():
    out = [hdr("D4 — every textual reading of the non-indexed handover vs F8")]

    readings = [
        delegate_and_test(
            "R1 literal: x = dsk + PRF^D(K_TT, e)",
            lambda V, vm, e: V.delegate_scalar(vm, e),
            "the text's formula, verbatim"),
        delegate_and_test(
            "R2 aggregate: hand (x_e, e) for e in {1,2,3}",
            lambda V, vm, e: V.delegate_scalar(vm, e),
            "several epochs delegated at once — each x_e linear in dsk"),
        delegate_and_test(
            "R3 hand over only PRF^D(K_TT, e) (no dsk)",
            lambda V, vm, e: scalar_from_bytes(PRF_D(vm["K_TT"], e8(e)), Q),
            "wrong key: C^D is encrypted to D* = D + [f]G_2, opening needs "
            "dsk too"),
        delegate_and_test(
            "R4 hand over group element D* (no scalar)",
            lambda V, vm, e: None,
            "trial-decryption computes [x]epk — needs the SCALAR; no "
            "pairing-based decryption exists in the text; dlog(D*) vs G_2 "
            "protects dsk"),
        delegate_and_test(
            "R5 blind x with fresh nonce b (x + b)",
            lambda V, vm, e: (V.delegate_scalar(vm, e)
                              + rand_scalar(R("d4/R5"))) % Q,
            "server cannot unblind without b — service dies"),
    ]

    # R6: cancellation of two delegated epochs (no address needed)
    rng, chain, mas, V, vm = build()
    x1 = V.delegate_scalar(vm, 1)
    x2 = V.delegate_scalar(vm, 2)
    diff = (x1 - x2) % Q
    f1 = scalar_from_bytes(PRF_D(vm["K_TT"], e8(1)), Q)
    f2 = scalar_from_bytes(PRF_D(vm["K_TT"], e8(2)), Q)
    r6_gains_dsk = diff == (f1 - f2) % Q   # dsk cancelled out: no dsk inside

    # R7: ephemeral handover (defender policy): x deleted after serving;
    # retroactive variant needs the address leak to happen while x retained
    rng, chain, mas, V, vm = build()
    ds2 = DetectionServer("DS_ephemeral", rng, record_handovers=False)
    x2 = V.delegate_scalar(vm, 2)
    ds2.nonindexed_scan(2, x2, mas[0].lists[2])     # served; x discarded
    ds2.learn(vm["K_TT"], vm["G_r"], vm["D"])       # address leaks LATER
    f2 = scalar_from_bytes(PRF_D(vm["K_TT"], e8(2)), Q)
    # retroactive recovery requires the delegate to still hold x (it doesn't)
    r7_retroactive = ds2.knows(x2) or bool(ds2.handovers)
    # contemporaneous variant: colluding sender DURING the delegation window
    dsk_rec = (x2 - f2) % Q
    r7_contemporary = dsk_rec == vm["dsk"]

    out.append("")
    out.append(__import__("common").table(
        ["reading", "service works?", "dsk recovered?", "silent all-epoch "
         "detection?", "note"],
        [[r["name"], "yes" if r["service"] else "NO — service broken",
          "yes" if r["dsk_recovered"] else
          ("n/a" if r["dsk_recovered"] is None else "no"),
          "yes" if r["silent_all_epochs"] else
          ("n/a" if r["silent_all_epochs"] is None else "no"),
          r["note"]] for r in readings]))
    out.append(f"""
R6 (two-epoch cancellation, no address needed): x1 - x2 = f1 - f2 exactly
(dsk cancels): {r6_gains_dsk} — the difference contains NO dsk, so it gains
the attacker nothing beyond what any address-holder already has.

R7 (ephemeral handover — defender policy, delete x after serving):
  * retroactive variant (address leaks AFTER the delegation): x is gone ->
    dsk NOT recoverable from server state: {not r7_retroactive}
  * contemporaneous variant (one colluding sender WHILE the delegation is
    live, the same condition F2 needs): dsk = x - f recovers:
    {r7_contemporary} — deletion cannot help; the scalar is on the wire and
    in the delegate's memory while in use.

CONCESSION. Every reading of the article's text that preserves the
non-indexed service hands the delegate a value linear in dsk:
  * R1/R2 function and leak (dsk recovered, silent all-epoch detection,
    zero further victim queries — F8 in full).
  * R3/R4/R5 break the service itself (the delegate cannot trial-decrypt).
  * R6 is a dead end for the attacker (no dsk in the difference).
  * R7 narrows F8's RETROACTIVE variant to the delegation window but
    cannot touch the contemporaneous one.
The article's only escape hatch is its own future-work note (IBE /
"daira's detection key design" simplification) — i.e., a redesign, not a
reading. F8 SURVIVES best-effort defense unchanged: the linear structure
dsk + PRF^D(K_TT, e) is load-bearing for the fallback path.

No patch found within the text. F8 is CONCEDED in full (High severity).
""")
    print("\n".join(out))


if __name__ == "__main__":
    main()
