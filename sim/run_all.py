#!/usr/bin/env python3
"""Entry point: run every scenario in attacks.py and print a verdict table.

Usage:  python3 run_all.py   (from the sim/ directory)
Exit code 0 always -- verdicts are findings, not test failures.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import attacks  # noqa: E402

EXPECTED = {
    # FINDINGS.md's claim for each scenario, for the mismatch report below.
    "A_F1": "BREAK", "A_F2": "BREAK", "A_F3": "BREAK", "A_F4": "BREAK",
    "A_F5": "BREAK", "A_F6": "BREAK", "A_F7a": "BREAK", "A_F7b": "BREAK",
    "A_F8": "BREAK",
    "N_a": "BLOCKED", "N_b": "BLOCKED", "N_c": "BLOCKED", "N_d": "BLOCKED",
    "N_e": "BLOCKED", "N_f": "BLOCKED", "N_g": "BLOCKED", "N_h": "BLOCKED",
}


def main() -> int:
    results = []
    for fn in attacks.ALL:
        print(f"--- {fn.__name__} " + "-" * (60 - len(fn.__name__)))
        try:
            r = fn()
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            r = dict(id=fn.__name__, target="?", verdict="ERROR",
                     mechanism=str(exc), control="", notes="")
        results.append(r)
        print(f"target   : {r['target']}")
        print(f"verdict  : {r['verdict']}")
        print(f"mechanism: {r['mechanism']}")
        print(f"control  : {r['control']}")
        print(f"notes    : {r['notes']}")
        print()

    print("=" * 78)
    print(f"{'ID':<7} {'VERDICT':<9} EXPECTED   MATCH")
    print("-" * 78)
    mismatches = 0
    for r in results:
        exp = EXPECTED.get(r["id"], "?")
        match = "yes" if r["verdict"] == exp else "NO <-- MISMATCH"
        if r["verdict"] != exp:
            mismatches += 1
        print(f"{r['id']:<7} {r['verdict']:<9} {exp:<10} {match}")
    print("-" * 78)
    print(f"{len(results)} scenarios, {mismatches} mismatch(es) vs FINDINGS.md")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.json")
    with open(out, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"raw results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
