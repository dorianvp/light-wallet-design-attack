#!/usr/bin/env python3
"""Run all five defender counter-experiments and capture the log.

Usage:  /opt/homebrew/bin/python3 defense/run_all.py
Writes defense/results.txt (captured output of every experiment).
"""

from __future__ import annotations

import io
import os
import sys
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import d1_f11_witness  # noqa: E402
import d2_footnote1    # noqa: E402
import d3_padding      # noqa: E402
import d4_f8_readings  # noqa: E402
import d5_tor          # noqa: E402

MODULES = [
    ("d1_f11_witness.py", "D1 vs F11 — fetch-all / subtree-sharded witnesses",
     d1_f11_witness),
    ("d2_footnote1.py", "D2 vs F2/F3/F5/F9 — footnote-1 deletion discipline",
     d2_footnote1),
    ("d3_padding.py", "D3 vs F4 — pad-to-K + idle cover", d3_padding),
    ("d4_f8_readings.py", "D4 vs F8 — every textual reading of the handover",
     d4_f8_readings),
    ("d5_tor.py", "D5 vs F5 — fresh Tor circuit per lookup", d5_tor),
]


def main():
    buf = io.StringIO()
    for fname, title, mod in MODULES:
        print(f"\n########## {title} ({fname}) ##########")
        inner = io.StringIO()
        with contextlib.redirect_stdout(inner):
            mod.main()
        text = inner.getvalue()
        print(text)
        buf.write(f"\n\n########## {title} ({fname}) ##########\n")
        buf.write(text)
    out_path = os.path.join(HERE, "results.txt")
    with open(out_path, "w") as f:
        f.write(buf.getvalue().lstrip() + "\n")
    print(f"\n[written: {out_path}]")


if __name__ == "__main__":
    main()
