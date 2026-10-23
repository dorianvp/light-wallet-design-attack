"""Shared infrastructure for the EMPIRICAL DEFENDER campaign.

Everything here implements DEFENDER-side readings of the article
(https://defuse.ca/zecsec/making-zcash-light-wallets-faster-and-more-private.htm)
and re-measures the attack campaign's findings (../FINDINGS.md) against them.
We reuse the campaign's own simulator (../sim) unmodified: defender behaviors
are subclasses / wrappers, never edits to the audited attack code.

Defender readings implemented here:
  * DisciplinedServer  — footnote-1-compliant Detection Server:
      - never persists (identity, tag) links past serving ("delete all trace
        of the relationship between wallets' identities and their requested
        tags after the requests have been served"),
      - deletes per-epoch buckets after a grace window G ("only ever needs
        ephemeral access to the tags wallets request"),
      - deletes the registration log (ip, r, G_r) after TTL T,
      - optional: deletes the non-indexed delegation scalar x immediately
        after serving (ephemeral handover).
  * EphemeralKeyServer — the article's own IBE-flavored optimization,
    modeled as its minimal concrete form: a fresh ssk per epoch, with epoch
    keys deleted after the same grace window ("old private keys can be
    deleted ... stronger forward-security and backward-security properties").

Stdlib only; deterministic (every RNG seeded).
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (os.path.join(_ROOT, "sim"),):
    if p not in sys.path:
        sys.path.insert(0, p)

import random  # noqa: E402

from protocol import DetectionServer  # noqa: E402


def R(seed: str) -> random.Random:
    """Deterministic RNG, mirroring sim's convention."""
    return random.Random("defense/" + seed)


# ---------------------------------------------------------------------------
# Footnote-1-compliant Detection Server
# ---------------------------------------------------------------------------

class DisciplinedServer(DetectionServer):
    """Detection Server that follows every deletion instruction the article
    states or footnote-1 assumes, as aggressively as a functioning service
    allows.

    Parameters
    ----------
    grace : int | None
        Buckets (index entries) for epoch e are retained exactly `grace`
        epochs after e closes, then purged. None = retain forever
        (the article never actually mandates bucket deletion; None is the
        retentive baseline the campaign attacked). grace >= 1 is required
        for the catch-up service ("for all days previous ... fetch quickly")
        to function at all.
    reglog_ttl : int | None
        Registration log rows (ip, r, G_r) deleted after this many epochs.
        0 = delete immediately after registration completes (the server
        never functionally needs r again: the decryption trick is stateless).
        None = retain forever (article is silent; this is the in-spec
        baseline).
    del_query_links : bool
        Delete (ip, e, T) query-log rows the moment the bucket has been
        served (footnote 1: "never logs users' IP addresses along with the
        tags users look up ... retains no trace of the order").
    del_handover : bool
        Delete the non-indexed delegation scalar x right after the scan
        completes (modeled "best possible" ephemeral handover).
    """

    def __init__(self, name: str, rng: random.Random, grace: int | None = None,
                 reglog_ttl: int | None = None, del_query_links: bool = True,
                 del_handover: bool = True, **kw):
        super().__init__(name, rng, **kw)
        self.grace = grace
        self.reglog_ttl = reglog_ttl
        self.del_query_links = del_query_links
        self.del_handover = del_handover
        self.epoch_clock = 0          # advances on close_epoch()
        self.served: set[tuple[int, bytes]] = set()
        self.reglog_born: list[tuple[int, str, bytes, int]] = []  # (row_idx, ip, r, born)

    # -- lifecycle ---------------------------------------------------------
    def register(self, wallet, r: bytes, ip: str):
        born = self.epoch_clock
        row = len(self.reglog)
        self.reglog_born.append((row, ip, r, born))
        return super().register(wallet, r, ip)

    def close_epoch(self, e: int) -> None:
        """End-of-epoch housekeeping. Call once per epoch, after indexing."""
        self.epoch_clock = e
        # 1. bucket deletion after grace (the earliest a functioning service
        #    can drop epoch-e state while still promising catch-up fetches).
        if self.grace is not None and e - self.grace >= 1:
            self.purge(e - self.grace)
        # 2. registration-log TTL.
        if self.reglog_ttl is not None:
            self.reglog = [row for (i, *row), (_, _, _, born) in
                           zip(self.reglog, self.reglog_born)
                           if e - born < self.reglog_ttl]
            self.reglog_born = [b for b in self.reglog_born
                                if e - b[3] < self.reglog_ttl]

    # -- serving -----------------------------------------------------------
    def query_indexed(self, wallet, e, T, nonce, proof, ip,
                      require_proof: bool = True):
        out = super().query_indexed(wallet, e, T, nonce, proof, ip,
                                    require_proof)
        self.served.add((e, T))
        if self.del_query_links:
            # footnote 1: no (identity, tag) association outlives the request
            self.query_log = [(i2, e2, t2) for (i2, e2, t2) in self.query_log
                              if (e2, t2) != (e, T)]
        return out

    def nonindexed_scan(self, e: int, x_scalar: int, postmix_list):
        out = super().nonindexed_scan(e, x_scalar, postmix_list)
        if self.del_handover:
            self.handovers = [(e2, x2) for (e2, x2) in self.handovers
                              if e2 != e]
        return out


class EphemeralKeyServer(DisciplinedServer):
    """The article's own optimization paragraph, minimal concrete form:
    a fresh ssk per epoch ("private keys ... only loaded onto the live server
    as needed, and old private keys can be deleted"), with the same grace
    window. Registration-era S_r values are served by the epoch-of-
    registration key; we track per-epoch keys and expose retain/delete."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.ssk_e: dict[int, int] = {}
        self._deleted: set[int] = set()

    def keygen_epoch(self, e: int, rng: random.Random) -> None:
        from primitives import rand_scalar
        self.ssk_e[e] = rand_scalar(rng)
        self.learn(self.ssk_e[e])

    def process_epoch(self, e, postmix_list, verify_pi: bool = True):
        if e in self._deleted or e not in self.ssk_e:
            return   # key gone: this epoch's C^T are permanently unopenable
        self.ssk = self.ssk_e[e]
        return super().process_epoch(e, postmix_list, verify_pi)

    def close_epoch(self, e: int) -> None:
        super().close_epoch(e)
        if self.grace is not None and e - self.grace >= 1:
            old = e - self.grace
            self.ssk_e.pop(old, None)
            self._deleted.add(old)
            self.forget_scalar(old)

    def forget_scalar(self, e: int) -> None:
        from primitives import Q
        # modeled destruction of a scalar (knowledge vault purge)
        if e in self.ssk_e:
            self.vault.discard(("i", self.ssk_e[e]))


# ---------------------------------------------------------------------------
# Small report helpers
# ---------------------------------------------------------------------------

def hdr(title: str) -> str:
    bar = "=" * 78
    return f"\n{bar}\n{title}\n{bar}"


def row(cells: list[str], widths: list[int]) -> str:
    return " | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths))


def table(headers: list[str], rows_: list[list[str]]) -> str:
    widths = [max(len(h), *(len(str(r[i])) for r in rows_)) if rows_
              else len(h) for i, h in enumerate(headers)]
    out = [row(headers, widths), "-+-".join("-" * w for w in widths)]
    out += [row(r, widths) for r in rows_]
    return "\n".join(out)
