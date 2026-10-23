# F5 — Live compromised DS links daily groups (and diversified addresses) by IP

- **File:** `F5-live-DS-IP-linking.md`
- **Violated invariant:** `p6c_ipPath` (`¬(ipCrossDayLink ∨ ipLinksDiversified)`)
- **Claim (P6):** with address secrecy, "DS cannot detect epochs not explicitly
  requested" and cannot connect daily groups.
- **Model encoding:** each indexed query stores `{server, ip, addr, e}` in the
  server's permanent query log (`queries`). A wallet has one IP for all its
  diversified addresses (`ipOf`). A *live* compromised DS joins log entries by
  IP.

## Trace 1 — cross-epoch linking, NO address leak (scripted `t_F5_liveIpCrossDayLink`)

| # | Step | State change |
|---|------|--------------|
| 0 | `initWith(true, true, true)` | genesis |
| 1 | `sendTx("p1", "alice.1")` | epoch 1 |
| 2 | `advanceEpoch` | mix of epoch 1 |
| 3 | `queryTag("alice.1", 1, "ds1")` | ds1 logs `(ipA, T(alice.1,1))` |
| 4 | `sendTx("p2", "alice.1")` | epoch 2 |
| 5 | `advanceEpoch` | mix of epoch 2 |
| 6 | `compromiseDS("ds1")` | **live** compromise; query log readable |
| 7 | `queryTag("alice.1", 2, "ds1")` | ds1 logs `(ipA, T(alice.1,2))` |

**Violating state:** `ipCrossDayLink = true`, `advCrossDay("alice.1") = true`
(the server also holds both buckets and learned both tags from the queries
themselves), **and `advAddr = ∅`** — the address never leaked; crypto was
never broken. Deletion discipline is irrelevant here: the queries happen live.

## Trace 2 — linking two *diversified* addresses (scripted `t_F5_ipLinksDiversified`)

Runs with `divSep = true` (the F1 fix in place!): `alice.1` and `alice.2` are
cryptographically unlinkable (`kttOf(alice.1) ≠ kttOf("alice.2")`), both are
registered at `ds1` and queried once each from `ipA`; compromising ds1 joins
the two log entries by IP:

```
ipLinksDiversified = true      kttOf(alice.1) != kttOf(alice.2)      advAddr = ∅
```

Network identity defeats diversifier unlinkability even with perfect key
derivation.

Both traces confirmed by random simulation (`raw/p6c_ipPath.txt`) and by
exhaustive Apalache counterexamples within 10 steps.

## Interpretation

The indexed path requires the wallet to talk to its DS from *some* network
identity. Against a live malicious DS, "which epochs does this IP care about"
is free metadata that stitches daily groups together in real time — the
strongest, simplest P6 breaker, since it needs no address leak, no retained
index, and no MA. The article's mitigation (fresh Tor circuit per query)
leaves timing/correlation attacks with the GPA; the model shows the DS alone
suffices. Note `t_P6a_granularIndexed` (holds) shows the *cryptographic*
granularity is real — `T_1 ≠ T_2` — the leak is at the network layer.
