/**
 * ZecLight.qnt — Quint state-machine model of the Zcash light-wallet detection
 * protocol proposed in "Making Zcash Light Wallets Faster and More Private"
 * (Taylor Hornby / Defuse Security, March 2023).
 *
 * Formalization source of truth: ../PROTOCOL.md (properties P1-P10, attack
 * hypotheses F1-F9). This file is the protocol + adversary state machine and
 * the property invariants (see ZecLightTests.qnt for concrete traces).
 *
 * Modeling rules (see README.md):
 *   - No real crypto. Secrets are opaque; derivations are deterministic
 *     constructor terms, so term equality == derived-value equality.
 *   - "Adversary can compute X" is a derived predicate over the adversary's
 *     base facts (leaked addresses, compromised servers, delegation log,
 *     query log, retained index buckets).
 *   - The adversary is the POOL of: global traffic observer (GPA), all
 *     compromised Detection Servers, all compromised Mix Authorities, and
 *     any address components handed over by colluding senders.
 *   - Quint's effect system requires all branches of `any` to update the same
 *     variables, so the whole state is one record `st`.
 */

module ZecLight {

  // ------------------------------------------------------------------
  // Static configuration (deliberately tiny; 2 epochs is enough for every
  // cross-day property)
  // ------------------------------------------------------------------

  pure val MAX_EPOCH = 3
  pure val epochsVal: Set[int] = 1.to(MAX_EPOCH)
  pure val serversVal: Set[str] = Set("ds1", "ds2")     // ds1 = "the" indexed DS, ds2 = fallback
  pure val authoritiesVal: Set[str] = Set("ma1", "ma2")
  pure val addressesVal: Set[str] = Set("alice.1", "alice.2", "bob.1")
  pure val sendersVal: Set[str] = Set("p1", "p2")
  pure val txIdsVal: Set[int] = 1.to(6)

  // alice.* are two diversified addresses of wallet "alice" (F1); bob.1 is an
  // unrelated honest wallet used as a control.
  pure def walletOf(a: str): str =
    if (a == "alice.1" or a == "alice.2") "alice" else "bob"

  // Network identity is per wallet (both diversified addresses are normally
  // used from the same IP) — this is what F5 exploits.
  pure def ipOf(a: str): str =
    if (walletOf(a) == "alice") "ipA" else "ipB"

  // ------------------------------------------------------------------
  // Cryptographic derivations as uninterpreted-but-deterministic terms.
  //
  //   K_TT = H(s)              -> KttOf(base)
  //   G_r  = GroupHash(r)      -> GrOf(base)
  //   T    = PRF^T(K_TT,G_r,e) -> TagOf((KttOf(base), GrOf(base), e))
  //   D*   = dsk+PRF^D(K_TT,e) -> DsOf((DskOf(base), KttOf(base), e))
  //
  // `base` is the derivation input: under the underspecified vk-only
  // derivation (divSep = false) all diversified addresses of a wallet share
  // secrets; under the fixed per-diversifier derivation (divSep = true) they
  // do not. Term equality is exactly derived-value equality.
  // ------------------------------------------------------------------

  type KttT = KttOf(str)
  type GrT = GrOf(str)
  type TagT = TagOf((KttT, GrT, int))
  type DskT = DskOf(str)
  type DsT = DsOf((DskT, KttT, int))

  def base(a: str): str = if (st.divSep) a else walletOf(a)

  def kttOf(a: str): KttT = KttOf(base(a))
  def grOf(a: str): GrT = GrOf(base(a))
  def tagOf(a: str, e: int): TagT = TagOf((kttOf(a), grOf(a), e))
  def dstarOf(a: str, e: int): DsT = DsOf((DskOf(base(a)), kttOf(a), e))

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  type Tx = { id: int, snd: str, rcv: str, e: int }
  type PME = { e: int, id: int }                            // post-mix list entry (a set => sorted + dedup)
  type RegT = { addr: str, server: str }                    // registration: server learned (IP, r)
  type Bkt = { server: str, addr: str, e: int, count: int } // DS private index: T -> {C^L}
  type Dlg = { addr: str, e: int, server: str }              // non-indexed delegation scalar retained by a server
  type Qry = { server: str, ip: str, addr: str, e: int }     // indexed query: server learned (IP, tag)
  type Obs = { wallet: str, e: int, count: int }             // GPA traffic observation (session volume)
  type Prb = { snd: str, server: str, addr: str }            // successful sender->server identification oracle
  type WH = { server: str, addr: str, e: int }               // entries a malicious DS withheld from an answer

  type State = {
    epoch: int,           // current epoch (mix of e happens when the epoch advances past e)
    txLog: Set[Tx],       // all transactions (id, sender, recipient address, epoch)
    postmix: Set[PME],    // published, signed, sorted, DEDUPLICATED post-mix lists
    regs: Set[RegT],      // registrations
    buckets: Set[Bkt],    // DS indices (keyed here by address; the server itself only knows the tag)
    deleg: Set[Dlg],      // delegation scalars ever handed out (retained forever by the server)
    queries: Set[Qry],    // indexed queries ever made (query log w/ IP, retained forever)
    advAddr: Set[str],    // addresses whose components (K_TT, G_r, S_r, D) the adversary holds
    compDS: Set[str],     // adversary-controlled detection servers
    compMA: Set[str],     // adversary-controlled mix authorities
    gpaCount: Set[Obs],   // counts the GPA infers from session volume
    oracleHits: Set[Prb], // successful identification-oracle probes (only possible if !piBinding)
    withheld: Set[WH],    // F7: answers a malicious DS silently truncated
    replayTries: int,     // attacker replay attempts (mix soundness demos)
    divSep: bool,         // scenario flag: per-diversifier secret derivation?
    piBinding: bool,      // scenario flag: transaction proof pi binds tag base and epk base?
    retainsIndex: bool,   // scenario flag: DS keeps its index across epochs (footnote-1 deletion discipline off?)
  }

  var st: State

  /** initialization with explicit scenario flags */
  action initWith(d, p, r) = all {
    st' = {
      epoch: 1,
      txLog: Set(),
      postmix: Set(),
      regs: Set({ addr: "alice.1", server: "ds1" }, { addr: "bob.1", server: "ds1" }),
      buckets: Set(),
      deleg: Set(),
      queries: Set(),
      advAddr: Set(),
      compDS: Set(),
      compMA: Set(),
      gpaCount: Set(),
      oracleHits: Set(),
      withheld: Set(),
      replayTries: 0,
      divSep: d,
      piBinding: p,
      retainsIndex: r,
    },
  }

  /** default initializer used by `quint run`: flags chosen nondeterministically */
  action init = all {
    nondet d = oneOf(Bool)
    nondet p = oneOf(Bool)
    nondet r = oneOf(Bool)
    initWith(d, p, r)
  }

  // ------------------------------------------------------------------
  // Protocol + adversary actions
  // ------------------------------------------------------------------

  def recvCount(a: str, e: int): int =
    st.txLog.filter(t => t.rcv == a and t.e == e).size()

  /** §3: registration — server learns (IP, r), hence G_r; wallet gets (G_r, S_r, pi_reg) */
  action register(a, s) = all {
    a.in(addressesVal),
    s.in(serversVal),
    not(st.regs.exists(r => r.addr == a)),
    st' = st.with("regs", st.regs.union(Set({ addr: a, server: s }))),
  }

  /** §4: send a transaction to address a in the current epoch (fresh id) */
  action sendTx(p, a) = all {
    p.in(sendersVal),
    a.in(addressesVal),
    nondet id = oneOf(txIdsVal)
    all {
      not(st.txLog.exists(t => t.id == id)),
      st' = st.with("txLog", st.txLog.union(Set({ id: id, snd: p, rcv: a, e: st.epoch }))),
    },
  }

  /** new index buckets built by every server at mix time for its registered addrs */
  def newBuckets: Set[Bkt] =
    st.regs
      .map(r => { server: r.server, addr: r.addr, e: st.epoch, count: recvCount(r.addr, st.epoch) })
      .filter(b => b.count > 0)

  /**
   * §5 + §6: end of epoch. Authorities decrypt pre-mix ciphertexts (AD "mix"||e
   * rejects cross-epoch replays), publish sorted+dedup lists; every DS opens the
   * C^T addressed to its own S_r's and indexes the C^L under the tag T.
   * retainsIndex = false models the footnote-1 deletion discipline.
   */
  action advanceEpoch = all {
    st.epoch < MAX_EPOCH,
    st' = st
      .with("epoch", st.epoch + 1)
      .with("postmix", st.postmix.union(st.txLog.filter(t => t.e == st.epoch).map(t => { e: st.epoch, id: t.id })))
      .with("buckets",
        (if (st.retainsIndex) st.buckets else st.buckets.filter(b => b.e >= st.epoch)).union(newBuckets)),
  }

  /**
   * §7.2: indexed detection. Wallet proves knowledge of (s, r) for (e, T_e);
   * the server answers with the bucket. The answer's session volume is
   * proportional to the number of received notes => observed by the GPA.
   */
  action queryTag(a, e, s) = all {
    a.in(addressesVal),
    e.in(epochsVal),
    s.in(serversVal),
    e < st.epoch,
    st.regs.contains({ addr: a, server: s }),
    st' = st
      .with("queries", st.queries.union(Set({ server: s, ip: ipOf(a), addr: a, e: e })))
      .with("gpaCount",
        if (recvCount(a, e) > 0)
          st.gpaCount.union(Set({ wallet: walletOf(a), e: e, count: recvCount(a, e) }))
        else st.gpaCount),
  }

  /**
   * §7.3: non-indexed detection (server-down fallback). Wallet hands the server
   * the scalar x = dsk + PRF^D(K_TT, e); server trial-decrypts every C^D of the
   * epoch and returns the matching C^L (again volume-proportional).
   */
  action delegateScalar(a, e, s) = all {
    a.in(addressesVal),
    e.in(epochsVal),
    s.in(serversVal),
    e < st.epoch,
    st' = st
      .with("deleg", st.deleg.union(Set({ addr: a, e: e, server: s })))
      .with("gpaCount",
        if (recvCount(a, e) > 0)
          st.gpaCount.union(Set({ wallet: walletOf(a), e: e, count: recvCount(a, e) }))
        else st.gpaCount),
  }

  /** address components (addr, G_r, S_r, K_TT, D) leak to the adversary (log leak, breach, ...) */
  action leakAddress(a) = all {
    a.in(addressesVal),
    st' = st.with("advAddr", st.advAddr.union(Set(a))),
  }

  /** F2: a past sender hands everything it necessarily knows (the full address) to the adversary */
  action senderCollude(p) = all {
    p.in(sendersVal),
    st' = st.with("advAddr", st.advAddr.union(st.txLog.filter(t => t.snd == p).map(t => t.rcv))),
  }

  action compromiseDS(s) = all {
    s.in(serversVal),
    st' = st.with("compDS", st.compDS.union(Set(s))),
  }

  /** key compromise is retroactive: pre-mix ciphertexts stay on the chain */
  action compromiseMA(m) = all {
    m.in(authoritiesVal),
    st' = st.with("compMA", st.compMA.union(Set(m))),
  }

  /**
   * P8 oracle probe: sender p (which holds address a) tries to learn whether
   * server s serves a, via a crafted tag/ciphertext. Without the same-base
   * binding of pi (and without pi_query) the DS's differing behavior reveals
   * it; with the binding the probe is blocked.
   */
  action oracleProbe(p, s, a) = all {
    p.in(sendersVal),
    s.in(serversVal),
    a.in(addressesVal),
    st.txLog.exists(t => t.snd == p and t.rcv == a),
    st' = st.with("oracleHits",
      if (st.piBinding or not(st.regs.exists(r => r.addr == a and r.server == s)))
        st.oracleHits
      else st.oracleHits.union(Set({ snd: p, server: s, addr: a }))),
  }

  /** F7: a malicious DS silently drops entries from an answer (completeness break) */
  action dsWithhold(s, a, e) = all {
    st.compDS.contains(s),
    st.buckets.exists(b => b.server == s and b.addr == a and b.e == e and b.count > 0),
    st' = st.with("withheld", st.withheld.union(Set({ server: s, addr: a, e: e }))),
  }

  /** N_c: attacker re-encrypts an already-mixed C^PoM to the authorities again (repetition tagging) */
  action replayRepitition = all {
    st' = st.with("replayTries", st.replayTries + 1),
    // dedup: the sorted, deduplicated post-mix list is unchanged; nothing else happens
  }

  /** N_d: attacker replays an old pre-mix ciphertext in a later epoch */
  action replayCrossEpoch = all {
    st' = st.with("replayTries", st.replayTries + 1),
    // AEAD AD "mix"||e mismatch: decryption fails, nothing enters the new list
  }

  // nondeterministic wrappers for random simulation
  action doRegister = all {
    nondet a = oneOf(addressesVal)
    nondet s = oneOf(serversVal)
    register(a, s)
  }

  action doSendTx = all {
    nondet p = oneOf(sendersVal)
    nondet a = oneOf(addressesVal)
    sendTx(p, a)
  }

  action doQueryTag = all {
    nondet a = oneOf(addressesVal)
    nondet e = oneOf(epochsVal)
    nondet s = oneOf(serversVal)
    queryTag(a, e, s)
  }

  action doDelegateScalar = all {
    nondet a = oneOf(addressesVal)
    nondet e = oneOf(epochsVal)
    nondet s = oneOf(serversVal)
    delegateScalar(a, e, s)
  }

  action doLeakAddress = all {
    nondet a = oneOf(addressesVal)
    leakAddress(a)
  }

  action doSenderCollude = all {
    nondet p = oneOf(sendersVal)
    senderCollude(p)
  }

  action doCompromiseDS = all {
    nondet s = oneOf(serversVal)
    compromiseDS(s)
  }

  action doCompromiseMA = all {
    nondet m = oneOf(authoritiesVal)
    compromiseMA(m)
  }

  action doOracleProbe = all {
    nondet p = oneOf(sendersVal)
    nondet s = oneOf(serversVal)
    nondet a = oneOf(addressesVal)
    oracleProbe(p, s, a)
  }

  action doWithhold = all {
    nondet s = oneOf(serversVal)
    nondet a = oneOf(addressesVal)
    nondet e = oneOf(epochsVal)
    dsWithhold(s, a, e)
  }

  action step = any {
    doRegister,
    doSendTx,
    advanceEpoch,
    doQueryTag,
    doDelegateScalar,
    doLeakAddress,
    doSenderCollude,
    doCompromiseDS,
    doCompromiseMA,
    doOracleProbe,
    doWithhold,
    replayRepitition,
    replayCrossEpoch,
  }

  // ------------------------------------------------------------------
  // Adversary knowledge (derived, deterministic closure of base facts)
  // ------------------------------------------------------------------

  /** any single compromised MA suffices: it (retroactively) decrypts pre-mix ciphertexts from the chain */
  def mappingLeaked: bool = st.compMA.size() > 0

  def addrLeaked(a: str): bool = st.advAddr.contains(a)

  /** server s can compute the tag of (a,e): via leaked components, or via a query it saw */
  def serverTagKnown(s: str, a: str, e: int): bool =
    addrLeaked(a) or st.queries.exists(q => q.server == s and q.addr == a and q.e == e)

  /**
   * F8: a malicious server that once received the delegation scalar
   * x = dsk + PRF^D(K_TT,e), plus the address components (any past sender),
   * computes dsk = x - PRF^D(K_TT,e).
   */
  def advDskKnown(a: str): bool =
    st.deleg.exists(d => d.addr == a and st.compDS.contains(d.server) and addrLeaked(a))

  /** adversary can compute the epoch detection scalar D*_{a,e} */
  def advDstarKnown(a: str, e: int): bool =
    advDskKnown(a) or st.deleg.exists(d => d.addr == a and d.e == e and st.compDS.contains(d.server))

  /** compromised server s can identify a's bucket in epoch e (bucket + tag knowledge) */
  def serverDetects(s: str, a: str, e: int): bool =
    st.buckets.exists(b =>
      b.server == s and b.addr == a and b.e == e and b.count > 0 and serverTagKnown(s, a, e))

  /** count knowledge from a RETAINED bucket (the F3/F9 retroactive-readout path). */
  def advCountViaRetainedIndex(a: str, e: int): bool =
    st.buckets.exists(b =>
      b.server.in(st.compDS) and b.addr == a and b.e == e and b.count > 0 and serverTagKnown(b.server, a, e))

  def advCountViaIndexAtCompDS(a: str, e: int): bool =
    advCountViaRetainedIndex(a, e)
      // FIDELITY: a DS that ANSWERED a query for (a,e) observed the bucket it
      // returned, including the empty one — it knows the count even when it is 0
      // (and, having seen the tag, can watch future epochs' buckets for it).
      or st.queries.exists(q =>
        st.compDS.contains(q.server) and q.addr == a and q.e == e)

  /** adversary learns HOW MANY notes a received in epoch e */
  def advCount(a: str, e: int): bool = advCountViaIndexAtCompDS(a, e) or advDstarKnown(a, e)

  /** adversary learns EXACTLY WHICH transactions went to a in epoch e (needs pre-mix<->post-mix mapping) */
  def advAttrib(a: str, e: int): bool = mappingLeaked and advCount(a, e)

  /** adversary connects a's daily groups across two different epochs */
  def advCrossDay(a: str): bool =
    epochsVal.exists(e1 =>
      epochsVal.exists(e2 => e1 < e2 and advCount(a, e1) and advCount(a, e2)))

  /** F5: a live compromised DS connects query-log entries by IP across epochs */
  def ipCrossDayLink: bool =
    st.queries.exists(q1 =>
      st.queries.exists(q2 =>
        q1.server == q2.server and st.compDS.contains(q1.server) and q1.ip == q2.ip and q1.e < q2.e))

  /** F5 strong form: same IP + same server links two different (diversified) addresses */
  def ipLinksDiversified: bool =
    st.queries.exists(q1 =>
      st.queries.exists(q2 =>
        q1.server == q2.server and st.compDS.contains(q1.server) and q1.ip == q2.ip and q1.addr != q2.addr))

  // ------------------------------------------------------------------
  // Properties. Each is a STATE invariant (safety): "the bad knowledge state
  // is unreachable". Expected outcomes per PROTOCOL.md are in the comments.
  // ------------------------------------------------------------------

  /** P1: a GPA observing encrypted traffic learns nothing about when/how many.
   *  EXPECT VIOLATED (F4): any query/delegation session's volume ~ #notes. */
  val p1_noCountLeak = st.gpaCount.size() == 0

  /** P3: a compromised DS (honest MAs) learns how many, not which.
   *  EXPECT HOLDS: exact attribution always requires the pre-mix<->post-mix mapping. */
  val p3_countsNotWhich =
    addressesVal.forall(a => epochsVal.forall(e => advAttrib(a, e).implies(st.compMA.size() > 0)))

  /** P4: a compromised MA alone learns nothing about the tx<->wallet mapping.
   *  EXPECT HOLDS: mapping alone never yields counts or attribution. */
  val p4_maAloneLearnsNothing =
    (st.compMA.size() > 0 and st.compDS.size() == 0 and st.advAddr.size() == 0)
      .implies(not(addressesVal.exists(a => epochsVal.exists(e => advCount(a, e)))))

  /** P5 (sound-direction reading): exact attribution requires BOTH a compromised
   *  Mix Authority AND the compromise of the address's own indexing DS.
   *  EXPECT VIOLATED via F8: attribution via a delegated-to fallback server (dsk)
   *  + MA, with the indexing DS fully honest. */
  val p5_bothNeeded =
    addressesVal.forall(a =>
      epochsVal.forall(e =>
        advAttrib(a, e)
          .implies(st.compMA.size() > 0 and st.regs.exists(r => r.addr == a and st.compDS.contains(r.server)))))

  /** P6a: cryptographic granularity of the indexed path — absent an address
   *  leak, a compromised server only ever detects epochs the wallet queried.
   *  EXPECT HOLDS: T = TagOf((Ktt, Gr, e)) is epoch-separable; no derivation
   *  rule connects tags of different epochs. */
  val p6a_granularCrypto = tuples(serversVal, addressesVal, epochsVal).forall(((s, a, e2)) =>
    (st.compDS.contains(s) and serverDetects(s, a, e2) and not(addrLeaked(a)))
      .implies(st.queries.exists(q => q.server == s and q.addr == a and q.e == e2)))

  /** P6b: after delegating only epoch e, the adversary holds detection authority
   *  for epoch e only.
   *  EXPECT VIOLATED (F8): one delegation + address leak => dsk => every epoch. */
  val p6b_limitedDelegation =
    addressesVal.forall(a =>
      epochsVal.forall(e2 => advDstarKnown(a, e2).implies(st.deleg.exists(d => d.addr == a and d.e == e2))))

  /** P6 ("cannot connect the groups from different days"), general form.
   *  EXPECT VIOLATED (F3/F9 via retained index + address leak; F5 via live IP). */
  val p6c_noCrossDayLink = addressesVal.forall(a => not(advCrossDay(a)))

  /** F3/F9 flavor: retained-index + address-leak cross-day link (bucket path
   *  ONLY — the answered-query path is deliberately excluded so this isolates
   *  the retroactive-readout mechanism; it therefore requires retainsIndex).
   *  EXPECT VIOLATED. */
  val p6c_indexPath =
    addressesVal.forall(a =>
      not(epochsVal.exists(e1 =>
        epochsVal.exists(e2 =>
          e1 < e2 and addrLeaked(a) and advCountViaRetainedIndex(a, e1) and advCountViaRetainedIndex(a, e2)))))

  /** F5 flavor: live compromised DS links daily groups (or diversified addresses)
   *  by IP, with NO address leak. EXPECT VIOLATED. */
  val p6c_ipPath = not(ipCrossDayLink or ipLinksDiversified)

  /** P8: pi + pi_query block the sender->server identification oracles.
   *  EXPECT VIOLATED in the pi-less variant (trace shows piBinding = false). */
  val p8_oracleBlocked = st.oracleHits.size() == 0

  /** P8 conditional on the fix: with the same-base binding the oracle is dead. EXPECT HOLDS. */
  val p8b_bindingBlocks = st.piBinding.implies(st.oracleHits.size() == 0)

  /** N_c/N_d: dedup + AD block repetition tagging and cross-epoch replay.
   *  EXPECT HOLDS (by construction of the abstraction: nothing but advanceEpoch
   *  ever touches postmix, and it writes the canonical deduplicated set). */
  def canonicalPostmix: Set[PME] = st.txLog.filter(t => t.e < st.epoch).map(t => { e: t.e, id: t.id })
  val mixSoundness = st.postmix == canonicalPostmix

  /** F1: diversified addresses of one wallet are unlinkable.
   *  EXPECT VIOLATED under the vk-only derivation (divSep = false). */
  val f1_diversifierUnlink =
    not(addrLeaked("alice.1") and addrLeaked("alice.2") and (kttOf("alice.1") == kttOf("alice.2")))

  /** F1 fixed variant: per-diversifier derivation keeps them unlinkable. EXPECT HOLDS. */
  val f1b_perDivUnlinkable = st.divSep.implies(kttOf("alice.1") != kttOf("alice.2"))

  /** Verify-friendly restatements of f1/f1b: they compare the DERIVATION INPUTS
   *  (str, tuple) instead of ADT constructor terms. Equivalent because KttOf,
   *  GrOf, TagOf, DsOf are injective constructors. Needed for `quint verify`:
   *  Apalache's MonotypeLanguagePred rejects ADT-constructor equality in
   *  invariants (f1/f1b proper therefore can only be sampled with quint run).
   *  EXPECT: v_f1b HOLDS; v_f1 VIOLATED (under divSep = false). */
  val v_f1b_divInputsDiffer = st.divSep.implies(base("alice.1") != base("alice.2"))
  val v_f1_sharedBaseLeak =
    not(addrLeaked("alice.1") and addrLeaked("alice.2") and base("alice.1") == base("alice.2"))

  /** P10: wallets receive all their notes via the DS. EXPECT VIOLATED (F7 withhold). */
  val p10_noSilentDrop = st.withheld.size() == 0

  /** sanity: tags of different epochs are different terms (epoch-separability). */
  val sanity_tagsEpochDistinct =
    addressesVal.forall(a =>
      epochsVal.forall(e1 => epochsVal.forall(e2 => (e1 != e2).implies(tagOf(a, e1) != tagOf(a, e2)))))
}

module ZecLightTests {
  import ZecLight.*

  // =================================================================
  // F4 / P1 — session volume leaks exact received counts to a GPA
  // =================================================================

  /** two notes to alice, one to bob; after the mixes, both query epoch 1 at ds1.
   *  The GPA reads the session volumes and distinguishes 2 vs 1 — and "when". */
  run t_F4_p1_countLeak =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(sendTx("p2", "alice.1"))
      .then(sendTx("p1", "bob.1"))
      .then(advanceEpoch)                                   // mix of epoch 1
      .then(queryTag("alice.1", 1, "ds1"))
      .then(queryTag("bob.1", 1, "ds1"))
      .expect(st.gpaCount == Set(
        { wallet: "alice", e: 1, count: 2 },
        { wallet: "bob", e: 1, count: 1 }))

  // =================================================================
  // F9 / F3 / P6 — retroactive cross-day linking via retained index
  // =================================================================

  /** victim receives in epochs 1 and 2; ONLY THEN the DS is compromised and a
   *  past sender leaks the address (K_TT is epoch-independent) — the adversary
   *  reads both daily groups out of the retained index. */
  run t_F9_retroCrossDayLink =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))                        // epoch 1
      .then(advanceEpoch)
      .then(sendTx("p2", "alice.1"))                        // epoch 2
      .then(advanceEpoch)
      .then(compromiseDS("ds1"))
      .then(senderCollude("p1"))                            // address components (K_TT, G_r) leak
      .expect(advCrossDay("alice.1")
        and advCountViaIndexAtCompDS("alice.1", 1)
        and advCountViaIndexAtCompDS("alice.1", 2)
        and not(advAttrib("alice.1", 1)))                   // counts, not which: no MA

  /** same attack but the DS follows the footnote-1 deletion discipline
   *  (retainsIndex = false): index entries die at the next mix, the retroactive
   *  readout of epoch 1 fails — the countermeasure works against THIS path. */
  run t_F9_deletionDisciplineHolds =
    initWith(true, true, false)
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(sendTx("p2", "alice.1"))
      .then(advanceEpoch)
      .then(compromiseDS("ds1"))
      .then(senderCollude("p1"))
      .expect(not(advCrossDay("alice.1")) and not(advCountViaIndexAtCompDS("alice.1", 1)))

  // =================================================================
  // F5 — live compromised DS links daily groups (and diversified
  // addresses) by IP, with NO address leak
  // =================================================================

  run t_F5_liveIpCrossDayLink =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))                        // epoch 1
      .then(advanceEpoch)
      .then(queryTag("alice.1", 1, "ds1"))                  // ds1 logs (ipA, T_1)
      .then(sendTx("p2", "alice.1"))                        // epoch 2
      .then(advanceEpoch)
      .then(compromiseDS("ds1"))                            // live compromise: query log readable
      .then(queryTag("alice.1", 2, "ds1"))                  // ds1 logs (ipA, T_2)
      .expect(ipCrossDayLink and advCrossDay("alice.1") and st.advAddr.size() == 0)

  /** the same leak connects two DIVERSIFIED addresses of the same wallet that
   *  were never linkable cryptographically (per-diversifier derivation on). */
  run t_F5_ipLinksDiversified =
    initWith(true, true, true)                              // divSep = true!
      .then(register("alice.2", "ds1"))
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(queryTag("alice.1", 1, "ds1"))
      .then(sendTx("p2", "alice.2"))
      .then(advanceEpoch)
      .then(queryTag("alice.2", 2, "ds1"))
      .then(compromiseDS("ds1"))
      .expect(ipLinksDiversified
        and kttOf("alice.1") != kttOf("alice.2")            // crypto did NOT link them
        and st.advAddr.size() == 0)

  // =================================================================
  // F8 / P6b / P5 — delegation scalar escalation to full dsk
  // =================================================================

  /** victim delegates ONLY epoch 1's detection scalar to fallback server ds2;
   *  ds2 + one colluding sender derive dsk; + one MA => exact attribution of
   *  epoch 2 — while the victim's indexing DS ds1 stays honest (P5 broken) and
   *  epoch 2 was never delegated (P6b broken). */
  run t_F8_delegationEscalation =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))                        // epoch 1: p1 now holds the address
      .then(advanceEpoch)
      .then(delegateScalar("alice.1", 1, "ds2"))            // ds2 receives x = dsk + PRF^D(K_TT,1)
      .then(compromiseDS("ds2"))
      .then(senderCollude("p1"))                            // ds2 computes dsk = x - PRF^D(K_TT,1)
      .then(sendTx("p2", "alice.1"))                        // epoch 2: victim keeps receiving
      .then(advanceEpoch)
      .then(compromiseMA("ma1"))
      .expect(advDskKnown("alice.1")                        // scalar custody broken
        and advDstarKnown("alice.1", 2)                     // detection authority for epoch 2
        and not(st.deleg.exists(d => d.addr == "alice.1" and d.e == 2)) // ...never delegated!
        and advAttrib("alice.1", 2)                         // exact attribution
        and not(st.compDS.contains("ds1")))                 // indexing DS never compromised (P5)

  /** honest delegation only: the server detects exactly the delegated epoch. */
  run t_P6b_honestDelegationScoped =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(sendTx("p2", "alice.1"))
      .then(advanceEpoch)
      .then(compromiseDS("ds2"))
      .then(delegateScalar("alice.1", 1, "ds2"))
      .expect(advDstarKnown("alice.1", 1) and not(advDstarKnown("alice.1", 2)))

  // =================================================================
  // F1 — diversified-address linkability under vk-only derivation
  // =================================================================

  /** underspecified derivation (divSep = false): two senders to two diversified
   *  addresses compare (K_TT, G_r) and find them EQUAL. */
  run t_F1_diversifiedLinkable =
    initWith(false, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(sendTx("p2", "alice.2"))
      .then(senderCollude("p1"))
      .then(senderCollude("p2"))
      .expect(kttOf("alice.1") == kttOf("alice.2") and grOf("alice.1") == grOf("alice.2"))

  /** fixed derivation (divSep = true): same collusion, terms differ. */
  run t_F1b_perDiversifierUnlinkable =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(sendTx("p2", "alice.2"))
      .then(senderCollude("p1"))
      .then(senderCollude("p2"))
      .expect(kttOf("alice.1") != kttOf("alice.2") and tagOf("alice.1", 1) != tagOf("alice.2", 1))

  // =================================================================
  // P8 — sender -> server identification oracle
  // =================================================================

  /** with the pi same-base binding (and pi_query): probing the true server and
   *  a false server both yield nothing. */
  run t_P8_bindingBlocksOracle =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))                        // p1 holds alice's address
      .then(oracleProbe("p1", "ds1", "alice.1"))            // ds1 IS alice's server
      .then(oracleProbe("p1", "ds2", "alice.1"))
      .expect(st.oracleHits.size() == 0)

  /** pi-less variant (piBinding = false): the same probe on the true server
   *  identifies it. */
  run t_P8_piLessOracleWorks =
    initWith(true, false, true)
      .then(sendTx("p1", "alice.1"))
      .then(oracleProbe("p1", "ds1", "alice.1"))
      .expect(st.oracleHits.contains({ snd: "p1", server: "ds1", addr: "alice.1" }))

  // =================================================================
  // P3 — compromised DS + honest MAs: how many, not which
  // =================================================================

  /** DS compromised + colluding sender => per-day counts, but WITHOUT an MA
   *  compromise the tx<->wallet attribution never materializes. */
  run t_P3_countsNotWhich =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(compromiseDS("ds1"))
      .then(senderCollude("p1"))
      .expect(advCount("alice.1", 1) and not(advAttrib("alice.1", 1)) and st.compMA.size() == 0)

  /** P5 as stated in the article (concession): indexing DS + MA + tag knowledge
   *  (here via a colluding sender) => exact attribution. Note the model shows
   *  attribution needs the sender-side leak on top of the two compromises. */
  run t_P5_concededAttribution =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(compromiseDS("ds1"))
      .then(compromiseMA("ma1"))
      .then(senderCollude("p1"))
      .expect(advAttrib("alice.1", 1))

  // =================================================================
  // P6a — cryptographic granularity of the indexed path
  // =================================================================

  /** the wallet queries epoch 1 only; the compromised server detects epoch 1
   *  but cannot compute the epoch-2 tag => cannot detect epoch 2. */
  run t_P6a_granularIndexed =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))                        // epoch 1
      .then(advanceEpoch)
      .then(sendTx("p2", "alice.1"))                        // epoch 2
      .then(advanceEpoch)
      .then(queryTag("alice.1", 1, "ds1"))
      .then(compromiseDS("ds1"))
      .expect(serverDetects("ds1", "alice.1", 1) and not(serverDetects("ds1", "alice.1", 2))
        and tagOf("alice.1", 1) != tagOf("alice.1", 2))

  // =================================================================
  // N_c / N_d — mix soundness against replay attacks
  // =================================================================

  /** repetition tagging + cross-epoch replay leave the post-mix list canonical
   *  and the per-tag bucket counts unchanged. */
  run t_mix_replaysBlocked =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(replayRepitition)
      .then(replayRepitition)
      .then(replayCrossEpoch)
      .expect(mixSoundness
        and st.replayTries == 3
        and st.buckets == Set({ server: "ds1", addr: "alice.1", e: 1, count: 1 })
        and st.postmix.size() == 1)

  // =================================================================
  // F7 / P10 — malicious DS silently withholds notes
  // =================================================================

  run t_F7_withhold =
    initWith(true, true, true)
      .then(sendTx("p1", "alice.1"))
      .then(advanceEpoch)
      .then(compromiseDS("ds1"))
      .then(dsWithhold("ds1", "alice.1", 1))
      .expect(st.withheld.contains({ server: "ds1", addr: "alice.1", e: 1 }))

  // =================================================================
  // sanity
  // =================================================================

  run t_sanity =
    initWith(true, true, true)
      .expect(sanity_tagsEpochDistinct
        and mixSoundness
        and st.regs == Set({ addr: "alice.1", server: "ds1" }, { addr: "bob.1", server: "ds1" }))
}
