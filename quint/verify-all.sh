#!/bin/zsh
# Exhaustive bounded model checking (Apalache via quint verify), one invariant
# at a time (the Apalache server occupies a fixed port). 10-minute watchdog per
# run. Results into verify-results/<inv>.txt .
cd "$(dirname "$0")" || exit 1
Q=../node_modules/.bin/quint
mkdir -p verify-results
INVS=(p3_countsNotWhich p4_maAloneLearnsNothing p6a_granularCrypto
      p8b_bindingBlocks f1b_perDivUnlinkable mixSoundness
      p6b_limitedDelegation p5_bothNeeded p6c_ipPath p6c_indexPath
      p1_noCountLeak p8_oracleBlocked f1_diversifierUnlink p10_noSilentDrop
      p6c_noCrossDayLink
      v_f1_sharedBaseLeak v_f1b_divInputsDiffer)
for inv in "${INVS[@]}"; do
  echo "=== $inv ($(date +%H:%M:%S)) ===" >> verify-results/PROGRESS.log
  ( $Q verify --main ZecLight --invariant "$inv" --max-steps 10 \
      ZecLight.qnt --out "verify-results/${inv}.json" \
      > "verify-results/${inv}.txt" 2>&1 ) &
  pid=$!
  ( sleep 600; kill -9 $pid 2>/dev/null ) &
  dog=$!
  if wait $pid; then rc=0; else rc=$?; fi
  kill -9 $dog 2>/dev/null
  verdict=$(grep -oE "No violations found|Found a counterexample|An issue found|error[^\n]*" "verify-results/${inv}.txt" | head -1)
  echo "$inv : exit=$rc : $verdict ($(date +%H:%M:%S))" >> verify-results/PROGRESS.log
done
echo "ALL DONE $(date +%H:%M:%S)" >> verify-results/PROGRESS.log
