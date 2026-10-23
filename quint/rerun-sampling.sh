#!/bin/zsh
# Regenerate sampling evidence for every invariant (quint run).
# Writes console output to traces/raw/<inv>.txt and JSON to traces/raw/<inv>.out.
# quint run exits 1 on violation; that is expected for the broken properties.
cd "$(dirname "$0")" || exit 1
Q=../node_modules/.bin/quint
INVS=(p1_noCountLeak p3_countsNotWhich p4_maAloneLearnsNothing p5_bothNeeded
      p6a_granularCrypto p6b_limitedDelegation p6c_noCrossDayLink p6c_indexPath
      p6c_ipPath p8_oracleBlocked p8b_bindingBlocks mixSoundness
      f1_diversifierUnlink f1b_perDivUnlinkable p10_noSilentDrop)
mkdir -p traces/raw
for inv in "${INVS[@]}"; do
  # JSON artifact (console suppressed)
  $Q run --main ZecLight --invariant "$inv" --max-samples 10000 --max-steps 25 \
      --seed=0x5ecc1a2b ZecLight.qnt --out "traces/raw/${inv}.out" >/dev/null 2>&1 || true
  # console artifact
  $Q run --main ZecLight --invariant "$inv" --max-samples 10000 --max-steps 25 \
      --seed=0x5ecc1a2b ZecLight.qnt > "traces/raw/${inv}.txt" 2>&1 || true
  verdict=$(grep -oE "No violation found|Found an issue" "traces/raw/${inv}.txt" | head -1)
  echo "$inv : $verdict"
done
