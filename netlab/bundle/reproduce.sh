#!/bin/sh
# Re-run this finding from the bundle alone (OROS PRV-3): the same commands, threshold and rule as
# `netlab finding`, in plain sh, so nobody needs our repo or our Python to check it.
# Every command runs on a device through `docker exec clab-<lab>-<device>`, as in the lab. On real
# kit, run the same command on that device's shell.
# Exit 0: this run names the finding's segment and owner. 1: it doesn't. 2: it can't tell (the
# bundle changed, the lab runs another image, or the path is different).
# Needs: sh, awk, sha256sum, docker. Usage: sh reproduce.sh   (LAB=, OUT=, WAIT= to override)
set -eu
cd "$(dirname "$0")"

# 1. The bundle is what was sent (checked before finding.env is read), and the lab runs the image the
#    finding was taken on.
sha256sum -c --quiet SHA256SUMS || { echo "Can't tell: files changed since the bundle was written (SHA256SUMS)"; exit 2; }
for image in $(awk '$1 == "image" { print $2 }' versions.txt); do
  digest=$(awk -v i="$image" '$1 == "image" && $2 == i { print $3 }' versions.txt)
  if ! docker image inspect --format '{{join .RepoDigests " "}}' "$image" | grep -qF "$digest"; then
    echo "Can't tell: $image here is not $digest, the image the finding was taken on"; exit 2
  fi
done

. ./finding.env
LAB=${LAB:-$(sed -n 's/^name: *//p' lab/topology.clab.yml)}
OUT=${OUT:-rerun-$(date -u +%Y%m%dT%H%M%SZ)}
WAIT=${WAIT:-180}  # seconds to wait for a freshly deployed lab to route the finding's path

on() { device=$1; shift; docker exec "clab-$LAB-$device" "$@"; }
# Loss % from ping's summary line ("200 packets transmitted, 160 [packets] received"). A ping that
# printed no summary lost everything.
loss() { awk '/packets transmitted/ { sent = $1; got = $4 } END { printf "%.1f", sent ? 100 * (sent - got) / sent : 100 }' "$1"; }
above() { awk -v x="$1" -v t="$THRESHOLD" 'BEGIN { exit !(x > t) }'; }  # true if a loss % is over the threshold

mkdir -p "$OUT"
: > "$OUT/segments.txt"

# 2. The path is the finding's path. Traced as the finding did (ICMP traceroute), and again while a
#    hop shows * or a freshly deployed lab is still converging.
deadline=$(( $(date +%s) + WAIT ))
while :; do
  on "$SRC" traceroute -I -n -q 1 -w 1 "$DST" > "$OUT/traceroute.txt" 2>&1 || true
  got=$(awk -v dst="$DST" 'NR > 1 { printf "%s ", $2; if ($2 == dst) exit }' "$OUT/traceroute.txt")
  [ "$got" != "$HOPS " ] || break
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "Can't tell: $SRC's path to $DST is '$got', the finding's was '$HOPS'"; exit 2
  fi
  sleep 2
done

# 3. Every hop at once from SRC, and every hop past our edge from the edge itself.
for hop in $HOPS; do
  on "$SRC" ping -q -c "$PROBES" -i "$INTERVAL" -W 1 "$hop" > "$OUT/$SRC-ping-$hop.txt" 2>&1 &
done
for hop in $BEYOND; do
  on "$EDGE" ping -q -c "$PROBES" -i "$INTERVAL" -W 1 "$hop" > "$OUT/$EDGE-ping-$hop.txt" 2>&1 &
done
wait

# 4. Loss starts at the first hop from which every later hop is lossy too. A lossy hop with clean
#    hops after it is a router rate-limiting replies to itself, not dropping traffic through it.
echo "$SRC -> $DST: $PROBES probes per hop, a hop is lossy above $THRESHOLD%"
i=0
start=0
for hop in $HOPS; do
  i=$((i + 1))
  pct=$(loss "$OUT/$SRC-ping-$hop.txt")
  if above "$pct"; then [ "$start" -gt 0 ] || start=$i; else start=0; fi
  segment="$(echo "$PATH_DEVICES" | cut -d' ' -f"$i")-$(echo "$PATH_DEVICES" | cut -d' ' -f"$((i + 1))")"
  owner=$(echo "$OWNERS" | cut -d'|' -f"$i")
  printf '  %-10s %-22s %5s%%\n' "$segment" "$owner" "$pct"
  echo "$segment|$owner" >> "$OUT/segments.txt"
done
found=""
found_owner=""
if [ "$start" -gt 0 ]; then
  found=$(sed -n "${start}p" "$OUT/segments.txt" | cut -d'|' -f1)
  found_owner=$(sed -n "${start}p" "$OUT/segments.txt" | cut -d'|' -f2)
fi

# 5. Our edge's own view, with no campus link in the way: loss past it if the finding blames the
#    far side, none if the finding blames us or found nothing.
edge_agrees=yes
for hop in $BEYOND; do
  pct=$(loss "$OUT/$EDGE-ping-$hop.txt")
  echo "  from our edge $EDGE directly: $hop $pct%"
  if [ -n "$OWNER" ] && [ "$OWNER" != "$OPERATOR" ]; then
    above "$pct" || edge_agrees=no
  elif above "$pct"; then
    edge_agrees=no
  fi
done

if [ "$found" = "$SEGMENT" ] && [ "$found_owner" = "$OWNER" ] && [ "$edge_agrees" = yes ]; then
  if [ -n "$SEGMENT" ]; then
    echo "Reproduced: loss starts on $SEGMENT (owner: $OWNER), as the finding says. Raw output: $OUT/"
  else
    echo "Reproduced: no loss above $THRESHOLD%, as the finding says. Raw output: $OUT/"
  fi
  exit 0
fi
[ "$edge_agrees" = yes ] || echo "  our edge's direct view does not match the finding"
echo "Did not reproduce: the finding says ${SEGMENT:-no loss} (${OWNER:-nobody}), this run found ${found:-no loss above $THRESHOLD%}${found_owner:+ ($found_owner)}. Raw output: $OUT/"
exit 1
