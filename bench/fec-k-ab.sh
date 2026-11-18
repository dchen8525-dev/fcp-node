#!/bin/bash
# FEC k A/B on the live path.
#
# The question: the controller picks k from the peer's measured shard loss
# (ceil(d * loss * FEC_HEADROOM)); on this path loss sits near 22%, which puts
# k around 4 while the agreed ceiling is 6. Is the controller leaving recovery
# on the table?
#
# The path swings several-fold between hours, so absolute numbers from different
# times mean nothing. Every leg is therefore the same 10-minute download of the
# same body from the VPS itself (no CDN in the loop), and the legs alternate
# pinned-6 / adaptive so drift lands on both.
#
# The measurement is the --metrics trace, not the debug log: debug also writes
# two lines per datagram, which at hundreds of packets a second perturbs the
# throughput the test is measuring.
#
# usage: bench/fec-k-ab.sh [seconds-per-leg] [legs]
set -u
SECS=${1:-600}
LEGS=${2:-4}
REMOTE=${FCP_BENCH_HOST:-orca-web}
URL=http://127.0.0.1:8099/blob.bin
KEY=$(tr -d '\r\n' < deploy/psk.txt)
OUT=logs/fec-k-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT" || exit 1
cd "$(dirname "$0")/.." || exit 1

echo "out=$OUT secs=$SECS legs=$LEGS"

kill_proxy() {
  for pid in $(netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep LISTENING | awk '{print $5}' | sort -u); do
    taskkill //PID "$pid" //F >/dev/null 2>&1
  done
}

ssh "$REMOTE" "rm -rf /srv/fcp-bench/metrics && mkdir -p /srv/fcp-bench/metrics"

for i in $(seq 1 "$LEGS"); do
  if [ $((i % 2)) -eq 1 ]; then PIN=6; LABEL=k6; else PIN=0; LABEL=auto; fi
  RLOG=/srv/fcp-bench/leg$i.log
  RMET=/srv/fcp-bench/metrics/leg$i/m

  ssh "$REMOTE" "bash /srv/fcp-bench/stop-bench.sh; rm -f $RLOG; setsid /srv/fcp-bench/run-bench.sh $PIN $RLOG $RMET >/dev/null 2>&1 < /dev/null & sleep 1.5; ss -lunp | grep -c :4462" >/dev/null 2>&1

  kill_proxy
  sleep 1
  node dist/fcp-bench-client.mjs client --key="$KEY" \
    --peer=144.34.186.164:4462 -b 127.0.0.1:1080 \
    --mtu-min=1040 --fec-data=10 --fec-parity-max=6 --log-level=info \
    --log-file="$OUT/leg$i-client.log" --metrics="$OUT/leg$i/client" \
    >/dev/null 2>&1 &
  CLI=$!
  ready=0
  for _ in $(seq 1 20); do
    if netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep -q LISTENING; then ready=1; break; fi
    kill -0 $CLI 2>/dev/null || break
    sleep 0.5
  done
  if [ "$ready" -ne 1 ]; then
    echo "leg$i ABORT: proxy never listened" >&2
    continue
  fi

  # Warm-up, discarded: every leg pays the same handshake, PMTUD walk and slow
  # start; folding that into the sample would bias whichever leg ran first.
  curl -s -o /dev/null --max-time 8 --noproxy '' -x socks5h://127.0.0.1:1080 "$URL" >/dev/null 2>&1

  # Total bytes over wall time, in whole-body GETs: the 512 MiB source is never
  # finished at these rates, but re-issuing keeps the leg honest if it ever is.
  start=$(date +%s)
  total=0
  fails=0
  while :; do
    rem=$((SECS - ($(date +%s) - start)))
    [ "$rem" -le 2 ] && break
    read -r byt <<EOF
$(curl -s -o /dev/null --max-time "$rem" --noproxy '' -x socks5h://127.0.0.1:1080 \
  -w "%{size_download}" "$URL")
EOF
    if [ "${byt:-0}" -lt 65536 ]; then fails=$((fails + 1)); fi
    total=$((total + ${byt:-0}))
  done
  elapsed=$(( $(date +%s) - start ))
  [ "$elapsed" -lt 1 ] && elapsed=1
  bw=$((total / elapsed))
  echo "leg$i $LABEL pin=$PIN bytes=$total secs=$elapsed Bps=$bw stalls=$fails" | tee -a "$OUT/legs.txt"

  kill $CLI 2>/dev/null
  wait $CLI 2>/dev/null
  kill_proxy
  scp -q "$REMOTE:$RLOG" "$OUT/leg$i-server.log" 2>/dev/null
  ssh "$REMOTE" "bash /srv/fcp-bench/stop-bench.sh; sleep 0.5; tar -C /srv/fcp-bench/metrics -czf /tmp/leg$i.tgz leg$i" >/dev/null 2>&1
  scp -q "$REMOTE:/tmp/leg$i.tgz" "$OUT/" 2>/dev/null && tar -C "$OUT" -xzf "$OUT/leg$i.tgz" 2>/dev/null
  ssh "$REMOTE" "rm -f /tmp/leg$i.tgz" >/dev/null 2>&1
done

echo "logs in $OUT"
