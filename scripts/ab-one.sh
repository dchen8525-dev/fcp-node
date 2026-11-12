#!/bin/bash
# One leg of an A/B throughput comparison on the live VPS path.
# The path swings 5x between hours, so absolute numbers from different times
# mean nothing; only alternating runs inside the same window are comparable.
# usage: ab-one.sh <label> [samples]
set -u
LABEL=${1:-run}
N=${2:-2}
URL=https://downloads.claude.ai/claude-code-releases/2.1.319/win32-x64/claude.exe
cd "$(dirname "$0")/.." || exit 1

# Git Bash's pkill only sees MSYS processes, so a node.exe client survives it
# and the next run silently fails on EADDRINUSE while the old one keeps
# serving. Kill by the Windows PID that owns the listen port instead.
for pid in $(netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep LISTENING | awk '{print $5}' | sort -u); do
  taskkill //PID "$pid" //F >/dev/null 2>&1
done
sleep 1
# The kill above can lose (a process without console access, a PID reused, a
# client started by something else). If the port is still taken, the leg would
# measure that stranger's throughput under this label, so refuse to run.
if netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep -q LISTENING; then
  echo "$LABEL ABORT: 127.0.0.1:1080 is still owned by a surviving process" >&2
  netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep LISTENING >&2
  exit 5
fi
node src/app/client.ts --key=00112233445566778899aabbccddeeff \
  --peer=144.34.186.164:4461 -b 127.0.0.1:1080 \
  --mtu-min=1040 --mtu-max=1500 --fec=10:6 --log-level=error \
  >/dev/null 2>&1 &
CLI=$!

# Readiness gate. Without it, a client that failed to bind (EADDRINUSE from a
# survivor the kill above missed, a bad flag, a crash on startup) leaves curl
# talking to yesterday's process -- or to nothing -- and the leg still prints
# `speed=0` as if it had measured something. A run whose numerator is zero is
# worse than no run: it silently enters the comparison.
ready=0
for _ in $(seq 1 20); do
  if netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep -q LISTENING; then
    ready=1
    break
  fi
  if ! kill -0 $CLI 2>/dev/null; then
    echo "$LABEL ABORT: client exited during startup (check the log; the port never came up)" >&2
    exit 2
  fi
  sleep 0.5
done
if [ "$ready" -ne 1 ]; then
  echo "$LABEL ABORT: 127.0.0.1:1080 never entered LISTENING within 10s" >&2
  kill $CLI 2>/dev/null
  for pid in $(netstat -ano 2>/dev/null | grep "127.0.0.1:1080" | grep LISTENING | awk '{print $5}' | sort -u); do
    taskkill //PID "$pid" //F >/dev/null 2>&1
  done
  exit 3
fi

# Discard a warm-up transfer: every leg pays the same handshake and slow start,
# and folding that into the first sample biases whichever leg ran first.
# --max-time cuts a 350 MB body short, so curl always exits 28 here; the exit
# code says nothing. What separates a working path from a dead one is whether
# bytes moved, so judge on size_download and let 28 mean "cut short as planned".
warm=$(curl -s -o /dev/null --max-time 6 -x socks5h://127.0.0.1:1080 \
  -w "%{size_download}" "$URL")
warm_rc=$?
if { [ "$warm_rc" -ne 0 ] && [ "$warm_rc" -ne 28 ]; } || [ "${warm:-0}" -lt 65536 ]; then
  echo "$LABEL ABORT: warm-up moved ${warm:-0} bytes (rc=$warm_rc) -- proxy up but not forwarding" >&2
  kill $CLI 2>/dev/null
  exit 4
fi

fails=0
for i in $(seq 1 "$N"); do
  # Same reasoning: a sample that dies at 0 bytes is a stall, not a slow leg.
  # Printing it as speed=0 would put a fake number into the comparison.
  read -r spd byt <<EOF
$(curl -s -o /dev/null --max-time 20 -x socks5h://127.0.0.1:1080 \
  -w "%{speed_download} %{size_download}" "$URL")
EOF
  if [ "${byt:-0}" -lt 1048576 ]; then
    echo "$LABEL run$i FAILED bytes=${byt:-0} (under 1 MiB is a stall, not a measurement)" >&2
    fails=$((fails + 1))
  else
    echo "$LABEL run$i speed=$spd bytes=$byt"
  fi
done
kill $CLI 2>/dev/null
[ "$fails" -eq 0 ] || exit 6
