#!/bin/sh
# Interleaved throughput sampling.
#
# Running 3 rounds per proxy in a row is wrong on a congested cross-border
# path: a 30 s congestion burst lands entirely inside one proxy's numbers.
# Here every round visits all proxies once, and the visiting order rotates,
# so slow periods are shared instead of attributed to whoever happened to be
# measured at the wrong minute.
#
#   sh bench/matrix.sh [seconds-per-sample] [rounds]

SECS=${1:-15}
ROUNDS=${2:-5}
URL=https://downloads.claude.ai/claude-code-releases/2.1.319/win32-x64/claude.exe

# port:name
PROXIES="1081:tcp 1083:kcp 1080:fcp"

round=1
while [ "$round" -le "$ROUNDS" ]; do
  # rotate the starting point by (round-1) so no proxy is always first
  list="$PROXIES"
  i=0
  while [ "$i" -lt $(( (round - 1) % 3 )) ]; do
    list="$(echo "$list" | cut -d' ' -f2- ) $(echo "$list" | cut -d' ' -f1)"
    i=$((i + 1))
  done
  for entry in $list; do
    port=${entry%%:*}
    name=${entry##*:}
    out=$(curl -s -o /dev/null --max-time "$SECS" \
      -x "socks5h://127.0.0.1:$port" \
      -w "%{speed_download} %{size_download}" "$URL" 2>/dev/null)
    set -- $out
    echo "$round,$name,${1:-0},${2:-0}"
  done
  round=$((round + 1))
done
