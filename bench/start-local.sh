#!/bin/sh
# Local ends of all four tunnels. Ports:
#   1080 fcp (fcp-node)   1081 tcp-proxy   1082 udp-proxy   1083 kcptun
# Started by the benchmark driver; kill with /tmp/bench-local.pid.
cd /d/work/fcp-node || exit 1
mkdir -p /tmp/benchpids

node src/app/client.ts --key=00112233445566778899aabbccddeeff \
  --peer=144.34.186.164:4461 -b 127.0.0.1:1080 --fec=10:3 --log-level=error \
  >/tmp/l-fcp.log 2>&1 &
echo $! > /tmp/benchpids/fcp

node bench/tcp-proxy.ts client --listen=127.0.0.1:1081 --peer=144.34.186.164:7001 \
  >/tmp/l-tcp.log 2>&1 &
echo $! > /tmp/benchpids/tcp

node bench/udp-proxy.ts client --listen=127.0.0.1:1082 --peer=144.34.186.164:7002 \
  >/tmp/l-udp.log 2>&1 &
echo $! > /tmp/benchpids/udp

./bench/bin/kcptun-client.exe -l ":1083" -r "144.34.186.164:7003" \
  --key=bench-kcp-key --mode=fast >/tmp/l-kcp.log 2>&1 &
echo $! > /tmp/benchpids/kcp

sleep 3
for p in fcp tcp udp kcp; do
  pid=$(cat /tmp/benchpids/$p 2>/dev/null)
  if kill -0 "$pid" 2>/dev/null; then echo "$p up (pid $pid)"; else echo "$p DOWN"; fi
done
wait
