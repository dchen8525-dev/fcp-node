@echo off
rem FCP-Node local client: listens on 127.0.0.1:1080, tunnels to the VPS over UDP 4461.
rem Run directly to (re)start the client. Logs go to logs\client.log.
rem
rem --fec=10:6: the parity *ceiling*. The adaptive controller picks k from the
rem measured shard loss, so on a clean link it still sends k=1; a P=3 ceiling
rem only means that on a 16-30% loss path it cannot ask for the 4-6 that path
rem needs (measured: k pinned at 3 on a 30% loss path).
rem
rem --log-level=info by default: debug writes ~750 KB/s to the log file
rem (~45 MB/min while downloading), which is pointless for daily use.
rem Debug is no longer a throughput hazard (log lines are batched), but if you
rem need it, prefer a short session: replace info below with debug.
cd /d D:\work\fcp-node
"C:\Users\admin\.workbuddy\binaries\node\versions\22.22.2-6\node.exe" src\app\client.ts --key=00112233445566778899aabbccddeeff --peer=144.34.186.164:4461 -b 127.0.0.1:1080 --mtu-min=1040 --mtu-max=1500 --fec=10:6 --log-level=info --log-file=D:\work\fcp-node\logs\client.log
