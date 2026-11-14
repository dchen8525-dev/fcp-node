// UDP echo endpoint for the window-sweep bench: echoes every datagram back.
// Usage: node bench/udp-echo.mjs [port=4463]   (run on the remote host)
import { createSocket } from 'node:dgram';
const port = Number(process.argv[2] || 4463);
const sock = createSocket('udp4');
sock.on('message', (msg, rinfo) => sock.send(msg, rinfo.port, rinfo.address));
sock.bind(port, '0.0.0.0', () => console.log(`udp echo ready on ${port}`));
