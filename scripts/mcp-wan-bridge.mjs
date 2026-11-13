#!/usr/bin/env node
/**
 * iOS MCP Wi-Fi + Cellular WAN Reverse Bridge & Multi-Path Router (Home PC Daemon)
 *
 * Ensures the iPhone's MCP server remains reachable from your home computer whether:
 *   1. The phone is at school / away on Cellular Data (pdp_ip0 behind carrier CGNAT)
 *      or restricted school Wi-Fi -> Phone connects outbound to this daemon's
 *      reverse bridge port (default TCP 8091) using the MCP-HELLO / MCP-REQ protocol.
 *   2. The phone is on Home Wi-Fi (10.0.x.x / 192.168.x.x) or Tailscale/VPN (100.x.y.z)
 *      -> Daemon automatically routes via the reverse bridge pool OR falls back to direct
 *      Wi-Fi / Tailscale / Cellular IPv6 endpoints transparently.
 *
 * Usage on Home PC:
 *   node scripts/mcp-wan-bridge.mjs --http-port 8090 --bridge-port 8091 --phone-ip 127.0.0.1
 *
 * Point your MCP client (Claude Code, Cursor, Codex, Antigravity) to:
 *   http://127.0.0.1:8090/mcp
 */

import net from "node:net";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";

function parseArgs(argv) {
  const opts = {
    httpHost: process.env.IOS_MCP_HTTP_HOST || "127.0.0.1",
    httpPort: Number(process.env.IOS_MCP_HTTP_PORT || 8090),
    bridgeHost: process.env.IOS_MCP_BRIDGE_BIND || "::",
    bridgePort: Number(process.env.IOS_MCP_BRIDGE_PORT || 8091),
    phoneIp: process.env.IOS_MCP_PHONE_IP || "",
    phonePort: Number(process.env.IOS_MCP_PHONE_PORT || 8090),
    tailscaleIp: process.env.IOS_MCP_TAILSCALE_IP || "",
    stateFile: path.join(os.homedir(), ".ios-mcp-wan-state.json"),
  };

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--http-host" && argv[i + 1]) opts.httpHost = argv[++i];
    else if (a === "--http-port" && argv[i + 1]) opts.httpPort = Number(argv[++i]);
    else if (a === "--bridge-host" && argv[i + 1]) opts.bridgeHost = argv[++i];
    else if (a === "--bridge-port" && argv[i + 1]) opts.bridgePort = Number(argv[++i]);
    else if (a === "--phone-ip" && argv[i + 1]) opts.phoneIp = argv[++i];
    else if (a === "--phone-port" && argv[i + 1]) opts.phonePort = Number(argv[++i]);
    else if (a === "--tailscale-ip" && argv[i + 1]) opts.tailscaleIp = argv[++i];
    else if (a === "--state-file" && argv[i + 1]) opts.stateFile = argv[++i];
  }
  return opts;
}

const opts = parseArgs(process.argv);

const pool = [];
let lastPhoneHello = {
  wifi_ip: opts.phoneIp || "",
  cellular_ipv4: "",
  cellular_ipv6: "",
  vpn_ip: opts.tailscaleIp || "",
  port: opts.phonePort || 8090,
  bound_if: "unknown",
  remoteAddress: "",
  lastSeenAt: 0,
};

let metrics = {
  totalRequests: 0,
  routedViaReverseBridge: 0,
  routedViaDirectSocket: 0,
  failedRequests: 0,
  totalBridgeHandshakes: 0,
};

try {
  if (fs.existsSync(opts.stateFile)) {
    const saved = JSON.parse(fs.readFileSync(opts.stateFile, "utf8"));
    lastPhoneHello = { ...lastPhoneHello, ...saved };
    if (opts.phoneIp) lastPhoneHello.wifi_ip = opts.phoneIp;
    if (opts.tailscaleIp) lastPhoneHello.vpn_ip = opts.tailscaleIp;
  }
} catch {}

function saveLastPhoneState() {
  try {
    fs.writeFileSync(opts.stateFile, JSON.stringify(lastPhoneHello, null, 2) + "\n", "utf8");
  } catch {}
}

function getLocalHostAddresses() {
  const ifs = os.networkInterfaces();
  const out = [];
  for (const [name, list] of Object.entries(ifs)) {
    for (const info of list || []) {
      if (info.internal) continue;
      if (info.family === "IPv4" || (info.family === "IPv6" && !info.address.startsWith("fe80:"))) {
        out.push({ interface: name, family: info.family, address: info.address });
      }
    }
  }
  return out;
}

function removeSocketFromPool(sock) {
  const idx = pool.findIndex((entry) => entry.socket === sock);
  if (idx !== -1) {
    pool.splice(idx, 1);
  }
}

/**
 * 1. Reverse Bridge Listener (TCP 8091)
 * Accepts persistent outbound connections from the iPhone over Cellular (pdp_ip0) or Wi-Fi (en0).
 */
const bridgeServer = net.createServer({ allowHalfOpen: false }, (socket) => {
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 15000);

  let handshakeDone = false;
  let leasedForHttp = false;
  let lineBuffer = "";

  const onData = (chunk) => {
    if (leasedForHttp) return;
    lineBuffer += chunk.toString("utf8");
    let nlIdx;
    while ((nlIdx = lineBuffer.indexOf("\n")) !== -1) {
      const line = lineBuffer.slice(0, nlIdx).replace(/\r$/, "");
      lineBuffer = lineBuffer.slice(nlIdx + 1);

      if (line.startsWith("MCP-HELLO ")) {
        const jsonPart = line.slice("MCP-HELLO ".length).trim();
        let meta = {};
        try {
          meta = JSON.parse(jsonPart);
        } catch {}

        lastPhoneHello = {
          ...lastPhoneHello,
          ...meta,
          remoteAddress: socket.remoteAddress || "",
          lastSeenAt: Date.now(),
        };
        if (opts.phoneIp && !meta.wifi_ip) {
          lastPhoneHello.wifi_ip = opts.phoneIp;
        }
        saveLastPhoneState();

        if (!handshakeDone) {
          handshakeDone = true;
          metrics.totalBridgeHandshakes++;
          pool.push({
            socket,
            meta: lastPhoneHello,
            connectedAt: Date.now(),
            lastHeartbeatAt: Date.now(),
            detachHandshakeListeners: () => {
              leasedForHttp = true;
              socket.removeListener("data", onData);
            },
          });
          console.log(
            `[wan-bridge] iPhone connected via ${meta.bound_if || "net"} (remote=${socket.remoteAddress}, wifi=${meta.wifi_ip || "-"}, cell4=${meta.cellular_ipv4 || "-"}, cell6=${meta.cellular_ipv6 || "-"}, pool=${pool.length})`
          );
        }
      } else if (line === "MCP-PING") {
        lastPhoneHello.lastSeenAt = Date.now();
        const entry = pool.find((e) => e.socket === socket);
        if (entry) entry.lastHeartbeatAt = Date.now();
        try {
          socket.write("MCP-PONG\n");
        } catch {}
      }
    }
  };

  socket.on("data", onData);
  socket.on("error", () => removeSocketFromPool(socket));
  socket.on("close", () => removeSocketFromPool(socket));
});

bridgeServer.on("error", (err) => {
  if (err.code === "EAFNOSUPPORT" && opts.bridgeHost === "::") {
    bridgeServer.listen(opts.bridgePort, "0.0.0.0");
    return;
  }
  console.error(`[wan-bridge] Bridge server error:`, err.message);
});

bridgeServer.listen(opts.bridgePort, opts.bridgeHost, () => {
  console.log(`[wan-bridge] Listening for iPhone reverse cellular/WAN connections on ${opts.bridgeHost}:${opts.bridgePort}`);
});

/**
 * Pop a healthy idle reverse-bridge socket from the iPhone pool.
 */
function acquireReverseBridgeSocket() {
  while (pool.length > 0) {
    const entry = pool.shift();
    if (
      entry &&
      entry.socket &&
      !entry.socket.destroyed &&
      entry.socket.writable &&
      entry.socket.readable
    ) {
      entry.detachHandshakeListeners();
      return entry.socket;
    }
  }
  return null;
}

/**
 * Candidate direct endpoints when the reverse bridge pool is empty
 * (e.g., phone is on local home Wi-Fi 10.0.x.x or Tailscale VPN).
 */
function getDirectCandidates() {
  const port = Number(lastPhoneHello.port || opts.phonePort || 8090);
  const candidates = [];
  const seen = new Set();

  const add = (host, label) => {
    if (!host || seen.has(host)) return;
    seen.add(host);
    candidates.push({ host, port, label });
  };

  add(opts.phoneIp, "cli_phone_ip");
  add(lastPhoneHello.wifi_ip, "wifi_en0");
  add(opts.tailscaleIp, "cli_tailscale_ip");
  add(lastPhoneHello.vpn_ip, "vpn_tailscale_utun");
  add(lastPhoneHello.cellular_ipv6, "cellular_ipv6_pdp_ip0");
  add(lastPhoneHello.cellular_ipv4, "cellular_ipv4_pdp_ip0");
  return candidates;
}

function connectDirectCandidate(candidates, index = 0) {
  return new Promise((resolve, reject) => {
    if (index >= candidates.length) {
      reject(new Error("No reachable direct Wi-Fi/Tailscale/Cellular endpoint and reverse bridge pool is empty"));
      return;
    }
    const cand = candidates[index];
    const sock = net.connect({ host: cand.host, port: cand.port, timeout: 2200 });
    let settled = false;

    const failNext = () => {
      if (settled) return;
      settled = true;
      sock.destroy();
      connectDirectCandidate(candidates, index + 1).then(resolve, reject);
    };

    sock.once("connect", () => {
      if (settled) return;
      settled = true;
      sock.setTimeout(0);
      sock.setNoDelay(true);
      resolve({ socket: sock, candidate: cand });
    });
    sock.once("timeout", failNext);
    sock.once("error", failNext);
  });
}

/**
 * 2. Local Home-PC MCP HTTP Endpoint / Transparent Proxy (TCP 8090)
 */
const httpProxyServer = net.createServer((clientSocket) => {
  clientSocket.setNoDelay(true);
  let initialChunks = [];
  let headerParsed = false;

  const onClientData = async (chunk) => {
    if (headerParsed) return;
    initialChunks.push(chunk);
    const combined = Buffer.concat(initialChunks);
    const headerEnd = combined.indexOf("\r\n\r\n");
    if (headerEnd === -1 && combined.length < 16384) {
      return;
    }

    headerParsed = true;
    clientSocket.removeListener("data", onClientData);
    clientSocket.pause();
    metrics.totalRequests++;

    const firstLine = combined.subarray(0, Math.min(combined.length, 256)).toString("utf8").split("\r\n")[0] || "";
    if (firstLine.startsWith("GET /bridge_status")) {
      const body = JSON.stringify(
        {
          ok: true,
          daemon: "ios-mcp-wan-bridge",
          reverse_pool_idle: pool.length,
          last_phone_hello: lastPhoneHello,
          direct_candidates: getDirectCandidates(),
          host_interfaces: getLocalHostAddresses(),
          metrics,
        },
        null,
        2
      );
      const resp =
        `HTTP/1.1 200 OK\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        `Connection: close\r\n\r\n` +
        body;
      clientSocket.end(resp);
      return;
    }

    // Route 1: Use an active Reverse Bridge socket from the iPhone (Cellular pdp_ip0 or remote Wi-Fi)
    const revSocket = acquireReverseBridgeSocket();
    if (revSocket) {
      metrics.routedViaReverseBridge++;
      try {
        revSocket.write("MCP-REQ\n");
        revSocket.write(combined);
        clientSocket.pipe(revSocket);
        revSocket.pipe(clientSocket);
        clientSocket.resume();

        const cleanup = () => {
          try { clientSocket.destroy(); } catch {}
          try { revSocket.destroy(); } catch {}
        };
        clientSocket.once("error", cleanup);
        revSocket.once("error", cleanup);
        clientSocket.once("close", cleanup);
        revSocket.once("close", cleanup);
        return;
      } catch {
        try { revSocket.destroy(); } catch {}
      }
    }

    // Route 2: Direct multi-interface fallback (Home Wi-Fi 10.0.x.x / Tailscale / Cellular IPv6)
    try {
      const { socket: directSock } = await connectDirectCandidate(getDirectCandidates());
      metrics.routedViaDirectSocket++;
      directSock.write(combined);
      clientSocket.pipe(directSock);
      directSock.pipe(clientSocket);
      clientSocket.resume();

      const cleanup = () => {
        try { clientSocket.destroy(); } catch {}
        try { directSock.destroy(); } catch {}
      };
      clientSocket.once("error", cleanup);
      directSock.once("error", cleanup);
      clientSocket.once("close", cleanup);
      directSock.once("close", cleanup);
    } catch (err) {
      metrics.failedRequests++;
      const errBody = JSON.stringify({
        error: "iPhone unreachable on both Cellular Reverse Bridge and Direct Wi-Fi/VPN",
        detail: err.message,
        reverse_pool_idle: pool.length,
        last_phone_hello: lastPhoneHello,
        hint: "Ensure 'wanBridgeHost' in iPhone Settings -> iOS MCP points to this computer's IP/hostname:8091, or pass --phone-ip <10.0.x.x> when on home Wi-Fi.",
      });
      const resp =
        `HTTP/1.1 502 Bad Gateway\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${Buffer.byteLength(errBody)}\r\n` +
        `Connection: close\r\n\r\n` +
        errBody;
      try {
        clientSocket.end(resp);
      } catch {}
    }
  };

  clientSocket.on("data", onClientData);
  clientSocket.on("error", () => {});
});

httpProxyServer.listen(opts.httpPort, opts.httpHost, () => {
  console.log(`[wan-bridge] Local MCP HTTP router listening at http://${opts.httpHost}:${opts.httpPort}/mcp`);
  console.log(`[wan-bridge] Bridge status endpoint: http://${opts.httpHost}:${opts.httpPort}/bridge_status`);
  const addrs = getLocalHostAddresses();
  if (addrs.length > 0) {
    console.log(`[wan-bridge] Configure iPhone Settings -> iOS MCP -> '家里电脑地址' (wanBridgeHost) with one of:`);
    for (const a of addrs) {
      const formatted = a.family === "IPv6" ? `[${a.address}]:${opts.bridgePort}` : `${a.address}:${opts.bridgePort}`;
      console.log(`             - ${formatted} (${a.interface})`);
    }
  }
});
