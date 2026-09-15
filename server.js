#!/usr/bin/env node
'use strict';

// ============================================
// LOAD BALANCER - Node.js
// Frontend tunggal untuk 4 backend Railway
// Single file. Tinggal deploy + generate domain.
// ============================================

const http = require('node:http');
const httpProxy = require('http-proxy');

// ============================================
// KONFIGURASI BACKEND
// Ubah daftar di bawah (satu per baris).
// Format: hostname saja, TANPA https:// dan TANPA trailing slash.
// Kalau ENV BACKENDS di-set, itu yang dipakai (dipisah koma).
// ============================================
const BACKENDS = (
  (process.env.BACKENDS && process.env.BACKENDS.split(',').map((s) => s.trim()).filter(Boolean)) ||
  [
    'wsudprelay-production-7524.up.railway.app',
    // 'backend-2.up.railway.app',
    // 'backend-3.up.railway.app',
    // 'backend-4.up.railway.app',
  ]
);

// ============================================
// KONFIGURASI STRATEGI
// ============================================
// 'random' | 'sticky' | 'roundrobin' | 'failover' | 'first'
// Untuk XUDP/WebSocket long-lived: PAKAI 'sticky'.
const WS_STRATEGY   = process.env.WS_STRATEGY   || 'sticky';
const HTTP_STRATEGY = process.env.HTTP_STRATEGY || 'first';

const PORT = parseInt(process.env.PORT, 10) || 8080;
const PROXY_TIMEOUT_MS = parseInt(process.env.PROXY_TIMEOUT_MS, 10) || 30000;

// ============================================
// STATS
// ============================================
const STATS = {
  startTime: Date.now(),
  http: 0,
  ws: 0,
  perBackend: Object.fromEntries(
    BACKENDS.map((b) => [b, { http: 0, ws: 0, errors: 0 }])
  ),
};

let rrIndex = 0;

// ============================================
// UTIL
// ============================================
function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function getClientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function pickBackend(req, strategy) {
  if (BACKENDS.length === 0) return null;
  if (BACKENDS.length === 1) return BACKENDS[0];

  if (strategy === 'sticky') {
    const ip = getClientIP(req);
    return BACKENDS[hashCode(ip) % BACKENDS.length];
  }
  if (strategy === 'roundrobin') {
    const b = BACKENDS[rrIndex % BACKENDS.length];
    rrIndex = (rrIndex + 1) % BACKENDS.length;
    return b;
  }
  if (strategy === 'failover' || strategy === 'first') {
    return BACKENDS[0];
  }
  // default: random
  return BACKENDS[Math.floor(Math.random() * BACKENDS.length)];
}

// ============================================
// PROXY INSTANCE
// ============================================
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  ws: true,
  secure: true,
  xfwd: true,
  proxyTimeout: PROXY_TIMEOUT_MS,
});

proxy.on('error', (err, req, res) => {
  const backend = req.__lbBackend || '?';
  if (STATS.perBackend[backend]) STATS.perBackend[backend].errors++;
  console.error(`[LB] error -> ${backend}: ${err.message}`);

  if (res && !res.headersSent && typeof res.writeHead === 'function') {
    try {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`LB: backend ${backend} error: ${err.message}`);
    } catch {}
  } else if (res && typeof res.end === 'function') {
    try { res.end(); } catch {}
  }
});

// ============================================
// HTTP SERVER
// ============================================
const server = http.createServer((req, res) => {
  STATS.http++;

  // Endpoint monitoring bawaan LB
  if (req.url === '/__lb/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      uptimeSec: Math.floor((Date.now() - STATS.startTime) / 1000),
      backends: BACKENDS,
      wsStrategy: WS_STRATEGY,
      httpStrategy: HTTP_STRATEGY,
      stats: STATS,
    }, null, 2));
    return;
  }

  const backend = pickBackend(req, HTTP_STRATEGY);
  if (!backend) {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('LB: no backend configured');
    return;
  }

  req.__lbBackend = backend;
  if (STATS.perBackend[backend]) STATS.perBackend[backend].http++;

  proxy.web(req, res, { target: `https://${backend}` });
});

// ============================================
// WEBSOCKET UPGRADE (untuk XUDP / v2ray WS)
// ============================================
server.on('upgrade', (req, socket, head) => {
  STATS.ws++;

  const backend = pickBackend(req, WS_STRATEGY);
  if (!backend) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy();
    return;
  }

  req.__lbBackend = backend;
  if (STATS.perBackend[backend]) STATS.perBackend[backend].ws++;
  console.log(`[LB-WS] ${getClientIP(req)} -> ${backend}${req.url}`);

  proxy.ws(req, socket, head, { target: `wss://${backend}` });
});

// ============================================
// START
// ============================================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[LB] listening on 0.0.0.0:${PORT}`);
  console.log(`[LB] backends      : ${BACKENDS.join(', ')}`);
  console.log(`[LB] WS strategy   : ${WS_STRATEGY}`);
  console.log(`[LB] HTTP strategy : ${HTTP_STRATEGY}`);
});

process.on('SIGTERM', () => {
  console.log('[LB] SIGTERM, shutting down gracefully');
  server.close(() => process.exit(0));
});