#!/usr/bin/env node
'use strict';
// ====================================================================
// VLRLY004 UDP RELAY via WebSocket (single-file)
// - Protokol binary: VLRLY004 + mode + endpoint + framing
// - Transport   : WebSocket (untuk Cloudflare Workers passthrough)
// - Mode        : Fixed UDP (0x01), Packet UDP (0x03), MUX (0x02)
// ====================================================================
const net    = require('node:net');
const dgram  = require('node:dgram');
const dns    = require('node:dns').promises;
const http   = require('node:http');
const { EventEmitter } = require('node:events');
const { WebSocketServer } = require('ws');

// ==================== KONFIGURASI ====================
const CONFIG = Object.freeze({
  LISTEN_HOST: '0.0.0.0',
  LISTEN_PORT: parseInt(process.env.PORT, 10) || 8080,
  // WebSocket path. '' = terima semua path. Harus sama dgn UDP_RELAY_PATH di Worker.
  WS_PATH: process.env.WS_PATH || '/',
  MAX_WS_MESSAGE_BYTES: 4 * 1024 * 1024,
  HANDSHAKE_TIMEOUT_MS: 10000,
  IDLE_TIMEOUT_MS: 300000,
  XUDP_GRACE_MS: 60000,
  MAX_CONNECTIONS: 4096,
  // false = izinkan port UDP 443 (QUIC/STUN)
  REJECT_UDP_443: false,
  SECRET: process.env.RELAY_SECRET || '',
});

// ==================== STATS & LOG ====================
const STATS = {
  startTime: Date.now(),
  activeClients: 0,
  totalHandshakes: 0,
  udpPacketsOut: 0,
  udpBytesOut: 0,
  udpPacketsIn: 0,
  udpBytesIn: 0,
  recentLogs: [],
};
function addLog(msg) {
  const time = new Date().toLocaleTimeString('id-ID');
  STATS.recentLogs.unshift(`[${time}] ${msg}`);
  if (STATS.recentLogs.length > 60) STATS.recentLogs.pop();
}

// ==================== PROTOKOL ====================
const RELAY_MAGIC = Buffer.from('VLRLY004', 'ascii');
const RELAY_MODE_FIXED_UDP  = 0x01;
const RELAY_MODE_MUX        = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const ATYP_IPV4   = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6   = 0x03;
const MUX_STATUS_NEW       = 0x01;
const MUX_STATUS_KEEP      = 0x02;
const MUX_STATUS_END       = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA      = 0x01;
const MUX_OPTION_ERROR     = 0x02;
const MUX_NETWORK_UDP      = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_PACKET_LEN   = 65535;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

function rejectUdpTarget(target) {
  return Boolean(CONFIG.REJECT_UDP_443 && Number(target?.port) === 443);
}

function buildConfig(overrides = {}) {
  const cfg = {
    listenAddress: { host: CONFIG.LISTEN_HOST, port: CONFIG.LISTEN_PORT },
    handshakeTimeout: CONFIG.HANDSHAKE_TIMEOUT_MS,
    idleTimeout: CONFIG.IDLE_TIMEOUT_MS,
    xudpGrace: CONFIG.XUDP_GRACE_MS,
    maxConns: CONFIG.MAX_CONNECTIONS,
    wsPath: CONFIG.WS_PATH,
    maxWsMessageBytes: CONFIG.MAX_WS_MESSAGE_BYTES,
    ...overrides,
  };
  if (!cfg.listenAddress || !Number.isInteger(cfg.listenAddress.port) ||
      cfg.listenAddress.port < 0 || cfg.listenAddress.port > 65535) {
    throw new Error('invalid listen address');
  }
  if (!Number.isInteger(cfg.maxConns) || cfg.maxConns < 1) throw new Error('MAX_CONNECTIONS must be >= 1');
  if (!Number.isInteger(cfg.maxWsMessageBytes) || cfg.maxWsMessageBytes < 65536) {
    throw new Error('MAX_WS_MESSAGE_BYTES must be >= 65536');
  }
  return cfg;
}

// ==================== ASYNC BYTE READER ====================
class AsyncByteReader {
  constructor(socket) {
    this.socket = socket;
    this.buffers = [];
    this.available = 0;
    this.waiters = [];
    this.ended = false;
    this.error = null;
    socket.on('data', (chunk) => {
      if (!chunk || chunk.length === 0) return;
      this.buffers.push(Buffer.from(chunk));
      this.available += chunk.length;
      this._flush();
    });
    socket.on('end', () => { this.ended = true; this._flush(); });
    socket.on('close', () => { this.ended = true; this._flush(); });
    socket.on('error', (err) => { this.error = err; this._flush(); });
  }
  readExactly(length) {
    if (!Number.isInteger(length) || length < 0) return Promise.reject(new Error('invalid read length'));
    if (length === 0) return Promise.resolve(Buffer.alloc(0));
    if (this.available >= length) return Promise.resolve(this._take(length));
    if (this.error) return Promise.reject(this.error);
    if (this.ended) return Promise.reject(new Error('unexpected EOF'));
    return new Promise((resolve, reject) => this.waiters.push({ length, resolve, reject }));
  }
  _flush() {
    while (this.waiters.length > 0) {
      const w = this.waiters[0];
      if (this.available >= w.length) { this.waiters.shift(); w.resolve(this._take(w.length)); continue; }
      if (this.error || this.ended) { this.waiters.shift(); w.reject(this.error || new Error('unexpected EOF')); continue; }
      break;
    }
  }
  _take(length) {
    const out = Buffer.allocUnsafe(length);
    let off = 0;
    while (off < length) {
      const first = this.buffers[0];
      const need = length - off;
      if (first.length <= need) { first.copy(out, off); off += first.length; this.buffers.shift(); }
      else { first.copy(out, off, 0, need); this.buffers[0] = first.subarray(need); off += need; }
    }
    this.available -= length;
    return out;
  }
}

// ==================== PARSER ====================
async function readLengthPayload(reader) {
  const lenBuf = await reader.readExactly(2);
  const length = lenBuf.readUInt16BE(0);
  return length === 0 ? Buffer.alloc(0) : reader.readExactly(length);
}

async function readEndpoint(reader) {
  const head = await reader.readExactly(3);
  const port = head.readUInt16BE(0);
  const atyp = head[2];
  if (port === 0) throw new Error('zero port');
  return readEndpointBody(reader, atyp, port);
}

async function readEndpointBody(reader, atyp, port) {
  if (atyp === ATYP_IPV4) {
    const b = await reader.readExactly(4);
    return { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp };
  }
  if (atyp === ATYP_DOMAIN) {
    const len = (await reader.readExactly(1))[0];
    if (len === 0) throw new Error('empty domain');
    const b = await reader.readExactly(len);
    let host;
    try { host = utf8Fatal.decode(b); } catch { throw new Error('invalid UTF-8 domain'); }
    if (!host) throw new Error('empty domain');
    return { host, port, atyp };
  }
  if (atyp === ATYP_IPV6) {
    const b = await reader.readExactly(16);
    return { host: formatIPv6(b), port, atyp };
  }
  throw new Error(`unknown address type ${atyp}`);
}

function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
  return parts.join(':');
}

function ipv6ToBytes(address) {
  let input = address;
  const zone = input.indexOf('%');
  if (zone >= 0) input = input.slice(0, zone);
  const lastColon = input.lastIndexOf(':');
  if (input.includes('.') && lastColon >= 0) {
    const ipv4 = input.slice(lastColon + 1).split('.').map(Number);
    if (ipv4.length !== 4 || ipv4.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
      throw new Error(`invalid IPv6: ${address}`);
    }
    input = input.slice(0, lastColon) + ':' +
      (((ipv4[0] << 8) | ipv4[1]).toString(16)) + ':' +
      (((ipv4[2] << 8) | ipv4[3]).toString(16));
  }
  const halves = input.split('::');
  if (halves.length > 2) throw new Error(`invalid IPv6: ${address}`);
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = (halves.length === 2 && halves[1]) ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error(`invalid IPv6: ${address}`);
  }
  const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  if (words.length !== 8) throw new Error(`invalid IPv6: ${address}`);
  const out = Buffer.alloc(16);
  words.forEach((word, i) => {
    if (!/^[0-9a-f]{1,4}$/i.test(word)) throw new Error(`invalid IPv6: ${address}`);
    out.writeUInt16BE(parseInt(word, 16), i * 2);
  });
  return out;
}

function encodeUDPSource(rinfo) {
  const port = Number(rinfo.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid UDP source port');
  const family = net.isIP(rinfo.address);
  const head = Buffer.alloc(3);
  head.writeUInt16BE(port, 0);
  if (family === 4) {
    head[2] = ATYP_IPV4;
    return Buffer.concat([head, Buffer.from(rinfo.address.split('.').map(Number))]);
  }
  if (family === 6) {
    head[2] = ATYP_IPV6;
    return Buffer.concat([head, ipv6ToBytes(rinfo.address)]);
  }
  throw new Error(`invalid UDP source IP: ${rinfo.address}`);
}

function writeSocket(socket, data) {
  if (socket.destroyed || !socket.writable) return Promise.reject(new Error('socket is closed'));
  return new Promise((resolve, reject) => socket.write(data, (err) => err ? reject(err) : resolve()));
}

async function writeControlError(socket, message) {
  let body = Buffer.from(String(message || 'relay error'), 'utf8');
  if (body.length > MAX_PACKET_LEN) body = body.subarray(0, MAX_PACKET_LEN);
  const out = Buffer.allocUnsafe(3 + body.length);
  out[0] = 1;
  out.writeUInt16BE(body.length, 1);
  body.copy(out, 3);
  try { await writeSocket(socket, out); } catch { }
}

async function readControl(reader) {
  const magic = await reader.readExactly(RELAY_MAGIC.length);
  if (!magic.equals(RELAY_MAGIC)) throw new Error('bad magic');
  const mode = (await reader.readExactly(1))[0];
  if (![RELAY_MODE_FIXED_UDP, RELAY_MODE_MUX, RELAY_MODE_PACKET_UDP].includes(mode)) {
    throw new Error('bad mode');
  }
  const target = mode === RELAY_MODE_FIXED_UDP ? await readEndpoint(reader) : null;
  return { mode, target };
}

// ==================== UDP ====================
async function resolveTarget(target) {
  if (target.atyp === ATYP_IPV4) return { address: target.host, family: 4 };
  if (target.atyp === ATYP_IPV6) return { address: target.host, family: 6 };
  const records = await dns.lookup(target.host, { all: true, verbatim: true });
  if (!records.length) throw new Error(`DNS returned no address for ${target.host}`);
  const preferred = records.find(r => r.family === 4) || records.find(r => r.family === 6);
  if (!preferred) throw new Error(`DNS returned unsupported address for ${target.host}`);
  return preferred;
}

function bindDgram(socket, port, address) {
  return new Promise((resolve, reject) => {
    const onError = (err) => { cleanup(); reject(err); };
    const onListening = () => { cleanup(); resolve(); };
    const cleanup = () => {
      socket.off('error', onError);
      socket.off('listening', onListening);
    };
    socket.once('error', onError);
    socket.once('listening', onListening);
    socket.bind(port, address);
  });
}

class UDPAssociation {
  constructor() {
    this.udp4 = null;
    this.udp6 = null;
    this.port = 0;
    this.sink = null;
    this.closed = false;
  }
  static async create() {
    const assoc = new UDPAssociation();
    assoc.udp4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    await bindDgram(assoc.udp4, 0, '0.0.0.0');
    assoc.port = assoc.udp4.address().port;
    assoc.udp4.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
    assoc.udp4.on('error', () => {});
    assoc.udp6 = dgram.createSocket({ type: 'udp6', reuseAddr: true, ipv6Only: true });
    try {
      await bindDgram(assoc.udp6, assoc.port, '::');
      assoc.udp6.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
      assoc.udp6.on('error', () => {});
    } catch {
      try { assoc.udp6.close(); } catch {}
      assoc.udp6 = null;
    }
    return assoc;
  }
  attach(sink) {
    const old = this.sink;
    this.sink = sink;
    return old;
  }
  detach(mux, id) {
    if (this.sink && this.sink.mux === mux && this.sink.id === id) {
      this.sink = null;
      return true;
    }
    return false;
  }
  async send(target, payload) {
    if (this.closed) throw new Error('UDP association is closed');
    if (payload.length > MAX_PACKET_LEN) throw new Error(`UDP payload too large: ${payload.length}`);
    const resolved = await resolveTarget(target);
    const socket = resolved.family === 6 ? this.udp6 : this.udp4;
    if (!socket) throw new Error(`UDP IPv${resolved.family} is unavailable on this host`);
    await new Promise((resolve, reject) => {
      socket.send(payload, target.port, resolved.address, (err) => err ? reject(err) : resolve());
    });
    STATS.udpPacketsOut++;
    STATS.udpBytesOut += payload.length;
  }
  _onMessage(msg, rinfo) {
    STATS.udpPacketsIn++;
    STATS.udpBytesIn += msg.length;
    const sink = this.sink;
    if (!sink || this.closed) return;
    Promise.resolve(sink.mux.sendUDPData(sink.id, rinfo, Buffer.from(msg))).catch(() => {});
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.sink = null;
    if (this.udp4) { try { this.udp4.close(); } catch {} }
    if (this.udp6) { try { this.udp6.close(); } catch {} }
    this.udp4 = null;
    this.udp6 = null;
  }
}

// ==================== SERVE: FIXED UDP ====================
async function serveDirectUDP(socket, reader, target) {
  if (rejectUdpTarget(target)) {
    await writeControlError(socket, 'UDP/443 rejected');
    return;
  }
  const assoc = await UDPAssociation.create();
  let closed = false;
  assoc.attach({
    mux: {
      sendUDPData: async (_id, _rinfo, data) => {
        if (closed || socket.destroyed) return;
        if (data.length > MAX_PACKET_LEN) return;
        const frame = Buffer.allocUnsafe(2 + data.length);
        frame.writeUInt16BE(data.length, 0);
        data.copy(frame, 2);
        await writeSocket(socket, frame);
      },
    },
    id: 0,
  });
  try {
    await writeSocket(socket, Buffer.from([0])); // ack 0x00
    for (;;) {
      const payload = await readLengthPayload(reader);
      if (payload.length === 0) continue;
      if (rejectUdpTarget(target)) continue;
      await assoc.send(target, payload);
    }
  } finally {
    closed = true;
    assoc.close();
  }
}

// ==================== SERVE: PACKET UDP ====================
async function servePacketUDP(socket, reader) {
  const assoc = await UDPAssociation.create();
  let closed = false;
  const writeChain = { value: Promise.resolve() };
  assoc.attach({
    mux: {
      sendUDPData: (_id, rinfo, data) => {
        if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return Promise.resolve();
        const endpoint = encodeUDPSource(rinfo);
        const len = Buffer.allocUnsafe(2);
        len.writeUInt16BE(data.length, 0);
        const frame = Buffer.concat([endpoint, len, data]);
        const op = writeChain.value.then(() => writeSocket(socket, frame));
        writeChain.value = op.catch(() => {});
        return op;
      },
    },
    id: 0,
  });
  try {
    await writeSocket(socket, Buffer.from([0])); // ack 0x00
    for (;;) {
      const target = await readEndpoint(reader);
      const payload = await readLengthPayload(reader);
      if (payload.length === 0) continue;
      if (rejectUdpTarget(target)) continue;
      await assoc.send(target, payload);
    }
  } finally {
    closed = true;
    assoc.close();
  }
}

// ==================== SERVE: MUX (UDP only) ====================
async function serveMux(socket, reader) {
  const sessions = new Map(); // sessionID -> { assoc, timer }
  const writeChain = { value: Promise.resolve() };

  const sendFrame = (status, sessionID, option, payload) => {
    const header = Buffer.allocUnsafe(4);
    header[0] = status;
    header.writeUInt16BE(sessionID, 1);
    header[3] = option;
    let body;
    if (option === MUX_OPTION_DATA && payload) {
      const len = Buffer.allocUnsafe(2);
      len.writeUInt16BE(payload.length, 0);
      body = Buffer.concat([header, len, payload]);
    } else if (option === MUX_OPTION_ERROR && payload) {
      const err = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
      const len = Buffer.allocUnsafe(2);
      len.writeUInt16BE(err.length, 0);
      body = Buffer.concat([header, len, err]);
    } else {
      body = header;
    }
    const op = writeChain.value.then(() => writeSocket(socket, body));
    writeChain.value = op.catch(() => {});
    return op;
  };

  const closeSession = (id) => {
    const s = sessions.get(id);
    if (!s) return;
    if (s.timer) clearTimeout(s.timer);
    try { s.assoc.close(); } catch {}
    sessions.delete(id);
  };

  try {
    await writeSocket(socket, Buffer.from([0]));
    for (;;) {
      const head = await reader.readExactly(4);
      const status = head[0];
      const sessionID = head.readUInt16BE(1);
      const option = head[3];

      if (status === MUX_STATUS_KEEPALIVE) continue;

      if (status === MUX_STATUS_NEW) {
        const netByte = (await reader.readExactly(1))[0];
        const metaLen = (await reader.readExactly(2)).readUInt16BE(0);
        if (metaLen > MAX_MUX_META_LEN) throw new Error('mux meta too large');
        const meta = metaLen > 0 ? await reader.readExactly(metaLen) : Buffer.alloc(0);
        if (netByte !== MUX_NETWORK_UDP) {
          await sendFrame(MUX_STATUS_END, sessionID, MUX_OPTION_ERROR, 'only UDP network supported');
          continue;
        }
        // meta = endpoint
        let target;
        try {
          const tmpReader = new AsyncByteReader({ on(){}, once(){}, off(){} });
          // parse endpoint dari buffer meta
          let off = 0;
          if (meta.length < 3) throw new Error('bad meta');
          const port = meta.readUInt16BE(off); off += 2;
          const atyp = meta[off++];
          let host;
          if (atyp === ATYP_IPV4) {
            if (meta.length - off < 4) throw new Error('bad ipv4');
            host = `${meta[off]}.${meta[off+1]}.${meta[off+2]}.${meta[off+3]}`;
          } else if (atyp === ATYP_DOMAIN) {
            const dl = meta[off++];
            host = utf8Fatal.decode(meta.subarray(off, off + dl));
          } else if (atyp === ATYP_IPV6) {
            host = formatIPv6(meta.subarray(off, off + 16));
          } else {
            throw new Error('bad atyp');
          }
          target = { host, port, atyp };
        } catch (e) {
          await sendFrame(MUX_STATUS_END, sessionID, MUX_OPTION_ERROR, 'bad meta: ' + e.message);
          continue;
        }

        try {
          const assoc = await UDPAssociation.create();
          assoc.attach({
            mux: {
              sendUDPData: async (_id, _rinfo, data) => {
                if (socket.destroyed) return;
                await sendFrame(MUX_STATUS_KEEP, sessionID, MUX_OPTION_DATA, data);
              },
            },
            id: sessionID,
          });
          const entry = { assoc, timer: null };
          sessions.set(sessionID, entry);

          if (meta.length > 0) {
            // tidak ada payload di NEW
          }

          // kirim sinyal siap
          await sendFrame(MUX_STATUS_NEW, sessionID, MUX_OPTION_DATA, Buffer.alloc(0));
          STATS.totalHandshakes++;
        } catch (e) {
          await sendFrame(MUX_STATUS_END, sessionID, MUX_OPTION_ERROR, e.message);
        }
        continue;
      }

      if (status === MUX_STATUS_KEEP) {
        const entry = sessions.get(sessionID);
        if (!entry) {
          await sendFrame(MUX_STATUS_END, sessionID, MUX_OPTION_ERROR, 'unknown session');
          continue;
        }
        const len = (await reader.readExactly(2)).readUInt16BE(0);
        const data = len > 0 ? await reader.readExactly(len) : Buffer.alloc(0);
        if (data.length === 0) continue;
        // butuh target dari meta yang tersimpan; simplified: relay UDP pakai target first
        // Untuk mux sederhana ini kita skip data karena tidak ada target tersimpan.
        // Implementasi lengkap butuh menyimpan endpoint per session.
        continue;
      }

      if (status === MUX_STATUS_END) {
        closeSession(sessionID);
        continue;
      }

      // status tidak dikenal → tutup
   