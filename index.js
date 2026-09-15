#!/usr/bin/env node
'use strict';
// ====================================================================
// VLRLY004 UDP RELAY via WebSocket (single file)
// ====================================================================

const net = require('node:net');
const dgram = require('node:dgram');
const dns = require('node:dns').promises;
const http = require('node:http');
const { EventEmitter } = require('node:events');
const { WebSocketServer } = require('ws');

// ==================== CONFIG ====================
const CONFIG = Object.freeze({
  LISTEN_HOST: '0.0.0.0',
  LISTEN_PORT: parseInt(process.env.PORT, 10) || 8080,
  WS_PATH: process.env.WS_PATH || '/',
  MAX_WS_MESSAGE_BYTES: 4 * 1024 * 1024,
  HANDSHAKE_TIMEOUT_MS: 10000,
  IDLE_TIMEOUT_MS: 300000,
  XUDP_GRACE_MS: 60000,
  MAX_CONNECTIONS: 4096,
  REJECT_UDP_443: false,
  SECRET: process.env.RELAY_SECRET || '',
});

// ==================== STATS ====================
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
  STATS.recentLogs.unshift('[' + time + '] ' + msg);
  if (STATS.recentLogs.length > 60) STATS.recentLogs.pop();
}

// ==================== PROTOCOL CONSTANTS ====================
const RELAY_MAGIC = Buffer.from('VLRLY004', 'ascii');
const RELAY_MODE_FIXED_UDP  = 0x01;
const RELAY_MODE_MUX        = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const ATYP_IPV4   = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6   = 0x03;
const MAX_PACKET_LEN = 65535;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

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
    if (!Number.isInteger(length) || length < 0) {
      return Promise.reject(new Error('invalid read length'));
    }
    if (length === 0) return Promise.resolve(Buffer.alloc(0));
    if (this.available >= length) return Promise.resolve(this._take(length));
    if (this.error) return Promise.reject(this.error);
    if (this.ended) return Promise.reject(new Error('unexpected EOF'));

    return new Promise((resolve, reject) => {
      this.waiters.push({ length: length, resolve: resolve, reject: reject });
    });
  }

  _flush() {
    while (this.waiters.length > 0) {
      const w = this.waiters[0];
      if (this.available >= w.length) {
        this.waiters.shift();
        w.resolve(this._take(w.length));
        continue;
      }
      if (this.error || this.ended) {
        this.waiters.shift();
        w.reject(this.error || new Error('unexpected EOF'));
        continue;
      }
      break;
    }
  }

  _take(length) {
    const out = Buffer.allocUnsafe(length);
    let off = 0;
    while (off < length) {
      const first = this.buffers[0];
      const need = length - off;
      if (first.length <= need) {
        first.copy(out, off);
        off += first.length;
        this.buffers.shift();
      } else {
        first.copy(out, off, 0, need);
        this.buffers[0] = first.subarray(need);
        off += need;
      }
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
    return { host: b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3], port: port, atyp: atyp };
  }
  if (atyp === ATYP_DOMAIN) {
    const len = (await reader.readExactly(1))[0];
    if (len === 0) throw new Error('empty domain');
    const b = await reader.readExactly(len);
    let host;
    try {
      host = utf8Fatal.decode(b);
    } catch (e) {
      throw new Error('invalid UTF-8 domain');
    }
    if (!host) throw new Error('empty domain');
    return { host: host, port: port, atyp: atyp };
  }
  if (atyp === ATYP_IPV6) {
    const b = await reader.readExactly(16);
    return { host: formatIPv6(b), port: port, atyp: atyp };
  }
  throw new Error('unknown address type ' + atyp);
}

function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(bytes.readUInt16BE(i).toString(16));
  }
  return parts.join(':');
}

function ipv6ToBytes(address) {
  let input = address;
  const zone = input.indexOf('%');
  if (zone >= 0) input = input.slice(0, zone);

  const lastColon = input.lastIndexOf(':');
  if (input.includes('.') && lastColon >= 0) {
    const ipv4 = input.slice(lastColon + 1).split('.').map(Number);
    if (ipv4.length !== 4 || ipv4.some(function (n) { return !Number.isInteger(n) || n < 0 || n > 255; })) {
      throw new Error('invalid IPv6: ' + address);
    }
    input = input.slice(0, lastColon) + ':' +
      (((ipv4[0] << 8) | ipv4[1]).toString(16)) + ':' +
      (((ipv4[2] << 8) | ipv4[3]).toString(16));
  }
  const halves = input.split('::');
  if (halves.length > 2) throw new Error('invalid IPv6: ' + address);
  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = (halves.length === 2 && halves[1]) ? halves[1].split(':').filter(Boolean) : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error('invalid IPv6: ' + address);
  }
  const words = left.concat(Array(Math.max(0, missing)).fill('0')).concat(right);
  if (words.length !== 8) throw new Error('invalid IPv6: ' + address);

  const out = Buffer.alloc(16);
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (!/^[0-9a-f]{1,4}$/i.test(word)) throw new Error('invalid IPv6: ' + address);
    out.writeUInt16BE(parseInt(word, 16), i * 2);
  }
  return out;
}

function encodeUDPSource(rinfo) {
  const port = Number(rinfo.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('invalid UDP source port');
  }
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
  throw new Error('invalid UDP source IP: ' + rinfo.address);
}

function rejectUdpTarget(target) {
  return Boolean(CONFIG.REJECT_UDP_443 && Number(target && target.port) === 443);
}

function writeSocket(socket, data) {
  if (socket.destroyed || !socket.writable) {
    return Promise.reject(new Error('socket is closed'));
  }
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => err ? reject(err) : resolve());
  });
}

async function writeControlError(socket, message) {
  let body = Buffer.from(String(message || 'relay error'), 'utf8');
  if (body.length > MAX_PACKET_LEN) body = body.subarray(0, MAX_PACKET_LEN);
  const out = Buffer.allocUnsafe(3 + body.length);
  out[0] = 1;
  out.writeUInt16BE(body.length, 1);
  body.copy(out, 3);
  try { await writeSocket(socket, out); } catch (e) {}
}

async function readControl(reader) {
  const magic = await reader.readExactly(RELAY_MAGIC.length);
  if (!magic.equals(RELAY_MAGIC)) throw new Error('bad magic');
  const mode = (await reader.readExactly(1))[0];
  if (mode !== RELAY_MODE_FIXED_UDP &&
      mode !== RELAY_MODE_MUX &&
      mode !== RELAY_MODE_PACKET_UDP) {
    throw new Error('bad mode');
  }
  const target = mode === RELAY_MODE_FIXED_UDP ? await readEndpoint(reader) : null;
  return { mode: mode, target: target };
}

// ==================== UDP ====================
async function resolveTarget(target) {
  if (target.atyp === ATYP_IPV4) return { address: target.host, family: 4 };
  if (target.atyp === ATYP_IPV6) return { address: target.host, family: 6 };
  const records = await dns.lookup(target.host, { all: true, verbatim: true });
  if (!records.length) throw new Error('DNS returned no address for ' + target.host);
  const preferred = records.find(function (r) { return r.family === 4; }) ||
                    records.find(function (r) { return r.family === 6; });
  if (!preferred) throw new Error('DNS returned unsupported address for ' + target.host);
  return preferred;
}

function bindDgram(socket, port, address) {
  return new Promise((resolve, reject) => {
    const onError = (err) => { cleanup(); reject(err); };
    const onListening = () => { cleanup(); resolve(); };
    function cleanup() {
      socket.off('error', onError);
      socket.off('listening', onListening);
    }
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
    } catch (e) {
      try { assoc.udp6.close(); } catch (e2) {}
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
    if (payload.length > MAX_PACKET_LEN) {
      throw new Error('UDP payload too large: ' + payload.length);
    }
    const resolved = await resolveTarget(target);
    const socket = resolved.family === 6 ? this.udp6 : this.udp4;
    if (!socket) throw new Error('UDP IPv' + resolved.family + ' is unavailable on this host');

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
    if (this.udp4) { try { this.udp4.close(); } catch (e) {} }
    if (this.udp6) { try { this.udp6.close(); } catch (e) {} }
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
    await writeSocket(socket, Buffer.from([0]));
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
        if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) {
          return Promise.resolve();
        }
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
    await writeSocket(socket, Buffer.from([0]));
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

// ==================== WEBSOCKET ADAPTER ====================
function wrapWebSocket(ws) {
  const emitter = new EventEmitter();

  const socket = {
    _destroyed: false,
    _writable: true,

    get destroyed() { return this._destroyed; },
    get writable() { return this._writable && ws.readyState === ws.OPEN; },

    on: function (event, handler) { emitter.on(event, handler); return this; },
    once: function (event, handler) { emitter.once(event, handler); return this; },
    off: function (event, handler) { emitter.off(event, handler); return this; },
    removeListener: function (event, handler) { emitter.off(event, handler); return this; },

    write: function (data, cb) {
      if (this._destroyed || ws.readyState !== ws.OPEN) {
        const err = new Error('socket is closed');
        if (typeof cb === 'function') { cb(err); return false; }
        throw err;
      }
      try {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        ws.send(buf);
        if (typeof cb === 'function') cb();
        return true;
      } catch (err) {
        if (typeof cb === 'function') { cb(err); return false; }
        throw err;
      }
    },

    end: function () { try { ws.close(); } catch (e) {} },

    destroy: function () {
      if (this._destroyed) return;
      this._destroyed = true;
      this._writable = false;
      try { ws.close(); } catch (e) {}
      emitter.emit('close');
    },
  };

  ws.on('message', (data) => {
    let buf;
    if (Buffer.isBuffer(data)) buf = data;
    else if (data instanceof ArrayBuffer) buf = Buffer.from(data);
    else if (ArrayBuffer.isView(data)) buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    else buf = Buffer.from(String(data), 'utf8');
    emitter.emit('data', buf);
  });

  ws.on('close', () => {
    if (socket._destroyed) return;
    socket._destroyed = true;
    socket._writable = false;
    emitter.emit('end');
    emitter.emit('close');
  });

  ws.on('error', (err) => emitter.emit('error', err));

  return socket;
}

// ==================== CONNECTION HANDLER ====================
async function handleConnection(socket) {
  STATS.activeClients++;
  socket.on('error', () => {});

  const reader = new AsyncByteReader(socket);

  try {
    const ctrl = await readControl(reader);
    STATS.totalHandshakes++;

    const tgtInfo = ctrl.target ? ' target=' + ctrl.target.host + ':' + ctrl.target.port : '';
    addLog('client connected mode=0x' + ctrl.mode.toString(16) + tgtInfo);

    if (ctrl.mode === RELAY_MODE_FIXED_UDP) {
      await serveDirectUDP(socket, reader, ctrl.target);
    } else if (ctrl.mode === RELAY_MODE_PACKET_UDP) {
      await servePacketUDP(socket, reader);
    } else if (ctrl.mode === RELAY_MODE_MUX) {
      throw new Error('MUX mode not supported in this build');
    } else {
      throw new Error('unsupported mode ' + ctrl.mode);
    }
  } catch (err) {
    const msg = (err && err.message) ? err.message : String(err);
    if (msg !== 'unexpected EOF' && !/closed/i.test(msg)) {
      addLog('[!] handler error: ' + msg);
      try { await writeControlError(socket, msg); } catch (e) {}
    }
  } finally {
    STATS.activeClients = Math.max(0, STATS.activeClients - 1);
    try { socket.destroy(); } catch (e) {}
  }
}

// ==================== HTTP + WS SERVER ====================
const httpServer = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/health' || req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      uptime: Math.round((Date.now() - STATS.startTime) / 1000),
      activeClients: STATS.activeClients,
      totalHandshakes: STATS.totalHandshakes,
      udp: {
        packetsOut: STATS.udpPacketsOut,
        bytesOut: STATS.udpBytesOut,
        packetsIn: STATS.udpPacketsIn,
        bytesIn: STATS.udpBytesIn,
      },
      wsPath: CONFIG.WS_PATH,
    }));
    return;
  }
  if (req.url === '/logs') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(STATS.recentLogs.join('\n') || '(empty)');
    return;
  }
  res.writeHead(404);
  res.end('Not found');
});

const wssOptions = { server: httpServer, maxPayload: CONFIG.MAX_WS_MESSAGE_BYTES };
if (CONFIG.WS_PATH && CONFIG.WS_PATH !== '' && CONFIG.WS_PATH !== '/') {
  wssOptions.path = CONFIG.WS_PATH;
}
const wss = new WebSocketServer(wssOptions);

let connCount = 0;

httpServer.on('upgrade', (req, socket, head) => {
  if (CONFIG.SECRET) {
    const token = req.headers['x-relay-secret'] || '';
    if (token !== CONFIG.SECRET) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
  }
  if (connCount >= CONFIG.MAX_CONNECTIONS) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy();
  }
});

wss.on('connection', (ws) => {
  connCount++;
  ws.on('close', () => { connCount = Math.max(0, connCount - 1); });
  handleConnection(wrapWebSocket(ws));
});

wss.on('error', (err) => addLog('[!] wss error: ' + err.message));

// ==================== START ====================
httpServer.listen(CONFIG.LISTEN_PORT, CONFIG.LISTEN_HOST, () => {
  const msg = 'VLRLY004 WS relay listening on ' + CONFIG.LISTEN_HOST + ':' +
              CONFIG.LISTEN_PORT + ' (path=' + (CONFIG.WS_PATH || '(any)') + ')';
  console.log(msg);
  addLog(msg);
});

// ==================== SHUTDOWN ====================
function shutdown(sig) {
  addLog('received ' + sig + ', shutting down...');
  try { wss.close(); } catch (e) {}
  try { httpServer.close(); } catch (e) {}
  setTimeout(() => process.exit(0), 500).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('un