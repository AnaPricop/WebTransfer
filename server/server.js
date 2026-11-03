/**
 * WebBeam signaling server (Node 20+, dependinta unica: `ws`)
 *
 * Ce vede serverul:   room id, hash(roomAuth), mesaje "sig" OPACE (SDP/ICE criptate AES-GCM in browser).
 * Ce NU vede:         cheia camerei (#key ramane in browser), continutul transferurilor, IP-urile din ICE.
 * Ce nu logheaza:     IP-uri, id-uri de camera, payload-uri.
 *
 * Reguli:
 *   - doar `host` poate crea o camera; `guest` poate intra doar intr-o camera existenta
 *   - max 1 host + 1 guest; la reconectarea aceluiasi rol, conexiunea veche e inlocuita
 *   - intrarea cere roomAuth (derivat din cheie) -> un strain care ghiceste ID-ul nu poate ocupa locul
 *   - rate limit per conexiune, limita de conexiuni per IP, blocare temporara dupa join-uri esuate
 *   - camere efemere: sterse dupa 60 s fara nimeni si dupa ROOM_MAX_AGE_MS
 *
 * Env: PORT (8787), ALLOWED_ORIGINS ("https://webbeam.pages.dev,https://exemplu.ro"),
 *      TRUST_PROXY=1 (exact un proxy in fata, ex. Render/Fly/Cloudflare), ROOM_MAX_AGE_MS, MAX_ROOMS, MAX_CONNS_PER_IP
 */

import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';

const env = process.env;
const PORT = Number(env.PORT ?? 8787);
const ALLOWED_ORIGINS = (env.ALLOWED_ORIGINS ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const TRUST_PROXY = env.TRUST_PROXY === '1';
const ROOM_MAX_AGE_MS = Number(env.ROOM_MAX_AGE_MS ?? 6 * 3600_000);
const MAX_ROOMS = Number(env.MAX_ROOMS ?? 5000);
const MAX_CONNS_PER_IP = Number(env.MAX_CONNS_PER_IP ?? 20);

const MAX_PAYLOAD = 64 * 1024;
const MAX_SIG_LEN = 48 * 1024;
const JOIN_TIMEOUT_MS = 5_000;
const SWEEP_MS = 15_000;
const EMPTY_ROOM_GRACE_MS = 60_000;
const MAX_FAILED_JOINS_PER_MIN = 20;
const BURST = 120; // mesaje
const REFILL_PER_SEC = 30;

const ROOM_RE = /^[A-Za-z0-9_-]{8,32}$/;
const AUTH_RE = /^[A-Za-z0-9_-]{43}$/;

/** @type {Map<string, {id:string, authHash:Buffer, peers:{host:any,guest:any}, createdAt:number, gcTimer:any}>} */
const rooms = new Map();
/** @type {Set<any>} */
const conns = new Set();
const ipConns = new Map();
const ipFails = new Map();

const sha256 = (s) => crypto.createHash('sha256').update(s).digest();

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = String(req.headers['x-forwarded-for'] ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (xff.length) return xff[xff.length - 1]; // adaugat de proxy-ul nostru; cel din stanga poate fi falsificat
  }
  return req.socket.remoteAddress ?? 'unknown';
}

function noteFail(ip) {
  const now = Date.now();
  let f = ipFails.get(ip);
  if (!f || f.resetAt < now) ipFails.set(ip, (f = { n: 0, resetAt: now + 60_000 }));
  return ++f.n > MAX_FAILED_JOINS_PER_MIN;
}
function isBlocked(ip) {
  const f = ipFails.get(ip);
  return !!f && f.resetAt > Date.now() && f.n > MAX_FAILED_JOINS_PER_MIN;
}

function takeToken(c) {
  const now = Date.now();
  c.tokens = Math.min(BURST, c.tokens + ((now - c.ts) / 1000) * REFILL_PER_SEC);
  c.ts = now;
  if (c.tokens < 1) return false;
  c.tokens -= 1;
  return true;
}

function send(c, obj) {
  if (c && c.ws.readyState === 1) c.ws.send(JSON.stringify(obj));
}

function kick(c, closeCode, code) {
  send(c, { t: 'error', code });
  try {
    c.ws.close(closeCode, code);
  } catch {
    /* deja inchis */
  }
}

const otherRole = (role) => (role === 'host' ? 'guest' : 'host');

/* ------------------------------ HTTP / upgrade ------------------------------ */

const server = http.createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
    return res.end('ok');
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD, perMessageDeflate: false });

function rejectUpgrade(socket, code) {
  socket.write(`HTTP/1.1 ${code} ${http.STATUS_CODES[code]}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

server.on('upgrade', (req, socket, head) => {
  const path = (req.url ?? '/').split('?')[0];
  if (path !== '/ws') return rejectUpgrade(socket, 404);
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.length && (!origin || !ALLOWED_ORIGINS.includes(origin))) return rejectUpgrade(socket, 403);
  const ip = clientIp(req);
  if (isBlocked(ip) || (ipConns.get(ip) ?? 0) >= MAX_CONNS_PER_IP) return rejectUpgrade(socket, 429);
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, ip));
});

/* ------------------------------ conexiuni ------------------------------ */

wss.on('connection', (ws, ip) => {
  const c = { ws, ip, room: null, role: null, alive: true, tokens: BURST, ts: Date.now() };
  conns.add(c);
  ipConns.set(ip, (ipConns.get(ip) ?? 0) + 1);

  const joinTimer = setTimeout(() => {
    if (!c.room) kick(c, 4002, 'join-timeout');
  }, JOIN_TIMEOUT_MS);

  ws.on('pong', () => (c.alive = true));

  ws.on('message', (raw, isBinary) => {
    if (isBinary) return kick(c, 4003, 'bad-frame');
    if (!takeToken(c)) return kick(c, 4029, 'rate-limited');
    let msg;
    try {
      msg = JSON.parse(raw.toString('utf8'));
    } catch {
      return kick(c, 4003, 'bad-json');
    }
    if (typeof msg !== 'object' || msg === null) return kick(c, 4003, 'bad-json');

    if (!c.room) {
      if (msg.t !== 'join') return kick(c, 4003, 'join-first');
      return handleJoin(c, msg);
    }
    if (msg.t === 'sig') return handleSig(c, msg);
    if (msg.t === 'ping') return send(c, { t: 'pong' });
    kick(c, 4003, 'unknown-type');
  });

  ws.on('close', () => {
    clearTimeout(joinTimer);
    conns.delete(c);
    const n = (ipConns.get(ip) ?? 1) - 1;
    if (n <= 0) ipConns.delete(ip);
    else ipConns.set(ip, n);
    leave(c);
  });

  ws.on('error', () => {});
});

function handleJoin(c, msg) {
  const { room: roomId, auth, role } = msg;
  if (typeof roomId !== 'string' || typeof auth !== 'string' || !ROOM_RE.test(roomId) || !AUTH_RE.test(auth) ||
      (role !== 'host' && role !== 'guest')) {
    return failJoin(c, 'bad-join');
  }

  let room = rooms.get(roomId);
  if (!room) {
    if (role !== 'host') return failJoin(c, 'room-not-found');
    if (rooms.size >= MAX_ROOMS) return kick(c, 4013, 'server-busy');
    room = { id: roomId, authHash: sha256(auth), peers: { host: null, guest: null }, createdAt: Date.now(), gcTimer: null };
    rooms.set(roomId, room);
  } else if (!crypto.timingSafeEqual(room.authHash, sha256(auth))) {
    return failJoin(c, 'bad-auth');
  }

  if (room.gcTimer) {
    clearTimeout(room.gcTimer);
    room.gcTimer = null;
  }

  const other = room.peers[otherRole(role)];
  const old = room.peers[role];
  if (old && old !== c) {
    // aceeasi parte s-a reconectat (reload, retea schimbata): o inlocuim pe cea veche
    room.peers[role] = null;
    old.room = null;
    send(old, { t: 'error', code: 'replaced' });
    try {
      old.ws.close(4000, 'replaced');
    } catch {
      /* deja inchis */
    }
    send(other, { t: 'peer-left' });
  }

  room.peers[role] = c;
  c.room = room;
  c.role = role;
  send(c, { t: 'joined', role, partner: !!other });
  send(other, { t: 'peer-joined' });
}

function failJoin(c, code) {
  const blocked = noteFail(c.ip);
  kick(c, blocked ? 4029 : 4004, blocked ? 'rate-limited' : code);
}

function handleSig(c, msg) {
  if (typeof msg.d !== 'string' || msg.d.length > MAX_SIG_LEN) return kick(c, 4003, 'too-large');
  const partner = c.room.peers[otherRole(c.role)];
  if (partner) send(partner, { t: 'sig', d: msg.d }); // fara partener: ignorat (hostul oferta abia dupa peer-joined)
}

function leave(c) {
  const room = c.room;
  if (!room || room.peers[c.role] !== c) return; // deja inlocuit
  room.peers[c.role] = null;
  c.room = null;
  const partner = room.peers[otherRole(c.role)];
  if (partner) return send(partner, { t: 'peer-left' });
  room.gcTimer = setTimeout(() => destroyRoom(room, 'room-expired'), EMPTY_ROOM_GRACE_MS);
  room.gcTimer.unref?.();
}

function destroyRoom(room, code) {
  if (room.gcTimer) clearTimeout(room.gcTimer);
  if (rooms.get(room.id) === room) rooms.delete(room.id);
  for (const role of ['host', 'guest']) {
    const p = room.peers[role];
    room.peers[role] = null;
    if (p) {
      p.room = null;
      kick(p, 4001, code);
    }
  }
}

/* ------------------------------ intretinere ------------------------------ */

const sweep = setInterval(() => {
  const now = Date.now();
  for (const c of conns) {
    if (!c.alive) {
      c.ws.terminate();
      continue;
    }
    c.alive = false;
    try {
      c.ws.ping();
    } catch {
      /* socket inchis intre timp */
    }
  }
  for (const room of rooms.values()) if (now - room.createdAt > ROOM_MAX_AGE_MS) destroyRoom(room, 'room-expired');
  for (const [ip, f] of ipFails) if (f.resetAt < now) ipFails.delete(ip);
}, SWEEP_MS);
sweep.unref();

function shutdown() {
  clearInterval(sweep);
  for (const c of conns) c.ws.close(1001, 'server-restart');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(PORT, () => console.log(`WebBeam signaling pe :${PORT} (origini: ${ALLOWED_ORIGINS.join(', ') || 'toate - doar pentru dev'})`));
