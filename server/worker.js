/**
 * WebBeam signaling pe Cloudflare Workers + Durable Objects (WebSocket Hibernation).
 *
 * Acelasi protocol ca server.js (Node), deci clientul nu se schimba:
 *   client -> server : {t:'join', room, auth, role} apoi {t:'sig', d}
 *   server -> client : {t:'joined', role, partner} | {t:'peer-joined'} | {t:'peer-left'} | {t:'sig', d} | {t:'error', code}
 *
 * O camera = un Durable Object (adresat dupa ID-ul din ?room=). Serverul vede doar ID-ul camerei,
 * hash(roomAuth) si mesaje "sig" opace; cheia (#key) nu ajunge niciodata aici.
 * Starea camerei (hash-ul de auth) e in storage; conexiunile "hiberneaza" cand nu se trimit mesaje.
 */

import { DurableObject } from 'cloudflare:workers';

const ROOM_RE = /^[A-Za-z0-9_-]{8,32}$/;
const AUTH_RE = /^[A-Za-z0-9_-]{43}$/;
const MAX_MSG = 64 * 1024;
const MAX_RELAY_FRAME = 80 * 1024; // cadru binar de relay: ciphertext E2EE de cel mult 64 KiB
const MAX_SIG_LEN = 48 * 1024;
const MAX_SOCKETS = 8;
const JOIN_TIMEOUT_MS = 5_000;
const EMPTY_ROOM_GRACE_MS = 60_000;
const ROOM_MAX_AGE_MS = 6 * 3600_000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/healthz') return new Response('ok', { headers: { 'cache-control': 'no-store' } });
    const allowed = (env.ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const origin = request.headers.get('Origin');
    const originOk = !allowed.length || (!!origin && allowed.includes(origin));

    if (url.pathname === '/turn') return turnCredentials(request, env, origin, originOk);
    if (url.pathname !== '/ws') return new Response('Not found', { status: 404 });
    if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
    if (!originOk) return new Response('Forbidden', { status: 403 });

    const room = url.searchParams.get('room') ?? '';
    if (!ROOM_RE.test(room)) return new Response('Bad room', { status: 400 });

    return env.ROOMS.get(env.ROOMS.idFromName(room)).fetch(request);
  },
};

/**
 * Credentiale TURN temporare de la Cloudflare Realtime (TURN_KEY_ID + TURN_KEY_API_TOKEN, ca secrete).
 * Fara secrete raspunde cu lista goala, iar clientul foloseste doar STUN. Doar pentru origini permise.
 */
async function turnCredentials(request, env, origin, originOk) {
  const headers = { 'cache-control': 'no-store', 'content-type': 'application/json' };
  if (origin && originOk) {
    headers['access-control-allow-origin'] = origin;
    headers['vary'] = 'Origin';
  }
  if (request.method !== 'GET') return new Response('Method not allowed', { status: 405 });
  if (!originOk) return new Response('Forbidden', { status: 403 });
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) return new Response('{"iceServers":[]}', { headers });
  try {
    const res = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(env.TURN_KEY_ID)}/credentials/generate-ice-servers`,
      {
        method: 'POST',
        headers: { authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ ttl: 6 * 3600 }),
      },
    );
    if (!res.ok) return new Response('{"iceServers":[]}', { headers });
    const data = await res.json();
    // doar serverele TURN; STUN-ul public il adauga clientul
    const turn = (Array.isArray(data.iceServers) ? data.iceServers : []).filter((s) => s.username && s.credential);
    return new Response(JSON.stringify({ iceServers: turn }), { headers });
  } catch {
    return new Response('{"iceServers":[]}', { headers });
  }
}

const isJoined = (ws) => !!ws.deserializeAttachment()?.role;
const otherRole = (role) => (role === 'host' ? 'guest' : 'host');

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export class Room extends DurableObject {
  async fetch(request) {
    if (this.ctx.getWebSockets().length >= MAX_SOCKETS) return new Response('Room busy', { status: 429 });
    const room = new URL(request.url).searchParams.get('room') ?? '';
    const { 0: client, 1: server } = new WebSocketPair();
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ room, role: null, at: Date.now() });
    await this.reschedule(); // timeout de join pentru conexiuni care nu trimit niciodata `join`
    return new Response(null, { status: 101, webSocket: client });
  }

  /* ------------------------------ mesaje ------------------------------ */

  async webSocketMessage(ws, message) {
    if (typeof message !== 'string') return this.relay(ws, message);
    if (message.length > MAX_MSG) return this.kick(ws, 4003, 'too-large');

    let msg;
    try {
      msg = JSON.parse(message);
    } catch {
      return this.kick(ws, 4003, 'bad-json');
    }
    if (typeof msg !== 'object' || msg === null) return this.kick(ws, 4003, 'bad-json');

    const att = ws.deserializeAttachment() ?? {};
    if (!att.role) {
      if (msg.t !== 'join') return this.kick(ws, 4003, 'join-first');
      return this.join(ws, att, msg);
    }
    if (msg.t === 'sig') {
      if (typeof msg.d !== 'string' || msg.d.length > MAX_SIG_LEN) return this.kick(ws, 4003, 'too-large');
      const partner = this.joinedPeers(ws).find((w) => w.deserializeAttachment().role === otherRole(att.role));
      if (partner) this.send(partner, { t: 'sig', d: msg.d }); // fara partener: ignorat
      return;
    }
    if (msg.t === 'ping') return this.send(ws, { t: 'pong' });
    this.kick(ws, 4003, 'unknown-type');
  }

  /**
   * Relay de rezerva cand P2P e blocat: cadre binare deja criptate E2EE (AES-GCM, contor anti-replay),
   * trimise partenerului imediat. Nu se citesc si nu se stocheaza nicaieri.
   */
  relay(ws, data) {
    const att = ws.deserializeAttachment() ?? {};
    if (!att.role) return this.kick(ws, 4003, 'bad-frame');
    if (data.byteLength > MAX_RELAY_FRAME) return this.kick(ws, 4003, 'too-large');
    const partner = this.joinedPeers(ws).find((w) => w.deserializeAttachment().role === otherRole(att.role));
    if (!partner) return;
    try {
      partner.send(data);
    } catch {
      /* partener inchis intre timp */
    }
  }

  async join(ws, att, msg) {
    const { room, auth, role } = msg;
    if (
      typeof room !== 'string' ||
      room !== att.room ||
      typeof auth !== 'string' ||
      !AUTH_RE.test(auth) ||
      (role !== 'host' && role !== 'guest')
    ) {
      return this.kick(ws, 4004, 'bad-join');
    }

    const authHash = await sha256hex(auth);
    const stored = await this.ctx.storage.get('authHash');
    if (!stored) {
      if (role !== 'host') return this.kick(ws, 4004, 'room-not-found'); // doar hostul creeaza camera
      await this.ctx.storage.put({ authHash, createdAt: Date.now() });
    } else if (!timingSafeEqual(stored, authHash)) {
      return this.kick(ws, 4004, 'bad-auth');
    }
    await this.ctx.storage.delete('emptySince');

    const peers = this.joinedPeers(ws);
    const partner = peers.find((w) => w.deserializeAttachment().role === otherRole(role));
    const old = peers.find((w) => w.deserializeAttachment().role === role);
    if (old) {
      // aceeasi parte s-a reconectat (reload, retea schimbata): o inlocuim pe cea veche
      old.serializeAttachment({ ...old.deserializeAttachment(), replaced: true });
      this.send(old, { t: 'error', code: 'replaced' });
      old.close(4000, 'replaced');
      if (partner) this.send(partner, { t: 'peer-left' });
    }

    ws.serializeAttachment({ room: att.room, role, at: att.at });
    this.send(ws, { t: 'joined', role, partner: !!partner });
    if (partner) this.send(partner, { t: 'peer-joined' });
    await this.reschedule();
  }

  /* ------------------------------ inchidere ------------------------------ */

  async webSocketClose(ws) {
    await this.onLeave(ws);
  }

  async webSocketError(ws) {
    await this.onLeave(ws);
  }

  async onLeave(ws) {
    const att = ws.deserializeAttachment();
    if (!att?.role || att.replaced) return; // inlocuit: partenerul a fost deja anuntat
    const partner = this.joinedPeers(ws).find((w) => w.deserializeAttachment().role === otherRole(att.role));
    if (partner) this.send(partner, { t: 'peer-left' });
    else await this.ctx.storage.put('emptySince', Date.now());
    await this.reschedule();
  }

  /* ------------------------------ expirare ------------------------------ */

  /** Un singur alarm, mereu setat la cel mai apropiat eveniment: expirarea camerei, GC camera goala, timeout join. */
  async reschedule() {
    const candidates = [];
    const created = await this.ctx.storage.get('createdAt');
    if (created) candidates.push(created + ROOM_MAX_AGE_MS);
    const emptySince = await this.ctx.storage.get('emptySince');
    if (emptySince) candidates.push(emptySince + EMPTY_ROOM_GRACE_MS);
    const unjoined = this.ctx.getWebSockets().filter((w) => w.readyState === 1 && !isJoined(w));
    if (unjoined.length) {
      candidates.push(Math.min(...unjoined.map((w) => w.deserializeAttachment().at)) + JOIN_TIMEOUT_MS);
    }
    if (candidates.length) await this.ctx.storage.setAlarm(Math.max(Date.now() + 500, Math.min(...candidates)));
  }

  async alarm() {
    const now = Date.now();
    const created = await this.ctx.storage.get('createdAt');
    const emptySince = await this.ctx.storage.get('emptySince');
    const sockets = this.ctx.getWebSockets();

    if ((created && now - created >= ROOM_MAX_AGE_MS) || (emptySince && now - emptySince >= EMPTY_ROOM_GRACE_MS)) {
      for (const ws of sockets) {
        try {
          ws.close(4001, 'room-expired');
        } catch {
          /* deja inchis */
        }
      }
      await this.ctx.storage.deleteAll();
      return;
    }
    for (const ws of sockets) {
      const a = ws.deserializeAttachment();
      if (ws.readyState === 1 && !a?.role && now - a.at >= JOIN_TIMEOUT_MS) this.kick(ws, 4002, 'join-timeout');
    }
    await this.reschedule();
  }

  /* ------------------------------ utilitare ------------------------------ */

  joinedPeers(except) {
    return this.ctx
      .getWebSockets()
      .filter((w) => w !== except && w.readyState === 1 && isJoined(w) && !w.deserializeAttachment().replaced);
  }

  send(ws, obj) {
    try {
      if (ws.readyState === 1) ws.send(JSON.stringify(obj));
    } catch {
      /* socket inchis intre timp */
    }
  }

  kick(ws, closeCode, code) {
    this.send(ws, { t: 'error', code });
    try {
      ws.close(closeCode, code);
    } catch {
      /* deja inchis */
    }
  }
}
