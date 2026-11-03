/**
 * Teste pentru serverul de signaling. Rulate implicit pe server/server.js (pornit de test).
 * Aceleasi teste ruleaza si pe Worker-ul Cloudflare:
 *   (in server/)  npx wrangler dev --port 8788
 *   TARGET_URL=ws://127.0.0.1:8788/ws npm test
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';

const SERVER = fileURLToPath(new URL('../server/server.js', import.meta.url));
const AUTH_A = 'A'.repeat(43);
const AUTH_B = 'B'.repeat(43);
const TARGET = process.env.TARGET_URL; // daca e setat, nu pornim serverul Node
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const rid = (name: string) => `${name}-${Math.random().toString(36).slice(2, 8)}`; // camere noi la fiecare rulare

function start(port: number, env: Record<string, string> = {}): ChildProcess {
  return spawn(process.execPath, [SERVER], { env: { ...process.env, PORT: String(port), ...env }, stdio: 'ignore' });
}

async function waitHealthy(port: number) {
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/healthz`)).ok) return;
    } catch {
      /* inca porneste */
    }
    await sleep(100);
  }
  throw new Error('serverul nu a pornit');
}

class Client {
  ws: WebSocket;
  inbox: any[] = [];
  private waiters: Array<() => void> = [];
  constructor(
    url: string,
    readonly room: string,
    origin?: string,
  ) {
    // ID-ul camerei si in URL: Worker-ul il foloseste pentru rutare; serverul Node il ignora
    this.ws = new WebSocket(`${url}?room=${room}`, origin ? { origin } : undefined);
    this.ws.on('message', (d) => {
      this.inbox.push(JSON.parse(d.toString()));
      this.waiters.splice(0).forEach((w) => w());
    });
    this.ws.on('close', () => this.waiters.splice(0).forEach((w) => w()));
    this.ws.on('error', () => {});
  }
  open() {
    return once(this.ws, 'open');
  }
  send(o: unknown) {
    this.ws.send(JSON.stringify(o));
  }
  async next(timeout = 3000): Promise<any> {
    const end = Date.now() + timeout;
    while (!this.inbox.length) {
      if (Date.now() > end) throw new Error('timeout asteptand mesaj');
      await new Promise<void>((r) => {
        this.waiters.push(r);
        setTimeout(r, 50);
      });
    }
    return this.inbox.shift();
  }
  async join(role: 'host' | 'guest', auth = AUTH_A, roomInMsg = this.room) {
    await this.open();
    this.send({ t: 'join', room: roomInMsg, auth, role });
    return this.next();
  }
}

const PORT = 18787;
const URL_ = TARGET ?? `ws://127.0.0.1:${PORT}/ws`;
let proc: ChildProcess | undefined;
const clients: Client[] = [];
const mk = (room: string, origin?: string, url = URL_) => {
  const c = new Client(url, room, origin);
  clients.push(c);
  return c;
};

before(async () => {
  if (TARGET) return;
  proc = start(PORT);
  await waitHealthy(PORT);
});
after(() => {
  clients.forEach((c) => c.ws.terminate());
  proc?.kill();
});

test('guest nu poate crea camera; host da', async () => {
  const g = mk(rid('guestfirst'));
  assert.equal((await g.join('guest')).code, 'room-not-found');
  const h = mk(rid('hostfirst'));
  assert.deepEqual(await h.join('host'), { t: 'joined', role: 'host', partner: false });
});

test('join, relay in ambele sensuri, auth gresit, inlocuire, plecare', async () => {
  const room = rid('relayroom');
  const host = mk(room);
  assert.equal((await host.join('host')).partner, false);

  const guest = mk(room);
  assert.deepEqual(await guest.join('guest'), { t: 'joined', role: 'guest', partner: true });
  assert.deepEqual(await host.next(), { t: 'peer-joined' });

  host.send({ t: 'sig', d: 'oferta-opaca' });
  assert.deepEqual(await guest.next(), { t: 'sig', d: 'oferta-opaca' });
  guest.send({ t: 'sig', d: 'raspuns-opac' });
  assert.deepEqual(await host.next(), { t: 'sig', d: 'raspuns-opac' });

  // auth gresit pe o camera existenta
  const intruder = mk(room);
  assert.equal((await intruder.join('guest', AUTH_B)).code, 'bad-auth');

  // acelasi rol, auth corect => il inlocuieste pe cel vechi (reload)
  const guest2 = mk(room);
  assert.equal((await guest2.join('guest')).partner, true);
  assert.deepEqual(await guest.next(), { t: 'error', code: 'replaced' });
  assert.deepEqual(await host.next(), { t: 'peer-left' });
  assert.deepEqual(await host.next(), { t: 'peer-joined' });

  // plecarea unuia e anuntata celuilalt
  guest2.ws.close();
  assert.deepEqual(await host.next(), { t: 'peer-left' });
});

test('mesaje invalide: primul mesaj != join, binar, sig prea mare, camera din mesaj != camera din URL', async () => {
  const a = mk(rid('invalida'));
  await a.open();
  a.send({ t: 'sig', d: 'x' });
  assert.equal((await a.next()).code, 'join-first');

  const b = mk(rid('invalidb'));
  await b.open();
  b.ws.send(Buffer.from([1, 2, 3]));
  assert.equal((await b.next()).code, 'bad-frame');

  const c = mk(rid('invalidc'));
  assert.equal((await c.join('host', AUTH_A, 'x')).code, 'bad-join');

  const h = mk(rid('bigsigroom'));
  await h.join('host');
  h.send({ t: 'sig', d: 'z'.repeat(50_000) });
  assert.equal((await h.next()).code, 'too-large');
});

test('allowlist de origini (doar serverul Node pornit de test)', { skip: !!TARGET }, async () => {
  const p = start(PORT + 1, { ALLOWED_ORIGINS: 'https://webbeam.pages.dev' });
  try {
    await waitHealthy(PORT + 1);
    const u = `ws://127.0.0.1:${PORT + 1}/ws`;
    const bad = mk(rid('originbad'), 'https://evil.example', u);
    await assert.rejects(bad.open(), /403/);
    const none = mk(rid('originnone'), undefined, u);
    await assert.rejects(none.open(), /403/);
    const ok = mk(rid('originok'), 'https://webbeam.pages.dev', u);
    assert.equal((await ok.join('host')).t, 'joined');
  } finally {
    p.kill();
  }
});
