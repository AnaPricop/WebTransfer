import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';

const SERVER = fileURLToPath(new URL('../server/server.js', import.meta.url));
const AUTH_A = 'A'.repeat(43);
const AUTH_B = 'B'.repeat(43);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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
  closeCode: number | null = null;
  private waiters: Array<() => void> = [];
  constructor(url: string, origin?: string) {
    this.ws = new WebSocket(url, origin ? { origin } : undefined);
    this.ws.on('message', (d) => {
      this.inbox.push(JSON.parse(d.toString()));
      this.waiters.splice(0).forEach((w) => w());
    });
    this.ws.on('close', (code) => {
      this.closeCode = code;
      this.waiters.splice(0).forEach((w) => w());
    });
    this.ws.on('error', () => {});
  }
  open() {
    return once(this.ws, 'open');
  }
  send(o: unknown) {
    this.ws.send(JSON.stringify(o));
  }
  async next(timeout = 2000): Promise<any> {
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
  async join(room: string, role: 'host' | 'guest', auth = AUTH_A) {
    await this.open();
    this.send({ t: 'join', room, auth, role });
    return this.next();
  }
}

const PORT = 18787;
const URL_ = `ws://127.0.0.1:${PORT}/ws`;
let proc: ChildProcess;
const clients: Client[] = [];
const mk = (origin?: string, url = URL_) => {
  const c = new Client(url, origin);
  clients.push(c);
  return c;
};

before(async () => {
  proc = start(PORT);
  await waitHealthy(PORT);
});
after(() => {
  clients.forEach((c) => c.ws.terminate());
  proc.kill();
});

test('guest nu poate crea camera; host da', async () => {
  const g = mk();
  assert.equal((await g.join('room-guest-first', 'guest')).code, 'room-not-found');
  const h = mk();
  assert.deepEqual(await h.join('room-host-first', 'host'), { t: 'joined', role: 'host', partner: false });
});

test('join, relay in ambele sensuri, camera plina/inlocuire/auth gresit', async () => {
  const room = 'relay-room-1';
  const host = mk();
  assert.equal((await host.join(room, 'host')).partner, false);

  const guest = mk();
  assert.deepEqual(await guest.join(room, 'guest'), { t: 'joined', role: 'guest', partner: true });
  assert.deepEqual(await host.next(), { t: 'peer-joined' });

  host.send({ t: 'sig', d: 'oferta-opaca' });
  assert.deepEqual(await guest.next(), { t: 'sig', d: 'oferta-opaca' });
  guest.send({ t: 'sig', d: 'raspuns-opac' });
  assert.deepEqual(await host.next(), { t: 'sig', d: 'raspuns-opac' });

  // auth gresit pe o camera existenta
  const intruder = mk();
  assert.equal((await intruder.join(room, 'guest', AUTH_B)).code, 'bad-auth');

  // acelasi rol, auth corect => il inlocuieste pe cel vechi (reload)
  const guest2 = mk();
  assert.equal((await guest2.join(room, 'guest')).partner, true);
  assert.deepEqual(await guest.next(), { t: 'error', code: 'replaced' });
  assert.deepEqual(await host.next(), { t: 'peer-left' });
  assert.deepEqual(await host.next(), { t: 'peer-joined' });

  // plecarea unuia e anuntata celuilalt
  guest2.ws.close();
  assert.deepEqual(await host.next(), { t: 'peer-left' });
});

test('mesaje invalide: primul mesaj != join, binar, sig prea mare, camera invalida', async () => {
  const a = mk();
  await a.open();
  a.send({ t: 'sig', d: 'x' });
  assert.equal((await a.next()).code, 'join-first');

  const b = mk();
  await b.open();
  b.ws.send(Buffer.from([1, 2, 3]));
  assert.equal((await b.next()).code, 'bad-frame');

  const c = mk();
  assert.equal((await c.join('x', 'host')).code, 'bad-join');

  const h = mk();
  await h.join('big-sig-room1', 'host');
  h.send({ t: 'sig', d: 'z'.repeat(50_000) });
  assert.equal((await h.next()).code, 'too-large');
});

test('allowlist de origini', async () => {
  const p = start(PORT + 1, { ALLOWED_ORIGINS: 'https://webbeam.pages.dev' });
  try {
    await waitHealthy(PORT + 1);
    const u = `ws://127.0.0.1:${PORT + 1}/ws`;
    const bad = mk('https://evil.example', u);
    await assert.rejects(bad.open(), /403/);
    const none = mk(undefined, u);
    await assert.rejects(none.open(), /403/);
    const ok = mk('https://webbeam.pages.dev', u);
    assert.equal((await ok.join('origin-room-1', 'host')).t, 'joined');
  } finally {
    p.kill();
  }
});
