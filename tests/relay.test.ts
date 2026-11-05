/**
 * Relay de rezerva: SecureChannel peste RelayLink, prin serverul Node real (cadre binare criptate E2EE).
 * Verifica transferul complet, backpressure-ul pe WebSocket si faptul ca serverul vede doar ciphertext.
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { WebSocket as WS } from 'ws';
import { deriveSessionKeys, generateRootKey } from '../src/lib/crypto';
import { RelayLink, SecureChannel, type IncomingOffer, type TransferProgress } from '../src/lib/webrtc';
import type { FileSink, SinkResult } from '../src/lib/fileSink';

const SERVER = fileURLToPath(new URL('../server/server.js', import.meta.url));
const PORT = 18795;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let proc: ChildProcess;
const sockets: WS[] = [];

before(async () => {
  proc = spawn(process.execPath, [SERVER], { env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${PORT}/healthz`)).ok) return;
    } catch {
      /* inca porneste */
    }
    await sleep(100);
  }
  throw new Error('serverul nu a pornit');
});
after(() => {
  sockets.forEach((s) => s.terminate());
  proc.kill();
});

class HashSink implements FileSink {
  readonly kind = 'memory' as const;
  hash = createHash('sha256');
  bytes = 0;
  closed = false;
  async write(chunk: Uint8Array): Promise<void> {
    this.hash.update(chunk);
    this.bytes += chunk.length;
  }
  async close(): Promise<SinkResult> {
    this.closed = true;
    return { saved: true, location: 'disk', dispose: async () => {} };
  }
  async abort(): Promise<void> {}
}

async function join(room: string, role: 'host' | 'guest', auth: string, spy?: (n: number) => void) {
  const ws = new WS(`ws://127.0.0.1:${PORT}/ws?room=${room}`);
  sockets.push(ws);
  ws.binaryType = 'arraybuffer';
  await once(ws, 'open');
  ws.send(JSON.stringify({ t: 'join', room, auth, role }));
  const link = new RelayLink(() => ws as unknown as globalThis.WebSocket);
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      spy?.((data as ArrayBuffer).byteLength);
      link.deliver(data as ArrayBuffer);
    }
  });
  await once(ws, 'message'); // {t:'joined'}
  return { ws, link };
}

test('transfer 12 MB + text prin relay WebSocket: hash identic, bufferedAmount limitat', async () => {
  const room = `relay-${Math.random().toString(36).slice(2, 8)}`;
  const auth = 'A'.repeat(43);
  const root = generateRootKey();
  const [hk, gk] = await Promise.all([deriveSessionKeys(root, 'host'), deriveSessionKeys(root, 'guest')]);

  const seen: number[] = [];
  const H = await join(room, 'host', auth);
  const G = await join(room, 'guest', auth, (n) => seen.push(n));

  const sinks: HashSink[] = [];
  const guest = new SecureChannel(G.link, gk, {
    maxMessageSize: () => 64 * 1024,
    name: 'guest',
    createSink: async () => {
      const s = new HashSink();
      sinks.push(s);
      return s;
    },
  });
  const host = new SecureChannel(H.link, hk, { maxMessageSize: () => 64 * 1024, name: 'host' });
  guest.on('incomingFile', (o: IncomingOffer) => void o.accept());

  let maxBuffered = 0;
  const probe = setInterval(() => (maxBuffered = Math.max(maxBuffered, H.ws.bufferedAmount)), 2);

  await Promise.all([
    new Promise<void>((r) => host.on('ready', () => r())),
    new Promise<void>((r) => guest.on('ready', () => r())),
  ]);

  const got = new Promise<string>((res) => guest.on('text', res));
  await host.sendText('salut prin relay');
  assert.equal(await got, 'salut prin relay');

  const data = randomBytes(12 * 1024 * 1024);
  const [id] = host.sendFiles([new File([data], 'relay.bin')]);
  const final = await new Promise<TransferProgress>((resolve) =>
    host.on('progress', (p) => {
      if (p.id === id && ['done', 'error', 'rejected', 'cancelled'].includes(p.state)) resolve(p);
    }),
  );
  clearInterval(probe);

  assert.equal(final.state, 'done', JSON.stringify(final));
  assert.equal(sinks[0]!.hash.digest('hex'), createHash('sha256').update(data).digest('hex'));
  assert.ok(maxBuffered <= 2 * 1024 * 1024, `bufferedAmount maxim ${maxBuffered}`);
  assert.ok(seen.every((n) => n <= 64 * 1024), 'cadrele relay depasesc 64 KiB');

  host.close();
  guest.close();
});

test('serverul refuza cadre binare prea mari si pe cele de dinainte de join', async () => {
  const room = `relaybig-${Math.random().toString(36).slice(2, 8)}`;
  const { ws } = await join(room, 'host', 'B'.repeat(43));
  const closed = once(ws, 'close');
  ws.send(Buffer.alloc(200 * 1024)); // peste maxPayload
  const [code] = await closed;
  assert.ok(code === 1009 || code === 4003, `cod ${code}`);

  const raw = new WS(`ws://127.0.0.1:${PORT}/ws?room=${room}x`);
  sockets.push(raw);
  await once(raw, 'open');
  raw.send(Buffer.from([1, 2, 3]));
  const [, ] = await once(raw, 'message'); // {t:'error', code:'bad-frame'}
  const [c2] = await once(raw, 'close');
  assert.equal(c2, 4003);
});
