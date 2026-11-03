import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { deriveSessionKeys, generateRootKey } from '../src/lib/crypto';
import {
  BUFFER_HIGH,
  RX_WINDOW,
  SecureChannel,
  type IncomingOffer,
  type TransferProgress,
} from '../src/lib/webrtc';
import type { FileSink, SinkResult } from '../src/lib/fileSink';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const allDcs: FakeDC[] = [];
after(() => allDcs.forEach((d) => d.stop()));

/** RTCDataChannel fals: viteza limitata, bufferedAmount real, bufferedamountlow, hook pentru sabotaj. */
class FakeDC {
  readyState = 'open';
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  binaryType = 'blob';
  maxBuffered = 0;
  deliveredBytes = 0;
  sent = 0;
  mangle: ((n: number, data: Uint8Array) => void) | null = null;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((ev: { data: ArrayBuffer }) => void) | null = null;
  onbufferedamountlow: (() => void) | null = null;
  peer!: FakeDC;
  private queue: Uint8Array[] = [];
  private credit = 0;
  private timer: ReturnType<typeof setInterval>;

  constructor(private readonly bytesPerMs: number) {
    this.timer = setInterval(() => this.tick(), 1);
    allDcs.push(this);
  }

  stop(): void {
    clearInterval(this.timer);
  }

  send(data: Uint8Array): void {
    if (this.readyState !== 'open') throw new Error('closed');
    const copy = data.slice();
    this.mangle?.(this.sent++, copy);
    this.queue.push(copy);
    this.bufferedAmount += copy.length;
    this.maxBuffered = Math.max(this.maxBuffered, this.bufferedAmount);
  }

  close(): void {
    if (this.readyState === 'closed') return;
    this.readyState = 'closed';
    clearInterval(this.timer);
    this.onclose?.();
    if (this.peer.readyState !== 'closed') this.peer.close();
  }

  private tick(): void {
    this.credit += this.bytesPerMs;
    while (this.queue.length && this.credit >= this.queue[0]!.length) {
      const msg = this.queue.shift()!;
      this.credit -= msg.length;
      const before = this.bufferedAmount;
      this.bufferedAmount -= msg.length;
      this.peer.deliveredBytes += msg.length;
      this.peer.onmessage?.({ data: msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.length) as ArrayBuffer });
      if (before > this.bufferedAmountLowThreshold && this.bufferedAmount <= this.bufferedAmountLowThreshold) {
        this.onbufferedamountlow?.();
      }
    }
    if (!this.queue.length) this.credit = Math.min(this.credit, this.bytesPerMs);
  }
}

function pair(bytesPerMs = 100_000) {
  const a = new FakeDC(bytesPerMs);
  const b = new FakeDC(bytesPerMs);
  a.peer = b;
  b.peer = a;
  return [a, b] as const;
}

class HashSink implements FileSink {
  readonly kind = 'memory' as const;
  hash = createHash('sha256');
  bytes = 0;
  closed = false;
  aborted = false;
  constructor(
    private readonly onWrite: (n: number) => void,
    private readonly delayMs = 0,
  ) {}
  async write(chunk: Uint8Array): Promise<void> {
    if (this.delayMs) await sleep(this.delayMs);
    this.hash.update(chunk);
    this.bytes += chunk.length;
    this.onWrite(chunk.length);
  }
  async close(): Promise<SinkResult> {
    this.closed = true;
    return { saved: true, location: 'disk', dispose: async () => {} };
  }
  async abort(): Promise<void> {
    this.aborted = true;
  }
}

async function setup(opts: { sinkDelayMs?: number; bytesPerMs?: number; guestRoot?: Uint8Array } = {}) {
  const root = generateRootKey();
  const hostKeys = await deriveSessionKeys(root, 'host');
  const guestKeys = await deriveSessionKeys((opts.guestRoot as typeof root) ?? root, 'guest');
  const [dcH, dcG] = pair(opts.bytesPerMs);
  const sinks: HashSink[] = [];
  const stats = { written: 0, maxPending: 0 };
  const guest = new SecureChannel(dcG as unknown as RTCDataChannel, guestKeys, {
    maxMessageSize: () => 262144,
    name: 'guest',
    createSink: async () => {
      const s = new HashSink((n) => {
        stats.written += n;
        stats.maxPending = Math.max(stats.maxPending, dcG.deliveredBytes - stats.written);
      }, opts.sinkDelayMs ?? 0);
      sinks.push(s);
      return s;
    },
  });
  const host = new SecureChannel(dcH as unknown as RTCDataChannel, hostKeys, { maxMessageSize: () => 262144, name: 'host' });
  guest.on('incomingFile', (o: IncomingOffer) => void o.accept());
  return { host, guest, dcH, dcG, sinks, stats };
}

const ready = (c: SecureChannel) => new Promise<void>((res) => c.on('ready', () => res()));

function waitFinal(c: SecureChannel, ids: number[]): Promise<Map<number, TransferProgress>> {
  const finals = new Map<number, TransferProgress>();
  return new Promise((resolve) => {
    c.on('progress', (p) => {
      if (ids.includes(p.id) && ['done', 'rejected', 'cancelled', 'error'].includes(p.state)) {
        finals.set(p.id, p);
        if (finals.size === ids.length) resolve(finals);
      }
    });
  });
}

test('transfer 24 MB + fisier gol + fisier mic: hash identic, backpressure respectat', async () => {
  const { host, guest, dcH, sinks, stats } = await setup();
  await Promise.all([ready(host), ready(guest)]);

  const big = randomBytes(24 * 1024 * 1024);
  const small = randomBytes(1234);
  const files = [new File([big], 'mare.bin'), new File([], 'gol.txt'), new File([small], '../../evil/../mic.bin')];
  const ids = host.sendFiles(files);
  const finals = await waitFinal(host, ids);

  for (const id of ids) assert.equal(finals.get(id)!.state, 'done', JSON.stringify(finals.get(id)));
  assert.equal(sinks.length, 3);
  assert.equal(sinks[0]!.hash.digest('hex'), createHash('sha256').update(big).digest('hex'));
  assert.equal(sinks[1]!.bytes, 0);
  assert.equal(sinks[2]!.hash.digest('hex'), createHash('sha256').update(small).digest('hex'));
  assert.ok(sinks.every((s) => s.closed && !s.aborted));

  // backpressure retea: bufferedAmount nu depaseste pragul inalt + un lot
  assert.ok(dcH.maxBuffered <= BUFFER_HIGH + 256 * 1024, `bufferedAmount maxim ${dcH.maxBuffered}`);
  assert.ok(dcH.maxBuffered > 0);
  void stats;
});

test('disc lent: datele neprocesate la receptor raman in fereastra de ack', async () => {
  const { host, guest, stats, sinks } = await setup({ sinkDelayMs: 2 });
  await Promise.all([ready(host), ready(guest)]);
  const data = randomBytes(40 * 1024 * 1024);
  const [id] = host.sendFiles([new File([data], 'lent.bin')]);
  const finals = await waitFinal(host, [id!]);
  assert.equal(finals.get(id!)!.state, 'done');
  assert.equal(sinks[0]!.hash.digest('hex'), createHash('sha256').update(data).digest('hex'));
  assert.ok(stats.maxPending <= RX_WINDOW + 512 * 1024, `in asteptare la receptor: ${stats.maxPending}`);
  console.log(`  (max in asteptare la receptor: ${(stats.maxPending / 1e6).toFixed(1)} MB, fereastra ${RX_WINDOW / 1e6} MB)`);
});

test('text scurt direct, text mare automat ca fisier', async () => {
  const { host, guest, sinks } = await setup();
  await Promise.all([ready(host), ready(guest)]);

  const got = new Promise<string>((res) => guest.on('text', res));
  assert.equal(await host.sendText('salut \u{1F680} "ghilimele"\nrand 2'), 'text');
  assert.equal(await got, 'salut \u{1F680} "ghilimele"\nrand 2');

  const big = 'x'.repeat(300_000);
  const incoming = new Promise<IncomingOffer>((res) => guest.on('incomingFile', res));
  assert.equal(await host.sendText(big), 'file');
  const offer = await incoming;
  assert.match(offer.name, /^clipboard-\d+\.txt$/);
  await sleep(300);
  assert.equal(sinks[0]!.bytes, 300_000);
});

test('anulare de la emitator in timpul transferului: sink-ul receptorului e abortat', async () => {
  const { host, guest, sinks } = await setup({ sinkDelayMs: 1 });
  await Promise.all([ready(host), ready(guest)]);
  const [id] = host.sendFiles([new File([randomBytes(60 * 1024 * 1024)], 'anulat.bin')]);
  const fin = waitFinal(host, [id!]);
  const recvCancelled = new Promise<TransferProgress>((res) =>
    guest.on('progress', (p) => p.state === 'cancelled' && res(p)),
  );
  await new Promise<void>((res) => host.on('progress', (p) => p.state === 'active' && p.bytes > 1_000_000 && res()));
  host.cancel(id!);
  assert.equal((await fin).get(id!)!.state, 'cancelled');
  assert.equal((await recvCancelled).state, 'cancelled');
  assert.ok(sinks[0]!.aborted);
});

test('refuzul receptorului: emitatorul vede "rejected", nu se trimite nimic', async () => {
  const { host, guest, dcH } = await setup();
  guest.on('incomingFile', (o) => o.reject('nu vreau'));
  await Promise.all([ready(host), ready(guest)]);
  const [id] = host.sendFiles([new File([randomBytes(2_000_000)], 'refuz.bin')]);
  const fin = await waitFinal(host, [id!]);
  assert.equal(fin.get(id!)!.state, 'rejected');
  assert.ok(dcH.sent < 10, 'doar hello + offer + end nu trebuie sa apara');
});

test('cadru sabotat in tranzit: receptorul inchide sesiunea cu eroare si aboreaza sink-ul', async () => {
  const { host, guest, dcH, sinks } = await setup();
  await Promise.all([ready(host), ready(guest)]);
  const err = new Promise<Error>((res) => guest.on('error', res));
  const closed = new Promise<string>((res) => guest.on('closed', res));
  const target = dcH.sent + 6; // al 6-lea cadru trimis de acum incolo
  dcH.mangle = (n, data) => {
    if (n === target) data[data.length - 3]! ^= 0xff;
  };
  host.sendFiles([new File([randomBytes(2_000_000)], 'sabotat.bin')]);
  assert.match((await err).message, /autentificare/);
  await closed;
  await sleep(50);
  assert.ok(sinks[0]?.aborted ?? true);
});

test('cheie diferita pe cele doua parti: nu se stabileste sesiunea, apare eroare', async () => {
  const { host, guest } = await setup({ guestRoot: generateRootKey() });
  const err = new Promise<Error>((res) => guest.on('error', res));
  assert.match((await err).message, /autentificare/);
  assert.equal(guest.isReady, false);
  assert.equal(host.isReady, false);
});
