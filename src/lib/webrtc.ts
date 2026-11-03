/**
 * WebBeam / webrtc.ts
 *
 * Doua straturi:
 *   SecureChannel : protocolul criptat peste un RTCDataChannel (text, oferte de fisiere, chunk-uri,
 *                   backpressure pe ambele capete). Nu stie nimic de signaling -> testabil izolat.
 *   WebBeamPeer   : signaling WebSocket (mesaje SDP/ICE criptate cu cheia camerei) + RTCPeerConnection
 *                   + ICE restart + detectie ruta (direct / relay) si porneste SecureChannel.
 *
 * Flow control (doua bariere independente)
 *   1. Emitator -> retea : nu trimitem cat timp dc.bufferedAmount > BUFFER_HIGH; reluam la
 *      `bufferedamountlow` (prag BUFFER_LOW = 64 KiB). Timer de siguranta de 250 ms pentru Safari.
 *   2. Receptor -> disc  : DataChannel nu are backpressure pe receptie, deci receptorul trimite
 *      `ack` dupa ce a SCRIS efectiv bytes-ii; emitatorul nu are voie sa aiba > RX_WINDOW bytes
 *      neconfirmati. Astfel un disc lent nu umple RAM-ul receptorului.
 *
 * Cadre pe canal (toate criptate cu FrameCipher):
 *   plaintext = [type:1][body]     type 1 = control JSON, type 2 = date: [id:u32 BE][bytes]
 */

import {
  FRAME_OVERHEAD,
  FrameCipher,
  FrameDecipher,
  b64urlEncode,
  deriveSessionKeys,
  openSignal,
  randomBytes,
  sealSignal,
  type Bytes,
  type Role,
  type SessionKeys,
} from './crypto';
import { createSink, isAbortError, sanitizeFileName, type FileSink, type SinkOptions, type SinkResult } from './fileSink';

/* ------------------------------------------------------------------ */
/* Constante                                                           */
/* ------------------------------------------------------------------ */

export const BUFFER_LOW = 64 * 1024;
export const BUFFER_HIGH = 1024 * 1024;
export const RX_ACK_EVERY = 256 * 1024;
export const RX_WINDOW = 8 * 1024 * 1024;

const MIN_FRAME = 16 * 1024; // marime sigura cross-browser daca nu cunoastem maxMessageSize
const MAX_FRAME = 64 * 1024;
const READ_BLOCK = 1024 * 1024;
const BATCH_BYTES = 128 * 1024;
const MAX_PENDING_OFFERS = 32;
const MAX_ICE_RESTARTS = 3;

const T_CTRL = 1;
const T_DATA = 2;
const DATA_HEADER = 1 + 4;

const te = new TextEncoder();
const td = new TextDecoder();
const noop = () => {};

export const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:stun.l.google.com:19302' },
];

/* ------------------------------------------------------------------ */
/* Utilitare                                                           */
/* ------------------------------------------------------------------ */

class Emitter<E extends { [K in keyof E]: unknown[] }> {
  private listeners: { [K in keyof E]?: Set<(...a: E[K]) => void> } = {};

  on<K extends keyof E>(event: K, fn: (...a: E[K]) => void): () => void {
    (this.listeners[event] ??= new Set()).add(fn);
    return () => this.listeners[event]?.delete(fn);
  }

  protected emit<K extends keyof E>(event: K, ...args: E[K]): void {
    this.listeners[event]?.forEach((fn) => {
      try {
        fn(...args);
      } catch (err) {
        console.error('[webbeam] listener error', err);
      }
    });
  }
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
}
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

const toError = (e: unknown): Error => (e instanceof Error ? e : new Error(String(e)));

class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}
class TransferAbort extends Error {}

const asObj = (x: unknown): Record<string, unknown> => {
  if (typeof x !== 'object' || x === null) throw new ProtocolError('mesaj invalid');
  return x as Record<string, unknown>;
};
const asUint = (x: unknown, max = Number.MAX_SAFE_INTEGER): number => {
  if (typeof x !== 'number' || !Number.isInteger(x) || x < 0 || x > max) throw new ProtocolError('numar invalid');
  return x;
};
const asStr = (x: unknown, max: number): string => {
  if (typeof x !== 'string' || x.length > max) throw new ProtocolError('text invalid');
  return x;
};

class SpeedMeter {
  private lastT = 0;
  private lastB = 0;
  private ewma = 0;
  start(now = performance.now()) {
    this.lastT = now;
    this.lastB = 0;
    this.ewma = 0;
  }
  /** Viteza in bytes/s, medie exponentiala recalculata la >= 0.5 s. */
  sample(bytes: number, now = performance.now()): number {
    const dt = (now - this.lastT) / 1000;
    if (dt >= 0.5) {
      const inst = (bytes - this.lastB) / dt;
      this.ewma = this.ewma === 0 ? inst : this.ewma * 0.7 + inst * 0.3;
      this.lastT = now;
      this.lastB = bytes;
    }
    return this.ewma;
  }
}

export function formatSpeed(bps: number): string {
  return `${(bps / 1e6).toFixed(bps >= 1e7 ? 0 : 1)} MB/s`;
}
export function formatEta(sec: number | null): string {
  if (sec === null || !Number.isFinite(sec)) return '--';
  const s = Math.max(0, Math.round(sec));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

/* ------------------------------------------------------------------ */
/* Tipuri publice                                                      */
/* ------------------------------------------------------------------ */

export type TransferState = 'pending' | 'active' | 'done' | 'rejected' | 'cancelled' | 'error';

export interface TransferProgress {
  id: number;
  direction: 'send' | 'receive';
  name: string;
  size: number;
  /** Emitator: bytes confirmati ca SCRISI de receptor. Receptor: bytes scrisi pe disc. */
  bytes: number;
  fraction: number;
  speedBps: number;
  etaSec: number | null;
  state: TransferState;
  error?: string;
}

export interface IncomingOffer {
  readonly id: number;
  readonly name: string;
  readonly size: number;
  readonly mime: string;
  /**
   * Apeleaza DIRECT din handler-ul de click (user gesture): deschide showSaveFilePicker.
   * Returneaza false daca utilizatorul a inchis dialogul sau transferul a fost anulat intre timp.
   */
  accept(opts?: SinkOptions): Promise<boolean>;
  reject(reason?: string): void;
}

export interface ReceivedFile {
  id: number;
  name: string;
  size: number;
  result: SinkResult;
}

type ChannelEvents = {
  ready: [info: { peerName?: string }];
  text: [text: string];
  incomingFile: [offer: IncomingOffer];
  progress: [p: TransferProgress];
  fileReceived: [file: ReceivedFile];
  closed: [reason: string];
  error: [err: Error];
};

type Ctrl =
  | { t: 'hello'; v: 1; maxMsg: number; name?: string }
  | { t: 'text'; text: string }
  | { t: 'offer'; id: number; name: string; size: number; mime: string }
  | { t: 'accept'; id: number }
  | { t: 'reject'; id: number; reason?: string }
  | { t: 'ack'; id: number; bytes: number }
  | { t: 'end'; id: number; bytes: number }
  | { t: 'done'; id: number }
  | { t: 'cancel'; id: number; by: 'sender' | 'receiver'; reason?: string };

interface Xfer {
  id: number;
  dir: 'send' | 'receive';
  name: string;
  size: number;
  mime: string;
  bytes: number;
  state: TransferState;
  error?: string;
  meter: SpeedMeter;
  lastEmit: number;
}
interface Outgoing extends Xfer {
  file: File;
  sent: number;
  cancelled: boolean;
  accepted: Deferred<boolean>;
  done: Deferred<boolean>;
}
interface Incoming extends Xfer {
  sink: FileSink | null;
  sinceAck: number;
}

const isTerminal = (s: TransferState) => s === 'done' || s === 'rejected' || s === 'cancelled' || s === 'error';

/* ------------------------------------------------------------------ */
/* SecureChannel                                                       */
/* ------------------------------------------------------------------ */

export interface SecureChannelOptions {
  /** Evaluat lazy: pc.sctp apare abia dupa negociere. */
  maxMessageSize?: () => number | undefined;
  name?: string;
  createSink?: typeof createSink;
}

export class SecureChannel extends Emitter<ChannelEvents> {
  private readonly cipher: FrameCipher;
  private readonly decipher: FrameDecipher;
  private txChain: Promise<void> = Promise.resolve();
  private rxChain: Promise<void> = Promise.resolve();
  private sendQueue: Promise<void> = Promise.resolve();
  private readonly waiters = new Set<() => void>();
  private readonly outgoing = new Map<number, Outgoing>();
  private readonly incoming = new Map<number, Incoming>();
  private frameSize = MIN_FRAME;
  private ready = false;
  private closed = false;
  private nextId = 1;

  constructor(
    private readonly dc: RTCDataChannel,
    keys: Pick<SessionKeys, 'send' | 'recv'>,
    private readonly opts: SecureChannelOptions = {},
  ) {
    super();
    this.cipher = new FrameCipher(keys.send);
    this.decipher = new FrameDecipher(keys.recv);

    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = BUFFER_LOW;
    dc.onopen = () => this.sendHello();
    dc.onclose = () => this.shutdown('canal inchis');
    dc.onerror = () => {}; // erorile se termina cu `close`
    dc.onmessage = (ev: MessageEvent) => this.onRaw(ev.data);
    dc.onbufferedamountlow = () => this.wake();
    if (dc.readyState === 'open') this.sendHello();
  }

  get isReady(): boolean {
    return this.ready && !this.closed;
  }

  /* ----------------------------- API ----------------------------- */

  /** Text scurt = un singur mesaj; text mare = trimis automat ca fisier clipboard-*.txt. */
  async sendText(text: string): Promise<'text' | 'file'> {
    this.assertReady();
    const msg: Ctrl = { t: 'text', text };
    if (1 + te.encode(JSON.stringify(msg)).length + FRAME_OVERHEAD <= this.frameSize) {
      await this.sendControl(msg);
      return 'text';
    }
    this.sendFiles([new File([text], `clipboard-${Date.now()}.txt`, { type: 'text/plain' })]);
    return 'file';
  }

  /** Pune fisierele intr-o coada (unul cate unul). Intoarce id-urile; progresul vine prin `progress`. */
  sendFiles(files: Iterable<File>): number[] {
    this.assertReady();
    const ids: number[] = [];
    for (const file of files) {
      const t: Outgoing = {
        id: this.nextId++,
        dir: 'send',
        name: sanitizeFileName(file.name),
        size: file.size,
        mime: file.type || 'application/octet-stream',
        bytes: 0,
        state: 'pending',
        meter: new SpeedMeter(),
        lastEmit: 0,
        file,
        sent: 0,
        cancelled: false,
        accepted: deferred<boolean>(),
        done: deferred<boolean>(),
      };
      this.outgoing.set(t.id, t);
      ids.push(t.id);
      this.emitProgress(t, true);
      this.sendQueue = this.sendQueue.then(() => this.runOutgoing(t));
    }
    return ids;
  }

  cancel(id: number): void {
    const out = this.outgoing.get(id);
    if (out && !isTerminal(out.state)) {
      out.cancelled = true;
      out.accepted.resolve(false);
      out.done.resolve(false);
      this.sendControl({ t: 'cancel', id, by: 'sender' }).catch(noop);
      this.wake();
      return;
    }
    const inc = this.incoming.get(id);
    if (inc && !isTerminal(inc.state)) {
      this.sendControl({ t: 'cancel', id, by: 'receiver' }).catch(noop);
      void this.abortIncoming(inc, 'cancelled');
    }
  }

  close(): void {
    this.shutdown('inchis local');
    try {
      this.dc.close();
    } catch {
      /* deja inchis */
    }
  }

  /* -------------------------- emitere -------------------------- */

  private sendHello(): void {
    const maxMsg = this.opts.maxMessageSize?.() ?? MIN_FRAME;
    this.sendControl({ t: 'hello', v: 1, maxMsg, name: this.opts.name }).catch((e) => this.fail(toError(e)));
  }

  private sendControl(msg: Ctrl): Promise<void> {
    const body = te.encode(JSON.stringify(msg));
    const plain = new Uint8Array(1 + body.length);
    plain[0] = T_CTRL;
    plain.set(body, 1);
    return this.enqueueFrames([plain]);
  }

  /**
   * Singurul loc care cheama cipher.seal + dc.send. Lantul `txChain` garanteaza ca ordinea
   * contoarelor = ordinea trimiterii, chiar daca apeleaza concomitent stream-ul si ack-urile.
   */
  private enqueueFrames(plains: Bytes[]): Promise<void> {
    const run = async () => {
      if (this.closed || this.dc.readyState !== 'open') throw new TransferAbort('canal inchis');
      const frames = await Promise.all(plains.map((p) => this.cipher.seal(p))); // contoare rezervate in ordine
      for (const f of frames) this.dc.send(f);
    };
    const p = this.txChain.then(run);
    this.txChain = p.catch(noop);
    return p;
  }

  private async runOutgoing(t: Outgoing): Promise<void> {
    try {
      if (t.cancelled || this.closed) return this.finish(t, t.cancelled ? 'cancelled' : 'error', 'conexiune pierduta');
      await this.sendControl({ t: 'offer', id: t.id, name: t.name, size: t.size, mime: t.mime });
      const accepted = await t.accepted.promise;
      if (t.cancelled || this.closed) return this.finish(t, t.cancelled ? 'cancelled' : 'error', 'conexiune pierduta');
      if (!accepted) return this.finish(t, 'rejected');

      t.state = 'active';
      t.meter.start();
      this.emitProgress(t, true);
      await this.streamFile(t);
      await this.sendControl({ t: 'end', id: t.id, bytes: t.sent });
      const ok = await t.done.promise;
      if (!ok) return this.finish(t, t.cancelled ? 'cancelled' : 'error', t.error ?? 'transfer esuat');
      t.bytes = t.size;
      this.finish(t, 'done');
    } catch (e) {
      if (e instanceof TransferAbort) this.finish(t, t.cancelled ? 'cancelled' : 'error', e.message);
      else this.finish(t, 'error', toError(e).message);
    }
  }

  private async streamFile(t: Outgoing): Promise<void> {
    const dataPerFrame = this.frameSize - FRAME_OVERHEAD - DATA_HEADER;
    const perBatch = Math.max(1, Math.floor(BATCH_BYTES / dataPerFrame));
    let offset = 0;
    // prefetch: citim blocul urmator in timp ce il criptam/trimitem pe cel curent
    let nextBlock: Promise<ArrayBuffer> | null = t.size > 0 ? t.file.slice(0, READ_BLOCK).arrayBuffer() : null;

    while (nextBlock) {
      const block = new Uint8Array(await nextBlock);
      if (block.length === 0) throw new Error('fisierul s-a schimbat in timpul transferului');
      offset += block.length;
      nextBlock = offset < t.size ? t.file.slice(offset, offset + READ_BLOCK).arrayBuffer() : null;

      let pos = 0;
      while (pos < block.length) {
        await this.waitForCapacity(t);
        const plains: Bytes[] = [];
        let batch = 0;
        for (let i = 0; i < perBatch && pos < block.length; i++) {
          const n = Math.min(dataPerFrame, block.length - pos);
          const plain = new Uint8Array(DATA_HEADER + n);
          plain[0] = T_DATA;
          new DataView(plain.buffer).setUint32(1, t.id);
          plain.set(block.subarray(pos, pos + n), DATA_HEADER);
          plains.push(plain);
          pos += n;
          batch += n;
        }
        await this.enqueueFrames(plains);
        t.sent += batch;
        this.emitProgress(t);
      }
    }
  }

  /** Asteapta pana cand si reteaua (bufferedAmount) si receptorul (fereastra de ack) au loc. */
  private async waitForCapacity(t: Outgoing): Promise<void> {
    for (;;) {
      if (t.cancelled) throw new TransferAbort('anulat');
      if (this.closed || this.dc.readyState !== 'open') throw new TransferAbort('conexiune pierduta');
      if (this.dc.bufferedAmount <= BUFFER_HIGH && t.sent - t.bytes < RX_WINDOW) return;
      await new Promise<void>((resolve) => {
        const wakeUp = () => {
          clearTimeout(timer);
          this.waiters.delete(wakeUp);
          resolve();
        };
        const timer = setTimeout(wakeUp, 250); // plasa de siguranta: bufferedamountlow e nesigur in unele Safari
        this.waiters.add(wakeUp);
      });
    }
  }

  private wake(): void {
    for (const w of [...this.waiters]) w();
  }

  /* -------------------------- receptie -------------------------- */

  private onRaw(data: unknown): void {
    if (!(data instanceof ArrayBuffer)) return this.fail(new ProtocolError('mesaj non-binar'));
    // lant secvential: ordinea de procesare = ordinea de sosire (contor strict + scrieri in ordine)
    this.rxChain = this.rxChain.then(() => this.processFrame(data)).catch((e) => this.fail(toError(e)));
  }

  private async processFrame(buf: ArrayBuffer): Promise<void> {
    if (this.closed) return;
    const plain = await this.decipher.open(new Uint8Array(buf));
    if (plain.length < 1) throw new ProtocolError('cadru gol');
    if (plain[0] === T_CTRL) return this.onControl(JSON.parse(td.decode(plain.subarray(1))));
    if (plain[0] === T_DATA) return this.onData(plain);
    throw new ProtocolError('tip de cadru necunoscut');
  }

  private async onControl(raw: unknown): Promise<void> {
    const m = asObj(raw);
    switch (m.t) {
      case 'hello': {
        if (this.ready) return;
        const peerMax = asUint(m.maxMsg);
        const local = this.opts.maxMessageSize?.() ?? MIN_FRAME;
        this.frameSize = Math.min(MAX_FRAME, local, peerMax);
        if (this.frameSize < 2048) throw new ProtocolError('maxMessageSize prea mic');
        this.ready = true;
        this.emit('ready', { peerName: typeof m.name === 'string' ? m.name.slice(0, 60) : undefined });
        return;
      }
      case 'text': {
        this.requireReady();
        this.emit('text', asStr(m.text, 1_000_000));
        return;
      }
      case 'offer': {
        this.requireReady();
        const id = asUint(m.id, 0xffffffff);
        if (this.incoming.has(id)) throw new ProtocolError('id de transfer duplicat');
        const pending = [...this.incoming.values()].filter((t) => t.state === 'pending').length;
        if (pending >= MAX_PENDING_OFFERS) {
          this.sendControl({ t: 'reject', id, reason: 'prea multe oferte' }).catch(noop);
          return;
        }
        const t: Incoming = {
          id,
          dir: 'receive',
          name: sanitizeFileName(asStr(m.name, 1024)),
          size: asUint(m.size),
          mime: asStr(m.mime, 128),
          bytes: 0,
          state: 'pending',
          meter: new SpeedMeter(),
          lastEmit: 0,
          sink: null,
          sinceAck: 0,
        };
        this.incoming.set(id, t);
        this.emitProgress(t, true);
        this.emit('incomingFile', this.makeOffer(t));
        return;
      }
      case 'accept':
        this.outgoing.get(asUint(m.id, 0xffffffff))?.accepted.resolve(true);
        return;
      case 'reject':
        this.outgoing.get(asUint(m.id, 0xffffffff))?.accepted.resolve(false);
        return;
      case 'ack': {
        const t = this.outgoing.get(asUint(m.id, 0xffffffff));
        if (!t || t.state !== 'active') return;
        t.bytes = Math.max(t.bytes, Math.min(asUint(m.bytes), t.sent));
        this.emitProgress(t);
        this.wake();
        return;
      }
      case 'end': {
        const t = this.incoming.get(asUint(m.id, 0xffffffff));
        if (!t || t.state !== 'active' || !t.sink) return;
        const declared = asUint(m.bytes);
        if (t.bytes !== t.size || declared !== t.size) {
          await this.abortIncoming(t, 'error', `dimensiune incorecta: primit ${t.bytes} din ${t.size}`);
          this.sendControl({ t: 'cancel', id: t.id, by: 'receiver', reason: 'dimensiune incorecta' }).catch(noop);
          return;
        }
        try {
          const result = await t.sink.close();
          t.state = 'done';
          this.emitProgress(t, true);
          this.emit('fileReceived', { id: t.id, name: t.name, size: t.size, result });
          await this.sendControl({ t: 'done', id: t.id });
        } catch (e) {
          await this.abortIncoming(t, 'error', toError(e).message);
          this.sendControl({ t: 'cancel', id: t.id, by: 'receiver', reason: 'scriere esuata' }).catch(noop);
        }
        return;
      }
      case 'done': {
        const t = this.outgoing.get(asUint(m.id, 0xffffffff));
        t?.done.resolve(true);
        return;
      }
      case 'cancel': {
        const id = asUint(m.id, 0xffffffff);
        const reason = typeof m.reason === 'string' ? m.reason.slice(0, 200) : undefined;
        if (m.by === 'sender') {
          const t = this.incoming.get(id);
          if (t && !isTerminal(t.state)) await this.abortIncoming(t, 'cancelled', reason);
        } else {
          const t = this.outgoing.get(id);
          if (t && !isTerminal(t.state)) {
            t.cancelled = true;
            t.error = reason;
            t.accepted.resolve(false);
            t.done.resolve(false);
            this.wake();
          }
        }
        return;
      }
      default:
        throw new ProtocolError('tip de control necunoscut');
    }
  }

  private async onData(plain: Bytes): Promise<void> {
    if (plain.length < DATA_HEADER) throw new ProtocolError('cadru de date prea scurt');
    const id = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(1);
    const t = this.incoming.get(id);
    if (!t || isTerminal(t.state)) return; // cadre ramase "in zbor" dupa anulare
    if (t.state !== 'active' || !t.sink) throw new ProtocolError('date pentru un transfer neacceptat');

    const chunk = plain.subarray(DATA_HEADER);
    if (t.bytes + chunk.length > t.size) throw new ProtocolError('peer-ul a trimis mai mult decat a anuntat');
    await t.sink.write(chunk); // asteptam scrierea => ack-ul reflecta bytes SCRISI, nu doar primiti
    t.bytes += chunk.length;
    t.sinceAck += chunk.length;
    if (t.sinceAck >= RX_ACK_EVERY) {
      t.sinceAck = 0;
      this.sendControl({ t: 'ack', id, bytes: t.bytes }).catch(noop);
    }
    this.emitProgress(t);
  }

  private makeOffer(t: Incoming): IncomingOffer {
    return {
      id: t.id,
      name: t.name,
      size: t.size,
      mime: t.mime,
      accept: async (sinkOpts) => {
        if (t.state !== 'pending' || this.closed) return false;
        let sink: FileSink;
        try {
          // apel SINCRON in gestul utilizatorului (showSaveFilePicker); await abia dupa
          const pendingSink = (this.opts.createSink ?? createSink)({ name: t.name, size: t.size, mime: t.mime }, sinkOpts);
          sink = await pendingSink;
        } catch (e) {
          this.declineIncoming(t, isAbortError(e) ? 'dialog de salvare inchis' : toError(e).message);
          if (!isAbortError(e)) this.emit('error', toError(e));
          return false;
        }
        if (t.state !== 'pending' || this.closed) {
          await sink.abort(); // emitatorul a anulat cat timp era deschis dialogul
          return false;
        }
        t.sink = sink;
        t.state = 'active';
        t.meter.start();
        this.emitProgress(t, true);
        await this.sendControl({ t: 'accept', id: t.id });
        return true;
      },
      reject: (reason) => this.declineIncoming(t, reason ?? 'refuzat'),
    };
  }

  private declineIncoming(t: Incoming, reason: string): void {
    if (t.state !== 'pending') return;
    t.state = 'rejected';
    t.error = reason;
    this.sendControl({ t: 'reject', id: t.id, reason }).catch(noop);
    this.emitProgress(t, true);
  }

  private async abortIncoming(t: Incoming, state: 'cancelled' | 'error', reason?: string): Promise<void> {
    t.state = state;
    t.error = reason;
    const sink = t.sink;
    t.sink = null;
    if (sink) await sink.abort().catch(noop);
    this.emitProgress(t, true);
  }

  /* --------------------------- stare --------------------------- */

  private finish(t: Outgoing, state: TransferState, error?: string): void {
    t.state = state;
    if (error) t.error = error;
    this.emitProgress(t, true);
  }

  private emitProgress(t: Xfer, force = false): void {
    const now = performance.now();
    if (!force && now - t.lastEmit < 100) return;
    t.lastEmit = now;
    const speed = t.state === 'active' ? t.meter.sample(t.bytes, now) : 0;
    this.emit('progress', {
      id: t.id,
      direction: t.dir,
      name: t.name,
      size: t.size,
      bytes: t.bytes,
      fraction: t.size === 0 ? (t.state === 'done' ? 1 : 0) : t.bytes / t.size,
      speedBps: speed,
      etaSec: speed > 0 ? (t.size - t.bytes) / speed : null,
      state: t.state,
      error: t.error,
    });
  }

  private assertReady(): void {
    if (!this.isReady) throw new Error('canalul nu e gata');
  }
  private requireReady(): void {
    if (!this.ready) throw new ProtocolError('mesaj inainte de handshake');
  }

  private fail(err: Error): void {
    if (this.closed) return;
    this.emit('error', err);
    this.shutdown(err.message);
    try {
      this.dc.close();
    } catch {
      /* deja inchis */
    }
  }

  private shutdown(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    const lost = 'conexiune pierduta';
    for (const t of this.outgoing.values()) {
      if (isTerminal(t.state)) continue;
      t.accepted.resolve(false);
      t.done.resolve(false);
      t.error = t.error ?? lost;
      if (t.state === 'pending') this.finish(t, 'error', lost);
    }
    for (const t of this.incoming.values()) {
      if (isTerminal(t.state)) continue;
      void this.abortIncoming(t, 'error', lost);
    }
    this.wake();
    this.emit('closed', reason);
  }
}

/* ------------------------------------------------------------------ */
/* WebBeamPeer: signaling + RTCPeerConnection                          */
/* ------------------------------------------------------------------ */

export type ConnectionState =
  | 'idle'
  | 'connecting-signaling'
  | 'waiting-for-peer'
  | 'negotiating'
  | 'connected'
  | 'reconnecting'
  | 'failed'
  | 'closed';

/** direct = host/srflx/prflx (P2P real), relay = trece prin TURN (tot criptat E2EE). */
export type RouteKind = 'direct' | 'relay' | 'unknown';

export interface WebBeamOptions {
  signalingUrl: string;
  roomId: string;
  rootKey: Bytes;
  role: Role;
  iceServers?: RTCIceServer[];
  deviceName?: string;
  createSink?: typeof createSink;
}

type PeerEvents = ChannelEvents & {
  state: [state: ConnectionState];
  route: [route: RouteKind];
};

type SigMsg =
  | { k: 'offer'; sid: string; sdp: string; restart?: boolean }
  | { k: 'answer'; sid: string; sdp: string }
  | { k: 'ice'; sid: string; c: RTCIceCandidateInit }
  | { k: 'restart' };

const FATAL_SIGNALING: Record<string, string> = {
  'bad-auth': 'Cheia din link nu corespunde camerei.',
  'room-not-found': 'Camera nu exista sau a expirat. Cere un cod QR nou.',
  'room-expired': 'Camera a expirat.',
  'bad-join': 'Cerere de conectare invalida.',
  'server-busy': 'Serverul de signaling e aglomerat. Incearca din nou.',
  'rate-limited': 'Prea multe cereri. Asteapta putin.',
};

export class WebBeamPeer extends Emitter<PeerEvents> {
  private keys!: SessionKeys;
  private ws: WebSocket | null = null;
  private joined = false;
  private fatal = false;
  private closedByUser = false;
  private sigTx: Promise<void> = Promise.resolve();
  private sigRx: Promise<void> = Promise.resolve();
  private joinWaiters: Array<() => void> = [];
  private wsAttempts = 0;
  private wsTimer: ReturnType<typeof setTimeout> | null = null;

  private pc: RTCPeerConnection | null = null;
  private channel: SecureChannel | null = null;
  private sid = '';
  private pendingIce: RTCIceCandidateInit[] = [];
  private restarts = 0;
  private restartTimer: ReturnType<typeof setTimeout> | null = null;

  private _state: ConnectionState = 'idle';
  private _route: RouteKind = 'unknown';

  constructor(private readonly opts: WebBeamOptions) {
    super();
  }

  get state(): ConnectionState {
    return this._state;
  }
  get route(): RouteKind {
    return this._route;
  }

  async start(): Promise<void> {
    this.setState('connecting-signaling');
    this.keys = await deriveSessionKeys(this.opts.rootKey, this.opts.role);
    this.connectSignaling();
  }

  sendText(text: string) {
    return this.requireChannel().sendText(text);
  }
  sendFiles(files: Iterable<File>) {
    return this.requireChannel().sendFiles(files);
  }
  cancel(id: number) {
    this.channel?.cancel(id);
  }

  close(): void {
    this.closedByUser = true;
    if (this.wsTimer) clearTimeout(this.wsTimer);
    if (this.restartTimer) clearTimeout(this.restartTimer);
    this.ws?.close(1000, 'bye');
    this.ws = null;
    this.teardownPeer();
    this.setState('closed');
  }

  private requireChannel(): SecureChannel {
    if (!this.channel?.isReady) throw new Error('nu exista conexiune P2P activa');
    return this.channel;
  }

  private setState(s: ConnectionState): void {
    if (this._state === s) return;
    this._state = s;
    this.emit('state', s);
  }

  /* ------------------------- signaling ------------------------- */

  private connectSignaling(): void {
    const ws = new WebSocket(this.opts.signalingUrl);
    this.ws = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ t: 'join', room: this.opts.roomId, auth: this.keys.roomAuth, role: this.opts.role }));
    };
    ws.onmessage = (ev) => this.onSignalingMessage(ev.data);
    ws.onerror = () => {};
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.joined = false;
      if (this.closedByUser || this.fatal || this._state === 'connected') return; // P2P stabil: signaling se redeschide la nevoie
      if (this.wsAttempts >= 6) {
        this.setState('failed');
        this.emit('error', new Error('Nu ma pot conecta la serverul de signaling.'));
        return;
      }
      const delay = Math.min(8000, 500 * 2 ** this.wsAttempts++) + Math.random() * 300;
      this.wsTimer = setTimeout(() => this.connectSignaling(), delay);
    };
  }

  private ensureSignaling(): Promise<void> {
    if (this.ws && this.joined) return Promise.resolve();
    if (!this.ws) this.connectSignaling();
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout signaling')), 10_000);
      this.joinWaiters.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  private onSignalingMessage(data: unknown): void {
    let msg: Record<string, unknown>;
    try {
      msg = asObj(JSON.parse(String(data)));
    } catch {
      return;
    }
    switch (msg.t) {
      case 'joined':
        this.joined = true;
        this.wsAttempts = 0;
        this.joinWaiters.splice(0).forEach((fn) => fn());
        if (msg.partner === true) {
          if (!this.channel?.isReady) this.onPeerPresent(); // daca P2P e deja activ, e doar o reluare a signaling-ului
        } else if (this._state !== 'connected') {
          this.setState('waiting-for-peer');
        }
        break;
      case 'peer-joined':
        this.onPeerPresent();
        break;
      case 'peer-left':
        if (this._state !== 'connected') {
          this.teardownPeer();
          this.setState('waiting-for-peer');
        }
        break;
      case 'sig':
        if (typeof msg.d === 'string') {
          const d = msg.d;
          this.sigRx = this.sigRx.then(() => this.handleSignal(d)).catch((e) => this.emit('error', toError(e)));
        }
        break;
      case 'error': {
        const code = String(msg.code ?? '');
        if (code in FATAL_SIGNALING) {
          this.fatal = true;
          this.setState('failed');
          this.emit('error', new Error(FATAL_SIGNALING[code]));
        }
        break;
      }
    }
  }

  /** Mesaj criptat; ordinea de trimitere = ordinea apelurilor. */
  private signal(msg: SigMsg): Promise<void> {
    const run = async () => {
      const d = await sealSignal(this.keys.signal, msg);
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error('signaling indisponibil');
      this.ws.send(JSON.stringify({ t: 'sig', d }));
    };
    const p = this.sigTx.then(run);
    this.sigTx = p.catch(noop);
    return p;
  }

  private async handleSignal(sealed: string): Promise<void> {
    let msg: SigMsg;
    try {
      msg = await openSignal<SigMsg>(this.keys.signal, sealed);
    } catch {
      throw new Error('Mesaj de signaling invalid: cheie gresita sau mesaj modificat.');
    }

    switch (msg.k) {
      case 'offer': {
        if (this.opts.role !== 'guest') return;
        if (!msg.restart || !this.pc) this.resetPeerConnection();
        const pc = this.pc!;
        this.sid = msg.sid;
        await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        await this.flushPendingIce();
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        await this.signal({ k: 'answer', sid: msg.sid, sdp: pc.localDescription!.sdp });
        return;
      }
      case 'answer': {
        if (this.opts.role !== 'host' || msg.sid !== this.sid || !this.pc) return;
        await this.pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
        await this.flushPendingIce();
        return;
      }
      case 'ice': {
        if (msg.sid !== this.sid || !this.pc) return;
        if (!this.pc.remoteDescription) this.pendingIce.push(msg.c);
        else await this.pc.addIceCandidate(msg.c).catch(noop);
        return;
      }
      case 'restart':
        if (this.opts.role === 'host') await this.startNegotiation(true);
        return;
    }
  }

  /* ------------------------ WebRTC ------------------------ */

  private onPeerPresent(): void {
    this.setState('negotiating');
    if (this.opts.role === 'host') void this.startNegotiation(false).catch((e) => this.emit('error', toError(e)));
    // guest: asteapta oferta; peer connection-ul se reface cand ajunge
  }

  private async startNegotiation(iceRestart: boolean): Promise<void> {
    if (this.opts.role !== 'host') return;
    if (!iceRestart || !this.pc) this.resetPeerConnection();
    const pc = this.pc!;
    this.sid = b64urlEncode(randomBytes(8));
    this.pendingIce = [];
    const offer = await pc.createOffer({ iceRestart });
    await pc.setLocalDescription(offer);
    await this.signal({ k: 'offer', sid: this.sid, sdp: pc.localDescription!.sdp, restart: iceRestart });
  }

  private resetPeerConnection(): void {
    this.teardownPeer();
    const pc = new RTCPeerConnection({
      iceServers: this.opts.iceServers ?? DEFAULT_ICE_SERVERS,
      bundlePolicy: 'max-bundle',
    });
    this.pc = pc;
    this.pendingIce = [];

    pc.onicecandidate = (ev) => {
      if (ev.candidate) this.signal({ k: 'ice', sid: this.sid, c: ev.candidate.toJSON() }).catch(noop);
    };
    pc.onconnectionstatechange = () => this.onConnectionState(pc);

    if (this.opts.role === 'host') this.attachChannel(pc.createDataChannel('webbeam', { ordered: true }));
    else pc.ondatachannel = (ev) => this.attachChannel(ev.channel);
  }

  private attachChannel(dc: RTCDataChannel): void {
    const ch = new SecureChannel(dc, this.keys, {
      maxMessageSize: () => this.pc?.sctp?.maxMessageSize,
      name: this.opts.deviceName,
      createSink: this.opts.createSink,
    });
    this.channel = ch;
    ch.on('ready', (info) => {
      this.restarts = 0;
      this.setState('connected');
      void this.detectRoute();
      this.emit('ready', info);
    });
    ch.on('text', (t) => this.emit('text', t));
    ch.on('incomingFile', (o) => this.emit('incomingFile', o));
    ch.on('progress', (p) => this.emit('progress', p));
    ch.on('fileReceived', (f) => this.emit('fileReceived', f));
    ch.on('error', (e) => this.emit('error', e));
    ch.on('closed', (reason) => {
      if (this.channel !== ch) return;
      this.channel = null;
      if (!this.closedByUser) this.setState('closed');
      this.emit('closed', reason);
    });
  }

  private onConnectionState(pc: RTCPeerConnection): void {
    if (pc !== this.pc) return;
    switch (pc.connectionState) {
      case 'connected':
        if (this.restartTimer) clearTimeout(this.restartTimer);
        if (this.channel?.isReady) {
          this.setState('connected');
          void this.detectRoute();
        }
        break;
      case 'disconnected':
        this.setState('reconnecting');
        this.restartTimer = setTimeout(() => void this.requestIceRestart(), 3000);
        break;
      case 'failed':
        void this.requestIceRestart();
        break;
    }
  }

  private async requestIceRestart(): Promise<void> {
    if (this.closedByUser || !this.pc) return;
    if (++this.restarts > MAX_ICE_RESTARTS) {
      this.setState('failed');
      this.emit('error', new Error('Conexiunea P2P a esuat (retea/NAT). Un server TURN ar putea ajuta.'));
      return;
    }
    this.setState('reconnecting');
    try {
      await this.ensureSignaling();
      if (this.opts.role === 'host') await this.startNegotiation(true);
      else await this.signal({ k: 'restart' });
    } catch (e) {
      this.emit('error', toError(e));
    }
  }

  private async flushPendingIce(): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    for (const c of this.pendingIce.splice(0)) await pc.addIceCandidate(c).catch(noop);
  }

  private teardownPeer(): void {
    const ch = this.channel;
    this.channel = null;
    ch?.close();
    const pc = this.pc;
    this.pc = null;
    if (pc) {
      pc.onicecandidate = null;
      pc.onconnectionstatechange = null;
      pc.ondatachannel = null;
      pc.close();
    }
  }

  /** Citeste perechea de candidati aleasa: relay (TURN) sau direct. */
  private async detectRoute(): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    let route: RouteKind = 'unknown';
    try {
      const byId = new Map<string, Record<string, unknown>>();
      (await pc.getStats()).forEach((r) => byId.set(r.id, r as unknown as Record<string, unknown>));
      let pair: Record<string, unknown> | undefined;
      for (const r of byId.values()) {
        if (r.type === 'transport' && typeof r.selectedCandidatePairId === 'string') {
          pair = byId.get(r.selectedCandidatePairId);
          break;
        }
      }
      if (!pair) {
        for (const r of byId.values()) {
          if (r.type === 'candidate-pair' && (r.selected === true || (r.nominated === true && r.state === 'succeeded'))) {
            pair = r;
            break;
          }
        }
      }
      if (pair) {
        const local = byId.get(String(pair.localCandidateId));
        const remote = byId.get(String(pair.remoteCandidateId));
        route = local?.candidateType === 'relay' || remote?.candidateType === 'relay' ? 'relay' : 'direct';
      }
    } catch {
      /* getStats poate lipsi/esua: ramane 'unknown' */
    }
    if (route !== this._route) {
      this._route = route;
      this.emit('route', route);
    }
  }
}
