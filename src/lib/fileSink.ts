/**
 * WebBeam / fileSink.ts
 *
 * Unde ajung bytes-ii primiti, fara sa tinem fisierul in RAM:
 *   1. FsAccessSink : File System Access API (Chromium desktop) -> scriere directa pe disc
 *   2. IdbSink      : fallback pentru Safari/iOS/Firefox -> batch-uri de 4 MiB in IndexedDB,
 *                     la final Blob compus din bucatile stocate (suportat de disc, nu de RAM)
 *                     + descarcare nativa prin <a download>
 *   3. MemorySink   : ultima plasa (IndexedDB indisponibil, ex. mod privat) -> Blob in memorie
 *
 * IMPORTANT: showSaveFilePicker cere "transient user activation". De aceea createSink() trebuie
 * apelat SINCRON din handler-ul de click pe "Accept" (vezi IncomingOffer.accept in webrtc.ts).
 */

export type Bytes = Uint8Array<ArrayBuffer>;

export interface SinkInfo {
  name: string;
  size: number;
  mime: string;
}

export interface SinkOptions {
  /** Director ales o singura data cu pickDirectory(): toate fisierele cad acolo, fara dialog per fisier. */
  directory?: FsDirHandle;
  /** Forteaza fallback-ul (pentru teste). */
  forceFallback?: boolean;
}

export interface SinkResult {
  /** true = fisierul e deja pe disc. false = a fost pornita descarcarea; UI arata butonul "Salveaza". */
  saved: boolean;
  location: 'disk' | 'download';
  /** Re-declanseaza descarcarea (pe iOS trebuie apelat dintr-un click). */
  save?: () => void;
  /** Elibereaza URL-ul blob si datele din IndexedDB. Apeleaza-l dupa ce utilizatorul a salvat. */
  dispose: () => Promise<void>;
}

export interface FileSink {
  readonly kind: 'fs-access' | 'indexeddb' | 'memory';
  write(chunk: Bytes): Promise<void>;
  close(): Promise<SinkResult>;
  /** Anuleaza si sterge orice urma partiala. */
  abort(): Promise<void>;
}

/* ---------- tipuri minimale pentru File System Access API ---------- */

interface FsWritable {
  write(data: Bytes): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}
interface FsFileHandle {
  createWritable(opts?: { keepExistingData?: boolean }): Promise<FsWritable>;
}
export interface FsDirHandle {
  getFileHandle(name: string, opts?: { create?: boolean }): Promise<FsFileHandle>;
}
interface FsGlobal {
  showSaveFilePicker?: (o?: { suggestedName?: string }) => Promise<FsFileHandle>;
  showDirectoryPicker?: (o?: { mode?: 'read' | 'readwrite' }) => Promise<FsDirHandle>;
}
const fsGlobal = () => globalThis as unknown as FsGlobal;

export function sinkCapabilities() {
  const g = fsGlobal();
  return {
    fsAccess: typeof g.showSaveFilePicker === 'function',
    directoryPicker: typeof g.showDirectoryPicker === 'function',
    indexedDB: typeof indexedDB !== 'undefined',
  };
}

export function isAbortError(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { name?: string }).name === 'AbortError';
}

/** Cere utilizatorului un director de salvare (Chromium). Apeleaza din click. */
export async function pickDirectory(): Promise<FsDirHandle | null> {
  const g = fsGlobal();
  if (!g.showDirectoryPicker) return null;
  try {
    return await g.showDirectoryPicker({ mode: 'readwrite' });
  } catch (e) {
    if (isAbortError(e)) return null;
    throw e;
  }
}

/** Nume sigur pentru disc: fara cai, caractere de control, nume rezervate Windows, max 180 caractere. */
export function sanitizeFileName(raw: string): string {
  const base = raw.split(/[\\/]/).pop() ?? '';
  const cleaned = base
    .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_')
    .replace(/^[.\s]+|[.\s]+$/g, '')
    .slice(0, 180);
  if (!cleaned) return 'file';
  return /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(cleaned) ? `_${cleaned}` : cleaned;
}

/* ------------------------------------------------------------------ */

export function createSink(info: SinkInfo, opts: SinkOptions = {}): Promise<FileSink> {
  const name = sanitizeFileName(info.name);
  const g = fsGlobal();

  // Ambele cai FS Access apeleaza picker-ul SINCRON (inainte de orice await) -> pastram user activation.
  if (!opts.forceFallback) {
    if (opts.directory) return FsAccessSink.inDirectory(opts.directory, name);
    if (typeof g.showSaveFilePicker === 'function') {
      return FsAccessSink.fromPicker(g.showSaveFilePicker({ suggestedName: name }));
    }
  }
  if (typeof indexedDB !== 'undefined') {
    return IdbSink.create(info, name).catch(() => new MemorySink(info, name));
  }
  return Promise.resolve(new MemorySink(info, name));
}

/* ------------------------------------------------------------------ */
/* 1. File System Access                                               */
/* ------------------------------------------------------------------ */

const FS_BATCH = 1024 * 1024;

class FsAccessSink implements FileSink {
  readonly kind = 'fs-access' as const;
  // Scrierile de 64 KiB una cate una sunt scumpe; le grupam in blocuri de ~1 MiB.
  // Memoria ramane marginita (< 1 MiB + un chunk), iar flush-ul asteptat da backpressure.
  private parts: Bytes[] = [];
  private bytes = 0;
  private constructor(private readonly writable: FsWritable) {}

  /** Primeste promisiunea picker-ului (deja apelat sincron de createSink). */
  static async fromPicker(pending: Promise<FsFileHandle>): Promise<FsAccessSink> {
    const handle = await pending; // AbortError daca utilizatorul inchide dialogul
    return new FsAccessSink(await handle.createWritable({ keepExistingData: false }));
  }

  static async inDirectory(dir: FsDirHandle, name: string): Promise<FsAccessSink> {
    const unique = await uniqueName(dir, name);
    const handle = await dir.getFileHandle(unique, { create: true });
    return new FsAccessSink(await handle.createWritable({ keepExistingData: false }));
  }

  async write(chunk: Bytes): Promise<void> {
    this.parts.push(chunk);
    this.bytes += chunk.length;
    if (this.bytes >= FS_BATCH) await this.flush();
  }

  private async flush(): Promise<void> {
    if (!this.parts.length) return;
    const out = new Uint8Array(this.bytes);
    let offset = 0;
    for (const p of this.parts) {
      out.set(p, offset);
      offset += p.length;
    }
    this.parts = [];
    this.bytes = 0;
    await this.writable.write(out);
  }

  async close(): Promise<SinkResult> {
    await this.flush();
    await this.writable.close(); // abia acum fisierul apare pe disc (Chromium scrie intr-un fisier swap)
    return { saved: true, location: 'disk', dispose: async () => {} };
  }

  async abort(): Promise<void> {
    this.parts = [];
    this.bytes = 0;
    try {
      await this.writable.abort();
    } catch {
      /* deja inchis */
    }
  }
}

async function uniqueName(dir: FsDirHandle, name: string): Promise<string> {
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  for (let i = 0; i < 200; i++) {
    const candidate = i === 0 ? name : `${stem} (${i})${ext}`;
    try {
      await dir.getFileHandle(candidate); // exista deja -> incercam urmatorul nume
    } catch (e) {
      if ((e as { name?: string }).name === 'NotFoundError') return candidate;
      throw e;
    }
  }
  throw new Error('prea multe fisiere cu acelasi nume');
}

/* ------------------------------------------------------------------ */
/* 2. IndexedDB fallback (Safari / iOS / Firefox)                      */
/* ------------------------------------------------------------------ */

const DB_NAME = 'webbeam-recv';
const STORE = 'chunks';
const IDB_BATCH = 4 * 1024 * 1024;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB indisponibil'));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new Error('tranzactie IndexedDB anulata'));
    tx.onerror = () => reject(tx.error ?? new Error('eroare IndexedDB'));
  });
}

const rangeFor = (key: string) => IDBKeyRange.bound([key, 0], [key, Number.MAX_SAFE_INTEGER]);

/** Sterge tot ce a ramas din transferuri intrerupte. Apeleaza o singura data la pornirea aplicatiei. */
export async function purgeStaleReceiveData(): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  try {
    const db = await openDb();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    await txDone(tx);
    db.close();
  } catch {
    /* best effort */
  }
}

class IdbSink implements FileSink {
  readonly kind = 'indexeddb' as const;
  private pending: Bytes[] = [];
  private pendingBytes = 0;
  private index = 0;

  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: string,
    private readonly name: string,
    private readonly mime: string,
  ) {}

  static async create(info: SinkInfo, name: string): Promise<IdbSink> {
    const db = await openDb();
    const key = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    return new IdbSink(db, key, name, info.mime);
  }

  async write(chunk: Bytes): Promise<void> {
    this.pending.push(chunk);
    this.pendingBytes += chunk.length;
    if (this.pendingBytes >= IDB_BATCH) await this.flush();
  }

  private async flush(): Promise<void> {
    if (!this.pending.length) return;
    const blob = new Blob(this.pending);
    this.pending = [];
    this.pendingBytes = 0;
    const tx = this.db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(blob, [this.key, this.index++]);
    await txDone(tx);
  }

  async close(): Promise<SinkResult> {
    await this.flush();
    const tx = this.db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).getAll(rangeFor(this.key));
    await txDone(tx);
    const blob = new Blob(req.result as Blob[], { type: this.mime || 'application/octet-stream' });
    return downloadResult(blob, this.name, () => this.dropRecords());
  }

  async abort(): Promise<void> {
    this.pending = [];
    await this.dropRecords();
  }

  private async dropRecords(): Promise<void> {
    try {
      const tx = this.db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).delete(rangeFor(this.key));
      await txDone(tx);
    } catch {
      /* best effort */
    }
    this.db.close();
  }
}

/* ------------------------------------------------------------------ */
/* 3. Memorie                                                          */
/* ------------------------------------------------------------------ */

class MemorySink implements FileSink {
  readonly kind = 'memory' as const;
  private parts: Bytes[] = [];

  constructor(
    private readonly info: SinkInfo,
    private readonly name: string,
  ) {}

  async write(chunk: Bytes): Promise<void> {
    this.parts.push(chunk);
  }

  async close(): Promise<SinkResult> {
    const blob = new Blob(this.parts, { type: this.info.mime || 'application/octet-stream' });
    this.parts = [];
    return downloadResult(blob, this.name, async () => {});
  }

  async abort(): Promise<void> {
    this.parts = [];
  }
}

/* ------------------------------------------------------------------ */

function downloadResult(blob: Blob, name: string, cleanup: () => Promise<void>): SinkResult {
  const url = URL.createObjectURL(blob);
  const save = () => triggerDownload(url, name);
  try {
    save(); // pe iOS poate fi ignorat daca nu suntem in gest -> UI ofera butonul "Salveaza" (save())
  } catch {
    /* mediu fara DOM */
  }
  return {
    saved: false,
    location: 'download',
    save,
    dispose: async () => {
      URL.revokeObjectURL(url);
      await cleanup();
    },
  };
}

function triggerDownload(url: string, name: string): void {
  if (typeof document === 'undefined') return;
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
}
