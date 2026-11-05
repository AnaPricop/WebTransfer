/**
 * WebBeam / crypto.ts  (WebCrypto only, zero dependinte)
 *
 * Model de securitate
 * -------------------
 *  - `rootKey` (32 octeti aleatori) traieste DOAR in fragmentul URL (#key=...) si in memoria
 *    celor doua browsere. Fragmentul nu e trimis niciodata la server (nici Pages, nici signaling).
 *  - Din rootKey derivam cu HKDF-SHA256 chei independente (separare de domenii):
 *      signal          : cripteaza SDP/ICE care trec prin serverul de signaling
 *                        => serverul nu vede IP-uri/fingerprint-uri si NU poate modifica oferta
 *                        (fara asta, un signaling malitios ar putea face MITM pe DTLS)
 *      host->guest,
 *      guest->host     : chei separate pe directie pentru RTCDataChannel
 *      roomAuth        : dovada ca ai cheia; serverul pastreaza doar hash(roomAuth), nu poate
 *                        reconstitui rootKey, iar un strain nu poate ocupa locul al 2-lea in camera
 *  - Pe canalul de date fiecare mesaj = nonce(12) || AES-256-GCM(plaintext) || tag(16)
 *      nonce = prefix aleator pe sesiune (4B) || contor monoton (8B)
 *    Receptorul impune contor strict crescator => detecteaza replay, reordonari, mesaje
 *    sterse sau inserate (canalul e ordered + reliable).
 */

export type Bytes = Uint8Array<ArrayBuffer>;
export type Role = 'host' | 'guest';

export const ROOT_KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
/** Octetii adaugati de FrameCipher.seal() peste plaintext. */
export const FRAME_OVERHEAD = NONCE_BYTES + TAG_BYTES;

const MAX_FRAMES_PER_KEY = 2 ** 32 - 1;

const te = new TextEncoder();
const SALT = te.encode('webbeam/v1/salt');
const SIGNAL_AAD = te.encode('webbeam/v1/signal');

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

/* ------------------------------------------------------------------ */
/* base64url + random                                                  */
/* ------------------------------------------------------------------ */

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new CryptoError('invalid base64url');
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function generateRootKey(): Bytes {
  return randomBytes(ROOT_KEY_BYTES);
}

/** Alfabet fara caractere ambigue (0/o, 1/l/i). 31 simbole, ~5 biti/caracter. */
const ROOM_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

/** ID scurt de camera (implicit 10 caractere ~ 49 biti), fara bias de modulo. */
export function generateRoomId(length = 10): string {
  const limit = 256 - (256 % ROOM_ALPHABET.length); // 248
  let out = '';
  while (out.length < length) {
    for (const b of randomBytes(length * 2)) {
      if (b < limit && out.length < length) out += ROOM_ALPHABET[b % ROOM_ALPHABET.length];
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Link-ul camerei: cheia sta in hash                                  */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Cod de conectare (introdus de mana)                                 */
/* ------------------------------------------------------------------ */
/*
 * Un cod scurt de 10 caractere (50 de biti, alfabet Crockford fara I L O U) din care ambele parti
 * deriva la fel ID-ul camerei si rootKey, printr-un KDF scump (PBKDF2-SHA256, 600.000 iteratii).
 * Serverul vede doar ID-ul camerei (tot rezultat al KDF-ului): ca sa afle codul ar trebui sa
 * incerce ~2^50 coduri, fiecare cu un KDF intreg. Codul e aleatoriu, generat de aplicatie
 * (nu ales de om), pentru ca un cod scurt ales de om ar fi usor de ghicit.
 */

const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CODE_LENGTH = 10;
const CODE_ITERATIONS = 600_000;
const CODE_SALT = te.encode('webbeam/v1/code');
const CODE_ROOM_BYTES = 9; // -> ID de camera de 12 caractere base64url

export function generateCode(): string {
  let out = '';
  for (const b of randomBytes(CODE_LENGTH)) out += CODE_ALPHABET[b & 31]; // 256 % 32 == 0: fara bias
  return out;
}

/** Tolereaza litere mici, spatii, cratime si confuziile uzuale (O->0, I/L->1). */
export function normalizeCode(raw: string): string {
  let out = '';
  for (const ch of raw.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1')) {
    if (CODE_ALPHABET.includes(ch)) out += ch;
  }
  return out.slice(0, CODE_LENGTH);
}

/** ABCDE-FGHJK, ca sa fie usor de citit si de scris. */
export function formatCode(code: string): string {
  const c = normalizeCode(code);
  return c.length > 5 ? `${c.slice(0, 5)}-${c.slice(5)}` : c;
}

export async function deriveFromCode(code: string): Promise<{ roomId: string; rootKey: Bytes }> {
  const norm = normalizeCode(code);
  if (norm.length !== CODE_LENGTH) throw new CryptoError('cod invalid');
  const base = await crypto.subtle.importKey('raw', te.encode(norm), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: CODE_SALT, iterations: CODE_ITERATIONS },
      base,
      8 * (CODE_ROOM_BYTES + ROOT_KEY_BYTES),
    ),
  );
  return { roomId: b64urlEncode(bits.subarray(0, CODE_ROOM_BYTES)), rootKey: bits.slice(CODE_ROOM_BYTES) };
}

export function buildRoomUrl(origin: string, roomId: string, rootKey: Uint8Array): string {
  return `${origin.replace(/\/$/, '')}/room/${roomId}#key=${b64urlEncode(rootKey)}`;
}

export function parseRootKeyFromHash(hash: string): Bytes | null {
  const m = /(?:^#|&)key=([A-Za-z0-9_-]{43})(?:&|$)/.exec(hash);
  if (!m) return null;
  try {
    const key = b64urlDecode(m[1]!);
    return key.length === ROOT_KEY_BYTES ? key : null;
  } catch {
    return null;
  }
}

/**
 * Citeste cheia din `location.hash`, o sterge din bara de adrese (history/screenshot/share)
 * si o tine in sessionStorage ca sa supravietuiasca unui reload (iOS omoara des tab-urile din fundal).
 * sessionStorage e per-tab si dispare la inchiderea tab-ului.
 */
export function consumeRootKey(roomId: string): Bytes | null {
  const storageKey = `webbeam:key:${roomId}`;
  const fromHash = parseRootKeyFromHash(location.hash);
  if (fromHash) {
    try {
      sessionStorage.setItem(storageKey, b64urlEncode(fromHash));
    } catch {
      /* storage indisponibil (mod privat strict) - nu e fatal */
    }
    history.replaceState(null, '', location.pathname + location.search);
    return fromHash;
  }
  try {
    const stored = sessionStorage.getItem(storageKey);
    return stored ? b64urlDecode(stored) : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Derivare chei                                                       */
/* ------------------------------------------------------------------ */

export interface SessionKeys {
  /** AES-GCM, pentru mesajele de signaling (nonce aleator per mesaj). */
  signal: CryptoKey;
  /** Cheia cu care CRIPTEZ pe canalul de date. */
  send: CryptoKey;
  /** Cheia cu care DECRIPTEZ pe canalul de date. */
  recv: CryptoKey;
  /** base64url(32B), se trimite serverului la join. Nu e rootKey si nu poate fi inversat in ea. */
  roomAuth: string;
}

export async function deriveSessionKeys(rootKey: Bytes, role: Role): Promise<SessionKeys> {
  if (!globalThis.crypto?.subtle) {
    throw new CryptoError('WebCrypto indisponibil: aplicatia trebuie servita prin HTTPS (sau localhost).');
  }
  if (rootKey.length !== ROOT_KEY_BYTES) throw new CryptoError('rootKey trebuie sa aiba 32 de octeti');

  const base = await crypto.subtle.importKey('raw', rootKey, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const params = (info: string): HkdfParams => ({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: te.encode(info) });
  const aes = (info: string) =>
    crypto.subtle.deriveKey(params(info), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const [signal, hostToGuest, guestToHost, authBits] = await Promise.all([
    aes('webbeam/v1/signal'),
    aes('webbeam/v1/data/host->guest'),
    aes('webbeam/v1/data/guest->host'),
    crypto.subtle.deriveBits(params('webbeam/v1/room-auth'), base, 256),
  ]);

  return {
    signal,
    send: role === 'host' ? hostToGuest : guestToHost,
    recv: role === 'host' ? guestToHost : hostToGuest,
    roomAuth: b64urlEncode(new Uint8Array(authBits)),
  };
}

/* ------------------------------------------------------------------ */
/* Signaling: mesaje mici, nonce aleator                               */
/* ------------------------------------------------------------------ */

export async function sealSignal(key: CryptoKey, message: unknown): Promise<string> {
  const nonce = randomBytes(NONCE_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: SIGNAL_AAD },
    key,
    te.encode(JSON.stringify(message)),
  );
  const out = new Uint8Array(NONCE_BYTES + ct.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(ct), NONCE_BYTES);
  return b64urlEncode(out);
}

export async function openSignal<T = unknown>(key: CryptoKey, sealed: string): Promise<T> {
  const raw = b64urlDecode(sealed);
  if (raw.length < FRAME_OVERHEAD) throw new CryptoError('signal message too short');
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.subarray(0, NONCE_BYTES), additionalData: SIGNAL_AAD },
      key,
      raw.subarray(NONCE_BYTES),
    );
    return JSON.parse(new TextDecoder().decode(pt)) as T;
  } catch {
    throw new CryptoError('signal authentication failed (cheie gresita sau mesaj modificat)');
  }
}

/* ------------------------------------------------------------------ */
/* Canal de date: criptare pe cadre cu contor                          */
/* ------------------------------------------------------------------ */

export class FrameCipher {
  private readonly prefix = randomBytes(4);
  private counter = 0;

  constructor(private readonly key: CryptoKey) {}

  /**
   * Contorul se rezerva SINCRON la apel (inainte de primul await), deci ordinea apelurilor
   * = ordinea contoarelor. Apelantul trebuie sa trimita cadrele in aceeasi ordine.
   */
  async seal(plain: Bytes): Promise<Bytes> {
    if (this.counter >= MAX_FRAMES_PER_KEY) throw new CryptoError('contor epuizat: e nevoie de re-keying');
    const c = this.counter++;
    const nonce = new Uint8Array(NONCE_BYTES);
    nonce.set(this.prefix, 0);
    const dv = new DataView(nonce.buffer);
    dv.setUint32(4, Math.floor(c / 2 ** 32));
    dv.setUint32(8, c >>> 0);

    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, this.key, plain);
    const out = new Uint8Array(NONCE_BYTES + ct.byteLength);
    out.set(nonce, 0);
    out.set(new Uint8Array(ct), NONCE_BYTES);
    return out;
  }
}

export class FrameDecipher {
  private prefix: Bytes | null = null;
  private expected = 0;

  constructor(private readonly key: CryptoKey) {}

  /** Verificarea contorului se face sincron; apelantii trebuie sa proceseze cadrele in ordinea sosirii. */
  async open(frame: Bytes): Promise<Bytes> {
    if (frame.length < FRAME_OVERHEAD) throw new CryptoError('frame prea scurt');
    const nonce = frame.subarray(0, NONCE_BYTES);
    const dv = new DataView(frame.buffer, frame.byteOffset, NONCE_BYTES);
    const counter = dv.getUint32(4) * 2 ** 32 + dv.getUint32(8);

    if (this.prefix === null) {
      this.prefix = nonce.slice(0, 4);
    } else {
      for (let i = 0; i < 4; i++) if (nonce[i] !== this.prefix[i]) throw new CryptoError('prefix de nonce schimbat');
    }
    if (counter !== this.expected) {
      throw new CryptoError(`contor neasteptat ${counter} (asteptat ${this.expected}): replay/reordonare/pierdere`);
    }
    this.expected++;

    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, this.key, frame.subarray(NONCE_BYTES));
      return new Uint8Array(pt);
    } catch {
      throw new CryptoError('autentificare esuata (cheie gresita sau cadru modificat)');
    }
  }
}
