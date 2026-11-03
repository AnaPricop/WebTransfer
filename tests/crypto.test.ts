import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FrameCipher,
  FrameDecipher,
  b64urlDecode,
  b64urlEncode,
  buildRoomUrl,
  deriveSessionKeys,
  generateRoomId,
  generateRootKey,
  openSignal,
  parseRootKeyFromHash,
  sealSignal,
} from '../src/lib/crypto';

test('base64url round-trip + room id', () => {
  const k = generateRootKey();
  assert.deepEqual(b64urlDecode(b64urlEncode(k)), k);
  assert.equal(b64urlEncode(k).length, 43);
  const id = generateRoomId();
  assert.match(id, /^[a-hjkmnp-z2-9]{10}$/);
});

test('cheia se extrage din hash, nu din query', () => {
  const k = generateRootKey();
  const url = new URL(buildRoomUrl('https://x.pages.dev', 'abc23456xy', k));
  assert.equal(url.pathname, '/room/abc23456xy');
  assert.equal(url.search, '');
  assert.deepEqual(parseRootKeyFromHash(url.hash), k);
  assert.equal(parseRootKeyFromHash('#key=scurt'), null);
});

test('host<->guest: chei pe directie, round-trip pe mii de cadre', async () => {
  const root = generateRootKey();
  const host = await deriveSessionKeys(root, 'host');
  const guest = await deriveSessionKeys(root, 'guest');
  assert.equal(host.roomAuth, guest.roomAuth);
  assert.notEqual(host.roomAuth, b64urlEncode(root));

  const tx = new FrameCipher(host.send);
  const rx = new FrameDecipher(guest.recv);
  for (let i = 0; i < 2000; i++) {
    const msg = new Uint8Array([i & 255, (i >> 8) & 255, 7]);
    assert.deepEqual(await rx.open(await tx.seal(msg)), msg);
  }
});

test('cheia pe directie gresita nu decripteaza', async () => {
  const root = generateRootKey();
  const host = await deriveSessionKeys(root, 'host');
  const frame = await new FrameCipher(host.send).seal(new Uint8Array([1, 2, 3]));
  await assert.rejects(new FrameDecipher(host.recv).open(frame), /autentificare/);
});

test('cadru modificat, replay si reordonare sunt respinse', async () => {
  const root = generateRootKey();
  const host = await deriveSessionKeys(root, 'host');
  const guest = await deriveSessionKeys(root, 'guest');
  const tx = new FrameCipher(host.send);
  const f0 = await tx.seal(new Uint8Array([0]));
  const f1 = await tx.seal(new Uint8Array([1]));
  const f2 = await tx.seal(new Uint8Array([2]));

  // tamper
  const bad = f0.slice();
  bad[bad.length - 1]! ^= 1;
  await assert.rejects(new FrameDecipher(guest.recv).open(bad), /autentificare/);

  // replay
  const rx = new FrameDecipher(guest.recv);
  await rx.open(f0);
  await assert.rejects(rx.open(f0), /contor neasteptat/);

  // reordonare / pierdere (f2 inainte de f1)
  const rx2 = new FrameDecipher(guest.recv);
  await rx2.open(f0);
  await assert.rejects(rx2.open(f2), /contor neasteptat/);
  void f1;
});

test('signaling criptat: cheie gresita sau mesaj modificat esueaza', async () => {
  const a = await deriveSessionKeys(generateRootKey(), 'host');
  const b = await deriveSessionKeys(generateRootKey(), 'guest');
  const sealed = await sealSignal(a.signal, { k: 'offer', sdp: 'v=0...' });
  assert.deepEqual(await openSignal(a.signal, sealed), { k: 'offer', sdp: 'v=0...' });
  await assert.rejects(openSignal(b.signal, sealed), /signal authentication failed/);
  const tampered = sealed.slice(0, -2) + (sealed.endsWith('AA') ? 'BB' : 'AA');
  await assert.rejects(openSignal(a.signal, tampered), /signal/);
});
