/**
 * Sovereign — Crypto Layer Unit Tests
 * Run with: node --test tests/crypto.test.mjs
 * Requires: Node 18+ (built-in Web Crypto + node:test)
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// ── Crypto functions copied verbatim from web/index.html ──────────────────────
const PBKDF2_ITER = 310000;

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    true, ['encrypt', 'decrypt']
  );
}

async function encrypt(data, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data)));
  return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(ct)));
}

async function decrypt(b64, key) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv  = raw.slice(0, 12);
  const ct  = raw.slice(12);
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// ── Helper ────────────────────────────────────────────────────────────────────
function randomSalt() { return crypto.getRandomValues(new Uint8Array(32)); }

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('deriveKey', () => {
  test('returns an extractable AES-GCM-256 CryptoKey', async () => {
    const key = await deriveKey('correcthorsebattery', randomSalt());
    assert.equal(key.type, 'secret');
    assert.equal(key.algorithm.name, 'AES-GCM');
    assert.equal(key.algorithm.length, 256);
    assert.equal(key.extractable, true);
  });

  test('same password + same salt → functionally identical key', async () => {
    const salt = randomSalt();
    const k1   = await deriveKey('samepassword1234', salt);
    const k2   = await deriveKey('samepassword1234', salt);
    // Verify by cross-encrypting/decrypting
    const ct = await encrypt({ test: true }, k1);
    const pt = await decrypt(ct, k2);
    assert.deepEqual(pt, { test: true });
  });

  test('different passwords → different keys (cross-decrypt fails)', async () => {
    const salt = randomSalt();
    const k1   = await deriveKey('password-alpha-12', salt);
    const k2   = await deriveKey('password-beta--12', salt);
    const ct   = await encrypt({ secret: 'value' }, k1);
    await assert.rejects(() => decrypt(ct, k2), /OperationError|DOMException/);
  });

  test('same password + different salt → different keys', async () => {
    const k1 = await deriveKey('sharedpassword12', randomSalt());
    const k2 = await deriveKey('sharedpassword12', randomSalt());
    const ct = await encrypt({ x: 1 }, k1);
    await assert.rejects(() => decrypt(ct, k2));
  });
});

describe('encrypt', () => {
  test('returns a non-empty base64 string', async () => {
    const key = await deriveKey('testpassword1234', randomSalt());
    const ct  = await encrypt({ hello: 'world' }, key);
    assert.equal(typeof ct, 'string');
    assert.ok(ct.length > 0);
    assert.doesNotThrow(() => atob(ct));
  });

  test('ciphertext is at least 12 bytes longer than plaintext (IV overhead)', async () => {
    const key       = await deriveKey('testpassword1234', randomSalt());
    const payload   = { entries: [] };
    const plainLen  = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    const ct        = await encrypt(payload, key);
    const ctLen     = Uint8Array.from(atob(ct), c => c.charCodeAt(0)).byteLength;
    assert.ok(ctLen >= plainLen + 12, `expected ctLen(${ctLen}) >= plainLen(${plainLen}) + 12`);
  });

  test('each call produces a unique ciphertext (random IV)', async () => {
    const key = await deriveKey('testpassword1234', randomSalt());
    const ct1 = await encrypt({ x: 1 }, key);
    const ct2 = await encrypt({ x: 1 }, key);
    assert.notEqual(ct1, ct2);
  });
});

describe('decrypt', () => {
  test('roundtrip: simple object', async () => {
    const key     = await deriveKey('myp@ssw0rd12345!', randomSalt());
    const payload = { entries: [{ id: '1', name: 'Gmail', value: 'hunter2' }] };
    assert.deepEqual(await decrypt(await encrypt(payload, key), key), payload);
  });

  test('roundtrip: empty entries array', async () => {
    const key = await deriveKey('emptytest1234567', randomSalt());
    assert.deepEqual(await decrypt(await encrypt({ entries: [] }, key), key), { entries: [] });
  });

  test('roundtrip: multi-line value', async () => {
    const key     = await deriveKey('multilinepass123', randomSalt());
    const payload = { entries: [{ id: '1', name: 'SSH Key', value: '-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----', multiline: true }] };
    assert.deepEqual(await decrypt(await encrypt(payload, key), key), payload);
  });

  test('roundtrip: unicode and special characters', async () => {
    const key     = await deriveKey('unicodepass12345', randomSalt());
    const payload = { entries: [{ name: '日本語テスト', value: '🔐 secret <>&"\'' }] };
    assert.deepEqual(await decrypt(await encrypt(payload, key), key), payload);
  });

  test('roundtrip: XSS-like payload survives intact', async () => {
    const key     = await deriveKey('xsstest123456789', randomSalt());
    const payload = { entries: [{ name: '<script>alert(1)</script>', value: '"; DROP TABLE users; --' }] };
    assert.deepEqual(await decrypt(await encrypt(payload, key), key), payload);
  });

  test('wrong key throws', async () => {
    const salt = randomSalt();
    const k1   = await deriveKey('correctpassword1', salt);
    const k2   = await deriveKey('wrongpassword123', salt);
    const ct   = await encrypt({ secret: 'data' }, k1);
    await assert.rejects(() => decrypt(ct, k2));
  });

  test('tampered ciphertext throws', async () => {
    const key    = await deriveKey('testpassword1234', randomSalt());
    const ct     = await encrypt({ x: 1 }, key);
    const bytes  = Uint8Array.from(atob(ct), c => c.charCodeAt(0));
    bytes[bytes.length - 1] ^= 0xff; // flip last byte
    const tampered = btoa(String.fromCharCode(...bytes));
    await assert.rejects(() => decrypt(tampered, key));
  });

  test('truncated ciphertext throws', async () => {
    const key     = await deriveKey('testpassword1234', randomSalt());
    const ct      = await encrypt({ x: 1 }, key);
    const short   = ct.slice(0, Math.floor(ct.length / 2));
    await assert.rejects(() => decrypt(short, key));
  });
});

describe('PBKDF2 parameters', () => {
  test('uses exactly 310,000 iterations', () => {
    assert.equal(PBKDF2_ITER, 310_000);
  });
});
