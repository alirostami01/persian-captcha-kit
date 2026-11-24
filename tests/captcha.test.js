import test from 'node:test';
import assert from 'node:assert/strict';
import { toPersianDigits, toEnglishDigits } from '../dist/index.js';
import { generateCaptcha, verifyCaptchaToken, MemoryCaptchaStore } from '../dist/server/index.js';
import { createCaptchaHandler } from '../dist/next/index.js';

const TEST_SECRET = 'a_very_secure_test_secret_key_with_at_least_32_characters_12345';

test('toEnglishDigits & toPersianDigits conversion', () => {
  assert.equal(toEnglishDigits('۱۲۳۴۵۶'), '123456');
  assert.equal(toEnglishDigits('١٢٣٤٥٦'), '123456');
  assert.equal(toEnglishDigits('012345'), '012345');
  assert.equal(toEnglishDigits(null), '');
  assert.equal(toEnglishDigits(undefined), '');
  assert.equal(toPersianDigits('123456'), '۱۲۳۴۵۶');
  assert.equal(toPersianDigits(null), '');
});

test('generateCaptcha enforces secret requirements and clamps parameters', () => {
  // Missing secret must throw an error
  assert.throws(() => generateCaptcha({ secret: '' }), /CAPTCHA_SECRET is required/);
  // Short secret (<32 chars) must throw an error
  assert.throws(() => generateCaptcha({ secret: 'too_short_secret' }), /must be at least 32 characters/);

  // Clamping: dimensions and charCount extremes
  const clampedMin = generateCaptcha({
    secret: TEST_SECRET,
    width: 10,       // should clamp to 120
    height: 5,       // should clamp to 36
    charCount: 2,    // should clamp to 4
    ttlSeconds: 5,   // should clamp to 30
  });
  assert.equal(clampedMin.code.length, 4);
  assert.equal(clampedMin.expiresIn, 30);
  assert.match(clampedMin.svg, /viewBox="0 0 120 36"/);

  const clampedMax = generateCaptcha({
    secret: TEST_SECRET,
    width: 2000,     // should clamp to 600
    height: 1000,    // should clamp to 200
    charCount: 50,   // should clamp to 8
    ttlSeconds: 9999,// should clamp to 900
  });
  assert.equal(clampedMax.code.length, 8);
  assert.equal(clampedMax.expiresIn, 900);
  assert.match(clampedMax.svg, /viewBox="0 0 600 200"/);
});

test('generateCaptcha outputs valid SVG with unique gradient IDs', () => {
  const c1 = generateCaptcha({ secret: TEST_SECRET });
  const c2 = generateCaptcha({ secret: TEST_SECRET });

  const idMatch1 = c1.svg.match(/id="(pck-bg-[a-f0-9]{8})"/);
  const idMatch2 = c2.svg.match(/id="(pck-bg-[a-f0-9]{8})"/);

  assert.ok(idMatch1, 'Gradient ID exists in c1');
  assert.ok(idMatch2, 'Gradient ID exists in c2');
  assert.notEqual(idMatch1[1], idMatch2[1], 'Each SVG must have a distinct gradient ID');
});

test('verifyCaptchaToken rejects forged and tampered tokens', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });
  const [id, exp, sig] = captcha.token.split('.');

  // 1. Tampered signature
  const tamperedSig = sig.slice(0, -4) + 'abcd';
  const r1 = await verifyCaptchaToken(`${id}.${exp}.${tamperedSig}`, captcha.code, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(r1.valid, false);
  assert.equal(r1.error, 'INVALID_CODE');

  // 2. Tampered ID
  const tamperedId = 'a' + id.slice(1);
  const r2 = await verifyCaptchaToken(`${tamperedId}.${exp}.${sig}`, captcha.code, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(r2.valid, false);
  assert.equal(r2.error, 'INVALID_CODE');

  // 3. Different secret key
  const OTHER_SECRET = 'another_valid_secret_key_with_32_characters_long_1234';
  const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: OTHER_SECRET,
    store,
  });
  assert.equal(r3.valid, false);
  assert.equal(r3.error, 'INVALID_CODE');

  // 4. Malformed tokens
  const malformed = ['invalid', 'a.b', 'a.b.c', 'not_hex.1234567890123.sig'];
  for (const t of malformed) {
    const res = await verifyCaptchaToken(t, '123456', { secret: TEST_SECRET, store });
    assert.equal(res.valid, false);
    assert.equal(res.error, 'INVALID_TOKEN');
  }
});

test('verifyCaptchaToken works with custom asynchronous store (e.g., Redis-compatible)', async () => {
  const customStoreMap = new Set();

  const asyncRedisLikeStore = {
    async isConsumed(id) {
      return customStoreMap.has(id);
    },
    async markConsumed(id) {
      if (customStoreMap.has(id)) return false;
      customStoreMap.add(id);
      return true;
    },
  };

  const captcha = generateCaptcha({ secret: TEST_SECRET });
  const r1 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store: asyncRedisLikeStore,
  });
  assert.equal(r1.valid, true);

  // Subsequent call with the same token must fail with ALREADY_USED
  const r2 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store: asyncRedisLikeStore,
  });
  assert.equal(r2.valid, false);
  assert.equal(r2.error, 'ALREADY_USED');
});

test('MemoryCaptchaStore handles capacity limits cleanly', () => {
  const smallStore = new MemoryCaptchaStore({ maxEntries: 2 });
  assert.equal(smallStore.markConsumed('id1', 60), true);
  assert.equal(smallStore.markConsumed('id2', 60), true);
  // Re-marking consumed ID should return false
  assert.equal(smallStore.markConsumed('id1', 60), false);

  // Adding 3rd entry should evict the oldest without crashing
  assert.equal(smallStore.markConsumed('id3', 60), true);
  assert.equal(smallStore.isConsumed('id3'), true);
});

test('createCaptchaHandler works for Next.js and preserves security headers', async () => {
  let loggedError = null;
  const handler = createCaptchaHandler({
    secret: TEST_SECRET,
    headers: {
      'X-Custom-Header': 'PersianCaptcha',
      'Cache-Control': 'public, max-age=3600', // Attempt to override cache control
    },
    onError: (err) => {
      loggedError = err;
    },
  });

  const response = await handler.GET();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('X-Custom-Header'), 'PersianCaptcha');
  // Critical security headers must remain non-cacheable
  assert.equal(response.headers.get('Cache-Control'), 'no-store, no-cache, must-revalidate, proxy-revalidate');
  assert.equal(response.headers.get('Pragma'), 'no-cache');
  assert.equal(loggedError, null);
});
