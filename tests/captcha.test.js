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
  assert.throws(() => generateCaptcha({ secret: '' }), /CAPTCHA_SECRET is required/);
  assert.throws(() => generateCaptcha({ secret: 'too_short_secret' }), /must be at least 32 bytes/);

  const clampedMin = generateCaptcha({
    secret: TEST_SECRET,
    width: 10,
    height: 5,
    charCount: 2,
    ttlSeconds: 5,
  });
  assert.equal(clampedMin.code.length, 4);
  assert.equal(clampedMin.expiresIn, 30);
  assert.match(clampedMin.svg, /viewBox="0 0 120 36"/);

  const clampedMax = generateCaptcha({
    secret: TEST_SECRET,
    width: 2000,
    height: 1000,
    charCount: 50,
    ttlSeconds: 9999,
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

test('verifyCaptchaToken enforces maxAttempts and blocks brute-force guessing', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // Attempt 1: wrong code
  const r1 = await verifyCaptchaToken(captcha.token, '000000', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 3,
  });
  assert.equal(r1.valid, false);
  assert.equal(r1.error, 'INVALID_CODE');
  assert.equal(r1.attemptsRemaining, 2);

  // Attempt 2: wrong code
  const r2 = await verifyCaptchaToken(captcha.token, '111111', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 3,
  });
  assert.equal(r2.valid, false);
  assert.equal(r2.error, 'INVALID_CODE');
  assert.equal(r2.attemptsRemaining, 1);

  // Attempt 3: correct code
  const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 3,
  });
  assert.equal(r3.valid, true);

  // Attempt 4: after successful consumption, token must be ALREADY_USED
  const r4 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 3,
  });
  assert.equal(r4.valid, false);
  assert.equal(r4.error, 'ALREADY_USED');
});

test('verifyCaptchaToken blocks token once maxAttempts is exceeded', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // 2 wrong attempts
  await verifyCaptchaToken(captcha.token, '000000', { secret: TEST_SECRET, store, maxAttempts: 2 });
  await verifyCaptchaToken(captcha.token, '111111', { secret: TEST_SECRET, store, maxAttempts: 2 });

  // 3rd attempt, even with correct code, must be blocked as TOO_MANY_ATTEMPTS
  const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r3.valid, false);
  assert.equal(r3.error, 'TOO_MANY_ATTEMPTS');
});

test('verifyCaptchaToken handles concurrent verification attempts safely', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // Fire 5 simultaneous verification attempts with the correct code
  const results = await Promise.all([
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
  ]);

  // Exactly one attempt must succeed (valid: true) and the rest must be ALREADY_USED
  const successCount = results.filter((r) => r.valid).length;
  const alreadyUsedCount = results.filter((r) => r.error === 'ALREADY_USED').length;

  assert.equal(successCount, 1, 'Only one concurrent request can successfully consume the token');
  assert.equal(alreadyUsedCount, 4, 'Remaining concurrent requests must be rejected as ALREADY_USED');
});

test('MemoryCaptchaStore validates maxEntries and refuses to drop unexpired entries', () => {
  assert.throws(() => new MemoryCaptchaStore({ maxEntries: 0 }), /maxEntries must be a positive integer/);
  assert.throws(() => new MemoryCaptchaStore({ maxEntries: -5 }), /maxEntries must be a positive integer/);

  const smallStore = new MemoryCaptchaStore({ maxEntries: 2 });
  smallStore.recordAttempt('id1', 3, 60);
  smallStore.recordAttempt('id2', 3, 60);

  // 3rd entry when memory is full of valid entries must throw capacity exceeded error
  assert.throws(
    () => smallStore.recordAttempt('id3', 3, 60),
    /MemoryCaptchaStore capacity exceeded/
  );
});

test('createCaptchaHandler works for Next.js and preserves security headers', async () => {
  let loggedError = null;
  const handler = createCaptchaHandler({
    secret: TEST_SECRET,
    headers: {
      'X-Custom-Header': 'PersianCaptcha',
      'Cache-Control': 'public, max-age=3600',
    },
    onError: (err) => {
      loggedError = err;
    },
  });

  const response = await handler.GET();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('X-Custom-Header'), 'PersianCaptcha');
  assert.equal(response.headers.get('Cache-Control'), 'no-store, no-cache, must-revalidate, proxy-revalidate');
  assert.equal(response.headers.get('Pragma'), 'no-cache');
  assert.equal(loggedError, null);
});
