import test from 'node:test';
import assert from 'node:assert/strict';
import { toPersianDigits, toEnglishDigits } from '../dist/index.js';
import { generateCaptcha, verifyCaptchaToken, MemoryCaptchaStore } from '../dist/server/index.js';
import { createCaptchaHandler } from '../dist/next/index.js';

const TEST_SECRET = 'a_very_secure_test_secret_key_with_at_least_32_characters_12345';

test('toEnglishDigits & toPersianDigits', () => {
  assert.equal(toEnglishDigits('۱۲۳۴۵۶'), '123456');
  assert.equal(toEnglishDigits('١٢٣٤٥٦'), '123456');
  assert.equal(toPersianDigits('123456'), '۱۲۳۴۵۶');
});

test('generateCaptcha requires valid secret', () => {
  // بدون سکرت باید خطا بدهد
  delete process.env.CAPTCHA_SECRET;
  delete process.env.AUTH_HMAC_KEY;
  assert.throws(() => generateCaptcha(), /CAPTCHA_SECRET is required/);

  // سکرت کوتاه باید خطا بدهد
  assert.throws(() => generateCaptcha({ secret: 'short' }), /must be at least 32 characters/);
});

test('generateCaptcha creates valid SVG and unique token', () => {
  const captcha = generateCaptcha({ secret: TEST_SECRET, charCount: 6 });
  assert.equal(typeof captcha.token, 'string');
  assert.equal(typeof captcha.svg, 'string');
  assert.equal(typeof captcha.code, 'string');
  assert.equal(captcha.code.length, 6);
  assert.ok(captcha.svg.includes('<svg'));
  assert.ok(captcha.svg.includes('</svg>'));
  // بررسی یکتا بودن شناسه گرادیان
  assert.match(captcha.svg, /id="pck-bg-[a-f0-9]{8}"/);
  assert.equal(captcha.expiresIn, 180);
});

test('verifyCaptchaToken works with English and Persian digits and prevents replay', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // تایید با ارقام فارسی
  const persianInput = toPersianDigits(captcha.code);
  const result = await verifyCaptchaToken(captcha.token, persianInput, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(result.valid, true);

  // Replay باید با شکست مواجه شود
  const replay = await verifyCaptchaToken(captcha.token, persianInput, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(replay.valid, false);
  assert.equal(replay.error, 'ALREADY_USED');
});

test('verifyCaptchaToken rejects invalid codes and does not pollute store with bad signatures', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // کد اشتباه
  const wrongCode = captcha.code === '111111' ? '222222' : '111111';
  const badCodeResult = await verifyCaptchaToken(captcha.token, wrongCode, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(badCodeResult.valid, false);
  assert.equal(badCodeResult.error, 'INVALID_CODE');

  // توکن با کد دست‌کاری شده نباید در Store ذخیره شود
  const futureExp = Date.now() + 180000;
  const fakeToken = `1234567890abcdef1234567890abcdef.${futureExp}.1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`;
  const badTokenResult = await verifyCaptchaToken(fakeToken, '123456', {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(badTokenResult.valid, false);
  assert.equal(badTokenResult.error, 'INVALID_CODE');
  // شناسه توکن جعلی نباید در store مصرف شده باشد
  assert.equal(store.isConsumed('1234567890abcdef1234567890abcdef'), false);
});

test('verifyCaptchaToken handles expired tokens', async () => {
  const captcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 30 });
  // جعل منقضی کردن زمان
  const [id, , sig] = captcha.token.split('.');
  const expiredExp = Date.now() - 1000;
  const expiredToken = `${id}.${expiredExp}.${sig}`;
  
  const expiredResult = await verifyCaptchaToken(expiredToken, captcha.code, {
    secret: TEST_SECRET,
  });
  assert.equal(expiredResult.valid, false);
  assert.equal(expiredResult.error, 'EXPIRED');
});

test('createCaptchaHandler works for Next.js App Router', async () => {
  const handler = createCaptchaHandler({ secret: TEST_SECRET });
  const response = await handler.GET();
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Cache-Control'), 'no-store, no-cache, must-revalidate, proxy-revalidate');
  const json = await response.json();
  assert.equal(json.ok, true);
  assert.ok(json.token);
  assert.ok(json.svg);
});
