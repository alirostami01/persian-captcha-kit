import test from 'node:test';
import assert from 'node:assert/strict';
import { generateCaptcha, verifyCaptchaToken, toPersianDigits, toEnglishDigits } from '../dist/index.js';
import { createCaptchaHandler } from '../dist/next/index.js';

test('toEnglishDigits & toPersianDigits', () => {
  assert.equal(toEnglishDigits('۱۲۳۴۵۶'), '123456');
  assert.equal(toEnglishDigits('١٢٣٤٥٦'), '123456');
  assert.equal(toPersianDigits('123456'), '۱۲۳۴۵۶');
});

test('generateCaptcha creates valid SVG and token', () => {
  const captcha = generateCaptcha({ charCount: 6 });
  assert.equal(typeof captcha.token, 'string');
  assert.equal(typeof captcha.svg, 'string');
  assert.equal(typeof captcha.code, 'string');
  assert.equal(captcha.code.length, 6);
  assert.ok(captcha.svg.includes('<svg'));
  assert.ok(captcha.svg.includes('</svg>'));
  assert.equal(captcha.expiresIn, 180);
});

test('verifyCaptchaToken works with English and Persian digits', () => {
  const captcha = generateCaptcha({ secret: 'my_test_secret_key_123456789012' });
  
  // Persian input
  const persianInput = toPersianDigits(captcha.code);
  const result = verifyCaptchaToken(captcha.token, persianInput, {
    secret: 'my_test_secret_key_123456789012',
  });
  assert.equal(result.valid, true);

  // Replay should fail
  const replay = verifyCaptchaToken(captcha.token, persianInput, {
    secret: 'my_test_secret_key_123456789012',
  });
  assert.equal(replay.valid, false);
  assert.equal(replay.error, 'ALREADY_USED');
});

test('verifyCaptchaToken handles invalid codes and formats', () => {
  const captcha = generateCaptcha();
  
  // Wrong code
  const wrongCode = captcha.code === '111111' ? '222222' : '111111';
  const badCodeResult = verifyCaptchaToken(captcha.token, wrongCode);
  assert.equal(badCodeResult.valid, false);
  assert.equal(badCodeResult.error, 'INVALID_CODE');

  // Invalid format
  const badFormat = verifyCaptchaToken(captcha.token, 'abc');
  assert.equal(badFormat.valid, false);
  assert.equal(badFormat.error, 'INVALID_FORMAT');

  // Expired
  const expiredCaptcha = generateCaptcha({ ttlSeconds: -5 });
  const expiredResult = verifyCaptchaToken(expiredCaptcha.token, expiredCaptcha.code);
  assert.equal(expiredResult.valid, false);
  assert.equal(expiredResult.error, 'EXPIRED');
});

test('createCaptchaHandler works for Next.js App Router', async () => {
  const handler = createCaptchaHandler();
  const response = await handler.GET();
  assert.equal(response.status, 200);
  const json = await response.json();
  assert.equal(json.ok, true);
  assert.ok(json.token);
  assert.ok(json.svg);
});
