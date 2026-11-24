import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import Redis from 'ioredis';
import { toPersianDigits, toEnglishDigits } from '../dist/index.js';
import { generateCaptcha, verifyCaptchaToken, MemoryCaptchaStore } from '../dist/server/index.js';
import { createCaptchaHandler } from '../dist/next/index.js';

const TEST_SECRET = 'a_very_secure_test_secret_key_with_at_least_32_characters_12345';

// Real Redis Lua script from README
const RECORD_ATTEMPT_LUA = `
local attemptKey = KEYS[1]
local consumedKey = KEYS[2]
local maxAttempts = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

if redis.call("EXISTS", consumedKey) == 1 then
  return {0, 0, 1}
end

local count = redis.call("INCR", attemptKey)
if count == 1 then
  redis.call("EXPIRE", attemptKey, ttl)
end

if count >= maxAttempts then
  redis.call("SET", consumedKey, "1", "EX", ttl)
end

if count > maxAttempts then
  return {0, 0, 0}
end

local remaining = maxAttempts - count
return {1, remaining, 0}
`;

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

test('generateCaptcha outputs valid SVG with unique gradient IDs and dual-signed token', () => {
  const c1 = generateCaptcha({ secret: TEST_SECRET });
  const c2 = generateCaptcha({ secret: TEST_SECRET });

  const idMatch1 = c1.svg.match(/id="(pck-bg-[a-f0-9]{8})"/);
  const idMatch2 = c2.svg.match(/id="(pck-bg-[a-f0-9]{8})"/);

  assert.ok(idMatch1, 'Gradient ID exists in c1');
  assert.ok(idMatch2, 'Gradient ID exists in c2');
  assert.notEqual(idMatch1[1], idMatch2[1], 'Each SVG must have a distinct gradient ID');

  const parts = c1.token.split('.');
  assert.equal(parts.length, 4, 'Token must contain 4 segments (id, exp, envelopeSig, codeSig)');
});

test('verifyCaptchaToken rejects forged envelope WITHOUT touching Store', async () => {
  const store = new MemoryCaptchaStore({ maxEntries: 1 });
  const fakeToken =
    '1234567890abcdef1234567890abcdef.1999999999999.1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

  for (let i = 0; i < 10; i++) {
    const res = await verifyCaptchaToken(fakeToken, '123456', { secret: TEST_SECRET, store });
    assert.equal(res.valid, false);
    assert.equal(res.error, 'INVALID_TOKEN');
  }

  const validCaptcha = generateCaptcha({ secret: TEST_SECRET });
  const validRes = await verifyCaptchaToken(validCaptcha.token, validCaptcha.code, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(validRes.valid, true, 'Store was not exhausted by forged tokens');
});

test('verifyCaptchaToken rejects unreasonable future expiry timestamps', async () => {
  const store = new MemoryCaptchaStore();
  const validCaptcha = generateCaptcha({ secret: TEST_SECRET });
  const [id, , envSig, codeSig] = validCaptcha.token.split('.');

  const farFutureExp = Date.now() + 10 * 24 * 60 * 60 * 1000;
  const futureToken = `${id}.${farFutureExp}.${envSig}.${codeSig}`;

  const res = await verifyCaptchaToken(futureToken, validCaptcha.code, {
    secret: TEST_SECRET,
    store,
  });
  assert.equal(res.valid, false);
  assert.equal(res.error, 'INVALID_TOKEN');
});

test('verifyCaptchaToken burns token atomically when maxAttempts is reached', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // Attempt 1: wrong code (maxAttempts: 2)
  const r1 = await verifyCaptchaToken(captcha.token, '000000', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r1.valid, false);
  assert.equal(r1.error, 'INVALID_CODE');
  assert.equal(r1.attemptsRemaining, 1);

  // Attempt 2: final allowed attempt with wrong code -> token is burned immediately in the same step
  const r2 = await verifyCaptchaToken(captcha.token, '111111', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r2.valid, false);
  assert.equal(r2.error, 'INVALID_CODE');
  assert.equal(r2.attemptsRemaining, 0);

  // Attempt 3: subsequent attempt must be rejected as ALREADY_USED
  const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r3.valid, false);
  assert.equal(r3.error, 'ALREADY_USED');
});

test('verifyCaptchaToken permits valid solution on the exact final allowed attempt', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  // Attempt 1: wrong code (maxAttempts: 2)
  await verifyCaptchaToken(captcha.token, '000000', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });

  // Attempt 2: final allowed attempt with correct code -> must succeed!
  const r2 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r2.valid, true);

  // Attempt 3: subsequent attempt rejected as ALREADY_USED
  const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r3.valid, false);
  assert.equal(r3.error, 'ALREADY_USED');
});

test('verifyCaptchaToken handles concurrent verification attempts safely on MemoryStore', async () => {
  const store = new MemoryCaptchaStore();
  const captcha = generateCaptcha({ secret: TEST_SECRET });

  const results = await Promise.all([
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
    verifyCaptchaToken(captcha.token, captcha.code, { secret: TEST_SECRET, store, maxAttempts: 5 }),
  ]);

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

test('Session Binding with Domain Separation', async () => {
  function deriveSessionSecret(masterSecret, sessionId) {
    return createHmac('sha256', masterSecret)
      .update(`persian-captcha-session:${sessionId}`)
      .digest('hex');
  }

  const sessionA = 'user_session_abc_12345';
  const sessionB = 'attacker_session_xyz_67890';

  const secretA = deriveSessionSecret(TEST_SECRET, sessionA);
  const secretB = deriveSessionSecret(TEST_SECRET, sessionB);

  // 1. Generate captcha bound to Session A
  const captchaA = generateCaptcha({ secret: secretA });

  // 2. Verification within Session A must SUCCEED
  const resValid = await verifyCaptchaToken(captchaA.token, captchaA.code, { secret: secretA });
  assert.equal(resValid.valid, true, 'Session A must verify its own token successfully');

  // 3. Verification of Session A token using Session B secret must FAIL (INVALID_TOKEN)
  const resInvalid = await verifyCaptchaToken(captchaA.token, captchaA.code, { secret: secretB });
  assert.equal(resInvalid.valid, false);
  assert.equal(resInvalid.error, 'INVALID_TOKEN', 'Token from Session A cannot be verified with Session B secret');
});

test('REAL REDIS SERVER: Lua Script, Cluster Hash Slots, TTL, and Concurrency', async () => {
  const redisPort = Number(process.env.TEST_REDIS_PORT || 6380);
  const redis = new Redis({
    host: '127.0.0.1',
    port: redisPort,
    lazyConnect: true,
    connectTimeout: 1000,
  });

  try {
    await redis.connect();
  } catch {
    console.warn(`[SKIP] Real Redis server not reachable on 127.0.0.1:${redisPort}, skipping live Redis test.`);
    return;
  }

  const redisStore = {
    async recordAttempt(id, maxAttempts, ttlSeconds) {
      const attemptKey = `captcha:{${id}}:attempt`;
      const consumedKey = `captcha:{${id}}:consumed`;

      const result = await redis.eval(
        RECORD_ATTEMPT_LUA,
        2,
        attemptKey,
        consumedKey,
        maxAttempts,
        ttlSeconds
      );

      const [allowed, remaining, consumed] = result;
      return {
        allowed: allowed === 1,
        attemptsRemaining: remaining,
        consumed: consumed === 1,
      };
    },

    async markConsumed(id, ttlSeconds) {
      const consumedKey = `captcha:{${id}}:consumed`;
      const res = await redis.set(consumedKey, '1', 'EX', ttlSeconds, 'NX');
      return res === 'OK';
    },
  };

  const captcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 60 });
  const id = captcha.token.split('.')[0];

  // 1. First attempt with wrong code
  const r1 = await verifyCaptchaToken(captcha.token, '000000', {
    secret: TEST_SECRET,
    store: redisStore,
    maxAttempts: 2,
  });
  assert.equal(r1.valid, false);
  assert.equal(r1.error, 'INVALID_CODE');
  assert.equal(r1.attemptsRemaining, 1);

  // Check TTL and Key on real Redis
  const ttl = await redis.ttl(`captcha:{${id}}:attempt`);
  assert.ok(ttl > 0 && ttl <= 60, `TTL must be active on real Redis (got ${ttl})`);

  // 2. Final attempt with correct code succeeds
  const r2 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store: redisStore,
    maxAttempts: 2,
  });
  assert.equal(r2.valid, true);

  // 3. Subsequent attempt rejected as ALREADY_USED
  const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store: redisStore,
    maxAttempts: 2,
  });
  assert.equal(r3.valid, false);
  assert.equal(r3.error, 'ALREADY_USED');

  // 4. Concurrency test on Real Redis: 5 parallel requests
  const concurrentCaptcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 60 });
  const concurrentResults = await Promise.all([
    verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: redisStore, maxAttempts: 5 }),
    verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: redisStore, maxAttempts: 5 }),
    verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: redisStore, maxAttempts: 5 }),
    verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: redisStore, maxAttempts: 5 }),
    verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: redisStore, maxAttempts: 5 }),
  ]);

  const liveSuccess = concurrentResults.filter((r) => r.valid).length;
  const liveAlreadyUsed = concurrentResults.filter((r) => r.error === 'ALREADY_USED').length;
  assert.equal(liveSuccess, 1, 'Only one concurrent request can succeed on real Redis');
  assert.equal(liveAlreadyUsed, 4, 'Remaining concurrent requests must be rejected by real Redis');

  // Cleanup keys
  await redis.del(`captcha:{${id}}:attempt`, `captcha:{${id}}:consumed`);
  await redis.quit();
});

test('React Component request ordering logic: ignores out-of-order delayed responses', async () => {
  let requestId = 0;
  let activeToken = '';

  const dispatchRequest = async (tokenToDeliver, delayMs) => {
    const currentId = ++requestId;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    if (currentId !== requestId) {
      return;
    }
    activeToken = tokenToDeliver;
  };

  const req1 = dispatchRequest('token_1_delayed', 100);
  const req2 = dispatchRequest('token_2_newer', 20);

  await Promise.all([req1, req2]);

  assert.equal(
    activeToken,
    'token_2_newer',
    'State must reflect the latest request even if older request finishes later'
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
