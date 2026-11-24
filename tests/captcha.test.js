import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import Redis from 'ioredis';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import ReactDOMClient from 'react-dom/client';
import { toPersianDigits, toEnglishDigits } from '../dist/index.js';
import { generateCaptcha, verifyCaptchaToken, MemoryCaptchaStore } from '../dist/server/index.js';
import { createCaptchaHandler } from '../dist/next/index.js';
import { PersianCaptcha } from '../dist/react/index.js';
import {
  MAX_CANDIDATE_ATTEMPTS,
  parseClusterShards,
  parseClusterSlots,
  getClusterTopology,
  findDeterministicCandidateId,
} from './helpers/cluster-topology.js';

// Setup minimal DOM environment for React tests
const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', {
  url: 'http://localhost',
});
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', {
  value: dom.window.navigator,
  configurable: true,
  writable: true,
});
globalThis.AbortController = dom.window.AbortController;
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const TEST_SECRET = 'a_very_secure_test_secret_key_with_at_least_32_characters_12345';

// Single source of truth: Load Lua script from external fixture file
const RECORD_ATTEMPT_LUA = fs.readFileSync(
  fileURLToPath(new URL('fixtures/record-attempt.lua', import.meta.url)),
  'utf8'
);

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

  const r1 = await verifyCaptchaToken(captcha.token, '000000', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r1.valid, false);
  assert.equal(r1.error, 'INVALID_CODE');
  assert.equal(r1.attemptsRemaining, 1);

  const r2 = await verifyCaptchaToken(captcha.token, '111111', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r2.valid, false);
  assert.equal(r2.error, 'INVALID_CODE');
  assert.equal(r2.attemptsRemaining, 0);

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

  await verifyCaptchaToken(captcha.token, '000000', {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });

  const r2 = await verifyCaptchaToken(captcha.token, captcha.code, {
    secret: TEST_SECRET,
    store,
    maxAttempts: 2,
  });
  assert.equal(r2.valid, true);

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

  const captchaA = generateCaptcha({ secret: secretA });

  const resValid = await verifyCaptchaToken(captchaA.token, captchaA.code, { secret: secretA });
  assert.equal(resValid.valid, true, 'Session A must verify its own token successfully');

  const resInvalid = await verifyCaptchaToken(captchaA.token, captchaA.code, { secret: secretB });
  assert.equal(resInvalid.valid, false);
  assert.equal(resInvalid.error, 'INVALID_TOKEN', 'Token from Session A cannot be verified with Session B secret');
});

test('REAL REDIS SERVER: Lua Script, Cluster Hash Slots, TTL, Consumed Key, and Concurrency', async () => {
  const redisPort = Number(process.env.TEST_REDIS_PORT || 6380);
  const isRequired = process.env.REQUIRE_REDIS === 'true';

  const redis = new Redis({
    host: '127.0.0.1',
    port: redisPort,
    lazyConnect: true,
    connectTimeout: 1000,
    maxRetriesPerRequest: 0,
    retryStrategy: () => null,
  });
  redis.on('error', () => {});

  try {
    await redis.connect();
  } catch (err) {
    try {
      redis.disconnect();
    } catch {}
    if (isRequired) {
      throw new Error(`[FAIL] Redis connection required in CI but failed to connect on 127.0.0.1:${redisPort}: ${err}`);
    }
    console.warn(`[SKIP] Real Redis server not reachable on 127.0.0.1:${redisPort}, skipping live Redis test.`);
    return;
  }

  const createdTokenIds = new Set();

  try {
    const redisStore = {
      async recordAttempt(tokenKeyId, maxAttempts, ttlSeconds) {
        const attemptKey = `captcha:{${tokenKeyId}}:attempt`;
        const consumedKey = `captcha:{${tokenKeyId}}:consumed`;

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

      async markConsumed(tokenKeyId, ttlSeconds) {
        const consumedKey = `captcha:{${tokenKeyId}}:consumed`;
        const res = await redis.set(consumedKey, '1', 'EX', ttlSeconds, 'NX');
        return res === 'OK';
      },
    };

    const captcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 60 });
    const realId = captcha.token.split('.')[0];
    createdTokenIds.add(realId);

    // 1. First attempt with wrong code
    const r1 = await verifyCaptchaToken(captcha.token, '000000', {
      secret: TEST_SECRET,
      store: redisStore,
      maxAttempts: 2,
    });
    assert.equal(r1.valid, false);
    assert.equal(r1.error, 'INVALID_CODE');
    assert.equal(r1.attemptsRemaining, 1);

    const attemptTtl = await redis.ttl(`captcha:{${realId}}:attempt`);
    assert.ok(attemptTtl > 0 && attemptTtl <= 60, `Attempt TTL must be active on real Redis (got ${attemptTtl})`);

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

    // Verify consumed key TTL
    const consumedTtl = await redis.ttl(`captcha:{${realId}}:consumed`);
    assert.ok(consumedTtl > 0 && consumedTtl <= 60, `Consumed TTL must be active on real Redis (got ${consumedTtl})`);

    // 4. Concurrency test on Real Redis: 5 parallel requests
    const concurrentCaptcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 60 });
    const concurrentRealId = concurrentCaptcha.token.split('.')[0];
    createdTokenIds.add(concurrentRealId);

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
  } finally {
    // Guaranteed cleanup of all real keys in finally with isolated error handling per key
    try {
      await Promise.allSettled(
        Array.from(createdTokenIds).map((tokenId) =>
          redis.del(`captcha:{${tokenId}}:attempt`, `captcha:{${tokenId}}:consumed`)
        )
      );
    } catch {
      // Ignore key deletion error
    } finally {
      try {
        await redis.quit();
      } catch {
        // Ignore disconnect error
      }
    }
  }
});

test('PROVEN REAL REDIS CLUSTER: Multi-Node Sharding, Hash Slot Co-location, and CrossSlot Prevention', async () => {
  const isClusterRequired = process.env.REQUIRE_REDIS_CLUSTER === 'true';
  let cluster;
  try {
    cluster = new Redis.Cluster(
      [
        { host: '127.0.0.1', port: 7000 },
        { host: '127.0.0.1', port: 7001 },
        { host: '127.0.0.1', port: 7002 },
      ],
      {
        clusterRetryStrategy: () => null,
        enableReadyCheck: true,
        scaleReads: 'all',
        lazyConnect: true,
      }
    );
    cluster.on('error', () => {});
    await cluster.connect();
    await cluster.ping();
  } catch (err) {
    if (cluster) {
      try { cluster.disconnect(); } catch {}
    }
    if (isClusterRequired) {
      throw new Error(`[FAIL] Redis Cluster connection required in CI but failed to connect on ports 7000-7002: ${err}`);
    }
    console.warn('[SKIP] Real Redis Cluster (ports 7000-7002) not running locally, skipping cluster proof test.');
    return;
  }

  const createdTokenIds = new Set();

  try {
    const clusterStore = {
      async recordAttempt(tokenKeyId, maxAttempts, ttlSeconds) {
        // Critical: The {tokenKeyId} hash tag ensures BOTH keys map to the exact same hash slot!
        const attemptKey = `captcha:{${tokenKeyId}}:attempt`;
        const consumedKey = `captcha:{${tokenKeyId}}:consumed`;

        const result = await cluster.eval(
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

      async markConsumed(tokenKeyId, ttlSeconds) {
        const consumedKey = `captcha:{${tokenKeyId}}:consumed`;
        const res = await cluster.set(consumedKey, '1', 'EX', ttlSeconds, 'NX');
        return res === 'OK';
      },
    };

    // 1. Verify Topology and Explicit Cluster Health via CLUSTER INFO
    const masters = cluster.nodes('master');
    assert.ok(masters.length >= 3, `Redis Cluster must have at least 3 master nodes connected (found ${masters.length})`);

    const infoStr = await cluster.cluster('INFO');
    assert.match(infoStr, /cluster_state:ok/, 'Cluster state must be ok');
    assert.match(infoStr, /cluster_slots_assigned:16384/, 'All 16384 slots must be assigned');
    assert.match(infoStr, /cluster_slots_ok:16384/, 'All 16384 slots must be ok');
    assert.match(infoStr, /cluster_slots_fail:0/, 'Zero cluster slots should be failed');

    const captcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 60 });
    const realId = captcha.token.split('.')[0];
    createdTokenIds.add(realId);

    // 2. Hash Slot Co-location Proof: Native Redis CLUSTER KEYSLOT validation
    const slotAttempt = await cluster.cluster('KEYSLOT', `captcha:{${realId}}:attempt`);
    const slotConsumed = await cluster.cluster('KEYSLOT', `captcha:{${realId}}:consumed`);
    assert.equal(
      slotAttempt,
      slotConsumed,
      `Both attempt and consumed keys for token {${realId}} MUST map to the exact same hash slot (${slotAttempt})`
    );

    // 3. First attempt with wrong code
    const r1 = await verifyCaptchaToken(captcha.token, '000000', {
      secret: TEST_SECRET,
      store: clusterStore,
      maxAttempts: 2,
    });
    assert.equal(r1.valid, false);
    assert.equal(r1.error, 'INVALID_CODE');
    assert.equal(r1.attemptsRemaining, 1);

    // Verify key in cluster
    const attemptVal = await cluster.get(`captcha:{${realId}}:attempt`);
    assert.equal(attemptVal, '1');

    // 4. Final attempt with correct code succeeds on cluster
    const r2 = await verifyCaptchaToken(captcha.token, captcha.code, {
      secret: TEST_SECRET,
      store: clusterStore,
      maxAttempts: 2,
    });
    assert.equal(r2.valid, true, 'Execution of atomic Lua on real Redis Cluster succeeds');

    // 5. Subsequent replay attempt blocked on cluster
    const r3 = await verifyCaptchaToken(captcha.token, captcha.code, {
      secret: TEST_SECRET,
      store: clusterStore,
      maxAttempts: 2,
    });
    assert.equal(r3.valid, false);
    assert.equal(r3.error, 'ALREADY_USED');

    // 6. Concurrency test across cluster
    const concurrentCaptcha = generateCaptcha({ secret: TEST_SECRET, ttlSeconds: 60 });
    const concurrentRealId = concurrentCaptcha.token.split('.')[0];
    createdTokenIds.add(concurrentRealId);

    const concurrentResults = await Promise.all([
      verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: clusterStore, maxAttempts: 5 }),
      verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: clusterStore, maxAttempts: 5 }),
      verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: clusterStore, maxAttempts: 5 }),
      verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: clusterStore, maxAttempts: 5 }),
      verifyCaptchaToken(concurrentCaptcha.token, concurrentCaptcha.code, { secret: TEST_SECRET, store: clusterStore, maxAttempts: 5 }),
    ]);

    const liveSuccess = concurrentResults.filter((r) => r.valid).length;
    const liveAlreadyUsed = concurrentResults.filter((r) => r.error === 'ALREADY_USED').length;
    assert.equal(liveSuccess, 1, 'Only one concurrent request can succeed on real Redis Cluster');
    assert.equal(liveAlreadyUsed, 4, 'Remaining concurrent requests must be rejected by real Redis Cluster');

    // 7. Multi-Node Sharding Proof via Redis 7+ CLUSTER SHARDS (with fallback to CLUSTER SLOTS):
    // Authoritatively query shard topology, match masters by immutable Node ID (MYID),
    // and execute atomic operations with 100% deterministic key allocation across every master.
    const allShards = await getClusterTopology(cluster);

    // Filter slot-owning shards (shards without slots must not be tested for key allocation)
    const activeShards = allShards.filter((shard) => shard.slots.length > 0);
    assert.ok(activeShards.length >= 3, 'Must have at least 3 active slot-owning shards');

    // Map each master instance by its unique, authoritative Node ID (MYID)
    const masterNodeMap = new Map();
    for (const m of masters) {
      const myId = await m.cluster('MYID');
      masterNodeMap.set(myId, m);
    }

    // Ensure every active shard maps to exactly one connected master connection
    for (const shard of activeShards) {
      assert.ok(
        masterNodeMap.has(shard.masterId),
        `Active shard with Node ID ${shard.masterId} must map to a connected master node`
      );
    }

    // Deterministically allocate and test a valid token for every single active master shard
    for (const shard of activeShards) {
      const targetMaster = masterNodeMap.get(shard.masterId);
      assert.ok(targetMaster, `Master instance matching Node ID ${shard.masterId} must exist`);

      // Deterministically find a 32-hex ID whose CRC16 slot falls into this shard (bounded by MAX_CANDIDATE_ATTEMPTS)
      const { id: deterministicId, slot } = await findDeterministicCandidateId(
        cluster,
        shard,
        MAX_CANDIDATE_ATTEMPTS
      );

      createdTokenIds.add(deterministicId);

      // Verify slot co-location for attempt and consumed keys
      const sAttempt = await cluster.cluster('KEYSLOT', `captcha:{${deterministicId}}:attempt`);
      const sConsumed = await cluster.cluster('KEYSLOT', `captcha:{${deterministicId}}:consumed`);
      assert.equal(sAttempt, sConsumed, 'Slot co-location must hold for attempt and consumed keys');
      assert.equal(sAttempt, slot);

      // Execute atomic Lua on the cluster
      const recordRes = await clusterStore.recordAttempt(deterministicId, 3, 60);
      assert.equal(recordRes.allowed, true, `recordAttempt for slot ${slot} must succeed`);
      assert.equal(recordRes.attemptsRemaining, 2);

      // Physically verify key existence on the authoritative master instance identified by Node ID
      const val = await targetMaster.get(`captcha:{${deterministicId}}:attempt`);
      assert.equal(val, '1', `Key must reside physically on master node ID ${shard.masterId} (slot ${slot})`);
    }
  } finally {
    // Guaranteed cleanup of all real keys in finally with isolated error handling per key
    try {
      await Promise.allSettled(
        Array.from(createdTokenIds).map((tokenId) =>
          cluster.del(`captcha:{${tokenId}}:attempt`, `captcha:{${tokenId}}:consumed`)
        )
      );
    } catch {
      // Ignore key deletion error
    } finally {
      try {
        await cluster.quit();
      } catch {
        // Ignore disconnect error
      }
    }
  }
});

test('React Component: same-instance concurrent requests with out-of-order delayed response', async () => {
  const container = document.getElementById('root');
  const root = ReactDOMClient.createRoot(container);

  let currentToken = 'initial_active_token';
  let currentCode = '';
  const onTokenChange = (t) => { currentToken = t; };
  const onCodeChange = (c) => { currentCode = c; };

  let callCount = 0;
  let triggerFirstResolve;
  let triggerSecondResolve;

  const firstPromise = new Promise((resolve) => { triggerFirstResolve = resolve; });
  const secondPromise = new Promise((resolve) => { triggerSecondResolve = resolve; });

  const mockFetchCaptcha = async () => {
    callCount++;
    const thisCall = callCount;
    if (thisCall === 1) {
      await firstPromise;
      return { ok: true, token: 'token_1_delayed', svg: '<svg id="svg_delayed_1"></svg>' };
    } else {
      await secondPromise;
      return { ok: true, token: 'token_2_faster', svg: '<svg id="svg_faster_2"></svg>' };
    }
  };

  // 1. Mount PersianCaptcha instance with an active token
  await act(async () => {
    root.render(
      React.createElement(PersianCaptcha, {
        token: currentToken,
        onTokenChange,
        code: currentCode,
        onCodeChange,
        fetchCaptcha: mockFetchCaptcha,
      })
    );
  });

  assert.equal(callCount, 0, 'No fetch on mount when token is already present');

  const inputEl = container.querySelector('input');
  assert.ok(inputEl, 'Input element must exist');
  const reloadBtn = container.querySelector('button[aria-label="دریافت کد جدید"]');
  assert.ok(reloadBtn, 'Reload button must exist and be enabled initially');
  assert.equal(reloadBtn.disabled, false, 'Reload button is enabled initially');

  // Trigger Call 1 via clicking the reload button
  await act(async () => {
    reloadBtn.click();
  });
  assert.equal(callCount, 1, 'Clicking reload button dispatches Call 1');

  // 2. While Call 1 is in-flight, simulate the parent resetting the token to '' (e.g., after failed submission)
  // Re-rendering the SAME instance with token='' triggers useEffect and dispatches Call 2
  await act(async () => {
    root.render(
      React.createElement(PersianCaptcha, {
        token: '',
        onTokenChange,
        code: currentCode,
        onCodeChange,
        fetchCaptcha: mockFetchCaptcha,
      })
    );
  });

  assert.equal(callCount, 2, 'Resetting token to empty string on the same instance dispatches Call 2');

  // 3. Resolve Call 2 FIRST (faster response)
  await act(async () => {
    triggerSecondResolve();
    await new Promise((r) => setTimeout(r, 20));
  });

  assert.equal(currentToken, 'token_2_faster', 'Token must update to the faster response (Call 2)');
  const imgElAfterCall2 = container.querySelector('img');
  assert.ok(imgElAfterCall2, 'SVG img tag must be rendered in DOM');
  assert.ok(imgElAfterCall2.src.includes('svg_faster_2'), 'DOM img src must display Call 2 SVG');

  // 4. Resolve Call 1 AFTER Call 2 (stale/delayed response)
  await act(async () => {
    triggerFirstResolve();
    await new Promise((r) => setTimeout(r, 20));
  });

  // Verify that the same instance discarded Call 1 completely:
  assert.equal(
    currentToken,
    'token_2_faster',
    'Component must discard delayed Call 1 response and retain latest token'
  );
  const finalImgEl = container.querySelector('img');
  assert.ok(
    finalImgEl.src.includes('svg_faster_2'),
    'DOM img src must still display Call 2 SVG and not be overwritten by delayed response'
  );

  // Clean up
  await act(async () => {
    root.unmount();
  });
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

test('Regression: parseClusterShards parses valid CLUSTER SHARDS response', () => {
  const mockShards = [
    [
      'slots', [0, 5460],
      'nodes', [
        ['id', 'node_1', 'port', 7000, 'ip', '127.0.0.1', 'role', 'master']
      ]
    ],
    [
      'slots', [5461, 10922],
      'nodes', [
        ['id', 'node_2', 'port', 7001, 'ip', '127.0.0.1', 'role', 'master']
      ]
    ]
  ];
  const result = parseClusterShards(mockShards);
  assert.equal(result.length, 2);
  assert.deepEqual(result[0], { masterId: 'node_1', slots: [[0, 5460]] });
  assert.deepEqual(result[1], { masterId: 'node_2', slots: [[5461, 10922]] });
});

test('Regression: unsupported SHARDS command triggers CLUSTER SLOTS fallback', async () => {
  let slotsCalled = false;
  const mockCluster = {
    async cluster(subcommand) {
      if (subcommand === 'SHARDS') {
        const err = new Error("ERR unknown subcommand 'SHARDS'. Try CLUSTER HELP.");
        err.name = 'ReplyError';
        throw err;
      }
      if (subcommand === 'SLOTS') {
        slotsCalled = true;
        return [
          [0, 5460, ['127.0.0.1', 7000, 'node_1']],
          [5461, 16383, ['127.0.0.1', 7001, 'node_2']],
        ];
      }
      throw new Error(`Unexpected subcommand: ${subcommand}`);
    },
  };

  const topology = await getClusterTopology(mockCluster);
  assert.equal(slotsCalled, true);
  assert.equal(topology.length, 2);
  assert.equal(topology[0].masterId, 'node_1');
  assert.equal(topology[1].masterId, 'node_2');
});

test('Regression: Redis < 4.0 / missing node ID produces explicit compatibility error', () => {
  // Redis 3.x returned [start, end, [ip, port]] without node ID (masterInfo length = 2)
  const redis3Slots = [
    [0, 5460, ['127.0.0.1', 7000]],
    [5461, 16383, ['127.0.0.1', 7001]],
  ];

  assert.throws(
    () => parseClusterSlots(redis3Slots),
    /Unsupported Redis Cluster topology version: CLUSTER SLOTS response does not contain node IDs/
  );
});

test('Regression: multiple non-contiguous slot ranges are grouped under one unique master ID', () => {
  const rawSlots = [
    [0, 1000, ['127.0.0.1', 7000, 'master_alpha']],
    [1001, 5000, ['127.0.0.1', 7001, 'master_beta']],
    [5001, 8000, ['127.0.0.1', 7000, 'master_alpha']],
    [8001, 16383, ['127.0.0.1', 7001, 'master_beta']],
  ];

  const result = parseClusterSlots(rawSlots);
  assert.equal(result.length, 2, 'Must produce exactly one shard per unique master ID');

  const alpha = result.find((s) => s.masterId === 'master_alpha');
  assert.ok(alpha);
  assert.deepEqual(alpha.slots, [
    [0, 1000],
    [5001, 8000],
  ]);

  const beta = result.find((s) => s.masterId === 'master_beta');
  assert.ok(beta);
  assert.deepEqual(beta.slots, [
    [1001, 5000],
    [8001, 16383],
  ]);
});

test('Regression: shards without slots are excluded from key allocation', () => {
  const mockShards = [
    { masterId: 'active_1', slots: [[0, 5000]] },
    { masterId: 'empty_master', slots: [] },
    { masterId: 'active_2', slots: [[5001, 16383]] },
  ];

  const activeShards = mockShards.filter((s) => s.slots.length > 0);
  assert.equal(activeShards.length, 2);
  assert.equal(activeShards.some((s) => s.masterId === 'empty_master'), false);
});

test('Regression: network errors in CLUSTER SHARDS are propagated without fallback', async () => {
  let slotsCalled = false;
  const mockCluster = {
    async cluster(subcommand) {
      if (subcommand === 'SHARDS') {
        const err = new Error('connect ECONNREFUSED 127.0.0.1:7000');
        err.code = 'ECONNREFUSED';
        throw err;
      }
      if (subcommand === 'SLOTS') {
        slotsCalled = true;
        return [];
      }
    },
  };

  await assert.rejects(
    async () => getClusterTopology(mockCluster),
    /ECONNREFUSED/
  );
  assert.equal(slotsCalled, false, 'SLOTS must never be called on network errors');
});

test('Regression: ACL and permission errors are propagated without fallback', async () => {
  let slotsCalled = false;
  const mockCluster = {
    async cluster(subcommand) {
      if (subcommand === 'SHARDS') {
        const err = new Error("NOPERM User captcha has no permissions to run 'cluster|shards'");
        throw err;
      }
      if (subcommand === 'SLOTS') {
        slotsCalled = true;
        return [];
      }
    },
  };

  await assert.rejects(
    async () => getClusterTopology(mockCluster),
    /NOPERM/
  );
  assert.equal(slotsCalled, false, 'SLOTS must never be called on ACL/permission errors');
});

test('Regression: malformed topology responses are rejected explicitly', async () => {
  assert.throws(() => parseClusterShards('not an array'), /Malformed CLUSTER SHARDS response/);
  assert.throws(
    () => parseClusterShards([['slots', 'bad_slots', 'nodes', []]]),
    /slots property must be an array/
  );
  assert.throws(
    () => parseClusterShards([['slots', [0, 100], 'nodes', [['id', '', 'role', 'master']]]]),
    /master node missing valid ID/
  );
  assert.throws(() => parseClusterSlots('not an array'), /Malformed CLUSTER SLOTS response/);
  assert.throws(() => parseClusterSlots([['bad_entry']]), /entry must contain at least/);
  assert.throws(
    () => parseClusterSlots([[100, 50, ['127.0.0.1', 7000, 'node1']]]),
    /invalid slot range/
  );
});

test('Regression: findDeterministicCandidateId terminates at configured limit with descriptive error', async () => {
  const mockCluster = {
    async cluster() {
      return 9999;
    },
  };

  const shard = {
    masterId: 'test_node_unreachable',
    slots: [[0, 500]],
  };

  await assert.rejects(
    async () => findDeterministicCandidateId(mockCluster, shard, 50),
    /Failed to find candidate token ID for master ID test_node_unreachable within 50 attempts/
  );
});
