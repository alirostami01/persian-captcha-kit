# Persian Captcha Kit (`persian-captcha-kit`)

[![npm version](https://img.shields.io/npm/v/persian-captcha-kit.svg?style=flat-square)](https://www.npmjs.com/package/persian-captcha-kit)
[![license](https://img.shields.io/npm/l/persian-captcha-kit.svg?style=flat-square)](https://github.com/alirostami01/persian-captcha-kit/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg?style=flat-square)](https://www.typescriptlang.org/)

A lightweight, zero-dependency, cryptographically secured Persian (Farsi) SVG Captcha toolkit for **Node.js**, **Next.js**, and **React**.

---

## Highlights

- **Zero Binary Dependencies:** Runs natively using standard `node:crypto`. No canvas, Cairo, or Python bindings required.
- **Dual-Signed HMAC Tokens:** Validates token envelope authenticity (ID and expiration window) *before* recording verification attempts, preventing Store exhaustion by forged tokens.
- **Brute-Force & Replay Protection:** Configurable maximum verification attempts (`maxAttempts`, defaults to 3) before a token is automatically burned.
- **Pluggable Anti-Replay Store:** Includes a non-evicting memory store and supports custom distributed stores (e.g., Redis via atomic Lua scripts) for multi-instance environments.
- **Timing-Safe:** Verified via `crypto.timingSafeEqual` to safeguard against timing attacks.
- **Dynamic Noise:** Random Bezier curves, scattered dots, and unique SVG gradient IDs per image.
- **Digit Normalization:** Handles Persian (`۰-۹`), Arabic (`٠-٩`), and Western (`0-9`) digits seamlessly.
- **Safe React Component:** Renders via an `<img>` data URI to prevent DOM/HTML injection and manages race conditions using `AbortController` and request ordering.
- **Dual Format:** Exports ESM, CommonJS, and complete TypeScript declaration types.

---

## Installation

```bash
npm install persian-captcha-kit
```

---

## Quick Start

### 1. Server-Side (Node.js / Express / Fastify)

```typescript
import { generateCaptcha, verifyCaptchaToken } from 'persian-captcha-kit/server';

// 1. Generate captcha (requires a secret of at least 32 bytes)
const captcha = generateCaptcha({
  secret: process.env.CAPTCHA_SECRET,
  width: 200,
  height: 54,
  ttlSeconds: 180,
  charCount: 6,
});

// Returns:
// {
//   token: '4a1b...29.1711234567.8f3a....c92e...',
//   svg: '<svg ...>...</svg>',
//   code: '482910',
//   expiresIn: 180
// }

// 2. Verify user response
const result = await verifyCaptchaToken(tokenFromClient, userInputCode, {
  secret: process.env.CAPTCHA_SECRET,
  maxAttempts: 3, // Defaults to 3 attempts
});

if (result.valid) {
  // Captcha passed successfully
} else {
  console.log(result.error);
  // 'INVALID_CODE'       -> Wrong code (check result.attemptsRemaining)
  // 'TOO_MANY_ATTEMPTS'  -> Exceeded max attempts quota
  // 'ALREADY_USED'       -> Token was already consumed
  // 'EXPIRED'            -> Token expired
  // 'INVALID_FORMAT'     -> Invalid digits length/format
  // 'INVALID_TOKEN'      -> Forged or malformed token
  // 'STORE_ERROR'        -> Store capacity exceeded or infrastructure error
}
```

---

### 2. Distributed Store with Redis (Atomic Lua Script)

For clustered or multi-instance environments, implement `CaptchaStore` using an atomic Lua script to guarantee concurrency safety and avoid orphan keys:

```typescript
import { verifyCaptchaToken, CaptchaStore, StoreResult } from 'persian-captcha-kit/server';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

// Lua script for atomic attempt recording and instant burning on final attempt
const RECORD_ATTEMPT_LUA = `
local attemptKey = KEYS[1]
local consumedKey = KEYS[2]
local maxAttempts = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

-- 1. Check if token was already burned or consumed
if redis.call("EXISTS", consumedKey) == 1 then
  return {0, 0, 1}
end

-- 2. Atomically increment attempts
local count = redis.call("INCR", attemptKey)
if count == 1 then
  redis.call("EXPIRE", attemptKey, ttl)
end

-- 3. If count hits or exceeds maxAttempts, burn token immediately for subsequent requests
if count >= maxAttempts then
  redis.call("SET", consumedKey, "1", "EX", ttl)
end

-- 4. Check if current attempt is allowed
if count > maxAttempts then
  return {0, 0, 0}
end

local remaining = maxAttempts - count
return {1, remaining, 0}
`;

const redisStore: CaptchaStore = {
  async recordAttempt(id: string, maxAttempts: number, ttlSeconds: number): Promise<StoreResult> {
    // Uses Redis Hash Tags `{id}` to ensure both keys map to the same Hash Slot in Redis Cluster
    const attemptKey = `captcha:{${id}}:attempt`;
    const consumedKey = `captcha:{${id}}:consumed`;

    const [allowed, remaining, consumed] = (await redis.eval(
      RECORD_ATTEMPT_LUA,
      2,
      attemptKey,
      consumedKey,
      maxAttempts,
      ttlSeconds
    )) as [number, number, number];

    return {
      allowed: allowed === 1,
      attemptsRemaining: remaining,
      consumed: consumed === 1,
    };
  },

  async markConsumed(id: string, ttlSeconds: number): Promise<boolean> {
    const consumedKey = `captcha:{${id}}:consumed`;
    const res = await redis.set(consumedKey, '1', 'EX', ttlSeconds, 'NX');
    return res === 'OK';
  },
};

// Use in verification:
const result = await verifyCaptchaToken(token, userInput, {
  secret: process.env.CAPTCHA_SECRET,
  store: redisStore,
  maxAttempts: 3,
});
```

> [!NOTE]
> The automated integration test suite verifies cluster behavior against a live multi-node Redis Cluster. The cluster topology verification test requires Redis 4.0+ (which introduced node IDs in `CLUSTER SLOTS`), and automatically uses `CLUSTER SHARDS` on Redis 7.0+. Normal runtime package usage with custom store adapters is version-agnostic and compatible with any Redis version supporting your chosen commands/Lua scripts.

---

### 3. Next.js App Router (`app/api/captcha/route.ts`)

```typescript
import { createCaptchaHandler } from 'persian-captcha-kit/next';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const { GET } = createCaptchaHandler({
  secret: process.env.CAPTCHA_SECRET,
  ttlSeconds: 180,
  charCount: 6,
});
```

---

### 4. Client-Side (React / Next.js)

```tsx
'use client';

import React, { useState } from 'react';
import { PersianCaptcha } from 'persian-captcha-kit/react';

export default function LoginForm() {
  const [token, setToken] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);

  return (
    <form>
      <PersianCaptcha
        token={token}
        onTokenChange={setToken}
        code={code}
        onCodeChange={setCode}
        apiEndpoint="/api/captcha"
        error={error}
      />
    </form>
  );
}
```

---

## Utility Functions

```typescript
import { toEnglishDigits, toPersianDigits } from 'persian-captcha-kit';

toEnglishDigits('۱۲۳۴۵۶'); // '123456'
toPersianDigits('123456'); // '۱۲۳۴۵۶'
```

---

## Scope & Security Architecture

### 1. CAPTCHA Scope
Persian Captcha Kit provides a cryptographically signed CAPTCHA challenge designed to distinguish humans from automated scripts. It does not replace network-level rate limiting (e.g., Cloudflare, IP-based limits) or account-lockout policies. Always combine CAPTCHA verification with proper rate limiting on sensitive routes.

### 2. Session Binding (Recommended for High-Security Endpoints)
By default, captcha tokens are self-contained and stateless. If your threat model requires binding a CAPTCHA strictly to a specific user session to prevent token forwarding between clients:

```typescript
import { createHmac } from 'node:crypto';
import { generateCaptcha, verifyCaptchaToken } from 'persian-captcha-kit/server';

// Derive domain-separated secret from trusted server-side session (never client-provided input)
function deriveSessionSecret(masterSecret: string, sessionId: string): string {
  return createHmac('sha256', masterSecret)
    .update(`persian-captcha-session:${sessionId}`)
    .digest('hex');
}

// When generating:
const sessionSecret = deriveSessionSecret(process.env.CAPTCHA_SECRET!, req.session.id);
const captcha = generateCaptcha({ secret: sessionSecret });

// When verifying:
const verifySecret = deriveSessionSecret(process.env.CAPTCHA_SECRET!, req.session.id);
const result = await verifyCaptchaToken(token, code, { secret: verifySecret });
```

---

## License

MIT © [Ali Rostami](https://github.com/alirostami01)
