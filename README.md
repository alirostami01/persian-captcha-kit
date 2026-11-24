# Persian Captcha Kit (`persian-captcha-kit`)

[![npm version](https://img.shields.io/npm/v/persian-captcha-kit.svg?style=flat-square)](https://www.npmjs.com/package/persian-captcha-kit)
[![license](https://img.shields.io/npm/l/persian-captcha-kit.svg?style=flat-square)](https://github.com/alirostami01/persian-captcha-kit/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg?style=flat-square)](https://www.typescriptlang.org/)

A lightweight, zero-dependency, cryptographically secured Persian (Farsi) SVG Captcha toolkit for **Node.js**, **Next.js**, and **React**.

---

## Highlights

- **Zero Binary Dependencies:** Runs natively using standard `node:crypto`. No canvas, Cairo, or Python bindings required.
- **HMAC Signed Tokens:** Employs HMAC-SHA256 tokens with mandatory secret validation (at least 32 bytes).
- **Brute-Force & Replay Protection:** Configurable maximum verification attempts (`maxAttempts`, defaults to 3) before a token is automatically burned.
- **Pluggable Anti-Replay Store:** Includes a non-evicting memory store and supports custom distributed stores (e.g., Redis via atomic operations) for multi-instance environments.
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
//   token: '4a1b...29.1711234567.8f3a...',
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

### 2. Distributed Store with Redis (ioredis / node-redis)

For clustered or multi-instance environments, implement the `CaptchaStore` interface:

```typescript
import { verifyCaptchaToken, CaptchaStore, StoreResult } from 'persian-captcha-kit/server';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

const redisStore: CaptchaStore = {
  async recordAttempt(id: string, maxAttempts: number, ttlSeconds: number): Promise<StoreResult> {
    const key = `captcha:attempt:${id}`;
    // Atomically increment attempt count
    const count = await redis.incr(key);
    if (count === 1) {
      await redis.expire(key, ttlSeconds);
    }

    const consumed = (await redis.get(`captcha:consumed:${id}`)) === '1';
    if (consumed) {
      return { allowed: false, attemptsRemaining: 0, consumed: true };
    }

    const allowed = count <= maxAttempts;
    return {
      allowed,
      attemptsRemaining: Math.max(0, maxAttempts - count),
      consumed: !allowed,
    };
  },

  async markConsumed(id: string, ttlSeconds: number): Promise<boolean> {
    const key = `captcha:consumed:${id}`;
    // Atomic SET NX EX ensures single consumption across all server instances
    const res = await redis.set(key, '1', 'EX', ttlSeconds, 'NX');
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

## Scope & Security Note

Persian Captcha Kit provides visual Turing challenge verification and cryptographic proof-of-work. It does not replace network-level rate limiting (e.g., Cloudflare, IP-based limits) or account-lockout policies. Always combine CAPTCHA verification with proper rate limiting on sensitive routes.

---

## License

MIT © [Ali Rostami](https://github.com/alirostami01)
