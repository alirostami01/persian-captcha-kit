# Persian Captcha Kit (`persian-captcha-kit`)

[![npm version](https://img.shields.io/npm/v/persian-captcha-kit.svg?style=flat-square)](https://www.npmjs.com/package/persian-captcha-kit)
[![license](https://img.shields.io/npm/l/persian-captcha-kit.svg?style=flat-square)](https://github.com/alirostami01/persian-captcha-kit/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg?style=flat-square)](https://www.typescriptlang.org/)

A lightweight, zero-dependency, cryptographically secure Persian (Farsi) SVG Captcha toolkit designed for **Node.js**, **Next.js**, and **React**.

---

## Highlights

- **Zero Binary Dependencies:** Runs natively with `node:crypto`. No need for Cairo, canvas, or Python bindings.
- **HMAC Signed Tokens:** Uses HMAC-SHA256 tokens with mandatory secret validation (at least 32 characters).
- **Pluggable Anti-Replay Store:** Comes with a capped in-memory store and supports custom distributed stores (e.g., Redis) for multi-instance environments.
- **Timing-Safe:** Verified via `crypto.timingSafeEqual` to safeguard against timing attacks.
- **Dynamic Noise:** Random Bezier curves, scattered dots, and unique SVG gradient IDs per image.
- **Digit Normalization:** Handles Persian (`۰-۹`), Arabic (`٠-٩`), and Western (`0-9`) digits seamlessly.
- **Secure React Component:** Uses data URIs in an `<img>` tag to prevent XSS and handles race conditions via `AbortController`.
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

// 1. Generate captcha (requires a secret of at least 32 characters)
const captcha = generateCaptcha({
  secret: process.env.CAPTCHA_SECRET, // or configure process.env.CAPTCHA_SECRET
  width: 200,
  height: 54,
  ttlSeconds: 180,
  charCount: 6,
});

// Returns:
// {
//   token: '...',
//   svg: '<svg ...>...</svg>',
//   code: '482910',
//   expiresIn: 180
// }

// 2. Verify user response
const result = await verifyCaptchaToken(tokenFromClient, userInputCode, {
  secret: process.env.CAPTCHA_SECRET,
});

if (result.valid) {
  // Captcha passed
} else {
  console.log(result.error);
  // 'INVALID_CODE' | 'EXPIRED' | 'ALREADY_USED' | 'INVALID_FORMAT' | 'INVALID_TOKEN'
}
```

---

### 2. Custom Distributed Store (e.g., Redis for Multi-Instance Setup)

```typescript
import { verifyCaptchaToken, CaptchaStore } from 'persian-captcha-kit/server';

// Example Redis adapter
const redisStore: CaptchaStore = {
  async isConsumed(id: string) {
    const exists = await redis.exists(`captcha:${id}`);
    return exists === 1;
  },
  async markConsumed(id: string, ttlSeconds: number) {
    // Atomic SET NX EX ensures single consumption across instances
    const res = await redis.set(`captcha:${id}`, '1', 'EX', ttlSeconds, 'NX');
    return res === 'OK';
  },
};

const result = await verifyCaptchaToken(token, userInput, {
  secret: process.env.CAPTCHA_SECRET,
  store: redisStore,
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

## License

MIT
