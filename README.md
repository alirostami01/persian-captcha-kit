# Persian Captcha Kit (`persian-captcha-kit`)

[![npm version](https://img.shields.io/npm/v/persian-captcha-kit.svg?style=flat-square)](https://www.npmjs.com/package/persian-captcha-kit)
[![license](https://img.shields.io/npm/l/persian-captcha-kit.svg?style=flat-square)](https://github.com/alirostami01/persian-captcha-kit/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg?style=flat-square)](https://www.typescriptlang.org/)

A lightweight, zero-dependency, cryptographically secure Persian (Farsi) SVG Captcha kit tailored for **Node.js**, **Next.js**, and **React**.

---

## 🌟 Highlights

- ⚡ **Zero External Dependencies:** Built solely on native `node:crypto`. No canvas bindings, Cairo, Python, or heavy binary dependencies required.
- 🔒 **Stateless & Cryptographically Secure:** Employs HMAC-SHA256 token verification. No database tables or migration steps required.
- 🛡️ **Anti-Replay & Timing-Safe:** Tokens are single-use (`ALREADY_USED` prevention) and validated using `crypto.timingSafeEqual` to guard against timing attacks.
- 🎨 **Dynamic SVG Generation:** Visual noise, curved Bezier lines, scatter dots, multi-layer depth, and random rotations for Persian digits.
- 🇮🇷 **Native Persian & Arabic Digits Handling:** Built-in normalization seamlessly accepts Persian (`۰-۹`), Arabic (`٠-٩`), and Western digits (`0-9`).
- 📦 **Dual Module Output:** Ships ESM and CommonJS builds with full TypeScript declarations (`.d.ts`).
- ⚛️ **Out-of-the-Box React & Next.js Support:** Plug-and-play UI component with zero CSS/framework assumptions and self-contained vector icons.

---

## 📦 Installation

```bash
# npm
npm install persian-captcha-kit

# pnpm
pnpm add persian-captcha-kit

# yarn
yarn add persian-captcha-kit
```

---

## 🚀 Quick Start

### 1. Server-Side (Node.js / Express / Fastify / NestJS)

```typescript
import { generateCaptcha, verifyCaptchaToken } from 'persian-captcha-kit/server';

// 1. Generate captcha
const captcha = generateCaptcha({
  width: 200,
  height: 54,
  ttlSeconds: 180, // Valid for 3 minutes
  charCount: 6,    // 6-digit Persian code
  secret: process.env.CAPTCHA_SECRET, // Optional HMAC secret
});

// captcha object returns:
// {
//   token: '4a1b...29.1711234567.8f3a...',
//   svg: '<svg ...>...</svg>',
//   code: '482910',
//   expiresIn: 180
// }

// Send `captcha.svg` and `captcha.token` to your client.
// Keep `captcha.code` private (it is cryptographically encoded inside `captcha.token`).

// 2. Verify user input
const verification = verifyCaptchaToken(tokenFromClient, inputFromUser, {
  secret: process.env.CAPTCHA_SECRET,
});

if (verification.valid) {
  console.log('Captcha verified successfully!');
} else {
  console.error('Verification error:', verification.error);
  // Possible error codes:
  // - 'INVALID_CODE': User entered the wrong digits
  // - 'EXPIRED': Token expired (exceeded ttlSeconds)
  // - 'ALREADY_USED': Replay attack prevented (token was already consumed)
  // - 'INVALID_FORMAT': Input is not a valid number sequence
  // - 'INVALID_TOKEN': Malformed or forged token
}
```

---

### 2. Next.js Route Handler (App Router)

Create an endpoint at `app/api/captcha/route.ts`:

```typescript
import { createCaptchaHandler } from 'persian-captcha-kit/next';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const { GET } = createCaptchaHandler({
  ttlSeconds: 180,
  charCount: 6,
  secret: process.env.CAPTCHA_SECRET,
});
```

---

### 3. Next.js Pages Router API (`pages/api/captcha.ts`)

```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import { generateCaptcha } from 'persian-captcha-kit/server';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, error: 'METHOD_NOT_ALLOWED' });
  }

  const captcha = generateCaptcha();

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  return res.status(200).json({
    ok: true,
    token: captcha.token,
    svg: captcha.svg,
    expiresIn: captcha.expiresIn,
  });
}
```

---

### 4. Client-Side (React / Next.js)

```tsx
'use client';

import React, { useState } from 'react';
import { PersianCaptcha } from 'persian-captcha-kit/react';

export default function LoginForm() {
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaCode, setCaptchaCode] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'user@example.com',
        captchaToken,
        captchaCode,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      setErrorMessage(data.message || 'Login failed');
      // Reset token to trigger captcha auto-refresh on failure
      setCaptchaToken('');
    }
  };

  return (
    <form onSubmit={handleSubmit} style={{ maxWidth: 360, margin: '0 auto' }}>
      {/* Other form fields */}

      <PersianCaptcha
        token={captchaToken}
        onTokenChange={setCaptchaToken}
        code={captchaCode}
        onCodeChange={setCaptchaCode}
        apiEndpoint="/api/captcha"
        error={errorMessage}
      />

      <button type="submit" style={{ marginTop: 16 }}>
        ورود
      </button>
    </form>
  );
}
```

---

## 🛠️ API Reference

### Server Module (`persian-captcha-kit/server`)

#### `generateCaptcha(options?): CaptchaResult`
Generates a random Persian digit captcha and returns its SVG payload and token.

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `width` | `number` | `200` | SVG image width in pixels. |
| `height` | `number` | `54` | SVG image height in pixels. |
| `ttlSeconds`| `number` | `180` | Token lifetime in seconds (3 minutes). |
| `charCount` | `number` | `6` | Total random Persian digits in the captcha. |
| `secret` | `string` | `process.env.CAPTCHA_SECRET` | Secret HMAC salt key. |

**Returns `CaptchaResult`:**
```typescript
interface CaptchaResult {
  token: string;     // Cryptographic token to pass to the client
  svg: string;       // Vector SVG markup ready to render
  code: string;      // The actual numerical digits (keep server-side)
  expiresIn: number; // TTL in seconds
}
```

---

#### `verifyCaptchaToken(token, userInput, options?): VerifyResult`
Validates a submitted user response against the given token.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `token` | `string` | The token string received from client. |
| `userInput` | `string` | Digits entered by the user (Persian, Arabic, or English). |
| `options.secret` | `string` | HMAC secret (must match the one used during generation). |

**Returns `VerifyResult`:**
```typescript
interface VerifyResult {
  valid: boolean;
  error?: 'INVALID_FORMAT' | 'INVALID_CODE' | 'EXPIRED' | 'ALREADY_USED' | 'INVALID_TOKEN';
}
```

---

### React Component (`persian-captcha-kit/react`)

#### `<PersianCaptcha {...props} />`

| Prop | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `token` | `string` | *Required* | Current captcha token state. |
| `onTokenChange` | `(token: string) => void` | *Required* | Callback triggered when a new token is retrieved. |
| `code` | `string` | *Required* | Current user input digits state. |
| `onCodeChange` | `(code: string) => void` | *Required* | Callback triggered when user types in the input. |
| `apiEndpoint` | `string` | `'/api/captcha'` | Target API URL returning `{ ok, token, svg }`. |
| `fetchCaptcha` | `() => Promise<PersianCaptchaApiResponse>` | `undefined` | Custom fetcher function (optional override for `apiEndpoint`). |
| `charCount` | `number` | `6` | Maximum digit count accepted by the input. |
| `error` | `string \| null` | `undefined` | Error message displayed below the input. |
| `disabled` | `boolean` | `false` | Disables input and reload button. |
| `className` | `string` | `''` | Custom CSS class applied to root container. |
| `label` | `string` | `'کد امنیتی (ارقام تصویر)'` | Label heading text. |
| `placeholder` | `string` | `'کد تصویر را وارد کنید'` | Input placeholder text. |
| `loadingText` | `string` | `'در حال بارگذاری...'` | Text shown while fetching new SVG. |
| `retryText` | `string` | `'خطا در دریافت کد؛ کلیک برای تلاش مجدد'` | Error prompt for reload on network failure. |

---

### Format Utilities (`persian-captcha-kit`)

Convenient conversion functions included out of the box:

```typescript
import { toEnglishDigits, toPersianDigits } from 'persian-captcha-kit';

toEnglishDigits('۱۲۳۴۵۶'); // '123456'
toEnglishDigits('١٢٣٤٥٦'); // '123456'
toPersianDigits('123456'); // '۱۲۳۴۵۶'
```

---

## 🔒 Security Architecture

1. **HMAC Signature Structure:**  
   Tokens follow the format:
   ```
   [random_uuid].[expiration_timestamp].[hmac_sha256_signature]
   ```
   The HMAC signs `id:expiration:code` using your secret key. The cleartext code is never exposed in the token.

2. **Replay Protection:**  
   Once a token is successfully verified or rejected due to a wrong code attempt, its `id` is marked as consumed in an in-memory TTL map until its natural expiration. Attempting to submit the same token twice triggers `ALREADY_USED`.

3. **Constant-Time Verification:**  
   Signatures are verified using `crypto.timingSafeEqual` to eliminate timing attack vectors.

---

## 📄 License

MIT © [Ali Rostami](https://github.com/alirostami01)
