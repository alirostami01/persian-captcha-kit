import { randomBytes, randomInt, createHmac, timingSafeEqual } from 'node:crypto';
import { toEnglishDigits } from '../utils/formatters.js';
import { CaptchaStore, defaultMemoryStore } from './store.js';

export interface CaptchaResult {
  token: string;
  svg: string;
  code: string;
  expiresIn: number;
}

export type VerifyErrorCode =
  | 'INVALID_FORMAT'
  | 'INVALID_CODE'
  | 'EXPIRED'
  | 'ALREADY_USED'
  | 'TOO_MANY_ATTEMPTS'
  | 'INVALID_TOKEN'
  | 'STORE_ERROR';

export interface VerifyResult {
  valid: boolean;
  error?: VerifyErrorCode;
  attemptsRemaining?: number;
}

export interface GenerateCaptchaOptions {
  width?: number;
  height?: number;
  ttlSeconds?: number;
  secret?: string;
  charCount?: number;
}

export interface VerifyCaptchaOptions {
  secret?: string;
  store?: CaptchaStore;
  maxAttempts?: number;
}

const PERSIAN_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
const TEXT_COLORS = ['#0f172a', '#1e293b', '#334155', '#0f766e', '#1d4ed8', '#4338ca', '#097969', '#374151'];
const LINE_COLORS = ['#94a3b8', '#cbd5e1', '#a1a1aa', '#64748b', '#7dd3fc', '#86efac'];

// Token structure: [32 hex id].[13 digits exp].[64 hex envelopeSig].[64 hex codeSig]
const TOKEN_REGEX = /^[a-f0-9]{32}\.\d{13}\.[a-f0-9]{64}\.[a-f0-9]{64}$/;

// Maximum allowable TTL in the future (15 minutes + 60s clock skew) to prevent future timestamp attacks
const MAX_FUTURE_WINDOW_MS = (900 + 60) * 1000;

export function resolveSecretKey(customSecret?: string): string {
  const secret = customSecret ?? process.env.CAPTCHA_SECRET ?? process.env.AUTH_HMAC_KEY;
  if (secret === undefined || secret === null || secret.trim() === '') {
    throw new Error(
      '[@persian-captcha-kit/server] CAPTCHA_SECRET is required. Please provide it via options or the CAPTCHA_SECRET environment variable.'
    );
  }

  const byteLength = Buffer.byteLength(secret, 'utf8');
  if (byteLength < 32) {
    throw new Error(
      `[@persian-captcha-kit/server] CAPTCHA_SECRET must be at least 32 bytes long (currently ${byteLength} bytes) to ensure cryptographic security.`
    );
  }
  return secret;
}

function clamp(value: number, min: number, max: number, defaultValue: number): number {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    return defaultValue;
  }
  return Math.max(min, Math.min(max, Math.round(value)));
}

/**
 * Generates a random Persian numerical CAPTCHA with SVG markup and dual-signed HMAC token.
 */
export function generateCaptcha(options?: GenerateCaptchaOptions): CaptchaResult {
  const secretKey = resolveSecretKey(options?.secret);

  const width = clamp(options?.width ?? 200, 120, 600, 200);
  const height = clamp(options?.height ?? 54, 36, 200, 54);
  const ttlSeconds = clamp(options?.ttlSeconds ?? 180, 30, 900, 180);
  const charCount = clamp(options?.charCount ?? 6, 4, 8, 6);

  const digits: number[] = [];
  for (let i = 0; i < charCount; i++) {
    digits.push(randomInt(0, 10));
  }
  const code = digits.join('');

  const lines: string[] = [];
  const lineCount = randomInt(3, 6);
  for (let i = 0; i < lineCount; i++) {
    const x1 = randomInt(5, Math.max(10, Math.floor(width * 0.15)));
    const y1 = randomInt(5, height - 5);
    const qx = randomInt(Math.floor(width / 3), Math.floor((width * 2) / 3));
    const qy = randomInt(5, height - 5);
    const x2 = randomInt(Math.floor(width * 0.85), width - 5);
    const y2 = randomInt(5, height - 5);
    const color = LINE_COLORS[randomInt(0, LINE_COLORS.length)];
    const strokeWidth = (randomInt(15, 25) / 10).toFixed(1);
    const opacity = (randomInt(50, 85) / 100).toFixed(2);
    lines.push(
      `<path d="M ${x1} ${y1} Q ${qx} ${qy} ${x2} ${y2}" stroke="${color}" stroke-width="${strokeWidth}" fill="none" opacity="${opacity}" />`
    );
  }

  const dots: string[] = [];
  const dotCount = randomInt(25, 40);
  for (let i = 0; i < dotCount; i++) {
    const cx = randomInt(5, width - 5);
    const cy = randomInt(5, height - 5);
    const r = (randomInt(10, 22) / 10).toFixed(1);
    const color = LINE_COLORS[randomInt(0, LINE_COLORS.length)];
    const opacity = (randomInt(40, 75) / 100).toFixed(2);
    dots.push(`<circle cx="${cx}" cy="${cy}" r="${r}" fill="${color}" opacity="${opacity}" />`);
  }

  const charElements: string[] = [];
  const paddingX = Math.floor(width * 0.12);
  const stepX = (width - paddingX * 2) / Math.max(charCount - 1, 1);
  const baseFontSize = Math.min(Math.floor(height * 0.65), 36);

  digits.forEach((digit, i) => {
    const persianChar = PERSIAN_DIGITS[digit];
    const x = Math.round(paddingX + i * stepX + randomInt(-2, 3));
    const y = Math.round(height * 0.68 + randomInt(-2, 3));
    const angle = randomInt(-16, 17);
    const fontSize = randomInt(baseFontSize - 3, baseFontSize + 3);
    const color = TEXT_COLORS[randomInt(0, TEXT_COLORS.length)];

    charElements.push(
      `<text x="${x}" y="${y}" font-family="Vazirmatn, 'Segoe UI', Tahoma, sans-serif" font-size="${fontSize}" font-weight="700" fill="${color}" transform="rotate(${angle}, ${x}, ${y})" text-anchor="middle" dominant-baseline="alphabetic">${persianChar}</text>`
    );
  });

  const halfLines = Math.ceil(lines.length / 2);
  const halfDots = Math.ceil(dots.length / 2);

  const backgroundLines = lines.slice(0, halfLines).join('');
  const foregroundLines = lines.slice(halfLines).join('');
  const backgroundDots = dots.slice(0, halfDots).join('');
  const foregroundDots = dots.slice(halfDots).join('');

  const gradientId = `pck-bg-${randomBytes(4).toString('hex')}`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="Persian Captcha Code">
  <defs>
    <linearGradient id="${gradientId}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f8fafc" />
      <stop offset="100%" stop-color="#f1f5f9" />
    </linearGradient>
  </defs>
  <rect width="${width}" height="${height}" rx="10" ry="10" fill="url(#${gradientId})" stroke="#cbd5e1" stroke-width="1.2" />
  ${backgroundLines}
  ${backgroundDots}
  ${charElements.join('')}
  ${foregroundLines}
  ${foregroundDots}
</svg>`;

  const id = randomBytes(16).toString('hex');
  const exp = Date.now() + ttlSeconds * 1000;

  // 1. Envelope signature: Signs the authenticity of the token's ID and expiry (Independent of the user code)
  const envelopeSig = createHmac('sha256', secretKey)
    .update(`envelope:${id}:${exp}`)
    .digest('hex');

  // 2. Code signature: Signs the solution code bound to this envelope
  const codeSig = createHmac('sha256', secretKey)
    .update(`code:${id}:${exp}:${code}`)
    .digest('hex');

  const token = `${id}.${exp}.${envelopeSig}.${codeSig}`;

  return {
    token,
    svg,
    code,
    expiresIn: ttlSeconds,
  };
}

/**
 * Validates a submitted captcha token and user input against replay, brute-force, and timing attacks.
 * Authenticates token envelope authenticity BEFORE recording any attempt in the store.
 */
export async function verifyCaptchaToken(
  token: string | undefined | null,
  userInput: string | undefined | null,
  options?: VerifyCaptchaOptions
): Promise<VerifyResult> {
  const secretKey = resolveSecretKey(options?.secret);
  const store = options?.store || defaultMemoryStore;
  const maxAttempts = clamp(options?.maxAttempts ?? 3, 1, 10, 3);

  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  // 1. Strict regex validation for dual-signed format
  if (!TOKEN_REGEX.test(token)) {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  const [id, expStr, envelopeSig, codeSig] = token.split('.');
  const exp = parseInt(expStr, 10);
  const now = Date.now();

  // 2. Bound expiration window: reject expired tokens or unreasonable future timestamps
  if (now > exp) {
    return { valid: false, error: 'EXPIRED' };
  }
  if (exp - now > MAX_FUTURE_WINDOW_MS) {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  // 3. Authenticate the ENVELOPE first in constant time.
  // If the envelope signature is forged, REJECT IMMEDIATELY without touching or polluting the Store.
  const expectedEnvelopeHmac = createHmac('sha256', secretKey)
    .update(`envelope:${id}:${expStr}`)
    .digest('hex');

  try {
    const envelopeSigBuffer = Buffer.from(envelopeSig, 'hex');
    const expectedEnvelopeBuffer = Buffer.from(expectedEnvelopeHmac, 'hex');

    if (
      envelopeSigBuffer.length !== expectedEnvelopeBuffer.length ||
      !timingSafeEqual(envelopeSigBuffer, expectedEnvelopeBuffer)
    ) {
      return { valid: false, error: 'INVALID_TOKEN' };
    }
  } catch {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  // 4. Validate user input format
  const normalizedInput = toEnglishDigits(userInput)
    .replace(/[\s\-_]/g, '')
    .trim();

  if (!/^\d{4,8}$/.test(normalizedInput)) {
    return { valid: false, error: 'INVALID_FORMAT' };
  }

  // 5. Authenticated envelope verified! Now safely record attempt in the store.
  const ttlSeconds = Math.max(1, Math.ceil((exp - now) / 1000));

  let attemptResult;
  try {
    attemptResult = await store.recordAttempt(id, maxAttempts, ttlSeconds);
  } catch {
    return { valid: false, error: 'STORE_ERROR' };
  }

  if (attemptResult.consumed) {
    return { valid: false, error: 'ALREADY_USED', attemptsRemaining: 0 };
  }

  if (!attemptResult.allowed) {
    return { valid: false, error: 'TOO_MANY_ATTEMPTS', attemptsRemaining: 0 };
  }

  // 6. Verify the code HMAC signature
  const expectedCodeHmac = createHmac('sha256', secretKey)
    .update(`code:${id}:${expStr}:${normalizedInput}`)
    .digest('hex');

  let isCodeValid = false;
  try {
    const codeSigBuffer = Buffer.from(codeSig, 'hex');
    const expectedCodeBuffer = Buffer.from(expectedCodeHmac, 'hex');
    isCodeValid =
      codeSigBuffer.length === expectedCodeBuffer.length &&
      timingSafeEqual(codeSigBuffer, expectedCodeBuffer);
  } catch {
    isCodeValid = false;
  }

  if (!isCodeValid) {
    return {
      valid: false,
      error: 'INVALID_CODE',
      attemptsRemaining: attemptResult.attemptsRemaining,
    };
  }

  // 7. Mark token as fully consumed upon successful verification
  try {
    // If the token was not already burned during the final allowed attempt, mark it consumed now
    if (attemptResult.attemptsRemaining > 0) {
      const consumed = await store.markConsumed(id, ttlSeconds);
      if (!consumed) {
        return { valid: false, error: 'ALREADY_USED', attemptsRemaining: 0 };
      }
    }
  } catch {
    return { valid: false, error: 'STORE_ERROR' };
  }

  return { valid: true, attemptsRemaining: attemptResult.attemptsRemaining };
}
