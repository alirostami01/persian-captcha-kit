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
  | 'INVALID_TOKEN';

export interface VerifyResult {
  valid: boolean;
  error?: VerifyErrorCode;
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
}

const PERSIAN_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
const TEXT_COLORS = ['#0f172a', '#1e293b', '#334155', '#0f766e', '#1d4ed8', '#4338ca', '#097969', '#374151'];
const LINE_COLORS = ['#94a3b8', '#cbd5e1', '#a1a1aa', '#64748b', '#7dd3fc', '#86efac'];

// Pattern: [32 hex chars].[13 digits timestamp].[64 hex chars HMAC]
const TOKEN_REGEX = /^[a-f0-9]{32}\.\d{13}\.[a-f0-9]{64}$/;

export function resolveSecretKey(customSecret?: string): string {
  const secret = (customSecret || process.env.CAPTCHA_SECRET || process.env.AUTH_HMAC_KEY || '').trim();
  if (!secret) {
    throw new Error(
      '[@persian-captcha-kit/server] CAPTCHA_SECRET is required. Please provide it via options or the CAPTCHA_SECRET environment variable.'
    );
  }
  if (secret.length < 32) {
    throw new Error(
      '[@persian-captcha-kit/server] CAPTCHA_SECRET must be at least 32 characters long to ensure cryptographic security.'
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
 * Generates a random Persian numerical CAPTCHA with SVG markup and HMAC token.
 */
export function generateCaptcha(options?: GenerateCaptchaOptions): CaptchaResult {
  const secretKey = resolveSecretKey(options?.secret);

  // Validate and clamp configuration values to prevent arithmetic errors and DoS attacks
  const width = clamp(options?.width ?? 200, 120, 600, 200);
  const height = clamp(options?.height ?? 54, 36, 200, 54);
  const ttlSeconds = clamp(options?.ttlSeconds ?? 180, 30, 900, 180);
  const charCount = clamp(options?.charCount ?? 6, 4, 8, 6);

  const digits: number[] = [];
  for (let i = 0; i < charCount; i++) {
    digits.push(randomInt(0, 10));
  }
  const code = digits.join('');

  // Generate random Bezier noise curves
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

  // Generate random scatter noise dots
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

  // Render Persian digit characters
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

  // Generate unique gradient ID to avoid collisions when multiple SVGs render on the same page
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
  const hmac = createHmac('sha256', secretKey);
  hmac.update(`${id}:${exp}:${code}`);
  const sig = hmac.digest('hex');
  const token = `${id}.${exp}.${sig}`;

  return {
    token,
    svg,
    code,
    expiresIn: ttlSeconds,
  };
}

/**
 * Validates a submitted captcha token and user input against replay and timing attacks.
 */
export async function verifyCaptchaToken(
  token: string | undefined | null,
  userInput: string | undefined | null,
  options?: VerifyCaptchaOptions
): Promise<VerifyResult> {
  const secretKey = resolveSecretKey(options?.secret);
  const store = options?.store || defaultMemoryStore;

  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  // Strict token format validation
  if (!TOKEN_REGEX.test(token)) {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  const [id, expStr, sig] = token.split('.');
  const exp = parseInt(expStr, 10);

  // Check expiration before further computation
  if (Date.now() > exp) {
    return { valid: false, error: 'EXPIRED' };
  }

  // Normalize user digits input (supports Persian, Arabic, and Western digits)
  const normalizedInput = toEnglishDigits(userInput)
    .replace(/[\s\-_]/g, '')
    .trim();

  if (!/^\d{4,8}$/.test(normalizedInput)) {
    return { valid: false, error: 'INVALID_FORMAT' };
  }

  // Verify HMAC signature in constant time before mutating state
  const expectedHmac = createHmac('sha256', secretKey)
    .update(`${id}:${expStr}:${normalizedInput}`)
    .digest('hex');

  let isSignatureValid = false;
  try {
    const sigBuffer = Buffer.from(sig, 'hex');
    const expectedBuffer = Buffer.from(expectedHmac, 'hex');
    isSignatureValid =
      sigBuffer.length === expectedBuffer.length && timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    isSignatureValid = false;
  }

  if (!isSignatureValid) {
    return { valid: false, error: 'INVALID_CODE' };
  }

  // Atomically mark token as consumed to prevent replay attacks
  const ttlSeconds = Math.max(1, Math.ceil((exp - Date.now()) / 1000));
  const consumed = await store.markConsumed(id, ttlSeconds);

  if (!consumed) {
    return { valid: false, error: 'ALREADY_USED' };
  }

  return { valid: true };
}
