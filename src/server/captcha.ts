import { randomBytes, randomInt, createHmac, timingSafeEqual } from 'node:crypto';
import { toEnglishDigits } from '../utils/formatters.js';

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
}

const PERSIAN_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
const TEXT_COLORS = ['#0f172a', '#1e293b', '#334155', '#0f766e', '#1d4ed8', '#4338ca', '#097969', '#374151'];
const LINE_COLORS = ['#94a3b8', '#cbd5e1', '#a1a1aa', '#64748b', '#7dd3fc', '#86efac'];

const consumedTokenIds = new Map<string, number>();

function cleanupConsumedTokens(): void {
  const now = Date.now();
  for (const [id, exp] of consumedTokenIds.entries()) {
    if (now > exp) {
      consumedTokenIds.delete(id);
    }
  }
}

function resolveSecretKey(customSecret?: string): string {
  if (customSecret && customSecret.trim().length > 0) {
    return customSecret;
  }
  return (
    process.env.CAPTCHA_SECRET ||
    process.env.AUTH_HMAC_KEY ||
    'persian_captcha_kit_default_fallback_hmac_secret_key_32_bytes_min'
  );
}

export function generateCaptcha(options?: GenerateCaptchaOptions): CaptchaResult {
  const width = options?.width ?? 200;
  const height = options?.height ?? 54;
  const ttlSeconds = options?.ttlSeconds ?? 180;
  const charCount = options?.charCount ?? 6;
  const secretKey = resolveSecretKey(options?.secret);

  const digits: number[] = [];
  for (let i = 0; i < charCount; i++) {
    digits.push(randomInt(0, 10));
  }
  const code = digits.join('');

  const lines: string[] = [];
  const lineCount = randomInt(3, 5);
  for (let i = 0; i < lineCount; i++) {
    const x1 = randomInt(5, 30);
    const y1 = randomInt(10, height - 10);
    const qx = randomInt(Math.floor(width / 3), Math.floor((width * 2) / 3));
    const qy = randomInt(5, height - 5);
    const x2 = randomInt(width - 30, width - 5);
    const y2 = randomInt(10, height - 10);
    const color = LINE_COLORS[randomInt(0, LINE_COLORS.length)];
    const strokeWidth = (randomInt(15, 25) / 10).toFixed(1);
    const opacity = (randomInt(50, 85) / 100).toFixed(2);
    lines.push(
      `<path d="M ${x1} ${y1} Q ${qx} ${qy} ${x2} ${y2}" stroke="${color}" stroke-width="${strokeWidth}" fill="none" opacity="${opacity}" />`
    );
  }

  const dots: string[] = [];
  const dotCount = randomInt(25, 35);
  for (let i = 0; i < dotCount; i++) {
    const cx = randomInt(5, width - 5);
    const cy = randomInt(5, height - 5);
    const r = (randomInt(10, 22) / 10).toFixed(1);
    const color = LINE_COLORS[randomInt(0, LINE_COLORS.length)];
    const opacity = (randomInt(40, 75) / 100).toFixed(2);
    dots.push(`<circle cx="${cx}" cy="${cy}" r="${r}" fill="${color}" opacity="${opacity}" />`);
  }

  const charElements: string[] = [];
  const startX = 26;
  const stepX = (width - 50) / Math.max(charCount - 1, 1);

  digits.forEach((digit, i) => {
    const persianChar = PERSIAN_DIGITS[digit];
    const x = Math.round(startX + i * stepX + randomInt(-2, 3));
    const y = Math.round(height * 0.68 + randomInt(-3, 4));
    const angle = randomInt(-16, 17);
    const fontSize = randomInt(28, 34);
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

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="کد امنیتی کپچای فارسی">
  <defs>
    <linearGradient id="pck-bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f8fafc" />
      <stop offset="100%" stop-color="#f1f5f9" />
    </linearGradient>
  </defs>
  <rect width="${width}" height="${height}" rx="10" ry="10" fill="url(#pck-bg)" stroke="#cbd5e1" stroke-width="1.2" />
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

export function verifyCaptchaToken(
  token: string | undefined | null,
  userInput: string | undefined | null,
  options?: VerifyCaptchaOptions
): VerifyResult {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  const normalizedInput = toEnglishDigits(userInput)
    .replace(/[\s\-_]/g, '')
    .trim();

  if (!/^\d+$/.test(normalizedInput)) {
    return { valid: false, error: 'INVALID_FORMAT' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  const [id, expStr, sig] = parts;
  const exp = parseInt(expStr, 10);

  if (!Number.isFinite(exp)) {
    return { valid: false, error: 'INVALID_TOKEN' };
  }

  if (Date.now() > exp) {
    return { valid: false, error: 'EXPIRED' };
  }

  if (consumedTokenIds.has(id)) {
    return { valid: false, error: 'ALREADY_USED' };
  }

  const secretKey = resolveSecretKey(options?.secret);
  const expectedHmac = createHmac('sha256', secretKey)
    .update(`${id}:${expStr}:${normalizedInput}`)
    .digest('hex');

  try {
    const sigBuffer = Buffer.from(sig, 'hex');
    const expectedBuffer = Buffer.from(expectedHmac, 'hex');

    if (sigBuffer.length !== expectedBuffer.length || !timingSafeEqual(sigBuffer, expectedBuffer)) {
      consumedTokenIds.set(id, exp);
      cleanupConsumedTokens();
      return { valid: false, error: 'INVALID_CODE' };
    }
  } catch {
    consumedTokenIds.set(id, exp);
    cleanupConsumedTokens();
    return { valid: false, error: 'INVALID_CODE' };
  }

  consumedTokenIds.set(id, exp);
  cleanupConsumedTokens();

  return { valid: true };
}
