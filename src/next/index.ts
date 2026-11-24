import { generateCaptcha, GenerateCaptchaOptions } from '../server/captcha.js';

export interface NextCaptchaHandlerOptions extends GenerateCaptchaOptions {
  headers?: Record<string, string>;
  onError?: (error: unknown) => void;
}

export function createCaptchaHandler(options?: NextCaptchaHandlerOptions) {
  const handler = async function GET() {
    try {
      const captcha = generateCaptcha(options);
      
      const customHeaders = options?.headers || {};
      
      return new Response(
        JSON.stringify({
          ok: true,
          token: captcha.token,
          svg: captcha.svg,
          expiresIn: captcha.expiresIn,
        }),
        {
          status: 200,
          headers: {
            ...customHeaders,
            // هدرهای حیاتی امنیتی و جلوگیری از کش غیرقابل بازنویسی هستند
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            Pragma: 'no-cache',
            Expires: '0',
            Vary: 'Origin',
          },
        }
      );
    } catch (err) {
      if (options?.onError) {
        options.onError(err);
      }
      return new Response(
        JSON.stringify({ ok: false, error: 'CAPTCHA_GENERATION_FAILED' }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
          },
        }
      );
    }
  };

  return { GET: handler };
}
