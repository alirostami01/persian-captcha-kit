import { generateCaptcha, GenerateCaptchaOptions } from '../server/captcha.js';

export interface NextCaptchaHandlerOptions extends GenerateCaptchaOptions {
  headers?: Record<string, string>;
}

export function createCaptchaHandler(options?: NextCaptchaHandlerOptions) {
  const handler = async function GET() {
    try {
      const captcha = generateCaptcha(options);
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
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            Vary: 'Origin',
            ...(options?.headers || {}),
          },
        }
      );
    } catch {
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
