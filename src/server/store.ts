export interface StoreResult {
  allowed: boolean;
  attemptsRemaining: number;
  consumed: boolean;
}

export interface CaptchaStore {
  /**
   * Records a verification attempt and checks whether the token has exceeded max attempts.
   * Atomically increments attempt count and burns/consumes the token when count reaches maxAttempts.
   * The current attempt itself is permitted if count <= maxAttempts, while subsequent calls are rejected as consumed.
   */
  recordAttempt(
    id: string,
    maxAttempts: number,
    ttlSeconds: number
  ): Promise<StoreResult> | StoreResult;

  /**
   * Atomically marks the token as fully consumed upon successful verification.
   * Returns true if successfully consumed, or false if already consumed.
   */
  markConsumed(id: string, ttlSeconds: number): Promise<boolean> | boolean;
}

interface EntryState {
  exp: number;
  attempts: number;
  consumed: boolean;
}

/**
 * In-memory storage implementation with strict capacity controls.
 * Never evicts unexpired entries to prevent replay vulnerabilities.
 */
export class MemoryCaptchaStore implements CaptchaStore {
  private entries = new Map<string, EntryState>();
  private readonly maxEntries: number;

  constructor(options?: { maxEntries?: number }) {
    const rawMax = options?.maxEntries;
    if (rawMax !== undefined) {
      if (typeof rawMax !== 'number' || !Number.isInteger(rawMax) || rawMax <= 0) {
        throw new Error('[@persian-captcha-kit/server] maxEntries must be a positive integer.');
      }
      this.maxEntries = rawMax;
    } else {
      this.maxEntries = 10_000;
    }
  }

  private cleanup(now: number): void {
    for (const [id, state] of this.entries.entries()) {
      if (now > state.exp) {
        this.entries.delete(id);
      }
    }
  }

  recordAttempt(id: string, maxAttempts: number, ttlSeconds: number): StoreResult {
    const now = Date.now();
    let state = this.entries.get(id);

    if (state && now > state.exp) {
      this.entries.delete(id);
      state = undefined;
    }

    if (!state) {
      if (this.entries.size >= this.maxEntries) {
        this.cleanup(now);
        if (this.entries.size >= this.maxEntries) {
          throw new Error('[@persian-captcha-kit/server] MemoryCaptchaStore capacity exceeded.');
        }
      }

      state = {
        exp: now + ttlSeconds * 1000,
        attempts: 1,
        consumed: maxAttempts <= 1, // If maxAttempts is 1, it burns immediately for subsequent attempts
      };
      this.entries.set(id, state);

      return {
        allowed: true,
        attemptsRemaining: Math.max(0, maxAttempts - 1),
        consumed: false, // The current attempt itself is allowed
      };
    }

    // If already consumed by prior maxAttempts exhaustion or prior success
    if (state.consumed) {
      return {
        allowed: false,
        attemptsRemaining: 0,
        consumed: true,
      };
    }

    state.attempts += 1;
    const allowed = state.attempts <= maxAttempts;

    // When the current attempt hits the ceiling, burn the token atomically for all future requests
    if (state.attempts >= maxAttempts) {
      state.consumed = true;
    }

    return {
      allowed,
      attemptsRemaining: Math.max(0, maxAttempts - state.attempts),
      consumed: false, // This attempt is allowed to be evaluated; subsequent attempts will see consumed: true
    };
  }

  markConsumed(id: string, ttlSeconds: number): boolean {
    const now = Date.now();
    let state = this.entries.get(id);

    if (state && now > state.exp) {
      this.entries.delete(id);
      state = undefined;
    }

    if (state) {
      if (state.consumed) {
        return false;
      }
      state.consumed = true;
      return true;
    }

    if (this.entries.size >= this.maxEntries) {
      this.cleanup(now);
      if (this.entries.size >= this.maxEntries) {
        throw new Error('[@persian-captcha-kit/server] MemoryCaptchaStore capacity exceeded.');
      }
    }

    this.entries.set(id, {
      exp: now + ttlSeconds * 1000,
      attempts: 1,
      consumed: true,
    });
    return true;
  }
}

export const defaultMemoryStore = new MemoryCaptchaStore();
