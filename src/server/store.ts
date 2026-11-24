export interface StoreResult {
  allowed: boolean;
  attemptsRemaining: number;
  consumed: boolean;
}

export interface CaptchaStore {
  /**
   * Records a verification attempt and checks whether the token has exceeded max attempts.
   * Increments attempt count atomically and returns whether the attempt is allowed.
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
 * Never evicts valid (unexpired) entries to prevent replay vulnerabilities.
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
        consumed: false,
      };
      this.entries.set(id, state);

      const allowed = state.attempts <= maxAttempts;
      return {
        allowed,
        attemptsRemaining: Math.max(0, maxAttempts - state.attempts),
        consumed: state.consumed,
      };
    }

    if (state.consumed) {
      return {
        allowed: false,
        attemptsRemaining: 0,
        consumed: true,
      };
    }

    state.attempts += 1;
    const allowed = state.attempts <= maxAttempts;
    if (!allowed) {
      state.consumed = true;
      return {
        allowed: false,
        attemptsRemaining: 0,
        consumed: false, // Indicates max attempts exceeded, not previously consumed
      };
    }

    return {
      allowed,
      attemptsRemaining: Math.max(0, maxAttempts - state.attempts),
      consumed: state.consumed,
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
