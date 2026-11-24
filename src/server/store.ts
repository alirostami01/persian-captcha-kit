export interface CaptchaStore {
  /**
   * Checks whether the given token ID has already been consumed.
   */
  isConsumed(id: string): Promise<boolean> | boolean;

  /**
   * Atomically marks the token ID as consumed.
   * Returns true if successfully registered, or false if already marked.
   */
  markConsumed(id: string, ttlSeconds: number): Promise<boolean> | boolean;
}

/**
 * In-memory storage implementation with size limits to prevent DoS attacks.
 */
export class MemoryCaptchaStore implements CaptchaStore {
  private consumed = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(options?: { maxEntries?: number }) {
    this.maxEntries = options?.maxEntries ?? 10_000;
  }

  private cleanup(now: number): void {
    for (const [id, exp] of this.consumed.entries()) {
      if (now > exp) {
        this.consumed.delete(id);
      }
    }
  }

  isConsumed(id: string): boolean {
    const exp = this.consumed.get(id);
    if (!exp) return false;
    if (Date.now() > exp) {
      this.consumed.delete(id);
      return false;
    }
    return true;
  }

  markConsumed(id: string, ttlSeconds: number): boolean {
    const now = Date.now();

    if (this.isConsumed(id)) {
      return false;
    }

    if (this.consumed.size >= this.maxEntries) {
      this.cleanup(now);
      if (this.consumed.size >= this.maxEntries) {
        const firstKey = this.consumed.keys().next().value;
        if (firstKey) this.consumed.delete(firstKey);
      }
    }

    const exp = now + ttlSeconds * 1000;
    this.consumed.set(id, exp);
    return true;
  }
}

export const defaultMemoryStore = new MemoryCaptchaStore();
