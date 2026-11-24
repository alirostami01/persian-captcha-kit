export interface CaptchaStore {
  /**
   * بررسی می‌کند که آیا این توکن قبلاً مصرف شده است یا خیر.
   */
  isConsumed(id: string): Promise<boolean> | boolean;

  /**
   * توکن را به عنوان مصرف‌شده ثبت می‌کند.
   * در صورت موفقیت‌آمیز بودن ثبت اتمیک true و در صورتی که توکن قبلاً ثبت شده باشد false برمی‌گرداند.
   */
  markConsumed(id: string, ttlSeconds: number): Promise<boolean> | boolean;
}

/**
 * پیاده‌سازی ذخیره‌ساز در حافظه (Memory Store) همراه با سقف ظرفیت برای جلوگیری از DoS
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
    
    // اگر از قبل وجود داشت و منقضی نشده بود
    if (this.isConsumed(id)) {
      return false;
    }

    // کنترل سقف تعداد رکوردها برای محافظت از حافظه
    if (this.consumed.size >= this.maxEntries) {
      this.cleanup(now);
      // اگر بعد از پاکسازی هنوز پر بود، قدیمی‌ترین رکورد حذف شود
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
