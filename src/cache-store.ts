import { InvalidArgumentError } from './errors';
import type { Clock } from './clock';

/** Колбэк эвикции (LRU/TTL). */
export type EvictHandler = (key: string, reason: 'lru' | 'ttl') => void;

/** Абстракция KV+TTL хранилища (DIP/LSP). */
export interface CacheStore {
  get<T>(key: string): T | undefined;
  set<T>(key: string, value: T, ttlMs?: number): void;
  has(key: string): boolean;
  delete(key: string): boolean;
  clear(): void;
  keys(): readonly string[];
  readonly size: number;
}

export interface MemoryCacheStoreOptions {
  clock: Clock;
  /** Максимум записей. При превышении вытесняется LRU. По умолчанию 10_000. */
  maxSize?: number;
  /** Колбэк эвикции. */
  onEvict?: EvictHandler;
}

/**
 * In-memory кэш с TTL + LRU-эвикцией.
 *
 * - `get` — ленивая TTL-инвалидация + перемещение в конец (LRU).
 * - `set` — вытеснение самой старой записи при `size >= maxSize`.
 * - `size` — O(1).
 *
 * Комплексность всех операций — амортизированная O(1).
 */
export class MemoryCacheStore implements CacheStore {
  private readonly map = new Map<string, { value: unknown; expiresAt: number | null }>();
  private readonly clock: Clock;
  private readonly maxSize: number;
  private readonly onEvict?: EvictHandler;

  constructor(options: MemoryCacheStoreOptions) {
    if (!options || !options.clock) {
      throw new InvalidArgumentError('MemoryCacheStore requires a clock.');
    }
    const max = options.maxSize ?? 10_000;
    if (!Number.isInteger(max) || max <= 0) {
      throw new InvalidArgumentError('maxSize must be a positive integer.');
    }
    this.clock = options.clock;
    this.maxSize = max;
    if (options.onEvict) this.onEvict = options.onEvict;
  }

  get<T>(key: string): T | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt !== null && entry.expiresAt <= this.clock.now()) {
      this.map.delete(key);
      this.onEvict?.(key, 'ttl');
      return undefined;
    }
    // LRU touch: переместить в конец.
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value as T;
  }

  set<T>(key: string, value: T, ttlMs?: number): void {
    if (ttlMs !== undefined) {
      if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
        throw new InvalidArgumentError('ttlMs must be a positive finite number.');
      }
    }
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      // Вытесняем первую (самую старую) запись.
      const oldest = this.map.keys().next();
      if (!oldest.done) {
        this.map.delete(oldest.value);
        this.onEvict?.(oldest.value, 'lru');
      }
    }
    this.map.set(key, {
      value,
      expiresAt: ttlMs === undefined ? null : this.clock.now() + ttlMs,
    });
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  delete(key: string): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  keys(): readonly string[] {
    return [...this.map.keys()];
  }

  get size(): number {
    return this.map.size;
  }
}
