import {
  AbortedError, AlreadyLoggedInError, DestroyedError, InvalidArgumentError,
  NotAuthenticatedError, RefreshFailedError, RefreshNotAvailableError, SessionError,
} from './errors';
import { SystemClock, type Clock } from './clock';
import { MemoryCacheStore, type CacheStore } from './cache-store';
import { MemorySessionStorage, SafeSessionStorage, type SessionStorage } from './session-storage';
import { NoopTelemetry } from './telemetry';
import type {
  LoginOptions, Session, SessionEvent, Telemetry, TokenRefresher, User,
} from './types';
import type { TokenValidator } from './token-validator';

/** Конфигурация менеджера. */
export interface SessionManagerOptions {
  /** Обязательный валидатор (DIP). */
  tokenValidator: TokenValidator;
  /** Опциональная стратегия refresh. */
  tokenRefresher?: TokenRefresher;
  /** Кастомный кэш. По умолчанию {@link MemoryCacheStore} с `maxSize: 10_000`. */
  cache?: CacheStore;
  /** Кастомное хранилище сессии. */
  storage?: SessionStorage;
  /** Часы (для тестов). */
  clock?: Clock;
  /** Префикс ключей. По умолчанию `"session"`. */
  namespace?: string;
  /** Телеметрия. По умолчанию {@link NoopTelemetry}. */
  telemetry?: Telemetry;
}

export type SessionListener = (event: SessionEvent) => void;

/**
 * # SessionManager (v2)
 *
 * Глобальный синглтон управления сессией и кэшем.
 *
 * ## Жизненный цикл сессии
 *
 * 1. **Инициализация.** {@link getInstance} создаёт единственный экземпляр.
 *    Предпринимается попытка восстановить сессию через {@link SessionStorage};
 *    просроченная — отбрасывается.
 * 2. **Логин.** {@link login} валидирует токен, опционально сохраняет
 *    refresh-token, строит {@link Session}, регистрирует scoped-индекс
 *    и **взводит авто-таймер экспирации** (`setTimeout(...).unref()`).
 * 3. **Работа.** Каждый метод сначала вызывает {@link reapExpired}
 *    (ленивая инвалидация). Кэш скоупится по `userId`.
 * 4. **Refresh.** {@link refresh} через {@link TokenRefresher} обновляет
 *    access-token; таймер перепланируется.
 * 5. **Логаут.** {@link logout} снимает таймер, чистит scoped-кэш
 *    за O(1) (индекс), сбрасывает storage.
 * 6. **destroy.** Полная очистка: таймеры, слушатели, кэш, storage.
 *
 * ## Условия истечения
 *
 * `expiresAt = min(token.exp * 1000, now + ttlMs)`.
 * TTL любой записи кэша зажимается остаточным временем сессии —
 * запись физически не переживает сессию. По истечении:
 *  - если есть refresh-token и refresher — вызывается refresh;
 *  - иначе сессия инвалидируется, кэш чистится, эмитится `expired`.
 *
 * ## Обработка ошибок
 *
 * Все доменные ошибки наследуют {@link SessionError} с полем `code`:
 * `ALREADY_LOGGED_IN`, `LOGIN_IN_PROGRESS`, `INVALID_TOKEN`,
 * `SESSION_EXPIRED`, `INVALID_ARGUMENT`, `NOT_AUTHENTICATED`,
 * `REFRESH_*`, `ABORTED`, `DESTROYED`.
 * Слушатели изолированы: throw в одном не влияет на других и на ядро.
 */
export class SessionManager {
  private static instance: SessionManager | null = null;

  private readonly validator: TokenValidator;
  private readonly refresher: TokenRefresher | null;
  private readonly cache: CacheStore;
  private readonly storage: SessionStorage;
  private readonly clock: Clock;
  private readonly namespace: string;
  private readonly telemetry: Telemetry;
  private readonly listeners = new Set<SessionListener>();

  /** Индекс `userId -> Set<fullKey>` — O(1) очистка scoped-кэша. */
  private readonly scopedKeys = new Map<string, Set<string>>();

  private current: Session | null = null;
  private loginInFlight: Promise<Session> | null = null;
  private refreshInFlight: Promise<Session> | null = null;
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyed = false;

  private constructor(options: SessionManagerOptions) {
    if (!options || !options.tokenValidator) {
      throw new InvalidArgumentError('SessionManager requires a TokenValidator.');
    }
    this.validator = options.tokenValidator;
    this.refresher = options.tokenRefresher ?? null;
    this.clock = options.clock ?? new SystemClock();
    this.namespace = options.namespace ?? 'session';
    this.telemetry = options.telemetry ?? NoopTelemetry;

    const rawStorage = options.storage ?? new MemorySessionStorage();
    this.storage = new SafeSessionStorage(rawStorage, this.telemetry);

    this.cache =
      options.cache ??
      new MemoryCacheStore({
        clock: this.clock,
        maxSize: 10_000,
        onEvict: (key, reason) => {
          this.forgetScopedKeyByFull(key);
          this.emit({
            type: 'cache:evict',
            at: this.clock.now(),
            session: this.current,
            meta: { key, reason },
          });
        },
      });

    const restored = this.storage.load();
    if (restored && restored.expiresAt > this.clock.now()) {
      this.current = restored;
      this.scheduleExpiry();
    } else if (restored) {
      this.storage.clear();
    }
  }

  /* ====================================================================
   * Singleton lifecycle
   * ================================================================== */

  static getInstance(options?: SessionManagerOptions): SessionManager {
    if (SessionManager.instance) return SessionManager.instance;
    if (!options) {
      throw new InvalidArgumentError('SessionManager is not initialized. Provide options on first call.');
    }
    SessionManager.instance = new SessionManager(options);
    return SessionManager.instance;
  }

  /**
   * Тестовый хелпер: отвязывает текущий инстанс от синглтона.
   *
   * В отличие от {@link destroy}, НЕ трогает инжектированный
   * {@link SessionStorage} — иначе нельзя проверить восстановление
   * сессии при пересоздании менеджера. Внутренние ресурсы
   * (таймер, слушатели, in-memory кэш, текущая сессия) освобождаются.
   */
  static resetInstance(): void {
    const inst = SessionManager.instance;
    SessionManager.instance = null;
    if (!inst) return;
    inst.cancelExpiry();
    inst.listeners.clear();
    inst.cache.clear();
    inst.scopedKeys.clear();
    inst.current = null;
    inst.destroyed = true;
  }

  /**
   * Полностью уничтожает менеджер: снимает таймер, чистит кэш, storage,
   * слушателей. После `destroy()` любые операции бросают {@link DestroyedError}.
   */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.cancelExpiry();
    this.listeners.clear();
    this.cache.clear();
    this.scopedKeys.clear();
    this.storage.clear();
    this.current = null;
    this.telemetry.log('info', 'SessionManager destroyed.');
  }

  /* ====================================================================
   * Session lifecycle
   * ================================================================== */

  /**
   * Аутентифицирует пользователя.
   *
   * @throws {@link InvalidArgumentError} пустой токен
   * @throws {@link InvalidTokenError}    валидация провалилась
   * @throws {@link SessionExpiredError}  токен просрочен
   * @throws {@link AlreadyLoggedInError} сессия активна или идёт логин
   * @throws {@link AbortedError}         signal был aborted
   * @throws {@link DestroyedError}       менеджер уничтожен
   */
  async login(options: LoginOptions): Promise<Session> {
    this.assertAlive();
    if (!options || typeof options.token !== 'string' || options.token.length === 0) {
      throw new InvalidArgumentError('login() requires a non-empty token string.');
    }
    if (options.signal?.aborted) throw new AbortedError();

    this.reapExpired();

    if (this.current && !options.force) throw new AlreadyLoggedInError();
    if (this.loginInFlight) throw new AlreadyLoggedInError('Login is already in progress.');

    const promise = this.performLogin(options);
    this.loginInFlight = promise;
    try {
      return await promise;
    } finally {
      if (this.loginInFlight === promise) this.loginInFlight = null;
    }
  }

  /**
   * Обновляет access-token через {@link TokenRefresher}.
   *
   * @throws {@link RefreshNotAvailableError} нет refresh-token/refresher
   * @throws {@link NotAuthenticatedError}    нет активной сессии
   * @throws {@link RefreshFailedError}       провайдер вернул ошибку
   */
  async refresh(signal?: AbortSignal): Promise<Session> {
    this.assertAlive();
    this.reapExpired();
    if (!this.current) throw new NotAuthenticatedError();
    if (!this.refresher || !this.current.refreshToken) {
      throw new RefreshNotAvailableError();
    }
    if (this.refreshInFlight) return this.refreshInFlight;

    const promise = this.performRefresh(this.current, signal);
    this.refreshInFlight = promise;
    try {
      return await promise;
    } finally {
      if (this.refreshInFlight === promise) this.refreshInFlight = null;
    }
  }

  /**
   * Закрывает сессию: снимает таймер, чистит scoped-кэш (O(1)), storage.
   * Идемпотентно.
   */
  logout(reason = 'manual'): void {
    if (!this.current) return;
    const session = this.current;
    this.current = null;
    this.cancelExpiry();
    this.clearScopedCache(session.user.id);
    this.storage.clear();
    this.emit({ type: 'logout', at: this.clock.now(), session: null, meta: { reason } });
  }

  getCurrentUser(): User | null {
    if (this.destroyed) return null;
    this.reapExpired();
    return this.current?.user ?? null;
  }

  getSession(): Session | null {
    if (this.destroyed) return null;
    this.reapExpired();
    return this.current;
  }

  isAuthenticated(): boolean {
    if (this.destroyed) return false;
    this.reapExpired();
    return this.current !== null;
  }

  /* ====================================================================
   * Cache
   * ================================================================== */

  cacheGet<T>(key: string): T | undefined {
    this.assertAlive();
    this.assertKey(key);
    this.reapExpired();
    const value = this.cache.get<T>(this.scopedKey(key));
    this.emit({
      type: value === undefined ? 'cache:miss' : 'cache:hit',
      at: this.clock.now(),
      session: this.current,
      meta: { key },
    });
    return value;
  }

  cacheSet<T>(key: string, value: T, ttlMs?: number): void {
    this.assertAlive();
    this.assertKey(key);
    this.reapExpired();

    const session = this.current;
    const remaining = session ? Math.max(0, session.expiresAt - this.clock.now()) : undefined;
    const effectiveTtl =
      remaining === undefined
        ? ttlMs
        : ttlMs === undefined
          ? remaining
          : Math.min(ttlMs, remaining);

    if (effectiveTtl !== undefined && effectiveTtl <= 0) return;

    const fullKey = this.scopedKey(key);
    this.cache.set(fullKey, value, effectiveTtl);
    this.rememberScopedKey(session?.user.id ?? 'anon', fullKey);
    this.emit({
      type: 'cache:set',
      at: this.clock.now(),
      session,
      meta: { key, ttlMs: effectiveTtl },
    });
  }

  cacheDelete(key: string): boolean {
    this.assertAlive();
    this.assertKey(key);
    const fullKey = this.scopedKey(key);
    const deleted = this.cache.delete(fullKey);
    if (deleted) {
      this.forgetScopedKeyByFull(fullKey);
      this.emit({
        type: 'cache:delete',
        at: this.clock.now(),
        session: this.current,
        meta: { key },
      });
    }
    return deleted;
  }

  /** Диагностика: количество ключей в scoped-индексе. */
  get scopedKeyCount(): number {
    let n = 0;
    for (const set of this.scopedKeys.values()) n += set.size;
    return n;
  }

  /* ====================================================================
   * Events
   * ================================================================== */

  subscribe(listener: SessionListener): () => void {
    if (typeof listener !== 'function') {
      throw new InvalidArgumentError('listener must be a function.');
    }
    if (this.destroyed) throw new DestroyedError();
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /* ====================================================================
   * Internals
   * ================================================================== */

  private async performLogin(options: LoginOptions): Promise<Session> {
    const payload = await this.validator.validate(options.token, options.signal);
    this.assertAlive();

    const now = this.clock.now();
    const tokenExpiry = payload.exp * 1000;
    if (tokenExpiry <= now) {
      throw new SessionError('SESSION_EXPIRED', 'Token is already expired.');
    }

    const user = this.resolveUser(payload, options.user);

    const ttlCap = options.ttlMs ?? tokenExpiry - now;
    if (!Number.isFinite(ttlCap) || ttlCap <= 0) {
      throw new InvalidArgumentError('Effective ttlMs must be a positive finite number.');
    }
    const expiresAt = Math.min(tokenExpiry, now + ttlCap);

    if (this.current) this.clearScopedCache(this.current.user.id);

    const session: Session = { user, token: options.token, issuedAt: now, expiresAt };
    if (options.refreshToken !== undefined) session.refreshToken = options.refreshToken;
    if (options.refreshTtlMs !== undefined) {
      if (!Number.isFinite(options.refreshTtlMs) || options.refreshTtlMs <= 0) {
        throw new InvalidArgumentError('refreshTtlMs must be a positive finite number.');
      }
      session.refreshExpiresAt = now + options.refreshTtlMs;
    }

    this.current = session;
    this.storage.save(session);
    this.scheduleExpiry();
    this.telemetry.log('info', 'login', { userId: user.id, expiresAt });
    this.emit({ type: 'login', at: now, session });
    return session;
  }

  private async performRefresh(prev: Session, signal?: AbortSignal): Promise<Session> {
    if (signal?.aborted) throw new AbortedError();
    try {
      const result = await this.refresher!.refresh(prev.refreshToken!, signal);
      this.assertAlive();
      if (!this.current || this.current.token !== prev.token) {
        // сессия изменилась за время refresh — игнорируем.
        return this.current ?? prev;
      }
      const now = this.clock.now();
      const tokenExpiry = (result.exp ?? Math.floor(prev.expiresAt / 1000) + 3600) * 1000;
      const session: Session = {
        user: prev.user,
        token: result.token,
        issuedAt: now,
        expiresAt: Math.min(tokenExpiry, now + (prev.expiresAt - prev.issuedAt)),
      };
      const refreshToken = result.refreshToken ?? prev.refreshToken;
      if (refreshToken !== undefined) session.refreshToken = refreshToken;
      if (prev.refreshExpiresAt !== undefined) session.refreshExpiresAt = prev.refreshExpiresAt;

      this.current = session;
      this.storage.save(session);
      this.scheduleExpiry();
      this.telemetry.log('info', 'refresh ok', { userId: session.user.id });
      this.emit({ type: 'refresh', at: now, session });
      return session;
    } catch (e) {
      if (e instanceof SessionError) throw e;
      this.telemetry.log('error', 'refresh failed', { error: String(e) });
      this.emit({ type: 'refresh:error', at: this.clock.now(), session: this.current, meta: { error: String(e) } });
      throw new RefreshFailedError(undefined, e);
    }
  }

  private resolveUser(
    payload: { sub: string; name?: string; roles?: readonly string[]; [k: string]: unknown },
    explicit?: User,
  ): User {
    if (explicit) {
      if (typeof explicit.id !== 'string' || explicit.id.length === 0) {
        throw new InvalidArgumentError('Provided user must have a non-empty string id.');
      }
      return explicit;
    }
    const rest: Record<string, unknown> = { ...payload };
    delete rest.sub; delete rest.exp; delete rest.iat; delete rest.name; delete rest.roles;
    const user: User = { ...rest, id: payload.sub };
    if (typeof payload.name === 'string') user.name = payload.name;
    if (Array.isArray(payload.roles)) user.roles = payload.roles;
    return user;
  }

  /** Ленивая инвалидация. Идемпотентно. */
  private reapExpired(): void {
    if (!this.current) return;
    if (this.current.expiresAt > this.clock.now()) return;
    const expired = this.current;
    this.current = null;
    this.cancelExpiry();
    this.clearScopedCache(expired.user.id);
    this.storage.clear();
    this.telemetry.log('info', 'session expired', { userId: expired.user.id });
    this.emit({
      type: 'expired',
      at: this.clock.now(),
      session: null,
      meta: { userId: expired.user.id, expiresAt: expired.expiresAt },
    });
  }

  /* ---------------- expiry timer ---------------- */

  private scheduleExpiry(): void {
    this.cancelExpiry();
    if (!this.current) return;
    const delay = Math.max(0, this.current.expiresAt - this.clock.now()) + 1;
    const timer = setTimeout(() => {
      // Авто-refresh, если возможно, иначе — инвалидация.
      if (this.current?.refreshToken && this.refresher) {
        void this.refresh().catch(() => { /* ошибку уже эмитнули */ });
      } else {
        this.reapExpired();
      }
    }, delay);
    (timer as unknown as { unref?: () => void }).unref?.();
    this.expiryTimer = timer;
  }

  private cancelExpiry(): void {
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }
  }

  /* ---------------- scoped index ---------------- */

  private rememberScopedKey(userId: string, fullKey: string): void {
    let set = this.scopedKeys.get(userId);
    if (!set) {
      set = new Set();
      this.scopedKeys.set(userId, set);
    }
    set.add(fullKey);
  }

  private forgetScopedKeyByFull(fullKey: string): void {
    // Быстрый путь: извлекаем userId из префикса.
    const uid = extractUserId(this.namespace, fullKey);
    if (!uid) return;
    const set = this.scopedKeys.get(uid);
    if (!set) return;
    set.delete(fullKey);
    if (set.size === 0) this.scopedKeys.delete(uid);
  }

  private clearScopedCache(userId: string): void {
    const set = this.scopedKeys.get(userId);
    if (!set) return;
    for (const k of set) this.cache.delete(k);
    set.clear();
    this.scopedKeys.delete(userId);
  }

  /* ---------------- misc ---------------- */

  private scopedKey(key: string): string {
    const uid = this.current?.user.id ?? 'anon';
    return `${this.namespace}:${uid}:${key}`;
  }

  private assertKey(key: string): void {
    if (typeof key !== 'string' || key.length === 0) {
      throw new InvalidArgumentError('Cache key must be a non-empty string.');
    }
  }

  private assertAlive(): void {
    if (this.destroyed) throw new DestroyedError();
  }

  private emit(event: SessionEvent): void {
    for (const listener of this.listeners) {
      try { listener(event); }
      catch (e) {
        this.telemetry.log('warn', 'listener threw', { error: String(e), type: event.type });
      }
    }
  }
}

/* ---------------- helpers ---------------- */

function extractUserId(namespace: string, fullKey: string): string | null {
  const prefix = `${namespace}:`;
  if (!fullKey.startsWith(prefix)) return null;
  const rest = fullKey.slice(prefix.length);
  const idx = rest.indexOf(':');
  if (idx <= 0) return null;
  return rest.slice(0, idx);
}

