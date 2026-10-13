/**
 * Публичные типы домена. Только контракты — никакой логики (ISP).
 */

/** Аутентифицированный пользователь. */
export interface User {
  id: string;
  name?: string;
  roles?: readonly string[];
  [key: string]: unknown;
}

/** Активная сессия. */
export interface Session {
  user: User;
  token: string;
  /** Opaque refresh-token (если поддерживается бэкендом). */
  refreshToken?: string;
  /** Момент выдачи (epoch ms). */
  issuedAt: number;
  /** Момент истечения access-токена (epoch ms). */
  expiresAt: number;
  /** Момент истечения refresh-токена (epoch ms), если известен. */
  refreshExpiresAt?: number;
}

/** Декодированный payload токена. */
export interface TokenPayload {
  sub: string;
  /** Unix-время истечения в **секундах**. */
  exp: number;
  iat?: number;
  name?: string;
  roles?: readonly string[];
  [key: string]: unknown;
}

/** Опции {@link SessionManager.login}. */
export interface LoginOptions {
  token: string;
  refreshToken?: string;
  /** TTL access-сессии в мс (жёстко ограничивается `exp` токена). */
  ttlMs?: number;
  /** TTL refresh-сессии в мс. */
  refreshTtlMs?: number;
  /** Явный пользователь; иначе строится из payload. */
  user?: User;
  /** Принудительный вход при активной сессии. */
  force?: boolean;
  /** Отмена валидации/refresh-запроса. */
  signal?: AbortSignal;
}

/** Результат операции refresh у провайдера. */
export interface RefreshResult {
  token: string;
  refreshToken?: string;
  /** Unix-время (сек) нового access-токена, если известно. */
  exp?: number;
}

/** Стратегия обновления токенов через бэкенд. */
export interface TokenRefresher {
  refresh(refreshToken: string, signal?: AbortSignal): Promise<RefreshResult>;
}

/** Уровень логирования телеметрии. */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/** Абстракция телеметрии — подставь pino/winston/console. */
export interface Telemetry {
  log(level: LogLevel, message: string, meta?: Record<string, unknown>): void;
}

/** Событие жизненного цикла. */
export type SessionEventType =
  | 'login'
  | 'logout'
  | 'expired'
  | 'refresh'
  | 'refresh:error'
  | 'cache:hit'
  | 'cache:miss'
  | 'cache:set'
  | 'cache:delete'
  | 'cache:evict';

export interface SessionEvent {
  type: SessionEventType;
  at: number;
  session: Session | null;
  meta?: Record<string, unknown>;
}
