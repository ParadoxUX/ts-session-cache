/**
 * # ts-session-cache v2
 *
 * Production-grade singleton-менеджер сессий и кэша.
 *
 * ```ts
 * import { SessionManager, HmacJwtValidator, SystemClock } from 'ts-session-cache';
 *
 * const sm = SessionManager.getInstance({
 *   tokenValidator: new HmacJwtValidator(process.env.JWT_SECRET!, new SystemClock()),
 * });
 * await sm.login({ token, refreshToken });
 * sm.cacheSet('profile', { theme: 'dark' }, 60_000);
 * sm.logout();
 * ```
 */

export { SessionManager } from './session-manager';
export type { SessionManagerOptions, SessionListener } from './session-manager';

export {
  JwtPayloadValidator,
  HmacJwtValidator,
  FunctionTokenValidator,
  CompositeTokenValidator,
} from './token-validator';
export type { TokenValidator } from './token-validator';

export { SystemClock, ManualClock } from './clock';
export type { Clock } from './clock';

export { MemoryCacheStore } from './cache-store';
export type { CacheStore, MemoryCacheStoreOptions, EvictHandler } from './cache-store';

export {
  MemorySessionStorage,
  NullSessionStorage,
  SafeSessionStorage,
} from './session-storage';
export type { SessionStorage } from './session-storage';

export { NoopTelemetry, ConsoleTelemetry } from './telemetry';

export {
  SessionError,
  AlreadyLoggedInError,
  NotAuthenticatedError,
  InvalidTokenError,
  SessionExpiredError,
  InvalidArgumentError,
  RefreshNotAvailableError,
  RefreshFailedError,
  AbortedError,
  DestroyedError,
} from './errors';
export type { SessionErrorCode } from './errors';

export type {
  User,
  Session,
  TokenPayload,
  LoginOptions,
  RefreshResult,
  TokenRefresher,
  SessionEvent,
  SessionEventType,
  Telemetry,
  LogLevel,
} from './types';
