import type { Session } from './types';
import type { Telemetry } from './types';

/** Абстракция персистентности сессии. */
export interface SessionStorage {
  load(): Session | null;
  save(session: Session): void;
  clear(): void;
}

/** In-memory. */
export class MemorySessionStorage implements SessionStorage {
  private session: Session | null = null;
  load(): Session | null { return this.session; }
  save(s: Session): void { this.session = s; }
  clear(): void { this.session = null; }
}

/** No-op. */
export class NullSessionStorage implements SessionStorage {
  load(): Session | null { return null; }
  save(): void {}
  clear(): void {}
}

/**
 * Безопасная обёртка: любые сбои делегата проглатываются и логируются,
 * состояние ядра не рушится. Валидирует форму восстановленной сессии.
 */
export class SafeSessionStorage implements SessionStorage {
  private readonly delegate: SessionStorage;
  private readonly telemetry: Telemetry;

  constructor(delegate: SessionStorage, telemetry: Telemetry) {
    this.delegate = delegate;
    this.telemetry = telemetry;
  }

  load(): Session | null {
    try {
      const s = this.delegate.load();
      if (!s) return null;
      if (!isValidSession(s)) {
        this.telemetry.log('warn', 'Discarding malformed session from storage.');
        return null;
      }
      return s;
    } catch (e) {
      this.telemetry.log('error', 'SessionStorage.load failed.', { error: String(e) });
      return null;
    }
  }

  save(session: Session): void {
    try { this.delegate.save(session); }
    catch (e) { this.telemetry.log('error', 'SessionStorage.save failed.', { error: String(e) }); }
  }

  clear(): void {
    try { this.delegate.clear(); }
    catch (e) { this.telemetry.log('error', 'SessionStorage.clear failed.', { error: String(e) }); }
  }
}

function isValidSession(s: unknown): s is Session {
  if (!s || typeof s !== 'object') return false;
  const x = s as Partial<Session>;
  return (
    typeof x.token === 'string' &&
    typeof x.issuedAt === 'number' &&
    typeof x.expiresAt === 'number' &&
    !!x.user && typeof x.user === 'object' && typeof x.user.id === 'string'
  );
}
