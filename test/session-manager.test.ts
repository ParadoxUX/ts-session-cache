import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AbortedError, AlreadyLoggedInError, CompositeTokenValidator, DestroyedError,
  FunctionTokenValidator, HmacJwtValidator, InvalidArgumentError, InvalidTokenError,
  JwtPayloadValidator, ManualClock, MemoryCacheStore, MemorySessionStorage,
  NotAuthenticatedError, RefreshFailedError, RefreshNotAvailableError, SessionExpiredError,
  SessionManager, type TokenRefresher,
} from '../src/index';

/* -------------------- helpers -------------------- */

const b64u = (o: object) =>
  Buffer.from(JSON.stringify(o)).toString('base64url');

const jwt = (expSec: number, sub = 'u1', extra: object = {}) =>
  `${b64u({ alg: 'HS256' })}.${b64u({ sub, exp: expSec, ...extra })}.sig`;

const NOW_SEC = Math.floor(Date.now() / 1000);

beforeEach(() => {
  SessionManager.resetInstance();
});

afterEach(() => {
  SessionManager.resetInstance();
  vi.useRealTimers();
});

/* ==================== Singleton ==================== */

describe('singleton', () => {
  it('throws without options on first call', () => {
    expect(() => SessionManager.getInstance()).toThrow(InvalidArgumentError);
  });
  it('returns same instance', () => {
    const v = new JwtPayloadValidator(new ManualClock(0));
    const a = SessionManager.getInstance({ tokenValidator: v });
    const b = SessionManager.getInstance();
    expect(a).toBe(b);
  });
  it('resetInstance returns fresh instance', () => {
    const a = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    SessionManager.resetInstance();
    const b = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    expect(a).not.toBe(b);
  });
});

/* ==================== Login ==================== */

describe('login', () => {
  it('authenticates and returns session', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    const s = await sm.login({ token: jwt(NOW_SEC + 60, 'u1', { name: 'Ann' }) });
    expect(s.user.id).toBe('u1');
    expect(s.user.name).toBe('Ann');
    expect(sm.isAuthenticated()).toBe(true);
  });

  it('rejects empty token', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await expect(sm.login({ token: '' })).rejects.toBeInstanceOf(InvalidArgumentError);
  });

  it('rejects garbage token', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await expect(sm.login({ token: 'x.y' })).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects expired token', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await expect(sm.login({ token: jwt(NOW_SEC - 1) })).rejects.toBeInstanceOf(SessionExpiredError);
  });

  it('blocks double login', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60) });
    await expect(sm.login({ token: jwt(NOW_SEC + 60) })).rejects.toBeInstanceOf(AlreadyLoggedInError);
  });

  it('force:true overwrites session', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60, 'u1') });
    const s = await sm.login({ token: jwt(NOW_SEC + 60, 'u2'), force: true });
    expect(s.user.id).toBe('u2');
  });

  it('login-in-flight is guarded', async () => {
    const slow = new FunctionTokenValidator(async () => {
      await new Promise(r => setTimeout(r, 20));
      return { sub: 'u1', exp: NOW_SEC + 60 };
    });
    const sm = SessionManager.getInstance({ tokenValidator: slow });
    const [a, b] = await Promise.allSettled([
      sm.login({ token: 'a' }),
      sm.login({ token: 'b' }),
    ]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual(['fulfilled', 'rejected']);
  });

  it('respects ttlMs cap', async () => {
    const clock = new ManualClock(1_000_000);
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(),
      clock,
    });
    await sm.login({ token: jwt(NOW_SEC + 3600), ttlMs: 100 });
    expect(sm.isAuthenticated()).toBe(true);
    clock.advance(101);
    expect(sm.isAuthenticated()).toBe(false);
  });

  it('aborts with signal', async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await expect(sm.login({ token: jwt(NOW_SEC + 60), signal: ctrl.signal }))
      .rejects.toBeInstanceOf(AbortedError);
  });
});

/* ==================== Expiry ==================== */

describe('expiry', () => {
  it('expires after ttl', async () => {
    const clock = new ManualClock(2_000_000);
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(), clock,
    });
    await sm.login({ token: jwt(NOW_SEC + 3600), ttlMs: 50 });
    clock.advance(51);
    expect(sm.getCurrentUser()).toBeNull();
  });

  it('emits "expired"', async () => {
    const clock = new ManualClock(3_000_000);
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(), clock,
    });
    const events: string[] = [];
    sm.subscribe(e => events.push(e.type));
    await sm.login({ token: jwt(NOW_SEC + 3600), ttlMs: 10 });
    clock.advance(11);
    sm.getCurrentUser();
    expect(events).toContain('expired');
  });
});

/* ==================== Logout ==================== */

describe('logout', () => {
  it('clears session and cache', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60) });
    sm.cacheSet('k', 'v');
    sm.logout();
    expect(sm.isAuthenticated()).toBe(false);
    expect(sm.cacheGet('k')).toBeUndefined();
    expect(sm.scopedKeyCount).toBe(0);
  });

  it('is idempotent', () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    sm.logout();
    sm.logout();
    expect(sm.isAuthenticated()).toBe(false);
  });
});

/* ==================== Cache ==================== */

describe('cache', () => {
  it('roundtrip get/set', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60) });
    sm.cacheSet('profile', { theme: 'dark' }, 10_000);
    expect(sm.cacheGet<{ theme: string }>('profile')).toEqual({ theme: 'dark' });
  });

  it('isolates by user', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60, 'u1') });
    sm.cacheSet('k', 'u1-val');
    await sm.login({ token: jwt(NOW_SEC + 60, 'u2'), force: true });
    expect(sm.cacheGet('k')).toBeUndefined();
  });

  it('ttl capped by session remaining', async () => {
    const clock = new ManualClock(4_000_000);
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator(), clock });
    await sm.login({ token: jwt(NOW_SEC + 3600), ttlMs: 100 });
    sm.cacheSet('k', 'v', 1_000_000); // превышает сессию
    clock.advance(101);
    expect(sm.cacheGet('k')).toBeUndefined();
  });

  it('rejects invalid key', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    expect(() => sm.cacheGet('')).toThrow(InvalidArgumentError);
    expect(() => sm.cacheSet('', 1)).toThrow(InvalidArgumentError);
  });

  it('emits hit/miss/set/delete', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60) });
    const types: string[] = [];
    sm.subscribe(e => types.push(e.type));
    sm.cacheSet('a', 1);
    sm.cacheGet('a');
    sm.cacheGet('b');
    sm.cacheDelete('a');
    expect(types).toEqual(['cache:set', 'cache:hit', 'cache:miss', 'cache:delete']);
  });
});

/* ==================== LRU ==================== */

describe('LRU eviction', () => {
  it('evicts oldest on overflow', () => {
    const store = new MemoryCacheStore({ clock: { now: () => 0 }, maxSize: 2 });
    store.set('a', 1);
    store.set('b', 2);
    store.set('c', 3);
    expect(store.get('a')).toBeUndefined();
    expect(store.get('b')).toBe(2);
    expect(store.get('c')).toBe(3);
  });

  it('get touches recency', () => {
    const store = new MemoryCacheStore({ clock: { now: () => 0 }, maxSize: 2 });
    store.set('a', 1);
    store.set('b', 2);
    store.get('a');    // a — самый свежий
    store.set('c', 3); // вытеснит b
    expect(store.get('a')).toBe(1);
    expect(store.get('b')).toBeUndefined();
  });

  it('rejects invalid maxSize', () => {
    expect(() => new MemoryCacheStore({ clock: { now: () => 0 }, maxSize: 0 })).toThrow();
  });
});

/* ==================== Refresh ==================== */

describe('refresh', () => {
  it('throws without refresher', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    await sm.login({ token: jwt(NOW_SEC + 60), refreshToken: 'r' });
    await expect(sm.refresh()).rejects.toBeInstanceOf(RefreshNotAvailableError);
  });

  it('throws without active session', async () => {
    const refresher: TokenRefresher = { refresh: async () => ({ token: 'new' }) };
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(), tokenRefresher: refresher,
    });
    await expect(sm.refresh()).rejects.toBeInstanceOf(NotAuthenticatedError);
  });

  it('updates access token', async () => {
    const refresher: TokenRefresher = {
      refresh: async () => ({ token: 'new-access', refreshToken: 'new-refresh' }),
    };
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(), tokenRefresher: refresher,
    });
    await sm.login({ token: jwt(NOW_SEC + 60), refreshToken: 'r' });
    const s = await sm.refresh();
    expect(s.token).toBe('new-access');
    expect(s.refreshToken).toBe('new-refresh');
  });

  it('wraps refresher errors', async () => {
    const refresher: TokenRefresher = { refresh: async () => { throw new Error('network'); } };
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(), tokenRefresher: refresher,
    });
    await sm.login({ token: jwt(NOW_SEC + 60), refreshToken: 'r' });
    await expect(sm.refresh()).rejects.toBeInstanceOf(RefreshFailedError);
  });

  it('emits refresh:error', async () => {
    const refresher: TokenRefresher = { refresh: async () => { throw new Error('boom'); } };
    const sm = SessionManager.getInstance({
      tokenValidator: new JwtPayloadValidator(), tokenRefresher: refresher,
    });
    await sm.login({ token: jwt(NOW_SEC + 60), refreshToken: 'r' });
    const types: string[] = [];
    sm.subscribe(e => types.push(e.type));
    await sm.refresh().catch(() => {});
    expect(types).toContain('refresh:error');
  });
});

/* ==================== Storage ==================== */

describe('storage', () => {
  it('restores valid session', async () => {
    const storage = new MemorySessionStorage();
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator(), storage });
    await sm.login({ token: jwt(NOW_SEC + 3600) });
    SessionManager.resetInstance();
    const sm2 = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator(), storage });
    expect(sm2.isAuthenticated()).toBe(true);
  });

  it('discards expired restored session', async () => {
    const storage = new MemorySessionStorage();
    storage.save({
      user: { id: 'u1' }, token: 'x', issuedAt: 0, expiresAt: 1,
    });
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator(), storage });
    expect(sm.isAuthenticated()).toBe(false);
  });
});

/* ==================== Validators ==================== */

describe('validators', () => {
  it('FunctionTokenValidator wraps non-domain errors', async () => {
    const v = new FunctionTokenValidator(() => { throw new Error('oops'); });
    await expect(v.validate('x')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('FunctionTokenValidator preserves SessionError', async () => {
    const v = new FunctionTokenValidator(() => { throw new SessionExpiredError(); });
    await expect(v.validate('x')).rejects.toBeInstanceOf(SessionExpiredError);
  });

  it('Composite rejects inconsistent sub', async () => {
    const a = new FunctionTokenValidator(() => ({ sub: 'a', exp: NOW_SEC + 60 }));
    const b = new FunctionTokenValidator(() => ({ sub: 'b', exp: NOW_SEC + 60 }));
    const c = new CompositeTokenValidator([a, b]);
    await expect(c.validate('x')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('HmacJwtValidator verifies signature', async () => {
    const secret = 'top-secret';
    const enc = new TextEncoder();
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'u1', exp: NOW_SEC + 60 })).toString('base64url');
    const key = await crypto.subtle.importKey('raw', enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${payload}`));
    const token = `${header}.${payload}.${Buffer.from(sig).toString('base64url')}`;

    const v = new HmacJwtValidator(secret, { now: () => Date.now() });
    const p = await v.validate(token);
    expect(p.sub).toBe('u1');
  });

  it('HmacJwtValidator rejects tampered token', async () => {
    const v = new HmacJwtValidator('a', { now: () => Date.now() });
    const token = `${b64u({ alg: 'HS256' })}.${b64u({ sub: 'u1', exp: NOW_SEC + 60 })}.AAAA`;
    await expect(v.validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });
});

/* ==================== destroy ==================== */

describe('destroy', () => {
  it('makes all ops throw DestroyedError', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    sm.destroy();
    await expect(sm.login({ token: jwt(NOW_SEC + 60) })).rejects.toBeInstanceOf(DestroyedError);
    expect(() => sm.cacheGet('x')).toThrow(DestroyedError);
    expect(() => sm.subscribe(() => {})).toThrow(DestroyedError);
  });
  it('getCurrentUser returns null after destroy', () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    sm.destroy();
    expect(sm.getCurrentUser()).toBeNull();
    expect(sm.isAuthenticated()).toBe(false);
  });
});

/* ==================== Listener isolation ==================== */

describe('listeners', () => {
  it('throwing listener does not break others or core', async () => {
    const sm = SessionManager.getInstance({ tokenValidator: new JwtPayloadValidator() });
    const seen: string[] = [];
    sm.subscribe(() => { throw new Error('boom'); });
    sm.subscribe(e => seen.push(e.type));
    await sm.login({ token: jwt(NOW_SEC + 60) });
    expect(seen).toEqual(['login']);
    expect(sm.isAuthenticated()).toBe(true);
  });
});
