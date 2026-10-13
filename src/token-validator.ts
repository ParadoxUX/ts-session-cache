import { AbortedError, InvalidTokenError, SessionExpiredError, SessionError } from './errors';
import { SystemClock, type Clock } from './clock';
import type { TokenPayload } from './types';

/**
 * Контракт валидатора токенов.
 * Может быть sync или async; должен уважать `signal`.
 */
export interface TokenValidator {
  validate(token: string, signal?: AbortSignal): TokenPayload | Promise<TokenPayload>;
}

/* ============================ JWT (no signature) =========================== */

/**
 * Разбирает JWT-payload БЕЗ проверки подписи.
 * Проверяет: формат, `sub`, `exp`, факт истечения.
 * ⚠️ Не защищает от подделки — используй {@link HmacJwtValidator}
 *    или собственный крипто-валидатор.
 */
export class JwtPayloadValidator implements TokenValidator {
  private readonly clock: Clock;
  constructor(clock: Clock = new SystemClock()) {
    this.clock = clock;
  }
  validate(token: string, signal?: AbortSignal): TokenPayload {
    throwIfAborted(signal);
    const payload = decodeJwtPayload(token);
    assertPayloadShape(payload);
    if (payload.exp * 1000 <= this.clock.now()) {
      throw new SessionExpiredError('JWT has expired.');
    }
    return payload;
  }
}

/* ============================ HMAC-SHA256 JWT ============================== */

/**
 * Полноценная проверка подписи HS256 через WebCrypto.
 * Требует `crypto.subtle` (Node 20+, браузеры, Deno).
 */
export class HmacJwtValidator implements TokenValidator {
  private readonly secret: Uint8Array;
  private readonly clock: Clock;

  constructor(secret: string | Uint8Array, clock: Clock = new SystemClock()) {
    this.secret = typeof secret === 'string' ? new TextEncoder().encode(secret) : secret;
    if (this.secret.length === 0) {
      throw new InvalidTokenError('HMAC secret must be non-empty.');
    }
    this.clock = clock;
  }

  async validate(token: string, signal?: AbortSignal): Promise<TokenPayload> {
    throwIfAborted(signal);
    const parts = splitJwt(token);
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      toBufferSource(this.secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const sigBytes = toBufferSource(base64UrlToBytes(parts.signature));
    const dataBytes = toBufferSource(new TextEncoder().encode(`${parts.header}.${parts.payload}`));
    const ok = await globalThis.crypto.subtle.verify('HMAC', key, sigBytes, dataBytes);
    if (!ok) throw new InvalidTokenError('JWT signature verification failed.');

    const payload = JSON.parse(base64UrlToString(parts.payload)) as TokenPayload;
    assertPayloadShape(payload);
    if (payload.exp * 1000 <= this.clock.now()) {
      throw new SessionExpiredError('JWT has expired.');
    }
    return payload;
  }
}

/* ============================ Function-based =============================== */

/**
 * Обёртка над произвольной функцией. Sync-throw и reject оборачиваются
 * в {@link InvalidTokenError} (кроме уже-доменных `SessionError`).
 */
export class FunctionTokenValidator implements TokenValidator {
  private readonly fn: (token: string, signal?: AbortSignal) => TokenPayload | Promise<TokenPayload>;

  constructor(fn: (token: string, signal?: AbortSignal) => TokenPayload | Promise<TokenPayload>) {
    this.fn = fn;
  }

  async validate(token: string, signal?: AbortSignal): Promise<TokenPayload> {
    throwIfAborted(signal);
    try {
      const payload = await this.fn(token, signal);
      assertPayloadShape(payload);
      return payload;
    } catch (e) {
      if (e instanceof SessionError) throw e;
      if (signal?.aborted) throw new AbortedError();
      throw new InvalidTokenError(
        `Custom validator failed: ${e instanceof Error ? e.message : String(e)}`,
        e,
      );
    }
  }
}

/* ============================ Composite =================================== */

/**
 * Композиция валидаторов: все обязаны пройти.
 * Требует консистентности `sub` и `exp` между результатами —
 * иначе ошибка (защита от рассинхронизации источников).
 */
export class CompositeTokenValidator implements TokenValidator {
  private readonly validators: readonly TokenValidator[];
  constructor(validators: readonly TokenValidator[]) {
    if (validators.length === 0) {
      throw new InvalidTokenError('CompositeTokenValidator requires at least one validator.');
    }
    this.validators = validators;
  }

  async validate(token: string, signal?: AbortSignal): Promise<TokenPayload> {
    let first: TokenPayload | null = null;
    for (const v of this.validators) {
      throwIfAborted(signal);
      const p = await v.validate(token, signal);
      if (first === null) {
        first = p;
        continue;
      }
      if (first.sub !== p.sub || first.exp !== p.exp) {
        throw new InvalidTokenError(
          `Validator results are inconsistent (sub/exp mismatch: ${first.sub}/${first.exp} vs ${p.sub}/${p.exp}).`,
        );
      }
    }
    return first as TokenPayload;
  }
}

/* ============================ utilities =================================== */

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new AbortedError();
}

function splitJwt(token: string): { header: string; payload: string; signature: string } {
  if (typeof token !== 'string' || token.length === 0) {
    throw new InvalidTokenError('Token must be a non-empty string.');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new InvalidTokenError('Token is not a well-formed JWT (expected 3 segments).');
  }
  return { header: parts[0]!, payload: parts[1]!, signature: parts[2]! };
}

function decodeJwtPayload(token: string): TokenPayload {
  const { payload } = splitJwt(token);
  try {
    return JSON.parse(base64UrlToString(payload)) as TokenPayload;
  } catch (e) {
    throw new InvalidTokenError('JWT payload is not valid JSON.', e);
  }
}

function assertPayloadShape(payload: unknown): asserts payload is TokenPayload {
  if (!payload || typeof payload !== 'object') {
    throw new InvalidTokenError('Token payload must be an object.');
  }
  const p = payload as Partial<TokenPayload>;
  if (typeof p.sub !== 'string' || p.sub.length === 0) {
    throw new InvalidTokenError('Token payload must contain a non-empty "sub".');
  }
  if (typeof p.exp !== 'number' || !Number.isFinite(p.exp)) {
    throw new InvalidTokenError('Token payload must contain a numeric "exp".');
  }
}

function base64UrlToString(input: string): string {
  const bytes = base64UrlToBytes(input);
  return new TextDecoder().decode(bytes);
}

function base64UrlToBytes(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;

  const g = globalThis as unknown as {
    atob?: (s: string) => string;
    Buffer?: { from(s: string, enc: string): Uint8Array };
  };
  if (typeof g.atob === 'function') {
    const bin = g.atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  if (g.Buffer) return g.Buffer.from(b64, 'base64');
  throw new InvalidTokenError('No base64 decoder available in this environment.');
}

/**
 * Приводит Uint8Array к BufferSource с гарантированным ArrayBuffer.
 * Обходит ограничение TS 5.7+ (`Uint8Array<ArrayBufferLike>` ⊄ `BufferSource`).
 * Копирует данные, если буфер — SharedArrayBuffer.
 */
function toBufferSource(u: Uint8Array): BufferSource {
  const buf = u.buffer;
  if (buf instanceof ArrayBuffer) {
    return new Uint8Array(buf, u.byteOffset, u.byteLength);
  }
  // SharedArrayBuffer: копируем в свежий ArrayBuffer.
  const copy = new Uint8Array(u.byteLength);
  copy.set(u);
  return copy;
}
