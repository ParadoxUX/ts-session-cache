# ts-session-cache

Production-grade singleton session & cache manager with token validation,
refresh flow, LRU cache and SOLID architecture.

## Install
\`\`\`bash
npm i ts-session-cache
\`\`\`

## Quick start
\`\`\`ts
import { SessionManager, HmacJwtValidator, SystemClock } from 'ts-session-cache';

const sm = SessionManager.getInstance({
  tokenValidator: new HmacJwtValidator(process.env.JWT_SECRET!, new SystemClock()),
});

await sm.login({ token, refreshToken });
sm.cacheSet('profile', { theme: 'dark' }, 60_000);
const me = sm.getCurrentUser();
sm.logout();
\`\`\`

## Features
- Singleton lifecycle with `resetInstance()` and `destroy()`
- Token validators: `JwtPayloadValidator`, `HmacJwtValidator`, `FunctionTokenValidator`, `CompositeTokenValidator`
- Refresh-token flow with auto-refresh timer
- User-scoped LRU cache with TTL capped by session lifetime
- `AbortSignal` support, `Telemetry`, structured `SessionError` hierarchy
- 39 tests, strict TypeScript (ES2022, `exactOptionalPropertyTypes`)

## License
MIT
