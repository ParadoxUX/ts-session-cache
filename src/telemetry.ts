import type { LogLevel, Telemetry } from './types';

/** Ничего не делает. Дефолт. */
export const NoopTelemetry: Telemetry = {
  log(): void {},
};

/** Пишет в `console` с префиксом. Удобно для локальной отладки. */
export class ConsoleTelemetry implements Telemetry {
  log(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
    const fn =
      level === 'error' ? console.error :
      level === 'warn' ? console.warn :
      level === 'debug' ? console.debug :
      console.info;
    fn(`[ts-session-cache] ${message}`, meta ?? {});
  }
}
