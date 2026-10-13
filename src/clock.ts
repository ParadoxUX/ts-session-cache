/** Источник времени. Инжектируется (DIP, тестируемость). */
export interface Clock {
  now(): number;
}

/** Системные часы. */
export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }
}

/** Детерминированные часы для тестов. */
export class ManualClock implements Clock {
  private t: number;
  constructor(start = 0) {
    this.t = start;
  }
  now(): number {
    return this.t;
  }
  advance(ms: number): void {
    this.t += ms;
  }
  set(ms: number): void {
    this.t = ms;
  }
}
