export class ApiRateLimiter {
  private readonly intervalMs: number;
  private nextStart = 0;
  private tail: Promise<void> = Promise.resolve();

  public constructor(callsPerSecond: number) {
    if (!Number.isFinite(callsPerSecond) || callsPerSecond <= 0) {
      throw new Error("callsPerSecond must be positive");
    }
    this.intervalMs = 1000 / callsPerSecond;
  }

  public enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.tail.then(async () => {
      const waitMs = this.nextStart - Date.now();
      if (waitMs > 0) await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
      this.nextStart = Date.now() + this.intervalMs;
      return task();
    });

    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}
