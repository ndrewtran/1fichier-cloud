export const MAX_ACTIVITY_BATCH = 10;
export const MAX_ACTIVITY_BATCH_BYTES = 60 * 1024;
export const MAX_ACTIVITY_RESPONSE_BYTES = 40 * 1024;

/** Bound one sanitized diagnostic body before it can enter an activity event. */
export function boundActivityResponseBody(value: unknown): unknown {
  const serialized = JSON.stringify(value);
  if (serialized !== undefined && new TextEncoder().encode(serialized).byteLength <= MAX_ACTIVITY_RESPONSE_BYTES) return value;
  return "[truncated]";
}

export function activityBatchBodyBytes(entries: readonly unknown[]): number {
  const body = JSON.stringify({ entries });
  return new TextEncoder().encode(body).byteLength;
}

/** Return the next request-sized prefix without serializing the remaining backlog. */
export function takeActivityBatch<T>(entries: readonly T[]): T[] {
  let batch: T[] = [];
  for (const entry of entries) {
    const candidate = [...batch, entry];
    if (batch.length > 0 && (candidate.length > MAX_ACTIVITY_BATCH || activityBatchBodyBytes(candidate) > MAX_ACTIVITY_BATCH_BYTES)) break;
    batch = candidate;
  }
  return batch;
}

/** Split events by both request count and exact UTF-8 body size for tests and diagnostics. */
export function splitActivityBatches<T>(entries: readonly T[]): T[][] {
  const batches: T[][] = [];
  let remaining = entries;
  while (remaining.length > 0) {
    const batch = takeActivityBatch(remaining);
    if (batch.length === 0) break;
    batches.push(batch);
    remaining = remaining.slice(batch.length);
  }
  return batches;
}
