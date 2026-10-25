import { WorkLimiter, WorkCapacityError } from '../server/workLimiter.ts';
import assert from 'node:assert/strict';
import { test } from 'node:test';

const hold = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

test('WorkLimiter admits at most concurrency callers and rejects overflow immediately', async () => {
  const limiter = new WorkLimiter(1, 0, 5000);
  const [a, b, c] = await Promise.allSettled([
    limiter.run(() => hold(30)),
    limiter.run(() => hold(30)),
    limiter.run(() => hold(30)),
  ]);
  assert.equal(a.status, 'fulfilled');
  assert.equal(b.status, 'rejected');
  assert.ok(b.reason instanceof WorkCapacityError);
  assert.equal(c.status, 'rejected');
  assert.ok(c.reason instanceof WorkCapacityError);
});

test('WorkLimiter queues up to queueLimit then rejects the overflow', async () => {
  const limiter = new WorkLimiter(1, 2, 5000);
  const [a, b, c, d] = await Promise.allSettled([
    limiter.run(() => hold(30)),
    limiter.run(() => hold(0)),
    limiter.run(() => hold(0)),
    limiter.run(() => hold(0)),
  ]);
  assert.equal(a.status, 'fulfilled');
  assert.equal(b.status, 'fulfilled');
  assert.equal(c.status, 'fulfilled');
  assert.equal(d.status, 'rejected');
  assert.ok(d.reason instanceof WorkCapacityError);
});

test('WorkLimiter rejects a queued caller whose wait exceeds waitMs', async () => {
  const limiter = new WorkLimiter(1, 1, 60);
  const [a, b, c] = await Promise.allSettled([
    limiter.run(() => hold(200)),
    limiter.run(() => hold(0)),
    limiter.run(() => hold(0)),
  ]);
  assert.equal(a.status, 'fulfilled');
  assert.equal(b.status, 'rejected');
  assert.ok(b.reason instanceof WorkCapacityError);
});

test('WorkLimiter releases slots to queued callers in FIFO order', async () => {
  const limiter = new WorkLimiter(1, 4, 5000);
  const order: string[] = [];
  const [a, b] = await Promise.allSettled([
    limiter.run(() => hold(40).then(() => order.push('a'))),
    limiter.run(async () => order.push('b')),
  ]);
  assert.equal(a.status, 'fulfilled');
  assert.equal(b.status, 'fulfilled');
  assert.deepEqual(order, ['a', 'b']);
});
