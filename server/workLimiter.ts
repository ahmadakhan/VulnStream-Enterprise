export class WorkCapacityError extends Error {
  constructor() {
    super('Expensive operation capacity exhausted');
    this.name = 'WorkCapacityError';
  }
}

/** FIFO admission with a bounded queue and a finite wait. Slots transfer atomically. */
export class WorkLimiter {
  private active = 0;
  private readonly waiting: Array<{ admit: () => void }> = [];
  constructor(
    private readonly concurrency: number,
    private readonly queueLimit: number,
    private readonly waitMs: number,
  ) {
    if (!Number.isInteger(concurrency) || concurrency < 1 || !Number.isInteger(queueLimit) || queueLimit < 0 || !Number.isFinite(waitMs) || waitMs <= 0)
      throw new Error('INVALID_WORK_LIMIT');
  }
  async run<T>(work: () => Promise<T>): Promise<T> {
    if (this.active < this.concurrency) this.active++;
    else {
      if (this.waiting.length >= this.queueLimit) throw new WorkCapacityError();
      await new Promise<void>((resolve, reject) => {
        const entry = { admit: () => { clearTimeout(timer); resolve(); } };
        const timer = setTimeout(() => {
          const index = this.waiting.indexOf(entry);
          if (index >= 0) this.waiting.splice(index, 1);
          reject(new WorkCapacityError());
        }, this.waitMs);
        this.waiting.push(entry);
      });
    }
    try { return await work(); }
    finally {
      const next = this.waiting.shift();
      if (next) next.admit();
      else this.active--;
    }
  }
}
