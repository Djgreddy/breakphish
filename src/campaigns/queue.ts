// Minimal in-process queue so the demo runs with no broker. In production,
// replace with SQS / RabbitMQ / Redis streams — same enqueue/consumer shape.

export interface SendJob { recipientId: string; }

type Consumer = (job: SendJob) => Promise<void>;

class Queue {
  private jobs: SendJob[] = [];
  private consumer: Consumer | null = null;
  private draining = false;

  onJob(consumer: Consumer) { this.consumer = consumer; }

  enqueue(job: SendJob) {
    this.jobs.push(job);
    void this.drain();
  }

  private async drain() {
    if (this.draining || !this.consumer) return;
    this.draining = true;
    while (this.jobs.length) {
      const job = this.jobs.shift()!;
      try { await this.consumer(job); }
      catch (err) { console.error('[queue] job failed', err); }
    }
    this.draining = false;
  }

  // For the demo: resolve once the queue is empty.
  async idle() {
    while (this.draining || this.jobs.length) await new Promise(r => setTimeout(r, 10));
  }
}

export const sendQueue = new Queue();
