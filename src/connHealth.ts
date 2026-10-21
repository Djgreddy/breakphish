// Tracks real-time health per customer: when we last received a Graph webhook
// notification (proves push is working) and when we last polled. The health panel
// reads this to show whether real-time is live or we're relying on polling.

const lastWebhook = new Map<string, number>();
const lastSync = new Map<string, number>();

export function markWebhook(customerId: string) { lastWebhook.set(customerId, Date.now()); }
export function markSync(customerId: string) { lastSync.set(customerId, Date.now()); }

export function healthFor(customerId: string) {
  const lw = lastWebhook.get(customerId) ?? 0;
  const ls = lastSync.get(customerId) ?? 0;
  // "realtime" = we've received a push in the last 20 minutes
  return { lastWebhookAt: lw, lastSyncAt: ls, realtime: lw > 0 && Date.now() - lw < 20 * 60000 };
}
