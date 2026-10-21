// Polling fallback for mail ingestion. Real-time webhooks are the primary path,
// but they can fail silently (subscription lapses, or a firewall blocks Microsoft's
// webhook POST). This loop re-scans every connected customer on a short cadence so
// the Message Log always catches up, even if webhooks aren't flowing. ingestTenantMail
// skips already-scored messages, so repeat scans only process genuinely new mail.

import { config } from './config';
import { listCustomers } from './onboarding';
import { getConnection } from './consent';
import { ingestTenantMail } from './emailsec/mailIngest';
import { subscribeTenant } from './emailsec/subscriptions';
import { markSync } from './connHealth';

let running = false;
let lastRun = 0;

export async function pollOnce(): Promise<void> {
  if (running) return; // never overlap runs
  running = true;
  lastRun = Date.now();
  try {
    for (const c of listCustomers()) {
      if (!getConnection(c.id)?.entraTenantId) continue; // only connected tenants
      try {
        // self-heal real-time: make sure every mailbox has a live subscription
        try { await subscribeTenant(c.id); } catch { /* firewall/handshake issues show up in the health panel */ }
        const r = await ingestTenantMail(c.id);
        markSync(c.id);
        if (r.scored) console.log(`[poll] ${c.name}: scored ${r.scored} new message(s)`);
      } catch (e) {
        console.error(`[poll] ${c.name}:`, (e as Error).message);
      }
    }
  } finally {
    running = false;
  }
}

export function pollStatus() { return { running, lastRun }; }

export function startMailPolling(intervalMs = 5 * 60000): void {
  if (config.directoryProvider !== 'graph') return; // mock tenants don't poll
  // kick one off shortly after boot, then on the interval
  setTimeout(() => { pollOnce().catch(() => {}); }, 20000);
  setInterval(() => { pollOnce().catch(() => {}); }, intervalMs);
  console.log(`[poll] mail polling started (every ${Math.round(intervalMs / 60000)} min)`);
}
