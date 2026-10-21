// Tracks when each user last received a quarantine digest, so scheduled digests
// can show only what's new since then (not the whole backlog).

import { dbEnabled, q } from './db/db';

const lastSent = new Map<string, number>(); // `${customerId}:${email}` -> epoch ms
const key = (c: string, e: string) => `${c}:${e.toLowerCase()}`;

export function getLastSent(customerId: string, email: string): number {
  return lastSent.get(key(customerId, email)) ?? 0;
}

export async function setLastSent(customerId: string, email: string, ts: number = Date.now()): Promise<void> {
  lastSent.set(key(customerId, email), ts);
  if (dbEnabled()) {
    await q(`insert into digest_state (customer_id, user_email, last_sent_at) values ($1,$2,to_timestamp($3/1000.0))
             on conflict (customer_id, user_email) do update set last_sent_at=excluded.last_sent_at`,
      [customerId, email.toLowerCase(), ts]);
  }
}

export async function hydrateDigestState(): Promise<void> {
  if (!dbEnabled()) return;
  const rows = await q<any>('select customer_id, user_email, last_sent_at from digest_state');
  for (const r of rows) lastSent.set(key(r.customer_id, r.user_email), new Date(r.last_sent_at).getTime());
}
