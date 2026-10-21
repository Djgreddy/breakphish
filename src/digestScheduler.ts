// Sends quarantine digests on each customer's configured schedule (days + times).
// Runs a light loop every few minutes; for each customer whose settings say "send
// now" (matching day + a time slot within the last window) it emails every user
// who has quarantined mail. A per-(customer, day, time) guard prevents re-sending
// the same slot twice.

import { config } from './config';
import { listCustomers } from './onboarding';
import { getConnection } from './consent';
import { getSettings } from './settings';
import { store } from './store';
import { emailStore } from './emailsec/store';
import { appToken } from './directory/graphProvider';
import { digestHtml, signPortalToken, quarantinedForUser } from './quarantinePortal';
import { getLastSent, setLastSent } from './digestState';

const DAY = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const sentSlots = new Set<string>(); // `${customerId}:${yyyy-mm-dd}:${time}`

// Parse "9:00 AM" → minutes-since-midnight.
function parseTime(t: string): number | null {
  const m = /^(\d{1,2}):(\d{2})\s*(AM|PM)?$/i.exec(t.trim());
  if (!m) return null;
  let h = parseInt(m[1], 10); const min = parseInt(m[2], 10); const ap = (m[3] ?? '').toUpperCase();
  if (ap === 'PM' && h < 12) h += 12; if (ap === 'AM' && h === 12) h = 0;
  return h * 60 + min;
}

async function sendDigestTo(customerId: string, entraTenantId: string, email: string, since = 0): Promise<boolean> {
  const html = digestHtml(customerId, email, signPortalToken(customerId, email), since);
  const token = await appToken(entraTenantId);
  const r = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(email)}/sendMail`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ message: { subject: 'Your Quarantine Digest', body: { contentType: 'HTML', content: html }, toRecipients: [{ emailAddress: { address: email } }] }, saveToSentItems: false }),
  });
  return r.ok;
}

async function runOnce(now = new Date()): Promise<void> {
  const today = DAY[now.getDay()];
  const dateKey = now.toISOString().slice(0, 10);
  const nowMin = now.getHours() * 60 + now.getMinutes();

  for (const c of listCustomers()) {
    const conn = getConnection(c.id);
    if (!conn?.entraTenantId) continue;
    const dg = getSettings(c.id).quarantineDigest;
    if (!dg || dg.frequency === 'Off' || !(dg.days ?? []).includes(today)) continue;

    for (const t of dg.times ?? []) {
      const slotMin = parseTime(t);
      if (slotMin == null) continue;
      // fire if we're within 10 minutes past the slot and haven't sent it today
      if (nowMin < slotMin || nowMin - slotMin > 10) continue;
      const guard = `${c.id}:${dateKey}:${t}`;
      if (sentSlots.has(guard)) continue;
      sentSlots.add(guard);

      // every user who has quarantined mail, but only send if they have NEW items
      const recipients = new Set<string>();
      for (const a of emailStore.quarantinedForTenant(c.id)) {
        const m = emailStore.messages.get((a as any).messageId);
        if (m?.to) recipients.add(m.to.toLowerCase());
      }
      let sent = 0, skipped = 0;
      for (const email of recipients) {
        const since = getLastSent(c.id, email);
        const fresh = quarantinedForUser(c.id, email, since);
        if (!fresh.length) { skipped++; continue; } // nothing new → no email
        try {
          if (await sendDigestTo(c.id, conn.entraTenantId, email, since)) { sent++; await setLastSent(c.id, email); }
        } catch { /* skip */ }
      }
      if (sent || skipped) console.log(`[digest] ${c.name} @ ${t}: sent ${sent}, skipped ${skipped} (no new items)`);
    }
  }
}

export function startDigestScheduler(): void {
  if (config.emailTransport === 'console') {
    // still runs, but Graph sendMail needs Mail.Send consent to actually deliver
  }
  const tick = () => runOnce().catch(e => console.error('[digest]', (e as Error).message));
  setInterval(tick, 5 * 60000); // every 5 minutes
  // prune yesterday's guards daily
  setInterval(() => { const d = new Date().toISOString().slice(0, 10); for (const k of sentSlots) if (!k.includes(d)) sentSlots.delete(k); }, 6 * 3600000);
  console.log('[digest] scheduler started (checks every 5 min)');
}

// Exposed for tests.
export const _internal = { runOnce, parseTime, sentSlots };
