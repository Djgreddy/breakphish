// Express routes for the admin-consent flow. In production these live behind the
// onboarding UI: "Connect Microsoft 365" sends the admin to /start, Microsoft
// redirects back to /callback, and we show the result.

import express from 'express';
import { buildConsentUrl, handleConsentCallback, getConnection } from './consent';
import { store } from './store';
import { syncTenant } from './directory/syncService';
import { getCustomer, markCustomerConnected } from './onboarding';
import { ingestTenantMail } from './emailsec/mailIngest';
import { subscribeTenant } from './emailsec/subscriptions';

// After a real admin grants consent, Microsoft gives us the customer's true
// tenant id and verified domains. Point the tenant at them and run the first
// directory sync. Mail scoring on real inboxes needs a Graph mail reader (not
// built yet), so a real connect currently delivers users + groups.
async function finishRealConnection(customerId: string): Promise<void> {
  const conn = getConnection(customerId);
  const t = store.getTenant(customerId);
  if (!conn?.entraTenantId || !t) return;
  t.entraTenantId = conn.entraTenantId;
  if (conn.verifiedDomains?.length) t.verifiedDomains = conn.verifiedDomains;
  // Persist the real tenant id + verified domains onto the customer record so
  // the connection survives a restart.
  await markCustomerConnected(customerId, conn.entraTenantId, conn.verifiedDomains ?? []);
  await syncTenant(customerId);

  // For email-security customers, pull an initial batch of real inbox mail so
  // the tracker/dashboard aren't empty on first load. Best-effort — a mail-read
  // failure shouldn't fail the whole connection.
  const customer = getCustomer(customerId);
  if (customer?.products.includes('email_security')) {
    try { await ingestTenantMail(customerId); }
    catch (e) { console.error('[connect] initial mail scan failed:', (e as Error).message); }
    // Turn on real-time: subscribe every mailbox to Graph change notifications.
    try { await subscribeTenant(customerId); }
    catch (e) { console.error('[connect] subscribe failed:', (e as Error).message); }
  }
}

export function buildConsentApp() {
  const app = express();

  // The admin clicks "Connect Microsoft 365" for a customer → redirect to MS.
  app.get('/onboarding/consent/start', (req, res) => {
    const customerId = String(req.query.customer ?? '');
    try {
      const { url } = buildConsentUrl(customerId);
      res.redirect(url);
    } catch (e) {
      res.status(400).send((e as Error).message);
    }
  });

  // Microsoft redirects here after the admin grants or declines.
  app.get('/onboarding/consent/callback', async (req, res) => {
    const result = await handleConsentCallback(req.query as Record<string, string | undefined>);
    const page = (title: string, body: string, color: string) =>
      `<!doctype html><meta charset="utf-8"><title>${title}</title>
       <body style="font-family:system-ui;background:#f5f6fb;display:grid;place-items:center;height:100vh;margin:0">
       <div style="max-width:440px;text-align:center;padding:32px;background:#fff;border:1px solid #e7e9f3;border-radius:16px">
       <div style="width:56px;height:56px;border-radius:14px;background:${color}22;display:grid;place-items:center;margin:0 auto 16px;font-size:26px">${color === '#15a34a' ? '✅' : '⚠️'}</div>
       <h2 style="margin:0 0 8px">${title}</h2><p style="color:#6b7490">${body}</p></div></body>`;
    if (result.ok) {
      const c = result.connection!;
      try {
        await finishRealConnection(result.customerId!);
      } catch (e) {
        return res.status(500).send(page('Connected, but sync failed', (e as Error).message, '#e11d48'));
      }
      const users = store.usersForTenant(result.customerId!).length;
      res.send(page('Microsoft 365 connected',
        `${c.displayName} · verified domains: ${c.verifiedDomains?.join(', ')} · ${users} users synced. <a href="/">Return to console</a>.`,
        '#15a34a'));
    } else {
      res.status(400).send(page('Consent not completed', result.error ?? 'Please try connecting again.', '#e11d48'));
    }
  });

  return app;
}
