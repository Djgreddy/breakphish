// The HTTP API the console talks to. Thin wrappers over the services already
// built — onboarding, consent, directory sync, the detection pipeline, and
// reporting. No new business logic lives here.

import express from 'express';
import { onboardCustomer, getCustomer, listCustomers, deleteCustomer, editCustomer, type Customer } from './onboarding';
import { buildConsentUrl, handleConsentCallback, getConnection, deleteConnection } from './consent';
import { syncTenant } from './directory/syncService';
import { store } from './store';
import { generateRawMessages } from './emailsec/generate';
import { ingestBatch } from './emailsec/pipeline';
import { emailStore } from './emailsec/store';
import { dashboard, liveTracker } from './emailsec/reporting';
import { ingestTenantMail } from './emailsec/mailIngest';
import { DEFAULT_POLICY, policyFor } from './emailsec/policy';
import { attachSession, requireAuth, requirePartner, requireCustomerAccess, sessionOf } from './auth/middleware';
import { getSettings, saveSettings } from './settings';
import { config } from './config';
import { healthSnapshot } from './health';
import { buildInfo, updateStatus } from './version';

const VERDICT_LABEL: Record<string, string> = {
  clean: 'Clean', spam: 'Spam', spam_likely: 'Spam-Likely', phishing: 'Phishing',
  malware: 'Malware', impersonation: 'Impersonation', policy_infomail: 'Policy — Infomail', policy_geo: 'Policy — Geo',
};

function mailboxesFor(customerId: string): string[] {
  const users = store.usersForTenant(customerId).filter(u => u.enabled);
  return users.length ? users.map(u => u.email) : [`admin@${getCustomer(customerId)?.primaryDomain}`];
}

// Connect (mock): run the consent callback with a synthetic tenant, then sync
// the directory and generate + score a stream of inbound mail. This is what the
// "Connect Microsoft 365" button triggers in mock mode. In production the
// connection completes via the real Microsoft redirect instead.
export async function connectAndSeed(customerId: string): Promise<void> {
  const { url } = buildConsentUrl(customerId);
  const state = new URL(url).searchParams.get('state')!;
  await handleConsentCallback({ admin_consent: 'True', tenant: `tid-${customerId}`, state });

  const conn = getConnection(customerId);
  const t = store.getTenant(customerId);
  if (t && conn?.entraTenantId) t.entraTenantId = conn.entraTenantId;
  await syncTenant(customerId);

  const c = getCustomer(customerId)!;
  if (c.products.includes('email_security')) {
    const raw = generateRawMessages(customerId, c.primaryDomain, mailboxesFor(customerId), Math.min(1400, c.mailboxes * 8));
    await ingestBatch(raw);
  }
}

function customerSummary(c: Customer) {
  const conn = getConnection(c.id);
  const d = c.products.includes('email_security') ? dashboard(c.id) : null;
  return {
    id: c.id, name: c.name, domain: c.primaryDomain, products: c.products,
    mailboxes: c.mailboxes, licenses: c.licenses,
    status: 'active',
    service: c.integrationModel === 'api' ? 'BreakPhish 365' : (c.integrationModel ?? ''),
    orderedAt: c.orderedAt, flags: c.flags, integrationModel: c.integrationModel,
    connection: conn ? { status: conn.status, verifiedDomains: conn.verifiedDomains ?? [] } : { status: 'not_connected', verifiedDomains: [] },
    syncedUsers: store.usersForTenant(c.id).length,
    threats: d ? d.threats : 0, processed: d ? d.processed : 0,
  };
}

export function buildApi() {
  const api = express.Router();
  api.use(express.json());
  api.use(attachSession);
  api.use(requireAuth);                              // every API call needs a session
  api.use('/customers/:id', requireCustomerAccess); // per-customer scope check

  // ---- Settings config (partner defaults + per-customer) ----
  // Partner may read/write 'partner' or any customer scope; an administrator
  // only their own customer scope.
  function resolveScope(req: any, res: any): string | null {
    const s = sessionOf(req)!;
    if (s.role === 'partner_admin') return String(req.query?.scope ?? req.body?.scope ?? 'partner');
    const scope = s.customerId;
    const asked = String(req.query?.scope ?? req.body?.scope ?? scope);
    if (asked !== scope) { res.status(403).json({ error: 'forbidden scope' }); return null; }
    return scope ?? null;
  }
  api.get('/settings/config', requireAuth, (req, res) => {
    const scope = resolveScope(req, res); if (scope == null) return;
    res.json({ scope, settings: getSettings(scope) });
  });
  api.put('/settings/config', requireAuth, async (req, res) => {
    try {
      const scope = resolveScope(req, res); if (scope == null) return;
      await saveSettings(scope, req.body?.settings);
      res.json({ ok: true });
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });

  // ---- Settings: health + version (partner only, read-only) ----
  api.get('/settings/health', requirePartner, async (_req, res) => res.json(await healthSnapshot()));
  api.get('/settings/version', requirePartner, (_req, res) => res.json(buildInfo()));
  // Checks the git remote for newer commits. Does NOT pull or deploy.
  api.get('/settings/update-check', requirePartner, async (_req, res) => {
    try { res.json(await updateStatus()); }
    catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  // ---- Partner ----
  api.get('/customers', requirePartner, (_req, res) => res.json(listCustomers().map(customerSummary)));

  api.post('/customers', requirePartner, async (req, res) => {
    try {
      const { name, domain, products, integrationModel, mailboxes } = req.body ?? {};
      const c = await onboardCustomer({
        name, primaryDomain: domain, products, integrationModel: integrationModel ?? 'api',
        mailboxes: Number(mailboxes) || 50,
      });
      const { url } = buildConsentUrl(c.id);
      res.status(201).json({ customer: customerSummary(c), consentUrl: url });
    } catch (e) {
      res.status(400).json({ error: (e as Error).message });
    }
  });

  api.get('/customers/:id', (req, res) => {
    const c = getCustomer(req.params.id);
    if (!c) return res.status(404).json({ error: 'not found' });
    res.json(customerSummary(c));
  });

  // Edit a customer's name, license count, and feature flags.
  api.patch('/customers/:id', requirePartner, async (req, res) => {
    try {
      const { name, licenses, flags } = req.body ?? {};
      const c = await editCustomer(req.params.id, { name, licenses, flags });
      if (!c) return res.status(404).json({ error: 'not found' });
      res.json(customerSummary(c));
    } catch (e) {
      res.status(400).json({ error: (e as Error).message });
    }
  });

  api.get('/customers/:id/consent-url', (req, res) => {
    try { res.json({ url: buildConsentUrl(req.params.id).url }); }
    catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });

  // Connect Microsoft 365.
  //  - real mode (graph): return the admin-consent URL for the browser to open;
  //    the real tenant id + directory sync happen in the consent callback.
  //  - mock mode: complete the fake consent + seed inline for offline demos.
  // Wrapped so a failure returns JSON instead of crashing the server.
  api.post('/customers/:id/connect', requirePartner, async (req, res) => {
    try {
      if (!getCustomer(req.params.id)) return res.status(404).json({ error: 'not found' });
      if (config.directoryProvider === 'mock') {
        await connectAndSeed(req.params.id);
        return res.json({ connected: true, customer: customerSummary(getCustomer(req.params.id)!) });
      }
      const { url } = buildConsentUrl(req.params.id);
      return res.json({ redirect: url }); // browser sends the admin to Microsoft
    } catch (e) {
      return res.status(500).json({ error: (e as Error).message });
    }
  });

  // Pull + score the latest real inbox mail for a connected tenant (graph mode).
  api.post('/customers/:id/scan-mail', async (req, res) => {
    try {
      if (!getCustomer(req.params.id)) return res.status(404).json({ error: 'not found' });
      if (config.directoryProvider === 'mock') return res.status(400).json({ error: 'scan-mail is for connected (graph) tenants' });
      const result = await ingestTenantMail(req.params.id);
      return res.json({ ok: true, ...result });
    } catch (e) {
      return res.status(500).json({ error: (e as Error).message });
    }
  });

  // Re-sync a connected tenant's directory + mail on demand (no re-consent).
  api.post('/customers/:id/resync', requirePartner, async (req, res) => {
    try {
      const id = req.params.id;
      if (!getCustomer(id)) return res.status(404).json({ error: 'not found' });
      const conn = getConnection(id);
      if (conn?.status !== 'connected' || !conn.entraTenantId) return res.status(400).json({ error: 'customer is not connected' });
      // Make sure the tenant has its verified domains (older connections may lack them).
      if (conn.verifiedDomains?.length) {
        const t = store.getTenant(id);
        if (t) { t.entraTenantId = conn.entraTenantId; t.verifiedDomains = conn.verifiedDomains; }
      }
      const sync = await syncTenant(id);
      let scored = 0;
      if (getCustomer(id)!.products.includes('email_security')) {
        const r = await ingestTenantMail(id); scored = r.scored;
      }
      res.json({ ok: true, users: sync.users, groups: sync.groups, scored });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  // Delete a customer and all its data (offboarding). Partner only.
  api.delete('/customers/:id', requirePartner, async (req, res) => {
    try {
      const id = req.params.id;
      if (!getCustomer(id)) return res.status(404).json({ error: 'not found' });
      deleteConnection(id);
      await deleteCustomer(id);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  // ---- Email Security (per customer) ----
  api.get('/customers/:id/dashboard', (req, res) => {
    if (!getCustomer(req.params.id)) return res.status(404).json({ error: 'not found' });
    res.json(dashboard(req.params.id));
  });

  api.get('/customers/:id/messages', (req, res) => {
    if (!getCustomer(req.params.id)) return res.status(404).json({ error: 'not found' });
    const q = String(req.query.q ?? '').toLowerCase();
    const from = String(req.query.from ?? '').toLowerCase();
    const to = String(req.query.to ?? '').toLowerCase();
    const verdict = String(req.query.verdict ?? '');
    const direction = String(req.query.direction ?? '');
    const status = String(req.query.status ?? '');
    const page = Math.max(0, Number(req.query.page ?? 0));
    const per = Math.min(100, Number(req.query.per ?? 15));
    const customer = getCustomer(req.params.id);
    const service = customer?.integrationModel === 'api' ? 'BreakPhish 365' : (customer?.integrationModel ?? '');
    let rows = liveTracker(req.params.id);
    if (verdict) rows = rows.filter(r => r.verdict === verdict);
    if (direction) rows = rows.filter(r => r.direction === direction);
    if (status) rows = rows.filter(r => r.status === status);
    if (from) rows = rows.filter(r => r.from.toLowerCase().includes(from));
    if (to) rows = rows.filter(r => r.to.toLowerCase().includes(to));
    if (q) rows = rows.filter(r => r.from.toLowerCase().includes(q) || r.to.toLowerCase().includes(q) || r.subject.toLowerCase().includes(q));
    const total = rows.length;
    const slice = rows.slice(page * per, page * per + per).map((r, i) => ({ ...r, verdictLabel: VERDICT_LABEL[r.verdict], service, idx: page * per + i }));
    res.json({ rows: slice, total, page, pages: Math.ceil(total / per) || 1 });
  });

  api.get('/customers/:id/messages/:mid', (req, res) => {
    const m = emailStore.messages.get(req.params.mid);
    const a = emailStore.analysisFor(req.params.mid);
    if (!m || !a) return res.status(404).json({ error: 'not found' });
    res.json({ message: m, analysis: a, verdictLabel: VERDICT_LABEL[a.verdict] });
  });

  api.get('/customers/:id/quarantine', (req, res) => {
    const q = emailStore.quarantinedForTenant(req.params.id).map(a => {
      const m = emailStore.messages.get(a.messageId)!;
      return { id: m.id, from: m.fromAddress, to: m.to, subject: m.subject, verdict: a.verdict, verdictLabel: VERDICT_LABEL[a.verdict], at: m.receivedAt };
    });
    res.json({ rows: q, total: q.length });
  });

  api.post('/customers/:id/messages/:mid/release', (req, res) => {
    const m = emailStore.messages.get(req.params.mid);
    if (!m) return res.status(404).json({ error: 'not found' });
    const r = emailStore.createReleaseRequest(req.params.id, req.params.mid, 'admin');
    res.json({ ok: true, request: r });
  });

  api.get('/customers/:id/users', (req, res) => {
    const users = store.usersForTenant(req.params.id).map(u => ({ email: u.email, name: u.displayName, department: u.department, enabled: u.enabled }));
    res.json({ rows: users, total: users.length });
  });

  api.get('/customers/:id/policy', (req, res) => {
    res.json({ policy: policyFor(req.params.id)?.dispositions ?? DEFAULT_POLICY.dispositions });
  });

  return api;
}
