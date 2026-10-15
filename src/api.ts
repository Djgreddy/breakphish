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
import { applyDisposition } from './emailsec/mailActions';
import { subscribeTenant, listSubscriptions } from './emailsec/subscriptions';
import { persistScored } from './db/hydrate';
import { dbEnabled } from './db/db';
import { DEFAULT_POLICY, policyFor } from './emailsec/policy';
import { attachSession, requireAuth, requirePartner, requireCustomerAccess, sessionOf } from './auth/middleware';
import { getSettings, saveSettings } from './settings';
import { listTeam, saveTeamMember, deleteTeamMember } from './team';
import { listTemplates, saveTemplate, deleteTemplate, listRules, saveRule, deleteRule, ruleTargetsAll, isDisabledFor, setRuleOverride, matchingRule } from './policy';
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
    realtime: listSubscriptions().filter(s => s.customerId === c.id).length,
    threats: d ? d.threats : 0, processed: d ? d.processed : 0,
  };
}

export function buildApi() {
  const api = express.Router();
  api.use(express.json({ limit: '4mb' })); // settings can include a base64 logo
  api.use(attachSession);
  api.use(requireAuth);                              // every API call needs a session
  api.use('/customers/:id', requireCustomerAccess); // per-customer scope check

  // ---- Team members (partner staff) ----
  api.get('/team', requirePartner, (_req, res) => res.json({ members: listTeam() }));
  api.post('/team', requirePartner, async (req, res) => {
    try {
      const { name, email, role, authType, mfaEnabled } = req.body ?? {};
      if (!name || !email) return res.status(400).json({ error: 'name and email are required' });
      const m = await saveTeamMember({ name, email, role, authType, mfaEnabled: Boolean(mfaEnabled) });
      res.status(201).json(m);
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.put('/team/:id', requirePartner, async (req, res) => {
    try { const m = await saveTeamMember({ ...req.body, id: req.params.id }); res.json(m); }
    catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.delete('/team/:id', requirePartner, async (req, res) => { await deleteTeamMember(req.params.id); res.json({ ok: true }); });

  // ---- Policy (templates + rules) ----
  // A partner sees/edits partner (global) scope. A customer sees global + its own,
  // and may only edit its own.
  function policyScopes(req: any): { scopes: string[]; own: string } {
    const s = sessionOf(req)!;
    if (s.role === 'partner_admin') return { scopes: ['partner'], own: 'partner' };
    return { scopes: ['partner', s.customerId!], own: s.customerId! };
  }
  api.get('/policy/templates', requireAuth, (req, res) => {
    const { scopes } = policyScopes(req);
    res.json({ templates: listTemplates(scopes).map(t => ({ ...t, editable: t.scope === policyScopes(req).own })) });
  });
  api.post('/policy/templates', requireAuth, async (req, res) => {
    try { const { own } = policyScopes(req); const t = await saveTemplate({ ...req.body, id: undefined, scope: own }); res.status(201).json(t); }
    catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.put('/policy/templates/:id', requireAuth, async (req, res) => {
    try {
      const { own } = policyScopes(req);
      const t = await saveTemplate({ ...req.body, id: req.params.id, scope: own });
      res.json(t);
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.delete('/policy/templates/:id', requireAuth, async (req, res) => {
    await deleteTemplate(req.params.id); res.json({ ok: true });
  });

  api.get('/policy/rules', requireAuth, (req, res) => {
    const s = sessionOf(req)!;
    const { scopes, own } = policyScopes(req);
    const kind = String(req.query.kind ?? '') || undefined;
    let rules = listRules(scopes, kind);
    // For a customer, only show global rules that actually target them.
    if (s.role !== 'partner_admin') {
      rules = rules.filter(r => r.scope === own || ruleTargetsAll(r) || (r.data.customerIds ?? []).includes(own));
    }
    res.json({ rules: rules.map(r => {
      const global = r.scope === 'partner';
      const appliesTo = ruleTargetsAll(r) ? 'All customers' : `${(r.data.customerIds ?? []).length} customer(s)`;
      const disabledForMe = global && s.role !== 'partner_admin' ? isDisabledFor(own, r.id) : false;
      return { ...r, editable: r.scope === own, global, appliesTo, disabledForMe };
    }) });
  });

  // A customer opts out of (or back into) a global rule, just for themselves.
  api.post('/policy/rules/:id/override', requireAuth, async (req, res) => {
    const s = sessionOf(req)!;
    if (s.role === 'partner_admin' || !s.customerId) return res.status(400).json({ error: 'only a customer can override a global rule' });
    await setRuleOverride(s.customerId, req.params.id, Boolean(req.body?.disabled));
    res.json({ ok: true });
  });
  api.post('/policy/rules', requireAuth, async (req, res) => {
    try { const { own } = policyScopes(req); const r = await saveRule({ ...req.body, id: undefined, scope: own }); res.status(201).json(r); }
    catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.put('/policy/rules/:id', requireAuth, async (req, res) => {
    try { const { own } = policyScopes(req); const r = await saveRule({ ...req.body, id: req.params.id, scope: own }); res.json(r); }
    catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.delete('/policy/rules/:id', requireAuth, async (req, res) => {
    await deleteRule(req.params.id); res.json({ ok: true });
  });

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
      // Keep a customer's display name in sync with its General company name.
      const name = req.body?.settings?.general?.companyName;
      if (scope !== 'partner' && name && getCustomer(scope)) await editCustomer(scope, { name });
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
        try { await subscribeTenant(id); } catch (e) { console.error('[resync] subscribe failed', (e as Error).message); }
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
    const range = String(req.query.range ?? 'all');
    let rows = liveTracker(req.params.id);
    // date range
    if (range !== 'all') {
      const now = Date.now();
      let from = 0, to = now;
      if (range === 'today') { const d = new Date(); d.setHours(0,0,0,0); from = d.getTime(); }
      else if (range === '7d') from = now - 7 * 864e5;
      else if (range === '30d') from = now - 30 * 864e5;
      else if (range === 'custom') { from = Date.parse(String(req.query.dfrom ?? '')) || 0; to = (Date.parse(String(req.query.dto ?? '')) + 864e5) || now; }
      rows = rows.filter(r => { const t = Date.parse(r.at); return t >= from && t <= to; });
    }
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
    // Lightweight event log derived from what we know.
    const events = [
      { at: m.receivedAt, event: 'Content analysis' },
      { at: m.receivedAt, event: a.disposition === 'remediated' ? 'Remediated' : a.disposition === 'quarantine' ? 'Quarantined' : a.disposition === 'junk' ? 'Moved to Junk' : 'Delivered' },
    ];
    // Context = the leading risk-signal category, labeled.
    const top = (a.signals ?? []).slice().sort((x: any, y: any) => (y.weight ?? 0) - (x.weight ?? 0))[0];
    const CTX: Record<string, string> = { spam: 'Content - Spam', phishing: 'Content - Phishing', malware: 'Attachment - Malware', impersonation: 'Identity - Impersonation', policy_infomail: 'Content - Infomail', policy_geo: 'Origin - Geo', auth: 'Authentication', reputation: 'Sender Reputation', url: 'Content - URL', behavioral: 'Behavioral' };
    const context = a.verdict === 'clean' ? 'Clean' : (top ? (CTX[top.category] ?? top.category) : CTX[a.verdict] ?? '—');
    const rule = matchingRule(m.tenantId, m.fromAddress);
    const enrich = { queueId: m.id, senderIp: m.senderIp || '', country: m.senderCountry || '', msVerdict: m.msVerdict || '', context, rules: rule ? rule.label : '', spamScore: Math.round(((a.signals ?? []).reduce((s: number, x: any) => s + (x.weight ?? 0), 0) / 14) * 100) / 100 };
    res.json({ message: m, analysis: a, verdictLabel: VERDICT_LABEL[a.verdict], events, enrich });
  });

  // Remediate a delivered message now: move it to quarantine and mark it.
  // option: 'plain' | 'block_recipient' | 'block_org'
  api.post('/customers/:id/messages/:mid/remediate', requireAuth, requireCustomerAccess, async (req, res) => {
    try {
      const id = req.params.id, mid = req.params.mid;
      const m = emailStore.messages.get(mid); const a = emailStore.analysisFor(mid);
      if (!m || !a) return res.status(404).json({ error: 'not found' });
      // flip disposition to remediated + persist
      a.disposition = 'remediated'; a.remediated = true;
      emailStore.saveAnalysis(a);
      await persistScored(m, a);
      // act on the mailbox (graph mode) — find the recipient mailbox id
      const conn = getConnection(id);
      const user = store.usersForTenant(id).find(u => u.email.toLowerCase() === m.to.toLowerCase());
      if (conn?.entraTenantId && user) await applyDisposition(conn.entraTenantId, user.externalId, { graphId: mid, internetMessageId: m.internetMessageId }, 'remediated');
      // optional block rule
      const option = String(req.body?.option ?? 'plain');
      if (option === 'block_recipient' || option === 'block_org') {
        await saveRule({ scope: option === 'block_org' ? 'partner' : id, kind: 'block', data: { sender: m.fromAddress, comment: `Blocked via remediation (${m.subject})` } });
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  api.get('/customers/:id/quarantine', (req, res) => {
    const q = emailStore.quarantinedForTenant(req.params.id).map(a => {
      const m = emailStore.messages.get(a.messageId)!;
      return { id: m.id, from: m.fromAddress, to: m.to, subject: m.subject, verdict: a.verdict, verdictLabel: VERDICT_LABEL[a.verdict], at: m.receivedAt };
    });
    res.json({ rows: q, total: q.length });
  });

  // Shared helper: find the recipient mailbox + connected tenant for a message.
  function mailboxFor(id: string, m: any) {
    const conn = getConnection(id);
    const user = store.usersForTenant(id).find(u => u.email.toLowerCase() === m.to.toLowerCase());
    return { conn, user };
  }

  // Release / deliver a held message back to the inbox.
  // option: 'plain' | 'allow_recipient' | 'allow_org'
  api.post('/customers/:id/messages/:mid/release', requireAuth, requireCustomerAccess, async (req, res) => {
    try {
      const id = req.params.id, mid = req.params.mid;
      const m = emailStore.messages.get(mid); const a = emailStore.analysisFor(mid);
      if (!m || !a) return res.status(404).json({ error: 'not found' });
      a.disposition = 'deliver'; a.remediated = false;
      emailStore.saveAnalysis(a); await persistScored(m, a);
      // Pin as released so a webhook firing after the move-to-inbox won't re-quarantine it.
      emailStore.markReleased(m.internetMessageId);
      if (m.internetMessageId) { try { await (await import('./db/persist')).markReleasedRow(m.internetMessageId, id); } catch {} }
      const { conn, user } = mailboxFor(id, m);
      if (conn?.entraTenantId && user) { try { await (await import('./emailsec/mailActions')).makeMailActions().moveToInbox(conn.entraTenantId, user.externalId, { graphId: mid, internetMessageId: m.internetMessageId }); } catch (e) { console.error('[release] move failed', (e as Error).message); } }
      const option = String(req.body?.option ?? 'plain');
      if (option === 'allow_recipient' || option === 'allow_org') {
        await saveRule({ scope: option === 'allow_org' ? 'partner' : id, kind: 'allow', data: { sender: m.fromAddress, comment: `Allowed via release (${m.subject})` } });
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  // Delete a held message. option: 'plain' | 'block_recipient' | 'block_org'
  api.post('/customers/:id/messages/:mid/delete', requireAuth, requireCustomerAccess, async (req, res) => {
    try {
      const id = req.params.id, mid = req.params.mid;
      const m = emailStore.messages.get(mid); const a = emailStore.analysisFor(mid);
      if (!m || !a) return res.status(404).json({ error: 'not found' });
      const { conn, user } = mailboxFor(id, m);
      if (conn?.entraTenantId && user) { try { await (await import('./emailsec/mailActions')).makeMailActions().moveToDeleted(conn.entraTenantId, user.externalId, { graphId: mid, internetMessageId: m.internetMessageId }); } catch (e) { console.error('[delete] move failed', (e as Error).message); } }
      const option = String(req.body?.option ?? 'plain');
      if (option === 'block_recipient' || option === 'block_org') {
        await saveRule({ scope: option === 'block_org' ? 'partner' : id, kind: 'block', data: { sender: m.fromAddress, comment: `Blocked via delete (${m.subject})` } });
      }
      // remove from the local store so it leaves the quarantine list
      emailStore.messages.delete(mid); emailStore.analyses.delete(mid);
      if (dbEnabled()) { await import('./db/db').then(d => d.q('delete from messages where id=$1', [mid])); }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  // Download the stored message as a simple .eml-style text.
  api.get('/customers/:id/messages/:mid/download', requireAuth, requireCustomerAccess, (req, res) => {
    const m = emailStore.messages.get(req.params.mid);
    if (!m) return res.status(404).json({ error: 'not found' });
    const eml = `From: ${m.fromDisplay} <${m.fromAddress}>\nTo: ${m.to}\nSubject: ${m.subject}\nDate: ${m.receivedAt}\n\n${m.bodyText ?? ''}`;
    res.set('content-type', 'message/rfc822').set('content-disposition', `attachment; filename="message.eml"`).send(eml);
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
