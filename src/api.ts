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
import { healthFor } from './connHealth';
import { persistScored } from './db/hydrate';
import { dbEnabled } from './db/db';
import { DEFAULT_POLICY, policyFor } from './emailsec/policy';
import { attachSession, requireAuth, requirePartner, requireCustomerAccess, sessionOf, blockReadOnlyWrites, requireTeamAdmin } from './auth/middleware';
import { getSettings, saveSettings } from './settings';
import { listTeam, saveTeamMember, deleteTeamMember } from './team';
import { hashPassword } from './auth/localAuth';
import { audit, listAudit, distinctAuditActions } from './audit';
import { portalLink, digestHtml, signPortalToken } from './quarantinePortal';
import { appToken } from './directory/graphProvider';
import { publicAiConfig, saveAiConfig } from './aiConfig';
import { testLlm } from './emailsec/llm';
import { getUsage } from './aiUsage';
import { reprocessTenant } from './emailsec/pipeline';
import { currentFolder } from './emailsec/mailActions';
import { listSenderIntel, setSenderOverride, baselineReason } from './emailsec/baseline';
import { geolocate, geoEnabled } from './emailsec/geo';
import { publicGeoConfig, saveGeoConfig } from './geoConfig';
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
    mode: c.mode, orderedAt: c.orderedAt, flags: c.flags, integrationModel: c.integrationModel,
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
  api.use(blockReadOnlyWrites);                      // read-only team members: GET only
  api.use('/customers/:id', requireCustomerAccess); // per-customer scope check

  // ---- Connection health (real-time status) ----
  api.get('/health/connections', requirePartner, (_req, res) => {
    const subsByCust = new Map<string, number>();
    for (const s of listSubscriptions()) subsByCust.set(s.customerId, (subsByCust.get(s.customerId) ?? 0) + 1);
    const rows = listCustomers().map(c => {
      const conn = getConnection(c.id);
      const mailboxes = store.usersForTenant(c.id).filter(u => u.enabled).length;
      const h = healthFor(c.id);
      return {
        id: c.id, name: c.name, connected: !!conn?.entraTenantId, mode: c.mode,
        mailboxes, subscriptions: subsByCust.get(c.id) ?? 0,
        lastWebhookAt: h.lastWebhookAt || null, lastSyncAt: h.lastSyncAt || null,
        realtime: h.realtime,
      };
    });
    res.json({ connections: rows });
  });

  // ---- Sender Intelligence (behavioral baseline) — partner admins only ----
  api.get('/customers/:id/sender-intel', requirePartner, requireTeamAdmin, (req, res) => {
    res.json({ senders: listSenderIntel(req.params.id) });
  });
  api.post('/customers/:id/sender-intel/override', requirePartner, requireTeamAdmin, async (req, res) => {
    try {
      const sender = String(req.body?.sender ?? ''); const value = req.body?.override;
      if (!sender || !['trusted', 'untrusted', 'reset'].includes(value)) return res.status(400).json({ error: 'sender and override (trusted|untrusted|reset) required' });
      await setSenderOverride(req.params.id, sender, value);
      logReq(req, 'sender.override', sender, value, req.params.id);
      res.json({ ok: true });
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });

  // ---- Audit log ----
  const logReq = (req: any, action: string, resource?: string, detail?: string, customerId?: string) => {
    const s = sessionOf(req);
    audit({ actorEmail: s?.email, role: s?.teamRole ?? s?.role, action, resource, detail, customerId });
  };
  api.get('/audit', requireAuth, (req, res) => {
    const s = sessionOf(req)!;
    const customerId = s.role === 'partner_admin' ? (String(req.query.customerId ?? '') || undefined) : s.customerId;
    const range = String(req.query.range ?? 'all');
    let from = 0; const now = Date.now();
    if (range === 'today') { const d = new Date(); d.setHours(0, 0, 0, 0); from = d.getTime(); }
    else if (range === '7d') from = now - 7 * 864e5;
    else if (range === '30d') from = now - 30 * 864e5;
    const entries = listAudit({
      q: String(req.query.q ?? '') || undefined,
      customerId,
      action: String(req.query.action ?? '') || undefined,
      resource: String(req.query.resource ?? '') || undefined,
      from,
      limit: 400,
    });
    res.json({ entries, actions: distinctAuditActions(customerId) });
  });

  // ---- Analytics (partner aggregate, or a single customer) ----
  api.get('/analytics', requireAuth, (req, res) => {
    const s = sessionOf(req)!;
    const scope = s.role === 'partner_admin' ? String(req.query.scope ?? 'all') : s.customerId!;
    const THREATS = ['phishing', 'malware', 'impersonation'];
    // date range
    const range = String(req.query.range ?? '30d');
    let from = 0;
    const now = Date.now();
    if (range === 'today') { const d = new Date(); d.setHours(0, 0, 0, 0); from = d.getTime(); }
    else if (range === '7d') from = now - 7 * 864e5;
    else if (range === '30d') from = now - 30 * 864e5;
    else if (range === 'last_month') { const d = new Date(); from = new Date(d.getFullYear(), d.getMonth() - 1, 1).getTime(); }
    const to = range === 'last_month' ? new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime() : now + 864e5;
    const msgs = [...emailStore.messages.values()].filter(m => (scope === 'all' || m.tenantId === scope) && (() => { const t = Date.parse(m.receivedAt || ''); return !from || (t >= from && t <= to); })());
    const verdicts: Record<string, number> = {};
    const dispositions: Record<string, number> = {};
    const byDay: Record<string, { total: number; threats: number }> = {};
    const threatSenders: Record<string, number> = {};
    const geo: Record<string, Record<string, number>> = {};
    const mailboxes: Record<string, Record<string, number>> = {};
    let processed = 0, threats = 0, quarantined = 0, clean = 0, msCaught = 0, spam = 0, policy = 0;
    for (const m of msgs) {
      const a = emailStore.analysisFor(m.id); if (!a) continue;
      processed++;
      verdicts[a.verdict] = (verdicts[a.verdict] ?? 0) + 1;
      dispositions[a.disposition] = (dispositions[a.disposition] ?? 0) + 1;
      if (a.verdict === 'clean') clean++;
      if (a.verdict === 'spam' || a.verdict === 'spam_likely') spam++;
      if (a.verdict === 'policy_infomail' || a.verdict === 'policy_geo') policy++;
      const isThreat = THREATS.includes(a.verdict);
      if (isThreat) { threats++; threatSenders[m.fromAddress] = (threatSenders[m.fromAddress] ?? 0) + 1; }
      if (a.disposition === 'quarantine' || a.disposition === 'remediated') quarantined++;
      if (m.msVerdict && m.msVerdict !== 'Not Spam') msCaught++;
      if (m.senderCountry) { (geo[m.senderCountry] ??= {})[a.verdict] = ((geo[m.senderCountry][a.verdict]) ?? 0) + 1; }
      if (m.direction === 'inbound' && m.to) { (mailboxes[m.to] ??= {})[a.verdict] = ((mailboxes[m.to][a.verdict]) ?? 0) + 1; }
      const day = (m.receivedAt || '').slice(0, 10);
      if (day) { (byDay[day] ??= { total: 0, threats: 0 }).total++; if (isThreat) byDay[day].threats++; }
    }
    const nonClean = processed - clean;
    const remediated = dispositions['remediated'] ?? 0;
    const sumBy = (by: Record<string, number>) => Object.values(by).reduce((s, n) => s + n, 0);
    const geoList = Object.entries(geo).map(([country, byVerdict]) => ({ country, count: sumBy(byVerdict), byVerdict })).sort((a, b) => b.count - a.count).slice(0, 10);
    const targetedMailboxes = Object.entries(mailboxes).map(([mailbox, byVerdict]) => ({ mailbox, count: sumBy(byVerdict), byVerdict })).sort((a, b) => b.count - a.count).slice(0, 10);
    const daysSaved = Math.round((nonClean * 20) / 86400); // ~20s saved per non-clean email

    // previous-period counts for trend deltas
    const windowLen = (from ? to - from : 30 * 864e5);
    const prevFrom = (from || now - 30 * 864e5) - windowLen, prevTo = from || now - 30 * 864e5;
    let pProcessed = 0, pClean = 0, pThreats = 0, pRemediated = 0;
    for (const m of [...emailStore.messages.values()]) {
      if (scope !== 'all' && m.tenantId !== scope) continue;
      const t = Date.parse(m.receivedAt || ''); if (!(t >= prevFrom && t < prevTo)) continue;
      const a = emailStore.analysisFor(m.id); if (!a) continue;
      pProcessed++; if (a.verdict === 'clean') pClean++;
      if (THREATS.includes(a.verdict)) pThreats++;
      if (a.disposition === 'remediated') pRemediated++;
    }
    const pct = (cur: number, prev: number) => prev === 0 ? (cur > 0 ? 100 : 0) : Math.round(((cur - prev) / prev) * 100);
    const deltas = { processed: pct(processed, pProcessed), clean: pct(clean, pClean), nonClean: pct(nonClean, pProcessed - pClean), threats: pct(threats, pThreats), remediated: pct(remediated, pRemediated) };

    // usage + pending releases (single-customer scope)
    const cust = scope !== 'all' ? getCustomer(scope) : undefined;
    const usage = cust ? {
      domains: new Set([cust.primaryDomain, ...(getConnection(scope)?.verifiedDomains ?? []), ...getSettings(scope).managedDomains]).size,
      mailboxes: store.usersForTenant(scope).length,
      licenses: cust.licenses,
    } : null;
    const pendingReleases = emailStore.releaseRequests.filter((r: any) => (scope === 'all' || r.customerId === scope) && r.status === 'pending').length;

    // partner-wide rollup (aggregate usage + customers by service)
    let partner: any = null;
    if (s.role === 'partner_admin' && scope === 'all') {
      const custs = listCustomers();
      let domains = 0, mailboxes = 0, licenses = 0;
      const byService = { 'BreakPhish 365': 0, 'BreakPhish Gateway': 0, 'BreakPhish Unified': 0 };
      for (const c of custs) {
        domains += new Set([c.primaryDomain, ...(getConnection(c.id)?.verifiedDomains ?? []), ...getSettings(c.id).managedDomains]).size;
        mailboxes += store.usersForTenant(c.id).length;
        licenses += c.licenses;
        const svc = c.integrationModel === 'gateway' ? 'BreakPhish Gateway' : c.integrationModel === 'unified' ? 'BreakPhish Unified' : 'BreakPhish 365';
        (byService as any)[svc]++;
      }
      partner = { totalCustomers: custs.length, byService, usage: { domains, mailboxes, licenses }, onTrial: 0 };
    }
    const timeline = Object.entries(byDay).sort(([a], [b]) => a < b ? -1 : 1).slice(-14).map(([day, v]) => ({ day, ...v }));
    const topSenders = Object.entries(threatSenders).sort(([, a], [, b]) => b - a).slice(0, 8).map(([sender, count]) => ({ sender, count }));
    // per-customer rollup (partner only)
    const perCustomer = s.role === 'partner_admin' && scope === 'all'
      ? listCustomers().map(c => {
          const cm = [...emailStore.messages.values()].filter(x => x.tenantId === c.id);
          let p = 0, t = 0, qd = 0;
          for (const x of cm) { const a = emailStore.analysisFor(x.id); if (!a) continue; p++; if (THREATS.includes(a.verdict)) t++; if (a.disposition === 'quarantine' || a.disposition === 'remediated') qd++; }
          return { id: c.id, name: c.name, processed: p, threats: t, quarantined: qd };
        })
      : [];
    res.json({
      scope, range, processed, threats, quarantined, clean, spam, policy,
      nonClean, remediated, daysSaved, msCaught, deltas, usage, pendingReleases, partner,
      cleanRate: processed ? Math.round((clean / processed) * 100) : 0,
      catchRate: processed ? Math.round((quarantined / processed) * 100) : 0,
      verdicts, dispositions, timeline, topSenders, perCustomer, geo: geoList, targetedMailboxes,
      generatedAt: new Date().toISOString(),
    });
  });

  // ---- AI provider (partner-wide) ----
  api.get('/ai/config', requirePartner, (_req, res) => res.json(publicAiConfig()));
  api.put('/ai/config', requirePartner, requireTeamAdmin, async (req, res) => {
    try {
      const { provider, apiKey, endpoint, model, azureDeployment, azureApiVersion } = req.body ?? {};
      await saveAiConfig({ provider, apiKey, endpoint, model, azureDeployment, azureApiVersion });
      logReq(req, 'ai.config.update', provider);
      res.json(publicAiConfig());
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.post('/ai/test', requirePartner, async (_req, res) => {
    const r = await testLlm();
    res.json(r);
  });
  api.get('/ai/usage', requirePartner, (_req, res) => res.json(getUsage()));

  // ---- Geolocation provider (partner-wide, for the transport-chain map) ----
  api.get('/geo/config', requirePartner, (_req, res) => res.json(publicGeoConfig()));
  api.put('/geo/config', requirePartner, requireTeamAdmin, async (req, res) => {
    try { await saveGeoConfig({ provider: req.body?.provider, dbPath: req.body?.dbPath }); logReq(req, 'geo.config.update', req.body?.provider); res.json(publicGeoConfig()); }
    catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.post('/geo/test', requirePartner, async (_req, res) => {
    if (!geoEnabled()) return res.json({ ok: false, error: 'No geolocation provider configured.' });
    try {
      const r = await geolocate(['8.8.8.8']); // Google DNS — a known, stable public IP
      const g = r['8.8.8.8'];
      if (!g) return res.json({ ok: false, error: 'Provider configured but returned no location (check the DB path or network).' });
      res.json({ ok: true, sample: g });
    } catch (e) { res.json({ ok: false, error: (e as Error).message }); }
  });
  // Minimal AI status for customers (just whether the AI tier is active — no config).
  api.get('/settings/ai-status', requireAuth, (_req, res) => res.json({ aiActive: publicAiConfig().active }));

  // ---- Team members (partner staff) ----
  const publicMember = (m: any) => ({ ...m, passwordHash: undefined, totpSecret: undefined });
  api.get('/team', requirePartner, (_req, res) => res.json({ members: listTeam().map(publicMember) }));
  api.post('/team', requirePartner, requireTeamAdmin, async (req, res) => {
    try {
      const { name, email, role, authType, mfaEnabled, password } = req.body ?? {};
      if (!name || !email) return res.status(400).json({ error: 'name and email are required' });
      if (authType === 'local' && (!password || String(password).length < 8)) return res.status(400).json({ error: 'local users need a password of at least 8 characters' });
      const passwordHash = authType === 'local' ? hashPassword(String(password)) : undefined;
      const m = await saveTeamMember({ name, email, role, authType, mfaEnabled: Boolean(mfaEnabled), passwordHash });
      logReq(req, 'team.create', email, `${authType} · ${role}`);
      res.status(201).json(publicMember(m));
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.put('/team/:id', requirePartner, requireTeamAdmin, async (req, res) => {
    try {
      const body = { ...req.body }; delete body.passwordHash; delete body.totpSecret; // never set these directly
      if (body.password) { if (String(body.password).length < 8) return res.status(400).json({ error: 'password too short' }); body.passwordHash = hashPassword(String(body.password)); delete body.password; }
      const m = await saveTeamMember({ ...body, id: req.params.id });
      res.json(publicMember(m));
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
  });
  api.delete('/team/:id', requirePartner, requireTeamAdmin, async (req, res) => { await deleteTeamMember(req.params.id); logReq(req, 'team.delete', req.params.id); res.json({ ok: true }); });

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
    try { const { own } = policyScopes(req); const r = await saveRule({ ...req.body, id: undefined, scope: own }); logReq(req, 'policy.rule.create', r.kind, (r.data.sender||'')); res.status(201).json(r); }
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
      logReq(req, 'settings.update', scope);
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
      logReq(req, 'customer.create', c.name, c.primaryDomain);
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

  // Re-score all of a customer's stored mail with the current rules (no Graph calls).
  api.post('/customers/:id/reprocess', requirePartner, async (req, res) => {
    try {
      const r = await reprocessTenant(req.params.id);
      logReq(req, 'mail.reprocess', req.params.id, `${r.changed}/${r.processed} changed`);
      res.json(r);
    } catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  // Set enforcement mode (partner only): passive (monitor) ↔ active (enforce).
  api.post('/customers/:id/mode', requirePartner, async (req, res) => {
    try {
      const mode = req.body?.mode === 'active' ? 'active' : 'passive';
      const c = await editCustomer(req.params.id, { mode });
      if (!c) return res.status(404).json({ error: 'not found' });
      logReq(req, 'customer.mode', req.params.id, mode);
      res.json({ ok: true, mode });
    } catch (e) { res.status(400).json({ error: (e as Error).message }); }
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
  api.delete('/customers/:id', requirePartner, requireTeamAdmin, async (req, res) => {
    try {
      const id = req.params.id;
      if (!getCustomer(id)) return res.status(404).json({ error: 'not found' });
      deleteConnection(id);
      await deleteCustomer(id);
      logReq(req, 'customer.delete', id);
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
    const domain = String(req.query.domain ?? '').toLowerCase();
    if (verdict) rows = rows.filter(r => r.verdict === verdict);
    if (direction) rows = rows.filter(r => r.direction === direction);
    if (status) rows = rows.filter(r => r.status === status);
    const lc = (s: any) => String(s ?? '').toLowerCase();
    const recips = (r: any) => (r.recipients?.length ? r.recipients : [r.to]).map(lc);
    if (from) rows = rows.filter(r => lc(r.from).includes(from));
    if (to) rows = rows.filter(r => recips(r).some((x: string) => x.includes(to)));
    // one search box: sender, recipient, subject, or body keywords
    if (q) rows = rows.filter(r => {
      const m = emailStore.messages.get(r.id);
      return lc(r.from).includes(q) || recips(r).some((x: string) => x.includes(q)) || lc(r.subject).includes(q) || lc(m?.bodyText).includes(q);
    });
    // filter by a verified domain (either side of the message)
    if (domain) rows = rows.filter(r => lc(r.from).endsWith('@' + domain) || lc(r.from).endsWith('.' + domain) || recips(r).some((x: string) => x.endsWith('@' + domain) || x.endsWith('.' + domain)));
    const total = rows.length;
    const slice = rows.slice(page * per, page * per + per).map((r, i) => ({ ...r, verdictLabel: VERDICT_LABEL[r.verdict], service, idx: page * per + i }));
    res.json({ rows: slice, total, page, pages: Math.ceil(total / per) || 1 });
  });

  api.get('/customers/:id/messages/:mid', async (req, res) => {
    const m = emailStore.messages.get(req.params.mid);
    const a = emailStore.analysisFor(req.params.mid);
    if (!m || !a) return res.status(404).json({ error: 'not found' });
    // geolocate transport hops for the map (fail-open; cached)
    let hops: any[] = m.transportHops ?? [];
    let geoEnabledFlag = false;
    if (geoEnabled() && hops.length) {
      try {
        const geo = await geolocate(hops.map(h => h.ip).filter(Boolean));
        hops = hops.map(h => ({ ...h, geo: geo[h.ip] ?? null }));
        geoEnabledFlag = true;
      } catch { /* fail open */ }
    }
    // Lightweight event log derived from what we know.
    const events = [
      { at: m.receivedAt, event: 'Content analysis' },
      { at: m.receivedAt, event: a.disposition === 'remediated' ? 'Remediated' : a.disposition === 'quarantine' ? 'Quarantined' : a.disposition === 'junk' ? 'Moved to Junk' : 'Delivered' },
    ];
    // Context = the leading risk-signal category, labeled.
    const top = (a.signals ?? []).slice().sort((x: any, y: any) => (y.weight ?? 0) - (x.weight ?? 0))[0];
    const CTX: Record<string, string> = { spam: 'Content - Spam', phishing: 'Content - Phishing', malware: 'Attachment - Malware', impersonation: 'Identity - Impersonation', policy_infomail: 'Content - Infomail', policy_geo: 'Origin - Geo', auth: 'Authentication', reputation: 'Sender Reputation', url: 'Content - URL', behavioral: 'Behavioral' };
    const context = a.verdict === 'clean' ? 'Clean' : (top ? (CTX[top.category] ?? top.category) : CTX[a.verdict] ?? '—');
    const rule = matchingRule(m.tenantId, m.fromAddress, m.to);
    const enrich = { queueId: m.id, senderIp: m.senderIp || '', country: m.senderCountry || '', msVerdict: m.msVerdict || '', context, rules: rule ? rule.label : '', senderIntel: baselineReason(m.tenantId, m.fromAddress), spamScore: Math.round(((a.signals ?? []).reduce((s: number, x: any) => s + (x.weight ?? 0), 0) / 14) * 100) / 100 };
    // Live lookup: where is this message right now in the mailbox?
    let currentFolderName: string | null = null;
    let folderNote = '';
    let folderChecked = false;
    const connF = getConnection(m.tenantId);
    const mailbox = (m as any).mailboxUserId || m.to;
    if (connF?.entraTenantId && mailbox && m.direction !== 'outbound') {
      folderChecked = true;
      try { const r = await currentFolder(connF.entraTenantId, mailbox, m.internetMessageId ?? '', m.id); currentFolderName = r.folder; folderNote = r.note ?? ''; }
      catch (e) { folderNote = (e as Error).message; }
    }
    // All mailboxes this logical message was delivered to (distribution groups).
    const recipients = [...new Set(
      [...emailStore.messages.values()]
        .filter(x => x.tenantId === m.tenantId && x.internetMessageId === m.internetMessageId && x.to)
        .map(x => x.to!)
    )];
    res.json({ message: { ...m, transportHops: hops, recipients, toHeader: (m as any).toHeader, currentFolder: currentFolderName, folderChecked, folderNote }, analysis: a, verdictLabel: VERDICT_LABEL[a.verdict], events, enrich, geoEnabled: geoEnabledFlag });
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
      const user = store.usersForTenant(id).find(u => u.email.toLowerCase() === String(m.to ?? "").toLowerCase());
      if (conn?.entraTenantId && user) await applyDisposition(conn.entraTenantId, user.externalId, { graphId: mid, internetMessageId: m.internetMessageId }, 'remediated');
      // optional block rule
      const option = String(req.body?.option ?? 'plain');
      if (option === 'block_recipient' || option === 'block_org') {
        await saveRule({ scope: option === 'block_org' ? 'partner' : id, kind: 'block', data: { sender: m.fromAddress, comment: `Blocked via remediation (${m.subject})` } });
      }
      logReq(req, 'mail.remediate', m.subject, `from ${m.fromAddress}` + (option !== 'plain' ? ` (+${option})` : ''), id);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  // Quarantine digest + end-user portal access
  api.get('/customers/:id/users/:email/portal-link', requireAuth, requireCustomerAccess, (req, res) => {
    res.json({ link: portalLink(req.params.id, req.params.email) });
  });
  api.post('/customers/:id/digest/preview', requireAuth, requireCustomerAccess, (req, res) => {
    const email = String(req.body?.email ?? '');
    if (!email) return res.status(400).json({ error: 'email required' });
    res.json({ html: digestHtml(req.params.id, email, signPortalToken(req.params.id, email)) });
  });
  // Send the digest to a user via Graph sendMail (requires Mail.Send app permission).
  api.post('/customers/:id/digest/send', requireAuth, requireCustomerAccess, async (req, res) => {
    try {
      const id = req.params.id; const email = String(req.body?.email ?? '');
      if (!email) return res.status(400).json({ error: 'email required' });
      const conn = getConnection(id);
      if (!conn?.entraTenantId) return res.status(400).json({ error: 'customer not connected' });
      const html = digestHtml(id, email, signPortalToken(id, email));
      const token = await appToken(conn.entraTenantId);
      const r = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(email)}/sendMail`, {
        method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ message: { subject: 'Your Quarantine Digest', body: { contentType: 'HTML', content: html }, toRecipients: [{ emailAddress: { address: email } }] }, saveToSentItems: false }),
      });
      if (!r.ok) {
        const txt = await r.text();
        return res.status(502).json({ error: `sendMail failed (${r.status}). This usually means the Mail.Send application permission hasn't been granted in Azure.`, detail: txt.slice(0, 300) });
      }
      logReq(req, 'digest.send', email, undefined, id);
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
    const user = store.usersForTenant(id).find(u => u.email.toLowerCase() === String(m.to ?? "").toLowerCase());
    return { conn, user };
  }

  // Release / deliver a held message back to the inbox.
  // option: 'plain' | 'allow_recipient' | 'allow_org'
  api.post('/customers/:id/messages/:mid/release', requireAuth, requireCustomerAccess, async (req, res) => {
    try {
      const id = req.params.id, mid = req.params.mid;
      const m = emailStore.messages.get(mid); const a = emailStore.analysisFor(mid);
      if (!m || !a) return res.status(404).json({ error: 'not found' });
      a.disposition = 'deliver'; a.remediated = false; a.releasedManually = true;
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
      logReq(req, 'mail.release', m.subject, `from ${m.fromAddress}` + (option!=='plain'?` (+${option})`:''), id);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: (e as Error).message }); }
  });

  // Report a false positive: deliver the message AND allow-list the sender so it
  // never false-flags again. scope: 'recipient' (this customer) | 'org' (partner-wide)
  api.post('/customers/:id/messages/:mid/false-positive', requireAuth, requireCustomerAccess, async (req, res) => {
    try {
      const id = req.params.id, mid = req.params.mid;
      const m = emailStore.messages.get(mid); const a = emailStore.analysisFor(mid);
      if (!m || !a) return res.status(404).json({ error: 'not found' });
      // deliver (release)
      a.disposition = 'deliver'; a.remediated = false; a.releasedManually = true;
      emailStore.saveAnalysis(a); await persistScored(m, a);
      emailStore.markReleased(m.internetMessageId);
      if (m.internetMessageId) { try { await (await import('./db/persist')).markReleasedRow(m.internetMessageId, id); } catch {} }
      const { conn, user } = mailboxFor(id, m);
      if (conn?.entraTenantId && user) { try { await (await import('./emailsec/mailActions')).makeMailActions().moveToInbox(conn.entraTenantId, user.externalId, { graphId: mid, internetMessageId: m.internetMessageId }); } catch (e) { console.error('[fp] move failed', (e as Error).message); } }
      // allow-list the sender
      const scope = (req.body?.scope ?? req.body?.option) === 'org' ? 'partner' : id;
      await saveRule({ scope, kind: 'allow', data: { sender: m.fromAddress, comment: `Allowed — reported false positive (${m.subject})` } });
      logReq(req, 'mail.false_positive', m.subject, `from ${m.fromAddress} (allow ${scope === 'partner' ? 'org' : 'recipient'})`, id);
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
      logReq(req, 'mail.delete', m.subject, `from ${m.fromAddress}` + (option!=='plain'?` (+${option})`:''), id);
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
