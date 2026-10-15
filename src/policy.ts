// Policy templates + rules, scoped to the partner (global) or a customer.
//
// Resolution for enforcement (what the pipeline asks for):
//   - active template = the customer's own default template, else the partner's
//     default template, else the built-in baseline.
//   - allow/block lists: the customer's rules are checked first (customer wins),
//     then the partner's global rules.
//
// Managed now; enforced for: per-verdict actions, auth-fail (DMARC/SPF),
// executable-attachment action, and allow/block lists. DLP / link-rewrite / geo
// are stored but noted as follow-ups.

import { randomUUID } from 'node:crypto';
import { dbEnabled, q } from './db/db';

export type Action = 'deliver' | 'junk' | 'junk_banner' | 'quarantine';
export type AuthAction = 'no_action' | 'quarantine' | 'reject' | 'sender_dmarc_policy';

// Template verdict keys as shown in the editor.
export const TEMPLATE_VERDICTS = ['Clean','Impersonation','Infomail','Malware','Phishing','Spam-Definite','Spam-High','Spam-Likely'] as const;

export interface PolicyTemplateData {
  verdictActions: Record<string, Action>;
  authActions: { dmarcFail: AuthAction; spfFail: AuthAction; spfNone: AuthAction };
  attachments: { types: string[]; action: Action };
  geo: { countries: string[]; action: Action };
  advanced: { coldOutreach: boolean; zeroTrust: boolean; spamSensitivity: string };
}
export interface PolicyTemplate {
  id: string; scope: string; name: string; comment: string; deployment: string;
  data: PolicyTemplateData; isDefault: boolean; createdBy: string; createdAt: string;
}
export interface PolicyRule {
  id: string; scope: string; kind: string; enabled: boolean; createdBy: string; createdAt: string;
  data: { comment?: string; senders?: string[]; ip?: string; action?: string; appliedTo?: string; preference?: string; [k: string]: any };
}

export const DEFAULT_TEMPLATE_DATA: PolicyTemplateData = {
  verdictActions: {
    'Clean': 'deliver', 'Impersonation': 'junk_banner', 'Infomail': 'junk', 'Malware': 'quarantine',
    'Phishing': 'quarantine', 'Spam-Definite': 'junk', 'Spam-High': 'junk', 'Spam-Likely': 'junk',
  },
  authActions: { dmarcFail: 'sender_dmarc_policy', spfFail: 'reject', spfNone: 'no_action' },
  attachments: { types: ['Executable'], action: 'quarantine' },
  geo: { countries: [], action: 'quarantine' },
  advanced: { coldOutreach: false, zeroTrust: false, spamSensitivity: 'Medium' },
};

const templates = new Map<string, PolicyTemplate>();
const rules = new Map<string, PolicyRule>();
// customer opt-out of a global rule: key `${customerId}:${ruleId}` -> disabled
const overrides = new Map<string, boolean>();
const ovKey = (c: string, r: string) => `${c}:${r}`;

export function isDisabledFor(customerId: string, ruleId: string): boolean { return overrides.get(ovKey(customerId, ruleId)) === true; }
export async function setRuleOverride(customerId: string, ruleId: string, disabled: boolean): Promise<void> {
  overrides.set(ovKey(customerId, ruleId), disabled);
  if (dbEnabled()) await q(`insert into policy_rule_overrides (customer_id,rule_id,disabled) values ($1,$2,$3) on conflict (customer_id,rule_id) do update set disabled=excluded.disabled`, [customerId, ruleId, disabled]);
}

// Which customers a global rule targets: 'all' or a specific id list.
export function ruleTargetsAll(r: PolicyRule): boolean { return r.data.applyToAll !== false && !(r.data.customerIds && r.data.customerIds.length); }
function ruleTargetsCustomer(r: PolicyRule, customerId: string): boolean {
  return ruleTargetsAll(r) || (r.data.customerIds ?? []).includes(customerId);
}
// Does this rule actively apply to a given tenant right now?
// The allow/block rule (if any) that governs a given sender for a tenant — for display.
export function matchingRule(tenantId: string, fromAddress: string): { kind: string; label: string } | null {
  const active = [...rules.values()].filter(r => ruleAppliesTo(r, tenantId));
  const allow = active.find(r => r.kind === 'allow' && matchesSender(r, fromAddress));
  if (allow) return { kind: 'allow', label: `Allow | ${(allow.data.sender ?? (allow.data.senders ?? []).join(','))}` };
  const block = active.find(r => r.kind === 'block' && matchesSender(r, fromAddress));
  if (block) return { kind: 'block', label: `Block | ${(block.data.sender ?? (block.data.senders ?? []).join(','))}` };
  return null;
}

export function ruleAppliesTo(r: PolicyRule, tenantId: string): boolean {
  if (!r.enabled) return false;
  if (r.scope === tenantId) return true;                 // the customer's own rule
  if (r.scope === 'partner') return ruleTargetsCustomer(r, tenantId) && !isDisabledFor(tenantId, r.id); // global, targeted, not opted-out
  return false;
}

// scoring verdict -> template verdict key
const VERDICT_KEY: Record<string, string> = {
  clean: 'Clean', impersonation: 'Impersonation', policy_infomail: 'Infomail',
  malware: 'Malware', phishing: 'Phishing', spam: 'Spam-Definite', spam_likely: 'Spam-Likely',
};

const rank: Record<Action, number> = { deliver: 0, junk: 1, junk_banner: 1, quarantine: 2 };
const stricter = (a: Action, b: Action): Action => (rank[a] >= rank[b] ? a : b);
// Disposition layer only knows deliver|junk|quarantine; banner is a follow-up.
const toDisposition = (a: Action): 'deliver' | 'junk' | 'quarantine' => (a === 'junk_banner' ? 'junk' : a);

/* ---------------- CRUD ---------------- */
export function listTemplates(scopes: string[]): PolicyTemplate[] {
  return [...templates.values()].filter(t => scopes.includes(t.scope)).sort((a, b) => a.createdAt < b.createdAt ? -1 : 1);
}
export function getTemplate(id: string) { return templates.get(id); }

export async function saveTemplate(input: Partial<PolicyTemplate> & { scope: string; name: string }): Promise<PolicyTemplate> {
  const existing = input.id ? templates.get(input.id) : undefined;
  const t: PolicyTemplate = {
    id: input.id ?? randomUUID(),
    scope: input.scope,
    name: input.name,
    comment: input.comment ?? existing?.comment ?? '',
    deployment: input.deployment ?? existing?.deployment ?? 'BreakPhish 365',
    data: { ...DEFAULT_TEMPLATE_DATA, ...(existing?.data ?? {}), ...(input.data ?? {}) },
    isDefault: input.isDefault ?? existing?.isDefault ?? false,
    createdBy: existing?.createdBy ?? input.createdBy ?? 'partner',
    createdAt: existing?.createdAt ?? new Date().toISOString(),
  };
  // Only one default per scope.
  if (t.isDefault) for (const o of templates.values()) if (o.scope === t.scope && o.id !== t.id) o.isDefault = false;
  templates.set(t.id, t);
  if (dbEnabled()) {
    for (const o of templates.values()) if (o.scope === t.scope) await persistTemplate(o);
  }
  return t;
}
export async function deleteTemplate(id: string): Promise<void> {
  templates.delete(id);
  if (dbEnabled()) await q('delete from policy_templates where id=$1', [id]);
}

export function listRules(scopes: string[], kind?: string): PolicyRule[] {
  return [...rules.values()].filter(r => scopes.includes(r.scope) && (!kind || r.kind === kind));
}
export async function saveRule(input: Partial<PolicyRule> & { scope: string; kind: string }): Promise<PolicyRule> {
  const existing = input.id ? rules.get(input.id) : undefined;
  const data = { ...(existing?.data ?? {}), ...(input.data ?? {}) };
  // Global rules default to "all customers" unless a subset is chosen.
  if (input.scope === 'partner' && data.applyToAll === undefined && !(data.customerIds && data.customerIds.length)) data.applyToAll = true;
  // An explicit top-level `enabled` wins; otherwise mirror the rule's `active`
  // flag (so toggling Active in the editor actually disables enforcement).
  const enabled = input.enabled ?? (data.active !== undefined ? data.active !== false : existing?.enabled ?? true);
  const r: PolicyRule = {
    id: input.id ?? randomUUID(), scope: input.scope, kind: input.kind,
    data,
    enabled,
    createdBy: existing?.createdBy ?? input.createdBy ?? 'partner',
    createdAt: existing?.createdAt ?? new Date().toISOString(),
  };
  rules.set(r.id, r);
  if (dbEnabled()) await persistRule(r);
  return r;
}
export async function deleteRule(id: string): Promise<void> {
  rules.delete(id);
  if (dbEnabled()) await q('delete from policy_rules where id=$1', [id]);
}

/* ---------------- resolution + enforcement ---------------- */
function defaultTemplateFor(scope: string): PolicyTemplate | undefined {
  return [...templates.values()].find(t => t.scope === scope && t.isDefault);
}
export function resolveTemplate(tenantId: string): PolicyTemplateData {
  return (defaultTemplateFor(tenantId) ?? defaultTemplateFor('partner'))?.data ?? DEFAULT_TEMPLATE_DATA;
}

function matchesSender(rule: PolicyRule, fromAddress: string): boolean {
  const dom = fromAddress.split('@')[1] ?? '';
  const list = [...(rule.data.senders ?? []), ...(rule.data.sender ? [rule.data.sender] : [])];
  return list.some(s => {
    s = String(s).toLowerCase().trim(); if (!s) return false;
    const bare = s.startsWith('*.') ? s.slice(2) : s;        // *.name.tld
    return fromAddress === s || dom === bare || dom.endsWith('.' + bare) || s === '@' + dom;
  });
}
// Allow wins over block. Only rules that actively apply to this tenant count
// (enabled, targeted to the customer, and not opted-out by them).
function allowBlock(tenantId: string, fromAddress: string): 'allow' | 'block' | null {
  const active = [...rules.values()].filter(r => ruleAppliesTo(r, tenantId));
  if (active.some(r => r.kind === 'allow' && matchesSender(r, fromAddress))) return 'allow';
  if (active.some(r => r.kind === 'block' && matchesSender(r, fromAddress))) return 'block';
  return null;
}

const EXEC_EXT = ['.exe','.zip','.iso','.js','.scr','.bat','.cmd','.msi'];

function wildMatch(pattern: string, text: string): boolean {
  if (!pattern) return false;
  if (pattern.includes('*')) {
    const re = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
    return re.test(text);
  }
  return text.toLowerCase().includes(pattern.toLowerCase());
}
const DLP_PATTERNS: Record<string, RegExp> = {
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  credit_card: /\b(?:\d[ -]*?){13,16}\b/,
  iban: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/,
};
// Outbound DLP: does any active DLP rule match this message?
export function dlpMatch(tenantId: string, msg: { subject?: string; bodyText?: string; urls?: string[] }): PolicyRule | null {
  for (const r of rules.values()) {
    if (r.kind !== 'dlp' || !ruleAppliesTo(r, tenantId)) continue;
    const d = r.data;
    const subj = (d.subjects ?? []).some((p: string) => wildMatch(p, msg.subject ?? ''));
    const url = (d.urls ?? []).some((p: string) => (msg.urls ?? []).some(u => wildMatch(p, u)));
    const body = (d.bodyRules ?? []).some((p: string) => wildMatch(p, msg.bodyText ?? ''));
    let pat = false;
    if (d.dlpPattern && DLP_PATTERNS[d.dlpPattern]) pat = DLP_PATTERNS[d.dlpPattern].test(msg.bodyText ?? '');
    if (subj || url || body || pat) return r;
  }
  return null;
}
export function hasActiveLinkRewrite(tenantId: string): boolean {
  return [...rules.values()].some(r => r.kind === 'link_rewrite' && ruleAppliesTo(r, tenantId) && r.data.active !== false);
}

// Decide the disposition for a scored message under the active policy.
export function dispositionFor(
  tenantId: string, verdict: string,
  message: { auth: { spf: string; dkim: string; dmarc: string }; attachments?: { filename: string }[]; fromAddress: string },
): 'deliver' | 'junk' | 'quarantine' {
  // 1. allow/block overrides everything
  const ab = allowBlock(tenantId, message.fromAddress);
  if (ab === 'allow') return 'deliver';
  if (ab === 'block') return 'quarantine';

  const tpl = resolveTemplate(tenantId);

  // 2. base action from verdict
  let act: Action;
  if (verdict === 'policy_geo') act = tpl.geo.action;
  else act = tpl.verdictActions[VERDICT_KEY[verdict] ?? 'Clean'] ?? 'deliver';

  // 3. auth-fail override (stricter wins)
  if (message.auth.dmarc === 'fail' && (tpl.authActions.dmarcFail === 'reject' || tpl.authActions.dmarcFail === 'quarantine')) act = stricter(act, 'quarantine');
  if (message.auth.spf === 'fail' && (tpl.authActions.spfFail === 'reject' || tpl.authActions.spfFail === 'quarantine')) act = stricter(act, 'quarantine');

  // 4. executable attachment override
  if (tpl.attachments.types.includes('Executable') && (message.attachments ?? []).some(a => EXEC_EXT.includes((a.filename.slice(a.filename.lastIndexOf('.')) || '').toLowerCase())))
    act = stricter(act, tpl.attachments.action);

  return toDisposition(act);
}

/* ---------------- persistence ---------------- */
async function persistTemplate(t: PolicyTemplate) {
  await q(
    `insert into policy_templates (id,scope,name,comment,deployment,data,is_default,created_by,created_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     on conflict (id) do update set name=excluded.name, comment=excluded.comment, deployment=excluded.deployment,
       data=excluded.data, is_default=excluded.is_default`,
    [t.id, t.scope, t.name, t.comment, t.deployment, JSON.stringify(t.data), t.isDefault, t.createdBy, t.createdAt],
  );
}
async function persistRule(r: PolicyRule) {
  await q(
    `insert into policy_rules (id,scope,kind,data,enabled,created_by,created_at)
     values ($1,$2,$3,$4,$5,$6,$7)
     on conflict (id) do update set data=excluded.data, enabled=excluded.enabled`,
    [r.id, r.scope, r.kind, JSON.stringify(r.data), r.enabled, r.createdBy, r.createdAt],
  );
}

export async function hydratePolicy(): Promise<{ templates: number; rules: number }> {
  if (!dbEnabled()) { seedBaseTemplates(); return { templates: templates.size, rules: 0 }; }
  const ts = await q<any>('select * from policy_templates');
  for (const r of ts) templates.set(r.id, { id: r.id, scope: r.scope, name: r.name, comment: r.comment ?? '', deployment: r.deployment ?? '', data: { ...DEFAULT_TEMPLATE_DATA, ...(r.data ?? {}) }, isDefault: r.is_default, createdBy: r.created_by ?? '', createdAt: (r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at) });
  const rs = await q<any>('select * from policy_rules');
  for (const r of rs) rules.set(r.id, { id: r.id, scope: r.scope, kind: r.kind, data: r.data ?? {}, enabled: r.enabled, createdBy: r.created_by ?? '', createdAt: (r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at) });
  const ov = await q<any>('select customer_id, rule_id, disabled from policy_rule_overrides');
  for (const o of ov) overrides.set(ovKey(o.customer_id, o.rule_id), o.disabled);
  if (!listTemplates(['partner']).length) await seedBaseTemplatesPersisted();
  return { templates: templates.size, rules: rules.size };
}

// Three base partner templates (like the Mesh defaults), O365 marked default.
function baseTemplates(): PolicyTemplate[] {
  const mk = (name: string, deployment: string, def: boolean): PolicyTemplate => ({
    id: randomUUID(), scope: 'partner', name, comment: '', deployment,
    data: structuredClone(DEFAULT_TEMPLATE_DATA), isDefault: def, createdBy: 'system', createdAt: new Date().toISOString(),
  });
  return [mk('Base Gateway policy template', 'BreakPhish Gateway', false), mk('Base 365 policy template', 'BreakPhish 365', true), mk('Base Unified policy template', 'BreakPhish Unified', false)];
}
function seedBaseTemplates() { if (!listTemplates(['partner']).length) for (const t of baseTemplates()) templates.set(t.id, t); }
async function seedBaseTemplatesPersisted() { for (const t of baseTemplates()) { templates.set(t.id, t); await persistTemplate(t); } }
