// Partner + per-customer settings. Scope is 'partner' (the defaults) or a
// customer id. A customer with no saved settings inherits the partner defaults;
// once it saves, it keeps its own copy. Write-through cache + hydrate, like the
// rest of the stores.

import { dbEnabled, q } from './db/db';

export interface IpRule { ip: string; mask: string; comment: string }
export interface Banner { color: string; message: string }

export interface Settings {
  general: { companyName: string; timezone: string };
  billing: {
    contactName: string; email: string; vatNumber: string; currency: string; billingReference: string;
    address: { line1: string; line2: string; line3: string; line4: string; postcode: string; city: string; country: string };
  };
  quarantineDigest: { frequency: string; days: string[]; times: string[]; verdicts: string[]; sendReleaseRequestsTo: string };
  security: { force2fa: boolean; ipAccess: IpRule[] };
  customization: { logoDataUrl: string; backgroundColor: string; appName: string; active: boolean };
  banners: { verdict: Record<string, Banner>; contextual: Record<string, Banner> };
  managedDomains: string[];   // custom domains the customer manages (treated as internal)
  bannersEnabled: boolean;    // stamp warning banners into delivered external mail
  aiAnalysisEnabled: boolean; // send email content to the AI provider (privacy opt-out)
}

export const DIGEST_VERDICTS = ['clean','spam','spam_likely','phishing','malware','impersonation','policy_infomail','policy_geo'];

const suspect = (w: string) =>
  `Warning! BreakPhish suspects this email is ${w}. [From: {{sender}}, {{source}}] Contact your IT provider before clicking any links or responding to the email.`;
const external =
  `Warning! This email originated from outside your organization. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.`;
const contains = (w: string) =>
  `Warning! This email contains ${w} related content. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.`;
const RED = '#e11d48', AMBER = '#f3b340', BLUE = '#2563eb', GRAY = '#6b7280';

const DEFAULT_BANNERS = {
  verdict: {
    'Banned':        { color: RED,   message: suspect('Banned') },
    'Clean':         { color: AMBER, message: external },
    'Impersonation': { color: RED,   message: suspect('Impersonation') },
    'Infomail':      { color: BLUE,  message: external },
    'Malware':       { color: RED,   message: suspect('Malware') },
    'Phishing':      { color: RED,   message: suspect('Phishing') },
    'Policy-Geo':    { color: RED,   message: `Warning! This email originated from a country not permitted by your organizational policy. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.` },
    'Spam-Definite': { color: GRAY,  message: suspect('Spam') },
    'Spam-High':     { color: GRAY,  message: suspect('Spam') },
    'Spam-Likely':   { color: GRAY,  message: suspect('Spam') },
  } as Record<string, Banner>,
  contextual: {
    'Clean-Financial':   { color: AMBER, message: contains('financial') },
    'Clean-Payroll':     { color: AMBER, message: contains('payroll') },
    'Clean-Invoice':     { color: AMBER, message: contains('invoice/payment') },
    'Clean-DisplayName': { color: AMBER, message: `Warning! The email sender closely matches someone in your organization. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.` },
    'Clean-NewSender':   { color: AMBER, message: `Warning! This is the first time you have received an email from this sender. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.` },
    'Clean-Lookalike':   { color: AMBER, message: `Warning! The sender's domain looks similar to a domain you trust. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.` },
    'Clean-ReplyTo':     { color: AMBER, message: `Warning! The Reply-To address differs from the sender's address. [From: {{sender}}, {{source}}] Do not click links or open attachments unless you recognize the sender and know the content is safe.` },
    'Clean-External':    { color: AMBER, message: external },
  } as Record<string, Banner>,
};

export const DEFAULT_SETTINGS: Settings = {
  general: { companyName: 'Your Company', timezone: '(UTC-06:00) Central Time (US & Canada)' },
  billing: {
    contactName: '', email: '', vatNumber: '', currency: 'USD', billingReference: '',
    address: { line1: '', line2: '', line3: '', line4: '', postcode: '', city: '', country: 'United States' },
  },
  quarantineDigest: {
    frequency: 'Daily', days: ['Mon','Tue','Wed','Thu','Fri'], times: ['9:00 AM'],
    verdicts: ['spam','spam_likely','phishing','malware','impersonation','policy_infomail'],
    sendReleaseRequestsTo: 'Administrators',
  },
  security: { force2fa: false, ipAccess: [] },
  customization: { logoDataUrl: '', backgroundColor: '#1b1240', appName: 'BreakPhish', active: false },
  banners: DEFAULT_BANNERS,
  managedDomains: [],
  bannersEnabled: false,
  aiAnalysisEnabled: true,
};

const cache = new Map<string, Settings>();

function merge(stored: any): Settings {
  // Shallow-merge top-level sections so new fields appear for old saved blobs.
  return {
    ...DEFAULT_SETTINGS,
    ...(stored ?? {}),
    general: { ...DEFAULT_SETTINGS.general, ...(stored?.general ?? {}) },
    billing: { ...DEFAULT_SETTINGS.billing, ...(stored?.billing ?? {}), address: { ...DEFAULT_SETTINGS.billing.address, ...(stored?.billing?.address ?? {}) } },
    quarantineDigest: { ...DEFAULT_SETTINGS.quarantineDigest, ...(stored?.quarantineDigest ?? {}) },
    security: { ...DEFAULT_SETTINGS.security, ...(stored?.security ?? {}) },
    customization: { ...DEFAULT_SETTINGS.customization, ...(stored?.customization ?? {}) },
    banners: {
      verdict: { ...DEFAULT_SETTINGS.banners.verdict, ...(stored?.banners?.verdict ?? {}) },
      contextual: { ...DEFAULT_SETTINGS.banners.contextual, ...(stored?.banners?.contextual ?? {}) },
    },
    managedDomains: stored?.managedDomains ?? [],
    bannersEnabled: stored?.bannersEnabled ?? false,
    aiAnalysisEnabled: stored?.aiAnalysisEnabled ?? true,
  };
}

export function getSettings(scope: string): Settings {
  if (cache.has(scope)) return cache.get(scope)!;
  if (scope !== 'partner' && cache.has('partner')) return cache.get('partner')!; // inherit partner defaults
  return DEFAULT_SETTINGS;
}

export async function saveSettings(scope: string, s: Settings): Promise<void> {
  const merged = merge(s);
  cache.set(scope, merged);
  if (dbEnabled()) {
    await q(
      `insert into settings (scope, data) values ($1, $2)
       on conflict (scope) do update set data = excluded.data, updated_at = now()`,
      [scope, JSON.stringify(merged)],
    );
  }
}

export async function hydrateSettings(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await q<{ scope: string; data: any }>('select scope, data from settings');
  for (const r of rows) cache.set(r.scope, merge(r.data));
  return rows.length;
}
