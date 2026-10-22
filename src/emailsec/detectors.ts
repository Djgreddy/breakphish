// Cheap, high-value algorithmic detectors that run on every message (no API cost):
//   - lookalike domain: sender domain is a near-miss of a tenant/brand domain
//   - directory impersonation: display name matches a real internal user but the
//     sending address isn't theirs
//
// These are tenant-aware, so they take the tenant's verified domains and users.

import type { Message, Signal } from './types';
import { store } from '../store';
import { senderStat } from './baseline';
import { detectionFlags } from '../policy';
import { msDeemedLegit } from './scorers';

const COMMON_BRANDS = [
  'microsoft.com', 'office365.com', 'outlook.com', 'live.com', 'google.com', 'gmail.com',
  'apple.com', 'amazon.com', 'paypal.com', 'docusign.com', 'dropbox.com', 'adobe.com',
  'linkedin.com', 'netflix.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
];

// Homoglyph / typo normalization so micros0ft ≈ microsoft, rn ≈ m, etc.
function normalize(s: string): string {
  return s.toLowerCase()
    .replace(/rn/g, 'm').replace(/vv/g, 'w')
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a')
    .replace(/5/g, 's').replace(/7/g, 't').replace(/8/g, 'b').replace(/\$/g, 's')
    .replace(/[^a-z.]/g, '');
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[m][n];
}

function domainOf(addr: string): string { return (addr.split('@')[1] ?? '').toLowerCase(); }
function nameKey(s: string): string { return (s || '').toLowerCase().replace(/[^a-z ]/g, '').replace(/\s+/g, ' ').trim(); }

// Sender domain looks like a tenant/brand domain but isn't it.
export function lookalikeDomainScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  const dom = domainOf(m.fromAddress);
  if (!dom) return [];
  const tenant = store.getTenant(m.tenantId);
  const own = (tenant?.verifiedDomains ?? []).map(d => d.toLowerCase());
  if (own.includes(dom)) return [];                       // actually internal — fine
  const targets = [...own, ...COMMON_BRANDS];
  const nd = normalize(dom);
  for (const t of targets) {
    const nt = normalize(t);
    if (!nt || dom === t) continue;   // identical real domain → fine; normalized-equal IS the lookalike
    const dist = levenshtein(nd, nt);
    // normalized-equal (homoglyph) or within edit distance 1–2 of a longer name
    if (dist === 0 || (dist <= 2 && nt.length >= 6)) {
      const weight = own.includes(t) ? 55 : 45;           // impersonating the tenant's own domain is worse
      return [{ code: 'lookalike_domain', detail: `Sender domain "${dom}" closely resembles "${t}"`, category: 'phishing', weight }];
    }
  }
  return [];
}

// Display name matches a real internal user, but the address isn't theirs.
export function directoryImpersonationScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound') return [];
  const display = nameKey(m.fromDisplay);
  if (!display || display.split(' ').length < 2) return [];   // need a full name to match
  const from = m.fromAddress.toLowerCase();
  for (const u of store.usersForTenant(m.tenantId)) {
    if (nameKey(u.displayName) === display && u.email.toLowerCase() !== from) {
      const external = m.source === 'external';
      return [{
        code: 'display_name_impersonation',
        detail: `Display name "${m.fromDisplay}" matches internal user ${u.displayName} (${u.email}), but was sent from ${m.fromAddress}`,
        category: 'impersonation',
        weight: external ? 55 : 35,
      }];
    }
  }
  return [];
}

// Punycode / IDN homograph: xn-- domains render as lookalike Unicode (e.g. аpple.com).
export function punycodeScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  const dom = domainOf(m.fromAddress);
  if (dom.split('.').some(label => label.startsWith('xn--'))) {
    return [{ code: 'punycode_domain', detail: `Sender uses an internationalized (punycode) domain "${dom}" — often a homograph/lookalike attack`, category: 'phishing', weight: 50 }];
  }
  return [];
}

// Reply-To points to a different (external) domain than the From address — classic
// reply-address spoofing used in BEC.
export function replyToMismatchScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || !m.replyTo) return [];
  const fromDom = domainOf(m.fromAddress);
  const replyDom = domainOf(m.replyTo);
  if (replyDom && fromDom && replyDom !== fromDom) {
    const tenant = store.getTenant(m.tenantId);
    const own = (tenant?.verifiedDomains ?? []).map(d => d.toLowerCase());
    if (own.includes(replyDom)) return []; // reply back into the org — fine
    return [{ code: 'reply_to_mismatch', detail: `Reply-To domain "${replyDom}" differs from the sender domain "${fromDom}"`, category: 'phishing', weight: 35 }];
  }
  return [];
}

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc'];
const BRAND_WORDS = ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'google', 'paypal', 'amazon', 'apple', 'docusign', 'netflix', 'chase', 'wellsfargo', 'bankofamerica', 'dropbox', 'adobe'];

function urlHost(u: string): string { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; } }
function registrable(host: string): string { const p = host.split('.'); return p.length >= 2 ? p.slice(-2).join('.') : host; }

// URL / link analysis. Weak signals (shorteners) score low so they only matter in
// combination; strong signals (lookalike / mismatch / IP) score high on their own.
export function urlScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  if (!detectionFlags(m.tenantId).linkHeuristics) return [];
  const out: Signal[] = [];
  const own = (store.getTenant(m.tenantId)?.verifiedDomains ?? []).map(d => d.toLowerCase());
  const hosts = (m.urls ?? []).map(urlHost).filter(Boolean);
  const seen = new Set<string>();
  for (const host of hosts) {
    if (seen.has(host)) continue; seen.add(host);
    const reg = registrable(host);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { out.push({ code: 'url_ip', detail: `Link points to a raw IP address (${host})`, category: 'phishing', weight: 35 }); continue; }
    if (host.split('.').some(l => l.startsWith('xn--'))) { out.push({ code: 'url_punycode', detail: `Link uses a punycode/IDN domain (${host})`, category: 'phishing', weight: 40 }); continue; }
    if (SHORTENERS.includes(reg)) { out.push({ code: 'url_shortener', detail: `Link uses a URL shortener (${reg}) that hides its destination`, category: 'spam', weight: 8 }); continue; }
    // lookalike of a tenant/brand domain
    const nd = normalize(host);
    for (const t of [...own, ...COMMON_BRANDS]) {
      if (reg === t) break;
      const dist = levenshtein(nd, normalize(t));
      if ((dist === 0 || (dist <= 2 && normalize(t).length >= 6)) && reg !== t) { out.push({ code: 'url_lookalike', detail: `Link domain "${host}" resembles "${t}"`, category: 'phishing', weight: 40 }); break; }
    }
    // brand word appears in the host (even homoglyphed) but the registrable domain
    // isn't that brand — e.g. paypal.secure-login.ru, micros0ft-login.com
    const nhost = normalize(host);
    const brand = BRAND_WORDS.find(b => nhost.includes(b));
    if (brand && !COMMON_BRANDS.some(cb => reg === cb)) out.push({ code: 'url_brand_impersonation', detail: `Link host impersonates "${brand}" but isn't an official domain (${host})`, category: 'phishing', weight: 35 });
  }
  if (m.linkMismatch) out.push({ code: 'link_text_mismatch', detail: 'A link’s visible text points to a different domain than its actual destination', category: 'phishing', weight: 45 });
  return out;
}

const SCRIPT_EXT = ['.js', '.vbs', '.ps1', '.hta', '.wsf', '.jse', '.vbe'];
const EXEC_EXT2 = ['.exe', '.scr', '.com', '.pif', '.msi', '.jar', '.bat', '.cmd', '.app'];
const MACRO_EXT = ['.docm', '.xlsm', '.pptm', '.dotm', '.xlam'];
const ARCHIVE_EXT = ['.zip', '.rar', '.7z', '.iso', '.img', '.cab', '.gz'];
const ext = (f: string) => { const i = f.lastIndexOf('.'); return i < 0 ? '' : f.slice(i).toLowerCase(); };

// Attachment depth. Double extensions and scripts/executables are strong; macro
// docs and HTML are medium; archives are weak (can't inspect contents).
export function attachmentScorer(m: Message): Signal[] {
  const out: Signal[] = [];
  for (const a of m.attachments ?? []) {
    const f = (a.filename ?? '').toLowerCase();
    const e = ext(f);
    const parts = f.split('.');
    const doubleExec = parts.length >= 3 && [...EXEC_EXT2, ...SCRIPT_EXT].includes('.' + parts[parts.length - 1]) && ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt', 'invoice'].includes(parts[parts.length - 2]);
    if (doubleExec) { out.push({ code: 'att_double_ext', detail: `Attachment "${a.filename}" uses a deceptive double extension`, category: 'malware', weight: 55 }); continue; }
    if (EXEC_EXT2.includes(e)) out.push({ code: 'att_executable', detail: `Executable attachment "${a.filename}"`, category: 'malware', weight: 50 });
    else if (SCRIPT_EXT.includes(e)) out.push({ code: 'att_script', detail: `Script attachment "${a.filename}"`, category: 'malware', weight: 45 });
    else if (MACRO_EXT.includes(e)) out.push({ code: 'att_macro', detail: `Macro-enabled Office attachment "${a.filename}"`, category: 'malware', weight: 28 });
    else if (e === '.html' || e === '.htm') out.push({ code: 'att_html', detail: `HTML attachment "${a.filename}" (possible HTML-smuggling phishing)`, category: 'phishing', weight: 22 });
    else if (ARCHIVE_EXT.includes(e)) out.push({ code: 'att_archive', detail: `Archive attachment "${a.filename}" (contents can't be inspected)`, category: 'spam', weight: 12 });
  }
  return out;
}

// Authentication depth: alignment, not just pass/fail.
export function authDepthScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  if (msDeemedLegit(m)) return []; // Microsoft vouched (compauth / Not-Spam / Bulk) — don't flag alignment
  const fromDom = domainOf(m.fromAddress);
  const own = (store.getTenant(m.tenantId)?.verifiedDomains ?? []).map(d => d.toLowerCase());
  // Someone sending AS your own domain, from outside, without passing DMARC — spoofing you.
  if (own.includes(fromDom) && m.auth.dmarc !== 'pass') {
    return [{ code: 'own_domain_spoof', detail: `Message claims to be from your domain (${fromDom}) but failed authentication — likely spoofing`, category: 'impersonation', weight: 60 }];
  }
  // Passed SPF/DKIM but failed DMARC → the authenticated domain doesn't align with
  // the From header. (This is the FP-prone part — some legit senders/forwarders
  // break DMARC — so it respects the authAlignment toggle. Own-domain spoofing
  // above is always on.)
  if (detectionFlags(m.tenantId).authAlignment && (m.auth.spf === 'pass' || m.auth.dkim === 'pass') && m.auth.dmarc === 'fail') {
    return [{ code: 'dmarc_alignment', detail: `Passed SPF/DKIM but failed DMARC — the authenticated domain doesn't match the From address (possible spoofing)`, category: 'phishing', weight: 38 }];
  }
  return [];
}

const URGENCY = ['urgent', 'immediately', 'asap', 'right away', 'as soon as possible', 'end of day', 'time-sensitive', 'act now', "don't delay", 'expires today', 'final notice'];
const PAYMENT = ['wire transfer', 'wire the', 'gift card', 'itunes card', 'bank details', 'routing number', 'account number', 'direct deposit', 'change my bank', 'update payment', 'outstanding invoice', 'overdue invoice', 'bitcoin', 'crypto', 'payroll', 'ach transfer'];
const CREDENTIAL = ['verify your account', 'confirm your password', 'unusual activity', 'sign in to', 'log in to', 'reset your password', 'account suspended', 'validate your', 'confirm your identity', 'verify your identity', 'click here to verify', 'your account will be'];
const has = (text: string, list: string[]) => list.some(k => text.includes(k));

// Content & structure: intent language + thread-hijacking.
export function contentStructureScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound') return [];
  if (!detectionFlags(m.tenantId).contentIntent) return [];
  const text = ((m.subject ?? '') + ' ' + (m.bodyText ?? '')).toLowerCase();
  const out: Signal[] = [];
  const urgency = has(text, URGENCY), payment = has(text, PAYMENT), credential = has(text, CREDENTIAL);
  if (payment && urgency) out.push({ code: 'bec_urgency_payment', detail: 'Urgent request involving payment / wire / gift-cards — classic BEC pattern', category: 'impersonation', weight: 45 });
  else if (payment) out.push({ code: 'payment_request', detail: 'Message requests a payment / financial action', category: 'spam', weight: 18 });
  if (credential) {
    // Credential/2FA/security language is normal in LEGIT transactional mail, which
    // passes DMARC and links to its own domain. Only treat it as a real phishing
    // signal when the message isn't DMARC-authenticated (spoofable); otherwise it's
    // informational. Lookalike/mismatch links are caught separately with full weight.
    const authed = m.auth.dmarc === 'pass';
    out.push({ code: 'credential_lure', detail: authed ? 'Account/security language (sender is DMARC-authenticated)' : 'Message asks you to verify credentials or account', category: 'phishing', weight: authed ? 6 : 30 });
  }
  else if (urgency) out.push({ code: 'urgency', detail: 'Urgency / pressure language', category: 'spam', weight: 10 });
  // Thread hijacking: a Re:/Fwd: from a sender we've NEVER corresponded with — in
  // EITHER direction. If we emailed them first (e.g. a helpdesk ticket), their reply
  // with "Re:" is expected and legitimate, not a hijack.
  if (/^\s*(re|fwd?|aw|wg)\s*:/i.test(m.subject ?? '') && m.source === 'external') {
    const st = senderStat(m.tenantId, m.fromAddress);
    const neverCorresponded = !st || (st.inbound === 0 && st.outbound === 0);
    if (neverCorresponded) out.push({ code: 'thread_hijack', detail: 'Reply/forward subject from a sender with no prior conversation in either direction', category: 'phishing', weight: 22 });
  }
  return out;
}

export function runDetectors(m: Message): Signal[] {
  return [
    ...lookalikeDomainScorer(m), ...directoryImpersonationScorer(m), ...punycodeScorer(m), ...replyToMismatchScorer(m),
    ...urlScorer(m), ...attachmentScorer(m), ...authDepthScorer(m), ...contentStructureScorer(m),
  ];
}
