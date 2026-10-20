// Cheap, high-value algorithmic detectors that run on every message (no API cost):
//   - lookalike domain: sender domain is a near-miss of a tenant/brand domain
//   - directory impersonation: display name matches a real internal user but the
//     sending address isn't theirs
//
// These are tenant-aware, so they take the tenant's verified domains and users.

import type { Message, Signal } from './types';
import { store } from '../store';

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

export function runDetectors(m: Message): Signal[] {
  return [...lookalikeDomainScorer(m), ...directoryImpersonationScorer(m), ...punycodeScorer(m), ...replyToMismatchScorer(m)];
}
