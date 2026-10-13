// Generates varied RAW inbound messages for a tenant. These are fed through the
// real detection pipeline (analyze), so every verdict comes from the actual
// scorers — nothing is assigned. Used to seed the API with realistic volume.

import { randomUUID } from 'node:crypto';
import type { Message } from './types';

type Profile = 'clean' | 'spam' | 'spam_likely' | 'infomail' | 'phishing' | 'impersonation' | 'malware';

// Weighted mix roughly matching a real inbound stream.
const MIX: [Profile, number][] = [
  ['clean', 0.84], ['spam', 0.055], ['spam_likely', 0.022],
  ['infomail', 0.03], ['phishing', 0.02], ['impersonation', 0.016], ['malware', 0.017],
];

const SENDERS: Record<Profile, [string, string, string][]> = {
  clean: [
    ['courtney.nelson@markcubancompanies.com', 'Courtney Nelson', 'Re: Time Entry Created: T2026101'],
    ['notifications@github.com', 'GitHub', 'Your weekly digest'],
    ['no-reply@zoom.us', 'Zoom', 'Your meeting recording is ready'],
    ['billing@aws.amazon.com', 'AWS', 'Your invoice is available'],
  ],
  spam: [
    ['deals@promo-blast.biz', 'Mega Deals', 'You have WON a $1000 reward — claim your prize'],
    ['winner@luckydraw-intl.co', 'Lucky Draw', 'Act now — risk-free miracle crypto giveaway'],
  ],
  spam_likely: [
    ['noreply@newsletter-hub.co', 'Industry News', 'This week in manufacturing'],
    ['hello@growthtips.io', 'Growth Tips', '5 ways to scale faster'],
  ],
  infomail: [
    ['marketing@saas-vendor.com', 'SaaS Vendor', 'New features you will love — newsletter'],
    ['news@retailchain.com', 'Retail Chain', 'Your monthly newsletter, view in browser'],
  ],
  phishing: [
    ['security@microsft-verify.com', 'Microsoft Account Team', 'Unusual sign-in — verify your password now'],
    ['it-helpdesk@o365-support-portal.co', 'IT Support', 'Action required: confirm your account immediately'],
  ],
  impersonation: [
    ['david.chen.exec@gmail.com', 'David Chen', 'Quick favor — are you available?'],
    ['a.nguyen.finance@outlook.com', 'Alice Nguyen', 'Urgent: change of banking details'],
  ],
  malware: [
    ['billing@vendor-invoices.net', 'Accounts Payable', 'Overdue invoice attached — remit payment'],
  ],
};

function buildFor(profile: Profile, tenantId: string, to: string, r: () => number): Message {
  const [fromAddress, fromDisplay, subject] = SENDERS[profile][Math.floor(r() * SENDERS[profile].length)];
  const base: Message = {
    id: randomUUID(), tenantId, direction: 'inbound', source: r() < 0.08 ? 'internal' : 'external',
    fromAddress, fromDisplay, to, subject, bodyText: '',
    receivedAt: new Date(Date.now() - Math.floor(r() * 86400000)).toISOString(),
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
    senderDomainAgeDays: 3000, firstTimeSender: false, urls: [], attachments: [],
  };
  switch (profile) {
    case 'clean': base.bodyText = 'Thanks, confirmed. See attached notes.'; break;
    case 'spam':
      base.bodyText = 'Act now! Claim your prize, risk-free. This miracle crypto giveaway ends today.';
      base.auth = { spf: 'fail', dkim: 'fail', dmarc: 'fail' }; base.senderDomainAgeDays = 120; break;
    case 'spam_likely':
      base.bodyText = 'Our weekly roundup of industry headlines.';
      base.auth = { spf: 'fail', dkim: 'fail', dmarc: 'none' }; base.firstTimeSender = true; break;
    case 'infomail':
      base.bodyText = 'Our monthly newsletter. Unsubscribe anytime. View in browser.'; break;
    case 'phishing':
      base.bodyText = 'We detected an unusual sign-in. Your account will be suspended. Verify your password immediately.';
      base.urls = ['https://login-microsoft-verify.com/auth'];
      base.auth = { spf: 'fail', dkim: 'none', dmarc: 'fail' }; base.senderDomainAgeDays = 6; base.firstTimeSender = true; break;
    case 'impersonation':
      base.bodyText = 'I am in meetings. Can you buy five $200 gift cards for a client? Urgent. Send me the codes.';
      base.replyTo = 'payments-dept@proton.me'; base.firstTimeSender = true; break;
    case 'malware':
      base.bodyText = 'Please find the overdue invoice attached and remit payment immediately.';
      base.attachments = [{ filename: 'Invoice_20934.zip', contentType: 'application/zip' }];
      base.auth = { spf: 'fail', dkim: 'fail', dmarc: 'fail' }; base.senderDomainAgeDays = 20; break;
  }
  return base;
}

// Simple seeded RNG so a tenant's stream is stable across restarts.
function seeded(seed: string) {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i++) { h = Math.imul(h ^ seed.charCodeAt(i), 3432918353); h = h << 13 | h >>> 19; }
  return () => { h = Math.imul(h ^ h >>> 16, 2246822507); h = Math.imul(h ^ h >>> 13, 3266489909); return ((h ^= h >>> 16) >>> 0) / 4294967296; };
}

export function generateRawMessages(tenantId: string, domain: string, mailboxes: string[], n: number): Message[] {
  const r = seeded(tenantId + '-gen');
  const out: Message[] = [];
  for (let i = 0; i < n; i++) {
    let x = r(), acc = 0, profile: Profile = 'clean';
    for (const [p, w] of MIX) { acc += w; if (x <= acc) { profile = p; break; } }
    const to = mailboxes[Math.floor(r() * mailboxes.length)];
    out.push(buildFor(profile, tenantId, to, r));
  }
  return out;
}
