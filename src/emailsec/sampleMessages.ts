// Sample inbound mail for the demo — one per verdict, the way a Graph ingestion
// would normalize messages before scoring. Deterministic so output is stable.

import { randomUUID } from 'node:crypto';
import type { Message } from './types';

const base = (tenantId: string, over: Partial<Message>): Message => ({
  id: randomUUID(),
  tenantId,
  direction: 'inbound',
  source: 'external',
  fromAddress: 'someone@example.com',
  fromDisplay: 'Someone',
  to: 'kle@comhometechnology.com',
  subject: '(no subject)',
  bodyText: '',
  receivedAt: new Date().toISOString(),
  auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
  senderDomainAgeDays: 3000,
  firstTimeSender: false,
  urls: [],
  attachments: [],
  ...over,
});

export function sampleMessages(tenantId: string): Message[] {
  return [
    // 1. Clean internal-style reply
    base(tenantId, {
      fromAddress: 'courtney.nelson@markcubancompanies.com', fromDisplay: 'Courtney Nelson',
      subject: 'Re: Time Entry Created: T2026101', bodyText: 'Thanks, confirmed for Thursday.',
    }),
    // 2. Clean newsletter-ish but legitimate (stays clean)
    base(tenantId, {
      fromAddress: 'updates@github.com', fromDisplay: 'GitHub',
      subject: 'Your weekly digest', bodyText: 'Here is what happened in your repositories this week.',
      senderDomainAgeDays: 5000,
    }),
    // 3. Spam marketing
    base(tenantId, {
      fromAddress: 'deals@promo-blast.biz', fromDisplay: 'Mega Deals',
      subject: 'You have WON a $1000 reward — claim your prize',
      bodyText: 'Act now! Claim your prize, risk-free. This miracle crypto giveaway ends today.',
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail' }, senderDomainAgeDays: 120,
    }),
    // 4. Spam-likely (borderline → delivered but tagged)
    base(tenantId, {
      fromAddress: 'noreply@newsletter-hub.co', fromDisplay: 'Industry News',
      subject: 'This week in manufacturing', bodyText: 'Our weekly roundup of industry headlines.',
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'none' }, firstTimeSender: true,
    }),
    // 5. Phishing credential harvest
    base(tenantId, {
      fromAddress: 'security@microsft-verify.com', fromDisplay: 'Microsoft Account Team',
      subject: 'Unusual sign-in — verify your password now',
      bodyText: 'We detected an unusual sign-in. Your account will be suspended. Verify your password immediately.',
      urls: ['https://login-microsoft-verify.com/auth'],
      auth: { spf: 'fail', dkim: 'none', dmarc: 'fail' }, senderDomainAgeDays: 6, firstTimeSender: true,
    }),
    // 6. BEC / impersonation (CEO gift-card from consumer domain)
    base(tenantId, {
      fromAddress: 'david.chen.exec@gmail.com', fromDisplay: 'David Chen',
      subject: 'Quick favor — are you available?',
      bodyText: 'I am in meetings. Can you buy five $200 gift cards for a client? Urgent. Send me the codes.',
      replyTo: 'david.chen.payments@proton.me',
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' }, firstTimeSender: true,
    }),
    // 7. Malware attachment
    base(tenantId, {
      fromAddress: 'billing@vendor-invoices.net', fromDisplay: 'Accounts Payable',
      subject: 'Overdue invoice attached — remit payment',
      bodyText: 'Please find the overdue invoice attached and remit payment immediately.',
      attachments: [{ filename: 'Invoice_20934.zip', contentType: 'application/zip' }],
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail' }, senderDomainAgeDays: 20,
    }),
    // 8. Policy — infomail (bulk marketing, legit but unwanted)
    base(tenantId, {
      fromAddress: 'marketing@saas-vendor.com', fromDisplay: 'SaaS Vendor',
      subject: 'New features you will love — newsletter',
      bodyText: 'Our monthly newsletter. Unsubscribe anytime. View in browser.',
      senderDomainAgeDays: 2000,
    }),
  ];
}
