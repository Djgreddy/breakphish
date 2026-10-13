// Seed templates + a tiny merge renderer. Sending addresses are lookalike
// domains, never the client's real domain (reputation protection, per spec).

import { store } from '../store';
import type { Template, User } from '../types';

export const SEED_TEMPLATES: Template[] = [
  {
    id: 't-o365',
    name: 'Microsoft 365 Password Expiry',
    category: 'Credential',
    difficulty: 'easy',
    fromName: 'Microsoft Account Team',
    fromAddress: 'no-reply@microsft-security.com',
    subject: 'Action required: your password expires today',
    html:
      `<p>Hi {{first_name}},</p>` +
      `<p>Your {{company}} Microsoft 365 password expires in <b>2 hours</b>. ` +
      `Verify now to keep access to email and files.</p>` +
      `<p><a href="{{click_url}}">Keep my password</a></p>`,
  },
  {
    id: 't-invoice',
    name: 'Overdue Invoice',
    category: 'BEC',
    difficulty: 'hard',
    fromName: 'Accounts Payable',
    fromAddress: 'billing@vendor-invoices.net',
    subject: 'OVERDUE: invoice #INV-20934 — immediate payment required',
    html:
      `<p>{{first_name}},</p>` +
      `<p>Invoice #INV-20934 is 14 days past due. Review and remit payment ` +
      `to avoid service interruption.</p>` +
      `<p><a href="{{click_url}}">View invoice &amp; pay</a></p>`,
  },
];

export function seedTemplates() {
  for (const t of SEED_TEMPLATES) store.upsertTemplate(t);
}

export interface RenderedEmail {
  fromName: string;
  fromAddress: string;
  to: string;
  subject: string;
  html: string;
}

export function render(template: Template, user: User, company: string, clickUrl: string, openUrl: string): RenderedEmail {
  const vars: Record<string, string> = {
    first_name: user.displayName.split(' ')[0] ?? 'there',
    company,
    click_url: clickUrl,
  };
  const html =
    template.html.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k] ?? '') +
    // invisible tracking pixel for opens
    `<img src="${openUrl}" width="1" height="1" alt="" style="display:none">`;
  return {
    fromName: template.fromName,
    fromAddress: template.fromAddress,
    to: user.email,
    subject: template.subject,
    html,
  };
}
