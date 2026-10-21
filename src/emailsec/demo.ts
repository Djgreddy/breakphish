// End-to-end demo of the API-model email-security product:
//   onboard a customer (API service) → ingest inbound mail → score each message
//   → apply policy → print a Live Email Tracker log and the dashboard breakdown.
// Also shows Gateway/Unified onboarding being blocked as coming-soon.
//
// Run: npm run demo:email

import { onboardCustomer, ComingSoonError } from '../onboarding';
import { ingestBatch } from './pipeline';
import { sampleMessages } from './sampleMessages';
import { dashboard, liveTracker } from './reporting';
import type { Verdict } from './types';

const line = (s = '') => console.log(s);
const hr = () => line('─'.repeat(74));

const VERDICT_LABEL: Record<Verdict, string> = {
  clean: 'Clean', spam: 'Spam', spam_likely: 'Spam-Likely', phishing: 'Phishing',
  malware: 'Malware', impersonation: 'Impersonation', policy_infomail: 'Policy — Infomail',
  policy_geo: 'Policy — Geo',
};
const STATUS_LABEL: Record<string, string> = {
  deliver: 'Deliver', junk: 'Junk', quarantine: 'Quarantine', remediated: 'Remediated',
};
const pad = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s.padEnd(n));

async function main() {
  line('\n🛡  BreakPhish — Email Security (API model) demo\n');

  // 1. Onboarding: Gateway / Unified are gated.
  line('1. New-customer onboarding — service availability');
  for (const model of ['gateway', 'unified', 'api'] as const) {
    try {
      const c = await onboardCustomer({
        name: 'COMHOME Technology Solutions',
        primaryDomain: 'comhometechnology.com',
        entraTenantId: '00000000-aaaa-bbbb-cccc-222222222222',
        products: ['email_security'],
        integrationModel: model,
        mailboxes: 175,
      });
      line(`   ✅ provisioned with "${model}" service (${c.mailboxes} mailboxes, products: ${c.products.join(', ')})`);
    } catch (e) {
      if (e instanceof ComingSoonError) line(`   ⏳ "${model}" — coming soon (blocked at onboarding)`);
      else throw e;
    }
  }
  hr();

  // 2. Ingest a batch of inbound mail and score it.
  const tenantId = 'comhometechnology';
  const msgs = sampleMessages(tenantId);
  await ingestBatch(msgs);
  line(`2. Ingested and scored ${msgs.length} inbound messages via the API pipeline\n`);

  // 3. Live Email Tracker
  line('   LIVE EMAIL TRACKER');
  line('   ' + pad('From', 34) + pad('Subject', 30) + pad('Verdict', 18) + 'Status');
  line('   ' + '-'.repeat(88));
  for (const row of liveTracker(tenantId)) {
    line('   ' + pad(row.from, 34) + pad(row.subject, 30) + pad((VERDICT_LABEL as any)[row.verdict], 18) + ((STATUS_LABEL as any)[row.status] ?? row.status));
  }
  hr();

  // 4. Dashboard
  const d = dashboard(tenantId);
  line('3. CUSTOMER DASHBOARD — Email Security Hub');
  line(`   Processed ${d.processed}  ·  Clean ${d.clean}  ·  Non-Clean ${d.nonClean}  ·  Threats ${d.threats}  ·  Remediated ${d.remediated}\n`);
  line('   Breakdown of non-clean emails by verdict:');
  const total = d.nonClean || 1;
  for (const [verdict, count] of Object.entries(d.breakdown).sort((a, b) => b[1] - a[1])) {
    const pct = Math.round((count / total) * 100);
    const bar = '█'.repeat(Math.max(1, Math.round(pct / 4)));
    line('   ' + pad(VERDICT_LABEL[verdict as Verdict], 20) + pad(bar, 26) + `${pct}% (${count})`);
  }
  hr();
  line('Loop complete: onboard (API) → ingest → score → policy → dashboard ✅\n');
}

main().catch(err => { console.error(err); process.exit(1); });
