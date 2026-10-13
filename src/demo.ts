// End-to-end demo of the MVP critical path, over real HTTP:
//   sync (mock M365) → launch campaign → send → simulate recipient behavior by
//   hitting the tracking endpoints → auto-enroll clickers → print the funnel.
//
// Run: npm run demo

import { createServer } from 'node:http';
import { store } from './store';
import { config } from './config';
import { seedTemplates } from './campaigns/templates';
import { startSendingWorker } from './campaigns/sendingWorker';
import { sendQueue } from './campaigns/queue';
import { syncTenant } from './directory/syncService';
import { createCampaign, launchCampaign } from './campaigns/campaignService';
import { buildTrackingApp } from './tracking/trackingServer';
import { campaignFunnel } from './campaigns/reporting';

const line = (s = '') => console.log(s);
const hr = () => line('─'.repeat(60));

async function main() {
  // 0. Boot: seed templates, start the sending worker, start tracking server.
  seedTemplates();
  startSendingWorker();
  const server = createServer(buildTrackingApp());
  await new Promise<void>(r => server.listen(config.port, r));

  line('\n🛡  BreakPhish — MVP critical-path demo');
  line(`   tracking server on ${config.publicBaseUrl}  ·  directory=${config.directoryProvider}  ·  mail=${config.emailTransport}`);
  hr();

  // 1. Onboard a tenant (would come from the Entra admin-consent callback).
  store.upsertTenant({
    id: 'acme',
    name: 'Acme Manufacturing',
    entraTenantId: '00000000-aaaa-bbbb-cccc-111111111111',
    verifiedDomains: ['acme.test'],
  });

  // 2. Directory sync (mock M365).
  const full = await syncTenant('acme');
  line(`1. Directory sync (${full.mode}): ${full.users} users, ${full.groups} groups from M365`);
  const delta = await syncTenant('acme');
  line(`   incremental sync (${delta.mode}): +${delta.users} user (new hire), ${delta.groups} group updated`);
  line(`   tenant now has ${store.usersForTenant('acme').filter(u => u.enabled).length} enabled users`);
  hr();

  // 3. Build + launch a campaign targeting everyone.
  const campaign = createCampaign({
    tenantId: 'acme',
    name: 'Q1 Baseline Phishing Test',
    templateId: 't-o365',
    audience: { kind: 'all' },
  });
  line(`2. Campaign "${campaign.name}" created (template: Microsoft 365 Password Expiry)`);
  const { recipients } = launchCampaign(campaign.id);
  line(`   launched → ${recipients} recipients queued`);
  hr();

  // 4. Wait for the send queue to drain.
  await sendQueue.idle();
  hr();

  // 5. Simulate recipient behavior by calling the real tracking URLs.
  const recs = store.recipientsForCampaign(campaign.id);
  const url = (path: 'o' | 'c' | 's' | 'r', token: string) => `${config.publicBaseUrl}/t/${path}/${token}`;

  line('3. Simulating recipient behavior (real HTTP to tracking endpoints):');
  // Everyone opens except the last one.
  for (const r of recs.slice(0, -1)) await fetch(url('o', r.token));
  line(`   ${recs.length - 1} opened`);

  // Three users click the lure.
  const clickers = recs.slice(0, 3);
  for (const r of clickers) {
    const res = await fetch(url('c', r.token));
    void (await res.text());
  }
  line(`   ${clickers.length} clicked → teachable moment shown + auto-remediation`);

  // One of those clickers also submits credentials on the fake login page.
  // We POST a fake password to prove it is NEVER stored.
  const submitter = clickers[0];
  await fetch(url('s', submitter.token), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: submitter.email, password: 'hunter2-SHOULD-NOT-BE-STORED' }).toString(),
  });
  line('   1 submitted credentials on the fake page');

  // Two users correctly report the phish.
  for (const r of recs.slice(5, 7)) {
    await fetch(url('r', r.token), { method: 'POST' });
  }
  line('   2 reported the phish ✅');
  hr();

  // 6. Verify the credential was never stored anywhere.
  const leaked = JSON.stringify(store.events).includes('hunter2');
  line(`4. Credential-capture check: posted password found in store? ${leaked ? '❌ LEAKED' : '✅ no — never stored'}`);
  hr();

  // 7. Final funnel + auto-enrollments.
  const f = campaignFunnel(campaign.id);
  line('5. Campaign results');
  line(`   recipients ${f.recipients} · delivered ${f.delivered} · opened ${f.opened} · clicked ${f.clicked} · submitted ${f.submitted} · reported ${f.reported}`);
  line(`   phish-prone: ${f.phishPronePct}%`);
  line('');
  line(`   Auto-enrollments (${store.enrollments.length}):`);
  for (const e of store.enrollments) {
    const u = store.usersForTenant('acme').find(x => x.id === e.userId);
    line(`     • ${u?.email}  →  ${e.moduleId}  (${e.reason})`);
  }
  hr();
  line('Loop complete: sync → send → tracked click → auto-training ✅\n');

  server.close();
}

main().catch(err => { console.error(err); process.exit(1); });
