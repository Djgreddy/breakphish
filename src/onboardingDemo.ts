// End-to-end onboarding demo (mock mode, fully offline):
//   create customer → build consent URL → simulate Microsoft's callback →
//   verify the tenant + read verified domains → directory sync →
//   (SAT only) generate + verify M365 allow-listing → readiness summary.
// Also shows a declined-consent path.
//
// Run: npm run demo:onboard

import { onboardCustomer } from './onboarding';
import { buildConsentUrl, handleConsentCallback, getConnection, scopesForProducts } from './consent';
import { syncTenant } from './directory/syncService';
import { allowlistConfig, verifyAllowlist } from './allowlist';
import { store } from './store';

const line = (s = '') => console.log(s);
const hr = () => line('─'.repeat(72));

// Pull the state out of a freshly-built consent URL so we can simulate the
// exact redirect Microsoft would send back.
function stateOf(url: string) { return new URL(url).searchParams.get('state')!; }

async function main() {
  line('\n🛡  BreakPhish — M365 onboarding demo (mock mode)\n');

  // 1. Create the customer (both products so we exercise allow-listing too).
  const customer = await onboardCustomer({
    name: 'Acme Manufacturing',
    primaryDomain: 'acme.test', // matches the mock directory's user domain
    products: ['email_security', 'sat'],
    integrationModel: 'api',
    mailboxes: 142,
  });
  line(`1. Customer created: ${customer.name} (${customer.products.join(' + ')}, ${customer.integrationModel})`);
  hr();

  // 2. Build the admin-consent URL.
  const { url, requested } = buildConsentUrl(customer.id);
  line('2. "Connect Microsoft 365" → admin opens this consent URL:');
  line('   ' + url.replace(/&/g, '\n     &'));
  line('\n   Permissions requested (admin sees these on the Microsoft consent screen):');
  for (const p of dedupe(requested.map(r => r.scope))) line(`     • ${p}`);
  hr();

  // 3a. Simulate a DECLINED consent first.
  line('3. Admin declines → Microsoft redirects back with an error:');
  const declined = await handleConsentCallback({ error: 'access_denied', error_description: 'admin did not grant', state: stateOf(url) });
  line(`   result: ${declined.ok ? 'ok' : 'blocked'} — ${declined.error}`);
  hr();

  // 3b. Now the admin grants. Rebuild the URL (new state) and simulate success.
  const grant = buildConsentUrl(customer.id);
  line('4. Admin grants consent → Microsoft redirects back:');
  const ok = await handleConsentCallback({ admin_consent: 'True', tenant: '00000000-aaaa-bbbb-cccc-222222222222', state: stateOf(grant.url) });
  const conn = getConnection(customer.id)!;
  line(`   status: ${conn.status.toUpperCase()}`);
  line(`   organization: ${conn.displayName}`);
  line(`   verified domains: ${conn.verifiedDomains?.join(', ')}`);
  line(`   granted scopes: ${conn.grantedScopes.join(', ')}`);
  hr();

  // 4. Directory sync now that we're connected.
  // (Point the tenant's entraTenantId at the connected one, then sync.)
  const t = store.getTenant(customer.id)!;
  t.entraTenantId = conn.entraTenantId;
  const sync = await syncTenant(customer.id);
  line(`5. Directory sync (${sync.mode}): ${sync.users} users, ${sync.groups} groups`);
  hr();

  // 5. Allow-listing (SAT entitled → phishing sims need inbox delivery).
  line('6. M365 allow-listing for phishing simulations (SAT):');
  const cfg = allowlistConfig(customer.id);
  line('   Paste into Microsoft 365 Defender → Advanced delivery → Phishing simulation:');
  line(`     sending domains : ${cfg.advancedDelivery.sendingDomains.join(', ')}`);
  line(`     sending IPs     : ${cfg.advancedDelivery.sendingIps.join(', ')}`);
  line(`     simulation URLs : ${cfg.advancedDelivery.simulationUrls.join(', ')}`);
  line('');
  const ver = await verifyAllowlist(customer.id);
  line(`   Verification: ${ver.passed ? 'PASSED ✅' : 'FAILED ❌'}`);
  for (const c of ver.checks) line(`     ${c.ok ? '✓' : '✗'} ${c.name} — ${c.detail}`);
  hr();

  // 6. Readiness summary.
  line('7. Onboarding status');
  line(`   ✓ Microsoft 365 connected (${conn.status})`);
  line(`   ✓ Directory synced (${store.usersForTenant(customer.id).length} users)`);
  line(`   ✓ Email Security ready (Graph mail access granted)`);
  line(`   ${ver.passed ? '✓' : '✗'} Phishing simulations ready (allow-listing ${ver.passed ? 'verified' : 'incomplete'})`);
  hr();
  line(`${ok.ok ? 'Customer is fully onboarded and ready for campaigns + protection ✅' : ''}\n`);
}

function dedupe<T>(a: T[]): T[] { return [...new Set(a)]; }

main().catch(err => { console.error(err); process.exit(1); });
