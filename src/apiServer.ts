// Boots the full local app: onboards a few customers, connects them (mock
// consent → sync → score inbound mail), then serves the JSON API and the
// API-wired console from the same origin. Open the printed URL and the console
// reads live data from the pipeline.
//
// Run: npm run api

import express from 'express';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { config } from './config';
import { onboardCustomer, hydrateCustomers, listCustomers } from './onboarding';
import { hydrateConnections } from './consent';
import { hydrateDirectory, hydrateEmail } from './db/hydrate';
import { hydrateSettings } from './settings';
import { hydratePolicy } from './policy';
import { hydrateTeam } from './team';
import { hydrateAudit } from './audit';
import { buildWebhookApp } from './webhooks';
import { buildPortalApp } from './quarantinePortal';
import { hydrateSubscriptions, renewDue } from './emailsec/subscriptions';
import { buildApi, connectAndSeed } from './api';
import { buildConsentApp } from './consentServer';
import { buildAuthApp } from './auth/authServer';
import { dbEnabled, migrate, ping } from './db/db';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Safety net: never let one failed request (e.g. a bad tenant during connect)
// take down the whole server. Log it and keep running.
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));
process.on('uncaughtException', (e) => console.error('[uncaughtException]', e));

async function seed() {
  // Demo seed uses placeholder tenants (acme.test / tid-acme) that only work
  // with the mock providers. In real mode, skip it — connecting a fake tenant
  // to live Microsoft Graph throws and crash-loops the server. Real customers
  // come from live onboarding + admin consent instead.
  if (config.directoryProvider !== 'mock') {
    console.log('Real directory provider detected — skipping demo seed. Onboard customers via the console + Microsoft consent.');
    return;
  }

  // A couple of customers come pre-connected so the console has data on load;
  // one is left unconnected so you can click "Connect Microsoft 365" yourself.
  const acme = await onboardCustomer({ name: 'Acme Manufacturing', primaryDomain: 'acme.test', products: ['email_security', 'sat'], integrationModel: 'api', mailboxes: 142 });
  await connectAndSeed(acme.id);

  const north = await onboardCustomer({ name: 'Northstar Health Group', primaryDomain: 'acme.test', products: ['email_security'], integrationModel: 'api', mailboxes: 318 });
  await connectAndSeed(north.id);

  // Unconnected trial customer.
  await onboardCustomer({ name: 'Oakridge Legal LLP', primaryDomain: 'acme.test', products: ['email_security'], integrationModel: 'api', mailboxes: 54 });

  console.log('Seeded customers (2 connected, 1 awaiting consent).');
}

async function main() {
  // If a database is configured, apply the schema before anything else so the
  // tables exist. Stores are ported to it incrementally; until then the app
  // still runs in-memory even with the DB connected.
  if (dbEnabled()) {
    try {
      await migrate();
      console.log(`[db] connected: ${(await ping()) ? 'ok' : 'FAILED'}`);
      const c = await hydrateCustomers();
      const n = await hydrateConnections();
      const dir = await hydrateDirectory();
      const em = await hydrateEmail();
      const st = await hydrateSettings();
      const pol = await hydratePolicy();
      const subN = await hydrateSubscriptions();
      await hydrateTeam();
      await hydrateAudit();
      console.log(`[db] hydrated ${c} customers, ${n} connections, ${dir.users} users, ${dir.groups} groups, ${em.messages} messages, ${st} settings, ${pol.templates} policy templates, ${subN} subscriptions from Postgres`);
    } catch (e) {
      console.error('[db] migration/hydrate failed — check DATABASE_URL:', (e as Error).message);
    }
  } else {
    console.log('[db] DATABASE_URL not set — running in-memory (data resets on restart)');
    await hydratePolicy(); // seeds base templates in memory
  }

  // Only seed demo data when there's nothing already (fresh in-memory run).
  if (listCustomers().length === 0) await seed();
  else console.log(`[db] ${listCustomers().length} customers present — skipping demo seed`);

  const app = express();
  app.use(buildWebhookApp());                // /webhooks/graph (public, clientState-validated)
  app.use(buildPortalApp());                 // /portal/* (public, token-authenticated end-user quarantine)
  app.use(buildAuthApp());                   // /auth/* (public)
  app.use('/api', buildApi());               // protected by session middleware
  app.use(buildConsentApp());               // /onboarding/consent/*

  // Keep Graph subscriptions alive (renew those nearing expiry) every 30 min.
  if (config.directoryProvider === 'graph') {
    setInterval(() => { renewDue().then(n => { if (n) console.log(`[subs] renewed ${n} subscription(s)`); }).catch(() => {}); }, 30 * 60000);
  }
  app.get('/', (_req, res) => res.sendFile(join(__dirname, '..', 'web', 'console.html')));
  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  createServer(app).listen(config.port, () => {
    console.log(`\n🛡  BreakPhish console + API running`);
    console.log(`   open  ${config.publicBaseUrl}/`);
    console.log(`   api   ${config.publicBaseUrl}/api/customers\n`);
  });
}

main().catch(err => { console.error(err); process.exit(1); });
