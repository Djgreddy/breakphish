// Read-only health snapshot for the Settings page. No controls, no actions —
// just what's running right now.

import { config } from './config';
import { listCustomers } from './onboarding';
import { getConnection } from './consent';
import { store } from './store';
import { emailStore } from './emailsec/store';
import { dbEnabled, ping } from './db/db';

const startedAt = Date.now();

export async function healthSnapshot() {
  const db = { enabled: dbEnabled(), connected: dbEnabled() ? await ping() : false };
  const customers = listCustomers();
  const connected = customers.filter(c => getConnection(c.id)?.status === 'connected');
  const mem = process.memoryUsage();
  return {
    status: 'ok',
    uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
    node: process.version,
    mode: {
      directory: config.directoryProvider,   // mock | graph
      auth: config.auth.provider,             // mock | entra
      email: config.emailTransport,
    },
    data: {
      customers: customers.length,
      connectedTenants: connected.length,
      syncedUsers: customers.reduce((n, c) => n + store.usersForTenant(c.id).length, 0),
      scoredMessages: emailStore.analyses.size,
      // Honest: DB may be connected while stores are still in-memory (porting in progress).
      persistence: db.enabled ? (db.connected ? 'postgres (connected)' : 'postgres (unreachable)') : 'in-memory',
    },
    db,
    memoryMb: {
      rss: Math.round(mem.rss / 1048576),
      heapUsed: Math.round(mem.heapUsed / 1048576),
    },
  };
}
