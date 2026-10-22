// Microsoft Graph change-notification subscriptions — the real-time ingestion
// engine. We create a subscription on each mailbox's inbox so Graph PUSHES a
// notification the instant mail arrives. Subscriptions for message resources
// expire in ~3 days, so a renewal loop keeps them alive.
//
// Mock mode records a fake subscription (no Graph call) so the flow is testable
// offline; graph mode creates real ones.

import { randomBytes, randomUUID } from 'node:crypto';
import { config } from '../config';
import { dbEnabled, q } from '../db/db';
import { appToken } from '../directory/graphProvider';
import { store } from '../store';
import { isUnscannable, markUnscannable, isUnscannableError } from './mailboxState';
import { getConnection } from '../consent';

const GRAPH = 'https://graph.microsoft.com/v1.0';
// Graph max for message subscriptions is 4230 minutes; stay under it.
const LIFETIME_MIN = 4000;
const RENEW_WHEN_MIN_LEFT = 360; // renew when < 6h remaining

export interface Subscription {
  id: string; customerId: string; userId: string; resource: string;
  clientState: string; expiration: string;
}

const subs = new Map<string, Subscription>(); // by subscription id

function notificationUrl() { return `${config.publicBaseUrl}/webhooks/graph`; }
function newExpiry() { return new Date(Date.now() + LIFETIME_MIN * 60000).toISOString(); }

export function getSubscription(id: string) { return subs.get(id); }
export function listSubscriptions() { return [...subs.values()]; }

async function persist(s: Subscription) {
  if (!dbEnabled()) return;
  await q(
    `insert into graph_subscriptions (id,customer_id,user_id,resource,client_state,expiration)
     values ($1,$2,$3,$4,$5,$6)
     on conflict (id) do update set expiration=excluded.expiration`,
    [s.id, s.customerId, s.userId, s.resource, s.clientState, s.expiration],
  );
}
async function forget(id: string) { subs.delete(id); if (dbEnabled()) await q('delete from graph_subscriptions where id=$1', [id]); }

// Create a subscription on one mailbox's inbox.
export async function createSubscription(customerId: string, entraTenantId: string, userId: string): Promise<Subscription | null> {
  const resource = `users/${userId}/mailFolders('inbox')/messages`;
  const clientState = randomBytes(16).toString('hex');
  const expiration = newExpiry();

  if (config.directoryProvider !== 'graph') {
    const s: Subscription = { id: `mock-${randomUUID()}`, customerId, userId, resource, clientState, expiration };
    subs.set(s.id, s); await persist(s); return s;
  }
  const token = await appToken(entraTenantId);
  const res = await fetch(`${GRAPH}/subscriptions`, {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ changeType: 'created', notificationUrl: notificationUrl(), resource, expirationDateTime: expiration, clientState }),
  });
  if (!res.ok) {
    const txt = await res.text();
    if (isUnscannableError(txt)) { markUnscannable(customerId, store.usersForTenant(customerId).find(u => u.externalId === userId)?.email || userId); }
    else console.error(`[subs] create failed ${res.status}: ${txt}`);
    return null;
  }
  const j = (await res.json()) as { id: string };
  const s: Subscription = { id: j.id, customerId, userId, resource, clientState, expiration };
  subs.set(s.id, s); await persist(s);
  return s;
}

export async function renewSubscription(s: Subscription): Promise<void> {
  const expiration = newExpiry();
  if (config.directoryProvider === 'graph') {
    const conn = getConnection(s.customerId);
    if (!conn?.entraTenantId) return;
    const token = await appToken(conn.entraTenantId);
    const res = await fetch(`${GRAPH}/subscriptions/${s.id}`, {
      method: 'PATCH', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ expirationDateTime: expiration }),
    });
    if (!res.ok) { // lapsed — recreate
      console.error(`[subs] renew failed ${res.status}; recreating`);
      await forget(s.id);
      await createSubscription(s.customerId, conn.entraTenantId, s.userId);
      return;
    }
  }
  s.expiration = expiration; await persist(s);
}

// Subscribe every synced mailbox of a connected customer.
export async function subscribeTenant(customerId: string): Promise<number> {
  const conn = getConnection(customerId);
  if (!conn?.entraTenantId) return 0;
  const existing = new Set([...subs.values()].filter(s => s.customerId === customerId).map(s => s.userId));
  let made = 0;
  for (const u of store.usersForTenant(customerId).filter(x => x.enabled)) {
    if (existing.has(u.externalId)) continue;
    if (isUnscannable(customerId, u.email || u.externalId)) continue; // not REST-accessible — don't try
    const s = await createSubscription(customerId, conn.entraTenantId, u.externalId);
    if (s) made++;
  }
  console.log(`[subs] ${customerId}: ${made} new subscription(s), ${subs.size} total`);
  return made;
}

// Renew any subscriptions near expiry. Called on a timer.
export async function renewDue(): Promise<number> {
  const cutoff = Date.now() + RENEW_WHEN_MIN_LEFT * 60000;
  let n = 0;
  for (const s of subs.values()) {
    if (Date.parse(s.expiration) <= cutoff) { try { await renewSubscription(s); n++; } catch (e) { console.error('[subs] renew error', (e as Error).message); } }
  }
  return n;
}

export async function hydrateSubscriptions(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await q<any>('select * from graph_subscriptions');
  for (const r of rows) subs.set(r.id, { id: r.id, customerId: r.customer_id, userId: r.user_id, resource: r.resource, clientState: r.client_state, expiration: (r.expiration instanceof Date ? r.expiration.toISOString() : r.expiration) });
  return rows.length;
}
