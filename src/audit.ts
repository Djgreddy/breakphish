// Audit log — a durable record of who did what. Write-through to Postgres, with
// a capped in-memory ring for fast reads.

import { randomUUID } from 'node:crypto';
import { dbEnabled, q } from './db/db';

export interface AuditEntry {
  id: string; at: string; actorEmail: string; role: string;
  action: string; resource: string; detail: string; customerId?: string;
}

const ring: AuditEntry[] = [];
const MAX = 2000;

// Fire-and-forget; never let auditing break the request.
export function audit(e: { actorEmail?: string; role?: string; action: string; resource?: string; detail?: string; customerId?: string }): void {
  const entry: AuditEntry = {
    id: randomUUID(), at: new Date().toISOString(),
    actorEmail: e.actorEmail ?? 'system', role: e.role ?? '', action: e.action,
    resource: e.resource ?? '', detail: e.detail ?? '', customerId: e.customerId,
  };
  ring.unshift(entry); if (ring.length > MAX) ring.pop();
  if (dbEnabled()) {
    q(`insert into audit_log (id, at, actor_email, role, action, resource, detail, customer_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [entry.id, entry.at, entry.actorEmail, entry.role, entry.action, entry.resource, entry.detail, entry.customerId ?? null])
      .catch(() => {});
  }
}

export function listAudit(opts: { q?: string; customerId?: string; action?: string; resource?: string; from?: number; limit?: number } = {}): AuditEntry[] {
  let rows = ring;
  if (opts.customerId) rows = rows.filter(r => r.customerId === opts.customerId);
  if (opts.action) rows = rows.filter(r => r.action === opts.action);
  if (opts.resource) { const s = opts.resource.toLowerCase(); rows = rows.filter(r => (r.resource || '').toLowerCase().includes(s)); }
  if (opts.from) rows = rows.filter(r => Date.parse(r.at) >= opts.from!);
  if (opts.q) { const s = opts.q.toLowerCase(); rows = rows.filter(r => (r.actorEmail + ' ' + r.action + ' ' + r.resource + ' ' + r.detail).toLowerCase().includes(s)); }
  return rows.slice(0, opts.limit ?? 200);
}

// Distinct action names (for a filter dropdown), optionally scoped to a customer.
export function distinctAuditActions(customerId?: string): string[] {
  const set = new Set<string>();
  for (const r of ring) if (!customerId || r.customerId === customerId) set.add(r.action);
  return [...set].sort();
}

export async function hydrateAudit(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await q<any>('select * from audit_log order by at desc limit 2000');
  ring.length = 0;
  for (const r of rows) ring.push({
    id: r.id, at: (r.at instanceof Date ? r.at.toISOString() : r.at), actorEmail: r.actor_email ?? 'system',
    role: r.role ?? '', action: r.action, resource: r.resource ?? '', detail: r.detail ?? '', customerId: r.customer_id ?? undefined,
  });
  return ring.length;
}
