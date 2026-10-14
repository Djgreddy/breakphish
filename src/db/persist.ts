// DB persistence for the customer + connection stores. The app keeps its
// in-memory maps for fast synchronous reads; these functions mirror writes to
// Postgres and load everything back on boot. Row shapes are defined structurally
// to avoid import cycles with onboarding/consent.

import { q } from './db';

export interface CustomerRow {
  id: string; name: string; primary_domain: string; entra_tenant_id: string | null;
  verified_domains: string[]; products: string[]; integration_model: string | null;
  mailboxes: number; status: string;
  licenses: number; ordered_at: string | Date; flags: any;
}
export interface ConnectionRow {
  customer_id: string; entra_tenant_id: string | null; status: string; reason: string | null;
  display_name: string | null; verified_domains: string[]; granted_scopes: string[];
  connected_at: string | null;
}

export async function upsertCustomer(c: {
  id: string; name: string; primaryDomain: string; entraTenantId?: string;
  verifiedDomains: string[]; products: string[]; integrationModel?: string;
  mailboxes: number; status?: string; licenses?: number; orderedAt?: string; flags?: any;
}): Promise<void> {
  await q(
    `insert into customers (id,name,primary_domain,entra_tenant_id,verified_domains,products,integration_model,mailboxes,status,licenses,ordered_at,flags)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     on conflict (id) do update set
       name=excluded.name, primary_domain=excluded.primary_domain, entra_tenant_id=excluded.entra_tenant_id,
       verified_domains=excluded.verified_domains, products=excluded.products,
       integration_model=excluded.integration_model, mailboxes=excluded.mailboxes, status=excluded.status,
       licenses=excluded.licenses, ordered_at=excluded.ordered_at, flags=excluded.flags`,
    [c.id, c.name, c.primaryDomain, c.entraTenantId ?? null, c.verifiedDomains, c.products,
     c.integrationModel ?? null, c.mailboxes, c.status ?? 'active',
     c.licenses ?? 0, c.orderedAt ?? new Date().toISOString(), JSON.stringify(c.flags ?? {})],
  );
}

export async function loadCustomers(): Promise<CustomerRow[]> {
  return q<CustomerRow>('select * from customers order by created_at');
}

export async function upsertConnection(customerId: string, conn: {
  entraTenantId?: string; status: string; reason?: string; displayName?: string;
  verifiedDomains?: string[]; grantedScopes?: string[]; connectedAt?: string;
}): Promise<void> {
  await q(
    `insert into connections (customer_id,entra_tenant_id,status,reason,display_name,verified_domains,granted_scopes,connected_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8)
     on conflict (customer_id) do update set
       entra_tenant_id=excluded.entra_tenant_id, status=excluded.status, reason=excluded.reason,
       display_name=excluded.display_name, verified_domains=excluded.verified_domains,
       granted_scopes=excluded.granted_scopes, connected_at=excluded.connected_at`,
    [customerId, conn.entraTenantId ?? null, conn.status, conn.reason ?? null, conn.displayName ?? null,
     conn.verifiedDomains ?? [], conn.grantedScopes ?? [], conn.connectedAt ?? null],
  );
}

export async function loadConnections(): Promise<ConnectionRow[]> {
  return q<ConnectionRow>('select * from connections');
}

// ---- directory: users + groups ----
export async function upsertUserRow(u: { id: string; tenantId: string; externalId: string; email: string; displayName: string; department?: string; enabled: boolean }): Promise<void> {
  await q(
    `insert into users (id,tenant_id,external_id,email,display_name,department,enabled)
     values ($1,$2,$3,$4,$5,$6,$7)
     on conflict (tenant_id,external_id) do update set
       email=excluded.email, display_name=excluded.display_name, department=excluded.department, enabled=excluded.enabled`,
    [u.id, u.tenantId, u.externalId, u.email, u.displayName, u.department ?? null, u.enabled],
  );
}
export async function loadUsers(): Promise<any[]> {
  return q('select * from users');
}
export async function upsertGroupRow(g: { id: string; tenantId: string; externalId: string; name: string; memberExternalIds: string[] }): Promise<void> {
  await q(
    `insert into groups (id,tenant_id,external_id,name,member_external_ids)
     values ($1,$2,$3,$4,$5)
     on conflict (tenant_id,external_id) do update set
       name=excluded.name, member_external_ids=excluded.member_external_ids`,
    [g.id, g.tenantId, g.externalId, g.name, g.memberExternalIds],
  );
}
export async function loadGroups(): Promise<any[]> {
  return q('select * from groups');
}

// ---- email: messages + analyses ----
export async function upsertMessageRow(m: any): Promise<void> {
  await q(
    `insert into messages (id,tenant_id,direction,source,from_address,from_display,to_address,subject,body_text,received_at,auth,reply_to,sender_domain_age_days,first_time_sender,urls,attachments)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
     on conflict (id) do nothing`,
    [m.id, m.tenantId, m.direction, m.source, m.fromAddress, m.fromDisplay, m.to, m.subject, m.bodyText ?? '',
     m.receivedAt, JSON.stringify(m.auth ?? {}), m.replyTo ?? null, m.senderDomainAgeDays ?? null,
     m.firstTimeSender ?? null, m.urls ?? [], JSON.stringify(m.attachments ?? [])],
  );
}
export async function loadMessages(): Promise<any[]> {
  return q('select * from messages order by received_at desc');
}
export async function upsertAnalysisRow(a: any): Promise<void> {
  await q(
    `insert into analyses (message_id,tenant_id,verdict,confidence,disposition,remediated,signals)
     values ($1,$2,$3,$4,$5,$6,$7)
     on conflict (message_id) do update set
       verdict=excluded.verdict, confidence=excluded.confidence, disposition=excluded.disposition,
       remediated=excluded.remediated, signals=excluded.signals`,
    [a.messageId, a.tenantId, a.verdict, a.confidence, a.disposition, a.remediated, JSON.stringify(a.signals ?? [])],
  );
}
export async function loadAnalyses(): Promise<any[]> {
  return q('select * from analyses');
}
