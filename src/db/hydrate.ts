// Loads directory (users/groups) and email (messages/analyses) back into the
// in-memory stores on boot, and persists them on write. Keeps the stores
// themselves synchronous; durability is handled here.

import { dbEnabled } from './db';
import { store } from '../store';
import { emailStore } from '../emailsec/store';
import {
  loadUsers, loadGroups, upsertUserRow, upsertGroupRow,
  loadMessages, loadAnalyses, upsertMessageRow, upsertAnalysisRow,
  loadReleased,
} from './persist';

// ---- load on boot ----
export async function hydrateDirectory(): Promise<{ users: number; groups: number }> {
  if (!dbEnabled()) return { users: 0, groups: 0 };
  const users = await loadUsers();
  for (const r of users) {
    store.upsertUser({ id: r.id, tenantId: r.tenant_id, externalId: r.external_id, email: r.email, displayName: r.display_name, department: r.department ?? undefined, enabled: r.enabled });
  }
  const groups = await loadGroups();
  for (const r of groups) {
    store.upsertGroup({ id: r.id, tenantId: r.tenant_id, externalId: r.external_id, name: r.name, memberExternalIds: r.member_external_ids ?? [] });
  }
  return { users: users.length, groups: groups.length };
}

export async function hydrateEmail(): Promise<{ messages: number; analyses: number }> {
  if (!dbEnabled()) return { messages: 0, analyses: 0 };
  const msgs = await loadMessages();
  for (const r of msgs) {
    emailStore.saveMessage({
      id: r.id, internetMessageId: r.internet_message_id ?? undefined, senderIp: r.sender_ip ?? undefined, msVerdict: r.ms_verdict ?? undefined, senderCountry: r.sender_country ?? undefined, transportHops: r.transport_hops ?? undefined, tenantId: r.tenant_id, direction: r.direction, source: r.source,
      fromAddress: r.from_address, fromDisplay: r.from_display, to: r.to_address, subject: r.subject,
      bodyText: r.body_text ?? '', receivedAt: (r.received_at instanceof Date ? r.received_at.toISOString() : r.received_at),
      auth: r.auth ?? { spf: 'none', dkim: 'none', dmarc: 'none' }, replyTo: r.reply_to ?? undefined,
      senderDomainAgeDays: r.sender_domain_age_days ?? 0, firstTimeSender: r.first_time_sender ?? false,
      urls: r.urls ?? [], attachments: r.attachments ?? [],
    });
  }
  const analyses = await loadAnalyses();
  for (const r of analyses) {
    emailStore.saveAnalysis({
      messageId: r.message_id, tenantId: r.tenant_id, verdict: r.verdict, confidence: r.confidence,
      disposition: r.disposition, remediated: r.remediated, releasedManually: r.released_manually ?? false, signals: r.signals ?? [],
    });
  }
  for (const imid of await loadReleased()) emailStore.markReleased(imid);
  return { messages: msgs.length, analyses: analyses.length };
}

// ---- persist on write ----
// Called after a directory sync upserts a tenant's users/groups into the store.
export async function persistTenantDirectory(tenantId: string): Promise<void> {
  if (!dbEnabled()) return;
  for (const u of store.usersForTenant(tenantId)) {
    await upsertUserRow({ id: u.id, tenantId: u.tenantId, externalId: u.externalId, email: u.email, displayName: u.displayName, department: u.department, enabled: u.enabled });
  }
  for (const g of [...store.groups.values()].filter(g => g.tenantId === tenantId)) {
    await upsertGroupRow({ id: g.id, tenantId: g.tenantId, externalId: g.externalId, name: g.name, memberExternalIds: g.memberExternalIds });
  }
}

// Called after the pipeline scores a message.
export async function persistScored(message: any, analysis: any): Promise<void> {
  if (!dbEnabled()) return;
  await upsertMessageRow(message);
  await upsertAnalysisRow(analysis);
}
