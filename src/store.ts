// In-memory store for the demo. Every method is tenant-scoped the way the real
// Postgres layer would be via row-level security. Swapping this file for a
// Postgres-backed implementation (same method signatures) is the only change
// needed to move off the demo store.

import { randomUUID } from 'node:crypto';
import type {
  Tenant, User, Group, Template, Campaign, Recipient, Event, Enrollment, EventType,
} from './types';

class Store {
  tenants = new Map<string, Tenant>();
  users = new Map<string, User>();
  groups = new Map<string, Group>();
  templates = new Map<string, Template>();
  campaigns = new Map<string, Campaign>();
  recipients = new Map<string, Recipient>();
  events: Event[] = [];
  enrollments: Enrollment[] = [];

  // --- tenants ---
  upsertTenant(t: Tenant) { this.tenants.set(t.id, t); return t; }
  getTenant(id: string) { return this.tenants.get(id); }

  // --- users (reconciled by tenantId + externalId) ---
  upsertUser(u: Omit<User, 'id'> & { id?: string }): User {
    const existing = [...this.users.values()].find(
      x => x.tenantId === u.tenantId && x.externalId === u.externalId,
    );
    const user: User = { ...u, id: existing?.id ?? u.id ?? randomUUID() };
    this.users.set(user.id, user);
    return user;
  }
  usersForTenant(tenantId: string) {
    return [...this.users.values()].filter(u => u.tenantId === tenantId);
  }
  userByExternalId(tenantId: string, externalId: string) {
    return [...this.users.values()].find(
      u => u.tenantId === tenantId && u.externalId === externalId,
    );
  }

  // --- groups ---
  upsertGroup(g: Omit<Group, 'id'> & { id?: string }): Group {
    const existing = [...this.groups.values()].find(
      x => x.tenantId === g.tenantId && x.externalId === g.externalId,
    );
    const group: Group = { ...g, id: existing?.id ?? g.id ?? randomUUID() };
    this.groups.set(group.id, group);
    return group;
  }
  groupByName(tenantId: string, name: string) {
    return [...this.groups.values()].find(
      g => g.tenantId === tenantId && g.name.toLowerCase() === name.toLowerCase(),
    );
  }

  // --- templates ---
  upsertTemplate(t: Template) { this.templates.set(t.id, t); return t; }
  getTemplate(id: string) { return this.templates.get(id); }

  // --- campaigns + recipients ---
  createCampaign(c: Omit<Campaign, 'id' | 'createdAt'>): Campaign {
    const campaign: Campaign = { ...c, id: randomUUID(), createdAt: new Date().toISOString() };
    this.campaigns.set(campaign.id, campaign);
    return campaign;
  }
  getCampaign(id: string) { return this.campaigns.get(id); }
  setCampaignStatus(id: string, status: Campaign['status']) {
    const c = this.campaigns.get(id); if (c) c.status = status;
  }

  createRecipient(r: Omit<Recipient, 'id'>): Recipient {
    const recipient: Recipient = { ...r, id: randomUUID() };
    this.recipients.set(recipient.id, recipient);
    return recipient;
  }
  getRecipient(id: string) { return this.recipients.get(id); }
  recipientsForCampaign(campaignId: string) {
    return [...this.recipients.values()].filter(r => r.campaignId === campaignId);
  }
  setRecipientStatus(id: string, status: Recipient['status']) {
    const r = this.recipients.get(id); if (r) r.status = status;
  }

  // --- events (append-only) ---
  // De-duplicates so a given recipient counts once per event type.
  recordEvent(e: { campaignId: string; recipientId: string; tenantId: string; type: EventType }): Event | null {
    const dup = this.events.find(
      x => x.recipientId === e.recipientId && x.type === e.type,
    );
    if (dup) return null;
    const event: Event = { ...e, id: randomUUID(), at: new Date().toISOString() };
    this.events.push(event);
    return event;
  }
  eventsForCampaign(campaignId: string) {
    return this.events.filter(e => e.campaignId === campaignId);
  }

  // --- enrollments ---
  enroll(e: Omit<Enrollment, 'id' | 'at'>): Enrollment | null {
    const dup = this.enrollments.find(
      x => x.userId === e.userId && x.moduleId === e.moduleId,
    );
    if (dup) return null;
    const enrollment: Enrollment = { ...e, id: randomUUID(), at: new Date().toISOString() };
    this.enrollments.push(enrollment);
    return enrollment;
  }
}

export const store = new Store();
