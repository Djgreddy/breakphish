// Core domain types. These mirror the Postgres tables in db/schema.sql so the
// in-memory store used for the demo maps 1:1 onto the real schema.

export type EventType =
  | 'delivered'
  | 'opened'
  | 'clicked'
  | 'submitted'
  | 'reported'
  | 'bounced';

export type RecipientStatus = 'queued' | 'sent' | 'bounced';

export type CampaignStatus =
  | 'draft'
  | 'approved'
  | 'running'
  | 'completed';

export interface Tenant {
  id: string;            // internal id
  name: string;
  entraTenantId?: string; // the client's M365 tenant id (for Graph)
  verifiedDomains: string[]; // targets must fall inside these (anti-abuse)
}

export interface User {
  id: string;            // internal id
  tenantId: string;
  externalId: string;    // Entra object id (so sync can reconcile)
  email: string;
  displayName: string;
  department?: string;
  manager?: string;
  enabled: boolean;
}

export interface Group {
  id: string;
  tenantId: string;
  externalId: string;
  name: string;
  memberExternalIds: string[];
}

export interface Template {
  id: string;
  name: string;
  category: string;
  difficulty: 'easy' | 'medium' | 'hard';
  fromName: string;
  fromAddress: string;   // a lookalike sending domain, NOT the client's real domain
  subject: string;
  html: string;          // may contain {{first_name}}, {{company}}, etc.
}

// What a campaign targets. 'all' = every enabled user in the tenant;
// otherwise a synced group by name.
export type Audience =
  | { kind: 'all' }
  | { kind: 'group'; groupName: string };

export interface Campaign {
  id: string;
  tenantId: string;
  name: string;
  templateId: string;
  audience: Audience;
  status: CampaignStatus;
  createdAt: string;
}

export interface Recipient {
  id: string;
  campaignId: string;
  tenantId: string;
  userId: string;
  email: string;
  status: RecipientStatus;
  token: string;         // per-recipient tracking token
}

export interface Event {
  id: string;
  campaignId: string;
  recipientId: string;
  tenantId: string;
  type: EventType;
  at: string;
  // NOTE: there is deliberately no field here for captured credentials.
  // The submit endpoint records only that a submit happened.
}

export interface Enrollment {
  id: string;
  tenantId: string;
  userId: string;
  moduleId: string;
  reason: string;        // e.g. "clicked:Q1 Baseline"
  at: string;
}
