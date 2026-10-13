// In-memory email-security store (mirrors future Postgres tables). Tenant-scoped
// the same way the SAT store is.

import { randomUUID } from 'node:crypto';
import type { Message, Analysis } from './types';

export interface ReleaseRequest {
  id: string;
  tenantId: string;
  messageId: string;
  requestedBy: string;
  status: 'pending' | 'released' | 'denied';
  at: string;
}

class EmailStore {
  messages = new Map<string, Message>();
  analyses = new Map<string, Analysis>(); // keyed by messageId
  releaseRequests: ReleaseRequest[] = [];

  saveMessage(m: Message) { this.messages.set(m.id, m); return m; }
  saveAnalysis(a: Analysis) { this.analyses.set(a.messageId, a); return a; }

  messagesForTenant(tenantId: string) {
    return [...this.messages.values()].filter(m => m.tenantId === tenantId);
  }
  analysisFor(messageId: string) { return this.analyses.get(messageId); }
  analysesForTenant(tenantId: string) {
    return [...this.analyses.values()].filter(a => a.tenantId === tenantId);
  }
  quarantinedForTenant(tenantId: string) {
    return this.analysesForTenant(tenantId).filter(a => a.disposition === 'quarantine' || a.disposition === 'remediated');
  }

  createReleaseRequest(tenantId: string, messageId: string, requestedBy: string): ReleaseRequest {
    const r: ReleaseRequest = {
      id: randomUUID(), tenantId, messageId, requestedBy,
      status: 'pending', at: new Date().toISOString(),
    };
    this.releaseRequests.push(r);
    return r;
  }
}

export const emailStore = new EmailStore();
