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
  // Messages manually released by an admin — identified by their STABLE
  // internetMessageId, so a webhook firing after the release-to-inbox won't
  // re-apply policy and bounce it back into quarantine.
  released = new Set<string>();

  markReleased(internetMessageId?: string) { if (internetMessageId) this.released.add(internetMessageId); }
  clearReleased(internetMessageId?: string) { if (internetMessageId) this.released.delete(internetMessageId); }
  isReleased(internetMessageId?: string) { return Boolean(internetMessageId && this.released.has(internetMessageId)); }

  saveMessage(m: Message) {
    // A message keeps the same internetMessageId even when Graph re-IDs it after a
    // folder move (e.g. after a release). Collapse any existing copy under the old
    // Graph id so the Message Log shows one entry, not a duplicate.
    if (m.internetMessageId) {
      for (const [oldId, existing] of this.messages) {
        if (oldId !== m.id && existing.internetMessageId === m.internetMessageId) {
          const oldA = this.analyses.get(oldId);
          if (oldA) { this.analyses.delete(oldId); if (!this.analyses.has(m.id)) this.analyses.set(m.id, { ...oldA, messageId: m.id }); }
          this.messages.delete(oldId);
        }
      }
    }
    this.messages.set(m.id, m); return m;
  }
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
