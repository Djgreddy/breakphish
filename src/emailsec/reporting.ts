// Reporting views that back the customer dashboard and the Live Email Tracker.

import { emailStore } from './store';
import type { Verdict } from './types';

const THREAT_VERDICTS: Verdict[] = ['phishing', 'malware', 'impersonation'];

export function dashboard(tenantId: string) {
  const analyses = emailStore.analysesForTenant(tenantId);
  const processed = analyses.length;
  const clean = analyses.filter(a => a.verdict === 'clean').length;
  const nonClean = processed - clean;
  const threats = analyses.filter(a => THREAT_VERDICTS.includes(a.verdict)).length;
  const remediated = analyses.filter(a => a.remediated).length;

  // Breakdown of non-clean emails by verdict.
  const breakdown: Record<string, number> = {};
  for (const a of analyses) {
    if (a.verdict === 'clean') continue;
    breakdown[a.verdict] = (breakdown[a.verdict] ?? 0) + 1;
  }

  return { processed, clean, nonClean, threats, remediated, breakdown };
}

export function liveTracker(tenantId: string) {
  const msgs = emailStore.messagesForTenant(tenantId);
  return msgs
    .map(m => {
      const a = emailStore.analysisFor(m.id)!;
      return {
        id: m.id,
        at: m.receivedAt,
        from: m.fromAddress,
        to: m.to,
        subject: m.subject,
        verdict: a.verdict,
        status: a.disposition,
        source: m.source,
        direction: m.direction,
      };
    })
    .sort((x, y) => (x.at < y.at ? 1 : -1));
}

export function pendingReleaseCount(tenantId: string) {
  return emailStore.releaseRequests.filter(r => r.tenantId === tenantId && r.status === 'pending').length;
}
