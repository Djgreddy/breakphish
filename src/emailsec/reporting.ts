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
  // Consolidate copies of the same logical message (same internetMessageId delivered
  // to multiple mailboxes, e.g. a distribution group) into ONE row, collecting all
  // recipient mailboxes. Per-copy storage is kept for digests/dedupe; this is display.
  const groups = new Map<string, { m: any; a: any; recipients: Set<string> }>();
  for (const m of msgs) {
    const a = emailStore.analysisFor(m.id);
    if (!a) continue; // saved but not yet scored — skip (don't crash the log)
    const key = m.internetMessageId || m.id;
    let g = groups.get(key);
    if (!g) { g = { m, a, recipients: new Set() }; groups.set(key, g); }
    if (m.to) g.recipients.add(m.to);
    // keep the newest copy as representative
    if (m.receivedAt > g.m.receivedAt) { g.m = m; g.a = a; }
  }
  return [...groups.values()]
    .map(({ m, a, recipients }) => {
      const released = a.disposition === 'deliver' && (a.releasedManually || emailStore.isReleased(m.internetMessageId));
      const recips = [...recipients];
      return {
        id: m.id,
        at: m.receivedAt,
        from: m.fromAddress ?? '',
        to: recips[0] ?? (m.to ?? ''),
        toHeader: m.toHeader ?? '',   // original addressed-to (e.g. the distro group)
        recipients: recips,
        recipientCount: recips.length,
        subject: m.subject ?? '',
        verdict: a.verdict,
        status: released ? 'released' : a.disposition,
        source: m.source,
        direction: m.direction,
      };
    })
    .sort((x, y) => (x.at < y.at ? 1 : -1));
}

export function pendingReleaseCount(tenantId: string) {
  return emailStore.releaseRequests.filter(r => r.tenantId === tenantId && r.status === 'pending').length;
}
