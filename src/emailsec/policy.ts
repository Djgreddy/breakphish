// Per-tenant policy: what disposition each verdict gets. In the product this is
// the Policy page; here it's a default map plus optional per-tenant overrides.

import type { Verdict, Disposition } from './types';

export interface Policy {
  dispositions: Record<Verdict, Disposition>;
  // Verdicts that, when acted on post-delivery, count as a remediation clawback.
  remediateOn: Verdict[];
}

export const DEFAULT_POLICY: Policy = {
  dispositions: {
    clean: 'deliver',
    spam_likely: 'deliver',      // delivered but tagged
    spam: 'junk',
    policy_infomail: 'junk',
    policy_geo: 'quarantine',
    phishing: 'quarantine',
    impersonation: 'quarantine',
    malware: 'quarantine',
  },
  remediateOn: ['phishing', 'impersonation', 'malware', 'policy_geo'],
};

const perTenant = new Map<string, Policy>();

export function policyFor(tenantId: string): Policy {
  return perTenant.get(tenantId) ?? DEFAULT_POLICY;
}
export function setPolicy(tenantId: string, p: Policy) { perTenant.set(tenantId, p); }
