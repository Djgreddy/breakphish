// After a customer admin consents, we confirm the connection actually works by
// reading their organization profile from Graph. This also returns the tenant's
// VERIFIED domains, which anchors the anti-abuse rule (we only ever target
// addresses inside a verified domain).
//
// Like the directory provider, there's a mock (offline) and a real Graph impl.

import { config } from '../config';
import { appToken } from './graphProvider';

export interface OrgProfile {
  displayName: string;
  verifiedDomains: string[];
}

export interface OrgVerifier {
  getOrganization(entraTenantId: string, hint?: { name?: string; domain?: string }): Promise<OrgProfile>;
}

export class MockOrgVerifier implements OrgVerifier {
  async getOrganization(_tid: string, hint?: { name?: string; domain?: string }): Promise<OrgProfile> {
    return {
      displayName: hint?.name ?? 'Connected Organization',
      verifiedDomains: hint?.domain ? [hint.domain] : ['example.com'],
    };
  }
}

export class GraphOrgVerifier implements OrgVerifier {
  async getOrganization(entraTenantId: string): Promise<OrgProfile> {
    const token = await appToken(entraTenantId);
    const res = await fetch(
      'https://graph.microsoft.com/v1.0/organization?$select=displayName,verifiedDomains',
      { headers: { authorization: `Bearer ${token}` } },
    );
    if (!res.ok) throw new Error(`organization read failed ${res.status}: ${await res.text()}`);
    const json = (await res.json()) as { value: Array<{ displayName: string; verifiedDomains: Array<{ name: string }> }> };
    const org = json.value[0];
    // Every entry in Graph's verifiedDomains is already verified — there is no
    // `isVerified` field to filter on (filtering on it dropped them all, which
    // left the allowlist empty and filtered out every synced user).
    return {
      displayName: org.displayName,
      verifiedDomains: (org.verifiedDomains ?? []).map(d => d.name),
    };
  }
}

export function makeOrgVerifier(): OrgVerifier {
  return config.directoryProvider === 'graph' ? new GraphOrgVerifier() : new MockOrgVerifier();
}
