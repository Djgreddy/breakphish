// Turn an authenticated identity into a platform role + scope, using the Entra
// `tid` claim:
//   - tid === the MSP's own tenant        → Partner admin (sees all customers)
//   - tid === a customer's connected tenant → that customer's Administrator
//   - anything else                         → not provisioned (no access)

import { config } from '../config';
import { listCustomers } from '../onboarding';
import { getConnection } from '../consent';
import type { Identity, Role } from './identity';

export interface RoleResult {
  role: Role;
  customerId?: string;
}

export function resolveRole(identity: Identity): RoleResult | null {
  // Debug: shows exactly what Microsoft sent vs what's configured. Remove later.
  console.log('[auth] resolveRole  tid=%o  configuredPartner=%o  email=%o',
    identity.tenantId, config.auth.partnerTenantId, identity.email);
  if (identity.tenantId === config.auth.partnerTenantId) {
    return { role: 'partner_admin' };
  }
  // Find the customer whose connected Entra tenant matches this identity's tid.
  for (const c of listCustomers()) {
    const conn = getConnection(c.id);
    if (conn?.entraTenantId && conn.entraTenantId === identity.tenantId) {
      return { role: 'administrator', customerId: c.id };
    }
  }
  return null; // identity belongs to no tenant we know — deny
}
