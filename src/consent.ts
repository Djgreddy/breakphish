// Microsoft Entra admin-consent flow for onboarding a customer's M365 tenant.
//
// Flow:
//   1. buildConsentUrl(customerId) → the admin opens this; Microsoft shows the
//      permissions our multi-tenant app requests and asks a Global Admin to grant.
//   2. Microsoft redirects back to our callback with admin_consent + tenant + state.
//   3. handleConsentCallback(...) validates state, stores the connection, then
//      verifies it by reading the org profile (display name + verified domains).
//
// The granular scope list below documents exactly what we ask for and why; the
// consent URL itself uses `.default`, which grants the app's configured
// permissions. Read-only for directory; Mail.ReadWrite only when the customer
// bought Email Security (needed to remediate/quarantine delivered mail).

import { randomUUID, randomBytes } from 'node:crypto';
import { config } from './config';
import { getCustomer } from './onboarding';
import type { Product } from './emailsec/types';
import { makeOrgVerifier } from './directory/graphOrg';
import { dbEnabled } from './db/db';
import { upsertConnection, loadConnections } from './db/persist';

function persistConn(customerId: string, c: TenantConnection): Promise<void> | void {
  if (!dbEnabled()) return;
  return upsertConnection(customerId, {
    entraTenantId: c.entraTenantId, status: c.status, reason: c.reason,
    displayName: c.displayName, verifiedDomains: c.verifiedDomains,
    grantedScopes: c.grantedScopes, connectedAt: c.connectedAt,
  });
}

// Load persisted connections on boot.
export async function hydrateConnections(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await loadConnections();
  for (const r of rows) {
    connections.set(r.customer_id, {
      customerId: r.customer_id, entraTenantId: r.entra_tenant_id ?? undefined,
      status: r.status as TenantConnection['status'], reason: r.reason ?? undefined,
      displayName: r.display_name ?? undefined, verifiedDomains: r.verified_domains ?? [],
      grantedScopes: r.granted_scopes ?? [], connectedAt: r.connected_at ?? undefined,
    });
  }
  return rows.length;
}

export const GRAPH_PERMISSIONS: Record<string, { scopes: string[]; why: string }> = {
  directory: {
    scopes: ['User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Organization.Read.All'],
    why: 'Sync users and groups for targeting and reporting (read-only).',
  },
  email_security: {
    scopes: ['Mail.Read', 'Mail.ReadWrite'],
    why: 'Read inbound mail to score it, and move/remediate confirmed threats.',
  },
};

export function scopesForProducts(products: Product[]): { scope: string; why: string }[] {
  const keys = ['directory', ...(products.includes('email_security') ? ['email_security'] : [])];
  return keys.flatMap(k => GRAPH_PERMISSIONS[k].scopes.map(scope => ({ scope, why: GRAPH_PERMISSIONS[k].why })));
}

export interface TenantConnection {
  customerId: string;
  entraTenantId?: string;
  status: 'pending' | 'connected' | 'failed';
  reason?: string;
  displayName?: string;
  verifiedDomains?: string[];
  grantedScopes: string[];
  connectedAt?: string;
}

const connections = new Map<string, TenantConnection>();        // customerId -> connection
const pendingStates = new Map<string, { customerId: string; createdAt: number }>();

// Build the admin-consent URL. `organizations` disallows personal accounts.
export function buildConsentUrl(customerId: string): { url: string; state: string; requested: { scope: string; why: string }[] } {
  const customer = getCustomer(customerId);
  if (!customer) throw new Error(`unknown customer ${customerId}`);

  const state = randomBytes(16).toString('hex');
  pendingStates.set(state, { customerId, createdAt: Date.now() });
  const pending = { customerId, status: 'pending' as const, grantedScopes: [] };
  connections.set(customerId, pending);
  void Promise.resolve(persistConn(customerId, pending)).catch(e => console.error('[db] persist connection', e));

  const requested = scopesForProducts(customer.products);
  const params = new URLSearchParams({
    client_id: config.graph.clientId,
    scope: 'https://graph.microsoft.com/.default',
    redirect_uri: config.graph.redirectUri,
    state,
  });
  const url = `https://login.microsoftonline.com/organizations/v2.0/adminconsent?${params}`;
  return { url, state, requested };
}

export interface ConsentCallbackResult {
  ok: boolean;
  customerId?: string;
  connection?: TenantConnection;
  error?: string;
}

// Handle the redirect back from Microsoft. On success it finishes by verifying
// the connection against Graph (mock or real).
export async function handleConsentCallback(query: Record<string, string | undefined>): Promise<ConsentCallbackResult> {
  const state = query.state;
  if (!state || !pendingStates.has(state)) {
    return { ok: false, error: 'Invalid or expired state — restart consent.' };
  }
  const { customerId } = pendingStates.get(state)!;
  pendingStates.delete(state);
  const customer = getCustomer(customerId);

  // Admin declined or an error occurred.
  if (query.error) {
    const conn: TenantConnection = {
      customerId, status: 'failed', grantedScopes: [],
      reason: `${query.error}: ${query.error_description ?? 'consent not granted'}`,
    };
    connections.set(customerId, conn);
    await persistConn(customerId, conn);
    return { ok: false, customerId, connection: conn, error: conn.reason };
  }

  const entraTenantId = query.tenant;
  if (query.admin_consent !== 'True' || !entraTenantId) {
    const conn: TenantConnection = { customerId, status: 'failed', grantedScopes: [], reason: 'Consent not completed.' };
    connections.set(customerId, conn);
    await persistConn(customerId, conn);
    return { ok: false, customerId, connection: conn, error: conn.reason };
  }

  // Consent granted — verify by reading the org profile.
  try {
    const org = await makeOrgVerifier().getOrganization(entraTenantId, { name: customer?.name, domain: customer?.primaryDomain });
    const conn: TenantConnection = {
      customerId, entraTenantId, status: 'connected',
      displayName: org.displayName, verifiedDomains: org.verifiedDomains,
      grantedScopes: (customer ? scopesForProducts(customer.products) : []).map(s => s.scope),
      connectedAt: new Date().toISOString(),
    };
    connections.set(customerId, conn);
    await persistConn(customerId, conn);
    return { ok: true, customerId, connection: conn };
  } catch (e) {
    const conn: TenantConnection = {
      customerId, entraTenantId, status: 'failed', grantedScopes: [],
      reason: `Consent granted but verification failed: ${(e as Error).message}`,
    };
    connections.set(customerId, conn);
    await persistConn(customerId, conn);
    return { ok: false, customerId, connection: conn, error: conn.reason };
  }
}

export function getConnection(customerId: string): TenantConnection | undefined {
  return connections.get(customerId);
}
