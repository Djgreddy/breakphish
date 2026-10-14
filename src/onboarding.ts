// New-customer onboarding. Mirrors the wizard: pick mail platform + service,
// enter details, create the tenant with its product entitlements. The API
// service is live; Gateway and Unified are gated as coming-soon.

import { store } from './store';
import type { Tenant } from './types';
import type { Product, IntegrationModel } from './emailsec/types';
import { INTEGRATION_AVAILABILITY } from './emailsec/types';
import { dbEnabled, q } from './db/db';
import { upsertCustomer, loadCustomers } from './db/persist';
import { emailStore } from './emailsec/store';

export interface OnboardInput {
  name: string;
  primaryDomain: string;
  entraTenantId?: string;
  products: Product[];                 // sat, email_security, or both
  integrationModel?: IntegrationModel; // required when email_security is chosen
  mailboxes?: number;
}

export class ComingSoonError extends Error {
  constructor(public model: IntegrationModel) {
    super(`The "${model}" service is coming soon and can't be provisioned yet. Choose the API service.`);
  }
}

export interface CustomerFlags {
  partnerAccess: boolean;
  customerBanners: boolean;
  analyticsReports: boolean;
  require2fa: boolean;
  forceAzureLogin: boolean;
}
export const DEFAULT_FLAGS: CustomerFlags = {
  partnerAccess: true, customerBanners: false, analyticsReports: false,
  require2fa: true, forceAzureLogin: true, // all sign-in is already Azure SSO
};

export interface Customer extends Tenant {
  primaryDomain: string;
  products: Product[];
  integrationModel?: IntegrationModel;
  mailboxes: number;
  licenses: number;
  orderedAt: string;
  flags: CustomerFlags;
  createdAt: string;
}

const customers = new Map<string, Customer>();

function persist(c: Customer): Promise<void> | void {
  if (!dbEnabled()) return;
  return upsertCustomer({
    id: c.id, name: c.name, primaryDomain: c.primaryDomain, entraTenantId: c.entraTenantId,
    verifiedDomains: c.verifiedDomains, products: c.products, integrationModel: c.integrationModel,
    mailboxes: c.mailboxes, status: 'active',
    licenses: c.licenses, orderedAt: c.orderedAt, flags: c.flags,
  });
}

// Async so creation can be durably persisted before returning.
export async function onboardCustomer(input: OnboardInput): Promise<Customer> {
  if (input.products.includes('email_security')) {
    const model = input.integrationModel;
    if (!model) throw new Error('An integration model is required for Email Security.');
    if (INTEGRATION_AVAILABILITY[model] !== 'available') throw new ComingSoonError(model);
  }

  const base = input.primaryDomain.split('.')[0];
  let id = base, n = 1;
  while (customers.has(id)) id = `${base}-${++n}`;
  const tenant: Tenant = {
    id, name: input.name, entraTenantId: input.entraTenantId,
    verifiedDomains: [input.primaryDomain.toLowerCase()],
  };
  store.upsertTenant(tenant);

  const customer: Customer = {
    ...tenant,
    primaryDomain: input.primaryDomain,
    products: input.products,
    integrationModel: input.integrationModel,
    mailboxes: input.mailboxes ?? 0,
    licenses: input.products.includes('sat') ? (input.mailboxes ?? 0) : 0,
    orderedAt: new Date().toISOString(),
    flags: { ...DEFAULT_FLAGS },
    createdAt: new Date().toISOString(),
  };
  customers.set(id, customer);
  await persist(customer);
  return customer;
}

// Edit mutable customer fields (name, licenses, feature flags).
export async function editCustomer(id: string, patch: { name?: string; licenses?: number; flags?: Partial<CustomerFlags> }): Promise<Customer | null> {
  const c = customers.get(id);
  if (!c) return null;
  if (patch.name != null) { c.name = patch.name; const t = store.getTenant(id); if (t) t.name = patch.name; }
  if (patch.licenses != null) c.licenses = Math.max(0, Math.floor(patch.licenses));
  if (patch.flags) c.flags = { ...c.flags, ...patch.flags };
  await persist(c);
  return c;
}

// Called after a real Microsoft connection resolves the true tenant id and
// verified domains — updates the customer record + its tenant and persists.
export async function markCustomerConnected(id: string, entraTenantId: string, verifiedDomains: string[]): Promise<void> {
  const c = customers.get(id);
  if (!c) return;
  c.entraTenantId = entraTenantId;
  if (verifiedDomains.length) c.verifiedDomains = verifiedDomains;
  const t = store.getTenant(id);
  if (t) { t.entraTenantId = entraTenantId; if (verifiedDomains.length) t.verifiedDomains = verifiedDomains; }
  await persist(c);
}

export function getCustomer(id: string) { return customers.get(id); }
export function listCustomers() { return [...customers.values()]; }

// Offboard a customer: wipe all its in-memory state and, when a DB is present,
// delete the customer row (which cascades to users, groups, messages, analyses,
// campaigns, etc.).
export async function deleteCustomer(id: string): Promise<void> {
  customers.delete(id);
  store.tenants.delete(id);
  for (const [k, u] of store.users) if (u.tenantId === id) store.users.delete(k);
  for (const [k, g] of store.groups) if (g.tenantId === id) store.groups.delete(k);
  for (const [k, m] of emailStore.messages) if (m.tenantId === id) emailStore.messages.delete(k);
  for (const [k, a] of emailStore.analyses) if (a.tenantId === id) emailStore.analyses.delete(k);
  if (dbEnabled()) await q('delete from customers where id=$1', [id]); // cascades
}

export function hasProduct(tenantId: string, product: Product): boolean {
  return Boolean(customers.get(tenantId)?.products.includes(product));
}

// Load persisted customers into memory on boot (and rebuild their tenants).
export async function hydrateCustomers(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await loadCustomers();
  for (const r of rows) {
    const tenant: Tenant = {
      id: r.id, name: r.name, entraTenantId: r.entra_tenant_id ?? undefined,
      verifiedDomains: r.verified_domains ?? [],
    };
    store.upsertTenant(tenant);
    customers.set(r.id, {
      ...tenant,
      primaryDomain: r.primary_domain,
      products: (r.products ?? []) as Product[],
      integrationModel: (r.integration_model ?? undefined) as IntegrationModel | undefined,
      mailboxes: r.mailboxes,
      licenses: r.licenses ?? 0,
      orderedAt: r.ordered_at ? (r.ordered_at instanceof Date ? r.ordered_at.toISOString() : r.ordered_at) : new Date().toISOString(),
      flags: { ...DEFAULT_FLAGS, ...(r.flags ?? {}) },
      createdAt: new Date().toISOString(),
    });
  }
  return rows.length;
}
