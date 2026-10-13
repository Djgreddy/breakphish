// New-customer onboarding. Mirrors the wizard: pick mail platform + service,
// enter details, create the tenant with its product entitlements. The API
// service is live; Gateway and Unified are gated as coming-soon.

import { store } from './store';
import type { Tenant } from './types';
import type { Product, IntegrationModel } from './emailsec/types';
import { INTEGRATION_AVAILABILITY } from './emailsec/types';
import { dbEnabled } from './db/db';
import { upsertCustomer, loadCustomers } from './db/persist';

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

export interface Customer extends Tenant {
  primaryDomain: string;
  products: Product[];
  integrationModel?: IntegrationModel;
  mailboxes: number;
  createdAt: string;
}

const customers = new Map<string, Customer>();

function persist(c: Customer): Promise<void> | void {
  if (!dbEnabled()) return;
  return upsertCustomer({
    id: c.id, name: c.name, primaryDomain: c.primaryDomain, entraTenantId: c.entraTenantId,
    verifiedDomains: c.verifiedDomains, products: c.products, integrationModel: c.integrationModel,
    mailboxes: c.mailboxes, status: 'active',
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
    createdAt: new Date().toISOString(),
  };
  customers.set(id, customer);
  await persist(customer);
  return customer;
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
      createdAt: new Date().toISOString(),
    });
  }
  return rows.length;
}
