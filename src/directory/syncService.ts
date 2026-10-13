// Pulls a snapshot from the configured provider and reconciles it into the
// store: upserts users and groups, applies delta tombstones, keeps a per-tenant
// deltaLink for the next incremental run.

import { store } from '../store';
import { config } from '../config';
import type { DirectoryProvider, DirSnapshot } from './provider';
import { MockDirectoryProvider } from './mockProvider';
import { GraphDirectoryProvider } from './graphProvider';
import { persistTenantDirectory } from '../db/hydrate';

const deltaLinks = new Map<string, string>(); // tenantId -> cursor

function provider(): DirectoryProvider {
  return config.directoryProvider === 'graph'
    ? new GraphDirectoryProvider()
    : new MockDirectoryProvider();
}

function apply(tenantId: string, snap: DirSnapshot) {
  const t = store.getTenant(tenantId)!;
  let users = 0, groups = 0;

  for (const u of snap.users) {
    if (u.removed) {
      const existing = store.userByExternalId(tenantId, u.externalId);
      if (existing) store.upsertUser({ ...existing, enabled: false }); // archive, keep history
      continue;
    }
    // Enforce that synced users fall inside the tenant's verified domains.
    const domain = u.email.split('@')[1]?.toLowerCase();
    if (domain && t.verifiedDomains.length && !t.verifiedDomains.includes(domain)) continue;
    store.upsertUser({
      tenantId, externalId: u.externalId, email: u.email,
      displayName: u.displayName, department: u.department, enabled: u.enabled,
    });
    users++;
  }

  for (const g of snap.groups) {
    if (g.removed) continue;
    store.upsertGroup({
      tenantId, externalId: g.externalId, name: g.name,
      memberExternalIds: g.memberExternalIds,
    });
    groups++;
  }

  if (snap.deltaLink) deltaLinks.set(tenantId, snap.deltaLink);
  return { users, groups };
}

export async function syncTenant(tenantId: string): Promise<{ users: number; groups: number; mode: 'full' | 'delta' }> {
  const t = store.getTenant(tenantId);
  if (!t) throw new Error(`unknown tenant ${tenantId}`);
  const cursor = deltaLinks.get(tenantId);
  const p = provider();
  let result: { users: number; groups: number; mode: 'full' | 'delta' };
  if (cursor) {
    const snap = await p.deltaSync(t.entraTenantId ?? '', cursor);
    result = { ...apply(tenantId, snap), mode: 'delta' };
  } else {
    const snap = await p.fullSync(t.entraTenantId ?? '');
    result = { ...apply(tenantId, snap), mode: 'full' };
  }
  await persistTenantDirectory(tenantId); // durably store synced users/groups
  return result;
}
