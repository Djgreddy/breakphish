// Real Microsoft Graph provider. Not exercised by the offline demo, but this is
// the production code path. It uses the multi-tenant app's client-credentials
// flow against the CLIENT's tenant id, then reads users/groups with delta
// queries. In production, prefer certificate auth over a client secret and store
// it in a vault keyed by tenant.

import type { DirectoryProvider, DirSnapshot, DirUser, DirGroup } from './provider';
import { config } from '../config';

const GRAPH = 'https://graph.microsoft.com/v1.0';

export async function appToken(entraTenantId: string): Promise<string> {
  const url = `https://login.microsoftonline.com/${entraTenantId}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: config.graph.clientId,
    client_secret: config.graph.clientSecret, // swap for client_assertion (cert) in prod
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials',
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) throw new Error(`token error ${res.status}: ${await res.text()}`);
  const json = (await res.json()) as { access_token: string };
  return json.access_token;
}

// Follows @odata.nextLink paging and returns the final @odata.deltaLink.
async function pageAll(startUrl: string, token: string): Promise<{ items: any[]; deltaLink?: string }> {
  let url: string | undefined = startUrl;
  const items: any[] = [];
  let deltaLink: string | undefined;
  while (url) {
    const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
    if (res.status === 429) { // throttled — honour Retry-After
      const wait = Number(res.headers.get('retry-after') ?? '2') * 1000;
      await new Promise(r => setTimeout(r, wait));
      continue;
    }
    if (!res.ok) throw new Error(`graph error ${res.status}: ${await res.text()}`);
    const json: any = await res.json();
    items.push(...(json.value ?? []));
    url = json['@odata.nextLink'];
    deltaLink = json['@odata.deltaLink'] ?? deltaLink;
  }
  return { items, deltaLink };
}

function mapUser(u: any): DirUser {
  return {
    externalId: u.id,
    email: u.mail ?? u.userPrincipalName,
    displayName: u.displayName,
    department: u.department ?? undefined,
    enabled: u.accountEnabled ?? true,
    removed: Boolean(u['@removed']),
  };
}

export class GraphDirectoryProvider implements DirectoryProvider {
  async fullSync(entraTenantId: string): Promise<DirSnapshot> {
    const token = await appToken(entraTenantId);
    const userPage = await pageAll(
      `${GRAPH}/users/delta?$select=id,displayName,mail,userPrincipalName,department,accountEnabled`,
      token,
    );
    const groupPage = await pageAll(`${GRAPH}/groups?$select=id,displayName`, token);

    const groups: DirGroup[] = [];
    for (const g of groupPage.items) {
      const members = await pageAll(`${GRAPH}/groups/${g.id}/members?$select=id`, token);
      groups.push({
        externalId: g.id,
        name: g.displayName,
        memberExternalIds: members.items.map((m: any) => m.id),
      });
    }
    return { users: userPage.items.map(mapUser), groups, deltaLink: userPage.deltaLink };
  }

  async deltaSync(entraTenantId: string, deltaLink: string): Promise<DirSnapshot> {
    const token = await appToken(entraTenantId);
    try {
      const userPage = await pageAll(deltaLink, token);
      // Groups would be pulled with /groups/delta in the same manner.
      return { users: userPage.items.map(mapUser), groups: [], deltaLink: userPage.deltaLink };
    } catch (e) {
      // An expired or invalid deltaLink requires restarting with a FULL sync — this is
      // Microsoft's documented resync pattern. Without this, directory sync fails
      // entirely (0 users), which breaks all mail scanning downstream.
      const msg = (e as Error).message;
      if (/Invalid deltaLink|Request_UnsupportedQuery|resync|\b410\b|\b400\b/i.test(msg)) {
        console.warn('[graph] deltaLink invalid — falling back to full directory sync');
        return this.fullSync(entraTenantId);
      }
      throw e;
    }
  }
}
