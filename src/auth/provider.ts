// Where identities come from. Mock = offline persona buttons. Entra = real
// "Sign in with Microsoft" OIDC authorization-code flow against the same
// multi-tenant app used for consent. Same swap pattern as directory/consent.

import { randomBytes } from 'node:crypto';
import { config } from '../config';
import { listCustomers, getCustomer } from '../onboarding';
import { getConnection } from '../consent';
import type { Identity } from './identity';

export interface Persona { id: string; label: string; }

export interface AuthProvider {
  // Mock only: the list of one-click sign-in personas.
  personas(): Persona[];
  // Mock only: resolve a persona directly to an identity (no redirect).
  identityForPersona(personaId: string): Identity | null;
  // Entra only: build the authorize URL to redirect the user to.
  authorizeUrl(state: string): string;
  // Entra only: exchange the returned code for an identity.
  exchangeCode(code: string): Promise<Identity>;
}

export class MockAuthProvider implements AuthProvider {
  personas(): Persona[] {
    const out: Persona[] = [{ id: 'partner', label: 'Casey Alvarez — Partner (MSP)' }];
    for (const c of listCustomers()) {
      if (getConnection(c.id)?.status === 'connected') {
        out.push({ id: c.id, label: `${c.name} — Administrator` });
      }
    }
    return out;
  }
  identityForPersona(personaId: string): Identity | null {
    if (personaId === 'partner') {
      return { sub: 'u-partner', email: 'casey@partner-msp.com', name: 'Casey Alvarez', tenantId: config.auth.partnerTenantId };
    }
    const c = getCustomer(personaId);
    const conn = getConnection(personaId);
    if (!c || conn?.status !== 'connected' || !conn.entraTenantId) return null;
    return { sub: `u-${c.id}-admin`, email: `admin@${c.primaryDomain}`, name: `${c.name} Admin`, tenantId: conn.entraTenantId };
  }
  authorizeUrl(): string { throw new Error('authorizeUrl is Entra-only'); }
  async exchangeCode(): Promise<Identity> { throw new Error('exchangeCode is Entra-only'); }
}

export class EntraAuthProvider implements AuthProvider {
  private redirectUri = `${config.publicBaseUrl}/auth/callback`;

  personas(): Persona[] { return []; }
  identityForPersona(): Identity | null { return null; }

  authorizeUrl(state: string): string {
    const params = new URLSearchParams({
      client_id: config.graph.clientId,
      response_type: 'code',
      redirect_uri: this.redirectUri,
      response_mode: 'query',
      scope: 'openid profile email',
      state,
    });
    // `organizations` = any work/school account; the tid claim tells us which.
    return `https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?${params}`;
  }

  async exchangeCode(code: string): Promise<Identity> {
    const body = new URLSearchParams({
      client_id: config.graph.clientId,
      client_secret: config.graph.clientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
      scope: 'openid profile email',
    });
    const res = await fetch('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
    });
    if (!res.ok) throw new Error(`token exchange failed ${res.status}: ${await res.text()}`);
    const json = (await res.json()) as { id_token: string };
    // Decode the id_token claims. PRODUCTION MUST validate the signature against
    // Microsoft's JWKS and check iss/aud/nonce; decoding alone is not enough.
    const claims = JSON.parse(Buffer.from(json.id_token.split('.')[1], 'base64').toString('utf8'));
    return {
      sub: claims.sub,
      email: claims.email ?? claims.preferred_username,
      name: claims.name ?? claims.preferred_username,
      tenantId: claims.tid,
    };
  }

  static genState() { return randomBytes(16).toString('hex'); }
}

export function makeAuthProvider(): AuthProvider {
  return config.auth.provider === 'entra' ? new EntraAuthProvider() : new MockAuthProvider();
}
