// Partner team members — the MSP's own staff who use the console. Two kinds:
//   - sso:   authenticate via Microsoft Entra SSO (the existing login path)
//   - local: email + password + MFA (stored here; the local password/TOTP login
//            path itself is a follow-up, so these are provisioned as invited)
//
// Stored and hydrated like the other stores.

import { randomUUID } from 'node:crypto';
import { dbEnabled, q } from './db/db';

export type TeamRole = 'partner_admin' | 'analyst' | 'read_only';
export interface TeamMember {
  id: string; email: string; name: string; role: TeamRole;
  authType: 'local' | 'sso'; mfaEnabled: boolean; status: 'active' | 'invited'; createdAt: string;
}

const members = new Map<string, TeamMember>();

export function listTeam(): TeamMember[] {
  return [...members.values()].sort((a, b) => a.createdAt < b.createdAt ? -1 : 1);
}
export function getTeamByEmail(email: string) {
  return [...members.values()].find(m => m.email.toLowerCase() === email.toLowerCase());
}

export async function saveTeamMember(input: Partial<TeamMember> & { email: string; name: string }): Promise<TeamMember> {
  const existing = input.id ? members.get(input.id)
    : [...members.values()].find(m => m.email.toLowerCase() === input.email.toLowerCase());
  const m: TeamMember = {
    id: existing?.id ?? input.id ?? randomUUID(),
    email: input.email.toLowerCase().trim(),
    name: input.name,
    role: (input.role ?? existing?.role ?? 'analyst') as TeamRole,
    authType: (input.authType ?? existing?.authType ?? 'sso'),
    mfaEnabled: input.mfaEnabled ?? existing?.mfaEnabled ?? false,
    // Local members start "invited" until the local login path is enabled; SSO are active immediately.
    status: input.status ?? existing?.status ?? ((input.authType ?? 'sso') === 'local' ? 'invited' : 'active'),
    createdAt: existing?.createdAt ?? new Date().toISOString(),
  };
  members.set(m.id, m);
  if (dbEnabled()) {
    await q(
      `insert into team_members (id,email,name,role,auth_type,mfa_enabled,status,created_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8)
       on conflict (id) do update set email=excluded.email, name=excluded.name, role=excluded.role,
         auth_type=excluded.auth_type, mfa_enabled=excluded.mfa_enabled, status=excluded.status`,
      [m.id, m.email, m.name, m.role, m.authType, m.mfaEnabled, m.status, m.createdAt],
    );
  }
  return m;
}

export async function deleteTeamMember(id: string): Promise<void> {
  members.delete(id);
  if (dbEnabled()) await q('delete from team_members where id=$1', [id]);
}

export async function hydrateTeam(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await q<any>('select * from team_members');
  for (const r of rows) members.set(r.id, {
    id: r.id, email: r.email, name: r.name, role: r.role,
    authType: r.auth_type ?? 'sso', mfaEnabled: r.mfa_enabled ?? false, status: r.status ?? 'active',
    createdAt: (r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at),
  });
  return rows.length;
}
