// Darktrace-style behavioral baseline. Builds a per-tenant "pattern of life" from
// message history: who each org normally corresponds with, how often, and whether
// it's two-way. New feeds two signals into detection:
//   - first_contact: inbound mail from an address the org has never heard from
//   - trust discount: established two-way correspondents get their risk dampened
//     (reduces false positives on normal business mail)
//
// It learns continuously (every scored message updates the model) and is rebuilt
// from stored history on boot. Pure data + algorithm — no external calls.

import type { Message, Signal } from './types';
import { emailStore } from './store';
import { dbEnabled, q } from '../db/db';

interface SenderStat { count: number; inbound: number; outbound: number; firstSeen: string; lastSeen: string; replied: boolean }
const tenants = new Map<string, Map<string, SenderStat>>();

// Admin overrides of the baseline's trust judgment: 'trusted' | 'untrusted'.
const overrides = new Map<string, 'trusted' | 'untrusted'>();
const ovKey = (t: string, a: string) => `${t}:${a.toLowerCase()}`;
export function getOverride(tenantId: string, addr: string) { return overrides.get(ovKey(tenantId, addr)); }
export async function setSenderOverride(tenantId: string, addr: string, value: 'trusted' | 'untrusted' | 'reset'): Promise<void> {
  const k = ovKey(tenantId, addr); addr = addr.toLowerCase();
  if (value === 'reset') {
    overrides.delete(k);
    if (dbEnabled()) await q('delete from sender_overrides where customer_id=$1 and sender=$2', [tenantId, addr]);
  } else {
    overrides.set(k, value);
    if (dbEnabled()) await q(`insert into sender_overrides (customer_id,sender,override,updated_at) values ($1,$2,$3,now()) on conflict (customer_id,sender) do update set override=excluded.override, updated_at=now()`, [tenantId, addr, value]);
  }
}

function correspondentOf(m: Message): string {
  // the external party: for outbound it's the recipient, otherwise the sender
  return (m.direction === 'outbound' ? m.to : m.fromAddress || '').toLowerCase();
}

export function learn(m: Message): void {
  const addr = correspondentOf(m); if (!addr) return;
  let t = tenants.get(m.tenantId); if (!t) { t = new Map(); tenants.set(m.tenantId, t); }
  let st = t.get(addr);
  if (!st) { st = { count: 0, inbound: 0, outbound: 0, firstSeen: m.receivedAt, lastSeen: m.receivedAt, replied: false }; t.set(addr, st); }
  st.count++;
  if (m.direction === 'outbound') { st.outbound++; st.replied = true; } else st.inbound++;
  if (m.receivedAt < st.firstSeen) st.firstSeen = m.receivedAt;
  if (m.receivedAt > st.lastSeen) st.lastSeen = m.receivedAt;
}

export function senderStat(tenantId: string, addr: string): SenderStat | undefined {
  return tenants.get(tenantId)?.get(addr.toLowerCase());
}

// Is this inbound sender an established, trusted two-way correspondent?
// An admin override wins over the learned judgment.
export function isEstablished(tenantId: string, addr: string): boolean {
  const ov = getOverride(tenantId, addr);
  if (ov === 'trusted') return true;
  if (ov === 'untrusted') return false;
  const st = senderStat(tenantId, addr);
  return !!st && st.replied && st.count >= 3;
}

// Signal(s) from the baseline. Called BEFORE learn(), so stats reflect prior mail.
export function baselineScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  const ov = getOverride(m.tenantId, m.fromAddress);
  if (ov === 'trusted') return [];
  if (ov === 'untrusted') return [{ code: 'admin_watch', detail: 'Admin flagged this sender for extra scrutiny', category: 'phishing', weight: 25 }];
  const st = senderStat(m.tenantId, m.fromAddress);
  if (!st || st.inbound === 0) {
    return [{ code: 'first_contact', detail: 'First-time sender — no prior correspondence with this address', category: 'phishing', weight: 12 }];
  }
  return [];
}

// Human-readable reason the baseline is treating a sender a certain way (for the UI).
export function baselineReason(tenantId: string, addr: string): string {
  const ov = getOverride(tenantId, addr);
  if (ov === 'trusted') return 'Admin-trusted';
  if (ov === 'untrusted') return 'Admin-watch';
  if (isEstablished(tenantId, addr)) return 'Trusted correspondent';
  const st = senderStat(tenantId, addr);
  if (!st || st.inbound === 0) return 'First-time sender';
  return 'Known sender';
}

// Everything the baseline has learned about a tenant's senders (for the admin page).
export function listSenderIntel(tenantId: string) {
  const m = tenants.get(tenantId);
  const rows = m ? [...m.entries()].map(([sender, st]) => ({
    sender, count: st.count, inbound: st.inbound, outbound: st.outbound,
    firstSeen: st.firstSeen, lastSeen: st.lastSeen,
    override: getOverride(tenantId, sender) ?? null,
    trusted: isEstablished(tenantId, sender),
    reason: baselineReason(tenantId, sender),
  })) : [];
  return rows.sort((a, b) => b.count - a.count);
}

export async function hydrateSenderOverrides(): Promise<number> {
  if (!dbEnabled()) return 0;
  const rows = await q<any>('select customer_id, sender, override from sender_overrides');
  for (const r of rows) overrides.set(ovKey(r.customer_id, r.sender), r.override);
  return rows.length;
}

export function hydrateBaseline(): number {
  tenants.clear();
  for (const m of emailStore.messages.values()) learn(m);
  let n = 0; for (const t of tenants.values()) n += t.size;
  return n;
}
