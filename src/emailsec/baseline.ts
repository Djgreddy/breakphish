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

interface SenderStat { count: number; inbound: number; outbound: number; firstSeen: string; lastSeen: string; replied: boolean }
const tenants = new Map<string, Map<string, SenderStat>>();

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
export function isEstablished(tenantId: string, addr: string): boolean {
  const st = senderStat(tenantId, addr);
  return !!st && st.replied && st.count >= 3;
}

// Signal(s) from the baseline. Called BEFORE learn(), so stats reflect prior mail.
export function baselineScorer(m: Message): Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  const st = senderStat(m.tenantId, m.fromAddress);
  if (!st || st.inbound === 0) {
    // brand-new sender — a mild amplifier that escalates when combined with risky content
    return [{ code: 'first_contact', detail: 'First-time sender — no prior correspondence with this address', category: 'phishing', weight: 12 }];
  }
  return [];
}

export function hydrateBaseline(): number {
  tenants.clear();
  for (const m of emailStore.messages.values()) learn(m);
  let n = 0; for (const t of tenants.values()) n += t.size;
  return n;
}
