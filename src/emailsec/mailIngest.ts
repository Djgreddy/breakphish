// Reads REAL inbound mail from Microsoft Graph, normalizes each message into the
// pipeline's Message shape, and scores it with the same analyze() the demo uses.
// This is what replaces the synthetic generator for a connected tenant.
//
// It runs only in graph mode and needs the Mail.Read application permission
// (already in the consent scopes). A production build would use Graph change
// notifications (webhooks) for near-real-time; this polls, which is simpler and
// enough for a pilot.

import { appToken } from '../directory/graphProvider';
import { store } from '../store';
import { getConnection } from '../consent';
import { analyze } from './pipeline';
import { emailStore } from './store';
import { applyDisposition, prependBanner, rewriteLinks } from './mailActions';
import { getSettings } from '../settings';
import { isActive } from '../onboarding';
import { dlpMatch, hasActiveLinkRewrite } from '../policy';
import { audit } from '../audit';
import { config } from '../config';
import type { Message } from './types';

// Pick the banner for a scored message and stamp it, if the customer enabled it.
const BANNER_FOR: Record<string, string> = {
  clean: 'Clean', spam: 'Spam-Definite', spam_likely: 'Spam-Likely', phishing: 'Phishing',
  malware: 'Malware', impersonation: 'Impersonation', policy_infomail: 'Infomail', policy_geo: 'Policy-Geo',
};
async function maybeStampBanner(tenantId: string, entraTenantId: string, userId: string, ref: { graphId: string; internetMessageId?: string }, msg: Message, analysis: { verdict: string }): Promise<void> {
  const st = getSettings(tenantId);
  if (!st.bannersEnabled) return;
  if (msg.source !== 'external') return;           // only external mail
  const key = BANNER_FOR[analysis.verdict]; if (!key) return;
  const b = st.banners.verdict[key]; if (!b || !b.message) return;
  const text = b.message.replace(/\{\{sender\}\}/g, msg.fromAddress).replace(/\{\{source\}\}/g, msg.source);
  const html = `<div style="border-left:4px solid ${b.color};background:#fff8e1;color:#5c4400;padding:10px 14px;margin:0 0 10px;font-family:Segoe UI,Arial,sans-serif;font-size:13px;border-radius:4px">${text}</div>`;
  await prependBanner(entraTenantId, userId, ref, html);
}

const GRAPH = 'https://graph.microsoft.com/v1.0';

// Parse SPF/DKIM/DMARC from Authentication-Results. There can be SEVERAL of these
// headers (each hop adds one); Microsoft's own result carries compauth= and is the
// authoritative one — prefer it. compauth is Microsoft's COMPOSITE authentication:
// compauth=pass means the sender is legitimate even when raw SPF/DKIM/DMARC fail,
// which is normal for forwarded / relayed / mailing-list mail.
function authFromHeaders(headers: Array<{ name: string; value: string }> = []) {
  const ars = headers.filter(h => h.name.toLowerCase() === 'authentication-results').map(h => (h.value || '').toLowerCase());
  const ar = ars.find(a => a.includes('compauth=')) ?? ars[0] ?? '';
  const read = (k: string): 'pass' | 'fail' | 'none' =>
    ar.includes(`${k}=pass`) ? 'pass' : ar.includes(`${k}=fail`) ? 'fail' : 'none';
  const compauth = (/compauth=([a-z]+)/.exec(ar)?.[1] ?? 'none') as 'pass' | 'fail' | 'softpass' | 'none';
  return { spf: read('spf'), dkim: read('dkim'), dmarc: read('dmarc'), compauth };
}

// Microsoft stamps its own result in X-Forefront-Antispam-Report (CIP = connecting
// IP, SFV = spam filter verdict) and X-Microsoft-Antispam (BCL). Parse what's there.
function msEnrichment(headers: Array<{ name: string; value: string }> = []) {
  const h = (n: string) => headers.find(x => x.name.toLowerCase() === n.toLowerCase())?.value ?? '';
  const ffar = h('X-Forefront-Antispam-Report');
  const cip = /CIP:([0-9a-fA-F.:]+)/.exec(ffar)?.[1];
  const xorig = /\[?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]?/.exec(h('X-Originating-IP'))?.[1];
  const sfv = /SFV:([A-Z]+)/.exec(ffar)?.[1];
  const SFV: Record<string, string> = { NSPM: 'Not Spam', SPM: 'Spam', SKS: 'Skipped (rule)', BLK: 'Blocked', SKI: 'Skipped', SKN: 'Not Spam (allow)', SKQ: 'Released' };
  const bcl = /BCL:(\d+)/.exec(h('X-Microsoft-Antispam'))?.[1];
  let msVerdict = sfv ? (SFV[sfv] ?? sfv) : '';
  if (!msVerdict && bcl && Number(bcl) > 0) msVerdict = `Bulk (BCL ${bcl})`;
  const ctry = /CTRY:([A-Z]{2})/.exec(ffar)?.[1];
  const COUNTRY: Record<string, string> = { US: 'United States', CA: 'Canada', GB: 'United Kingdom', AU: 'Australia', DE: 'Germany', FR: 'France', NL: 'Netherlands', IN: 'India', CN: 'China', RU: 'Russia', BR: 'Brazil' };
  const country = ctry ? (COUNTRY[ctry] ?? ctry) : '';
  return { senderIp: cip ?? xorig ?? '', msVerdict, country };
}

// Detect <a href="X">TEXT</a> where TEXT shows one domain but href goes elsewhere.
function hasLinkMismatch(html: string): boolean {
  if (!html) return false;
  const re = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const href = m[1];
    const text = m[2].replace(/<[^>]+>/g, ' ').trim();
    const textDom = (text.match(/(?:[a-z0-9-]+\.)+[a-z]{2,}/i) ?? [])[0];
    if (!textDom || !/^https?:/i.test(href)) continue;
    try {
      const hd = new URL(href).hostname.toLowerCase().replace(/^www\./, '');
      const td = textDom.toLowerCase().replace(/^www\./, '');
      if (hd && td && !hd.endsWith(td) && !td.endsWith(hd)) return true;
    } catch { /* ignore */ }
  }
  return false;
}

// Parse the SMTP transport chain from Received: headers (origin → recipient).
export interface TransportHop { index: number; from: string; by: string; ip: string; at: string | null }
function parseTransport(headers: Array<{ name: string; value: string }> = []): TransportHop[] {
  const received = headers.filter(h => h.name.toLowerCase() === 'received').map(h => h.value);
  // Headers appear most-recent-first; reverse so hop 1 is the origin.
  return received.reverse().map((v, i) => {
    const fromM = /from\s+([^\s(;]+)(?:\s*\(([^)]*)\))?/i.exec(v);
    const byM = /by\s+([^\s(;]+)/i.exec(v);
    const ipSrc = (fromM?.[2] ?? '') + ' ' + v;
    const ipM = /\[?((?:\d{1,3}\.){3}\d{1,3})\]?/.exec(ipSrc) ?? /\[((?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4})\]/.exec(ipSrc);
    const dateM = /;\s*([^;]+)$/.exec(v);
    let at: string | null = null;
    if (dateM) { const d = Date.parse(dateM[1].trim()); if (!Number.isNaN(d)) at = new Date(d).toISOString(); }
    return { index: i + 1, from: (fromM?.[1] ?? '').toLowerCase(), by: (byM?.[1] ?? '').toLowerCase(), ip: ipM?.[1] ?? '', at };
  });
}

function stripHtml(s: string): string {
  return (s ?? '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 4000);
}
function extractUrls(s: string): string[] {
  return Array.from(new Set((s.match(/https?:\/\/[^\s"'<>)]+/gi) ?? []).slice(0, 20)));
}

function normalize(tenantId: string, verifiedDomains: string[], m: any, folder: 'inbox' | 'sentitems'): Message {
  const from = m.from?.emailAddress ?? {};
  const fromAddress = (from.address ?? '').toLowerCase();
  const toAddress = (m.toRecipients?.[0]?.emailAddress?.address ?? '').toLowerCase();
  const senderDomain = fromAddress.split('@')[1] ?? '';
  const recipientDomain = toAddress.split('@')[1] ?? '';
  const internalSender = verifiedDomains.includes(senderDomain);
  const internalRecipient = verifiedDomains.includes(recipientDomain);
  const outbound = folder === 'sentitems';
  // Internal = stays inside the org (both ends verified). Otherwise external.
  const source: 'internal' | 'external' = internalSender && internalRecipient ? 'internal' : 'external';
  const bodyText = m.body?.contentType === 'html' ? stripHtml(m.body?.content) : (m.body?.content ?? m.bodyPreview ?? '');
  const linkMismatch = m.body?.contentType === 'html' ? hasLinkMismatch(m.body?.content ?? '') : false;
  const ms = msEnrichment(m.internetMessageHeaders);
  return {
    id: m.id,
    internetMessageId: m.internetMessageId,
    tenantId,
    senderIp: ms.senderIp,
    msVerdict: ms.msVerdict,
    senderCountry: ms.country,
    transportHops: parseTransport(m.internetMessageHeaders),
    direction: outbound ? 'outbound' : (internalSender ? 'internal' : 'inbound'),
    source,
    fromAddress,
    fromDisplay: from.name ?? fromAddress,
    to: m.toRecipients?.[0]?.emailAddress?.address ?? '',
    subject: m.subject ?? '(no subject)',
    bodyText,
    receivedAt: m.receivedDateTime ?? new Date().toISOString(),
    auth: authFromHeaders(m.internetMessageHeaders),
    replyTo: m.replyTo?.[0]?.emailAddress?.address,
    // Enrichment we don't have a real source for yet — conservative defaults.
    // (domain-age + first-time-sender would come from intel / history.)
    senderDomainAgeDays: 3000,
    firstTimeSender: false,
    urls: extractUrls(bodyText),
    linkMismatch,
    attachments: (m.attachments ?? []).map((a: any) => ({ filename: a.name, contentType: a.contentType })),
  };
}

// Per-mailbox high-water mark (last message time we've ingested), so each scan
// pulls EVERYTHING new since last time — not just the latest 25. In-memory;
// analysisFor() is the real dedupe, so a restart just re-checks a recent window.
const highWater = new Map<string, string>();
const hwKey = (c: string, u: string, f: string) => `${c}:${u}:${f}`;
const FIRST_SCAN_LOOKBACK_DAYS = 14;

// Pull ALL messages received since the last scan for one mailbox (paginated), and
// score any we haven't seen before. Returns how many new messages were scored.
async function ingestFolder(tenantId: string, entraTenantId: string, verifiedDomains: string[], userId: string, token: string, folder: 'inbox' | 'sentitems'): Promise<number> {
  const dateField = folder === 'sentitems' ? 'sentDateTime' : 'receivedDateTime';
  const select = folder === 'sentitems'
    ? 'id,internetMessageId,subject,from,sender,toRecipients,sentDateTime,bodyPreview,body,internetMessageHeaders'
    : 'id,internetMessageId,subject,from,toRecipients,replyTo,receivedDateTime,bodyPreview,body,internetMessageHeaders';
  const key = hwKey(tenantId, userId, folder);
  const since = highWater.get(key) ?? new Date(Date.now() - FIRST_SCAN_LOOKBACK_DAYS * 864e5).toISOString();
  let url: string =
    `${GRAPH}/users/${encodeURIComponent(userId)}/mailFolders/${folder}/messages` +
    `?$filter=${dateField} ge ${since}&$orderby=${dateField} desc&$top=50&$select=${select}&$expand=attachments($select=name,contentType)`;

  let scored = 0, pages = 0, newest = since;
  while (url && pages < 40) { // cap ~2000 msgs/scan to bound a huge first scan
    let res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
    if (res.status === 429) { // throttled — back off once and retry
      const wait = Number(res.headers.get('retry-after') ?? '5') * 1000;
      await new Promise(r => setTimeout(r, Math.min(wait, 15000)));
      res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
    }
    if (!res.ok) throw new Error(`mail read failed for ${userId}/${folder}: ${res.status} ${await res.text()}`);
    const json = (await res.json()) as { value: any[]; '@odata.nextLink'?: string };
    for (const m of json.value ?? []) {
      const when = m.receivedDateTime ?? m.sentDateTime;
      if (when && when > newest) newest = when;
      // sentitems lack receivedDateTime — fall back to sentDateTime.
      if (!m.receivedDateTime && m.sentDateTime) m.receivedDateTime = m.sentDateTime;
      if (emailStore.analysisFor(m.id)) continue; // already scored — skip
      scored += await scoreIngested(tenantId, entraTenantId, verifiedDomains, userId, folder, m);
    }
    url = json['@odata.nextLink'] ?? '';
    pages++;
  }
  highWater.set(key, newest); // advance the high-water mark
  return scored;
}

async function scoreIngested(tenantId: string, entraTenantId: string, verifiedDomains: string[], userId: string, folder: 'inbox' | 'sentitems', m: any): Promise<number> {
  {
    const msg = normalize(tenantId, verifiedDomains, m, folder);
    msg.mailboxUserId = userId;
    const analysis = await analyze(msg);
    const ref = { graphId: m.id, internetMessageId: m.internetMessageId };
    const active = isActive(tenantId); // passive (monitor) customers are scored but not acted on
    // Enforce: act on the real mailbox for inbound mail the policy junks/quarantines.
    if (folder === 'inbox' && ['junk', 'quarantine', 'remediated'].includes(analysis.disposition)) {
      if (active) await applyDisposition(entraTenantId, userId, ref, analysis.disposition);
    } else if (folder === 'inbox') {
      if (active) {
        await maybeStampBanner(tenantId, entraTenantId, userId, ref, msg, analysis);
        if (hasActiveLinkRewrite(tenantId)) await rewriteLinks(entraTenantId, userId, ref, config.publicBaseUrl);
      }
    } else if (folder === 'sentitems') {
      const dlp = dlpMatch(tenantId, msg);
      if (dlp) {
        audit({ action: 'dlp.match', resource: msg.subject, detail: `outbound to ${msg.to} matched DLP rule`, customerId: tenantId });
        if (active && dlp.data.action === 'quarantine') await applyDisposition(entraTenantId, userId, ref, 'quarantine');
      }
    }
    return 1;
  }
}

async function ingestMailbox(tenantId: string, entraTenantId: string, verifiedDomains: string[], userId: string, token: string): Promise<number> {
  const internal = [...verifiedDomains, ...getSettings(tenantId).managedDomains];
  let n = 0;
  n += await ingestFolder(tenantId, entraTenantId, internal, userId, token, 'inbox');
  n += await ingestFolder(tenantId, entraTenantId, internal, userId, token, 'sentitems');
  return n;
}

// Fetch, score, and (if needed) act on ONE message — used by the webhook when a
// real-time notification arrives. Returns the disposition, or null if skipped.
export async function ingestOneMessage(tenantId: string, entraTenantId: string, userId: string, messageId: string): Promise<string | null> {
  if (emailStore.analysisFor(messageId)) return null; // already scored
  const t = store.getTenant(tenantId);
  if (!t) return null;
  const token = await appToken(entraTenantId);
  const url = `${GRAPH}/users/${encodeURIComponent(userId)}/messages/${messageId}` +
    `?$select=id,internetMessageId,subject,from,toRecipients,replyTo,receivedDateTime,bodyPreview,body,internetMessageHeaders&$expand=attachments($select=name,contentType)`;
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) { console.error(`[webhook] fetch message failed ${res.status}`); return null; }
  const m = await res.json();
  const internalDomains = [...t.verifiedDomains, ...getSettings(tenantId).managedDomains];
  const msg = normalize(tenantId, internalDomains, m, 'inbox');
  msg.mailboxUserId = userId;
  const analysis = await analyze(msg);
  const ref = { graphId: m.id, internetMessageId: m.internetMessageId };
  if (isActive(tenantId)) { // passive customers are scored but not acted on
    if (['junk', 'quarantine', 'remediated'].includes(analysis.disposition)) {
      await applyDisposition(entraTenantId, userId, ref, analysis.disposition);
    } else {
      await maybeStampBanner(tenantId, entraTenantId, userId, ref, msg, analysis);
      if (hasActiveLinkRewrite(tenantId)) await rewriteLinks(entraTenantId, userId, ref, config.publicBaseUrl);
    }
  }
  return analysis.disposition;
}

// Ingest inbox mail for every synced user of a connected tenant.
export async function ingestTenantMail(tenantId: string): Promise<{ mailboxes: number; scored: number }> {
  const conn = getConnection(tenantId);
  const t = store.getTenant(tenantId);
  if (!conn?.entraTenantId || !t) throw new Error('tenant not connected');

  const token = await appToken(conn.entraTenantId);
  const users = store.usersForTenant(tenantId).filter(u => u.enabled);
  let scored = 0;
  for (const u of users) {
    try { scored += await ingestMailbox(tenantId, conn.entraTenantId, t.verifiedDomains, u.externalId, token); }
    catch (e) { console.error(`[mailIngest] ${u.email}:`, (e as Error).message); }
  }
  return { mailboxes: users.length, scored };
}
