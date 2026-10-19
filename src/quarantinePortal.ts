// End-user quarantine access. A signed token (HMAC, time-limited) lets a specific
// user view and act on THEIR OWN quarantined mail without a full login — the same
// mechanism powers the action links in the quarantine digest email.
//
// Security: the token encodes {customerId, email, exp} and is HMAC-signed. Every
// action re-verifies the token and is scoped to messages addressed to that email.

import express from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from './config';
import { emailStore } from './emailsec/store';
import { getCustomer } from './onboarding';
import { getConnection } from './consent';
import { store } from './store';
import { makeMailActions } from './emailsec/mailActions';
import { persistScored } from './db/hydrate';
import { audit } from './audit';

const b64u = (b: Buffer) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

export function signPortalToken(customerId: string, email: string, ttlDays = 7): string {
  const payload = b64u(Buffer.from(JSON.stringify({ c: customerId, e: email.toLowerCase(), x: Date.now() + ttlDays * 864e5 })));
  const sig = b64u(createHmac('sha256', config.tokenSecret).update(payload).digest());
  return `${payload}.${sig}`;
}
export function verifyPortalToken(token: string): { customerId: string; email: string } | null {
  try {
    const [payload, sig] = token.split('.');
    const expect = b64u(createHmac('sha256', config.tokenSecret).update(payload).digest());
    const a = Buffer.from(sig), b = Buffer.from(expect);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    const p = JSON.parse(fromB64u(payload).toString());
    if (Date.now() > p.x) return null;
    return { customerId: p.c, email: p.e };
  } catch { return null; }
}

function quarantinedForUser(customerId: string, email: string) {
  // quarantinedForTenant returns ANALYSES — map each to its message, then match recipient.
  return emailStore.quarantinedForTenant(customerId)
    .map((a: any) => emailStore.messages.get(a.messageId))
    .filter((m: any): m is any => !!m && (m.to || '').toLowerCase() === email.toLowerCase());
}

async function mailboxFor(customerId: string, email: string) {
  const conn = getConnection(customerId);
  const user = store.usersForTenant(customerId).find(u => u.email.toLowerCase() === email.toLowerCase());
  return { conn, user };
}

const esc = (s: string) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));

// The digest email body (also used as the portal page). items link back with the token.
export function digestHtml(customerId: string, email: string, token: string): string {
  const base = config.publicBaseUrl;
  const items = quarantinedForUser(customerId, email);
  const rows = items.map((m: any) => {
    const a = emailStore.analysisFor(m.id);
    const verdict = a?.verdict ?? 'spam';
    const act = (doo: string) => `${base}/portal/action?token=${encodeURIComponent(token)}&id=${encodeURIComponent(m.id)}&do=${doo}`;
    return `<tr><td style="padding:14px;border:1px solid #2a2a3a;background:#1b1b28;color:#ddd">
      <span style="display:inline-block;background:#2563eb;color:#fff;font-size:11px;padding:2px 8px;border-radius:4px">${esc(verdictLabel(verdict))}</span>
      <div style="color:#8a8; font-size:12px;margin-top:6px">${esc(new Date(m.receivedAt).toLocaleString())}</div>
      <div style="font-weight:600;margin:4px 0">${esc(m.fromDisplay || m.fromAddress)} &lt;${esc(m.fromAddress)}&gt;</div>
      <div style="color:#aaa">${esc(m.subject)}</div>
    </td><td style="padding:14px;border:1px solid #2a2a3a;background:#1b1b28;white-space:nowrap;text-align:right">
      <a href="${act('deliver')}" style="display:block;margin:4px 0;padding:6px 14px;background:#16a34a;color:#fff;text-decoration:none;border-radius:6px;font-size:13px">Deliver</a>
      <a href="${base}/portal/preview?token=${encodeURIComponent(token)}&id=${encodeURIComponent(m.id)}" style="display:block;margin:4px 0;padding:6px 14px;border:1px solid #555;color:#ddd;text-decoration:none;border-radius:6px;font-size:13px">Preview</a>
      <a href="${act('delete')}" style="display:block;margin:4px 0;padding:6px 14px;background:#dc2626;color:#fff;text-decoration:none;border-radius:6px;font-size:13px">Delete</a>
    </td></tr>`;
  }).join('');
  return `<div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:auto;background:#12121c;border-radius:10px;overflow:hidden">
    <div style="background:#4f46e5;padding:22px 24px"><h1 style="color:#fff;font-size:20px;margin:0">Your Quarantine Digest</h1></div>
    <div style="padding:18px 24px;color:#ccc">Hi ${esc(email)}, you have ${items.length} quarantined email${items.length === 1 ? '' : 's'}.</div>
    <table style="width:100%;border-collapse:collapse">${rows || '<tr><td style="padding:20px;color:#888">No quarantined mail.</td></tr>'}</table>
    <div style="padding:16px 24px;color:#777;font-size:12px">Powered by BreakPhish Security · <a href="${base}/portal/quarantine?token=${encodeURIComponent(token)}" style="color:#8ab">Open quarantine portal</a></div>
  </div>`;
}
function verdictLabel(v: string) {
  return ({ clean: 'Clean', spam: 'Spam', spam_likely: 'Spam-Likely', phishing: 'Phishing', malware: 'Malware', impersonation: 'Impersonation', policy_infomail: 'Infomail', policy_geo: 'Policy-Geo' } as any)[v] ?? v;
}

export function buildPortalApp() {
  const app = express.Router();
  app.use(express.urlencoded({ extended: false }));

  app.get('/portal/quarantine', (req, res) => {
    const v = verifyPortalToken(String(req.query.token ?? ''));
    if (!v) return res.status(401).send(page('Link expired', 'This quarantine link is invalid or has expired. Please ask your administrator for a new one.'));
    res.set('content-type', 'text/html').send(page('Quarantine', digestHtml(v.customerId, v.email, String(req.query.token))));
  });

  app.get('/portal/preview', (req, res) => {
    const v = verifyPortalToken(String(req.query.token ?? '')); if (!v) return res.status(401).send(page('Link expired', 'Invalid link.'));
    const m = emailStore.messages.get(String(req.query.id ?? ''));
    if (!m || (m.to || '').toLowerCase() !== v.email || m.tenantId !== v.customerId) return res.status(404).send(page('Not found', 'Message not found.'));
    res.set('content-type', 'text/html').send(page('Preview', `<div style="max-width:700px;margin:auto;background:#1b1b28;color:#ddd;padding:20px;border-radius:8px"><div style="color:#888;font-size:12px">From ${esc(m.fromAddress)} · ${esc(m.subject)}</div><hr style="border-color:#333"><pre style="white-space:pre-wrap;font-family:inherit">${esc(m.bodyText || '(no preview)')}</pre></div>`));
  });

  app.get('/portal/action', async (req, res) => {
    const v = verifyPortalToken(String(req.query.token ?? '')); if (!v) return res.status(401).send(page('Link expired', 'Invalid link.'));
    const id = String(req.query.id ?? ''); const doo = String(req.query.do ?? '');
    const m = emailStore.messages.get(id); const a = emailStore.analysisFor(id);
    if (!m || !a || (m.to || '').toLowerCase() !== v.email || m.tenantId !== v.customerId) return res.status(404).send(page('Not found', 'Message not found or not yours.'));
    const { conn, user } = await mailboxFor(v.customerId, v.email);
    try {
      if (doo === 'deliver') {
        a.disposition = 'deliver'; a.remediated = false; emailStore.saveAnalysis(a); await persistScored(m, a);
        emailStore.markReleased(m.internetMessageId);
        if (conn?.entraTenantId && user) await makeMailActions().moveToInbox(conn.entraTenantId, user.externalId, { graphId: id, internetMessageId: m.internetMessageId });
        audit({ actorEmail: v.email, role: 'end_user', action: 'mail.release', resource: m.subject, detail: 'via quarantine portal', customerId: v.customerId });
        return res.send(page('Delivered', `"${esc(m.subject)}" has been delivered to your inbox.`));
      }
      if (doo === 'delete') {
        if (conn?.entraTenantId && user) await makeMailActions().moveToDeleted(conn.entraTenantId, user.externalId, { graphId: id, internetMessageId: m.internetMessageId });
        emailStore.messages.delete(id); emailStore.analyses.delete(id);
        audit({ actorEmail: v.email, role: 'end_user', action: 'mail.delete', resource: m.subject, detail: 'via quarantine portal', customerId: v.customerId });
        return res.send(page('Deleted', `"${esc(m.subject)}" has been deleted.`));
      }
      return res.status(400).send(page('Unknown action', 'Unknown action.'));
    } catch (e) { return res.status(500).send(page('Error', (e as Error).message)); }
  });

  return app;
}

function page(title: string, bodyHtml: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · BreakPhish</title></head><body style="margin:0;background:#0c0c14;padding:30px 16px;font-family:Segoe UI,Arial,sans-serif"><div style="max-width:680px;margin:auto">${bodyHtml.startsWith('<') ? bodyHtml : `<div style="background:#1b1b28;color:#ddd;padding:24px;border-radius:10px;text-align:center">${esc(bodyHtml)}</div>`}</div></body></html>`;
}

// Build a portal link for a user (for the admin to share, or the digest to use).
export function portalLink(customerId: string, email: string): string {
  return `${config.publicBaseUrl}/portal/quarantine?token=${encodeURIComponent(signPortalToken(customerId, email))}`;
}
