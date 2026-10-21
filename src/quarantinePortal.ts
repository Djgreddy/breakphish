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
import { saveRule } from './policy';
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

// since (epoch ms): when > 0, only items quarantined after that time (delta digest).
export function quarantinedForUser(customerId: string, email: string, since = 0) {
  return emailStore.quarantinedForTenant(customerId)
    .map((a: any) => emailStore.messages.get(a.messageId))
    .filter((m: any): m is any => !!m && (m.to || '').toLowerCase() === email.toLowerCase()
      && (since === 0 || Date.parse(m.receivedAt) > since));
}

async function mailboxFor(customerId: string, email: string) {
  const conn = getConnection(customerId);
  const user = store.usersForTenant(customerId).find(u => u.email.toLowerCase() === email.toLowerCase());
  return { conn, user };
}

const esc = (s: string) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));

const VERDICT_COLOR: Record<string, string> = {
  clean: '#6b7280', spam: '#d97706', spam_likely: '#d97706', phishing: '#dc2626',
  malware: '#dc2626', impersonation: '#dc2626', policy_infomail: '#2563eb', policy_geo: '#dc2626',
};
// The digest email body (also used as the portal page). Table-based + inline
// styles for email-client compatibility; light theme for readability.
export function digestHtml(customerId: string, email: string, token: string, since = 0): string {
  const base = config.publicBaseUrl;
  const items = quarantinedForUser(customerId, email, since);
  const isDelta = since > 0;
  const act = (m: any, doo: string) => `${base}/portal/action?token=${encodeURIComponent(token)}&id=${encodeURIComponent(m.id)}&do=${doo}`;
  const link = (label: string, href: string, color = '#2563eb') => `<a href="${href}" style="color:${color};text-decoration:none;font-size:13.5px;font-weight:600">${label}</a>`;
  const rows = items.map((m: any) => {
    const dt = new Date(m.receivedAt);
    const date = dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    const time = dt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    return `<tr><td style="padding:16px 0;border-bottom:1px solid #e6e6e6">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
        <td style="vertical-align:top">
          <div style="font-weight:700;color:#1a1a1a;font-size:14px;line-height:1.35">${esc(m.subject || '(no subject)')}</div>
          <div style="color:#8a8a8a;font-size:12.5px;margin-top:3px">${esc(m.fromDisplay || m.fromAddress)} &lt;${esc(m.fromAddress)}&gt;</div>
        </td>
        <td style="vertical-align:top;text-align:right;white-space:nowrap;padding-left:14px">
          <div style="color:#8a8a8a;font-size:12px;font-weight:600">${date}</div>
          <div style="color:#8a8a8a;font-size:12px">${time}</div>
        </td>
      </tr></table>
      <div style="margin-top:10px">
        ${link('Deliver', act(m, 'deliver'))} &nbsp;&nbsp; ${link('Allow sender', act(m, 'allow'))} &nbsp;&nbsp; ${link('Block sender', act(m, 'block'), '#c0392b')}
      </div>
    </td></tr>`;
  }).join('');
  const portal = `${base}/portal/quarantine?token=${encodeURIComponent(token)}`;
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;font-family:Arial,Helvetica,sans-serif;padding:8px 0">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%">
        <tr><td align="center" style="padding:26px 0 8px">
          <span style="font-size:22px;font-weight:800;color:#1a1a1a;letter-spacing:-.5px">Break<span style="color:#2563eb">Phish</span></span>
        </td></tr>
        <tr><td style="padding:14px 28px 0">
          <h1 style="font-size:22px;font-weight:700;color:#1a1a1a;margin:0 0 16px">You have ${items.length} ${isDelta ? 'new ' : ''}quarantined inbound email${items.length === 1 ? '' : 's'}</h1>
          <a href="${portal}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;font-size:15px;font-weight:600;padding:12px 22px;border-radius:5px">View in BreakPhish</a>
        </td></tr>
        <tr><td style="padding:16px 28px 0">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">${rows || '<tr><td style="padding:20px 0;color:#8a8a8a;font-size:14px">No quarantined mail.</td></tr>'}</table>
        </td></tr>
        <tr><td style="padding:26px 28px 30px">
          <div style="color:#9a9a9a;font-size:12px;line-height:1.5;text-align:center">This email was sent from BreakPhish because you or your administrator requested that you be notified of your quarantined messages. You can manage your full quarantine in <a href="${portal}" style="color:#2563eb;text-decoration:none">the BreakPhish portal</a>.</div>
        </td></tr>
      </table>
    </td></tr>
  </table>`;
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
        a.disposition = 'deliver'; a.remediated = false; a.releasedManually = true; emailStore.saveAnalysis(a); await persistScored(m, a);
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
      if (doo === 'allow') {
        // deliver this one AND allow the sender going forward
        a.disposition = 'deliver'; a.remediated = false; a.releasedManually = true; emailStore.saveAnalysis(a); await persistScored(m, a);
        emailStore.markReleased(m.internetMessageId);
        if (conn?.entraTenantId && user) await makeMailActions().moveToInbox(conn.entraTenantId, user.externalId, { graphId: id, internetMessageId: m.internetMessageId });
        await saveRule({ scope: v.customerId, kind: 'allow', data: { sender: m.fromAddress, comment: `Allowed by ${v.email} from quarantine digest` } });
        audit({ actorEmail: v.email, role: 'end_user', action: 'sender.allow', resource: m.fromAddress, detail: 'via quarantine digest', customerId: v.customerId });
        return res.send(page('Sender allowed', `"${esc(m.subject)}" has been delivered, and mail from ${esc(m.fromAddress)} will be allowed going forward.`));
      }
      if (doo === 'block') {
        await saveRule({ scope: v.customerId, kind: 'block', data: { sender: m.fromAddress, comment: `Blocked by ${v.email} from quarantine digest` } });
        if (conn?.entraTenantId && user) await makeMailActions().moveToDeleted(conn.entraTenantId, user.externalId, { graphId: id, internetMessageId: m.internetMessageId });
        emailStore.messages.delete(id); emailStore.analyses.delete(id);
        audit({ actorEmail: v.email, role: 'end_user', action: 'sender.block', resource: m.fromAddress, detail: 'via quarantine digest', customerId: v.customerId });
        return res.send(page('Sender blocked', `Mail from ${esc(m.fromAddress)} will be blocked going forward.`));
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
