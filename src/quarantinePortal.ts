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

const VERDICT_COLOR: Record<string, string> = {
  clean: '#6b7280', spam: '#d97706', spam_likely: '#d97706', phishing: '#dc2626',
  malware: '#dc2626', impersonation: '#dc2626', policy_infomail: '#2563eb', policy_geo: '#dc2626',
};
// The digest email body (also used as the portal page). Table-based + inline
// styles for email-client compatibility; light theme for readability.
export function digestHtml(customerId: string, email: string, token: string): string {
  const base = config.publicBaseUrl;
  const items = quarantinedForUser(customerId, email);
  const btn = (label: string, href: string, bg: string, fg: string, border = bg) =>
    `<a href="${href}" style="display:inline-block;min-width:74px;text-align:center;padding:8px 14px;margin:0 0 6px;background:${bg};color:${fg};text-decoration:none;border-radius:6px;font-size:13px;font-weight:600;border:1px solid ${border}">${label}</a>`;
  const rows = items.map((m: any) => {
    const a = emailStore.analysisFor(m.id);
    const verdict = a?.verdict ?? 'spam';
    const color = VERDICT_COLOR[verdict] ?? '#6b7280';
    const act = (doo: string) => `${base}/portal/action?token=${encodeURIComponent(token)}&id=${encodeURIComponent(m.id)}&do=${doo}`;
    return `<tr><td style="padding:0 24px 14px">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e6e8ef;border-radius:10px;border-collapse:separate;overflow:hidden">
        <tr>
          <td style="padding:16px 18px;vertical-align:top">
            <span style="display:inline-block;background:${color};color:#fff;font-size:11px;font-weight:700;letter-spacing:.03em;padding:3px 9px;border-radius:5px;text-transform:uppercase">${esc(verdictLabel(verdict))}</span>
            <div style="color:#8a90a2;font-size:12px;margin-top:10px">${esc(new Date(m.receivedAt).toLocaleString())}</div>
            <div style="font-weight:600;color:#1c2338;font-size:14px;margin:3px 0">${esc(m.fromDisplay || m.fromAddress)} <span style="color:#8a90a2;font-weight:400">&lt;${esc(m.fromAddress)}&gt;</span></div>
            <div style="color:#5b6478;font-size:13.5px">${esc(m.subject || '(no subject)')}</div>
          </td>
          <td style="padding:16px 18px;vertical-align:top;text-align:right;white-space:nowrap">
            ${btn('Deliver', act('deliver'), '#16a34a', '#fff')}<br>
            ${btn('Preview', `${base}/portal/preview?token=${encodeURIComponent(token)}&id=${encodeURIComponent(m.id)}`, '#ffffff', '#374151', '#d1d5db')}<br>
            ${btn('Delete', act('delete'), '#dc2626', '#fff')}
          </td>
        </tr>
      </table>
    </td></tr>`;
  }).join('');
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fb;padding:24px 0;font-family:'Segoe UI',Helvetica,Arial,sans-serif">
    <tr><td align="center">
      <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 1px 3px rgba(20,27,46,.08)">
        <tr><td style="background:linear-gradient(135deg,#4f46e5,#6366f1);padding:26px 24px">
          <div style="color:#fff;font-size:21px;font-weight:700">🛡 Your Quarantine Digest</div>
          <div style="color:#dcdcff;font-size:13px;margin-top:4px">BreakPhish Security</div>
        </td></tr>
        <tr><td style="padding:22px 24px 6px">
          <div style="color:#1c2338;font-size:15px;font-weight:600">Hi ${esc(email.split('@')[0])},</div>
          <div style="color:#5b6478;font-size:14px;margin-top:4px">You have <b style="color:#1c2338">${items.length}</b> message${items.length === 1 ? '' : 's'} held in quarantine. Review them below — <b>Deliver</b> to send to your inbox, <b>Preview</b> to view safely, or <b>Delete</b> to remove.</div>
        </td></tr>
        ${rows || '<tr><td style="padding:20px 24px;color:#8a90a2;font-size:14px">No quarantined mail. 🎉</td></tr>'}
        <tr><td style="padding:14px 24px 26px">
          <a href="${base}/portal/quarantine?token=${encodeURIComponent(token)}" style="display:inline-block;padding:11px 20px;background:#1c2338;color:#fff;text-decoration:none;border-radius:8px;font-size:13.5px;font-weight:600">Open quarantine portal →</a>
          <div style="color:#9aa1b6;font-size:11.5px;margin-top:16px;border-top:1px solid #eef0f7;padding-top:14px">This digest was sent by your email security provider. Only act on messages you recognize. Links are secured to your account.</div>
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
