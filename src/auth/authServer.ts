// Auth endpoints. Mock mode signs in via persona (no redirect); Entra mode does
// the real OIDC round trip. Partners can impersonate a customer ("Login As"),
// which issues a scoped administrator session that remembers the acting partner.

import express from 'express';
import { randomBytes } from 'node:crypto';
import { config } from '../config';
import { getCustomer } from '../onboarding';
import { makeAuthProvider } from './provider';
import { resolveRole } from './roles';
import { newSession, setSessionCookie, clearSessionCookie } from './session';
import { attachSession, sessionOf, requireAuth, requirePartner } from './middleware';
import type { Identity, Session } from './identity';
import { getTeamByEmail, updateTeamCreds } from '../team';
import { audit } from '../audit';
import { verifyPassword, generateTotpSecret, otpauthUri, verifyTotp } from './localAuth';
import QRCode from 'qrcode';

const provider = makeAuthProvider();
const states = new Map<string, number>(); // entra CSRF states

function sessionFromIdentity(identity: Identity): Session | null {
  const r = resolveRole(identity);
  if (!r) return null;
  return newSession({
    sub: identity.sub, email: identity.email, name: identity.name,
    role: r.role, customerId: r.customerId,
  });
}

export function buildAuthApp() {
  const app = express.Router();
  app.use(express.json());
  app.use(attachSession);

  // --- mock: list personas + one-click sign-in ---
  app.get('/auth/personas', (_req, res) => res.json({ provider: config.auth.provider, personas: provider.personas() }));

  app.post('/auth/login/mock', (req, res) => {
    if (config.auth.provider !== 'mock') return res.status(400).json({ error: 'mock login disabled' });
    const identity = provider.identityForPersona(String(req.body?.persona ?? ''));
    if (!identity) return res.status(400).json({ error: 'unknown persona' });
    const session = sessionFromIdentity(identity);
    if (!session) return res.status(403).json({ error: 'identity is not provisioned for any tenant' });
    setSessionCookie(res, session);
    res.json({ session: publicSession(session) });
  });

  // --- local: email + password (+ TOTP MFA) for local team members ---
  app.post('/auth/login/local', async (req, res) => {
    const email = String(req.body?.email ?? '').toLowerCase().trim();
    const password = String(req.body?.password ?? '');
    const code = req.body?.code ? String(req.body.code) : '';
    const m = getTeamByEmail(email);
    if (!m || m.authType !== 'local' || !m.passwordHash) return res.status(401).json({ error: 'invalid email or password' });
    if (!verifyPassword(password, m.passwordHash)) return res.status(401).json({ error: 'invalid email or password' });

    const finish = () => {
      // All partner staff get the partner_admin *scope*, but their teamRole limits
      // what they can actually do (analyst / read_only enforced in middleware).
      const session = newSession({ sub: 'local:' + m.id, email: m.email, name: m.name, role: 'partner_admin', teamRole: m.role });
      setSessionCookie(res, session);
      audit({ actorEmail: m.email, role: m.role, action: 'auth.login', detail: 'local' + (m.mfaEnabled?' + MFA':'') });
      return res.json({ session: publicSession(session) });
    };

    if (!m.mfaEnabled) return finish();

    // ensure a secret exists (pending until confirmed)
    let secret = m.totpSecret;
    if (!secret) { secret = generateTotpSecret(); await updateTeamCreds(m.id, { totpSecret: secret }); }

    if (!code) {
      if (!m.totpEnabled) {
        const uri = otpauthUri(secret, m.email);
        let qr: string | undefined;
        try { qr = await QRCode.toDataURL(uri, { margin: 1, width: 200 }); } catch {}
        return res.json({ needsMfa: true, enroll: true, otpauthUri: uri, secret, qr });
      }
      return res.json({ needsMfa: true, enroll: false });
    }
    if (!verifyTotp(secret, code)) return res.status(401).json({ error: 'invalid verification code' });
    if (!m.totpEnabled) await updateTeamCreds(m.id, { totpEnabled: true, status: 'active' });
    return finish();
  });

  // --- entra: redirect to Microsoft, then handle the callback ---
  app.get('/auth/login', (_req, res) => {
    if (config.auth.provider !== 'entra') return res.status(400).send('Use mock login');
    const state = randomBytes(16).toString('hex');
    states.set(state, Date.now());
    res.redirect(provider.authorizeUrl(state));
  });

  app.get('/auth/callback', async (req, res) => {
    const state = String(req.query.state ?? '');
    if (!states.has(state)) return res.status(400).send('Invalid state');
    states.delete(state);
    try {
      const identity = await provider.exchangeCode(String(req.query.code ?? ''));
      const session = sessionFromIdentity(identity);
      if (!session) return res.status(403).send('Your account is not provisioned for BreakPhish.');
      setSessionCookie(res, session);
      res.redirect('/');
    } catch (e) {
      res.status(400).send((e as Error).message);
    }
  });

  // --- current session ---
  app.get('/auth/me', (req, res) => {
    const s = sessionOf(req);
    if (!s) return res.status(401).json({ error: 'not authenticated' });
    res.json({ session: publicSession(s) });
  });

  app.post('/auth/logout', (_req, res) => { clearSessionCookie(res); res.json({ ok: true }); });

  // --- partner impersonation ("Login As") ---
  app.post('/auth/impersonate', requirePartner, (req, res) => {
    const customerId = String(req.body?.customerId ?? '');
    if (!getCustomer(customerId)) return res.status(404).json({ error: 'unknown customer' });
    const partner = sessionOf(req)!;
    const session = newSession({
      sub: partner.sub, email: partner.email, name: partner.name,
      role: 'administrator', customerId, impersonating: true,
      actor: { sub: partner.sub, email: partner.email, name: partner.name },
    });
    setSessionCookie(res, session);
    res.json({ session: publicSession(session) });
  });

  app.post('/auth/stop-impersonating', requireAuth, (req, res) => {
    const s = sessionOf(req)!;
    if (!s.impersonating || !s.actor) return res.status(400).json({ error: 'not impersonating' });
    const session = newSession({ sub: s.actor.sub, email: s.actor.email, name: s.actor.name, role: 'partner_admin' });
    setSessionCookie(res, session);
    res.json({ session: publicSession(session) });
  });

  return app;
}

// Never leak internal fields the client doesn't need.
function publicSession(s: Session) {
  return {
    name: s.name, email: s.email, role: s.role, customerId: s.customerId,
    impersonating: Boolean(s.impersonating),
    customerName: s.customerId ? getCustomer(s.customerId)?.name : undefined,
    customerDomain: s.customerId ? getCustomer(s.customerId)?.primaryDomain : undefined,
  };
}
