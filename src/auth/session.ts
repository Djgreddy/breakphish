// Stateless session as an HMAC-signed token (a minimal JWT-style envelope),
// carried in an httpOnly cookie. Same signing approach as the tracking tokens.
// Production would likely add rotation + refresh tokens; the shape is here.

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import { config } from '../config';
import type { Session } from './identity';

function b64url(b: Buffer) { return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64url(s: string) { return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }

export function signSession(s: Session): string {
  const payload = b64url(Buffer.from(JSON.stringify(s)));
  const sig = b64url(createHmac('sha256', config.auth.sessionSecret).update(payload).digest());
  return `${payload}.${sig}`;
}

export function verifySession(token: string | undefined): Session | null {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = createHmac('sha256', config.auth.sessionSecret).update(payload).digest();
  const got = unb64url(sig);
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null;
  try {
    const s = JSON.parse(unb64url(payload).toString('utf8')) as Session;
    if (!s.exp || s.exp < Math.floor(Date.now() / 1000)) return null; // expired
    return s;
  } catch { return null; }
}

export function newSession(partial: Omit<Session, 'exp'>): Session {
  return { ...partial, exp: Math.floor(Date.now() / 1000) + config.auth.sessionTtlSec };
}

export function setSessionCookie(res: Response, session: Session) {
  res.cookie(config.auth.cookieName, signSession(session), {
    httpOnly: true, sameSite: 'lax', path: '/',
    maxAge: config.auth.sessionTtlSec * 1000,
    // secure: true in production (HTTPS only)
  });
}
export function clearSessionCookie(res: Response) {
  res.clearCookie(config.auth.cookieName, { path: '/' });
}

// Tiny cookie reader (avoids a cookie-parser dependency).
export function readCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  (header ?? '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i < 0) return;
    out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
