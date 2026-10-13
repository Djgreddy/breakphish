// Stateless per-recipient tracking tokens. Payload = "campaignId.recipientId",
// signed with HMAC so the tracking endpoints can verify a hit is genuine
// without a lookup, then record the event. A bad/forged token is rejected.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from '../config';

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

export function makeToken(campaignId: string, recipientId: string): string {
  const payload = `${campaignId}.${recipientId}`;
  const sig = createHmac('sha256', config.tokenSecret).update(payload).digest();
  return b64url(Buffer.from(payload)) + '.' + b64url(sig);
}

export function verifyToken(token: string): { campaignId: string; recipientId: string } | null {
  const [p, s] = token.split('.');
  if (!p || !s) return null;
  let payload: string;
  try { payload = unb64url(p).toString('utf8'); } catch { return null; }
  const expected = createHmac('sha256', config.tokenSecret).update(payload).digest();
  const got = unb64url(s);
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null;
  const [campaignId, recipientId] = payload.split('.');
  if (!campaignId || !recipientId) return null;
  return { campaignId, recipientId };
}
