// Express middleware enforcing authentication and scope. A partner admin may
// read any customer; an administrator may only reach the customer they're
// scoped to (their own, or one a partner is impersonating).

import type { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { readCookies, verifySession } from './session';
import type { Session } from './identity';

// Augment the request with the verified session.
export function attachSession(req: Request, _res: Response, next: NextFunction) {
  const cookies = readCookies(req.headers.cookie);
  (req as any).session = verifySession(cookies[config.auth.cookieName]);
  next();
}

export function sessionOf(req: Request): Session | null {
  return (req as any).session ?? null;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!sessionOf(req)) return res.status(401).json({ error: 'not authenticated' });
  next();
}

export function requirePartner(req: Request, res: Response, next: NextFunction) {
  const s = sessionOf(req);
  if (!s) return res.status(401).json({ error: 'not authenticated' });
  if (s.role !== 'partner_admin') return res.status(403).json({ error: 'partner access required' });
  next();
}

// Read-only team members may only GET. Blocks every mutating method.
export function blockReadOnlyWrites(req: Request, res: Response, next: NextFunction) {
  const s = sessionOf(req);
  if (s?.teamRole === 'read_only' && req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(403).json({ error: 'read-only access: this action is not permitted for your role' });
  }
  next();
}

// Admin-only actions (team management, deleting customers, partner settings).
// SSO/customer sessions (no teamRole) are treated as full admins.
export function requireTeamAdmin(req: Request, res: Response, next: NextFunction) {
  const s = sessionOf(req);
  if (!s) return res.status(401).json({ error: 'not authenticated' });
  if (s.teamRole && s.teamRole !== 'partner_admin') {
    return res.status(403).json({ error: 'administrator role required for this action' });
  }
  next();
}

// For /customers/:id routes — partner sees all, administrator only their scope.
export function requireCustomerAccess(req: Request, res: Response, next: NextFunction) {
  const s = sessionOf(req);
  if (!s) return res.status(401).json({ error: 'not authenticated' });
  const id = req.params.id;
  if (s.role === 'partner_admin') return next();
  if (s.role === 'administrator' && s.customerId === id) return next();
  return res.status(403).json({ error: 'forbidden for this customer' });
}
