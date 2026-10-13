// Identity = who the IdP says you are. Session = what we let you do here.

export interface Identity {
  sub: string;          // stable IdP subject id
  email: string;
  name: string;
  tenantId: string;     // Entra `tid` claim — drives role resolution
}

export type Role = 'partner_admin' | 'administrator';

export interface Session {
  sub: string;
  email: string;
  name: string;
  role: Role;
  customerId?: string;  // set for administrators (own org, or one being impersonated)
  impersonating?: boolean;
  actor?: { sub: string; email: string; name: string }; // the partner, while impersonating
  exp: number;          // unix seconds
}
