// Pluggable email transport. The console transport logs instead of sending, so
// the demo needs no mail provider. A real transport would send via an ESP that
// permits simulation content and supports dedicated, warmed IP pools.

import type { RenderedEmail } from './templates';

export interface EmailTransport {
  send(email: RenderedEmail): Promise<{ delivered: boolean }>;
}

export class ConsoleTransport implements EmailTransport {
  async send(email: RenderedEmail): Promise<{ delivered: boolean }> {
    console.log(
      `   ✉  [send] ${email.to}  from "${email.fromName}" <${email.fromAddress}>  subj: ${email.subject}`,
    );
    return { delivered: true };
  }
}

export function makeTransport(): EmailTransport {
  return new ConsoleTransport();
}
