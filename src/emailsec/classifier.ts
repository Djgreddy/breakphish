// The content-classification layer. This is the "AI" seam: a pluggable
// interface so a heuristic classifier (offline, deterministic, used by the demo)
// and a real LLM classifier are interchangeable — exactly like the directory
// provider pattern.
//
// In production the LLM classifier is where cost, latency, and privacy
// (sending customer email to a model) must be managed. The heuristic version
// needs none of that and is a reasonable first-pass detector.

import type { Message } from './types';

export interface ContentLabels {
  phishing: number;      // 0..1 intent scores
  bec: number;           // business email compromise / impersonation intent
  spam: number;
  infomail: number;      // bulk/marketing/newsletter
  benign: number;
  rationale: string;
}

export interface ContentClassifier {
  classify(message: Message): Promise<ContentLabels>;
}

const has = (text: string, terms: string[]) =>
  terms.some(t => text.includes(t));

export class HeuristicClassifier implements ContentClassifier {
  async classify(m: Message): Promise<ContentLabels> {
    const text = `${m.subject}\n${m.bodyText}`.toLowerCase();

    const credentialLure = has(text, [
      'verify your password', 'password expire', 'reset your password',
      'confirm your account', 'account will be suspended', 'unusual sign-in',
      'validate your login', 'sign in to continue',
    ]);
    const becLure = has(text, [
      'gift card', 'wire transfer', 'update banking', 'change my direct deposit',
      'are you available', 'quick favor', 'urgent request', 'invoice attached', 'remit payment',
    ]);
    const marketing = has(text, [
      'unsubscribe', '% off', 'limited time offer', 'newsletter', 'view in browser', 'shop now',
    ]);
    const spammy = has(text, [
      'you have won', 'claim your prize', 'act now', 'risk-free', 'miracle', 'crypto giveaway',
    ]);

    let phishing = credentialLure ? 0.8 : 0;
    let bec = becLure ? 0.75 : 0;
    let spam = spammy ? 0.7 : 0;
    let infomail = marketing ? 0.8 : 0;

    // urgency amplifies phishing/bec a little
    if (has(text, ['urgent', 'immediately', 'within 2 hours', 'final notice'])) {
      phishing = Math.min(1, phishing + 0.1);
      bec = Math.min(1, bec + 0.1);
    }

    const benign = 1 - Math.max(phishing, bec, spam, infomail);
    const top = Math.max(phishing, bec, spam, infomail, benign);
    const rationale =
      top === benign ? 'no strong intent markers'
      : phishing === top ? 'credential-harvest language'
      : bec === top ? 'payment/impersonation request pattern'
      : spam === top ? 'spam phrasing'
      : 'bulk/marketing markers';

    return { phishing, bec, spam, infomail, benign, rationale };
  }
}

// Real LLM classifier — not used by the offline demo. Prompts a small model as a
// strict JSON classifier. Shown for the production path.
export class LLMClassifier implements ContentClassifier {
  async classify(m: Message): Promise<ContentLabels> {
    // Pseudocode for the real call:
    //   const res = await fetch('https://api.anthropic.com/v1/messages', { ... })
    //   with a system prompt instructing JSON-only {phishing,bec,spam,infomail,benign}
    //   then parse and clamp. Falls back to HeuristicClassifier on error/timeout.
    return new HeuristicClassifier().classify(m);
  }
}

export function makeClassifier(): ContentClassifier {
  return process.env.CONTENT_CLASSIFIER === 'llm'
    ? new LLMClassifier()
    : new HeuristicClassifier();
}
