// Email-security domain types. The verdict taxonomy mirrors the customer
// dashboard: Clean / Spam / Phishing / Malware / Impersonation / Policy, plus
// a graded "spam-likely" band that is delivered-but-tagged.

export type Product = 'sat' | 'email_security';

// The three service cards from the new-customer wizard.
// 'api' is live; the other two are gated as coming-soon for now.
export type IntegrationModel = 'api' | 'gateway' | 'unified';

export const INTEGRATION_AVAILABILITY: Record<IntegrationModel, 'available' | 'coming_soon'> = {
  api: 'available',       // "Mesh 365"-style: Microsoft Graph, post-delivery
  gateway: 'coming_soon', // MX-based relay fleet — not built yet
  unified: 'coming_soon', // API + MX together — not built yet
};

export type Verdict =
  | 'clean'
  | 'spam'
  | 'spam_likely'
  | 'phishing'
  | 'malware'
  | 'impersonation'
  | 'policy_infomail'
  | 'policy_geo';

// What actually happened to the message. In the API model, detection is
// post-delivery, so a block is a clawback ("remediated").
export type Disposition = 'deliver' | 'junk' | 'quarantine' | 'remediated';

export type Direction = 'inbound' | 'outbound' | 'internal';

export interface Attachment {
  filename: string;
  // Pretend content type; a real pipeline hashes + detonates these.
  contentType: string;
}

// A message as handed to the pipeline (what a Graph ingestion would normalize to).
export interface Message {
  id: string;                      // Graph item id (changes when the message moves folders)
  internetMessageId?: string;      // stable RFC id (use this to re-find the message)
  senderIp?: string;               // connecting IP (from Microsoft headers)
  msVerdict?: string;              // Microsoft's own spam verdict (SFV/BCL)
  senderCountry?: string;          // sender country (from Microsoft headers)
  transportHops?: { index: number; from: string; by: string; ip: string; at: string | null }[];
  mailboxUserId?: string;          // the mailbox this copy was ingested from (for per-recipient dedupe)
  toHeader?: string;               // original To header (e.g. the distro group address)
  tenantId: string;
  direction: Direction;
  source: 'external' | 'internal';
  fromAddress: string;
  fromDisplay: string;
  to: string;
  subject: string;
  bodyText: string;
  receivedAt: string;
  // Signals a real pipeline derives from headers / intel; pre-computed here.
  auth: { spf: 'pass' | 'fail' | 'none'; dkim: 'pass' | 'fail' | 'none'; dmarc: 'pass' | 'fail' | 'none'; compauth?: 'pass' | 'fail' | 'softpass' | 'none' };
  replyTo?: string;
  senderDomainAgeDays: number;
  firstTimeSender: boolean;
  urls: string[];
  linkMismatch?: boolean;
  attachments: Attachment[];
}

// One detector's output. Many signals aggregate into a verdict.
export interface Signal {
  code: string;           // e.g. 'dmarc_fail'
  detail: string;         // human-readable
  category: Exclude<Verdict, 'clean' | 'spam_likely'>; // which bucket it pushes toward
  weight: number;         // 0..100 contribution
}

export interface Analysis {
  releasedManually?: boolean;
  messageId: string;
  tenantId: string;
  verdict: Verdict;
  confidence: number;     // 0..1
  disposition: Disposition;
  remediated: boolean;    // clawed back after delivery
  signals: Signal[];
}
