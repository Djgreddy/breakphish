// The cheap, deterministic detection layers that run before the content model.
// Each returns Signals that the aggregator combines. Order matters only for
// cost in production (cheap checks first); here they all run.

import type { Message, Signal } from './types';

// Known internal exec display names per tenant would come from directory sync;
// hard-coded here for the demo to show display-name impersonation detection.
const KNOWN_EXECS = ['David Chen', 'COMHOME Admin', 'Alice Nguyen'];

const MALWARE_EXTS = ['.exe', '.zip', '.iso', '.html', '.htm', '.js', '.scr'];

// Microsoft already evaluates authentication (incl. composite auth / ARC / forwarding)
// and classifies the message. If it passed compauth, or Microsoft delivered it as
// Not Spam / Bulk, the raw SPF/DKIM/DMARC failures are forwarding/config artifacts,
// not spoofing — don't re-penalize them. BreakPhish's value is the content/behavioral
// layer (lookalike, impersonation, LLM intent), which still runs regardless.
export function msDeemedLegit(m: Message): boolean {
  if (m.auth.compauth === 'pass') return true;
  const v = (m.msVerdict ?? '').toLowerCase();
  return v.startsWith('not spam') || v.startsWith('bulk');
}

export function authScorer(m: Message): Signal[] {
  const out: Signal[] = [];
  if (msDeemedLegit(m)) return out; // Microsoft vouched for auth — don't re-penalize
  if (m.auth.dmarc === 'fail') {
    out.push({ code: 'dmarc_fail', detail: 'DMARC alignment failed', category: 'phishing', weight: 35 });
  }
  if (m.auth.spf === 'fail') {
    out.push({ code: 'spf_fail', detail: 'SPF failed', category: 'spam', weight: 20 });
  }
  if (m.auth.dkim === 'fail') {
    out.push({ code: 'dkim_fail', detail: 'DKIM signature invalid', category: 'spam', weight: 15 });
  }
  return out;
}

export function reputationScorer(m: Message): Signal[] {
  const out: Signal[] = [];
  if (m.senderDomainAgeDays < 30) {
    out.push({ code: 'new_domain', detail: `sender domain is ${m.senderDomainAgeDays}d old`, category: 'phishing', weight: 30 });
  }
  const domain = m.fromAddress.split('@')[1] ?? '';
  if (/gmail\.com|outlook\.com|protonmail\.com/.test(domain) && m.direction === 'inbound') {
    // consumer domain claiming a business identity is a mild signal
    out.push({ code: 'consumer_domain', detail: 'business request from a consumer mailbox', category: 'impersonation', weight: 15 });
  }
  return out;
}

export function behavioralScorer(m: Message): Signal[] {
  const out: Signal[] = [];
  if (m.firstTimeSender) {
    out.push({ code: 'first_time_sender', detail: 'first email from this sender to this org', category: 'phishing', weight: 12 });
  }
  if (m.replyTo && m.replyTo.split('@')[1] !== m.fromAddress.split('@')[1]) {
    out.push({ code: 'replyto_mismatch', detail: 'Reply-To domain differs from From', category: 'impersonation', weight: 28 });
  }
  // Display-name impersonation: a known exec name from an unexpected domain.
  const execMatch = KNOWN_EXECS.find(n => m.fromDisplay.toLowerCase().includes(n.toLowerCase()));
  if (execMatch) {
    const domain = m.fromAddress.split('@')[1] ?? '';
    const looksInternal = domain.includes('comhome') || domain.includes('acme');
    if (!looksInternal) {
      out.push({ code: 'execname_spoof', detail: `display name impersonates "${execMatch}"`, category: 'impersonation', weight: 45 });
    }
  }
  return out;
}

export function urlAttachmentScorer(m: Message): Signal[] {
  const out: Signal[] = [];
  for (const a of m.attachments) {
    const ext = a.filename.slice(a.filename.lastIndexOf('.')).toLowerCase();
    if (MALWARE_EXTS.includes(ext)) {
      out.push({ code: 'risky_attachment', detail: `attachment ${a.filename} (${ext})`, category: 'malware', weight: 55 });
    }
  }
  for (const u of m.urls) {
    if (/bit\.ly|tinyurl|\.ru\/|login-|-secure\.|verify-/.test(u)) {
      out.push({ code: 'suspicious_url', detail: `link ${u}`, category: 'phishing', weight: 25 });
    }
  }
  return out;
}

export function runStaticScorers(m: Message): Signal[] {
  return [
    ...authScorer(m),
    ...reputationScorer(m),
    ...behavioralScorer(m),
    ...urlAttachmentScorer(m),
  ];
}
