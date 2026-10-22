// The detection pipeline. For each message: run the static scorers, run the
// content classifier, aggregate everything into category scores, pick a verdict,
// then apply the tenant's policy to get a disposition. In the API model, a block
// on an already-delivered message is a clawback → remediated.

import type { Message, Analysis, Signal, Verdict } from './types';
import { runStaticScorers } from './scorers';
import { runDetectors } from './detectors';
import { baselineScorer, learn, isEstablished, senderStat } from './baseline';
import { domainAgeDays } from './domainAge';
import { classifyIntent, llmEnabled } from './llm';
import { recordScored } from '../aiUsage';
import { makeClassifier } from './classifier';
import { dispositionFor, resolveTemplate, detectionFlags, isAllowlisted } from '../policy';
import { getSettings } from '../settings';
import { emailStore } from './store';
import { persistScored } from '../db/hydrate';

const classifier = makeClassifier();

type Category = Exclude<Verdict, 'clean' | 'spam_likely'>;

function aggregate(signals: Signal[]): Record<Category, number> {
  const scores: Record<Category, number> = {
    spam: 0, phishing: 0, malware: 0, impersonation: 0, policy_infomail: 0, policy_geo: 0,
  };
  for (const s of signals) scores[s.category] = Math.min(100, scores[s.category] + s.weight);
  return scores;
}

function decideVerdict(scores: Record<Category, number>): { verdict: Verdict; confidence: number } {
  // Threats take precedence over spam when present.
  const ranked: [Category, number][] = (Object.entries(scores) as [Category, number][])
    .sort((a, b) => b[1] - a[1]);
  const [topCat, topScore] = ranked[0];

  // Hard thresholds per category.
  if (scores.malware >= 50) return { verdict: 'malware', confidence: scores.malware / 100 };
  if (scores.impersonation >= 45) return { verdict: 'impersonation', confidence: scores.impersonation / 100 };
  if (scores.phishing >= 45) return { verdict: 'phishing', confidence: scores.phishing / 100 };
  if (scores.policy_infomail >= 40) return { verdict: 'policy_infomail', confidence: scores.policy_infomail / 100 };

  if (topCat === 'spam') {
    if (topScore >= 50) return { verdict: 'spam', confidence: topScore / 100 };
    if (topScore >= 25) return { verdict: 'spam_likely', confidence: topScore / 100 };
  }
  if (topScore >= 45) return { verdict: topCat as Verdict, confidence: topScore / 100 };
  return { verdict: 'clean', confidence: 1 - topScore / 100 };
}

// Fold the content classifier's intent scores into signals so they aggregate
// alongside the static ones.
async function contentSignals(m: Message): Promise<Signal[]> {
  const labels = await classifier.classify(m);
  const out: Signal[] = [];
  if (labels.phishing >= 0.5) out.push({ code: 'content_phishing', detail: labels.rationale, category: 'phishing', weight: Math.round(labels.phishing * 45) });
  if (labels.bec >= 0.5) out.push({ code: 'content_bec', detail: labels.rationale, category: 'impersonation', weight: Math.round(labels.bec * 40) });
  if (labels.spam >= 0.5) out.push({ code: 'content_spam', detail: labels.rationale, category: 'spam', weight: Math.round(labels.spam * 45) });
  if (labels.infomail >= 0.5) out.push({ code: 'content_infomail', detail: labels.rationale, category: 'policy_infomail', weight: Math.round(labels.infomail * 55) });
  return out;
}

// Established two-way correspondents are trusted — dampen their non-malware risk
// so normal business mail from known partners isn't false-flagged.
function trustDiscount(scores: Record<Category, number>, m: Message): Record<Category, number> {
  if (m.direction !== 'inbound' || m.source !== 'external') return scores;
  // An admin allow-listing a sender is an explicit trust decision — dampen hard.
  if (isAllowlisted(m.tenantId, m.fromAddress)) {
    scores.spam = Math.round(scores.spam * 0.2);
    scores.phishing = Math.round(scores.phishing * 0.25);
    scores.impersonation = Math.round(scores.impersonation * 0.3);
    scores.policy_infomail = Math.round(scores.policy_infomail * 0.2);
  } else if (isEstablished(m.tenantId, m.fromAddress)) {
    scores.spam = Math.round(scores.spam * 0.5);
    scores.phishing = Math.round(scores.phishing * 0.6);
    scores.impersonation = Math.round(scores.impersonation * 0.7);
    // malware is never discounted by relationship
  }
  return scores;
}

// Microsoft Bulk (BCL) or a List-Unsubscribe header = bulk / newsletter / notification
// mail → classify as Infomail (matches how gateways like Mesh tag it), so the
// customer's Infomail policy action decides what happens to it.
function bulkInfomailSignals(m: Message): import('./types').Signal[] {
  if (m.direction !== 'inbound' || m.source !== 'external') return [];
  const bulk = /bulk/i.test(m.msVerdict ?? '');
  if (bulk || m.listUnsubscribe) {
    const why = [bulk ? 'Microsoft Bulk' : '', m.listUnsubscribe ? 'List-Unsubscribe header' : ''].filter(Boolean).join(' + ');
    return [{ code: 'bulk_infomail', detail: `Bulk / notification mail (${why})`, category: 'policy_infomail', weight: 50 }];
  }
  return [];
}

// Spam filtering sensitivity (from the active policy template) scales the spam
// score: High flags more, Low flags less. Medium is neutral.
function adjustSpamSensitivity(scores: Record<Category, number>, tenantId: string): Record<Category, number> {
  const s = resolveTemplate(tenantId).advanced?.spamSensitivity ?? 'Medium';
  const mult = s === 'High' ? 1.35 : s === 'Low' ? 0.7 : 1;
  if (mult !== 1) scores.spam = Math.min(100, Math.round(scores.spam * mult));
  return scores;
}

// The "ambiguous middle": not confidently clean, not already a hard threat —
// exactly where static signatures miss payload-less BEC. These get the LLM.
function isAmbiguous(verdict: Verdict, confidence: number): boolean {
  if (verdict === 'malware' || verdict === 'phishing' || verdict === 'impersonation') return false; // already caught
  if (verdict === 'clean') return confidence < 0.92;    // not confidently clean
  return confidence < 0.85;                             // spam/infomail with soft confidence
}

export async function analyze(message: Message, opts: { reprocess?: boolean } = {}): Promise<Analysis> {
  emailStore.saveMessage(message);
  if (!opts.reprocess && message.direction === 'inbound' && message.source === 'external') recordScored();

  let signals = [...runStaticScorers(message), ...runDetectors(message), ...baselineScorer(message), ...bulkInfomailSignals(message), ...await contentSignals(message)];
  let scores = trustDiscount(adjustSpamSensitivity(aggregate(signals), message.tenantId), message);
  let { verdict, confidence } = decideVerdict(scores);

  // Newly-registered domain check — only for first-contact external senders (cached),
  // and only when the customer's policy has it enabled.
  if (!opts.reprocess && message.direction === 'inbound' && message.source === 'external' && detectionFlags(message.tenantId).newDomain) {
    const st = senderStat(message.tenantId, message.fromAddress);
    if (!st || st.inbound === 0) {
      const days = await domainAgeDays(message.fromAddress.split('@')[1] ?? '');
      if (days != null && days < 30) {
        signals = [...signals, { code: 'new_domain', detail: `Sender domain was registered ${days} day${days === 1 ? '' : 's'} ago`, category: 'phishing', weight: days < 7 ? 42 : 25 }];
        scores = trustDiscount(adjustSpamSensitivity(aggregate(signals), message.tenantId), message);
        ({ verdict, confidence } = decideVerdict(scores));
      }
    }
  }

  // Tier 2 — behavioral AI only on the ambiguous middle, and only for inbound
  // external mail (where BEC/phishing lives). Fail-open to the static verdict.
  // A customer can opt out of AI content analysis for privacy.
  const aiAllowed = getSettings(message.tenantId).aiAnalysisEnabled !== false;
  if (aiAllowed && llmEnabled() && message.direction === 'inbound' && message.source === 'external' && isAmbiguous(verdict, confidence)) {
    const r = await classifyIntent(message);
    if (r && r.confidence >= 0.6 && r.verdict !== 'clean') {
      const cat = r.verdict === 'bec' ? 'impersonation' : r.verdict === 'spam' ? 'spam' : r.verdict;
      signals = [...signals, { code: 'ai_intent', detail: `AI: ${r.verdict} — ${r.reason}`, category: cat as any, weight: Math.round(r.confidence * 55) }];
      scores = trustDiscount(adjustSpamSensitivity(aggregate(signals), message.tenantId), message);
      ({ verdict, confidence } = decideVerdict(scores));
    } else if (r) {
      signals = [...signals, { code: 'ai_intent', detail: `AI: clean — ${r.reason}`, category: 'spam', weight: 0 }];
    }
  }

  // If an admin manually released this message, it stays delivered — policy
  // (incl. block rules) is NOT re-applied, so it can't bounce back to quarantine.
  const released = emailStore.isReleased(message.internetMessageId);
  const act = released ? 'deliver' : dispositionFor(message.tenantId, verdict, message);
  // Auto-handling is labeled by its disposition (deliver / junk / quarantine).
  // "Remediated" is reserved for a manual admin remediation action.
  const disposition = act;
  const remediated = false;

  const analysis: Analysis = {
    messageId: message.id,
    tenantId: message.tenantId,
    verdict,
    confidence: Math.round(confidence * 100) / 100,
    disposition,
    remediated,
    signals,
  };
  emailStore.saveAnalysis(analysis);
  if (!opts.reprocess) learn(message); // update the behavioral baseline with this correspondence
  await persistScored(message, analysis); // durably store the message + its verdict
  return analysis;
}

// Batch ingest (what a Graph poll / webhook push would feed).
export async function ingestBatch(messages: Message[]): Promise<Analysis[]> {
  const out: Analysis[] = [];
  for (const m of messages) out.push(await analyze(m));
  return out;
}

// Re-score every stored message for a tenant with the CURRENT logic, without
// re-fetching from Graph or taking any mailbox actions. Applies accumulated
// detection/policy fixes to mail that was scored under older rules.
export async function reprocessTenant(tenantId: string): Promise<{ processed: number; changed: number }> {
  const msgs = emailStore.messagesForTenant(tenantId);
  let changed = 0;
  for (const m of msgs) {
    const before = emailStore.analysisFor(m.id)?.disposition;
    const a = await analyze(m, { reprocess: true });
    if (a.disposition !== before) changed++;
  }
  return { processed: msgs.length, changed };
}
