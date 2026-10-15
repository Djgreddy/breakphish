// The detection pipeline. For each message: run the static scorers, run the
// content classifier, aggregate everything into category scores, pick a verdict,
// then apply the tenant's policy to get a disposition. In the API model, a block
// on an already-delivered message is a clawback → remediated.

import type { Message, Analysis, Signal, Verdict } from './types';
import { runStaticScorers } from './scorers';
import { makeClassifier } from './classifier';
import { dispositionFor } from '../policy';
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

export async function analyze(message: Message): Promise<Analysis> {
  emailStore.saveMessage(message);

  const signals = [...runStaticScorers(message), ...await contentSignals(message)];
  const scores = aggregate(signals);
  const { verdict, confidence } = decideVerdict(scores);

  // If an admin manually released this message, it stays delivered — policy
  // (incl. block rules) is NOT re-applied, so it can't bounce back to quarantine.
  const released = emailStore.isReleased(message.internetMessageId);
  const act = released ? 'deliver' : dispositionFor(message.tenantId, verdict, message);
  const isThreat = ['phishing', 'malware', 'impersonation', 'policy_geo'].includes(verdict);
  const remediated = !released && isThreat && act === 'quarantine'; // post-delivery clawback
  const disposition = remediated ? 'remediated' : act;

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
  await persistScored(message, analysis); // durably store the message + its verdict
  return analysis;
}

// Batch ingest (what a Graph poll / webhook push would feed).
export async function ingestBatch(messages: Message[]): Promise<Analysis[]> {
  const out: Analysis[] = [];
  for (const m of messages) out.push(await analyze(m));
  return out;
}
