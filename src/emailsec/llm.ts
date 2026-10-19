// Provider-agnostic behavioral-AI classifier. Judges intent/tone/language —
// catching payload-less BEC, credential phishing, and impersonation that static
// signatures miss. Supports Azure OpenAI, OpenAI, and Anthropic via config; when
// provider is 'none' it is disabled and the pipeline stays fully static.

import { config } from '../config';
import type { Message } from './types';

export interface LlmResult {
  verdict: 'clean' | 'spam' | 'phishing' | 'bec' | 'impersonation';
  confidence: number;      // 0..1
  reason: string;
}

export function llmEnabled(): boolean {
  return config.llm.provider !== 'none' && !!config.llm.apiKey;
}

const SYSTEM = `You are an email security analyst. Judge an email's INTENT, not just keywords.
Classify it as one of: clean, spam, phishing, bec (business email compromise / wire-fraud / payroll-diversion), impersonation.
Focus on: urgency/pressure, requests for money/gift-cards/wire transfers/credentials, unusual tone or language cadence, mismatch between display name and sender, and requests to break normal process.
Respond ONLY with compact JSON: {"verdict":"...","confidence":0.0-1.0,"reason":"short phrase"}. No prose.`;

function userPrompt(m: Message): string {
  const body = (m.bodyText ?? '').slice(0, 4000);
  return `From: ${m.fromDisplay} <${m.fromAddress}>
To: ${m.to}
Subject: ${m.subject}
Auth: SPF=${m.auth.spf} DKIM=${m.auth.dkim} DMARC=${m.auth.dmarc}

${body}`;
}

function parse(text: string): LlmResult | null {
  try {
    const json = text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1);
    const o = JSON.parse(json);
    const verdict = ['clean', 'spam', 'phishing', 'bec', 'impersonation'].includes(o.verdict) ? o.verdict : 'clean';
    return { verdict, confidence: Math.max(0, Math.min(1, Number(o.confidence) || 0)), reason: String(o.reason ?? '').slice(0, 160) };
  } catch { return null; }
}

async function callAzure(m: Message): Promise<string> {
  const url = `${config.llm.endpoint.replace(/\/$/, '')}/openai/deployments/${config.llm.azureDeployment}/chat/completions?api-version=${config.llm.azureApiVersion}`;
  const r = await fetch(url, {
    method: 'POST', headers: { 'api-key': config.llm.apiKey, 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: userPrompt(m) }], temperature: 0, max_tokens: 120, response_format: { type: 'json_object' } }),
  });
  if (!r.ok) throw new Error(`azure ${r.status}: ${await r.text()}`);
  return (await r.json()).choices?.[0]?.message?.content ?? '';
}
async function callOpenAI(m: Message): Promise<string> {
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST', headers: { authorization: `Bearer ${config.llm.apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ model: config.llm.model, messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: userPrompt(m) }], temperature: 0, max_tokens: 120, response_format: { type: 'json_object' } }),
  });
  if (!r.ok) throw new Error(`openai ${r.status}: ${await r.text()}`);
  return (await r.json()).choices?.[0]?.message?.content ?? '';
}
async function callAnthropic(m: Message): Promise<string> {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'x-api-key': config.llm.apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: config.llm.model, max_tokens: 120, system: SYSTEM, messages: [{ role: 'user', content: userPrompt(m) }] }),
  });
  if (!r.ok) throw new Error(`anthropic ${r.status}: ${await r.text()}`);
  const j: any = await r.json();
  return (j.content ?? []).map((c: any) => c.text ?? '').join('');
}

// Returns null if disabled or on any error (fail-open to the static verdict).
export async function classifyIntent(m: Message): Promise<LlmResult | null> {
  if (!llmEnabled()) return null;
  try {
    const text = config.llm.provider === 'azure' ? await callAzure(m)
      : config.llm.provider === 'anthropic' ? await callAnthropic(m)
      : await callOpenAI(m);
    return parse(text);
  } catch (e) {
    console.error('[llm] classify failed:', (e as Error).message);
    return null;
  }
}
