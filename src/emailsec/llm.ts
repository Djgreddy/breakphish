// Provider-agnostic behavioral-AI classifier. Judges intent/tone/language —
// catching payload-less BEC, credential phishing, and impersonation that static
// signatures miss. Supports Azure OpenAI, OpenAI, and Anthropic via config; when
// provider is 'none' it is disabled and the pipeline stays fully static.

import { getLlmConfig } from '../aiConfig';
import { recordLlmCall } from '../aiUsage';
import type { Message } from './types';

type Call = { content: string; usage: { input: number; output: number } };

export interface LlmResult {
  verdict: 'clean' | 'spam' | 'phishing' | 'bec' | 'impersonation';
  confidence: number;      // 0..1
  reason: string;
}

export function llmEnabled(): boolean {
  const c = getLlmConfig();
  return c.provider !== 'none' && !!c.apiKey;
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
Auth: SPF=${m.auth.spf} DKIM=${m.auth.dkim} DMARC=${m.auth.dmarc}${m.auth.compauth && m.auth.compauth !== 'none' ? ` CompositeAuth=${m.auth.compauth} (Microsoft's verdict; pass means legitimate even if SPF/DKIM/DMARC fail, e.g. forwarded mail)` : ''}

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

async function callAzure(m: Message): Promise<Call> {
  const c = getLlmConfig();
  const url = `${c.endpoint.replace(/\/$/, '')}/openai/deployments/${c.azureDeployment}/chat/completions?api-version=${c.azureApiVersion}`;
  const r = await fetch(url, {
    method: 'POST', headers: { 'api-key': c.apiKey, 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: userPrompt(m) }], temperature: 0, max_tokens: 120, response_format: { type: 'json_object' } }),
  });
  if (!r.ok) throw new Error(`azure ${r.status}: ${await r.text()}`);
  const j: any = await r.json();
  return { content: j.choices?.[0]?.message?.content ?? '', usage: { input: j.usage?.prompt_tokens ?? 0, output: j.usage?.completion_tokens ?? 0 } };
}
async function callOpenAI(m: Message): Promise<Call> {
  const c = getLlmConfig();
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST', headers: { authorization: `Bearer ${c.apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ model: c.model, messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: userPrompt(m) }], temperature: 0, max_tokens: 120, response_format: { type: 'json_object' } }),
  });
  if (!r.ok) throw new Error(`openai ${r.status}: ${await r.text()}`);
  const j: any = await r.json();
  return { content: j.choices?.[0]?.message?.content ?? '', usage: { input: j.usage?.prompt_tokens ?? 0, output: j.usage?.completion_tokens ?? 0 } };
}
async function callAnthropic(m: Message): Promise<Call> {
  const c = getLlmConfig();
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'x-api-key': c.apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: c.model, max_tokens: 120, system: SYSTEM, messages: [{ role: 'user', content: userPrompt(m) }] }),
  });
  if (!r.ok) throw new Error(`anthropic ${r.status}: ${await r.text()}`);
  const j: any = await r.json();
  return { content: (j.content ?? []).map((c: any) => c.text ?? '').join(''), usage: { input: j.usage?.input_tokens ?? 0, output: j.usage?.output_tokens ?? 0 } };
}

// For the "Test connection" button — runs one classification on a sample BEC email.
export async function testLlm(): Promise<{ ok: boolean; result?: LlmResult; error?: string }> {
  if (!llmEnabled()) return { ok: false, error: 'No AI provider configured (set a provider and API key).' };
  const sample: Message = {
    id: 'test', internetMessageId: '<test>', tenantId: 'test', direction: 'inbound', source: 'external',
    fromAddress: 'ceo@example-corp.com', fromDisplay: 'Company CEO', to: 'finance@you.com',
    subject: 'Urgent wire request', bodyText: 'Are you at your desk? I need you to process an urgent wire transfer to a new vendor before end of day. Keep this confidential for now.',
    receivedAt: new Date().toISOString(), auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' }, urls: [], attachments: [],
  } as any;
  try {
    const prov = getLlmConfig().provider;
    const call = prov === 'azure' ? await callAzure(sample) : prov === 'anthropic' ? await callAnthropic(sample) : await callOpenAI(sample);
    const r = parse(call.content);
    if (!r) return { ok: false, error: 'Provider responded but the output could not be parsed.' };
    return { ok: true, result: r };
  } catch (e) { return { ok: false, error: (e as Error).message }; }
}

// Returns null if disabled or on any error (fail-open to the static verdict).
export async function classifyIntent(m: Message): Promise<LlmResult | null> {
  if (!llmEnabled()) return null;
  try {
    const prov = getLlmConfig().provider;
    const call = prov === 'azure' ? await callAzure(m)
      : prov === 'anthropic' ? await callAnthropic(m)
      : await callOpenAI(m);
    recordLlmCall(call.usage.input, call.usage.output);
    return parse(call.content);
  } catch (e) {
    console.error('[llm] classify failed:', (e as Error).message);
    return null;
  }
}
