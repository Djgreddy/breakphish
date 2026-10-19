// Partner-wide AI provider configuration.
//
// Resolution order: if LLM_PROVIDER is set in the environment, that wins and the
// WebUI is read-only ("managed via environment"). Otherwise the DB-stored config
// (set through the WebUI) is used. The API key is encrypted at rest (AES-256-GCM)
// and is NEVER returned to the client — the UI only shows whether a key is set.

import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { config } from './config';
import { dbEnabled, q } from './db/db';

export type Provider = 'none' | 'azure' | 'openai' | 'anthropic';
export interface LlmConfig {
  provider: Provider; apiKey: string; endpoint: string; model: string;
  azureDeployment: string; azureApiVersion: string;
}

const KEY = createHash('sha256').update(config.tokenSecret).digest(); // 32 bytes
function enc(plain: string): string {
  const iv = randomBytes(12); const c = createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return `${iv.toString('hex')}:${c.getAuthTag().toString('hex')}:${ct.toString('hex')}`;
}
function dec(s: string): string {
  try {
    const [iv, tag, ct] = s.split(':');
    const d = createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'hex'));
    d.setAuthTag(Buffer.from(tag, 'hex'));
    return Buffer.concat([d.update(Buffer.from(ct, 'hex')), d.final()]).toString('utf8');
  } catch { return ''; }
}

const envConfigured = () => (process.env.LLM_PROVIDER ?? 'none') !== 'none';

// In-memory copy of the DB config (hydrated on boot).
let db: LlmConfig & { hasKey: boolean } = {
  provider: 'none', apiKey: '', endpoint: '', model: 'gpt-4o-mini', azureDeployment: '', azureApiVersion: '2024-06-01', hasKey: false,
};

// The EFFECTIVE config the classifier uses.
export function getLlmConfig(): LlmConfig & { source: 'env' | 'db' | 'none' } {
  if (envConfigured()) return { ...config.llm, source: 'env' };
  if (db.provider !== 'none') return { provider: db.provider, apiKey: db.apiKey, endpoint: db.endpoint, model: db.model, azureDeployment: db.azureDeployment, azureApiVersion: db.azureApiVersion, source: 'db' };
  return { provider: 'none', apiKey: '', endpoint: '', model: '', azureDeployment: '', azureApiVersion: '', source: 'none' };
}

// What the WebUI sees — no key, plus whether one is set and whether env locks it.
export function publicAiConfig() {
  const eff = getLlmConfig();
  const locked = envConfigured();
  const shown = locked ? config.llm : db;
  return {
    provider: shown.provider, endpoint: shown.endpoint || '', model: shown.model || '',
    azureDeployment: shown.azureDeployment || '', azureApiVersion: shown.azureApiVersion || '2024-06-01',
    hasKey: locked ? !!config.llm.apiKey : db.hasKey,
    locked, source: eff.source, active: eff.provider !== 'none' && (locked ? !!config.llm.apiKey : db.hasKey),
  };
}

// Save from the WebUI. An empty apiKey keeps the existing one (write-only field).
export async function saveAiConfig(input: { provider: Provider; apiKey?: string; endpoint?: string; model?: string; azureDeployment?: string; azureApiVersion?: string }): Promise<void> {
  if (envConfigured()) throw new Error('AI provider is managed via environment variables and cannot be changed here.');
  db.provider = input.provider;
  db.endpoint = input.endpoint ?? '';
  db.model = input.model ?? 'gpt-4o-mini';
  db.azureDeployment = input.azureDeployment ?? '';
  db.azureApiVersion = input.azureApiVersion ?? '2024-06-01';
  if (input.apiKey) { db.apiKey = input.apiKey; db.hasKey = true; }
  if (input.provider === 'none') { db.apiKey = ''; db.hasKey = false; }
  if (dbEnabled()) {
    await q(
      `insert into ai_config (id, provider, api_key_enc, endpoint, model, azure_deployment, azure_api_version, updated_at)
       values ('partner', $1, $2, $3, $4, $5, $6, now())
       on conflict (id) do update set provider=excluded.provider, api_key_enc=excluded.api_key_enc,
         endpoint=excluded.endpoint, model=excluded.model, azure_deployment=excluded.azure_deployment,
         azure_api_version=excluded.azure_api_version, updated_at=now()`,
      [db.provider, db.hasKey ? enc(db.apiKey) : null, db.endpoint, db.model, db.azureDeployment, db.azureApiVersion],
    );
  }
}

export async function hydrateAiConfig(): Promise<void> {
  if (!dbEnabled()) return;
  const rows = await q<any>(`select * from ai_config where id='partner'`);
  const r = rows[0]; if (!r) return;
  const apiKey = r.api_key_enc ? dec(r.api_key_enc) : '';
  db = {
    provider: r.provider ?? 'none', apiKey, endpoint: r.endpoint ?? '', model: r.model ?? 'gpt-4o-mini',
    azureDeployment: r.azure_deployment ?? '', azureApiVersion: r.azure_api_version ?? '2024-06-01', hasKey: !!apiKey,
  };
}
