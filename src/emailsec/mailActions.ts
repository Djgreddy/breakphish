// Remediation actions on real mailboxes via Microsoft Graph (Mail.ReadWrite).
//
// IMPORTANT: a Graph message item id changes when the message moves folders, so
// the id captured at scan time is stale after the first move. These actions
// therefore RE-RESOLVE the message by its stable internetMessageId before acting.
// Mock mode logs; graph mode acts for real.

import { config } from '../config';
import { appToken } from '../directory/graphProvider';

const GRAPH = 'https://graph.microsoft.com/v1.0';
const QUARANTINE_FOLDER = 'BreakPhish Quarantine';

export interface MsgRef { graphId: string; internetMessageId?: string }

export interface MailActions {
  moveToJunk(entraTenantId: string, userId: string, ref: MsgRef): Promise<void>;
  moveToQuarantine(entraTenantId: string, userId: string, ref: MsgRef): Promise<void>;
  moveToInbox(entraTenantId: string, userId: string, ref: MsgRef): Promise<void>;
  moveToDeleted(entraTenantId: string, userId: string, ref: MsgRef): Promise<void>;
}

class MockMailActions implements MailActions {
  async moveToJunk(_t: string, u: string, r: MsgRef) { console.log(`[mailActions:mock] junk ${u} ${r.graphId}`); }
  async moveToQuarantine(_t: string, u: string, r: MsgRef) { console.log(`[mailActions:mock] quarantine ${u} ${r.graphId}`); }
  async moveToInbox(_t: string, u: string, r: MsgRef) { console.log(`[mailActions:mock] release→inbox ${u} ${r.graphId}`); }
  async moveToDeleted(_t: string, u: string, r: MsgRef) { console.log(`[mailActions:mock] delete ${u} ${r.graphId}`); }
}

class GraphMailActions implements MailActions {
  // Resolve the message's CURRENT item id by its stable internetMessageId.
  private async currentId(token: string, userId: string, ref: MsgRef): Promise<string> {
    if (!ref.internetMessageId) return ref.graphId;
    const imid = ref.internetMessageId.replace(/'/g, "''");
    const res = await fetch(
      `${GRAPH}/users/${encodeURIComponent(userId)}/messages?$filter=internetMessageId eq '${imid}'&$select=id&$top=1`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    if (res.ok) {
      const j = (await res.json()) as { value: { id: string }[] };
      if (j.value?.[0]) return j.value[0].id;
    }
    return ref.graphId; // fall back to the stored id
  }

  private async move(entraTenantId: string, userId: string, ref: MsgRef, destinationId: string) {
    const token = await appToken(entraTenantId);
    const id = await this.currentId(token, userId, ref);
    const res = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages/${id}/move`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ destinationId }),
    });
    if (!res.ok) throw new Error(`move failed ${res.status}: ${await res.text()}`);
  }

  // Find (incl. hidden) or create the quarantine folder; tolerate 409.
  private async quarantineFolderId(entraTenantId: string, userId: string): Promise<string> {
    const token = await appToken(entraTenantId);
    const find = async () => {
      const r = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/mailFolders?includeHiddenFolders=true&$filter=displayName eq '${QUARANTINE_FOLDER}'&$select=id`, { headers: { authorization: `Bearer ${token}` } });
      if (r.ok) { const j = (await r.json()) as { value: { id: string }[] }; return j.value?.[0]?.id; }
      return undefined;
    };
    const existing = await find();
    if (existing) return existing;
    const create = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/mailFolders`, {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: QUARANTINE_FOLDER, isHidden: true }),
    });
    if (create.ok) return ((await create.json()) as { id: string }).id;
    // 409 (already exists) or other — re-find and use it.
    const after = await find();
    if (after) return after;
    throw new Error(`quarantine folder ${create.status}: ${await create.text()}`);
  }

  async moveToJunk(t: string, u: string, r: MsgRef) { await this.move(t, u, r, 'junkemail'); }
  async moveToQuarantine(t: string, u: string, r: MsgRef) { const fid = await this.quarantineFolderId(t, u); await this.move(t, u, r, fid); }
  async moveToInbox(t: string, u: string, r: MsgRef) { await this.move(t, u, r, 'inbox'); }
  async moveToDeleted(t: string, u: string, r: MsgRef) { await this.move(t, u, r, 'deleteditems'); }
}

// Where does this message currently live in the mailbox? Resolves by
// internetMessageId (folder moves change the Graph id) and returns the folder's
// display name — Inbox, Junk Email, Deleted Items, a quarantine folder, or a
// user-created folder. Returns null if the message can't be found.
const WELL_KNOWN_FOLDER: Record<string, string> = {
  inbox: 'Inbox', junkemail: 'Junk Email', deleteditems: 'Deleted Items', sentitems: 'Sent Items',
  drafts: 'Drafts', archive: 'Archive', clutter: 'Clutter', conversationhistory: 'Conversation History',
};
export async function currentFolder(entraTenantId: string, mailbox: string, internetMessageId: string, graphId?: string): Promise<string | null> {
  try {
    const token = await appToken(entraTenantId);
    const base = `${GRAPH}/users/${encodeURIComponent(mailbox)}`;
    let folderId = '';
    if (internetMessageId) {
      const r = await fetch(`${base}/messages?$filter=internetMessageId eq '${internetMessageId.replace(/'/g, "''")}'&$select=id,parentFolderId&$top=1`, { headers: { authorization: `Bearer ${token}` } });
      if (r.ok) { const j: any = await r.json(); folderId = j.value?.[0]?.parentFolderId ?? ''; }
    }
    if (!folderId && graphId) {
      const r = await fetch(`${base}/messages/${graphId}?$select=parentFolderId`, { headers: { authorization: `Bearer ${token}` } });
      if (r.ok) folderId = (await r.json()).parentFolderId ?? '';
    }
    if (!folderId) return null; // not found — moved out of this mailbox or hard-deleted
    const f = await fetch(`${base}/mailFolders/${folderId}?$select=displayName,wellKnownName`, { headers: { authorization: `Bearer ${token}` } });
    if (!f.ok) return null;
    const j: any = await f.json();
    const wk = (j.wellKnownName ?? '').toLowerCase();
    return WELL_KNOWN_FOLDER[wk] ?? j.displayName ?? null;
  } catch { return null; }
}

export function makeMailActions(): MailActions {
  return config.directoryProvider === 'graph' ? new GraphMailActions() : new MockMailActions();
}

// Rewrite links in a message body so clicks pass through BreakPhish's protection
// redirect. Idempotent (skips already-rewritten bodies).
const REWRITE_MARK = 'data-bp-links';
export async function rewriteLinks(entraTenantId: string, userId: string, ref: MsgRef, baseUrl: string): Promise<boolean> {
  if (config.directoryProvider !== 'graph') { console.log(`[linkrw:mock] rewrite ${userId} ${ref.graphId}`); return true; }
  try {
    const token = await appToken(entraTenantId);
    const sel = ref.internetMessageId
      ? `?$filter=internetMessageId eq '${ref.internetMessageId.replace(/'/g, "''")}'&$select=id,body&$top=1`
      : null;
    let id = ref.graphId, body = '';
    if (sel) { const f = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages${sel}`, { headers: { authorization: `Bearer ${token}` } }); if (f.ok) { const j: any = await f.json(); if (j.value?.[0]) { id = j.value[0].id; body = j.value[0].body?.content ?? ''; } } }
    else { const f = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages/${id}?$select=id,body`, { headers: { authorization: `Bearer ${token}` } }); if (f.ok) { const j: any = await f.json(); body = j.body?.content ?? ''; } }
    if (!body || body.includes(REWRITE_MARK)) return true;
    const rewritten = body.replace(/href\s*=\s*"(https?:\/\/[^"]+)"/gi, (_m, url) => `href="${baseUrl}/l?u=${encodeURIComponent(url)}"`);
    if (rewritten === body) return true;
    const stamped = `<!--${REWRITE_MARK}-->` + rewritten;
    const res = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages/${id}`, {
      method: 'PATCH', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ body: { contentType: 'html', content: stamped } }),
    });
    if (!res.ok) { console.error(`[linkrw] patch failed ${res.status}`); return false; }
    return true;
  } catch (e) { console.error('[linkrw] failed', (e as Error).message); return false; }
}

// Stamp a warning banner into the top of a message body (HTML). Idempotent via a
// marker comment so a re-scan won't double-stamp.
const BANNER_MARK = 'data-bp-banner';
export async function prependBanner(entraTenantId: string, userId: string, ref: MsgRef, bannerHtml: string): Promise<boolean> {
  if (config.directoryProvider !== 'graph') { console.log(`[banner:mock] stamp ${userId} ${ref.graphId}`); return true; }
  try {
    const token = await appToken(entraTenantId);
    // resolve current id + read current body
    const imid = ref.internetMessageId ? `?$filter=internetMessageId eq '${ref.internetMessageId.replace(/'/g, "''")}'&$select=id,body` : '';
    let id = ref.graphId, body = '';
    if (imid) {
      const f = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages${imid}&$top=1`, { headers: { authorization: `Bearer ${token}` } });
      if (f.ok) { const j: any = await f.json(); if (j.value?.[0]) { id = j.value[0].id; body = j.value[0].body?.content ?? ''; } }
    } else {
      const f = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages/${id}?$select=id,body`, { headers: { authorization: `Bearer ${token}` } });
      if (f.ok) { const j: any = await f.json(); body = j.body?.content ?? ''; }
    }
    if (body.includes(BANNER_MARK)) return true; // already stamped
    const stamped = `<div ${BANNER_MARK}="1">${bannerHtml}</div>` + body;
    const res = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages/${id}`, {
      method: 'PATCH', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ body: { contentType: 'html', content: stamped } }),
    });
    if (!res.ok) { console.error(`[banner] patch failed ${res.status}`); return false; }
    return true;
  } catch (e) { console.error('[banner] failed', (e as Error).message); return false; }
}

// Apply a disposition to the real mailbox. Returns true if it acted without error.
export async function applyDisposition(entraTenantId: string, userId: string, ref: MsgRef, disposition: string): Promise<boolean> {
  try {
    const a = makeMailActions();
    if (disposition === 'junk') await a.moveToJunk(entraTenantId, userId, ref);
    else if (disposition === 'quarantine' || disposition === 'remediated') await a.moveToQuarantine(entraTenantId, userId, ref);
    return true;
  } catch (e) {
    console.error(`[mailActions] ${disposition} failed for ${ref.graphId}:`, (e as Error).message);
    return false;
  }
}
