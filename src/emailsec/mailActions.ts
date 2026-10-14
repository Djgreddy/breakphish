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

export function makeMailActions(): MailActions {
  return config.directoryProvider === 'graph' ? new GraphMailActions() : new MockMailActions();
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
