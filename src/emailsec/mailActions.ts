// Remediation actions on real mailboxes via Microsoft Graph (Mail.ReadWrite).
// This is what turns a verdict into an action: move a message to Junk, or claw
// it back into a hidden "BreakPhish Quarantine" folder.
//
// Mock mode logs instead of calling Graph, so the flow runs offline; the
// disposition the pipeline records already reflects the intended action, so the
// Quarantine screen populates either way. In graph mode it also moves the real
// message.

import { config } from '../config';
import { appToken } from '../directory/graphProvider';

const GRAPH = 'https://graph.microsoft.com/v1.0';
const QUARANTINE_FOLDER = 'BreakPhish Quarantine';

export interface MailActions {
  moveToJunk(entraTenantId: string, userId: string, messageId: string): Promise<void>;
  moveToQuarantine(entraTenantId: string, userId: string, messageId: string): Promise<void>;
  moveToInbox(entraTenantId: string, userId: string, messageId: string): Promise<void>; // release
  moveToDeleted(entraTenantId: string, userId: string, messageId: string): Promise<void>;
}

class MockMailActions implements MailActions {
  async moveToJunk(_t: string, u: string, m: string) { console.log(`[mailActions:mock] junk ${u} ${m}`); }
  async moveToQuarantine(_t: string, u: string, m: string) { console.log(`[mailActions:mock] quarantine ${u} ${m}`); }
  async moveToInbox(_t: string, u: string, m: string) { console.log(`[mailActions:mock] release→inbox ${u} ${m}`); }
  async moveToDeleted(_t: string, u: string, m: string) { console.log(`[mailActions:mock] delete ${u} ${m}`); }
}

class GraphMailActions implements MailActions {
  private async move(entraTenantId: string, userId: string, messageId: string, destinationId: string) {
    const token = await appToken(entraTenantId);
    const res = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/messages/${messageId}/move`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ destinationId }),
    });
    if (!res.ok) throw new Error(`move failed ${res.status}: ${await res.text()}`);
  }

  // Find (or create) the hidden quarantine folder and return its id.
  private async quarantineFolderId(entraTenantId: string, userId: string): Promise<string> {
    const token = await appToken(entraTenantId);
    const find = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/mailFolders?$filter=displayName eq '${QUARANTINE_FOLDER}'`, { headers: { authorization: `Bearer ${token}` } });
    if (find.ok) {
      const j = (await find.json()) as { value: { id: string }[] };
      if (j.value?.[0]) return j.value[0].id;
    }
    const create = await fetch(`${GRAPH}/users/${encodeURIComponent(userId)}/mailFolders`, {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: QUARANTINE_FOLDER, isHidden: true }),
    });
    if (!create.ok) throw new Error(`create quarantine folder failed ${create.status}: ${await create.text()}`);
    return ((await create.json()) as { id: string }).id;
  }

  async moveToJunk(entraTenantId: string, userId: string, messageId: string) {
    await this.move(entraTenantId, userId, messageId, 'junkemail'); // well-known folder
  }
  async moveToQuarantine(entraTenantId: string, userId: string, messageId: string) {
    const fid = await this.quarantineFolderId(entraTenantId, userId);
    await this.move(entraTenantId, userId, messageId, fid);
  }
  async moveToInbox(entraTenantId: string, userId: string, messageId: string) {
    await this.move(entraTenantId, userId, messageId, 'inbox'); // release back to inbox
  }
  async moveToDeleted(entraTenantId: string, userId: string, messageId: string) {
    await this.move(entraTenantId, userId, messageId, 'deleteditems');
  }
}

export function makeMailActions(): MailActions {
  return config.directoryProvider === 'graph' ? new GraphMailActions() : new MockMailActions();
}

// Apply a disposition to the real mailbox. Best-effort — a failed move logs but
// doesn't break the scan.
export async function applyDisposition(entraTenantId: string, userId: string, messageId: string, disposition: string): Promise<void> {
  try {
    const a = makeMailActions();
    if (disposition === 'junk') await a.moveToJunk(entraTenantId, userId, messageId);
    else if (disposition === 'quarantine' || disposition === 'remediated') await a.moveToQuarantine(entraTenantId, userId, messageId);
  } catch (e) {
    console.error(`[mailActions] ${disposition} failed for ${messageId}:`, (e as Error).message);
  }
}
