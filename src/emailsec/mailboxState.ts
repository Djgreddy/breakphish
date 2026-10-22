// Some "mailboxes" in the directory aren't REST-accessible: service accounts,
// shared/resource mailboxes without a license, soft-deleted, or on-premise (hybrid)
// mailboxes. Graph returns "MailboxNotEnabledForRESTAPI". Retrying them every poll
// wastes API calls, floods the logs, and slows the sync. Once we see that error for
// a mailbox we mark it unscannable and skip it going forward (re-learned on restart).

const unscannable = new Set<string>();
const key = (tenantId: string, mailbox: string) => `${tenantId}:${mailbox.toLowerCase()}`;

// Graph errors that mean "this mailbox can't be read/subscribed via REST".
export function isUnscannableError(msg: string): boolean {
  return /MailboxNotEnabledForRESTAPI|inactive, soft-deleted, or is hosted on-premise|ErrorNonExistentMailbox|ResourceNotFound/i.test(msg);
}

export function markUnscannable(tenantId: string, mailbox: string) { unscannable.add(key(tenantId, mailbox)); }
export function isUnscannable(tenantId: string, mailbox: string) { return unscannable.has(key(tenantId, mailbox)); }
export function unscannableCount(tenantId: string) {
  let n = 0; for (const k of unscannable) if (k.startsWith(tenantId + ':')) n++; return n;
}
