// A DirectoryProvider abstracts "where users and groups come from". The sync
// service only talks to this interface, so Microsoft Graph, a mock, SCIM, or
// Google Workspace are interchangeable.

export interface DirUser {
  externalId: string;
  email: string;
  displayName: string;
  department?: string;
  enabled: boolean;
  removed?: boolean; // delta tombstone
}

export interface DirGroup {
  externalId: string;
  name: string;
  memberExternalIds: string[];
  removed?: boolean;
}

export interface DirSnapshot {
  users: DirUser[];
  groups: DirGroup[];
  // Opaque cursor to pass back next time for an incremental (delta) pull.
  deltaLink?: string;
}

export interface DirectoryProvider {
  // Full pull on first sync.
  fullSync(entraTenantId: string): Promise<DirSnapshot>;
  // Incremental pull using the cursor from a previous snapshot.
  deltaSync(entraTenantId: string, deltaLink: string): Promise<DirSnapshot>;
}
