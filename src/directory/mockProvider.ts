// Offline provider: returns deterministic fake users/groups so the whole loop
// runs with zero external setup. The delta call returns one change (a new hire)
// to exercise the incremental path.

import type { DirectoryProvider, DirSnapshot } from './provider';

const BASE_USERS = [
  { externalId: 'u1', email: 'alice.nguyen@acme.test',  displayName: 'Alice Nguyen',  department: 'Finance',     enabled: true },
  { externalId: 'u2', email: 'bob.smith@acme.test',     displayName: 'Bob Smith',     department: 'Finance',     enabled: true },
  { externalId: 'u3', email: 'carla.reyes@acme.test',   displayName: 'Carla Reyes',   department: 'Engineering', enabled: true },
  { externalId: 'u4', email: 'derek.kim@acme.test',     displayName: 'Derek Kim',     department: 'Engineering', enabled: true },
  { externalId: 'u5', email: 'elena.popov@acme.test',   displayName: 'Elena Popov',   department: 'Sales',       enabled: true },
  { externalId: 'u6', email: 'frank.ortiz@acme.test',   displayName: 'Frank Ortiz',   department: 'Sales',       enabled: true },
  { externalId: 'u7', email: 'grace.liu@acme.test',     displayName: 'Grace Liu',     department: 'HR',          enabled: true },
  { externalId: 'u8', email: 'harry.osei@acme.test',    displayName: 'Harry Osei',    department: 'IT',          enabled: true },
];

const BASE_GROUPS = [
  { externalId: 'g1', name: 'Finance',     memberExternalIds: ['u1', 'u2'] },
  { externalId: 'g2', name: 'Engineering', memberExternalIds: ['u3', 'u4'] },
  { externalId: 'g3', name: 'All Staff',   memberExternalIds: ['u1','u2','u3','u4','u5','u6','u7','u8'] },
];

export class MockDirectoryProvider implements DirectoryProvider {
  async fullSync(_entraTenantId: string): Promise<DirSnapshot> {
    return {
      users: BASE_USERS.map(u => ({ ...u })),
      groups: BASE_GROUPS.map(g => ({ ...g })),
      deltaLink: 'mock-delta-cursor-1',
    };
  }

  async deltaSync(_entraTenantId: string, _deltaLink: string): Promise<DirSnapshot> {
    // One new hire joins Sales; nothing else changed.
    return {
      users: [
        { externalId: 'u9', email: 'iris.chen@acme.test', displayName: 'Iris Chen', department: 'Sales', enabled: true },
      ],
      groups: [
        { externalId: 'g3', name: 'All Staff', memberExternalIds: ['u1','u2','u3','u4','u5','u6','u7','u8','u9'] },
      ],
      deltaLink: 'mock-delta-cursor-2',
    };
  }
}
