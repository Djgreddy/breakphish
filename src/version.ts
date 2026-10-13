// Build/version info + a read-only update check.
//
// The app runs inside a container with no .git, so build info comes from
// environment variables set at deploy time (see deploy.sh), and the update check
// asks the GitHub API for the latest commit on your branch and compares. It
// NEVER pulls or deploys — updating stays a deliberate terminal command.

import { config } from './config';

export function buildInfo() {
  return {
    commit: process.env.GIT_COMMIT ?? 'unknown',
    branch: process.env.GIT_BRANCH ?? config.github.branch,
    committedAt: process.env.GIT_COMMITTED_AT ?? null,
    version: process.env.APP_VERSION ?? 'pilot',
  };
}

export interface UpdateStatus {
  upToDate: boolean | null;   // null = can't tell (no repo configured)
  current: string;
  latestRemote: string | null;
  checkedAt: string;
  note?: string;
}

export async function updateStatus(): Promise<UpdateStatus> {
  const checkedAt = new Date().toISOString();
  const current = (process.env.GIT_COMMIT ?? 'unknown').trim();
  const repo = config.github.repo;   // e.g. "yourorg/breakphish"
  const branch = config.github.branch;

  if (!repo) {
    return { upToDate: null, current, latestRemote: null, checkedAt, note: 'Set GITHUB_REPO to enable update checks.' };
  }
  try {
    const headers: Record<string, string> = { accept: 'application/vnd.github+json', 'user-agent': 'breakphish' };
    if (config.github.token) headers.authorization = `Bearer ${config.github.token}`;
    const res = await fetch(`https://api.github.com/repos/${repo}/commits/${encodeURIComponent(branch)}`, { headers });
    if (!res.ok) return { upToDate: null, current, latestRemote: null, checkedAt, note: `GitHub API ${res.status}` };
    const json = (await res.json()) as { sha: string };
    const latestRemote = json.sha.slice(0, 7);
    const cur = current.slice(0, 7);
    const upToDate = current !== 'unknown' ? latestRemote === cur : null;
    return { upToDate, current: cur, latestRemote, checkedAt };
  } catch (e) {
    return { upToDate: null, current, latestRemote: null, checkedAt, note: (e as Error).message };
  }
}
