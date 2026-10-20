// Central config. Everything swappable between "dev/mock" and "real" lives here.

export const config = {
  // Where the tracking server listens. Tracking URLs are built from publicBaseUrl.
  port: Number(process.env.PORT ?? 4000),
  publicBaseUrl: process.env.PUBLIC_BASE_URL ?? `http://localhost:${process.env.PORT ?? 4000}`,

  // Secret used to sign per-recipient tracking tokens (HMAC). Rotate in prod.
  tokenSecret: process.env.TOKEN_SECRET ?? 'dev-only-not-a-real-secret',

  // 'mock' runs offline with fake directory data.
  // 'graph' calls real Microsoft Graph (needs the Entra app creds below).
  directoryProvider: (process.env.DIRECTORY_PROVIDER ?? 'mock') as 'mock' | 'graph',

  // 'console' just logs the email. Swap for a real ESP transport in prod.
  emailTransport: (process.env.EMAIL_TRANSPORT ?? 'console') as 'console',

  // Behavioral-AI classifier. Provider-agnostic: set LLM_PROVIDER + the matching
  // key/endpoint. 'none' (default) keeps detection fully static (no API calls).
  // Tiered: only the ambiguous middle is escalated to the model.
  llm: {
    provider: (process.env.LLM_PROVIDER ?? 'none') as 'none' | 'azure' | 'openai' | 'anthropic',
    apiKey: process.env.LLM_API_KEY ?? '',
    // Azure: the resource endpoint, e.g. https://my-res.openai.azure.com
    endpoint: process.env.LLM_ENDPOINT ?? '',
    // OpenAI/Anthropic: the model name; Azure: ignored (uses deployment).
    model: process.env.LLM_MODEL ?? 'gpt-4o-mini',
    // Azure deployment name + api version.
    azureDeployment: process.env.LLM_AZURE_DEPLOYMENT ?? '',
    azureApiVersion: process.env.LLM_AZURE_API_VERSION ?? '2024-06-01',
  },

  // IP geolocation for the email transport-chain map. 'maxmind' reads a local
  // GeoLite2-City.mmdb (private, recommended); 'ipapi' calls ip-api.com (sends IPs
  // to a third party); 'none' (default) disables the map and shows the hop list.
  geo: {
    provider: (process.env.GEOIP_PROVIDER ?? 'none') as 'none' | 'maxmind' | 'ipapi',
    dbPath: process.env.GEOIP_DB ?? '/opt/breakphish/GeoLite2-City.mmdb',
  },

  // Microsoft Graph multi-tenant app (only used when directoryProvider = 'graph').
  graph: {
    clientId: process.env.GRAPH_CLIENT_ID ?? '00000000-0000-0000-0000-000000000000',
    clientSecret: process.env.GRAPH_CLIENT_SECRET ?? '', // prefer a certificate in prod
    // Where Microsoft redirects the admin after they grant (or decline) consent.
    redirectUri: process.env.GRAPH_REDIRECT_URI
      ?? `${process.env.PUBLIC_BASE_URL ?? `http://localhost:${process.env.PORT ?? 4000}`}/onboarding/consent/callback`,
  },

  // Default remediation module assigned on a click/submit.
  remediationModuleId: process.env.REMEDIATION_MODULE_ID ?? 'm-phish',

  // For the Settings page's read-only "update available?" check (GitHub API).
  github: {
    repo: process.env.GITHUB_REPO ?? '',        // "owner/name"
    branch: process.env.GITHUB_BRANCH ?? 'main',
    token: process.env.GITHUB_TOKEN ?? '',       // needed only for private repos
  },

  // Authentication / SSO.
  auth: {
    // 'mock' signs users in via persona buttons (offline). 'entra' uses real
    // "Sign in with Microsoft" OIDC against the same multi-tenant app.
    provider: (process.env.AUTH_PROVIDER ?? 'mock') as 'mock' | 'entra',
    // The MSP's own Entra tenant. Users from this tenant are Partner admins.
    partnerTenantId: process.env.PARTNER_TENANT_ID ?? 'partner-tenant',
    sessionSecret: process.env.SESSION_SECRET ?? 'dev-session-secret-change-me',
    cookieName: 'bp_session',
    sessionTtlSec: Number(process.env.SESSION_TTL ?? 3600),
  },

  // Phishing-simulation sending identity the customer allow-lists in M365.
  // These are examples; a real deployment pulls them from the ESP + domain pool.
  sending: {
    domains: (process.env.SENDING_DOMAINS ?? 'secure-notify.bpsim.com,mail-alerts.bpsim.net').split(','),
    ips: (process.env.SENDING_IPS ?? '198.51.100.20,198.51.100.21').split(','),
    simulationUrlHost: process.env.SIM_URL_HOST ?? 'track.bpsim.com',
  },
};
