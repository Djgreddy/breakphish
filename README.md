# BreakPhish — MVP scaffold

A runnable reference implementation of two products on one multi-tenant core,
sold à la carte via entitlements:

**1. Security Awareness Training** — the phishing-simulation loop:

```
M365 directory sync  →  campaign send  →  tracked click  →  auto-enrolled training
```

**2. Email Security (API model)** — the "Mesh 365"-style detection loop:

```
onboard (API service)  →  ingest inbound mail  →  score  →  policy  →  quarantine/dashboard
```

Gateway (MX) and Unified services appear in onboarding but are gated as
coming-soon until the MTA fleet exists; the API service is fully live here.

It runs **fully offline** with a mock directory and a console mailer, so you can
see the whole loop before wiring up real Microsoft Graph or an email provider.
Everything swappable (directory source, mailer, data store) sits behind an
interface so going to production is a one-file change, not a rewrite.

## Run it

```bash
npm install
npm run demo        # SAT loop: sync → send → tracked click → auto-training
npm run demo:email  # Email Security: onboard → ingest → score → dashboard
npm run demo:onboard # M365 onboarding: consent → verify → sync → allow-list
npm run api         # live console + API — open http://localhost:4000
npm run typecheck   # strict TypeScript, no errors
npm run server      # just the tracking server on :4000
```

`npm run demo` syncs a mock tenant, launches a campaign, "sends" to 9 users,
then drives real HTTP hits against the tracking endpoints to simulate opens,
clicks, a credential submit, and reports — ending with the phish-prone % and the
list of users auto-enrolled in remediation.

## What's implemented

| Path | File(s) |
| --- | --- |
| Directory sync (full + delta) | `src/directory/` — `provider.ts`, `syncService.ts` |
| Real Microsoft Graph client | `src/directory/graphProvider.ts` (client-credentials + delta) |
| Offline mock directory | `src/directory/mockProvider.ts` |
| Campaign build + audience resolution + launch | `src/campaigns/campaignService.ts` |
| Templates + merge rendering | `src/campaigns/templates.ts` |
| Queue + sending worker | `src/campaigns/queue.ts`, `sendingWorker.ts`, `transport.ts` |
| Per-recipient HMAC tracking tokens | `src/tracking/tokens.ts` |
| Tracking endpoints (open/click/submit/report) | `src/tracking/trackingServer.ts` |
| Auto-remediation on click/submit | `src/training/remediation.ts` |
| Funnel + phish-prone reporting | `src/campaigns/reporting.ts` |
| Postgres schema + row-level security | `db/schema.sql` |

### Email Security (API model)

| Path | File(s) |
| --- | --- |
| Customer onboarding + entitlements + service gating | `src/onboarding.ts` |
| Verdict taxonomy + domain types | `src/emailsec/types.ts` |
| Detection pipeline (aggregate → verdict → policy) | `src/emailsec/pipeline.ts` |
| Static scorers (auth / reputation / behavioral / URL+attachment) | `src/emailsec/scorers.ts` |
| Pluggable AI content classifier (heuristic + LLM stub) | `src/emailsec/classifier.ts` |
| Per-tenant policy (verdict → disposition) | `src/emailsec/policy.ts` |
| Quarantine + release store | `src/emailsec/store.ts` |
| Dashboard + Live Email Tracker reporting | `src/emailsec/reporting.ts` |

The pipeline reuses the same M365 integration and tenant model as SAT. Swapping
the heuristic classifier for the real LLM one (`CONTENT_CLASSIFIER=llm`) and the
sample-message source for a Graph ingestion are the only changes to go live.

**Integration models:** `api` is available; `gateway` and `unified` are marked
coming-soon in `INTEGRATION_AVAILABILITY` and rejected at onboarding until the
MX relay fleet is built.

### M365 onboarding (Entra admin consent)

| Path | File(s) |
| --- | --- |
| Admin-consent URL, callback handling, connection store | `src/consent.ts` |
| Graph permission scopes per product (least privilege) | `src/consent.ts` (`GRAPH_PERMISSIONS`) |
| Org verification + verified-domain read (mock + Graph) | `src/directory/graphOrg.ts` |
| Consent start/callback HTTP routes | `src/consentServer.ts` |
| M365 allow-listing config + test-send verification (SAT) | `src/allowlist.ts` |

`npm run demo:onboard` walks the whole flow: create customer → build the
consent URL (with the exact scopes the admin sees) → simulate a declined consent
→ simulate a granted consent → verify the tenant and read its verified domains →
directory sync → generate + verify the Advanced Delivery allow-listing values.

**Scopes** are read-only for directory (`User.Read.All`, `Group.Read.All`,
`GroupMember.Read.All`, `Organization.Read.All`); `Mail.Read` + `Mail.ReadWrite`
are added only when the customer bought Email Security (needed to remediate
delivered threats). To run against real Microsoft: set `DIRECTORY_PROVIDER=graph`
plus `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` / `GRAPH_REDIRECT_URI`, register
the multi-tenant app in Entra with those permissions, and serve `consentServer`.

### Live console + API

`npm run api` boots the whole thing: it onboards a few customers, connects them
(mock consent → directory sync → scores a stream of inbound mail through the real
pipeline), then serves a JSON API and an **API-wired console** from the same
origin. Open `http://localhost:4000` and the console reads **live data** — real
connection status, real synced users, and real scored mail (no synthetic
browser data). Click a flagged message and the detail panel shows the actual
signals the scorers produced, with weights.

| Path | File(s) |
| --- | --- |
| HTTP API over the services | `src/api.ts` |
| Server: seed + serve API + console | `src/apiServer.ts` |
| API-wired console (fetches `/api/*`) | `web/console.html` |
| Realistic message generator (fed through the real pipeline) | `src/emailsec/generate.ts` |

API endpoints: `GET /api/customers`, `POST /api/customers`,
`POST /api/customers/:id/connect`, `GET /api/customers/:id/dashboard`,
`GET /api/customers/:id/messages`, `GET /api/customers/:id/messages/:mid`,
`GET /api/customers/:id/users`, `GET /api/customers/:id/quarantine`,
`GET /api/customers/:id/policy`, plus the consent routes from `consentServer`.

The published console artifact (claude.ai) stays synthetic because a hosted page
can't reach a localhost API; this `web/console.html` is the real-data version you
run locally and point at your own API in production.

### Authentication & SSO

Real sign-in replaces the role toggle. `npm run api` now opens on a login screen.

| Path | File(s) |
| --- | --- |
| Identity / role / session types | `src/auth/identity.ts` |
| Signed session tokens + cookie | `src/auth/session.ts` |
| Role resolution from the Entra `tid` claim | `src/auth/roles.ts` |
| Auth providers (mock personas + real Entra OIDC) | `src/auth/provider.ts` |
| Auth middleware (requireAuth / requirePartner / customer scope) | `src/auth/middleware.ts` |
| Auth routes (login, callback, me, logout, impersonate) | `src/auth/authServer.ts` |

How it works: the Entra `tid` (tenant id) claim decides the role — the MSP's own
tenant → **Partner admin** (sees all customers); a customer's connected tenant →
that customer's **Administrator** (scoped to their org); anything else is denied.
Partners impersonate a customer via **Login As**, which issues a scoped
administrator session that remembers the acting partner (Return to partner
reverses it). The same multi-tenant Entra app from consent is reused for
"Sign in with Microsoft" (`AUTH_PROVIDER=entra`); mock mode uses one-click
persona buttons offline.

Enforcement is verified: unauthenticated calls get 401, a customer admin gets
403 on any other customer's data and on the all-customers list, and impersonation
correctly narrows a partner to a single customer. **Note:** the Entra provider
decodes the `id_token` for the scaffold; production must validate its signature
against Microsoft's JWKS and check `iss`/`aud`/`nonce`.

## Two hard rules enforced in code

1. **No credential capture.** The submit endpoint records only that a submit
   happened; it never reads, logs, or stores the posted body. The demo POSTs a
   fake password and asserts it's absent from the store.
2. **Targets stay inside the tenant.** Sync drops any user whose email domain
   isn't in the tenant's `verifiedDomains` — simulations can't be aimed outside
   the authorizing organization.

## Going from mock to real

Set these in `.env` (see `.env.example`):

- `DIRECTORY_PROVIDER=graph` + `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` — uses
  the real multi-tenant Graph app. (Prefer certificate auth in production.)
- Swap `ConsoleTransport` in `src/campaigns/transport.ts` for an ESP that allows
  simulation content and dedicated warmed IPs.
- Replace `src/store.ts` with a Postgres-backed store using `db/schema.sql`; set
  `app.tenant_id` per request so row-level security isolates tenants.
- Replace the in-process queue with SQS / RabbitMQ / Redis streams.

## Not in this scaffold (next up)

- **Unified console UI** — the single pane: product switcher (SAT / Email
  Security / both), Partner vs Administrator roles, "Login As", the onboarding
  wizard, Live Email Tracker, and quarantine review screens.
- **SSO/auth** — WorkOS or Auth0 + native Entra OIDC.
- **Real detection efficacy** — LLM classifier wiring, threat-intel feeds, URL
  detonation and attachment sandboxing (bought, not built), and the feedback
  loop from releases/reports. This is the continuous program, not a feature.
- **Gateway (MX) service** — the MTA relay fleet behind the gated card.
- SAT: M365 allow-listing wizard, Report-Phish add-in, drip scheduling, module
  player.

The spec covers all of these; this scaffold is the spine they attach to.
