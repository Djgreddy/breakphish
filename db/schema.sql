-- BreakPhish — full Postgres schema (pilot).
--
-- Covers everything the app persists today: customers + entitlements, Microsoft
-- tenant connections, synced directory users/groups, email messages + analyses
-- + quarantine, SAT campaigns, team members, and the audit log.
--
-- Tenant isolation is modeled with a tenant_id on customer-scoped tables. The
-- app enforces scope in the data layer (every query is customer-scoped); the
-- commented RLS policies at the bottom can be enabled for defense-in-depth once
-- the app sets `app.tenant_id` per connection.

create extension if not exists "pgcrypto";

-- ------- partner / customers -------
create table if not exists customers (
  id                text primary key,
  name              text not null,
  primary_domain    text not null,
  entra_tenant_id   text,
  verified_domains  text[] not null default '{}',
  products          text[] not null default '{}',
  integration_model text,
  mailboxes         integer not null default 0,
  status            text not null default 'active',
  created_at        timestamptz not null default now()
);

-- ------- Microsoft connection state (one per customer) -------
create table if not exists connections (
  customer_id      text primary key references customers(id) on delete cascade,
  entra_tenant_id  text,
  status           text not null default 'pending',
  reason           text,
  display_name     text,
  verified_domains text[] not null default '{}',
  granted_scopes   text[] not null default '{}',
  connected_at     timestamptz
);

-- ------- directory: users + groups -------
create table if not exists users (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    text not null references customers(id) on delete cascade,
  external_id  text not null,
  email        text not null,
  display_name text not null,
  department   text,
  enabled      boolean not null default true,
  unique (tenant_id, external_id)
);
create index if not exists users_tenant_idx on users(tenant_id);

create table if not exists groups (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           text not null references customers(id) on delete cascade,
  external_id         text not null,
  name                text not null,
  member_external_ids text[] not null default '{}',
  unique (tenant_id, external_id)
);
create index if not exists groups_tenant_idx on groups(tenant_id);

-- ------- email security: messages + analyses -------
create table if not exists messages (
  id                     text primary key,
  tenant_id              text not null references customers(id) on delete cascade,
  direction              text not null,
  source                 text not null,
  from_address           text not null,
  from_display           text not null,
  to_address             text not null,
  subject                text not null,
  body_text              text,
  received_at            timestamptz not null,
  auth                   jsonb not null default '{}',
  reply_to               text,
  sender_domain_age_days integer,
  first_time_sender      boolean,
  urls                   text[] not null default '{}',
  attachments            jsonb not null default '[]',
  created_at             timestamptz not null default now()
);
create index if not exists messages_tenant_idx on messages(tenant_id, received_at desc);

create table if not exists analyses (
  message_id   text primary key references messages(id) on delete cascade,
  tenant_id    text not null references customers(id) on delete cascade,
  verdict      text not null,
  confidence   real not null default 0,
  disposition  text not null,
  remediated   boolean not null default false,
  signals      jsonb not null default '[]',
  created_at   timestamptz not null default now()
);
create index if not exists analyses_tenant_idx on analyses(tenant_id);
create index if not exists analyses_verdict_idx on analyses(tenant_id, verdict);

create table if not exists release_requests (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    text not null references customers(id) on delete cascade,
  message_id   text not null references messages(id) on delete cascade,
  requested_by text not null,
  status       text not null default 'pending',
  at           timestamptz not null default now()
);

-- ------- SAT: campaigns + recipients + events + enrollments -------
create table if not exists campaigns (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   text not null references customers(id) on delete cascade,
  name        text not null,
  template_id text not null,
  audience    jsonb not null,
  status      text not null default 'draft',
  created_at  timestamptz not null default now()
);
create table if not exists recipients (
  id          uuid primary key default gen_random_uuid(),
  campaign_id uuid not null references campaigns(id) on delete cascade,
  tenant_id   text not null references customers(id) on delete cascade,
  user_id     uuid,
  email       text not null,
  status      text not null default 'queued',
  token       text not null
);
create table if not exists events (
  id           uuid primary key default gen_random_uuid(),
  campaign_id  uuid not null references campaigns(id) on delete cascade,
  recipient_id uuid not null references recipients(id) on delete cascade,
  tenant_id    text not null references customers(id) on delete cascade,
  type         text not null,
  at           timestamptz not null default now()
);
create unique index if not exists events_recipient_type_idx on events(recipient_id, type);
create table if not exists enrollments (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  text not null references customers(id) on delete cascade,
  user_id    uuid,
  module_id  text not null,
  reason     text not null,
  at         timestamptz not null default now()
);

-- ------- team members (MSP staff) -------
create table if not exists team_members (
  id         uuid primary key default gen_random_uuid(),
  email      text not null unique,
  name       text not null,
  role       text not null default 'partner_admin',
  created_at timestamptz not null default now()
);

-- ------- audit log -------
create table if not exists audit_log (
  id          uuid primary key default gen_random_uuid(),
  at          timestamptz not null default now(),
  actor_email text,
  role        text,
  customer_id text,
  resource    text not null,
  action      text not null,
  response    integer,
  ip          text
);
create index if not exists audit_at_idx on audit_log(at desc);

-- ------- customer management fields (added for the management layer) -------
-- Idempotent: safe to run on an existing customers table.
alter table customers add column if not exists licenses   integer     not null default 0;
alter table customers add column if not exists ordered_at  timestamptz not null default now();
alter table customers add column if not exists flags       jsonb       not null default '{}';

-- ------- partner/customer settings (keyed by scope: 'partner' or a customer id) -------
create table if not exists settings (
  scope      text primary key,
  data       jsonb not null default '{}',
  updated_at timestamptz not null default now()
);

-- ------- policy: templates + rules (partner or customer scope) -------
create table if not exists policy_templates (
  id         text primary key,
  scope      text not null,              -- 'partner' or a customer id
  name       text not null,
  comment    text,
  deployment text,
  data       jsonb not null default '{}',
  is_default boolean not null default false,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists policy_templates_scope_idx on policy_templates(scope);

create table if not exists policy_rules (
  id         text primary key,
  scope      text not null,
  kind       text not null,              -- custom|allow|block|dlp|auto_remediation|link_rewrite
  data       jsonb not null default '{}',
  enabled    boolean not null default true,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists policy_rules_scope_idx on policy_rules(scope, kind);

-- stable RFC message id (survives folder moves; Graph item id does not)
alter table messages add column if not exists internet_message_id text;

-- ------- Graph change-notification subscriptions (real-time ingestion) -------
create table if not exists graph_subscriptions (
  id           text primary key,          -- Graph subscription id
  customer_id  text not null,
  user_id      text not null,             -- mailbox (Entra object id)
  resource     text not null,
  client_state text not null,
  expiration   timestamptz not null,
  created_at   timestamptz not null default now()
);
create index if not exists graph_subscriptions_cust_idx on graph_subscriptions(customer_id);

-- messages an admin manually released (policy is not re-applied to these)
create table if not exists released_overrides (
  internet_message_id text primary key,
  tenant_id           text,
  at                  timestamptz not null default now()
);

-- per-customer disable of a global (partner) rule (customer opt-out)
create table if not exists policy_rule_overrides (
  customer_id text not null,
  rule_id     text not null,
  disabled    boolean not null default true,
  primary key (customer_id, rule_id)
);

-- message enrichment from Microsoft headers
alter table messages add column if not exists sender_ip  text;
alter table messages add column if not exists ms_verdict text;

alter table messages add column if not exists sender_country text;

-- team member fields: local vs SSO + MFA
alter table team_members add column if not exists auth_type text not null default 'sso';   -- 'local' | 'sso'
alter table team_members add column if not exists mfa_enabled boolean not null default false;
alter table team_members add column if not exists status text not null default 'active';   -- active | invited

-- local-auth fields for team members
alter table team_members add column if not exists password_hash text;
alter table team_members add column if not exists totp_secret   text;
alter table team_members add column if not exists totp_enabled  boolean not null default false;

-- audit detail column
alter table audit_log add column if not exists detail text;

-- partner-wide AI provider config (single row; api key stored encrypted)
create table if not exists ai_config (
  id                text primary key default 'partner',
  provider          text not null default 'none',
  api_key_enc       text,
  endpoint          text,
  model             text,
  azure_deployment  text,
  azure_api_version text,
  updated_at        timestamptz not null default now()
);

-- AI usage counters (aggregated per month)
create table if not exists ai_usage (
  month        text primary key,          -- YYYY-MM
  calls        bigint not null default 0,
  input_tokens bigint not null default 0,
  output_tokens bigint not null default 0,
  scored       bigint not null default 0
);
-- editable price (per 1M tokens) for cost estimation
alter table ai_config add column if not exists input_price  numeric not null default 0;
alter table ai_config add column if not exists output_price numeric not null default 0;

-- flag for messages delivered via a manual admin release
alter table analyses add column if not exists released_manually boolean not null default false;

-- enforcement mode: 'passive' (monitor — score+log, no actions) or 'active' (enforce)
-- existing customers default to active (they were already enforcing); new trials start passive.
alter table customers add column if not exists mode text not null default 'active';
