create table if not exists admins (
  id text primary key,
  username text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists app_settings (
  id text primary key default 'main',
  brand_name text not null default 'Hyper Regedit Access',
  app_icon_url text not null default '/icon.png',
  login_background_url text not null default '/assets/hyper-logo.jpeg',
  dashboard_logo_url text not null default '/icon.png',
  live_background_url text not null default '/assets/hyper-logo.jpeg',
  telegram_url text not null default 'https://t.me/your_support',
  maintenance_enabled boolean not null default false,
  maintenance_message text not null default 'System maintenance is running. Please try again later.',
  web_clip_url text not null default 'https://yourdomain.com/app',
  updated_at timestamptz not null default now()
);

create table if not exists packages (
  id text primary key,
  name text not null,
  price numeric(10, 2) not null default 0,
  duration_days integer not null default 7,
  status text not null default 'Active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists app_users (
  id text primary key,
  username text not null unique,
  password_hash text not null,
  package_id text references packages(id) on delete set null,
  package_name text not null default 'Custom Access',
  status text not null default 'Active',
  expires_at timestamptz,
  device_id text,
  device_ids jsonb not null default '[]'::jsonb,
  max_devices integer not null default 1,
  device_locked_at timestamptz,
  last_seen_at timestamptz,
  online_until timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists feature_options (
  id text primary key,
  name text not null,
  slug text not null unique,
  symbol text not null default 'HX',
  icon_url text not null default '',
  description text not null default '',
  enabled boolean not null default true,
  sort_order integer not null default 100,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists user_option_states (
  user_id text not null references app_users(id) on delete cascade,
  option_id text not null references feature_options(id) on delete cascade,
  enabled boolean not null default false,
  updated_at timestamptz not null default now(),
  primary key (user_id, option_id)
);

create table if not exists access_logs (
  id text primary key,
  user_id text references app_users(id) on delete set null,
  username text not null default '',
  action text not null,
  ip_address text not null default '',
  user_agent text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists app_users_username_idx on app_users(username);
create index if not exists app_users_status_idx on app_users(status);
create index if not exists feature_options_slug_idx on feature_options(slug);
create index if not exists access_logs_created_at_idx on access_logs(created_at desc);

alter table if exists app_settings
  add column if not exists login_background_url text not null default '/assets/hyper-logo.jpeg';

alter table if exists app_settings
  add column if not exists dashboard_logo_url text not null default '/icon.png';

alter table if exists app_settings
  add column if not exists live_background_url text not null default '/assets/hyper-logo.jpeg';

alter table if exists app_users
  add column if not exists device_ids jsonb not null default '[]'::jsonb;

alter table if exists app_users
  add column if not exists max_devices integer not null default 1;

update app_users
set device_ids = jsonb_build_array(device_id)
where coalesce(device_id, '') <> ''
  and jsonb_array_length(coalesce(device_ids, '[]'::jsonb)) = 0;
