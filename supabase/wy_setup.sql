-- Waleed & Yasmin wedding: separate tables in the shared Supabase project.
-- Run once in Supabase Dashboard -> SQL Editor. Does not touch the existing
-- guests / faqs / wedding_settings / user_roles tables or their data.

create extension if not exists pgcrypto;

-- Admins for this wedding only (separate from public.user_roles)
create table if not exists public.wy_user_roles (
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'admin' check (role in ('admin')),
  created_at timestamptz not null default now(),
  primary key (user_id, role)
);

create or replace function public.wy_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.wy_user_roles
    where user_id = auth.uid() and role = 'admin'
  );
$$;

-- RSVPs
create table if not exists public.wy_guests (
  id uuid primary key default gen_random_uuid(),
  full_name text not null check (char_length(full_name) between 1 and 200),
  phone text check (phone is null or char_length(phone) <= 50),
  email text check (email is null or char_length(email) <= 254),
  attendance text not null check (attendance in ('yes', 'no')),
  guest_count integer not null default 1 check (guest_count between 0 and 20),
  companions jsonb not null default '[]'::jsonb,
  dietary_requirements text check (dietary_requirements is null or char_length(dietary_requirements) <= 1000),
  message text check (message is null or char_length(message) <= 2000),
  created_at timestamptz not null default now()
);

-- Site settings (optional; the site falls back to built-in values when empty)
create table if not exists public.wy_wedding_settings (
  id uuid primary key default gen_random_uuid(),
  couple_name_1 text,
  couple_name_2 text,
  wedding_date date,
  hero_subtitle text,
  banquet_location text,
  banquet_address text,
  banquet_maps_url text,
  updated_at timestamptz not null default now()
);

-- FAQ (optional; the FAQ section is hidden when empty)
create table if not exists public.wy_faqs (
  id uuid primary key default gen_random_uuid(),
  question text not null,
  answer text not null,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

alter table public.wy_user_roles enable row level security;
alter table public.wy_guests enable row level security;
alter table public.wy_wedding_settings enable row level security;
alter table public.wy_faqs enable row level security;

-- Roles: a signed-in user can see only their own role rows
drop policy if exists wy_user_roles_select_own on public.wy_user_roles;
create policy wy_user_roles_select_own on public.wy_user_roles
  for select to authenticated using (user_id = auth.uid());

-- Guests: anyone may submit an RSVP; only wedding admins can read or delete
drop policy if exists wy_guests_insert_public on public.wy_guests;
create policy wy_guests_insert_public on public.wy_guests
  for insert to anon, authenticated with check (true);

drop policy if exists wy_guests_select_admin on public.wy_guests;
create policy wy_guests_select_admin on public.wy_guests
  for select to authenticated using (public.wy_is_admin());

drop policy if exists wy_guests_delete_admin on public.wy_guests;
create policy wy_guests_delete_admin on public.wy_guests
  for delete to authenticated using (public.wy_is_admin());

-- Settings and FAQ: public read, admin write
drop policy if exists wy_settings_select_public on public.wy_wedding_settings;
create policy wy_settings_select_public on public.wy_wedding_settings
  for select to anon, authenticated using (true);

drop policy if exists wy_settings_write_admin on public.wy_wedding_settings;
create policy wy_settings_write_admin on public.wy_wedding_settings
  for all to authenticated using (public.wy_is_admin()) with check (public.wy_is_admin());

drop policy if exists wy_faqs_select_public on public.wy_faqs;
create policy wy_faqs_select_public on public.wy_faqs
  for select to anon, authenticated using (true);

drop policy if exists wy_faqs_write_admin on public.wy_faqs;
create policy wy_faqs_write_admin on public.wy_faqs
  for all to authenticated using (public.wy_is_admin()) with check (public.wy_is_admin());

grant select, insert, delete on public.wy_guests to anon, authenticated;
grant select on public.wy_wedding_settings, public.wy_faqs to anon, authenticated;
grant insert, update, delete on public.wy_wedding_settings, public.wy_faqs to authenticated;
grant select on public.wy_user_roles to authenticated;

-- ---------------------------------------------------------------------------
-- Make someone an admin of THIS wedding (run after they sign up on /admin).
-- Replace the email, then run just this statement:
--
-- insert into public.wy_user_roles (user_id, role)
-- select id, 'admin' from auth.users where email = 'admin@example.com'
-- on conflict do nothing;
