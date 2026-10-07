-- Passcode-protected access to Waleed & Yasmin RSVPs for rsvp-dashboard.html.
-- Run AFTER wy_setup.sql, in Supabase Dashboard -> SQL Editor.
-- The passcode is checked inside the database; the page never contains it.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.wy_dashboard_secret (
  id integer primary key default 1 check (id = 1),
  passcode_hash text not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.wy_passcode_failures (
  at timestamptz not null default now()
);

-- No policies: these two tables are unreachable through the public API.
alter table public.wy_dashboard_secret enable row level security;
alter table public.wy_passcode_failures enable row level security;

-- Returns 'ok', 'wrong' or 'locked' (20 wrong tries in 15 minutes locks it).
create or replace function public.wy_check_passcode(p_passcode text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_hash text;
  v_fails integer;
begin
  delete from public.wy_passcode_failures where at < now() - interval '1 day';

  select count(*) into v_fails
  from public.wy_passcode_failures
  where at > now() - interval '15 minutes';
  if v_fails >= 20 then
    return 'locked';
  end if;

  select passcode_hash into v_hash from public.wy_dashboard_secret where id = 1;
  if v_hash is null or p_passcode is null or crypt(p_passcode, v_hash) <> v_hash then
    insert into public.wy_passcode_failures default values;
    return 'wrong';
  end if;
  return 'ok';
end;
$$;

create or replace function public.wy_get_responses(p_passcode text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_status text := public.wy_check_passcode(p_passcode);
begin
  if v_status <> 'ok' then
    return jsonb_build_object('ok', false, 'error', v_status);
  end if;
  return jsonb_build_object(
    'ok', true,
    'rows', coalesce(
      (select jsonb_agg(to_jsonb(g) order by g.created_at desc) from public.wy_guests g),
      '[]'::jsonb
    )
  );
end;
$$;

create or replace function public.wy_delete_response(p_passcode text, p_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_status text := public.wy_check_passcode(p_passcode);
begin
  if v_status <> 'ok' then
    return jsonb_build_object('ok', false, 'error', v_status);
  end if;
  delete from public.wy_guests where id = p_id;
  return jsonb_build_object('ok', true);
end;
$$;

revoke all on function public.wy_check_passcode(text) from public, anon, authenticated;
revoke all on function public.wy_get_responses(text) from public;
revoke all on function public.wy_delete_response(text, uuid) from public;
grant execute on function public.wy_get_responses(text) to anon, authenticated;
grant execute on function public.wy_delete_response(text, uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- Set (or change) the passcode. Replace YOUR_PASSCODE, run this statement,
-- and don't save the real passcode in this file (the repository is shared).
--
-- insert into public.wy_dashboard_secret (id, passcode_hash)
-- values (1, extensions.crypt('YOUR_PASSCODE', extensions.gen_salt('bf')))
-- on conflict (id) do update
--   set passcode_hash = excluded.passcode_hash, updated_at = now();
