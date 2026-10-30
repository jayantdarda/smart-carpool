-- Smart Carpool - Migration 1: profiles
-- Creates the profiles table, a shared updated_at helper, and the defensive
-- profile-creation trigger on auth.users.
--
-- Security model:
--   * SELECT: any signed-in user (needed for driver names on ride details)
--   * INSERT: own row only (recovery path; the trigger is the normal path)
--   * UPDATE: none - profile edits go through update_profile() RPC only,
--     which is the pattern we will reuse for any future protected fields.
--
-- Privileges (GRANT/REVOKE) are explicit on purpose. Supabase is changing
-- (and has changed) what new tables get by default, so nothing here relies
-- on default grants: anon gets nothing, authenticated gets exactly what the
-- policies below need.

-- 1. Profiles table (1:1 with auth.users)
create table public.profiles (
  id uuid
    primary key
    references auth.users (id) on delete cascade,
  display_name text
    not null
    check (length(trim(display_name)) > 0 and length(display_name) <= 60),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.profiles is
  'Application profile, one row per auth user. Created by handle_new_user() trigger.';

-- 2. Shared updated_at maintainer (used by several tables)
create function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- Trigger helpers are never called directly; Postgres does not check EXECUTE
-- when a trigger fires, so strip the default PUBLIC grant.
revoke execute on function public.set_updated_at() from public, anon, authenticated;

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();

-- 3. Defensive profile creation on signup.
--    Never breaks signup:
--      - display_name falls back through metadata -> email handle -> literal,
--        so it can never be NULL, empty, or longer than the 60-char limit.
--      - ON CONFLICT DO NOTHING makes duplicate attempts harmless.
--      - The EXCEPTION wrapper guarantees a profile problem can never
--        abort the signup transaction (a warning is still logged).
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  begin
    insert into public.profiles (id, display_name)
    values (
      new.id,
      coalesce(
        nullif(trim(left(new.raw_user_meta_data ->> 'display_name', 60)), ''),
        nullif(trim(left(new.raw_user_meta_data ->> 'name', 60)), ''),
        nullif(trim(left(split_part(new.email, '@', 1), 60)), ''),
        'New User'
      )
    )
    on conflict (id) do nothing;
  exception when others then
    raise warning 'smart-carpool: profile creation failed for user %: %', new.id, sqlerrm;
  end;
  return new;
end;
$$;

-- Postgres grants EXECUTE to PUBLIC by default; strip it so only the
-- trigger can invoke this. (Postgres does not check EXECUTE for trigger
-- firing, so this does not affect the trigger itself.)
revoke execute on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 4. Row Level Security
alter table public.profiles enable row level security;

-- Explicit table privileges (RLS still decides which rows).
-- INSERT is limited to the two columns a client may legitimately supply.
revoke all on table public.profiles from anon, authenticated;
grant select on table public.profiles to authenticated;
grant insert (id, display_name) on table public.profiles to authenticated;
grant select, insert, update, delete on table public.profiles to service_role;

-- Any signed-in user can read basic profile info (driver names on rides, etc.)
create policy profiles_select_authenticated
  on public.profiles for select
  to authenticated
  using (true);

-- Recovery path: a user may create their own profile row if the trigger
-- ever failed to do so. The normal path is the trigger above.
create policy profiles_insert_self_recovery
  on public.profiles for insert
  to authenticated
  with check (id = (select auth.uid()));

-- NOTE: deliberately no UPDATE policy and no UPDATE privilege. See update_profile() below.

-- 5. Profile updates via secure RPC.
--    The function touches display_name only, so future protected columns
--    (roles, verification state, etc.) added to profiles are safe by default:
--    clients will have no direct UPDATE path at all.
create function public.update_profile(p_display_name text)
returns public.profiles
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_name text := trim(coalesce(p_display_name, ''));
  v_profile public.profiles%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  if length(v_name) = 0 or length(v_name) > 60 then
    raise exception 'VALIDATION_ERROR: display name must be 1-60 characters';
  end if;

  update public.profiles
     set display_name = v_name
   where id = v_caller
  returning * into v_profile;

  if not found then
    raise exception 'NOT_FOUND: no profile row for this account';
  end if;

  return v_profile;
end;
$$;

revoke execute on function public.update_profile(text) from public, anon;
grant execute on function public.update_profile(text) to authenticated;
