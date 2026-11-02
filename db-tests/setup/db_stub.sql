-- Per-database Supabase stub: auth schema, auth.users, auth.uid().
create schema auth authorization supabase_auth_admin;
create table auth.users (
  id uuid primary key default gen_random_uuid(),
  email text,
  raw_user_meta_data jsonb,
  created_at timestamptz not null default now()
);
alter table auth.users owner to supabase_auth_admin;
create function auth.uid() returns uuid language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;
alter function auth.uid() owner to supabase_auth_admin;
grant usage on schema auth to postgres, anon, authenticated, service_role;
grant execute on function auth.uid() to postgres, anon, authenticated, service_role;
grant all on all tables in schema auth to postgres;
grant usage on schema public to anon, authenticated, service_role;
