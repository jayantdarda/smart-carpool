-- Cluster-level roles, mimicking a Supabase project.
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role supabase_auth_admin login noinherit createrole;
create role postgres login createrole createdb bypassrls;   -- NOT a superuser, like Supabase
grant anon, authenticated, service_role to postgres;
