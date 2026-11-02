-- Smart Carpool - post-push security audit (READ-ONLY).
-- Run in the Supabase SQL editor (or: psql ... -f verify_security.sql) after
-- pushing the migrations. Every section is titled with what it should return.
-- Sections marked "EXPECT: 0 rows" are problems if they return anything.

\echo '== 1. EXPECT: 0 rows - public tables without row level security'
select c.relname as table_without_rls
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity;

\echo '== 2. EXPECT: 0 rows - SECURITY DEFINER functions without a fixed search_path'
select p.oid::regprocedure as function_without_search_path
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and p.prosecdef
   and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) cfg where cfg like 'search_path=%');

\echo '== 3. EXPECT: 0 rows - anything in public that the anon role can touch'
select c.relname as relation, 'table/view' as kind
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind in ('r','v','m','p')
   and (has_any_column_privilege('anon', c.oid, 'SELECT')
     or has_any_column_privilege('anon', c.oid, 'INSERT')
     or has_any_column_privilege('anon', c.oid, 'UPDATE')
     or has_table_privilege('anon', c.oid, 'DELETE'))
union all
select p.oid::regprocedure::text, 'function'
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'EXECUTE');

\echo '== 4. EXPECT: only update_profile, request_booking, approve_booking, reject_booking,'
\echo '==    cancel_booking, start_ride, cancel_ride, complete_ride, simulate_payment'
select p.oid::regprocedure as function_executable_by_authenticated
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and has_function_privilege('authenticated', p.oid, 'EXECUTE')
 order by 1::text;

\echo '== 5. EXPECT: 0 rows - authenticated privileges that differ from the intended matrix'
with expected(relation, priv) as (values
  ('profiles','SELECT'), ('profiles','INSERT'),
  ('vehicles','SELECT'), ('vehicles','INSERT'), ('vehicles','UPDATE'), ('vehicles','DELETE'),
  ('rides','SELECT'), ('rides','INSERT'), ('rides','UPDATE'),
  ('bookings','SELECT'), ('payments','SELECT'),
  ('vehicles_public','SELECT'), ('rides_with_availability','SELECT')
), actual as (
  select c.relname as relation, p.priv
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
   cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(priv)
   where n.nspname = 'public' and c.relkind in ('r','v')
     and ( (p.priv in ('SELECT','INSERT','UPDATE') and has_any_column_privilege('authenticated', c.oid, p.priv))
        or (p.priv in ('DELETE','TRUNCATE','REFERENCES','TRIGGER') and has_table_privilege('authenticated', c.oid, p.priv)) )
)
select 'UNEXPECTED' as problem, relation, priv from actual except select 'UNEXPECTED', relation, priv from expected
union all
select 'MISSING', relation, priv from expected except select 'MISSING', relation, priv from actual;

\echo '== 6. EXPECT: rides.status and rides.driver_id are NOT writable by authenticated (0 rows)'
select column_name from information_schema.column_privileges
 where table_schema = 'public' and table_name = 'rides' and grantee = 'authenticated'
   and privilege_type in ('INSERT','UPDATE') and column_name in ('status','driver_id')
   and not (column_name = 'driver_id' and privilege_type = 'INSERT');

\echo '== 7. Policies (review by eye - one line each)'
select tablename, policyname, cmd, roles from pg_policies where schemaname = 'public' order by 1, 2;
