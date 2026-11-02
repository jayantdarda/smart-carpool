-- Smart Carpool - one-shot security audit for the Supabase SQL editor (READ-ONLY).
--
-- The SQL editor only shows the result of the LAST statement, and does not
-- understand psql's \echo, so this is ONE query. Paste it all and run it.
--
--   0 rows            => every check passed.
--   any row           => a problem; the "check" column says which one.
--
-- (verify_security.sql is the longer psql version with section headings.)

with expected_fn(sig) as (values
  ('update_profile(text)'), ('request_booking(uuid,integer,text)'),
  ('approve_booking(uuid)'), ('reject_booking(uuid)'), ('cancel_booking(uuid)'),
  ('start_ride(uuid)'), ('cancel_ride(uuid)'), ('complete_ride(uuid)'),
  ('simulate_payment(uuid)')
), expected_priv(relation, priv) as (values
  ('profiles','SELECT'), ('profiles','INSERT'),
  ('vehicles','SELECT'), ('vehicles','INSERT'), ('vehicles','UPDATE'), ('vehicles','DELETE'),
  ('rides','SELECT'), ('rides','INSERT'), ('rides','UPDATE'),
  ('bookings','SELECT'), ('payments','SELECT'),
  ('vehicles_public','SELECT'), ('rides_with_availability','SELECT')
), actual_priv as (
  select c.relname::text as relation, p.priv
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
   cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(priv)
   where n.nspname = 'public' and c.relkind in ('r','v')
     and ( (p.priv in ('SELECT','INSERT','UPDATE') and has_any_column_privilege('authenticated', c.oid, p.priv))
        or (p.priv in ('DELETE','TRUNCATE','REFERENCES','TRIGGER') and has_table_privilege('authenticated', c.oid, p.priv)) )
)
select '1. table without row level security' as "check", c.relname::text as detail
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity
union all
select '2. SECURITY DEFINER function without fixed search_path', p.oid::regprocedure::text
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and p.prosecdef
   and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) cfg where cfg like 'search_path=%')
union all
select '3. anon can touch a table/view', c.relname::text
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind in ('r','v','m','p')
   and (has_any_column_privilege('anon', c.oid, 'SELECT')
     or has_any_column_privilege('anon', c.oid, 'INSERT')
     or has_any_column_privilege('anon', c.oid, 'UPDATE')
     or has_table_privilege('anon', c.oid, 'DELETE'))
union all
select '3. anon can execute a function', p.oid::regprocedure::text
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'EXECUTE')
union all
select '4. authenticated can execute a function that is not a client RPC', p.oid::regprocedure::text
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and has_function_privilege('authenticated', p.oid, 'EXECUTE')
   and not exists (select 1 from expected_fn e where e.sig = p.oid::regprocedure::text)
union all
select '4. client RPC missing (or not executable by authenticated)', e.sig
  from expected_fn e
 where not exists (
   select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.oid::regprocedure::text = e.sig
      and has_function_privilege('authenticated', p.oid, 'EXECUTE'))
union all
select '5. authenticated has a privilege that is not in the intended matrix', a.relation || ' ' || a.priv
  from actual_priv a
 where not exists (select 1 from expected_priv e where e.relation = a.relation and e.priv = a.priv)
union all
select '5. authenticated is missing a privilege the app needs', e.relation || ' ' || e.priv
  from expected_priv e
 where not exists (select 1 from actual_priv a where a.relation = e.relation and a.priv = e.priv)
union all
select '6. clients can write rides.status / rides.driver_id (update)', column_name::text
  from information_schema.column_privileges
 where table_schema = 'public' and table_name = 'rides' and grantee = 'authenticated'
   and privilege_type = 'UPDATE' and column_name in ('status', 'driver_id')
union all
select '6. clients can insert rides.status', column_name::text
  from information_schema.column_privileges
 where table_schema = 'public' and table_name = 'rides' and grantee = 'authenticated'
   and privilege_type = 'INSERT' and column_name = 'status'
union all
select '7. blanket policy (USING true) that allows writes', tablename || '.' || policyname
  from pg_policies
 where schemaname = 'public' and cmd in ('INSERT','UPDATE','DELETE','ALL')
   and (qual = 'true' or with_check = 'true')
order by 1, 2;
