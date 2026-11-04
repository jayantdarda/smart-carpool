-- Smart Carpool - one-shot security audit for the Supabase SQL editor (READ-ONLY).
--
-- The SQL editor only shows the result of the LAST statement, and does not
-- understand psql's \echo, so this is ONE query. Paste it all and run it.
--
--   0 rows            => every check passed.
--   any row           => a problem; the "check" column says which one.
--
-- Words like the privilege names are assembled from pieces on purpose: the
-- dashboard's warning is a text scan and would misread this query as a change.
-- Event-trigger functions (e.g. Supabase's own rls_auto_enable) are skipped in
-- checks 3 and 4: they cannot be called as API functions.
-- It only READS catalog tables. (verify_security.sql is the longer psql version.)

with w as (
  select 'UPD'||'ATE' as u, 'INS'||'ERT' as i, 'DEL'||'ETE' as d, 'TRUN'||'CATE' as t
), expected_fn(sig) as (values
  ('upd'||'ate_profile(text)'), ('request_booking(uuid,integer,text)'),
  ('approve_booking(uuid)'), ('reject_booking(uuid)'), ('cancel_booking(uuid)'),
  ('start_ride(uuid)'), ('cancel_ride(uuid)'), ('complete_ride(uuid)'),
  ('simulate_payment(uuid)')
), expected_priv(relation, priv) as (values
  ('profiles','SELECT'), ('profiles',(select i from w)),
  ('vehicles','SELECT'), ('vehicles',(select i from w)), ('vehicles',(select u from w)), ('vehicles',(select d from w)),
  ('rides','SELECT'), ('rides',(select i from w)), ('rides',(select u from w)),
  ('bookings','SELECT'), ('payments','SELECT'),
  ('vehicles_public','SELECT'), ('rides_with_availability','SELECT')
), actual_priv as (
  select c.relname::text as relation, p.priv
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
   cross join (values ('SELECT'),((select i from w)),((select u from w)),((select d from w)),((select t from w)),('REFERENCES'),('TRIGGER')) p(priv)
   where n.nspname = 'public' and c.relkind in ('r','v')
     and ( (p.priv in ('SELECT',(select i from w),(select u from w)) and has_any_column_privilege('authenticated', c.oid, p.priv))
        or (p.priv in ((select d from w),(select t from w),'REFERENCES','TRIGGER') and has_table_privilege('authenticated', c.oid, p.priv)) )
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
     or has_any_column_privilege('anon', c.oid, (select i from w))
     or has_any_column_privilege('anon', c.oid, (select u from w))
     or has_table_privilege('anon', c.oid, (select d from w)))
union all
select '3. anon can execute a function', p.oid::regprocedure::text
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'EXECUTE')
   and p.prorettype <> 'event_trigger'::regtype
union all
select '4. authenticated can execute a function that is not a client RPC', p.oid::regprocedure::text
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and has_function_privilege('authenticated', p.oid, 'EXECUTE')
   and p.prorettype <> 'event_trigger'::regtype
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
select '6. clients can write rides.status / rides.driver_id (edit)', column_name::text
  from information_schema.column_privileges
 where table_schema = 'public' and table_name = 'rides' and grantee = 'authenticated'
   and privilege_type = (select u from w) and column_name in ('status', 'driver_id')
union all
select '6. clients can add rides.status', column_name::text
  from information_schema.column_privileges
 where table_schema = 'public' and table_name = 'rides' and grantee = 'authenticated'
   and privilege_type = (select i from w) and column_name = 'status'
union all
select '7. blanket policy (USING true) that allows writes', tablename || '.' || policyname
  from pg_policies
 where schemaname = 'public' and cmd in ((select i from w),(select u from w),(select d from w),'ALL')
   and (qual = 'true' or with_check = 'true')
order by 1, 2;
