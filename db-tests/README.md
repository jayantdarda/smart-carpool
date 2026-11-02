# Database tests

`run_tests.py` exercises the migrations the way the apps will: as `anon` and `authenticated`
(role + JWT `sub`, same mechanism as PostgREST), plus real parallel sessions for the race tests.
It needs only python3 (stdlib) and the `psql` client, against any Linux Postgres 15/16.
It is NOT meant to be pointed at the hosted Supabase project (it needs a superuser for two
time-travel fixtures and the `supabase_auth_admin` role). For the hosted project use
`../supabase/verification/verify_security_dashboard.sql` instead (one query; paste it in the SQL editor; 0 rows = pass).

    # run these from the repository root
    # once per cluster (as a superuser named supabase_admin):
    psql -U supabase_admin -d postgres -f db-tests/setup/cluster_roles.sql
    # per run:
    PGHOST=/path/to/socket PGPORT=54329 db-tests/setup/mkdb.sh t_new new supabase/migrations   # new Supabase grant defaults
    PGHOST=/path/to/socket PGPORT=54329 db-tests/setup/mkdb.sh t_old old supabase/migrations   # old grant defaults
    PGHOST=/path/to/socket PGPORT=54329 python3 db-tests/run_tests.py t_new --rounds 30
    PGHOST=/path/to/socket PGPORT=54329 python3 db-tests/run_tests.py t_old --rounds 30

Both modes must pass: the migrations must work whichever default grants a Supabase project has.
Use `-k <text>` to run tests whose name contains <text>. `--rounds` scales the race/fuzz tests.
`setup/db_stub.sql` fakes only what Supabase provides (auth schema, auth.users, auth.uid(), roles).

Note: `start_ride` is only allowed from 30 minutes before the scheduled departure
until 12 hours after it (boundaries inclusive), so test fixtures that start a ride
use a near departure (`hours=0.25`).

Supabase-native pgTAP tests (if added later) live in `supabase/tests/database/` and run with
`pnpm supabase test db`; keep them separate from this suite.
