#!/bin/bash
# Build a throwaway Supabase-like database and apply the migrations to it.
#   usage: mkdb.sh <dbname> <old|new> <migrations_dir>
#     old = Supabase's former default (new tables auto-granted to anon/authenticated/service_role)
#     new = Supabase's current default (nothing auto-granted)
#   env:   PGHOST (socket dir or host), PGPORT (default 5432), ADMIN_USER (a superuser, default supabase_admin)
# One-time per cluster, first:  psql -U $ADMIN_USER -d postgres -f cluster_roles.sql
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
DB=$1; MODE=$2; MIG=$3
ADMIN_USER=${ADMIN_USER:-supabase_admin}
P="psql -X -q -v ON_ERROR_STOP=1 ${PGHOST:+-h $PGHOST} -p ${PGPORT:-5432}"
$P -U "$ADMIN_USER" -d postgres -c "drop database if exists $DB" -c "create database $DB owner postgres"
$P -U "$ADMIN_USER" -d "$DB" -f "$HERE/db_stub.sql"
$P -U postgres -d "$DB" -f "$HERE/defaults_$MODE.sql"
for f in $(ls "$MIG"/*.sql | sort); do
  echo "applying $(basename "$f")"
  $P -U postgres -d "$DB" -f "$f"
done
echo "OK $DB ($MODE)"
