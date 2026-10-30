-- Smart Carpool - Migration 2: vehicles + rides
--
-- Vehicles:
--   * Owner-only RLS on the table (the owner sees everything, including
--     the registration plate; everyone else sees nothing from the table).
--   * A vehicles_public view exposes non-sensitive columns, and ONLY for
--     vehicles that are used by at least one ride (so it cannot be used to
--     list every vehicle in the system). The view deliberately uses definer
--     semantics (security_invoker = false), i.e. it bypasses the base table's
--     RLS by design; its column list and WHERE clause are what enforce
--     privacy. owner_id is NOT exposed: use rides.driver_id.
--   * Plates are normalized (uppercase, letters+digits only) BEFORE the
--     global UNIQUE constraint applies, so "mh 12-ab 1234" == "MH12AB1234".
--
-- Rides:
--   * A ride's vehicle MUST belong to the ride's driver. This is enforced by
--     a composite foreign key (vehicle_id, driver_id) -> vehicles (id, owner_id),
--     i.e. a database constraint that holds for every write path.
--   * Clients can INSERT/UPDATE only the columns granted below. They can never
--     write status or driver_id directly: new rides are always 'scheduled' and
--     lifecycle changes go through the RPCs (start_ride / cancel_ride /
--     complete_ride) in the last migration.
--   * Integrity triggers: future departure times, passenger capacity must fit
--     the vehicle, and an explicit status state machine. (The trigger that
--     protects rides with active bookings lives in the bookings migration.)
--   * No DELETE policy/privilege: rides are cancelled, never deleted.

-- 1. Vehicles
create table public.vehicles (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  make text not null check (length(trim(make)) between 1 and 60),
  model text not null check (length(trim(model)) between 1 and 60),
  color text check (color is null or length(color) <= 30),
  registration_number text not null check (length(registration_number) between 1 and 20),
  total_seats integer not null check (total_seats between 2 and 9),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vehicles_registration_number_unique unique (registration_number),
  -- Target for the rides composite foreign key (vehicle must belong to driver).
  constraint vehicles_id_owner_unique unique (id, owner_id)
);

comment on column public.vehicles.total_seats is
  'Total seating including the driver. Any ride using this vehicle can carry at most total_seats - 1 passengers.';

create trigger vehicles_set_updated_at
  before update on public.vehicles
  for each row execute function public.set_updated_at();

-- Normalize before constraints apply: plate -> uppercase letters/digits only,
-- make/model/color trimmed (blank color becomes NULL).
create function public.normalize_vehicle()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.registration_number :=
    upper(regexp_replace(coalesce(new.registration_number, ''), '[^A-Za-z0-9]', '', 'g'));
  new.make := trim(new.make);
  new.model := trim(new.model);
  new.color := nullif(trim(new.color), '');
  return new;
end;
$$;

revoke execute on function public.normalize_vehicle() from public, anon, authenticated;

create trigger vehicles_normalize
  before insert or update of registration_number, make, model, color on public.vehicles
  for each row execute function public.normalize_vehicle();

-- 2. Rides
create table public.rides (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid not null references public.profiles (id) on delete cascade,
  vehicle_id uuid not null,
  origin_label text not null check (length(trim(origin_label)) between 1 and 200),
  origin_latitude double precision not null check (origin_latitude between -90 and 90),
  origin_longitude double precision not null check (origin_longitude between -180 and 180),
  destination_label text not null check (length(trim(destination_label)) between 1 and 200),
  destination_latitude double precision not null check (destination_latitude between -90 and 90),
  destination_longitude double precision not null check (destination_longitude between -180 and 180),
  departure_time timestamptz not null,
  passenger_capacity integer not null check (passenger_capacity >= 1),
  fare_per_seat numeric(10,2) not null check (fare_per_seat >= 0),
  status text not null default 'scheduled'
    check (status in ('scheduled', 'in_progress', 'completed', 'cancelled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- The vehicle must belong to the driver. Holds for INSERT and UPDATE alike.
  constraint rides_vehicle_belongs_to_driver
    foreign key (vehicle_id, driver_id)
    references public.vehicles (id, owner_id)
    on delete restrict
);

comment on column public.rides.passenger_capacity is
  'Seats offered to passengers. Must be <= total_seats - 1 of the referenced vehicle.';

create trigger rides_set_updated_at
  before update on public.rides
  for each row execute function public.set_updated_at();

-- Integrity: capacity fits the vehicle, departure is in the future when
-- created/changed, new rides start 'scheduled', and status follows the
-- state machine:
--   scheduled -> in_progress -> completed
--   scheduled -> cancelled
-- SECURITY DEFINER so the vehicle lookup does not depend on the caller's RLS.
create function public.validate_ride()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_vehicle_seats integer;
begin
  if tg_op = 'INSERT' then
    if new.status <> 'scheduled' then
      raise exception 'INVALID_TRANSITION: new rides must start as scheduled';
    end if;
    if new.departure_time <= now() then
      raise exception 'VALIDATION_ERROR: departure time must be in the future';
    end if;
  else
    -- Only when the value changes: status-only updates must keep working
    -- for already-departed rides (drivers can still cancel/complete them).
    if new.departure_time is distinct from old.departure_time
       and new.departure_time <= now() then
      raise exception 'VALIDATION_ERROR: departure time must be in the future';
    end if;

    if new.status is distinct from old.status then
      if not (
        (old.status = 'scheduled' and new.status in ('in_progress', 'cancelled'))
        or (old.status = 'in_progress' and new.status = 'completed')
      ) then
        raise exception 'INVALID_TRANSITION: % -> % is not allowed', old.status, new.status;
      end if;
    end if;
  end if;

  -- Capacity vs vehicle (cross-table, so it cannot be a CHECK constraint).
  -- Only re-checked when capacity or vehicle changes, so completing a ride
  -- can never be blocked by later edits to the vehicle.
  if tg_op = 'INSERT'
     or new.passenger_capacity is distinct from old.passenger_capacity
     or new.vehicle_id is distinct from old.vehicle_id then
    select total_seats into v_vehicle_seats
      from public.vehicles
     where id = new.vehicle_id;
    -- A missing vehicle is reported by the foreign key itself.
    if v_vehicle_seats is not null and new.passenger_capacity > v_vehicle_seats - 1 then
      raise exception 'VALIDATION_ERROR: passenger capacity exceeds this vehicle''s limit (%)',
        v_vehicle_seats - 1;
    end if;
  end if;

  return new;
end;
$$;

revoke execute on function public.validate_ride() from public, anon, authenticated;

create trigger rides_validate
  before insert or update on public.rides
  for each row execute function public.validate_ride();

-- Prevent seat-count reductions that conflict with rides that are still
-- scheduled OR currently in progress on this vehicle. (Completed/cancelled
-- rides keep their own capacity snapshot, so they are intentionally exempt.)
create function public.guard_vehicle_seat_edit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.total_seats < old.total_seats and exists (
    select 1
      from public.rides r
     where r.vehicle_id = new.id
       and r.status in ('scheduled', 'in_progress')
       and r.passenger_capacity > new.total_seats - 1
  ) then
    raise exception 'CONFLICT: cannot reduce seats - scheduled or in-progress rides on this vehicle require more capacity';
  end if;
  return new;
end;
$$;

revoke execute on function public.guard_vehicle_seat_edit() from public, anon, authenticated;

create trigger vehicles_guard_seat_edit
  before update of total_seats on public.vehicles
  for each row execute function public.guard_vehicle_seat_edit();

-- 3. Non-sensitive vehicle details for ride browsing.
--    Definer semantics on purpose (see header). Only vehicles that appear on
--    at least one ride are visible, and owner_id/plate are never exposed.
create view public.vehicles_public
with (security_invoker = false)
as
  select v.id, v.make, v.model, v.color, v.total_seats
    from public.vehicles v
   where exists (select 1 from public.rides r where r.vehicle_id = v.id);

revoke all on public.vehicles_public from anon, authenticated;
grant select on public.vehicles_public to authenticated;
grant select on public.vehicles_public to service_role;

-- 4. RLS + privileges on vehicles: owner-only for every operation.
--    Non-owners must never read the table directly (plate privacy);
--    they read vehicles_public instead.
alter table public.vehicles enable row level security;

revoke all on table public.vehicles from anon, authenticated;
grant select, delete on table public.vehicles to authenticated;
grant insert (owner_id, make, model, color, registration_number, total_seats)
  on table public.vehicles to authenticated;
grant update (make, model, color, registration_number, total_seats)
  on table public.vehicles to authenticated;
grant select, insert, update, delete on table public.vehicles to service_role;

create policy vehicles_owner_all
  on public.vehicles for all
  to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

-- 5. RLS + privileges on rides
alter table public.rides enable row level security;

revoke all on table public.rides from anon, authenticated;
grant select on table public.rides to authenticated;
grant insert (
  driver_id, vehicle_id,
  origin_label, origin_latitude, origin_longitude,
  destination_label, destination_latitude, destination_longitude,
  departure_time, passenger_capacity, fare_per_seat
) on table public.rides to authenticated;
-- status and driver_id are deliberately NOT updatable by clients.
grant update (
  vehicle_id,
  origin_label, origin_latitude, origin_longitude,
  destination_label, destination_latitude, destination_longitude,
  departure_time, passenger_capacity, fare_per_seat
) on table public.rides to authenticated;
grant select, insert, update, delete on table public.rides to service_role;

-- Signed-in users can browse all rides (search + details).
create policy rides_select_authenticated
  on public.rides for select
  to authenticated
  using (true);

-- Drivers create rides only as themselves, always 'scheduled'. That the
-- vehicle is theirs is enforced by the composite foreign key above.
create policy rides_insert_own
  on public.rides for insert
  to authenticated
  with check (
    driver_id = (select auth.uid())
    and status = 'scheduled'
  );

-- Drivers may edit their own rides only while still 'scheduled'. Edits that
-- would hurt people who already requested seats are blocked by the
-- rides_guard_active_bookings trigger (bookings migration).
create policy rides_update_own_scheduled
  on public.rides for update
  to authenticated
  using (driver_id = (select auth.uid()) and status = 'scheduled')
  with check (driver_id = (select auth.uid()) and status = 'scheduled');

-- No DELETE policy: rides are cancelled, never deleted (history preserved).

-- 6. Indexes
create index rides_driver_id_idx on public.rides (driver_id);
create index rides_vehicle_id_idx on public.rides (vehicle_id);
create index rides_discovery_idx on public.rides (status, departure_time);
