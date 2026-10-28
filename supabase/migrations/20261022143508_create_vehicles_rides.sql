-- Smart Carpool - Migration 2: vehicles + rides
--
-- Vehicles:
--   * Owner-only RLS on the table (the owner sees everything, including
--     the registration plate; everyone else sees nothing from the table).
--   * A vehicles_public view exposes non-sensitive columns of all rows
--     for ride browsing. The view deliberately uses definer semantics
--     (security_invoker = false), i.e. it bypasses the base table's RLS
--     by design, while its column list is what enforces plate privacy.
--   * Plates are normalized (uppercase, whitespace stripped) BEFORE the
--     global UNIQUE constraint applies.
--
-- Rides:
--   * Driver-scoped creation/editing; creation requires the referenced
--     vehicle to belong to the caller (RLS WITH CHECK subquery).
--   * Integrity triggers: future departure times, passenger capacity
--     must fit the vehicle, and an explicit status state machine.
--   * Direct UPDATE only while a ride is 'scheduled' and must KEEP the
--     status 'scheduled' - lifecycle changes go through the RPCs in
--     migration 3 (start_ride / cancel_ride / complete_ride).
--   * No DELETE policy: rides are cancelled, never deleted (history).

-- 1. Vehicles
create table public.vehicles (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  make text not null check (length(trim(make)) > 0),
  model text not null check (length(trim(model)) > 0),
  color text,
  registration_number text not null check (length(trim(registration_number)) > 0),
  total_seats integer not null check (total_seats between 2 and 9),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint vehicles_registration_number_unique unique (registration_number)
);

comment on column public.vehicles.total_seats is
  'Total seating including the driver. Any ride using this vehicle can carry at most total_seats - 1 passengers.';

create trigger vehicles_set_updated_at
  before update on public.vehicles
  for each row execute function public.set_updated_at();

-- Normalize the plate (and trim make/model) before constraints apply.
create function public.normalize_vehicle()
returns trigger
language plpgsql
as $$
begin
  new.registration_number :=
    upper(regexp_replace(trim(new.registration_number), '\s+', '', 'g'));
  new.make := trim(new.make);
  new.model := trim(new.model);
  return new;
end;
$$;

create trigger vehicles_normalize
  before insert or update of registration_number, make, model on public.vehicles
  for each row execute function public.normalize_vehicle();

-- 2. Rides
create table public.rides (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid not null references public.profiles (id) on delete cascade,
  vehicle_id uuid not null references public.vehicles (id) on delete restrict,
  origin_label text not null check (length(trim(origin_label)) > 0),
  origin_latitude double precision not null check (origin_latitude between -90 and 90),
  origin_longitude double precision not null check (origin_longitude between -180 and 180),
  destination_label text not null check (length(trim(destination_label)) > 0),
  destination_latitude double precision not null check (destination_latitude between -90 and 90),
  destination_longitude double precision not null check (destination_longitude between -180 and 180),
  departure_time timestamptz not null,
  passenger_capacity integer not null check (passenger_capacity >= 1),
  fare_per_seat numeric(10,2) not null check (fare_per_seat >= 0),
  status text not null default 'scheduled'
    check (status in ('scheduled', 'in_progress', 'completed', 'cancelled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on column public.rides.passenger_capacity is
  'Seats offered to passengers. Must be <= total_seats - 1 of the referenced vehicle.';

create trigger rides_set_updated_at
  before update on public.rides
  for each row execute function public.set_updated_at();

-- Integrity: capacity fits the vehicle, departure is in the future when
-- created/changed, and status follows the state machine:
--   scheduled -> in_progress -> completed
--   scheduled -> cancelled
create function public.validate_ride()
returns trigger
language plpgsql
as $$
declare
  v_vehicle_seats integer;
begin
  -- Capacity vs vehicle (cross-table, so it cannot be a CHECK constraint).
  select total_seats into v_vehicle_seats
    from public.vehicles
   where id = new.vehicle_id;
  if v_vehicle_seats is null or new.passenger_capacity > v_vehicle_seats - 1 then
    raise exception 'VALIDATION_ERROR: passenger capacity exceeds this vehicle''s limit (%)',
      coalesce(v_vehicle_seats - 1, 0);
  end if;

  -- Future departure on insert, and on update only when the value changes.
  -- (Status-only updates must keep working for already-departed rides, so
  -- drivers can still cancel/complete them via the RPCs.)
  if tg_op = 'INSERT' then
    if new.departure_time <= now() then
      raise exception 'VALIDATION_ERROR: departure time must be in the future';
    end if;
  elsif new.departure_time is distinct from old.departure_time then
    if new.departure_time <= now() then
      raise exception 'VALIDATION_ERROR: departure time must be in the future';
    end if;
  end if;

  -- Explicit status state machine.
  if tg_op = 'UPDATE' and new.status is distinct from old.status then
    if not (
      (old.status = 'scheduled' and new.status in ('in_progress', 'cancelled'))
      or (old.status = 'in_progress' and new.status = 'completed')
    ) then
      raise exception 'INVALID_TRANSITION: % -> % is not allowed', old.status, new.status;
    end if;
  end if;

  return new;
end;
$$;

create trigger rides_validate
  before insert or update on public.rides
  for each row execute function public.validate_ride();

-- Prevent seat-count reductions that conflict with scheduled rides on this
-- vehicle. (Completed/cancelled rides keep their own capacity snapshot, so
-- they are intentionally exempt.)
create function public.guard_vehicle_seat_edit()
returns trigger
language plpgsql
as $$
begin
  if new.total_seats < old.total_seats and exists (
    select 1
      from public.rides r
     where r.vehicle_id = new.id
       and r.status = 'scheduled'
       and r.passenger_capacity > new.total_seats - 1
  ) then
    raise exception 'CONFLICT: cannot reduce seats - scheduled rides on this vehicle require more capacity';
  end if;
  return new;
end;
$$;

create trigger vehicles_guard_seat_edit
  before update of total_seats on public.vehicles
  for each row execute function public.guard_vehicle_seat_edit();

-- 3. Non-sensitive vehicle details for ride browsing.
create view public.vehicles_public
with (security_invoker = false)
as
  select id, owner_id, make, model, color, total_seats, created_at
    from public.vehicles;

grant select on public.vehicles_public to authenticated;

-- 4. RLS on vehicles: owner-only for every operation.
--    Non-owners must never read the table directly (plate privacy);
--    they read vehicles_public instead.
alter table public.vehicles enable row level security;

create policy vehicles_owner_all
  on public.vehicles for all
  to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());

-- 5. RLS on rides
alter table public.rides enable row level security;

-- Signed-in users can browse all rides (search + details).
create policy rides_select_authenticated
  on public.rides for select
  to authenticated
  using (true);

-- Drivers create rides only as themselves and only with their own vehicle.
create policy rides_insert_own_vehicle
  on public.rides for insert
  to authenticated
  with check (
    driver_id = auth.uid()
    and exists (
      select 1
        from public.vehicles v
       where v.id = vehicle_id
         and v.owner_id = auth.uid()
    )
  );

-- Drivers may edit their own rides only while still 'scheduled', and any
-- direct edit must KEEP status = 'scheduled' - lifecycle changes happen
-- exclusively through the RPCs (start_ride / cancel_ride / complete_ride).
create policy rides_update_own_scheduled
  on public.rides for update
  to authenticated
  using (driver_id = auth.uid() and status = 'scheduled')
  with check (driver_id = auth.uid() and status = 'scheduled');

-- No DELETE policy: rides are cancelled, never deleted (history preserved).

-- 6. Indexes
create index rides_driver_id_idx on public.rides (driver_id);
create index rides_vehicle_id_idx on public.rides (vehicle_id);
create index rides_discovery_idx on public.rides (status, departure_time);
