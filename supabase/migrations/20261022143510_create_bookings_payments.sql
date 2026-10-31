-- Smart Carpool - Migration 3a: bookings + payments (tables, RLS, helpers)
--
-- Bookings:
--   * SELECT only via RLS (passenger or driver of the ride).
--   * NO direct INSERT/UPDATE/DELETE privileges or policies - every booking
--     mutation happens inside SECURITY DEFINER RPCs (next migrations) so the
--     capacity rules cannot be bypassed from any client.
--   * Pending requests HOLD seats (confirmed + live pending are the two
--     capacity-consuming states); rejected/cancelled/expired/completed
--     release them. A pending request is "live" until expires_at.
--     Expired holds are excluded from capacity math two ways: the RPCs sweep
--     them to status 'expired', and rides_with_availability ignores them even
--     before they are swept.
--
--   CLIENT RULE: a row with status = 'pending' AND expires_at <= now() is an
--   expired request, even if the sweep has not rewritten its status yet. UIs
--   must display it as "expired" and must not offer approve/reject for it.
--
-- Payments (DEMO only - no real money is ever collected):
--   * Created as 'pending' when a booking is confirmed; the passenger
--     taps "Pay" -> simulate_payment() -> 'simulated_paid'.
--   * Cancelling a confirmed booking marks its payment 'simulated_refunded'.

-- 1. Bookings
create table public.bookings (
  id uuid primary key default gen_random_uuid(),
  ride_id uuid not null references public.rides (id) on delete cascade,
  passenger_id uuid not null references public.profiles (id) on delete cascade,
  seats_requested integer not null check (seats_requested >= 1),
  status text not null
    check (status in ('pending', 'confirmed', 'rejected', 'cancelled', 'expired', 'completed')),
  contact_phone text not null check (contact_phone ~ '^\+91[6-9][0-9]{9}$'),
  fare_per_seat numeric(10,2) not null check (fare_per_seat >= 0),
  total_fare numeric(10,2) generated always as (fare_per_seat * seats_requested) stored,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint bookings_pending_requires_expiry
    check ((status = 'pending' and expires_at is not null) or (status <> 'pending'))
);

comment on column public.bookings.expires_at is
  'Deadline for the driver to answer a pending request. A pending request holds seats until confirmed, rejected, cancelled, or expired.';

comment on column public.bookings.contact_phone is
  'Passenger-provided contact number for the driver. Self-reported, not verified.';

create trigger bookings_set_updated_at
  before update on public.bookings
  for each row execute function public.set_updated_at();

-- One active (pending/confirmed) booking per passenger per ride.
-- The RPCs check this with a friendly error; this index is the hard
-- database-level backstop against races and abuse.
create unique index bookings_one_active_per_ride_passenger
  on public.bookings (ride_id, passenger_id)
  where status in ('pending', 'confirmed');

-- Serves both the capacity SUM inside the RPCs and the driver request list.
create index bookings_active_per_ride
  on public.bookings (ride_id)
  where status in ('pending', 'confirmed');

-- Serves the passenger's own list and the re-request cooldown lookup.
create index bookings_passenger_idx on public.bookings (passenger_id);
create index bookings_ride_passenger_idx on public.bookings (ride_id, passenger_id);

alter table public.bookings enable row level security;

-- Read-only for clients. Nothing else is granted: writes are RPC-only.
revoke all on table public.bookings from anon, authenticated;
grant select on table public.bookings to authenticated;
grant select, insert, update, delete on table public.bookings to service_role;

create policy bookings_select_involved
  on public.bookings for select
  to authenticated
  using (
    passenger_id = (select auth.uid())
    or exists (
      select 1
        from public.rides r
       where r.id = bookings.ride_id
         and r.driver_id = (select auth.uid())
    )
  );

-- 2. Payments (demo)
create table public.payments (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid not null unique references public.bookings (id) on delete cascade,
  amount numeric(10,2) not null check (amount >= 0),
  currency text not null default 'INR' check (currency ~ '^[A-Z]{3}$'),
  status text not null default 'pending'
    check (status in ('pending', 'simulated_paid', 'simulated_refunded')),
  provider_reference text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.payments is
  'DEMO payment records. No real money is ever collected or transferred.';

create trigger payments_set_updated_at
  before update on public.payments
  for each row execute function public.set_updated_at();

alter table public.payments enable row level security;

revoke all on table public.payments from anon, authenticated;
grant select on table public.payments to authenticated;
grant select, insert, update, delete on table public.payments to service_role;

-- Visible to the booking's passenger and to the ride's driver. (The inner
-- bookings lookup is itself filtered by the bookings RLS policy above.)
create policy payments_select_involved
  on public.payments for select
  to authenticated
  using (
    exists (
      select 1
        from public.bookings b
       where b.id = payments.booking_id
         and (
           b.passenger_id = (select auth.uid())
           or exists (
             select 1
               from public.rides r
              where r.id = b.ride_id
                and r.driver_id = (select auth.uid())
           )
         )
    )
  );

-- 3. Timeout configuration - single source of truth.
--    Change this value (in a new migration) to tune the pending-request
--    deadline. The rider UI reads expires_at from the booking row.
create function public.booking_hold_interval()
returns interval
language sql
immutable
set search_path = ''
as $$
  select interval '3 minutes';
$$;

revoke execute on function public.booking_hold_interval() from public, anon, authenticated;

-- 4. Internal helper: release stale pending holds for one ride.
--    Called inside capacity-affecting RPCs so expired holds are never counted.
--    (updated_at is maintained by trigger.) Not callable by clients.
create function public.expire_stale_bookings(p_ride_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.bookings
     set status = 'expired'
   where ride_id = p_ride_id
     and status = 'pending'
     and expires_at <= now();
end;
$$;

revoke execute on function public.expire_stale_bookings(uuid) from public, anon, authenticated;

-- 5. Seat availability for browsing.
--    Passengers cannot read other people's bookings (RLS), so they cannot
--    compute remaining seats themselves. This view does it for them, exposing
--    only COUNTS - never who booked. Same rows as the rides SELECT policy
--    (every ride is visible to every signed-in user). Live holds = confirmed
--    seats + pending seats whose deadline has not passed.
--    NOTE: columns are listed explicitly; if rides gains a column, recreate
--    this view in a new migration to expose it.
create view public.rides_with_availability
with (security_invoker = false)
as
  select
    r.id,
    r.driver_id,
    r.vehicle_id,
    r.origin_label,
    r.origin_latitude,
    r.origin_longitude,
    r.destination_label,
    r.destination_latitude,
    r.destination_longitude,
    r.departure_time,
    r.passenger_capacity,
    r.fare_per_seat,
    r.status,
    r.created_at,
    r.updated_at,
    h.seats_held::integer as seats_held,
    greatest(r.passenger_capacity - h.seats_held, 0)::integer as seats_available
  from public.rides r
  cross join lateral (
    select coalesce(sum(b.seats_requested), 0) as seats_held
      from public.bookings b
     where b.ride_id = r.id
       and (b.status = 'confirmed'
            or (b.status = 'pending' and b.expires_at > now()))
  ) h;

revoke all on public.rides_with_availability from anon, authenticated;
grant select on public.rides_with_availability to authenticated;
grant select on public.rides_with_availability to service_role;

-- 6. Protect people who already asked for (or hold) seats on a ride.
--    While a ride holds any live seats, its driver cannot move it (route,
--    time, vehicle) and cannot cut capacity below the seats already held.
--    To change those things the driver cancels the ride and creates a new one.
--    (Fare edits are allowed: every booking snapshots its own fare.)
--    This closes the "edit the ride directly to overbook it" path: it is a
--    trigger, so it holds for every write path, not only the API.
create function public.guard_ride_edit_with_bookings()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_moved boolean;
  v_held integer;
begin
  v_moved :=
    (new.origin_label, new.origin_latitude, new.origin_longitude,
     new.destination_label, new.destination_latitude, new.destination_longitude,
     new.departure_time, new.vehicle_id)
    is distinct from
    (old.origin_label, old.origin_latitude, old.origin_longitude,
     old.destination_label, old.destination_latitude, old.destination_longitude,
     old.departure_time, old.vehicle_id);

  if not v_moved and new.passenger_capacity >= old.passenger_capacity then
    return new;  -- nothing that could affect existing requests
  end if;

  select coalesce(sum(seats_requested), 0) into v_held
    from public.bookings
   where ride_id = new.id
     and (status = 'confirmed'
          or (status = 'pending' and expires_at > now()));

  if v_held = 0 then
    return new;
  end if;

  if v_moved then
    raise exception 'CONFLICT: this ride has % seat(s) requested or booked; cancel it and create a new ride instead of changing its route, time, or vehicle', v_held;
  end if;

  if new.passenger_capacity < v_held then
    raise exception 'CONFLICT: capacity cannot go below the % seat(s) already requested or booked', v_held;
  end if;

  return new;
end;
$$;

revoke execute on function public.guard_ride_edit_with_bookings() from public, anon, authenticated;

create trigger rides_guard_active_bookings
  before update on public.rides
  for each row execute function public.guard_ride_edit_with_bookings();
