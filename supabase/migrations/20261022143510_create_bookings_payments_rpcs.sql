-- Smart Carpool - Migration 3: bookings + payments + RPCs
--
-- Bookings:
--   * SELECT only via RLS (passenger or driver of the ride).
--   * NO direct INSERT/UPDATE/DELETE policies - every booking mutation
--     happens inside SECURITY DEFINER RPCs so the capacity rules cannot
--     be bypassed from any client.
--   * Pending requests HOLD seats (confirmed + pending are the two
--     capacity-consuming states); rejected/cancelled/expired/completed
--     release them. Expired holds are excluded from capacity math via
--     a sweep that runs inside every capacity-affecting RPC.
--
-- Payments (DEMO only - no real money is ever collected):
--   * Created as 'pending' when a booking is confirmed; the passenger
--     taps "Pay" -> simulate_payment() -> 'simulated_paid'.
--   * Cancelling a confirmed booking marks its payment 'simulated_refunded'.
--
-- Concurrency: every RPC locks the ride row (SELECT ... FOR UPDATE) first,
-- which serializes all concurrent booking actions on the same ride.
-- Two passengers racing for the last seat can never oversubscribe it.

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

create index bookings_passenger_idx on public.bookings (passenger_id);

alter table public.bookings enable row level security;

create policy bookings_select_involved
  on public.bookings for select
  to authenticated
  using (
    passenger_id = auth.uid()
    or exists (
      select 1
        from public.rides r
       where r.id = ride_id
         and r.driver_id = auth.uid()
    )
  );

-- No INSERT/UPDATE/DELETE policies: RPC-only mutations (see below).

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

create policy payments_select_involved
  on public.payments for select
  to authenticated
  using (
    exists (
      select 1
        from public.bookings b
       where b.id = booking_id
         and b.passenger_id = auth.uid()
    )
    or exists (
      select 1
        from public.bookings b
        join public.rides r on r.id = b.ride_id
       where b.id = booking_id
         and r.driver_id = auth.uid()
    )
  );

-- No INSERT/UPDATE/DELETE policies: RPC-only mutations.

-- 3. Timeout configuration - single source of truth.
--    Change this value (in a new migration) to tune the pending-request
--    deadline. The rider UI reads expires_at from the booking row.
create function public.booking_hold_interval()
returns interval
language sql
immutable
as $$
  select interval '3 minutes';
$$;

revoke execute on function public.booking_hold_interval() from public, anon, authenticated;

-- 4. Internal helper: release stale pending holds for one ride.
--    Called at the start of every capacity-affecting RPC so expired
--    holds are never counted. (updated_at is maintained by trigger.)
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

-- 5. RPC: request_booking
--    Atomically: authorize -> validate -> sweep stale holds -> re-check
--    duplicates -> count held seats -> insert pending booking with a
--    3-minute expiry. The FOR UPDATE ride lock serializes concurrency.
create function public.request_booking(
  p_ride_id uuid,
  p_seats integer,
  p_contact_phone text
)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_passenger uuid := auth.uid();
  v_ride public.rides%rowtype;
  v_digits text;
  v_phone text;
  v_held integer;
  v_booking_id uuid := gen_random_uuid();
  v_booking public.bookings%rowtype;
begin
  if v_passenger is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  -- Normalize the phone server-side: digits only, optional leading 91,
  -- must be a 10-digit Indian mobile number.
  v_digits := regexp_replace(coalesce(p_contact_phone, ''), '[^0-9]', '', 'g');
  if v_digits ~ '^91[0-9]{10}$' then
    v_digits := substr(v_digits, 3);
  end if;
  if v_digits !~ '^[6-9][0-9]{9}$' then
    raise exception 'VALIDATION_ERROR: contact phone must be a 10-digit Indian mobile number';
  end if;
  v_phone := '+91' || v_digits;

  if p_seats is null or p_seats < 1 then
    raise exception 'VALIDATION_ERROR: request at least 1 seat';
  end if;

  -- Lock the ride row: serializes every concurrent booking action on it.
  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  if v_ride.driver_id = v_passenger then
    raise exception 'VALIDATION_ERROR: you cannot book your own ride';
  end if;
  if v_ride.status <> 'scheduled' then
    raise exception 'RIDE_NOT_AVAILABLE: this ride is no longer accepting requests';
  end if;
  if v_ride.departure_time <= now() then
    raise exception 'RIDE_NOT_AVAILABLE: this ride''s departure time has passed';
  end if;
  if p_seats > v_ride.passenger_capacity then
    raise exception 'VALIDATION_ERROR: this ride only has % passenger seat(s)', v_ride.passenger_capacity;
  end if;

  -- Release stale holds first so capacity math only counts live requests.
  perform public.expire_stale_bookings(p_ride_id);

  if exists (
    select 1
      from public.bookings
     where ride_id = p_ride_id
       and passenger_id = v_passenger
       and status in ('pending', 'confirmed')
  ) then
    raise exception 'DUPLICATE_BOOKING: you already have an active request on this ride';
  end if;

  select coalesce(sum(seats_requested), 0) into v_held
    from public.bookings
   where ride_id = p_ride_id
     and status in ('pending', 'confirmed');

  if v_held + p_seats > v_ride.passenger_capacity then
    raise exception 'NOT_ENOUGH_SEATS: only % seat(s) left on this ride',
      v_ride.passenger_capacity - v_held;
  end if;

  insert into public.bookings
    (id, ride_id, passenger_id, seats_requested, status, contact_phone,
     fare_per_seat, expires_at)
  values
    (v_booking_id, p_ride_id, v_passenger, p_seats, 'pending', v_phone,
     v_ride.fare_per_seat, now() + public.booking_hold_interval());

  select * into v_booking
    from public.bookings
   where id = v_booking_id;

  return v_booking;
end;
$$;

revoke execute on function public.request_booking(uuid, integer, text) from public, anon;
grant execute on function public.request_booking(uuid, integer, text) to authenticated;

-- 6. RPC: approve_booking (driver confirms a pending request).
--    The seat was already held while pending, so no capacity check is
--    needed - approval can never overbook. A demo payment row is created
--    as 'pending' for the passenger to "Pay".
create function public.approve_booking(p_booking_id uuid)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride_id uuid;
  v_ride public.rides%rowtype;
  v_booking public.bookings%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select ride_id into v_ride_id
    from public.bookings
   where id = p_booking_id;
  if v_ride_id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;

  select * into v_ride
    from public.rides
   where id = v_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  if v_ride.driver_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can approve requests';
  end if;
  if v_ride.status <> 'scheduled' or v_ride.departure_time <= now() then
    raise exception 'RIDE_NOT_AVAILABLE: this ride is no longer accepting requests';
  end if;

  -- Sweep first: the target itself may have just timed out.
  perform public.expire_stale_bookings(v_ride_id);

  select * into v_booking
    from public.bookings
   where id = p_booking_id
     for update;
  if v_booking.status <> 'pending' then
    raise exception 'INVALID_STATE: only pending requests can be confirmed (current: %)', v_booking.status;
  end if;

  update public.bookings
     set status = 'confirmed',
         expires_at = null
   where id = p_booking_id;

  insert into public.payments (booking_id, amount, currency, status)
  values (p_booking_id, v_booking.total_fare, 'INR', 'pending')
  on conflict (booking_id) do nothing;

  select * into v_booking
    from public.bookings
   where id = p_booking_id;

  return v_booking;
end;
$$;

revoke execute on function public.approve_booking(uuid) from public, anon;
grant execute on function public.approve_booking(uuid) to authenticated;

-- 7. RPC: reject_booking (driver rejects a pending request; seats released)
create function public.reject_booking(p_booking_id uuid)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride_id uuid;
  v_ride public.rides%rowtype;
  v_booking public.bookings%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select ride_id into v_ride_id
    from public.bookings
   where id = p_booking_id;
  if v_ride_id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;

  select * into v_ride
    from public.rides
   where id = v_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  if v_ride.driver_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can reject requests';
  end if;
  if v_ride.status <> 'scheduled' or v_ride.departure_time <= now() then
    raise exception 'RIDE_NOT_AVAILABLE: this ride is no longer accepting requests';
  end if;

  perform public.expire_stale_bookings(v_ride_id);

  select * into v_booking
    from public.bookings
   where id = p_booking_id
     for update;
  if v_booking.status <> 'pending' then
    raise exception 'INVALID_STATE: only pending requests can be rejected (current: %)', v_booking.status;
  end if;

  update public.bookings
     set status = 'rejected'
   where id = p_booking_id;

  select * into v_booking
    from public.bookings
   where id = p_booking_id;

  return v_booking;
end;
$$;

revoke execute on function public.reject_booking(uuid) from public, anon;
grant execute on function public.reject_booking(uuid) to authenticated;

-- 8. RPC: cancel_booking
--    Passenger cancels their own request, or the driver cancels a booking
--    on their ride (including confirmed ones). Allowed only while the ride
--    is still 'scheduled' and before departure. Cancelling a confirmed
--    booking marks its demo payment 'simulated_refunded'.
create function public.cancel_booking(p_booking_id uuid)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride_id uuid;
  v_ride public.rides%rowtype;
  v_booking public.bookings%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select ride_id into v_ride_id
    from public.bookings
   where id = p_booking_id;
  if v_ride_id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;

  select * into v_ride
    from public.rides
   where id = v_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  perform public.expire_stale_bookings(v_ride_id);

  select * into v_booking
    from public.bookings
   where id = p_booking_id
     for update;

  if v_booking.passenger_id <> v_caller and v_ride.driver_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the passenger or the driver can cancel this booking';
  end if;
  if v_booking.status not in ('pending', 'confirmed') then
    raise exception 'INVALID_STATE: this booking can no longer be cancelled (current: %)', v_booking.status;
  end if;
  if v_ride.status <> 'scheduled' or v_ride.departure_time <= now() then
    raise exception 'RIDE_NOT_AVAILABLE: this ride is no longer accepting changes';
  end if;

  update public.bookings
     set status = 'cancelled'
   where id = p_booking_id;

  -- Demo payment lifecycle: refund/void whatever its state was.
  update public.payments
     set status = 'simulated_refunded'
   where booking_id = p_booking_id
     and status in ('pending', 'simulated_paid');

  select * into v_booking
    from public.bookings
   where id = p_booking_id;

  return v_booking;
end;
$$;

revoke execute on function public.cancel_booking(uuid) from public, anon;
grant execute on function public.cancel_booking(uuid) to authenticated;

-- 9. RPC: start_ride (driver: scheduled -> in_progress)
--    Allowed before departure_time (drivers can leave early).
create function public.start_ride(p_ride_id uuid)
returns public.rides
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride public.rides%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  if v_ride.driver_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can start this ride';
  end if;
  if v_ride.status <> 'scheduled' then
    raise exception 'INVALID_STATE: only scheduled rides can be started (current: %)', v_ride.status;
  end if;

  update public.rides
     set status = 'in_progress'
   where id = p_ride_id;

  select * into v_ride
    from public.rides
   where id = p_ride_id;

  return v_ride;
end;
$$;

revoke execute on function public.start_ride(uuid) from public, anon;
grant execute on function public.start_ride(uuid) to authenticated;

-- 10. RPC: cancel_ride (driver: scheduled -> cancelled)
--     All active bookings on the ride are cancelled and released;
--     demo payments for confirmed bookings are refunded/voided.
create function public.cancel_ride(p_ride_id uuid)
returns public.rides
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride public.rides%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  if v_ride.driver_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can cancel this ride';
  end if;
  if v_ride.status <> 'scheduled' then
    raise exception 'INVALID_STATE: only scheduled rides can be cancelled (current: %)', v_ride.status;
  end if;

  perform public.expire_stale_bookings(p_ride_id);

  -- Refund/void demo payments for confirmed bookings on this ride.
  update public.payments p
     set status = 'simulated_refunded'
    from public.bookings b
   where p.booking_id = b.id
     and b.ride_id = p_ride_id
     and b.status = 'confirmed'
     and p.status in ('pending', 'simulated_paid');

  -- Release every remaining hold/request.
  update public.bookings
     set status = 'cancelled'
   where ride_id = p_ride_id
     and status in ('pending', 'confirmed');

  update public.rides
     set status = 'cancelled'
   where id = p_ride_id;

  select * into v_ride
    from public.rides
   where id = p_ride_id;

  return v_ride;
end;
$$;

revoke execute on function public.cancel_ride(uuid) from public, anon;
grant execute on function public.cancel_ride(uuid) to authenticated;

-- 11. RPC: complete_ride (driver: in_progress -> completed)
--     Confirmed bookings become 'completed'; any still-pending requests
--     (driver never answered) become 'expired'. Demo payments are left
--     in their honest state (pending or simulated_paid).
create function public.complete_ride(p_ride_id uuid)
returns public.rides
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride public.rides%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
  if not found then
    raise exception 'NOT_FOUND: ride not found';
  end if;

  if v_ride.driver_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can complete this ride';
  end if;
  if v_ride.status <> 'in_progress' then
    raise exception 'INVALID_STATE: only in-progress rides can be completed (current: %)', v_ride.status;
  end if;

  -- Settle every remaining booking on the ride.
  update public.bookings
     set status = 'expired'
   where ride_id = p_ride_id
     and status = 'pending';

  update public.bookings
     set status = 'completed'
   where ride_id = p_ride_id
     and status = 'confirmed';

  update public.rides
     set status = 'completed'
   where id = p_ride_id;

  select * into v_ride
    from public.rides
   where id = p_ride_id;

  return v_ride;
end;
$$;

revoke execute on function public.complete_ride(uuid) from public, anon;
grant execute on function public.complete_ride(uuid) to authenticated;

-- 12. RPC: simulate_payment (passenger taps "Pay" on a confirmed booking)
--     Purely a demo state change - no money moves anywhere.
create function public.simulate_payment(p_booking_id uuid)
returns public.payments
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_booking public.bookings%rowtype;
  v_payment public.payments%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select * into v_booking
    from public.bookings
   where id = p_booking_id;
  if v_booking.id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;

  if v_booking.passenger_id <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the passenger can pay for this booking';
  end if;
  if v_booking.status <> 'confirmed' then
    raise exception 'INVALID_STATE: only confirmed bookings can be paid (current: %)', v_booking.status;
  end if;

  select * into v_payment
    from public.payments
   where booking_id = p_booking_id
     for update;
  if v_payment.id is null then
    raise exception 'NOT_FOUND: no payment record for this booking';
  end if;
  if v_payment.status <> 'pending' then
    raise exception 'INVALID_STATE: this payment was already settled (current: %)', v_payment.status;
  end if;

  update public.payments
     set status = 'simulated_paid',
         provider_reference = 'demo_' || gen_random_uuid()::text
   where id = v_payment.id;

  select * into v_payment
    from public.payments
   where id = v_payment.id;

  return v_payment;
end;
$$;

revoke execute on function public.simulate_payment(uuid) from public, anon;
grant execute on function public.simulate_payment(uuid) to authenticated;
