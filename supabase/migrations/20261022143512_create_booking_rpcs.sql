-- Smart Carpool - Migration 3b: booking RPCs
--   request_booking, approve_booking, reject_booking, cancel_booking
--
-- Pattern shared by every RPC here (review one, then diff the others):
--   1. auth.uid() must be non-null.
--   2. Look up the booking/ride WITHOUT locking and authorize the caller, so
--      an unauthorized caller can never take a lock on someone's ride.
--   3. Lock the ride row (SELECT ... FOR UPDATE). This serializes every
--      concurrent booking action on that ride - two passengers racing for the
--      last seat can never oversubscribe it.
--   4. Sweep expired holds, re-read the booking under lock, validate state.
--   5. Mutate, return the new row.
-- All are SECURITY DEFINER with an empty search_path (every object is
-- schema-qualified), EXECUTE revoked from public/anon, granted to
-- authenticated only. Errors are 'CODE: message' strings.

-- 1. RPC: request_booking
--    Atomically: authorize -> validate -> lock ride -> sweep stale holds ->
--    re-check duplicates / cooldown / pending cap -> count held seats ->
--    insert a pending booking with a 3-minute expiry.
--    Anti-abuse limits (constants below): at most 3 live pending requests per
--    passenger, and a 10-minute cooldown on a ride after the passenger's
--    request there was rejected or timed out.
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
  c_max_pending constant integer := 3;
  c_cooldown constant interval := interval '10 minutes';
  v_passenger uuid := auth.uid();
  v_ride public.rides%rowtype;
  v_digits text;
  v_phone text;
  v_held integer;
  v_pending integer;
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

  -- One request at a time per passenger, so the pending-request cap below
  -- cannot be raced from two rides at once. (Always taken before the ride
  -- lock, and by this function only, so it cannot deadlock.)
  perform pg_advisory_xact_lock(
    hashtext('smart_carpool.request_booking'), hashtext(v_passenger::text));

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

  -- Cooldown: no re-requesting the same ride right after a rejection/timeout.
  if exists (
    select 1
      from public.bookings
     where ride_id = p_ride_id
       and passenger_id = v_passenger
       and ((status = 'rejected' and updated_at > now() - c_cooldown)
         or (status = 'expired'  and expires_at > now() - c_cooldown))
  ) then
    raise exception 'COOLDOWN: wait a few minutes before requesting this ride again';
  end if;

  select count(*) into v_pending
    from public.bookings
   where passenger_id = v_passenger
     and status = 'pending'
     and expires_at > now();
  if v_pending >= c_max_pending then
    raise exception 'PENDING_LIMIT: you can have at most % pending requests at a time', c_max_pending;
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

-- 2. RPC: approve_booking (driver confirms a pending request).
--    The seat was already held while pending, so no capacity check is
--    needed - approval can never overbook. A demo payment row is created
--    as 'pending' for the passenger to "Pay".
--    If the request already timed out, raises REQUEST_EXPIRED (the sweep is
--    rolled back with the error; clients must apply the CLIENT RULE in the
--    previous migration's header).
create function public.approve_booking(p_booking_id uuid)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride_id uuid;
  v_driver uuid;
  v_ride public.rides%rowtype;
  v_booking public.bookings%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select b.ride_id, r.driver_id into v_ride_id, v_driver
    from public.bookings b
    join public.rides r on r.id = b.ride_id
   where b.id = p_booking_id;
  if v_ride_id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;
  if v_driver <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can approve requests';
  end if;

  select * into v_ride
    from public.rides
   where id = v_ride_id
     for update;

  if v_ride.status <> 'scheduled' or v_ride.departure_time <= now() then
    raise exception 'RIDE_NOT_AVAILABLE: this ride is no longer accepting requests';
  end if;

  -- Sweep first: the target itself may have just timed out.
  perform public.expire_stale_bookings(v_ride_id);

  select * into v_booking
    from public.bookings
   where id = p_booking_id
     for update;
  if v_booking.status = 'expired' then
    raise exception 'REQUEST_EXPIRED: this request timed out before it was answered';
  end if;
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

-- 3. RPC: reject_booking (driver rejects a pending request; seats released)
create function public.reject_booking(p_booking_id uuid)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride_id uuid;
  v_driver uuid;
  v_ride public.rides%rowtype;
  v_booking public.bookings%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select b.ride_id, r.driver_id into v_ride_id, v_driver
    from public.bookings b
    join public.rides r on r.id = b.ride_id
   where b.id = p_booking_id;
  if v_ride_id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;
  if v_driver <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can reject requests';
  end if;

  select * into v_ride
    from public.rides
   where id = v_ride_id
     for update;

  if v_ride.status <> 'scheduled' or v_ride.departure_time <= now() then
    raise exception 'RIDE_NOT_AVAILABLE: this ride is no longer accepting requests';
  end if;

  perform public.expire_stale_bookings(v_ride_id);

  select * into v_booking
    from public.bookings
   where id = p_booking_id
     for update;
  if v_booking.status = 'expired' then
    raise exception 'REQUEST_EXPIRED: this request timed out before it was answered';
  end if;
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

-- 4. RPC: cancel_booking
--    Passenger cancels their own request, or the driver cancels a booking
--    on their ride (including confirmed ones). Allowed only while the ride
--    is still 'scheduled' and before departure. Cancelling a confirmed
--    booking marks its demo payment 'simulated_refunded'.
--    Idempotent: cancelling a booking that is already cancelled or expired
--    just returns it (the end state is what the caller wanted).
create function public.cancel_booking(p_booking_id uuid)
returns public.bookings
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_ride_id uuid;
  v_passenger uuid;
  v_driver uuid;
  v_ride public.rides%rowtype;
  v_booking public.bookings%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select b.ride_id, b.passenger_id, r.driver_id into v_ride_id, v_passenger, v_driver
    from public.bookings b
    join public.rides r on r.id = b.ride_id
   where b.id = p_booking_id;
  if v_ride_id is null then
    raise exception 'NOT_FOUND: booking not found';
  end if;
  if v_caller <> v_passenger and v_caller <> v_driver then
    raise exception 'NOT_AUTHORIZED: only the passenger or the driver can cancel this booking';
  end if;

  select * into v_ride
    from public.rides
   where id = v_ride_id
     for update;

  perform public.expire_stale_bookings(v_ride_id);

  select * into v_booking
    from public.bookings
   where id = p_booking_id
     for update;

  if v_booking.status in ('cancelled', 'expired') then
    return v_booking;
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
