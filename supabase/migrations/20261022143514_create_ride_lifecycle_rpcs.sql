-- Smart Carpool - Migration 3c: ride lifecycle + demo payment RPCs
--   start_ride, cancel_ride, complete_ride, simulate_payment
--
-- Same pattern as the booking RPCs: auth.uid() required, caller authorized
-- BEFORE any lock is taken, then lock the ride row, validate state, mutate.
-- SECURITY DEFINER, empty search_path, EXECUTE only for authenticated.

-- 1. RPC: start_ride (driver: scheduled -> in_progress)
--    Only from 30 minutes before the scheduled departure onward; a late
--    start (after departure) is still allowed. Requests the driver never
--    answered lapse ('expired'): once a ride is under way nobody can
--    approve, reject, or cancel them, so they must not linger.
create function public.start_ride(p_ride_id uuid)
returns public.rides
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_driver uuid;
  v_ride public.rides%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select driver_id into v_driver
    from public.rides
   where id = p_ride_id;
  if v_driver is null then
    raise exception 'NOT_FOUND: ride not found';
  end if;
  if v_driver <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can start this ride';
  end if;

  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
  if v_ride.status <> 'scheduled' then
    raise exception 'INVALID_STATE: only scheduled rides can be started (current: %)', v_ride.status;
  end if;
  -- Start window: no earlier than 30 minutes before the scheduled departure.
  -- Checked before touching bookings, so a rejected start has no side effects.
  if v_ride.departure_time > now() + interval '30 minutes' then
    raise exception 'RIDE_NOT_AVAILABLE: a ride can only be started within 30 minutes of its departure time';
  end if;

  update public.bookings
     set status = 'expired'
   where ride_id = p_ride_id
     and status = 'pending';

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

-- 2. RPC: cancel_ride (driver: scheduled -> cancelled)
--    All active bookings on the ride are cancelled and released;
--    demo payments for confirmed bookings are refunded/voided.
create function public.cancel_ride(p_ride_id uuid)
returns public.rides
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_driver uuid;
  v_ride public.rides%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select driver_id into v_driver
    from public.rides
   where id = p_ride_id;
  if v_driver is null then
    raise exception 'NOT_FOUND: ride not found';
  end if;
  if v_driver <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can cancel this ride';
  end if;

  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
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

-- 3. RPC: complete_ride (driver: in_progress -> completed)
--    Confirmed bookings become 'completed'; any still-pending requests
--    (should not exist after start_ride) become 'expired'. Demo payments are
--    left in their honest state (pending or simulated_paid).
--    NOTE for the demo script: a passenger can only "Pay" while the booking
--    is 'confirmed', i.e. before the ride is completed.
create function public.complete_ride(p_ride_id uuid)
returns public.rides
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_caller uuid := auth.uid();
  v_driver uuid;
  v_ride public.rides%rowtype;
begin
  if v_caller is null then
    raise exception 'NOT_AUTHORIZED: you must be signed in';
  end if;

  select driver_id into v_driver
    from public.rides
   where id = p_ride_id;
  if v_driver is null then
    raise exception 'NOT_FOUND: ride not found';
  end if;
  if v_driver <> v_caller then
    raise exception 'NOT_AUTHORIZED: only the driver can complete this ride';
  end if;

  select * into v_ride
    from public.rides
   where id = p_ride_id
     for update;
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

-- 4. RPC: simulate_payment (passenger taps "Pay" on a confirmed booking)
--    Purely a demo state change - no money moves anywhere.
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
