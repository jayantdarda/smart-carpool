#!/usr/bin/env python3
"""
Smart Carpool - database test suite (permissions, RLS, state machine, races).

Needs only: python3 (stdlib) + the `psql` client. No pip packages.
It talks to a Postgres that already has the migrations applied and a
Supabase-style environment (roles anon / authenticated / service_role, an
auth schema with auth.users and auth.uid()). See tests/README.md.

  usage:  python3 run_tests.py <dbname> [-k substring] [--rounds N]
  env:    PGHOST (socket dir or host), PGPORT, TEST_ADMIN_USER (a superuser,
          default supabase_admin), TEST_OWNER_USER (migration owner, default
          postgres), TEST_AUTH_USER (owner of auth.users, default
          supabase_auth_admin)

Clients are simulated exactly the way PostgREST does it: SET ROLE
authenticated|anon plus the request.jwt.claim.sub setting that auth.uid()
reads. Every test creates its own fresh data and uses its own users.
"""
import os
import re
import subprocess
import sys
import threading
import time
import uuid
import random
from concurrent.futures import ThreadPoolExecutor

HOST = os.environ.get("PGHOST", "/var/lib/postgresql/sc_test")
PORT = os.environ.get("PGPORT", "54329")
ADMIN = os.environ.get("TEST_ADMIN_USER", "supabase_admin")
OWNER = os.environ.get("TEST_OWNER_USER", "postgres")
AUTHADM = os.environ.get("TEST_AUTH_USER", "supabase_auth_admin")
DB = None
ROUNDS = 12

ZERO = "00000000-0000-0000-0000-000000000000"
PHONE = "9876543210"


# ---------------------------------------------------------------- plumbing
class R:
    def __init__(self, rc, out, err):
        self.rc, self.out, self.err = rc, out.strip(), err
        m = re.search(r"ERROR:\s+([0-9A-Z]{5}):\s+(.*)", err)
        self.sqlstate = m.group(1) if m else None
        self.msg = m.group(2).strip() if m else ""
        self.ok = rc == 0 and not m

    @property
    def code(self):  # our 'CODE: text' business errors
        m = re.match(r"([A-Z_]+):", self.msg)
        return m.group(1) if m else None

    @property
    def rows(self):
        return [ln.split("|") for ln in self.out.splitlines() if ln != ""]

    @property
    def val(self):
        rows = self.rows
        return rows[-1][0] if rows else None

    def __repr__(self):
        return f"<R ok={self.ok} sqlstate={self.sqlstate} msg={self.msg!r} out={self.out[:80]!r}>"


def _cmd(user, db=None):
    return ["psql", "-X", "-q", "-At", "-F", "|", "-h", HOST, "-p", PORT,
            "-U", user, "-d", db or DB, "-v", "ON_ERROR_STOP=1", "-f", "-"]


def psql(script, user=OWNER, timeout=120):
    p = subprocess.run(_cmd(user), input=script, capture_output=True, text=True, timeout=timeout)
    return R(p.returncode, p.stdout, p.stderr)


def esc(s):
    return s.replace("'", "''")


def preamble(uid, role):
    s = "\\set VERBOSITY verbose\nbegin;\n"
    if role:
        s += f"set local role {role};\n"
        if uid:
            s += f"select set_config('request.jwt.claim.sub', '{uid}', true) as _jwt \\gset\n"
    return s


def sql(body, uid=None, role="authenticated", commit=True, user=OWNER):
    """Run `body` as a client (role + jwt sub). role=None -> as the owner role."""
    tail = "commit;\n" if commit else "rollback;\n"
    return psql(preamble(uid, role) + body.rstrip().rstrip(";") + ";\n" + tail, user=user)


def admin(body):
    return psql("\\set VERBOSITY verbose\n" + body, user=ADMIN)


def owner(body):
    return psql("\\set VERBOSITY verbose\n" + body, user=OWNER)


# ---------------------------------------------------------------- fixtures
def user(name=None, meta=None):
    uid = str(uuid.uuid4())
    name = name or "u" + uid[:6]
    if meta is None:
        meta = '{"display_name": "%s"}' % name
    r = psql(f"insert into auth.users (id, email, raw_user_meta_data) "
             f"values ('{uid}', '{name}@test.local', '{esc(meta)}'::jsonb);", user=AUTHADM)
    assert r.ok, f"user fixture failed: {r}"
    return uid


def vehicle(owner_id, seats=5):
    plate = "TS%08d" % random.randint(0, 10**8 - 1)
    r = owner(f"insert into public.vehicles (owner_id, make, model, registration_number, total_seats) "
              f"values ('{owner_id}', 'Maruti', 'Ertiga', '{plate}', {seats}) returning id;")
    assert r.ok, f"vehicle fixture failed: {r}"
    return r.val


def ride(driver, veh=None, cap=3, fare=100, hours=24):
    veh = veh or vehicle(driver, max(cap + 1, 2))
    r = owner(f"insert into public.rides (driver_id, vehicle_id, origin_label, origin_latitude, origin_longitude, "
              f"destination_label, destination_latitude, destination_longitude, departure_time, passenger_capacity, fare_per_seat) "
              f"values ('{driver}', '{veh}', 'A', 19.07, 72.87, 'B', 18.52, 73.85, now() + interval '{hours} hours', {cap}, {fare}) returning id;")
    assert r.ok, f"ride fixture failed: {r}"
    return r.val


def req(uid, ride_id, seats=1, phone=PHONE):
    return sql(f"select id, status from public.request_booking('{ride_id}', {seats}, '{phone}')", uid)


def bk(uid, fn, booking_id):
    return sql(f"select id, status from public.{fn}('{booking_id}')", uid)


def bstatus(booking_id):
    return owner(f"select status from public.bookings where id = '{booking_id}';").val


def pstatus(booking_id):
    return owner(f"select status from public.payments where booking_id = '{booking_id}';").val


def avail(ride_id):
    r = owner(f"select seats_held, seats_available from public.rides_with_availability where id = '{ride_id}';")
    return tuple(int(x) for x in r.rows[0])


def expire_now(booking_id):
    """Time-travel: make a pending request's deadline pass (without sweeping it)."""
    r = owner(f"update public.bookings set expires_at = now() - interval '1 minute' where id = '{booking_id}' and status = 'pending';")
    assert r.ok, r


def age_updated_at(booking_id, minutes):
    r = admin(f"set session_replication_role = replica; "
              f"update public.bookings set updated_at = now() - interval '{minutes} minutes', "
              f"expires_at = expires_at - interval '{minutes} minutes' where id = '{booking_id}';")
    assert r.ok, r


def new_booking(rd, passenger, seats=1):
    r = req(passenger, rd, seats)
    assert r.ok, f"booking fixture failed: {r}"
    return r.rows[0][0]


# ---------------------------------------------------------------- test runner
TESTS = []


def test(name):
    def deco(fn):
        TESTS.append((name, fn))
        return fn
    return deco


def ok(r, what=""):
    assert r.ok, f"expected success {what}, got {r.sqlstate} {r.msg}"


def fail(r, sqlstate=None, code=None, what=""):
    assert not r.ok, f"expected an error {what}, but it succeeded: {r.out}"
    if sqlstate:
        assert r.sqlstate == sqlstate, f"expected SQLSTATE {sqlstate} {what}, got {r.sqlstate}: {r.msg}"
    if code:
        assert r.code == code, f"expected {code} {what}, got {r.sqlstate}: {r.msg}"


def eq(a, b, what=""):
    assert a == b, f"{what}: expected {b!r}, got {a!r}"


# ================================================================ SIGNUP / PROFILES
@test("signup: profile created from metadata / email / fallbacks, never longer than 60")
def t_signup():
    a = user("Alice")
    eq(owner(f"select display_name from public.profiles where id='{a}';").val, "Alice")
    b = user("bobsmith", meta="{}")
    eq(owner(f"select display_name from public.profiles where id='{b}';").val, "bobsmith")
    c = user("c", meta='{"display_name": "%s"}' % ("x" * 500))
    eq(owner(f"select length(display_name) from public.profiles where id='{c}';").val, "60")
    d = str(uuid.uuid4())
    ok(psql(f"insert into auth.users (id) values ('{d}');", user=AUTHADM))
    eq(owner(f"select display_name from public.profiles where id='{d}';").val, "New User")
    e = user("zed", meta='{"name": "   "}')
    eq(owner(f"select display_name from public.profiles where id='{e}';").val, "zed")
    f = user("arr", meta="[1,2]")
    eq(owner(f"select display_name from public.profiles where id='{f}';").val, "arr")


@test("signup: a failing profile insert can NEVER abort signup (exception wrapper)")
def t_signup_never_breaks():
    uid = str(uuid.uuid4())
    r = admin(f"begin; alter table public.profiles add constraint tmp_fail check (false) not valid; "
              f"insert into auth.users (id, email) values ('{uid}', 'x@y.z'); "
              f"select (select count(*) from auth.users where id='{uid}')::text || ',' || "
              f"(select count(*) from public.profiles where id='{uid}')::text; rollback;")
    ok(r, "signup with broken profile insert")
    eq(r.val, "1,0", "user row exists, profile row does not")


@test("profiles: everyone signed in can read; direct UPDATE/DELETE/TRUNCATE are impossible")
def t_profiles_rw():
    u1, u2 = user(), user()
    r = sql("select count(*) from public.profiles where id in ('%s','%s')" % (u1, u2), u1)
    eq(r.val, "2")
    fail(sql("update public.profiles set display_name='hacked' where id='%s'" % u2, u1), "42501")
    fail(sql("update public.profiles set display_name='mine' where id='%s'" % u1, u1), "42501")
    fail(sql("delete from public.profiles where id='%s'" % u2, u1), "42501")
    fail(sql("truncate public.profiles", u1), "42501")


@test("profiles: update_profile trims, validates length, only edits the caller")
def t_update_profile():
    u1, u2 = user("one"), user("two")
    r = sql("select display_name from public.update_profile('   New Name  ')", u1)
    ok(r)
    eq(r.val, "New Name")
    eq(owner(f"select display_name from public.profiles where id='{u2}';").val, "two", "other user untouched")
    fail(sql("select * from public.update_profile('')", u1), code="VALIDATION_ERROR")
    fail(sql("select * from public.update_profile('   ')", u1), code="VALIDATION_ERROR")
    fail(sql("select * from public.update_profile(null)", u1), code="VALIDATION_ERROR")
    fail(sql("select * from public.update_profile('%s')" % ("y" * 61), u1), code="VALIDATION_ERROR")
    ok(sql("select * from public.update_profile('%s')" % ("y" * 60), u1))
    fail(sql("select * from public.update_profile('x')", None, role="anon"), "42501")


@test("profiles: recovery INSERT only for yourself, only id+display_name, max 60 chars")
def t_profile_recovery():
    u1, u2 = user(), user()
    owner(f"delete from public.profiles where id='{u1}';")
    fail(sql(f"insert into public.profiles (id, display_name) values ('{u2}', 'x')", u1), "42501", what="other id")
    fail(sql(f"insert into public.profiles (id, display_name) values ('{u1}', '{'z'*61}')", u1), "23514", what="too long")
    fail(sql(f"insert into public.profiles (id, display_name, created_at) values ('{u1}', 'x', now())", u1), "42501",
         what="extra column")
    ok(sql(f"insert into public.profiles (id, display_name) values ('{u1}', 'Back')", u1))


# ================================================================ PRIVILEGES
RELATIONS = ["profiles", "vehicles", "rides", "bookings", "payments", "vehicles_public", "rides_with_availability"]
CLIENT_RPCS = [
    "update_profile('x')",
    f"request_booking('{ZERO}', 1, '{PHONE}')",
    f"approve_booking('{ZERO}')", f"reject_booking('{ZERO}')", f"cancel_booking('{ZERO}')",
    f"start_ride('{ZERO}')", f"cancel_ride('{ZERO}')", f"complete_ride('{ZERO}')", f"simulate_payment('{ZERO}')",
]
INTERNALS = ["handle_new_user()", f"expire_stale_bookings('{ZERO}')", "booking_hold_interval()",
             "set_updated_at()", "normalize_vehicle()", "validate_ride()", "guard_vehicle_seat_edit()",
             "guard_ride_edit_with_bookings()"]


@test("anon: cannot read/write ANY relation or call ANY function")
def t_anon():
    for rel in RELATIONS:
        fail(sql(f"select 1 from public.{rel} limit 1", None, role="anon"), "42501", what=f"anon select {rel}")
    for rel in ["profiles", "vehicles", "rides", "bookings", "payments"]:
        fail(sql(f"delete from public.{rel}", None, role="anon"), "42501", what=f"anon delete {rel}")
    for fn in CLIENT_RPCS + INTERNALS:
        fail(sql(f"select public.{fn}", None, role="anon"), "42501", what=f"anon call {fn}")


@test("authenticated: cannot call internal helpers / trigger functions directly")
def t_internal_functions():
    u = user()
    for fn in INTERNALS:
        fail(sql(f"select public.{fn}", u), "42501", what=f"authenticated call {fn}")


@test("authenticated: no direct writes to bookings/payments/rides.status (privilege-level, not just RLS)")
def t_no_direct_writes():
    d, p = user(), user()
    rd = ride(d)
    b = new_booking(rd, p)
    for stmt in [
        f"insert into public.bookings (ride_id, passenger_id, seats_requested, status, contact_phone, fare_per_seat) values ('{rd}','{p}',1,'confirmed','+919876543210',0)",
        f"update public.bookings set status='confirmed' where id='{b}'",
        f"delete from public.bookings where id='{b}'",
        "truncate public.bookings",
        f"insert into public.payments (booking_id, amount, status) values ('{b}', 0, 'simulated_paid')",
        "update public.payments set status='simulated_paid'",
        "delete from public.payments",
        "truncate public.payments",
        f"update public.rides set status='completed' where id='{rd}'",
        f"update public.rides set driver_id='{p}' where id='{rd}'",
        f"delete from public.rides where id='{rd}'",
        "truncate public.rides",
        f"update public.vehicles set created_at = now()",
    ]:
        for who in (d, p):
            fail(sql(stmt, who), "42501", what=stmt[:60])
    eq(bstatus(b), "pending", "booking untouched")


# ================================================================ VEHICLES
@test("vehicles: owner CRUD; plate normalized + globally unique; others see nothing")
def t_vehicles():
    o, x = user(), user()
    n = random.randint(1000, 9999)
    r = sql("insert into public.vehicles (owner_id, make, model, color, registration_number, total_seats) "
            f"values ('{o}', ' Tata ', ' Nexon ', '   ', 'mh 12-ab {n}', 5) returning registration_number, make, model, coalesce(color,'<null>')", o)
    ok(r)
    eq(r.rows[0], [f"MH12AB{n}", "Tata", "Nexon", "<null>"], "normalized")
    fail(sql(f"insert into public.vehicles (owner_id, make, model, registration_number, total_seats) values ('{x}','a','b','MH12AB-{n}',4)", x), "23505",
         what="duplicate plate with different punctuation")
    fail(sql(f"insert into public.vehicles (owner_id, make, model, registration_number, total_seats) values ('{x}','a','b','---',4)", x), "23514",
         what="plate with no letters/digits")
    fail(sql(f"insert into public.vehicles (owner_id, make, model, registration_number, total_seats) values ('{o}','a','b','ZZ1',4)", x), "42501",
         what="owner_id spoof")
    for seats in (1, 10):
        fail(sql(f"insert into public.vehicles (owner_id, make, model, registration_number, total_seats) values ('{x}','a','b','SE{seats}{n}',{seats})", x), "23514")
    eq(sql("select count(*) from public.vehicles", x).val, "0", "stranger sees no vehicles")
    eq(sql("select count(*) from public.vehicles where owner_id='%s'" % o, o).val, "1")
    eq(len(sql("update public.vehicles set make='pwn' where owner_id='%s' returning id" % o, x).rows), 0, "stranger update hits 0 rows")
    eq(len(sql("delete from public.vehicles where owner_id='%s' returning id" % o, x).rows), 0, "stranger delete hits 0 rows")
    ok(sql("update public.vehicles set color='Red' where owner_id='%s'" % o, o))
    fail(sql("update public.vehicles set owner_id='%s' where owner_id='%s'" % (x, o), o), "42501", what="cannot hand over ownership")


@test("vehicles_public: no plate, no owner_id; only vehicles that have a ride; anon blocked")
def t_vehicles_public():
    o, x = user(), user()
    v = vehicle(o)
    eq(sql(f"select count(*) from public.vehicles_public where id='{v}'", x).val, "0", "vehicle without ride is invisible")
    ride(o, v)
    eq(sql(f"select count(*) from public.vehicles_public where id='{v}'", x).val, "1", "vehicle with a ride is visible")
    fail(sql("select owner_id from public.vehicles_public", x), "42703", what="owner_id not exposed")
    fail(sql("select registration_number from public.vehicles_public", x), "42703", what="plate not exposed")
    fail(sql("insert into public.vehicles_public (id) values (gen_random_uuid())", x), "42501")


@test("vehicles: seat reduction blocked while a scheduled OR in-progress ride needs the seats")
def t_vehicle_seat_guard():
    o = user()
    v = vehicle(o, 5)
    rd = ride(o, v, cap=4, hours=0.25)  # started below: must be within the 30-minute start window
    fail(sql(f"update public.vehicles set total_seats=4 where id='{v}'", o), code="CONFLICT")
    ok(sql(f"update public.vehicles set total_seats=6 where id='{v}'", o))
    ok(sql(f"update public.vehicles set total_seats=5 where id='{v}'", o))
    ok(sql(f"select id from public.start_ride('{rd}')", o))
    fail(sql(f"update public.vehicles set total_seats=4 where id='{v}'", o), code="CONFLICT", what="in-progress ride")
    ok(sql(f"select id from public.complete_ride('{rd}')", o))
    ok(sql(f"update public.vehicles set total_seats=2 where id='{v}'", o), "after the ride is completed")


# ================================================================ RIDES
RIDE_COLS = ("driver_id, vehicle_id, origin_label, origin_latitude, origin_longitude, destination_label, "
             "destination_latitude, destination_longitude, departure_time, passenger_capacity, fare_per_seat")


def ride_insert(driver, veh, cap=3, fare=100, lat=19.0, dep="now() + interval '2 hours'", extra_cols="", extra_vals=""):
    return (f"insert into public.rides ({RIDE_COLS}{extra_cols}) values ('{driver}', '{veh}', 'A', {lat}, 72.8, 'B', 18.5, 73.8, "
            f"{dep}, {cap}, {fare}{extra_vals}) returning id, status")


@test("rides: driver creates with own vehicle; always 'scheduled'; every bad input is rejected")
def t_ride_create():
    d, x = user(), user()
    v, xv = vehicle(d, 5), vehicle(x, 5)
    r = sql(ride_insert(d, v, cap=4), d)
    ok(r)
    eq(r.rows[0][1], "scheduled")
    fail(sql(ride_insert(d, xv), d), "23503", what="someone else's vehicle")
    fail(sql(ride_insert(x, v), d), "42501", what="driver_id spoof")
    fail(sql(ride_insert(d, v, extra_cols=", status", extra_vals=", 'completed'"), d), "42501", what="status column not insertable")
    fail(sql(ride_insert(d, v, cap=5), d), code="VALIDATION_ERROR", what="capacity > seats-1")
    fail(sql(ride_insert(d, v, cap=0), d), "23514", what="capacity 0")
    fail(sql(ride_insert(d, v, dep="now() - interval '1 hour'"), d), code="VALIDATION_ERROR", what="past departure")
    fail(sql(ride_insert(d, v, lat=91), d), "23514", what="latitude 91")
    fail(sql(ride_insert(d, v, fare=-1), d), "23514", what="negative fare")
    # Even the table owner path cannot create a ride on someone else's vehicle:
    fail(owner(ride_insert(d, xv)), "23503", what="owner path, foreign vehicle")
    fail(owner(ride_insert(d, v, extra_cols=", status", extra_vals=", 'completed'")), code="INVALID_TRANSITION", what="owner path, non-scheduled insert")


@test("rides: edits - only the driver, never status/driver_id, never someone else's vehicle")
def t_ride_edit_basic():
    d, x = user(), user()
    v, xv = vehicle(d, 6), vehicle(x, 6)
    rd = ride(d, v, cap=3)
    ok(sql(f"update public.rides set fare_per_seat = 250 where id='{rd}'", d))
    eq(len(sql(f"update public.rides set fare_per_seat = 1 where id='{rd}' returning id", x).rows), 0, "stranger edits 0 rows")
    fail(sql(f"update public.rides set status='completed' where id='{rd}'", d), "42501")
    fail(sql(f"update public.rides set driver_id='{x}' where id='{rd}'", d), "42501")
    fail(sql(f"update public.rides set vehicle_id='{xv}' where id='{rd}'", d), "23503", what="swap in a foreign vehicle")
    v2 = vehicle(d, 4)
    ok(sql(f"update public.rides set vehicle_id='{v2}' where id='{rd}'", d))
    fail(sql(f"update public.rides set passenger_capacity=4 where id='{rd}'", d), code="VALIDATION_ERROR", what="capacity over new vehicle")
    fail(sql(f"update public.rides set departure_time = now() - interval '1 hour' where id='{rd}'", d), code="VALIDATION_ERROR")
    ok(sql(f"select id from public.cancel_ride('{rd}')", d))
    eq(len(sql(f"update public.rides set fare_per_seat = 5 where id='{rd}' returning id", d).rows), 0, "cancelled rides are not editable")


@test("rides: H3 - cannot move a ride or cut capacity below seats that were requested/booked")
def t_ride_guard():
    d, p1, p2 = user(), user(), user()
    v, v2 = vehicle(d, 6), vehicle(d, 6)
    rd = ride(d, v, cap=4)
    ok(sql(f"update public.rides set departure_time = departure_time + interval '1 hour', origin_label='A2' where id='{rd}'", d), "free to edit with no bookings")
    b1 = new_booking(rd, p1, 2)
    for col, val in [("departure_time", "departure_time + interval '1 hour'"), ("origin_label", "'Elsewhere'"),
                     ("origin_latitude", "10"), ("origin_longitude", "10"), ("destination_label", "'Elsewhere'"),
                     ("destination_latitude", "10"), ("destination_longitude", "10"), ("vehicle_id", f"'{v2}'")]:
        fail(sql(f"update public.rides set {col} = {val} where id='{rd}'", d), code="CONFLICT", what=f"move {col} with a live request")
    fail(sql(f"update public.rides set passenger_capacity=1 where id='{rd}'", d), code="CONFLICT", what="capacity below held")
    ok(sql(f"update public.rides set passenger_capacity=2 where id='{rd}'", d), "capacity == held is fine")
    ok(sql(f"update public.rides set passenger_capacity=5 where id='{rd}'", d), "capacity increase is fine")
    ok(sql(f"update public.rides set fare_per_seat=999 where id='{rd}'", d), "fare edits are fine")
    eq(owner(f"select fare_per_seat from public.bookings where id='{b1}';").val, "100.00", "booking keeps its own fare snapshot")
    ok(bk(d, "approve_booking", b1))
    fail(sql(f"update public.rides set departure_time = departure_time + interval '1 hour' where id='{rd}'", d), code="CONFLICT", what="confirmed booking")
    ok(bk(p1, "cancel_booking", b1))
    ok(sql(f"update public.rides set departure_time = departure_time + interval '1 hour' where id='{rd}'", d), "free again after cancel")
    # an expired-but-unswept request does not freeze the ride
    b2 = new_booking(rd, p2, 1)
    fail(sql(f"update public.rides set origin_label='Z' where id='{rd}'", d), code="CONFLICT")
    expire_now(b2)
    eq(bstatus(b2), "pending", "still 'pending' in the table (unswept)")
    ok(sql(f"update public.rides set origin_label='Z' where id='{rd}'", d), "expired request no longer freezes the ride")


@test("rides_with_availability: seats_held/seats_available count confirmed + live pending only")
def t_availability():
    d, p1, p2, p3, x = user(), user(), user(), user(), user()
    rd = ride(d, cap=4)
    eq(avail(rd), (0, 4))
    b1 = new_booking(rd, p1, 1)
    b2 = new_booking(rd, p2, 2)
    eq(avail(rd), (3, 1))
    ok(bk(d, "approve_booking", b2))
    eq(avail(rd), (3, 1), "approving does not change availability")
    expire_now(b1)
    eq(bstatus(b1), "pending")
    eq(avail(rd), (2, 2), "expired hold ignored even before it is swept")
    r = sql(f"select seats_held, seats_available, status from public.rides_with_availability where id='{rd}'", x)
    eq(r.rows[0], ["2", "2", "scheduled"], "any signed-in user can read it")
    eq(sql("select count(*) from public.bookings", x).val, "0", "...but still cannot read bookings")
    ok(bk(p2, "cancel_booking", b2))
    eq(avail(rd), (0, 4))
    fail(sql("select 1 from public.rides_with_availability limit 1", None, role="anon"), "42501")


# ================================================================ BOOKING FLOW
@test("request_booking: success shape, fare snapshot, 3-minute expiry")
def t_request_ok():
    d, p = user(), user()
    rd = ride(d, cap=3, fare=125)
    r = sql(f"select status, seats_requested, fare_per_seat, total_fare, contact_phone, "
            f"extract(epoch from (expires_at - now()))::int from public.request_booking('{rd}', 2, '98765 43210')", p)
    ok(r)
    st, seats, fare, total, phone, secs = r.rows[0]
    eq((st, seats, fare, total, phone), ("pending", "2", "125.00", "250.00", "+919876543210"))
    assert 170 <= int(secs) <= 180, f"expiry should be ~180s, got {secs}"


@test("request_booking: every invalid input is rejected with the right code")
def t_request_validation():
    d, p, p2 = user(), user(), user()
    rd = ride(d, cap=2)
    fail(req(p, rd, 1, "12345"), code="VALIDATION_ERROR", what="short phone")
    fail(req(p, rd, 1, "5876543210"), code="VALIDATION_ERROR", what="phone must start 6-9")
    fail(req(p, rd, 1, ""), code="VALIDATION_ERROR", what="empty phone")
    ok(sql(f"select id from public.request_booking('{rd}', 1, '+91 98765-43210')", p), "formatted phone is normalized")
    fail(req(p2, rd, 0), code="VALIDATION_ERROR", what="0 seats")
    fail(req(p2, rd, -1), code="VALIDATION_ERROR", what="-1 seats")
    fail(sql(f"select id from public.request_booking('{rd}', null, '{PHONE}')", p2), code="VALIDATION_ERROR", what="null seats")
    fail(req(p2, rd, 3), code="VALIDATION_ERROR", what="more than the ride offers")
    fail(req(d, rd, 1), code="VALIDATION_ERROR", what="driver books own ride")
    fail(req(p, rd, 1), code="DUPLICATE_BOOKING")
    fail(req(p2, rd, 2), code="NOT_ENOUGH_SEATS", what="1 of 2 seats already held")
    fail(req(p2, ZERO), code="NOT_FOUND")
    fail(sql(f"select id from public.request_booking('{rd}', 1, '{PHONE}')", None, role="authenticated"), code="NOT_AUTHORIZED", what="no jwt")


@test("request_booking: ride must be scheduled and not yet departed")
def t_request_ride_state():
    d, p = user(), user()
    r1, r2, r3 = ride(d), ride(d, hours=0.25), ride(d)  # r2 is started below: within the start window
    ok(sql(f"select id from public.cancel_ride('{r1}')", d))
    fail(req(p, r1), code="RIDE_NOT_AVAILABLE", what="cancelled")
    ok(sql(f"select id from public.start_ride('{r2}')", d))
    fail(req(p, r2), code="RIDE_NOT_AVAILABLE", what="in progress")
    ok(admin(f"set session_replication_role = replica; update public.rides set departure_time = now() - interval '1 hour' where id='{r3}';"))
    fail(req(p, r3), code="RIDE_NOT_AVAILABLE", what="departure passed")


@test("visibility: bookings/payments are visible only to the passenger and the ride's driver")
def t_visibility():
    d, p1, p2, x, d2 = user(), user(), user(), user(), user()
    rd = ride(d, cap=4)
    b1, b2 = new_booking(rd, p1), new_booking(rd, p2)
    ok(bk(d, "approve_booking", b1))
    cnt = lambda who: int(sql("select count(*) from public.bookings", who).val)
    eq((cnt(p1), cnt(p2), cnt(d), cnt(x), cnt(d2)), (1, 1, 2, 0, 0), "bookings visible to p1,p2,driver,stranger,other driver")
    pc = lambda who: int(sql("select count(*) from public.payments", who).val)
    eq((pc(p1), pc(p2), pc(d), pc(x), pc(d2)), (1, 0, 1, 0, 0), "payments visible")


@test("approve_booking: only the ride's driver; creates exactly one demo payment")
def t_approve():
    d, p, x = user(), user(), user()
    rd = ride(d, cap=3, fare=40)
    b = new_booking(rd, p, 2)
    fail(bk(p, "approve_booking", b), code="NOT_AUTHORIZED", what="passenger")
    fail(bk(x, "approve_booking", b), code="NOT_AUTHORIZED", what="stranger")
    fail(sql(f"select id from public.approve_booking('{b}')", None, role="anon"), "42501")
    fail(bk(d, "approve_booking", ZERO), code="NOT_FOUND")
    r = bk(d, "approve_booking", b)
    ok(r)
    eq(r.rows[0][1], "confirmed")
    eq(owner(f"select status || '/' || amount from public.payments where booking_id='{b}';").val, "pending/80.00")
    fail(bk(d, "approve_booking", b), code="INVALID_STATE", what="approve twice")
    eq(owner(f"select count(*) from public.payments where booking_id='{b}';").val, "1")
    eq(owner(f"select expires_at is null from public.bookings where id='{b}';").val, "t")


@test("reject_booking: releases seats; passenger cooldown on that ride, not elsewhere")
def t_reject_cooldown():
    d, p = user(), user()
    rd, rd2 = ride(d, cap=1), ride(d, cap=1)
    b = new_booking(rd, p)
    fail(bk(p, "reject_booking", b), code="NOT_AUTHORIZED")
    ok(bk(d, "reject_booking", b))
    eq(avail(rd), (0, 1), "seat released")
    fail(bk(d, "reject_booking", b), code="INVALID_STATE")
    fail(req(p, rd), code="COOLDOWN", what="immediate re-request after rejection")
    ok(req(p, rd2), "other ride is unaffected")
    age_updated_at(b, 11)
    ok(req(p, rd), "cooldown over after 10 minutes")


@test("expiry: expired holds free the seats (swept by the next request); approve/reject raise REQUEST_EXPIRED")
def t_expiry():
    d, p1, p2, p3 = user(), user(), user(), user()
    rd = ride(d, cap=2)
    b1 = new_booking(rd, p1, 2)
    fail(req(p2, rd, 1), code="NOT_ENOUGH_SEATS", what="live hold blocks")
    expire_now(b1)
    ok(req(p2, rd, 1), "expired hold no longer counts")
    eq(bstatus(b1), "expired", "swept by the successful request")
    fail(bk(d, "approve_booking", b1), code="REQUEST_EXPIRED")
    fail(bk(d, "reject_booking", b1), code="REQUEST_EXPIRED")
    # unswept case: error rolls the sweep back (documented), nothing is corrupted
    b3 = new_booking(rd, p3, 1)
    expire_now(b3)
    fail(bk(d, "approve_booking", b3), code="REQUEST_EXPIRED")
    eq(bstatus(b3), "pending", "sweep rolled back with the error (clients apply the CLIENT RULE)")
    eq(owner(f"select count(*) from public.payments where booking_id='{b3}';").val, "0", "no payment for an expired request")
    fail(req(p3, rd), code="COOLDOWN", what="timed-out request also triggers cooldown")


@test("cancel_booking: passenger or driver only; refunds demo payment; idempotent; blocked once ride started")
def t_cancel_booking():
    d, p, x, p2 = user(), user(), user(), user()
    rd = ride(d, cap=3, hours=0.25)  # started below: must be within the 30-minute start window
    b = new_booking(rd, p, 1)
    fail(bk(x, "cancel_booking", b), code="NOT_AUTHORIZED")
    fail(bk(p2, "cancel_booking", b), code="NOT_AUTHORIZED")
    fail(bk(p, "cancel_booking", ZERO), code="NOT_FOUND")
    ok(bk(p, "cancel_booking", b))
    eq(avail(rd), (0, 3))
    r = bk(p, "cancel_booking", b)
    ok(r, "second cancel is idempotent")
    eq(r.rows[0][1], "cancelled")
    # confirmed -> cancelled by passenger, payment refunded; and paid -> refunded by driver
    b1, b2 = new_booking(rd, p, 1), new_booking(rd, p2, 1)
    ok(bk(d, "approve_booking", b1)); ok(bk(d, "approve_booking", b2))
    ok(bk(p2, "simulate_payment", b2))
    ok(bk(p, "cancel_booking", b1)); eq(pstatus(b1), "simulated_refunded")
    ok(bk(d, "cancel_booking", b2)); eq(pstatus(b2), "simulated_refunded", "paid payment refunded when the driver cancels")
    eq(avail(rd), (0, 3))
    b3 = new_booking(rd, p, 1)
    ok(bk(d, "reject_booking", b3))
    fail(bk(p, "cancel_booking", b3), code="INVALID_STATE", what="rejected requests cannot be cancelled")
    # after the ride starts
    b4 = new_booking(rd, p2, 1); b5 = new_booking(rd, x, 1)
    ok(bk(d, "approve_booking", b4))
    ok(sql(f"select id from public.start_ride('{rd}')", d))
    fail(bk(p2, "cancel_booking", b4), code="RIDE_NOT_AVAILABLE", what="confirmed booking on a started ride")
    r = bk(x, "cancel_booking", b5)
    ok(r, "request that lapsed when the ride started")
    eq(r.rows[0][1], "expired")


@test("anti-abuse: at most 3 live pending requests per passenger; frees up on cancel/expiry")
def t_pending_cap():
    d, p = user(), user()
    rides = [ride(d, cap=2) for _ in range(5)]
    bs = [new_booking(r, p) for r in rides[:3]]
    fail(req(p, rides[3]), code="PENDING_LIMIT")
    ok(bk(p, "cancel_booking", bs[0]))
    b3 = new_booking(rides[3], p)
    fail(req(p, rides[4]), code="PENDING_LIMIT")
    ok(bk(d, "approve_booking", bs[1]))
    ok(req(p, rides[4]), "a confirmed booking no longer counts as pending")
    expire_now(b3)
    ok(req(p, rides[0], 1), "cancelled earlier -> allowed again; expired one no longer counts")


@test("simulate_payment: only the passenger, only confirmed, only once; never moves money")
def t_payment():
    d, p, x = user(), user(), user()
    rd = ride(d, cap=3)
    b = new_booking(rd, p)
    fail(bk(p, "simulate_payment", b), code="INVALID_STATE", what="pending booking")
    ok(bk(d, "approve_booking", b))
    fail(bk(d, "simulate_payment", b), code="NOT_AUTHORIZED", what="driver cannot pay")
    fail(bk(x, "simulate_payment", b), code="NOT_AUTHORIZED")
    fail(bk(p, "simulate_payment", ZERO), code="NOT_FOUND")
    r = sql(f"select status, provider_reference from public.simulate_payment('{b}')", p)
    ok(r)
    assert r.rows[0][0] == "simulated_paid" and r.rows[0][1].startswith("demo_"), r
    fail(bk(p, "simulate_payment", b), code="INVALID_STATE", what="pay twice")
    ok(bk(p, "cancel_booking", b))
    eq(pstatus(b), "simulated_refunded")
    fail(bk(p, "simulate_payment", b), code="INVALID_STATE", what="pay after cancel")


@test("ride lifecycle: start/cancel/complete authorization, transitions, and what happens to bookings")
def t_lifecycle():
    d, p1, p2, p3, x = user(), user(), user(), user(), user()
    rd = ride(d, cap=4, hours=0.25)  # started below: must be within the 30-minute start window
    b1, b2, b3 = new_booking(rd, p1), new_booking(rd, p2), new_booking(rd, p3)
    ok(bk(d, "approve_booking", b1)); ok(bk(p1, "simulate_payment", b1))
    ok(bk(d, "approve_booking", b2))
    for fn in ("start_ride", "cancel_ride", "complete_ride"):
        fail(sql(f"select id from public.{fn}('{rd}')", p1), code="NOT_AUTHORIZED", what=f"{fn} by passenger")
        fail(sql(f"select id from public.{fn}('{rd}')", x), code="NOT_AUTHORIZED", what=f"{fn} by stranger")
        fail(sql(f"select id from public.{fn}('{ZERO}')", d), code="NOT_FOUND")
    fail(sql(f"select id from public.complete_ride('{rd}')", d), code="INVALID_STATE", what="complete a scheduled ride")
    ok(sql(f"select id from public.start_ride('{rd}')", d))
    eq((bstatus(b1), bstatus(b2), bstatus(b3)), ("confirmed", "confirmed", "expired"), "unanswered request lapsed at start")
    fail(sql(f"select id from public.start_ride('{rd}')", d), code="INVALID_STATE")
    fail(sql(f"select id from public.cancel_ride('{rd}')", d), code="INVALID_STATE", what="cancel after start")
    fail(bk(d, "approve_booking", b3), code="RIDE_NOT_AVAILABLE")
    fail(req(x, rd), code="RIDE_NOT_AVAILABLE")
    ok(sql(f"select id from public.complete_ride('{rd}')", d))
    eq((bstatus(b1), bstatus(b2)), ("completed", "completed"))
    eq((pstatus(b1), pstatus(b2)), ("simulated_paid", "pending"), "payments left in their honest state")
    fail(bk(p2, "simulate_payment", b2), code="INVALID_STATE", what="cannot pay after completion (documented)")
    eq(owner(f"select status from public.rides where id='{rd}';").val, "completed")
    fail(sql(f"select id from public.complete_ride('{rd}')", d), code="INVALID_STATE")
    fail(sql(f"select id from public.start_ride('{rd}')", d), code="INVALID_STATE")


@test("ride lifecycle: start_ride window - 30 minutes before to 12 hours after departure")
def t_start_window():
    d, p = user(), user()

    def set_departure(rd, expr):
        # trigger-free time travel, so window boundaries can be placed precisely
        ok(admin(f"set session_replication_role = replica; update public.rides set departure_time = {expr} where id='{rd}';"))

    # too early: departure 24 hours away -> rejected, and nothing else changes
    rd = ride(d, cap=2)
    b = new_booking(rd, p)
    fail(sql(f"select id from public.start_ride('{rd}')", d), code="RIDE_NOT_AVAILABLE", what="more than 30 minutes before departure")
    eq(owner(f"select status from public.rides where id='{rd}';").val, "scheduled")
    eq(bstatus(b), "pending", "a rejected start must not modify bookings")

    # earliest boundary, inclusive: departure exactly now()+30 min at fixture
    # time; the RPC's clock is only milliseconds later, so it is inside
    rd = ride(d, cap=2)
    set_departure(rd, "now() + interval '30 minutes'")
    ok(sql(f"select id from public.start_ride('{rd}')", d))
    eq(owner(f"select status from public.rides where id='{rd}';").val, "in_progress")

    # 10 s outside the earliest boundary -> still rejected (test round trips
    # take milliseconds, far below the 10 s margin)
    rd = ride(d, cap=2)
    set_departure(rd, "now() + interval '30 minutes 10 seconds'")
    fail(sql(f"select id from public.start_ride('{rd}')", d), code="RIDE_NOT_AVAILABLE", what="just outside the earliest boundary")
    eq(owner(f"select status from public.rides where id='{rd}';").val, "scheduled")

    # inside the window: 15 minutes before departure -> allowed
    rd2 = ride(d, cap=2, hours=0.25)
    ok(sql(f"select id from public.start_ride('{rd2}')", d))
    eq(owner(f"select status from public.rides where id='{rd2}';").val, "in_progress")

    # latest boundary, inclusive: 10 s inside the 12-hour limit -> allowed
    # (departure exactly now()-12 h cannot be tested reliably: the RPC's
    # clock is already milliseconds past it, so the test brackets it instead)
    rd = ride(d, cap=2)
    set_departure(rd, "now() - interval '11 hours 59 minutes 50 seconds'")
    ok(sql(f"select id from public.start_ride('{rd}')", d))
    eq(owner(f"select status from public.rides where id='{rd}';").val, "in_progress")

    # 12 hours + 10 s after departure -> rejected, with no side effects:
    # the ride stays scheduled and the confirmed booking keeps its payment
    rd = ride(d, cap=2)
    b = new_booking(rd, p)
    ok(bk(d, "approve_booking", b))
    set_departure(rd, "now() - interval '12 hours 10 seconds'")
    fail(sql(f"select id from public.start_ride('{rd}')", d), code="RIDE_NOT_AVAILABLE", what="more than 12 hours after departure")
    eq(owner(f"select status from public.rides where id='{rd}';").val, "scheduled", "a rejected start must not modify the ride")
    eq(bstatus(b), "confirmed", "a rejected start must not modify bookings")
    eq(pstatus(b), "pending", "a rejected start must not modify payments")


@test("cancel_ride: cancels every active booking, refunds paid + pending payments, frees the seats")
def t_cancel_ride():
    d, p1, p2, p3 = user(), user(), user(), user()
    rd = ride(d, cap=4)
    b1, b2, b3 = new_booking(rd, p1), new_booking(rd, p2), new_booking(rd, p3)
    ok(bk(d, "approve_booking", b1)); ok(bk(p1, "simulate_payment", b1))
    ok(bk(d, "approve_booking", b2))
    ok(sql(f"select id from public.cancel_ride('{rd}')", d))
    eq((bstatus(b1), bstatus(b2), bstatus(b3)), ("cancelled",) * 3)
    eq((pstatus(b1), pstatus(b2), pstatus(b3)), ("simulated_refunded", "simulated_refunded", None), "no payment for the pending one")
    eq(owner(f"select status from public.rides where id='{rd}';").val, "cancelled")
    eq(avail(rd), (0, 4))
    fail(sql(f"select id from public.cancel_ride('{rd}')", d), code="INVALID_STATE")


@test("history: deleting a driver/passenger/vehicle through the API is impossible; vehicle with rides can't be deleted by owner")
def t_history():
    d = user()
    v = vehicle(d)
    ride(d, v)
    fail(sql(f"delete from public.vehicles where id='{v}'", d), "23503", what="vehicle referenced by a ride (RESTRICT)")


# ================================================================ CONCURRENCY
def race(workers, timeout=60):
    """workers: list of (uid, body_sql, role). Runs all bodies as simultaneously as possible
    (they all block on an advisory-lock gate, which is then released at once). Returns [R]."""
    gate = random.randint(10**6, 10**9)
    holder = subprocess.Popen(_cmd(OWNER), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    holder.stdin.write(f"select pg_advisory_lock({gate});\n")
    holder.stdin.flush()
    holder.stdout.readline()  # lock acquired
    procs = []
    for uid, body, role in workers:
        script = (f"\\set VERBOSITY verbose\nselect pg_advisory_lock_shared({gate});\n" + preamble(uid, role)
                  + body.rstrip().rstrip(";") + ";\ncommit;\n")
        p = subprocess.Popen(_cmd(OWNER), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p.stdin.write(script)
        p.stdin.close()
        procs.append(p)
    deadline = time.time() + 20
    while time.time() < deadline:
        n = psql("select count(*) from pg_locks where locktype='advisory' and not granted;").val
        if n and int(n) >= len(workers):
            break
        time.sleep(0.02)
    holder.stdin.write(f"select pg_advisory_unlock({gate});\n")
    holder.stdin.close()
    out = []
    for p in procs:
        so = p.stdout.read()
        se = p.stderr.read()
        p.wait(timeout=timeout)
        out.append(R(p.returncode, so, se))
    holder.wait(timeout=10)
    return out


def held_live(ride_id):
    return int(owner(f"select coalesce(sum(seats_requested),0) from public.bookings where ride_id='{ride_id}' "
                     f"and (status='confirmed' or (status='pending' and expires_at > now()));").val)


def codes(results):
    return sorted((r.code or r.sqlstate or "OK") for r in results)


@test("RACE: N passengers, last seat(s) - exactly `capacity` succeed, never more")
def t_race_last_seat():
    d = user()
    for rnd in range(ROUNDS):
        cap = random.choice([1, 1, 2, 3])
        n = 10
        rd = ride(d, cap=cap)
        ps = [user() for _ in range(n)]
        res = race([(p, f"select id from public.request_booking('{rd}', 1, '{PHONE}')", "authenticated") for p in ps])
        c = codes(res)
        eq(c.count("OK"), cap, f"round {rnd}: successes (cap {cap}) {c}")
        eq(c.count("NOT_ENOUGH_SEATS"), n - cap, f"round {rnd}: the rest are refused cleanly {c}")
        eq(held_live(rd), cap, "held seats == capacity")


@test("RACE: mixed seat counts never exceed capacity")
def t_race_mixed():
    d = user()
    for rnd in range(ROUNDS):
        cap = 4
        rd = ride(d, cap=cap)
        sizes = [random.choice([1, 2, 3, 4]) for _ in range(8)]
        ps = [user() for _ in sizes]
        res = race([(p, f"select id from public.request_booking('{rd}', {s}, '{PHONE}')", "authenticated") for p, s in zip(ps, sizes)])
        bad = [r for r in res if not r.ok and r.code != "NOT_ENOUGH_SEATS"]
        assert not bad, f"unexpected errors: {bad}"
        assert held_live(rd) <= cap, f"OVERBOOKED: {held_live(rd)} > {cap}"
        assert held_live(rd) >= 1


@test("RACE: double approve - exactly one wins, exactly one payment")
def t_race_double_approve():
    d, p = user(), user()
    for rnd in range(ROUNDS):
        rd = ride(d, cap=2)
        b = new_booking(rd, p)
        res = race([(d, f"select id from public.approve_booking('{b}')", "authenticated") for _ in range(6)])
        c = codes(res)
        eq(c.count("OK"), 1, f"round {rnd}: {c}")
        eq(c.count("INVALID_STATE"), 5, f"round {rnd}: {c}")
        eq(owner(f"select count(*) from public.payments where booking_id='{b}';").val, "1")


@test("RACE: approve vs cancel on the same booking always ends in a consistent state")
def t_race_approve_cancel():
    d, p = user(), user()
    seen = set()
    for rnd in range(ROUNDS * 2):
        rd = ride(d, cap=2)
        b = new_booking(rd, p)
        res = race([(d, f"select id from public.approve_booking('{b}')", "authenticated"),
                    (p, f"select id from public.cancel_booking('{b}')", "authenticated")])
        bad = [r for r in res if not r.ok and r.code not in ("INVALID_STATE",)]
        assert not bad, f"unexpected: {bad}"
        state = (bstatus(b), pstatus(b) or None)
        seen.add(state)
        assert state in {("cancelled", None), ("cancelled", "simulated_refunded"), ("confirmed", "pending")}, f"inconsistent: {state}"
    print(f"      (final states seen: {sorted(seen, key=str)})")


@test("RACE: driver cuts capacity while passengers book - never ends up overbooked")
def t_race_capacity_cut():
    d = user()
    for rnd in range(ROUNDS * 2):
        v = vehicle(d, 6)
        rd = ride(d, v, cap=4)
        ps = [user() for _ in range(5)]
        workers = [(p, f"select id from public.request_booking('{rd}', 1, '{PHONE}')", "authenticated") for p in ps]
        workers.append((d, f"update public.rides set passenger_capacity = 1 where id='{rd}'", "authenticated"))
        res = race(workers)
        bad = [r for r in res if not r.ok and r.code not in ("NOT_ENOUGH_SEATS", "CONFLICT")]
        assert not bad, f"unexpected: {bad}"
        cap = int(owner(f"select passenger_capacity from public.rides where id='{rd}';").val)
        assert held_live(rd) <= cap, f"OVERBOOKED after capacity cut: held {held_live(rd)} > capacity {cap}"


@test("RACE: one passenger firing 6 requests at 6 rides at once - exactly 3 pending (cap), no more")
def t_race_pending_cap():
    d = user()
    for rnd in range(ROUNDS):
        p = user()  # fresh passenger each round (pending requests stay live for 3 minutes)
        rides = [ride(d, cap=2) for _ in range(6)]
        res = race([(p, f"select id from public.request_booking('{r}', 1, '{PHONE}')", "authenticated") for r in rides])
        c = codes(res)
        eq((c.count("OK"), c.count("PENDING_LIMIT")), (3, 3), f"round {rnd}: {c}")


@test("FUZZ: random concurrent operations - invariants hold, no deadlocks, no unexpected errors")
def t_fuzz():
    drivers = [user() for _ in range(2)]
    passengers = [user() for _ in range(6)]
    rides_ = []
    for dr in drivers:
        for _ in range(2):
            # mix of rides inside and outside the 30-minute start window so start/complete
            # ops exercise both outcomes without producing unexpected errors
            rides_.append((ride(dr, vehicle(dr, 6), cap=random.choice([2, 3, 4]),
                                hours=random.choice([0.25, 24])), dr))
    bookings = []  # (booking_id, ride_id, passenger, driver)
    lock = threading.Lock()
    unexpected = []
    expected_codes = {"NOT_AUTHORIZED", "NOT_FOUND", "VALIDATION_ERROR", "RIDE_NOT_AVAILABLE", "DUPLICATE_BOOKING",
                      "NOT_ENOUGH_SEATS", "INVALID_STATE", "INVALID_TRANSITION", "CONFLICT", "REQUEST_EXPIRED",
                      "COOLDOWN", "PENDING_LIMIT"}

    def judge(res, label):
        if res.ok:
            return
        if res.sqlstate == "P0001" and res.code in expected_codes:
            return
        unexpected.append((label, res.sqlstate, res.msg))

    def op(_):
        rd, dr = random.choice(rides_)
        p = random.choice(passengers)
        kind = random.choices(
            ["request", "approve", "reject", "cancel_p", "cancel_d", "pay", "start", "cancel_ride", "complete", "cap", "expire"],
            weights=[30, 14, 8, 8, 4, 8, 3, 2, 3, 5, 6])[0]
        if kind == "request":
            r = req(p, rd, random.choice([1, 1, 2]))
            judge(r, kind)
            if r.ok:
                with lock:
                    bookings.append((r.rows[0][0], rd, p, dr))
            return
        with lock:
            b = random.choice(bookings) if bookings else None
        if kind in ("approve", "reject", "cancel_d") and b:
            fn = {"approve": "approve_booking", "reject": "reject_booking", "cancel_d": "cancel_booking"}[kind]
            judge(bk(b[3], fn, b[0]), kind)
        elif kind == "cancel_p" and b:
            judge(bk(b[2], "cancel_booking", b[0]), kind)
        elif kind == "pay" and b:
            judge(bk(b[2], "simulate_payment", b[0]), kind)
        elif kind in ("start", "cancel_ride", "complete"):
            fn = {"start": "start_ride", "cancel_ride": "cancel_ride", "complete": "complete_ride"}[kind]
            judge(sql(f"select id from public.{fn}('{rd}')", dr), kind)
        elif kind == "cap":
            judge(sql(f"update public.rides set passenger_capacity = {random.choice([1, 2, 3, 4])} where id='{rd}'", dr), kind)
        elif kind == "expire" and b:
            owner(f"update public.bookings set expires_at = now() - interval '1 minute' where id='{b[0]}' and status='pending';")

    n_ops = 150 * max(1, ROUNDS // 6)
    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(op, range(n_ops)))
    assert not unexpected, f"{len(unexpected)} unexpected errors, e.g. {unexpected[:3]}"
    # ---- invariants
    for rd, _ in rides_:
        cap = int(owner(f"select passenger_capacity from public.rides where id='{rd}';").val)
        assert held_live(rd) <= cap, f"OVERBOOKED ride {rd}: {held_live(rd)} > {cap}"
    q = lambda s: owner(s).rows
    assert not q("select 1 from public.bookings b join public.rides r on r.id=b.ride_id where r.status in ('cancelled','completed') and b.status in ('pending','confirmed')"), \
        "terminal ride still has active bookings"
    assert not q("select 1 from public.bookings b join public.rides r on r.id=b.ride_id where r.status='in_progress' and b.status='pending'"), \
        "in-progress ride still has pending requests"
    assert not q("select 1 from public.bookings b where status='confirmed' and not exists (select 1 from public.payments p where p.booking_id=b.id)"), \
        "confirmed booking without a payment"
    assert not q("select 1 from public.payments p join public.bookings b on b.id=p.booking_id where b.status in ('pending','rejected','expired')"), \
        "payment exists for a booking that was never confirmed"
    assert not q("select 1 from public.payments p join public.bookings b on b.id=p.booking_id where b.status='cancelled' and p.status <> 'simulated_refunded'"), \
        "cancelled booking whose payment was not refunded"
    done = owner("select count(*) from public.bookings;").val
    print(f"      ({n_ops} random ops, {done} bookings created, 0 deadlocks / unexpected errors)")


# ================================================================ main
def main():
    global DB, ROUNDS
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    DB = args[0]
    flt = None
    if "-k" in args:
        flt = args[args.index("-k") + 1]
    if "--rounds" in args:
        ROUNDS = int(args[args.index("--rounds") + 1])
    passed, failed = 0, []
    t0 = time.time()
    for name, fn in TESTS:
        if flt and flt.lower() not in name.lower():
            continue
        t = time.time()
        try:
            fn()
            passed += 1
            print(f"PASS  {name}  ({time.time() - t:.1f}s)")
        except AssertionError as e:
            failed.append((name, str(e)))
            print(f"FAIL  {name}\n      -> {e}")
        except Exception as e:  # harness/setup error
            failed.append((name, f"{type(e).__name__}: {e}"))
            print(f"ERROR {name}\n      -> {type(e).__name__}: {e}")
    print(f"\n{passed} passed, {len(failed)} failed  ({time.time() - t0:.0f}s)  db={DB}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
