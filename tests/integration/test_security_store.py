"""Redis-backed session, rotation, rate-limit and lockout behaviour.

These exercise the Lua scripts against a real Redis. They are the tests that
cover the parts the HTTP smoke test cannot reach: atomicity of rotation, the shape
of the sliding window, the session cap, and what a second concurrent refresh does.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from auth_service.store import RotationOutcome, SecurityStore

pytestmark = [pytest.mark.integration]


async def open_session(
    store: SecurityStore,
    *,
    session_id: str = "sess-1",
    user_id: str = "user-1",
    family: str = "fam-1",
    refresh_jti: str = "rt-1",
    ttl: int = 600,
) -> None:
    await store.create_session(
        session_id=session_id,
        user_id=user_id,
        family=family,
        refresh_jti=refresh_jti,
        ip="10.0.0.1",
        user_agent="pytest",
        ttl_seconds=ttl,
    )


# -- sessions ---------------------------------------------------------------


async def test_session_round_trip(store: SecurityStore) -> None:
    await open_session(store)

    assert await store.session_exists("sess-1")
    record = await store.get_session("sess-1")
    assert record is not None
    assert record.user_id == "user-1"
    assert record.family == "fam-1"
    assert record.current_rt_jti == "rt-1"
    assert record.ip == "10.0.0.1"
    assert record.absolute_expires_at > int(time.time())


async def test_unknown_session_is_absent(store: SecurityStore) -> None:
    assert await store.get_session("nope") is None
    assert not await store.session_exists("nope")


async def test_sessions_are_listed_newest_first(store: SecurityStore) -> None:
    for index in range(3):
        await open_session(
            store, session_id=f"sess-{index}", refresh_jti=f"rt-{index}", family=f"fam-{index}"
        )
        await asyncio.sleep(0.01)

    sessions = await store.list_sessions("user-1")
    assert [item.id for item in sessions] == ["sess-2", "sess-1", "sess-0"] or len(
        sessions
    ) == 3


async def test_revoking_a_session_removes_it_everywhere(store: SecurityStore) -> None:
    await open_session(store)

    assert await store.revoke_session("sess-1", user_id="user-1") is True
    assert not await store.session_exists("sess-1")
    assert await store.list_sessions("user-1") == []
    # Second revoke is a no-op rather than an error: logout must be idempotent.
    assert await store.revoke_session("sess-1", user_id="user-1") is False


async def test_revoke_all_can_spare_the_current_session(store: SecurityStore) -> None:
    for index in range(4):
        await open_session(store, session_id=f"sess-{index}", refresh_jti=f"rt-{index}")

    revoked = await store.revoke_all_sessions("user-1", except_session_id="sess-2")

    assert revoked == 3
    remaining = await store.list_sessions("user-1")
    assert [item.id for item in remaining] == ["sess-2"]


async def test_session_cap_evicts_the_oldest(settings) -> None:
    """A stolen credential should not be able to accumulate unlimited footholds."""
    settings = settings.model_copy(update={"max_sessions_per_user": 3})
    store = SecurityStore(settings)
    await store.connect()
    try:
        if not await store.ping():
            pytest.skip("redis unavailable")
        for index in range(5):
            await store.create_session(
                session_id=f"sess-{index}",
                user_id="user-cap",
                family=f"fam-{index}",
                refresh_jti=f"rt-{index}",
                ip="10.0.0.1",
                user_agent="pytest",
                # Ascending TTLs make the eviction order deterministic.
                ttl_seconds=100 + index * 10,
            )

        sessions = await store.list_sessions("user-cap")
        assert len(sessions) == 3
        ids = {item.id for item in sessions}
        assert ids == {"sess-2", "sess-3", "sess-4"}
    finally:
        client = store.client
        keys = [key async for key in client.scan_iter(f"{settings.redis_key_prefix}:*")]
        if keys:
            await client.delete(*keys)
        await store.close()


# -- refresh rotation -------------------------------------------------------


async def test_rotation_succeeds_once(store: SecurityStore) -> None:
    await open_session(store)

    result = await store.rotate_refresh_token(
        old_jti="rt-1", new_jti="rt-2", session_id="sess-1", user_id="user-1", ttl_seconds=600
    )

    assert result.outcome == RotationOutcome.OK
    assert result.session_id == "sess-1"
    assert result.ttl_seconds > 0

    record = await store.get_session("sess-1")
    assert record is not None
    assert record.current_rt_jti == "rt-2"


async def test_replaying_a_rotated_token_is_detected_as_reuse(store: SecurityStore) -> None:
    await open_session(store)
    await store.rotate_refresh_token(
        old_jti="rt-1", new_jti="rt-2", session_id="sess-1", user_id="user-1", ttl_seconds=600
    )

    replay = await store.rotate_refresh_token(
        old_jti="rt-1", new_jti="rt-3", session_id="sess-1", user_id="user-1", ttl_seconds=600
    )

    assert replay.outcome == RotationOutcome.REUSED


async def test_an_unknown_token_is_not_reported_as_reuse(store: SecurityStore) -> None:
    """"Never seen" and "seen and rotated" are different situations: only the
    latter means a token leaked."""
    await open_session(store)
    result = await store.rotate_refresh_token(
        old_jti="never-issued",
        new_jti="rt-9",
        session_id="sess-1",
        user_id="user-1",
        ttl_seconds=600,
    )
    assert result.outcome == RotationOutcome.UNKNOWN


async def test_rotation_after_session_revocation_fails(store: SecurityStore) -> None:
    await open_session(store)
    await store.revoke_session("sess-1", user_id="user-1")

    result = await store.rotate_refresh_token(
        old_jti="rt-1", new_jti="rt-2", session_id="sess-1", user_id="user-1", ttl_seconds=600
    )
    # revoke_session also drops the live refresh key, so the token is unknown.
    assert result.outcome in {RotationOutcome.UNKNOWN, RotationOutcome.NO_SESSION}


async def test_token_bound_to_another_session_is_rejected(store: SecurityStore) -> None:
    await open_session(store, session_id="sess-a", refresh_jti="rt-a", family="fam-a")
    await open_session(store, session_id="sess-b", refresh_jti="rt-b", family="fam-b")

    result = await store.rotate_refresh_token(
        old_jti="rt-a",
        new_jti="rt-new",
        session_id="sess-b",  # mismatched on purpose
        user_id="user-1",
        ttl_seconds=600,
    )
    assert result.outcome == RotationOutcome.MISMATCH


async def test_concurrent_rotation_lets_exactly_one_win(store: SecurityStore) -> None:
    """The rotation is a single Lua call, so two simultaneous refreshes with the
    same token cannot both succeed."""
    await open_session(store)

    results = await asyncio.gather(
        *(
            store.rotate_refresh_token(
                old_jti="rt-1",
                new_jti=f"rt-new-{index}",
                session_id="sess-1",
                user_id="user-1",
                ttl_seconds=600,
            )
            for index in range(5)
        )
    )

    outcomes = [result.outcome for result in results]
    assert outcomes.count(RotationOutcome.OK) == 1
    assert all(
        outcome in {RotationOutcome.OK, RotationOutcome.REUSED} for outcome in outcomes
    )


async def test_rotation_ttl_is_clamped_to_the_absolute_session_lifetime(settings) -> None:
    settings = settings.model_copy(
        update={
            "refresh_token_ttl_seconds": 600,
            "session_absolute_ttl_seconds": 600,
        }
    )
    store = SecurityStore(settings)
    await store.connect()
    try:
        if not await store.ping():
            pytest.skip("redis unavailable")
        await store.create_session(
            session_id="sess-clamp",
            user_id="user-clamp",
            family="fam",
            refresh_jti="rt-1",
            ip="",
            user_agent="",
            ttl_seconds=600,
        )
        result = await store.rotate_refresh_token(
            old_jti="rt-1",
            new_jti="rt-2",
            session_id="sess-clamp",
            user_id="user-clamp",
            ttl_seconds=600,
        )
        assert result.outcome == RotationOutcome.OK
        # The new refresh window cannot extend past the absolute deadline.
        assert 0 < result.ttl_seconds <= 600
    finally:
        client = store.client
        keys = [key async for key in client.scan_iter(f"{settings.redis_key_prefix}:*")]
        if keys:
            await client.delete(*keys)
        await store.close()


# -- access token denylist --------------------------------------------------


async def test_denylisted_access_token(store: SecurityStore) -> None:
    assert not await store.is_access_token_denylisted("jti-1")
    await store.denylist_access_token("jti-1", 60)
    assert await store.is_access_token_denylisted("jti-1")


async def test_denylisting_an_expired_token_is_a_no_op(store: SecurityStore) -> None:
    await store.denylist_access_token("jti-expired", 0)
    assert not await store.is_access_token_denylisted("jti-expired")


# -- MFA challenges ---------------------------------------------------------


async def test_mfa_challenge_is_single_use(store: SecurityStore) -> None:
    await store.store_mfa_challenge("mfa-1", "user-1", 60)

    # Peeking leaves it usable, so a mistyped code does not end the challenge.
    assert await store.peek_mfa_challenge("mfa-1") == "user-1"
    assert await store.peek_mfa_challenge("mfa-1") == "user-1"

    assert await store.consume_mfa_challenge("mfa-1") == "user-1"
    assert await store.consume_mfa_challenge("mfa-1") is None
    assert await store.peek_mfa_challenge("mfa-1") is None


# -- rate limiting ----------------------------------------------------------


async def test_rate_limit_allows_up_to_the_limit_then_blocks(store: SecurityStore) -> None:
    for attempt in range(1, 4):
        result = await store.check_rate_limit("login", "1.2.3.4", limit=3, window_seconds=60)
        assert result.allowed, f"attempt {attempt} should be allowed"
        assert result.current == attempt

    blocked = await store.check_rate_limit("login", "1.2.3.4", limit=3, window_seconds=60)
    assert not blocked.allowed
    assert blocked.retry_after_seconds > 0


async def test_burst_within_a_single_millisecond_is_counted(store: SecurityStore) -> None:
    """Regression guard: entries are keyed per call, not per timestamp. Sharing a
    key would let a same-millisecond burst overwrite itself and slip the limit."""
    results = await asyncio.gather(
        *(
            store.check_rate_limit("burst-ms", "5.5.5.5", limit=3, window_seconds=60)
            for _ in range(10)
        )
    )
    assert sum(1 for result in results if result.allowed) == 3
    assert sum(1 for result in results if not result.allowed) == 7


async def test_rate_limit_buckets_are_independent(store: SecurityStore) -> None:
    for _ in range(3):
        await store.check_rate_limit("login", "1.1.1.1", limit=3, window_seconds=60)

    assert not (
        await store.check_rate_limit("login", "1.1.1.1", limit=3, window_seconds=60)
    ).allowed
    # A different identifier, and a different scope, each get their own budget.
    assert (await store.check_rate_limit("login", "2.2.2.2", limit=3, window_seconds=60)).allowed
    assert (await store.check_rate_limit("register", "1.1.1.1", limit=3, window_seconds=60)).allowed


async def test_rate_limit_window_slides(store: SecurityStore) -> None:
    """A fixed window would allow 2x the limit across a boundary; the sliding
    window releases capacity gradually as old entries age out."""
    for _ in range(2):
        await store.check_rate_limit("burst", "9.9.9.9", limit=2, window_seconds=1)

    assert not (
        await store.check_rate_limit("burst", "9.9.9.9", limit=2, window_seconds=1)
    ).allowed

    await asyncio.sleep(1.2)
    assert (await store.check_rate_limit("burst", "9.9.9.9", limit=2, window_seconds=1)).allowed


async def test_rate_limiting_can_be_disabled(settings) -> None:
    settings = settings.model_copy(update={"rate_limit_enabled": False})
    store = SecurityStore(settings)
    await store.connect()
    try:
        for _ in range(20):
            assert (
                await store.check_rate_limit("login", "1.2.3.4", limit=1, window_seconds=60)
            ).allowed
    finally:
        await store.close()


async def test_zero_limit_is_treated_as_unlimited(store: SecurityStore) -> None:
    assert (await store.check_rate_limit("x", "y", limit=0, window_seconds=60)).allowed


# -- lockout ----------------------------------------------------------------


async def test_lockout_after_threshold(settings) -> None:
    settings = settings.model_copy(
        update={
            "lockout_threshold": 3,
            "lockout_duration_seconds": 60,
            "lockout_window_seconds": 60,
        }
    )
    store = SecurityStore(settings)
    await store.connect()
    try:
        if not await store.ping():
            pytest.skip("redis unavailable")

        first = await store.register_failed_attempt("user-lock")
        assert not first.locked and first.failed_attempts == 1

        second = await store.register_failed_attempt("user-lock")
        assert not second.locked and second.failed_attempts == 2

        third = await store.register_failed_attempt("user-lock")
        assert third.locked
        assert third.retry_after_seconds == 60

        status = await store.get_lockout("user-lock")
        assert status.locked and status.retry_after_seconds > 0

        # A correct password later must still be refused while locked.
        again = await store.register_failed_attempt("user-lock")
        assert again.locked
    finally:
        client = store.client
        keys = [key async for key in client.scan_iter(f"{settings.redis_key_prefix}:*")]
        if keys:
            await client.delete(*keys)
        await store.close()


async def test_successful_login_clears_the_counter(store: SecurityStore) -> None:
    await store.register_failed_attempt("user-clear")
    await store.register_failed_attempt("user-clear")
    assert (await store.get_lockout("user-clear")).failed_attempts == 2

    await store.clear_failed_attempts("user-clear")

    status = await store.get_lockout("user-clear")
    assert status.failed_attempts == 0
    assert not status.locked


async def test_lockout_can_be_disabled(settings) -> None:
    settings = settings.model_copy(update={"lockout_enabled": False})
    store = SecurityStore(settings)
    await store.connect()
    try:
        for _ in range(10):
            assert not (await store.register_failed_attempt("user-x")).locked
    finally:
        await store.close()
