"""Redis-backed security state: sessions, refresh-token rotation, revocation,
rate limiting, lockout and single-use MFA challenges.

Why Redis rather than Mongo for all of this: every item here is short-lived and
read on the hot path of `Introspect`/`Refresh`, and every item wants a TTL. Redis
gives expiry for free (no sweeper job) and the multi-step state changes are done
in Lua so they are atomic without a transaction round trip.

Failure policy differs per concern and is deliberate:
  * session/token state - fail closed. If Redis is unreachable we cannot prove a
    token has not been revoked, so the request is rejected with UNAVAILABLE.
  * rate limiting/lockout - fail open. A Redis outage should not lock every user
    out of the product; the event is logged and counted so it is visible.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import redis.asyncio as redis
from redis.exceptions import RedisError

from authmesh_common.errors import AppError, ErrorCode
from authmesh_common.logging import get_logger

from . import authmetrics
from .settings import AuthServiceSettings

log = get_logger(__name__)


# --- Lua ------------------------------------------------------------------

# Sliding-window limiter. A fixed-window counter would let a caller send 2x the
# limit across a window boundary; the sorted set holds one entry per request and
# is trimmed to the window on each call, so the limit holds at any instant.
_RATE_LIMIT_LUA = """
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local retry = math.ceil(window / 1000)
  if oldest[2] then
    retry = math.ceil((tonumber(oldest[2]) + window - now) / 1000)
  end
  if retry < 1 then retry = 1 end
  return {0, count, retry}
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], window)
return {1, count + 1, 0}
"""

# Failed-login accounting plus lockout, in one atomic step so concurrent
# attempts cannot race past the threshold.
_LOCKOUT_LUA = """
local locked_ttl = redis.call('TTL', KEYS[2])
if locked_ttl > 0 then
  return {1, locked_ttl, 0}
end
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
if count >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'EX', tonumber(ARGV[3]))
  redis.call('DEL', KEYS[1])
  return {1, tonumber(ARGV[3]), count}
end
return {0, 0, count}
"""

# Refresh-token rotation.
#
# The old token id is deleted and simultaneously remembered in a `used` marker.
# A second presentation of the same refresh token therefore finds no live entry
# but does find the marker, which is the signal that the token leaked: the
# response tells the caller to burn the session. This is the standard detection
# for stolen refresh tokens, and doing it in Lua means two concurrent refreshes
# cannot both succeed.
_ROTATE_LUA = """
local sid = redis.call('GET', KEYS[1])
if not sid then
  if redis.call('EXISTS', KEYS[2]) == 1 then
    return {'reused', redis.call('GET', KEYS[2]), '0'}
  end
  return {'unknown', '', '0'}
end
if sid ~= ARGV[4] then
  return {'mismatch', sid, '0'}
end
if redis.call('EXISTS', KEYS[4]) == 0 then
  return {'no_session', sid, '0'}
end
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local absolute = tonumber(redis.call('HGET', KEYS[4], 'absolute_expires_at') or '0')
if absolute > 0 then
  if now >= absolute then
    return {'absolute_expired', sid, '0'}
  end
  if now + ttl > absolute then
    ttl = absolute - now
  end
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], sid, 'EX', ttl)
redis.call('SET', KEYS[3], sid, 'EX', ttl)
redis.call('HSET', KEYS[4], 'current_rt_jti', ARGV[3], 'last_used_at', ARGV[1],
           'expires_at', now + ttl)
redis.call('EXPIRE', KEYS[4], ttl)
redis.call('ZREMRANGEBYSCORE', KEYS[5], 0, now)
redis.call('ZADD', KEYS[5], now + ttl, sid)
redis.call('EXPIRE', KEYS[5], tonumber(ARGV[5]), 'GT')
return {'ok', sid, tostring(ttl)}
"""


class RotationOutcome:
    OK = "ok"
    REUSED = "reused"
    UNKNOWN = "unknown"
    MISMATCH = "mismatch"
    NO_SESSION = "no_session"
    ABSOLUTE_EXPIRED = "absolute_expired"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    current: int
    retry_after_seconds: int


@dataclass(frozen=True)
class LockoutResult:
    locked: bool
    retry_after_seconds: int
    failed_attempts: int


@dataclass(frozen=True)
class RotationResult:
    outcome: str
    session_id: str
    ttl_seconds: int


@dataclass
class SessionRecord:
    id: str
    user_id: str
    created_at: int
    last_used_at: int
    expires_at: int
    absolute_expires_at: int
    ip: str
    user_agent: str
    family: str
    current_rt_jti: str

    @classmethod
    def from_hash(cls, session_id: str, data: dict[str, str]) -> "SessionRecord":
        return cls(
            id=session_id,
            user_id=data.get("user_id", ""),
            created_at=int(float(data.get("created_at", 0) or 0)),
            last_used_at=int(float(data.get("last_used_at", 0) or 0)),
            expires_at=int(float(data.get("expires_at", 0) or 0)),
            absolute_expires_at=int(float(data.get("absolute_expires_at", 0) or 0)),
            ip=data.get("ip", ""),
            user_agent=data.get("user_agent", ""),
            family=data.get("family", ""),
            current_rt_jti=data.get("current_rt_jti", ""),
        )


class SecurityStore:
    def __init__(self, settings: AuthServiceSettings) -> None:
        self._settings = settings
        self._redis: redis.Redis | None = None
        self._rate_limit_script: Any = None
        self._lockout_script: Any = None
        self._rotate_script: Any = None

    # -- lifecycle ---------------------------------------------------------

    async def connect(self) -> None:
        settings = self._settings
        self._redis = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_timeout=settings.redis_socket_timeout_seconds,
            socket_connect_timeout=settings.redis_connect_timeout_seconds,
            max_connections=settings.redis_max_connections,
            health_check_interval=30,
            client_name=settings.service_name,
        )
        self._rate_limit_script = self._redis.register_script(_RATE_LIMIT_LUA)
        self._lockout_script = self._redis.register_script(_LOCKOUT_LUA)
        self._rotate_script = self._redis.register_script(_ROTATE_LUA)
        log.info("redis client created")

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def ping(self) -> bool:
        if self._redis is None:
            return False
        try:
            return bool(await self._redis.ping())
        except RedisError as exc:
            log.warning("redis ping failed", extra={"reason": str(exc)})
            return False

    @property
    def client(self) -> redis.Redis:
        if self._redis is None:
            raise AppError(ErrorCode.UNAVAILABLE, "session store is not connected")
        return self._redis

    # -- keys --------------------------------------------------------------

    def _key(self, *parts: str) -> str:
        return ":".join((self._settings.redis_key_prefix, *parts))

    def _session_key(self, session_id: str) -> str:
        return self._key("sess", session_id)

    def _user_sessions_key(self, user_id: str) -> str:
        return self._key("usess", user_id)

    def _refresh_key(self, jti: str) -> str:
        return self._key("rt", jti)

    def _refresh_used_key(self, jti: str) -> str:
        return self._key("rtused", jti)

    def _denylist_key(self, jti: str) -> str:
        return self._key("bl", jti)

    def _mfa_key(self, jti: str) -> str:
        return self._key("mfa", jti)

    def _failed_key(self, user_id: str) -> str:
        return self._key("fail", user_id)

    def _lock_key(self, user_id: str) -> str:
        return self._key("lock", user_id)

    def _rate_key(self, scope: str, identifier: str) -> str:
        return self._key("rl", scope, identifier)

    @staticmethod
    def _fail_closed(exc: RedisError) -> AppError:
        log.error("redis operation failed", extra={"reason": str(exc)})
        authmetrics.STORE_ERRORS.labels(operation="session").inc()
        return AppError(ErrorCode.UNAVAILABLE, "session store is unavailable")

    # -- sessions ----------------------------------------------------------

    async def create_session(
        self,
        *,
        session_id: str,
        user_id: str,
        family: str,
        refresh_jti: str,
        ip: str,
        user_agent: str,
        ttl_seconds: int,
    ) -> None:
        now = int(time.time())
        absolute_expires_at = now + self._settings.session_absolute_ttl_seconds
        session_key = self._session_key(session_id)
        user_key = self._user_sessions_key(user_id)

        try:
            async with self.client.pipeline(transaction=True) as pipe:
                pipe.hset(
                    session_key,
                    mapping={
                        "user_id": user_id,
                        "created_at": now,
                        "last_used_at": now,
                        "expires_at": now + ttl_seconds,
                        "absolute_expires_at": absolute_expires_at,
                        "ip": ip,
                        "user_agent": user_agent[:512],
                        "family": family,
                        "current_rt_jti": refresh_jti,
                    },
                )
                pipe.expire(session_key, ttl_seconds)
                pipe.set(self._refresh_key(refresh_jti), session_id, ex=ttl_seconds)
                pipe.zremrangebyscore(user_key, 0, now)
                pipe.zadd(user_key, {session_id: now + ttl_seconds})
                pipe.expire(user_key, self._settings.session_absolute_ttl_seconds)
                await pipe.execute()
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

        await self._enforce_session_cap(user_id)

    async def _enforce_session_cap(self, user_id: str) -> None:
        """Keep only the newest N sessions so a compromised credential cannot be
        used to accumulate an unbounded number of long-lived footholds."""
        cap = self._settings.max_sessions_per_user
        if cap <= 0:
            return
        user_key = self._user_sessions_key(user_id)
        try:
            total = await self.client.zcard(user_key)
            if total <= cap:
                return
            # Sorted by expiry ascending; the oldest-expiring are the stalest.
            excess = await self.client.zrange(user_key, 0, total - cap - 1)
            if not excess:
                return
            async with self.client.pipeline(transaction=True) as pipe:
                for session_id in excess:
                    pipe.delete(self._session_key(session_id))
                pipe.zrem(user_key, *excess)
                await pipe.execute()
            log.info(
                "evicted sessions over cap",
                extra={"evicted": len(excess), "cap": cap},
            )
            authmetrics.SESSIONS_REVOKED.labels(reason="session_cap").inc(len(excess))
        except RedisError as exc:
            # Not fatal: the new session is already usable.
            log.warning("session cap enforcement failed", extra={"reason": str(exc)})

    async def session_exists(self, session_id: str) -> bool:
        try:
            return bool(await self.client.exists(self._session_key(session_id)))
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

    async def get_session(self, session_id: str) -> SessionRecord | None:
        try:
            data = await self.client.hgetall(self._session_key(session_id))
        except RedisError as exc:
            raise self._fail_closed(exc) from exc
        if not data:
            return None
        return SessionRecord.from_hash(session_id, data)

    async def touch_session(self, session_id: str) -> None:
        try:
            await self.client.hset(
                self._session_key(session_id), "last_used_at", int(time.time())
            )
        except RedisError as exc:
            log.warning("failed to touch session", extra={"reason": str(exc)})

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        user_key = self._user_sessions_key(user_id)
        now = int(time.time())
        try:
            session_ids = await self.client.zrangebyscore(user_key, now, "+inf")
            if not session_ids:
                return []
            async with self.client.pipeline(transaction=False) as pipe:
                for session_id in session_ids:
                    pipe.hgetall(self._session_key(session_id))
                results = await pipe.execute()
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

        sessions: list[SessionRecord] = []
        stale: list[str] = []
        for session_id, data in zip(session_ids, results):
            if data:
                sessions.append(SessionRecord.from_hash(session_id, data))
            else:
                stale.append(session_id)

        if stale:
            # The session hash expired or was revoked; drop the index entry.
            try:
                await self.client.zrem(user_key, *stale)
            except RedisError:
                pass

        sessions.sort(key=lambda item: item.created_at, reverse=True)
        return sessions

    async def revoke_session(self, session_id: str, *, user_id: str | None = None) -> bool:
        """Delete a session. Access tokens carrying this `sid` stop validating
        immediately because Introspect requires the session to exist."""
        try:
            session = await self.get_session(session_id)
            owner = user_id or (session.user_id if session else None)
            async with self.client.pipeline(transaction=True) as pipe:
                pipe.delete(self._session_key(session_id))
                if session is not None and session.current_rt_jti:
                    pipe.delete(self._refresh_key(session.current_rt_jti))
                if owner:
                    pipe.zrem(self._user_sessions_key(owner), session_id)
                results = await pipe.execute()
        except RedisError as exc:
            raise self._fail_closed(exc) from exc
        return bool(results and results[0])

    async def revoke_all_sessions(
        self, user_id: str, *, except_session_id: str | None = None
    ) -> int:
        user_key = self._user_sessions_key(user_id)
        try:
            session_ids = await self.client.zrange(user_key, 0, -1)
            targets = [sid for sid in session_ids if sid != except_session_id]
            if not targets:
                return 0
            async with self.client.pipeline(transaction=True) as pipe:
                for session_id in targets:
                    pipe.delete(self._session_key(session_id))
                pipe.zrem(user_key, *targets)
                await pipe.execute()
        except RedisError as exc:
            raise self._fail_closed(exc) from exc
        return len(targets)

    # -- refresh rotation --------------------------------------------------

    async def rotate_refresh_token(
        self,
        *,
        old_jti: str,
        new_jti: str,
        session_id: str,
        user_id: str,
        ttl_seconds: int,
    ) -> RotationResult:
        now = int(time.time())
        try:
            raw = await self._rotate_script(
                keys=[
                    self._refresh_key(old_jti),
                    self._refresh_used_key(old_jti),
                    self._refresh_key(new_jti),
                    self._session_key(session_id),
                    self._user_sessions_key(user_id),
                ],
                args=[
                    now,
                    ttl_seconds,
                    new_jti,
                    session_id,
                    self._settings.session_absolute_ttl_seconds,
                ],
            )
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

        outcome = raw[0] if isinstance(raw[0], str) else raw[0].decode()
        returned_sid = raw[1] if isinstance(raw[1], str) else raw[1].decode()
        ttl_value = raw[2] if isinstance(raw[2], str) else raw[2].decode()
        return RotationResult(
            outcome=outcome,
            session_id=returned_sid,
            ttl_seconds=int(ttl_value or 0),
        )

    # -- access token denylist --------------------------------------------

    async def denylist_access_token(self, jti: str, ttl_seconds: int) -> None:
        """Revoke one access token without killing its session (used by Logout
        so the caller's current access token dies with the refresh token)."""
        if ttl_seconds <= 0:
            return
        try:
            await self.client.set(self._denylist_key(jti), "1", ex=ttl_seconds)
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

    async def is_access_token_denylisted(self, jti: str) -> bool:
        try:
            return bool(await self.client.exists(self._denylist_key(jti)))
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

    # -- MFA challenges ----------------------------------------------------

    async def store_mfa_challenge(self, jti: str, user_id: str, ttl_seconds: int) -> None:
        try:
            await self.client.set(self._mfa_key(jti), user_id, ex=ttl_seconds)
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

    async def peek_mfa_challenge(self, jti: str) -> str | None:
        """Read a challenge without consuming it, so a mistyped code does not
        force the user back through the password step."""
        try:
            return await self.client.get(self._mfa_key(jti))
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

    async def consume_mfa_challenge(self, jti: str) -> str | None:
        """Atomically fetch-and-delete so a challenge token works exactly once."""
        try:
            return await self.client.getdel(self._mfa_key(jti))
        except RedisError as exc:
            raise self._fail_closed(exc) from exc

    # -- rate limiting -----------------------------------------------------

    async def check_rate_limit(
        self, scope: str, identifier: str, *, limit: int, window_seconds: int
    ) -> RateLimitResult:
        if not self._settings.rate_limit_enabled or limit <= 0:
            return RateLimitResult(True, 0, 0)

        now_ms = int(time.time() * 1000)
        # The member must be unique per call. Deriving it from the timestamp alone
        # would make two requests in the same millisecond collide, and ZADD would
        # update the existing member's score instead of adding a second entry, so
        # a burst would be undercounted exactly when the limiter matters most.
        member = f"{now_ms}-{uuid.uuid4().hex}"
        try:
            allowed, current, retry_after = await self._rate_limit_script(
                keys=[self._rate_key(scope, identifier)],
                args=[now_ms, window_seconds * 1000, limit, member],
            )
        except RedisError as exc:
            # Fail open: availability of login beats perfect throttling.
            log.error(
                "rate limiter unavailable; allowing request",
                extra={"scope": scope, "reason": str(exc)},
            )
            authmetrics.STORE_ERRORS.labels(operation="rate_limit").inc()
            return RateLimitResult(True, 0, 0)

        result = RateLimitResult(bool(int(allowed)), int(current), int(retry_after))
        if not result.allowed:
            authmetrics.RATE_LIMIT_BLOCKS.labels(scope=scope).inc()
        return result

    # -- lockout -----------------------------------------------------------

    async def register_failed_attempt(self, user_id: str) -> LockoutResult:
        if not self._settings.lockout_enabled:
            return LockoutResult(False, 0, 0)
        try:
            locked, retry_after, count = await self._lockout_script(
                keys=[self._failed_key(user_id), self._lock_key(user_id)],
                args=[
                    self._settings.lockout_window_seconds,
                    self._settings.lockout_threshold,
                    self._settings.lockout_duration_seconds,
                ],
            )
        except RedisError as exc:
            log.error("lockout accounting failed", extra={"reason": str(exc)})
            authmetrics.STORE_ERRORS.labels(operation="lockout").inc()
            return LockoutResult(False, 0, 0)

        result = LockoutResult(bool(int(locked)), int(retry_after), int(count))
        if result.locked and result.failed_attempts:
            authmetrics.ACCOUNT_LOCKOUTS.inc()
        return result

    async def get_lockout(self, user_id: str) -> LockoutResult:
        if not self._settings.lockout_enabled:
            return LockoutResult(False, 0, 0)
        try:
            async with self.client.pipeline(transaction=False) as pipe:
                pipe.ttl(self._lock_key(user_id))
                pipe.get(self._failed_key(user_id))
                ttl, failures = await pipe.execute()
        except RedisError as exc:
            log.error("lockout lookup failed", extra={"reason": str(exc)})
            return LockoutResult(False, 0, 0)
        ttl = int(ttl or -2)
        return LockoutResult(ttl > 0, max(ttl, 0), int(failures or 0))

    async def clear_failed_attempts(self, user_id: str) -> None:
        try:
            await self.client.delete(self._failed_key(user_id), self._lock_key(user_id))
        except RedisError as exc:
            log.warning("failed to clear lockout counters", extra={"reason": str(exc)})
