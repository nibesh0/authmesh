#!/usr/bin/env bash
# Clears rate-limit counters and lockouts in the local Redis.
#
# Useful when running the smoke test repeatedly: the limiter is doing its job, but
# on a laptop every request shares one source address, so the per-IP budgets drain
# after a couple of runs. Sessions are left alone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PREFIX="${REDIS_KEY_PREFIX:-am}"

# KEYS scans the whole keyspace, which is fine for a development database and
# keeps this a single atomic call instead of a shell pipeline.
LUA='local n = 0
for _, key in ipairs(redis.call("KEYS", ARGV[1])) do
  redis.call("DEL", key)
  n = n + 1
end
return n'

for pattern in rl fail lock; do
  deleted="$(docker compose exec -T redis \
    redis-cli --no-raw EVAL "$LUA" 0 "${PREFIX}:${pattern}:*")"
  echo "${PREFIX}:${pattern}:* -> ${deleted}"
done
