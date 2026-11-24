local attemptKey = KEYS[1]
local consumedKey = KEYS[2]
local maxAttempts = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

if redis.call("EXISTS", consumedKey) == 1 then
  return {0, 0, 1}
end

local count = redis.call("INCR", attemptKey)
if count == 1 then
  redis.call("EXPIRE", attemptKey, ttl)
end

if count >= maxAttempts then
  redis.call("SET", consumedKey, "1", "EX", ttl)
end

if count > maxAttempts then
  return {0, 0, 0}
end

local remaining = maxAttempts - count
return {1, remaining, 0}
