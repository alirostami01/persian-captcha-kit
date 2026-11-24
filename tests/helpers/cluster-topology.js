/**
 * Redis Cluster Topology Helper for Integration Tests
 *
 * Compatibility:
 * - Redis 7.0+: Uses `CLUSTER SHARDS` natively to query shard topology and master node IDs.
 * - Redis 4.0–6.x: Falls back to `CLUSTER SLOTS` when `CLUSTER SHARDS` is unrecognized,
 *   aggregating non-contiguous slot ranges by master node ID.
 * - Redis < 4.0 / Missing Node IDs: Rejects explicitly with an unsupported version error,
 *   as Redis 4.0 is the minimum supported version for this Cluster topology test.
 *
 * Note: This Redis version requirement applies specifically to the integration test topology verification,
 * not to general package runtime usage.
 */

export const MAX_CANDIDATE_ATTEMPTS = 1_000_000;

/**
 * Checks whether an error from CLUSTER SHARDS represents an unrecognized/unsupported command or subcommand.
 * Network, timeout, authentication, ACL, and malformed errors return false and must be rethrown.
 */
export function isUnsupportedShardsError(err) {
  if (!err) return false;
  const msg = err.message || '';

  // Network, ACL, auth, connection errors must never be treated as unsupported command
  if (
    /NOAUTH|WRONGPASS|NOPERM|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|ClusterAllFailedError|Connection is closed|disconnected/i.test(
      msg
    )
  ) {
    return false;
  }

  // Redis ReplyError for unknown command / subcommand
  return (
    /unknown (sub)?command/i.test(msg) ||
    /wrong number of arguments for 'cluster'/i.test(msg)
  );
}

/**
 * Parses raw CLUSTER SHARDS response (Redis 7.0+).
 * Produces an array of shards: [{ masterId, slots: [[start, end], ...] }]
 * Throws on malformed topology.
 */
export function parseClusterShards(rawShards) {
  if (!Array.isArray(rawShards)) {
    throw new Error('Malformed CLUSTER SHARDS response: expected an array of shards');
  }

  const shards = [];

  for (const shard of rawShards) {
    if (!Array.isArray(shard)) {
      throw new Error('Malformed CLUSTER SHARDS response: shard entry must be an array');
    }

    const slots = [];
    let masterId = null;
    let foundNodes = false;

    for (let i = 0; i < shard.length; i += 2) {
      const key = shard[i];
      const val = shard[i + 1];

      if (key === 'slots') {
        if (!Array.isArray(val)) {
          throw new Error('Malformed CLUSTER SHARDS response: slots property must be an array');
        }
        for (let s = 0; s < val.length; s += 2) {
          const start = val[s];
          const end = val[s + 1];
          if (
            typeof start !== 'number' ||
            typeof end !== 'number' ||
            start < 0 ||
            end > 16383 ||
            start > end
          ) {
            throw new Error(`Malformed CLUSTER SHARDS response: invalid slot range [${start}, ${end}]`);
          }
          slots.push([start, end]);
        }
      } else if (key === 'nodes') {
        if (!Array.isArray(val)) {
          throw new Error('Malformed CLUSTER SHARDS response: nodes property must be an array');
        }
        foundNodes = true;
        for (const nodeProps of val) {
          if (!Array.isArray(nodeProps)) {
            throw new Error('Malformed CLUSTER SHARDS response: node descriptor must be an array');
          }
          const propMap = {};
          for (let p = 0; p < nodeProps.length; p += 2) {
            propMap[nodeProps[p]] = nodeProps[p + 1];
          }
          if (propMap.role === 'master') {
            if (!propMap.id || typeof propMap.id !== 'string' || propMap.id.trim() === '') {
              throw new Error('Malformed CLUSTER SHARDS response: master node missing valid ID');
            }
            masterId = propMap.id;
          }
        }
      }
    }

    if (!foundNodes || !masterId) {
      throw new Error('Malformed CLUSTER SHARDS response: shard missing valid master node');
    }

    shards.push({ masterId, slots });
  }

  return shards;
}

/**
 * Parses raw CLUSTER SLOTS response (Redis 4.0–6.x fallback).
 * Groups all slot ranges belonging to the same master node ID into a single shard.
 * Throws explicit error on Redis < 4.0 (missing node IDs) or malformed responses.
 */
export function parseClusterSlots(rawSlots) {
  if (!Array.isArray(rawSlots)) {
    throw new Error('Malformed CLUSTER SLOTS response: expected an array of slot ranges');
  }

  const masterShardMap = new Map();

  for (const entry of rawSlots) {
    if (!Array.isArray(entry) || entry.length < 3) {
      throw new Error('Malformed CLUSTER SLOTS response: entry must contain at least [start, end, masterInfo]');
    }

    const [start, end, masterInfo] = entry;

    if (
      typeof start !== 'number' ||
      typeof end !== 'number' ||
      start < 0 ||
      end > 16383 ||
      start > end
    ) {
      throw new Error(`Malformed CLUSTER SLOTS response: invalid slot range [${start}, ${end}]`);
    }

    if (!Array.isArray(masterInfo) || masterInfo.length < 2) {
      throw new Error('Malformed CLUSTER SLOTS response: masterInfo must be an array with [ip, port, ...]');
    }

    // Node IDs in CLUSTER SLOTS were added in Redis 4.0 (as the 3rd element masterInfo[2]).
    // If missing or not a non-empty string, fail explicitly.
    if (masterInfo.length < 3 || typeof masterInfo[2] !== 'string' || masterInfo[2].trim() === '') {
      throw new Error(
        'Unsupported Redis Cluster topology version: CLUSTER SLOTS response does not contain node IDs. ' +
          'Minimum supported Redis version for Cluster topology test is Redis 4.0+'
      );
    }

    const masterId = masterInfo[2];

    if (!masterShardMap.has(masterId)) {
      masterShardMap.set(masterId, {
        masterId,
        slots: [],
      });
    }

    masterShardMap.get(masterId).slots.push([start, end]);
  }

  return Array.from(masterShardMap.values());
}

/**
 * Queries the authoritative cluster topology.
 * Tries `CLUSTER SHARDS` first (Redis 7.0+).
 * On recognized unsupported command error, falls back to `CLUSTER SLOTS` (Redis 4.0–6.x).
 * Rethrows all other errors (network, auth, ACL, malformed responses).
 */
export async function getClusterTopology(cluster) {
  try {
    const rawShards = await cluster.cluster('SHARDS');
    return parseClusterShards(rawShards);
  } catch (err) {
    if (isUnsupportedShardsError(err)) {
      const rawSlots = await cluster.cluster('SLOTS');
      return parseClusterSlots(rawSlots);
    }
    throw err;
  }
}

/**
 * Deterministically finds a 32-character hexadecimal candidate ID
 * whose CRC16 hash slot falls within the slot ranges of the specified shard.
 * Bounded by maxAttempts (defaults to MAX_CANDIDATE_ATTEMPTS = 1_000_000).
 */
export async function findDeterministicCandidateId(
  cluster,
  shard,
  maxAttempts = MAX_CANDIDATE_ATTEMPTS
) {
  let count = 0;
  while (count < maxAttempts) {
    const candidateHex = count.toString(16).padStart(32, '0');
    const slot = await cluster.cluster('KEYSLOT', `captcha:{${candidateHex}}:attempt`);
    if (shard.slots.some(([start, end]) => slot >= start && slot <= end)) {
      return { id: candidateHex, slot };
    }
    count++;
  }

  throw new Error(
    `Failed to find candidate token ID for master ID ${shard.masterId} within ${maxAttempts} attempts (target slots: ${JSON.stringify(
      shard.slots
    )})`
  );
}
