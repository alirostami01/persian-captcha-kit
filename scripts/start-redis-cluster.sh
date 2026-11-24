#!/usr/bin/env bash
set -e

echo "Starting 3-node Redis Cluster on ports 7000, 7001, 7002..."
for port in 7000 7001 7002; do
  docker rm -f redis-$port 2>/dev/null || true
  docker run -d --name redis-$port --net host redis:alpine \
    redis-server --port $port --cluster-enabled yes --cluster-config-file nodes-$port.conf \
    --cluster-node-timeout 5000 --appendonly no \
    --cluster-bus-port-protected-mode no --protected-mode no
done

echo "Waiting for all Redis nodes to respond to PING..."
for port in 7000 7001 7002; do
  READY=0
  for attempt in $(seq 1 30); do
    if docker exec redis-$port redis-cli -p $port ping 2>/dev/null | grep -q "PONG"; then
      READY=1
      break
    fi
    sleep 0.3
  done
  if [ "$READY" -ne 1 ]; then
    echo "ERROR: Redis node on port $port failed to respond within 10 seconds." >&2
    exit 1
  fi
done

echo "Initializing Redis Cluster..."
docker exec redis-7000 redis-cli --cluster create \
  127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 \
  --cluster-replicas 0 --cluster-yes

echo "Waiting for Redis Cluster state to become OK..."
CLUSTER_OK=0
for attempt in $(seq 1 30); do
  INFO=$(docker exec redis-7000 redis-cli -p 7000 cluster info 2>/dev/null || true)
  if echo "$INFO" | grep -q "cluster_state:ok" && echo "$INFO" | grep -q "cluster_slots_assigned:16384"; then
    CLUSTER_OK=1
    break
  fi
  sleep 0.3
done

if [ "$CLUSTER_OK" -ne 1 ]; then
  echo "ERROR: Redis Cluster failed to reach healthy state (cluster_state:ok) within 10 seconds." >&2
  exit 1
fi

echo "Redis Cluster started and healthy!"
