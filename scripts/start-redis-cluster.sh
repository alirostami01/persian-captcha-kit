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

sleep 1

echo "Initializing Redis Cluster..."
docker run --rm --net host redis:alpine redis-cli --cluster create \
  127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 \
  --cluster-replicas 0 --cluster-yes

echo "Redis Cluster started and healthy!"
