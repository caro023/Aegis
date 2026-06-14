#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"

# Namespace dove girano i pod reali (dove si applica la policy)

# Namespace dove girano i pod di test (source per i test script)
TEST_NS="test-pods"

# Nota: gli intenti specificano esplicitamente:
#   - il namespace dei pod di test come source per il testing
#   - il namespace test-pods come target dove viene applicata la policy YAML
#   - il protocollo reale usato dal servizio (Thrift/TCP, Redis RESP, MongoDB BSON, Memcached, HTTP)

INTENTS=(
  # --- THRIFT/TCP tra microservizi ---
  "In the test-pods namespace, the pod labeled app=user-service uses curl to test connectivity. Allow egress from user-service to user-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=social-graph-service uses curl to test connectivity. Allow egress from social-graph-service to social-graph-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=post-storage-service uses curl to test connectivity. Allow egress from post-storage-service to post-storage-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=url-shorten-service uses curl to test connectivity. Allow egress from url-shorten-service to url-shorten-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=media-service uses curl to test connectivity. Allow egress from media-service to media-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=user-timeline-service uses curl to test connectivity. Allow egress from user-timeline-service to user-timeline-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- REDIS (protocollo RESP, porta 6379) ---
  "In the test-pods namespace, the pod labeled app=home-timeline-redis uses redis-cli to test connectivity. Allow egress from home-timeline-service to home-timeline-redis on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=social-graph-redis uses redis-cli to test connectivity. Allow egress from social-graph-service to social-graph-redis on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=user-timeline-redis uses redis-cli to test connectivity. Allow egress from user-timeline-service to user-timeline-redis on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=social-graph-redis uses redis-cli to test connectivity. Deny ingress to social-graph-redis from all pods except social-graph-service on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=home-timeline-redis uses redis-cli to test connectivity. Deny ingress to home-timeline-redis from all pods except home-timeline-service on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- MEMCACHED (protocollo ASCII/binary, porta 11211) ---
  "In the test-pods namespace, the pod labeled app=media-memcached uses nc to test connectivity on port 11211. Allow egress from media-service to media-memcached on TCP port 11211 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=post-storage-memcached uses nc to test connectivity on port 11211. Allow egress from post-storage-service to post-storage-memcached on TCP port 11211 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=url-shorten-memcached uses nc to test connectivity on port 11211. Allow egress from url-shorten-service to url-shorten-memcached on TCP port 11211 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=user-memcached uses nc to test connectivity on port 11211. Allow egress from user-service to user-memcached on TCP port 11211 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=post-storage-memcached uses nc to test connectivity on port 11211. Deny ingress to post-storage-memcached from all pods except post-storage-service on TCP port 11211 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- MONGODB (protocollo BSON, porta 27017) ---
  "In the test-pods namespace, the pod labeled app=media-mongodb uses mongosh to test connectivity. Deny ingress to media-mongodb from all pods except media-service on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=post-storage-mongodb uses mongosh to test connectivity. Deny ingress to post-storage-mongodb from all pods except post-storage-service on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=social-graph-mongodb uses mongosh to test connectivity. Deny ingress to social-graph-mongodb from all pods except social-graph-service on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=user-mongodb uses mongosh to test connectivity. Deny ingress to user-mongodb from all pods except user-service on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- THRIFT tra microservizi (porta 9090) ---
  "In the test-pods namespace, the pod labeled app=compose-post-service uses curl to test Thrift connectivity on port 9090. Allow egress from compose-post-service to text-service on TCP port 9090 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=compose-post-service uses curl to test Thrift connectivity on port 9090. Allow egress from compose-post-service to unique-id-service on TCP port 9090 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=compose-post-service uses curl to test Thrift connectivity on port 9090. Allow egress from compose-post-service to user-mention-service on TCP port 9090 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=home-timeline-service uses curl to test Thrift connectivity on port 9090. Allow egress from home-timeline-service to post-storage-service on TCP port 9090 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=user-timeline-service uses curl to test Thrift connectivity on port 9090. Allow egress from user-timeline-service to post-storage-service on TCP port 9090 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- HTTP/Nginx (porta 8080) ---
  "In the test-pods namespace, the pod labeled app=nginx-thrift uses curl to test HTTP connectivity on port 8080. Allow ingress to nginx-thrift from all pods on TCP port 8080 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=media-frontend uses curl to test HTTP connectivity on port 8080. Allow ingress to media-frontend only from nginx-thrift on TCP port 8080 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- JAEGER tracing (HTTP porta 16686 / UDP 6831) ---
  "In the test-pods namespace, the pod labeled app=jaeger uses curl to test HTTP connectivity on port 16686. Allow ingress to jaeger from all pods in the test-pods namespace on TCP port 16686. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=jaeger uses curl to test connectivity. Allow egress from all microservices to jaeger on UDP port 6831 in the test-pods namespace for distributed tracing. Apply the policy to the test-pods namespace."

  # --- DENY totale ---
  "In the test-pods namespace, the pod labeled app=user-mongodb uses mongosh to test connectivity. Deny all ingress traffic to user-timeline-mongodb except from user-timeline-service on any port in the test-pods namespace. Apply the policy to the test-pods namespace."
)

COUNT=1

for INTENT in "${INTENTS[@]}"; do
  echo "=================================================="
  echo "TEST $COUNT"
  echo "INTENT: $INTENT"
  echo "=================================================="

  curl -s -X POST "$CONTROLLER_URL" \
    -H "Content-Type: application/json" \
    -d "{\"prompt\":\"$INTENT\"}"

  echo
  echo
  COUNT=$((COUNT+1))

  sleep 3
done