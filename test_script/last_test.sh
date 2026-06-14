#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"

# Namespace dove girano i pod di test (source/target per le policy)
TEST_NS="test-pods"

# Pod disponibili in test-pods e relativi tool/protocolli:
#   frontend     -> nginx:alpine,      HTTP/80,        tools: wget, nc (busybox)
#   api-backend  -> python:3.12-slim,  HTTP/8000,      tools: nessuno -> devtcp (bash presente)
#   cache        -> redis:7-alpine,    TCP/6379,       tools: nc (busybox)
#   dns-worker   -> coredns,           UDP/53+TCP/53,  tools: nessuno
#   grpc-service -> pause:3.9,         TCP/50051,      tools: nessuno, niente bash (distroless)
#   toolbox      -> nicolaka/netshoot, TCP/1883,       tools: curl, wget, nc, ncat, nmap, ping, telnet, openssl

INTENTS=(
  # --- 1) HTTP semplice: frontend -> api-backend (source ha nc/wget) ---
  "In the test-pods namespace, the pod labeled app=frontend uses nc to test HTTP connectivity. Allow egress from frontend to api-backend on TCP port 8000 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 2) Redis-like via nc: frontend -> cache ---
  "In the test-pods namespace, the pod labeled app=frontend uses nc to test connectivity on port 6379. Allow egress from frontend to cache on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 3) devtcp puro: api-backend (nessun tool, solo bash) -> cache ---
  "In the test-pods namespace, the pod labeled app=api-backend has no curl, wget, or nc available, only bash. Allow egress from api-backend to cache on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 4) Deny ingress selettivo: solo frontend puo' raggiungere cache ---
  "In the test-pods namespace, the pod labeled app=cache uses nc to test connectivity. Deny ingress to cache from all pods except frontend on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 5) toolbox (tutti i tool) -> grpc-service, target senza tool e senza bash ---
  "In the test-pods namespace, the pod labeled app=toolbox uses ncat to test connectivity. Allow egress from toolbox to grpc-service on TCP port 50051 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 6) UDP/DNS: tutti i pod -> dns-worker su UDP 53 ---
  "In the test-pods namespace, the pod labeled app=dns-worker uses no networking tools. Allow ingress to dns-worker from all pods on UDP port 53 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 7) TCP DNS aggiuntivo: toolbox -> dns-worker su TCP 53 ---
  "In the test-pods namespace, the pod labeled app=toolbox uses dig to test connectivity. Allow egress from toolbox to dns-worker on TCP port 53 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 8) Deny totale verso api-backend tranne frontend ---
  "In the test-pods namespace, the pod labeled app=api-backend has no networking tools, only bash. Deny all ingress traffic to api-backend except from frontend on TCP port 8000 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 9) Ingress allow generale su frontend (HTTP pubblico) ---
  "In the test-pods namespace, the pod labeled app=frontend uses wget to test HTTP connectivity. Allow ingress to frontend from all pods on TCP port 80 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 10) Caso limite pensato per il rollback: api-backend (no tool) -> grpc-service (no tool, no bash) ---
  "In the test-pods namespace, the pod labeled app=api-backend has no curl, wget, or nc available, only bash. Allow egress from api-backend to grpc-service on TCP port 50051 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 11) Multi-porta: toolbox -> cache (6379) e api-backend (8000) ---
  "In the test-pods namespace, the pod labeled app=toolbox uses nc to test connectivity. Allow egress from toolbox to cache on TCP port 6379 and from toolbox to api-backend on TCP port 8000 in the test-pods namespace. Apply the policy to the test-pods namespace."

  # --- 12) Deny totale verso grpc-service tranne toolbox ---
  "In the test-pods namespace, the pod labeled app=toolbox uses ncat to test connectivity. Deny all ingress traffic to grpc-service except from toolbox on TCP port 50051 in the test-pods namespace. Apply the policy to the test-pods namespace."
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
