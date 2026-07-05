#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"

# Namespace dove girano i pod di test
TEST_NS="test-pods"

# Pod disponibili in test-pods:
#   frontend     -> nginx:alpine,      HTTP/80,        tools: curl, wget, nc, ping, sh
#   api-backend  -> python:3.12-slim,  HTTP/8000,      tools: openssl, bash, sh
#   cache        -> redis:7-alpine,    TCP/6379,       tools: wget, nc, ping, sh
#   dns-worker   -> coredns,           UDP/53+TCP/53,  tools: nessuno
#   grpc-service -> netshoot (nc -l),  TCP/50051,      tools: curl, wget, nc, nmap, ping, telnet, openssl, bash, sh
#   toolbox      -> nicolaka/netshoot, TCP/1883,       tools: curl, wget, nc, nmap, ping, telnet, openssl, bash, sh

INTENTS=(

  # ================================================================
  # SEZIONE 1: intenti DETTAGLIATI (porta, protocollo, namespace espliciti)
  # ================================================================

  "In the test-pods namespace, the pod labeled app=frontend uses nc to test HTTP connectivity. Allow egress from frontend to api-backend on TCP port 8000 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=frontend uses nc to test connectivity on port 6379. Allow egress from frontend to cache on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=api-backend has no curl, wget, or nc available, only bash and openssl. Allow egress from api-backend to cache on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=cache uses nc to test connectivity. Deny ingress to cache from all pods except frontend on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=toolbox uses nc to test connectivity. Allow egress from toolbox to grpc-service on TCP port 50051 in the test-pods namespace. Apply the policy to the test-pods namespace."

  "In the test-pods namespace, the pod labeled app=dns-worker uses no networking tools. Allow ingress to dns-worker from all pods on UDP port 53 in the test-pods namespace. Apply the policy to the test-pods namespace."

    # Porta nota dal contesto, namespace omesso
  "The api-backend needs to call the auth-service to validate tokens before processing requests. Allow that traffic."

  # Pattern classico service-to-service, porta implicita
  "The payment-service should be able to reach the api-backend."

  # Broker pattern, porta AMQP nota agli ingegneri
  "Allow the api-backend and the notification-service to publish messages to the message-broker on port 5672."

  # Osservabilità, porta Prometheus standard
  "The metrics-collector needs to scrape all services in the namespace on port 9090. Allow that."

  # Auth come gateway obbligatorio
  "Only the api-backend should be allowed to talk to the auth-service. Block everything else."

  # Isolamento parziale con eccezione
  "The payment-service is sensitive — it should only accept connections from api-backend and auth-service."

  # Notifiche triggered dal backend
  "After a payment is processed, api-backend sends a notification. Allow egress from api-backend to notification-service."

  # Cache condivisa con policy selettiva
  "Both api-backend and payment-service use the cache. Only they should be able to reach it on port 6379."

  # Broker accessibile solo internamente
  "The message-broker should not be reachable from frontend or toolbox, only from backend services."

  # Zero-trust su un servizio critico
  "Lock down the auth-service: only api-backend and payment-service can call it."

  # ================================================================
  # SEZIONE 2: intenti GENERICI / informali (come scritti da un utente
  # non esperto: niente porta, niente protocollo, nomi vaghi, dettagli
  # impliciti o dati per scontato)
  # ================================================================

  
  # Porta non specificata, nomi diretti
  "Let the frontend talk to the api-backend."
 
  "Let the toolbox connect to the cache."
 
  # Verbo vago, nessuna porta
  "I want the api-backend to be able to reach the cache service."
 
  # Nome alternativo per il servizio
  "Allow the frontend to access the redis cache."
 
  # Ingress generico, nessuna porta
  "I want my frontend to be reachable from everywhere."
 
  # Deny senza porta, verbo informale
  "Stop the api-backend from reaching the cache."
 
  # "Except" pattern, nessuna porta
  "Make sure only the toolbox can reach the grpc service."
 
  # Nome generico per il servizio
  "Lock down the cache so only the frontend can connect."
 
  # DNS in modo colloquiale
  "Everyone should be able to do DNS lookups against the dns worker."
 
  # Deny totale su un servizio
  "The grpc service should not be reachable by anyone except toolbox."
 
  # Sicurezza generica
  "Secure the cache so random pods can't just connect to it."
 

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

  sleep 5
done