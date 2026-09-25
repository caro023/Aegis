#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"

INTENTS=(
  "I want the api-backend to be able to reach the cache service."
  "The payment service should be able to call the backend api."
  "Let the frontend talk to the api-backend but keep it away from the cache."
  "The cache should not be reachable by anyone except the frontend."
  "Stop the api-backend from reaching the cache directly."
  "The auth-service is sensitive and should only be reachable from trusted services: api-backend and payment-service."
  "Lock down the cache so random pods can't connect to it."
  "Stop the api-backend from reaching the cache."
  "Make sure only the frontend can reach the cache."
  "The message-broker should not be reachable from frontend or toolbox."
  "The cache should accept incoming connections from the frontend only."
  "The payment-service should only accept incoming connections from api-backend and auth-service."
  "The api-backend should be able to send outgoing traffic to the cache for data retrieval."
  "The payment-service should be able to reach the api-backend."
  "Only the api-backend should be allowed to talk to the auth-service. Block everything else."
  "The payment-service is sensitive — it should only accept connections from api-backend and auth-service."
  "The message-broker should not be reachable from frontend or toolbox, only from backend services."
  "Lock down the auth-service: only api-backend and payment-service can call it."
  "Let the frontend talk to the api-backend."
  "Let the toolbox connect to the cache."
  "I want my frontend to be reachable from everywhere."
  "Lock down the cache so only the frontend can connect."
  "Secure the cache so random pods can't just connect to it."
  "The cache should only respond to requests from api-backend, not initiate new connections toward it."
  "Restrict access to the cache to frontend only, without interrupting any existing connections from other pods."
  "Lock down the message-broker so only api-backend can reach it, but do not drop connections that are already established from other pods."
  "Make sure that pods already connected to the cache can finish their work before the new deny policy takes effect."
  "Allow frontend to talk to productcatalogservice"
  "Allow frontend to talk to recommendationservice"
  "Allow frontend to talk to checkoutservice"
  "Allow checkoutservice to talk to paymentservice"
  "Allow checkoutservice to talk to shippingservice"
  "Allow checkoutservice to talk to emailservice"
  "Allow recommendationservice to talk to productcatalogservice"
  "Allow currencyservice to talk to frontend"

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
