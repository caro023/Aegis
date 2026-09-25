#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"

INTENTS=(
  "Allow the frontend to access the redis cache."
  "Make the notification-service able to send messages to the broker."
  "The frontend can call the api-backend, but should have no direct access to the cache or the message-broker."
  "Allow the api-backend to send notifications to the notification-service, but prevent it from publishing directly to the message-broker."
  "The toolbox can reach the grpc-service for testing, but must not be able to connect to auth-service or payment-service."
  "The api-backend can reach the cache but not the message-broker."
  "Allow payment-service to call api-backend, but stop it from reaching the cache directly."
  "The grpc-service should not accept connections from anyone other than toolbox."
  "Prevent the frontend from sending traffic directly to the message-broker."
  "Nobody should be able to reach the grpc service except the toolbox."
  "The auth-service should only accept incoming requests from api-backend and payment-service."
  "The grpc-service should only receive traffic from toolbox."
  "The message-broker should only receive messages from api-backend and notification-service."
  "The frontend should be allowed to send outgoing requests to the api-backend."
  "The payment-service needs to make outgoing calls to the api-backend to process orders."
  "The toolbox should be able to send outgoing connections to the grpc-service for testing."
  "The api-backend should be allowed to send outgoing notifications to the notification-service."
  "The api-backend needs to call the auth-service to validate tokens before processing requests. Allow that traffic."
  "After a payment is processed, api-backend sends a notification. Allow egress from api-backend to notification-service."
  "Make sure only the toolbox can reach the grpc service."
  "Everyone should be able to do DNS lookups against the dns worker."
  "The grpc service should not be reachable by anyone except toolbox."
  "Deny frontend from talking to paymentservice"
  "Deny frontend from talking to cartservice"
  "Deny adservice from talking to paymentservice"
  "Allow all pods to access DNS on UDP 53"
  "Allow frontend egress to productcatalogservice only on TCP 80"
  "Allow recommendationservice ingress from frontend"
  "Deny all egress traffic from adservice"
  "Allow cartservice to talk to redis-cart using TCP"
  "Allow frontend to access checkoutservice over HTTP"
  "Allow checkoutservice to access paymentservice over gRPC"
  "Deny frontend access to redis-cart"
  "Allow emailservice to reach DNS"
  "Deny all traffic from frontend to paymentservice on all ports"
  "Allow frontend to communicate with recommendationservice on any protocol"
  "Allow shippingservice ingress only from checkoutservice"
  "Allow paymentservice ingress only from checkoutservice"
  "Deny recommendationservice from talking to paymentservice"
  "Allow frontend to communicate with cartservice"
  "Allow cartservice to communicate with checkoutservice"
  "Deny all ingress traffic to redis-cart except cartservice"

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
