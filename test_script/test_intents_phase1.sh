#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"


INTENTS=(
'Allow frontend to talk to productcatalogservice'
'Allow frontend to talk to recommendationservice'
'Allow frontend to talk to checkoutservice'
'Allow checkoutservice to talk to paymentservice'
'Allow checkoutservice to talk to shippingservice'
'Allow checkoutservice to talk to emailservice'
'Allow recommendationservice to talk to productcatalogservice'
'Allow cartservice to talk to redis-cart on port 6379'
'Deny frontend from talking to paymentservice'
'Deny frontend from talking to cartservice'
'Deny adservice from talking to paymentservice'
'Allow all pods to access DNS on UDP 53'
'Allow frontend egress to productcatalogservice only on TCP 80'
'Allow recommendationservice ingress from frontend'
'Allow currencyservice to talk to frontend'
'Deny all egress traffic from adservice'
'Allow cartservice to talk to redis-cart using TCP'
'Allow frontend to access checkoutservice over HTTP'
'Allow checkoutservice to access paymentservice over gRPC'
'Deny frontend access to redis-cart'
'Allow emailservice to reach DNS'
'Allow all pods in default namespace to access kube-dns'
'Deny all traffic from frontend to paymentservice on all ports'
'Allow frontend to communicate with recommendationservice on any protocol'
'Allow shippingservice ingress only from checkoutservice'
'Allow paymentservice ingress only from checkoutservice'
'Deny recommendationservice from talking to paymentservice'
'Allow frontend to communicate with cartservice'
'Allow cartservice to communicate with checkoutservice'
'Deny all ingress traffic to redis-cart except cartservice'
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
