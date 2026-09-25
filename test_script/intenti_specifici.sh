#!/bin/bash

CONTROLLER_URL="http://localhost:9090/intent"

INTENTS=(
  "The toolbox should connect to grpc-service but nothing else in the namespace."
  "In test-pods, deny all ingress traffic to cache on port 6379."
  "Block all egress from frontend to api-backend on TCP port 8000 in test-pods."
  "In namespace test-pods, deny any traffic from toolbox to grpc-service on port 50051."
  "Deny all ingress to payment-service on port 3000 in test-pods."
  "Block egress from api-backend to message-broker on port 5672 in test-pods."
  "In test-pods, deny ingress to cache from all pods except frontend on TCP port 6379."
  "Block all access to auth-service except from api-backend and payment-service in test-pods."
  "In test-pods, deny egress from frontend to any pod except api-backend on port 8000."
  "Deny all ingress to grpc-service except from toolbox on port 50051 in test-pods."
  "Block all pods from reaching message-broker on port 5672 except api-backend and notification-service in test-pods."
  "Allow ingress to cache on TCP port 6379 from frontend in test-pods."
  "In test-pods, permit ingress traffic to grpc-service on port 50051 from toolbox."
  "Allow ingress to auth-service on port 8080 from api-backend and payment-service in test-pods."
  "In test-pods, allow ingress to message-broker on port 5672 from api-backend only."
  "Permit ingress to api-backend on port 8000 from frontend in namespace test-pods."
  "Allow egress from frontend to api-backend on TCP port 8000 in test-pods."
  "In test-pods, permit egress from toolbox to grpc-service on port 50051."
  "Allow egress from api-backend to cache on TCP port 6379 in test-pods."
  "In test-pods, allow egress from payment-service to api-backend on port 8000."
  "Permit egress from api-backend to notification-service on port 4000 in test-pods."
  "In the test-pods namespace, the pod labeled app=frontend uses nc to test HTTP connectivity. Allow egress from frontend to api-backend on TCP port 8000 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=frontend uses nc to test connectivity on port 6379. Allow egress from frontend to cache on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=api-backend has no curl, wget, or nc available, only bash and openssl. Allow egress from api-backend to cache on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=cache uses nc to test connectivity. Deny ingress to cache from all pods except frontend on TCP port 6379 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=toolbox uses nc to test connectivity. Allow egress from toolbox to grpc-service on TCP port 50051 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=dns-worker uses no networking tools. Allow ingress to dns-worker from all pods on UDP port 53 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "Allow the api-backend and the notification-service to publish messages to the message-broker on port 5672."
  "The metrics-collector needs to scrape all services in the namespace on port 9090. Allow that."
  "Both api-backend and payment-service use the cache. Only they should be able to reach it on port 6379."
  "Allow all pods in test-pods to perform DNS lookups against dns-worker on UDP port 53."
  "In test-pods, permit UDP traffic from all pods to dns-worker on port 53 for name resolution."
  "Enable DNS queries from api-backend to dns-worker on port 53 in test-pods."
  "Allow frontend to resolve service names via dns-worker on UDP port 53 in test-pods."
  "Allow TCP traffic from frontend to api-backend on port 8000 in test-pods."
  "In test-pods, permit TCP connections from toolbox to grpc-service on port 50051."
  "Allow TCP egress from api-backend to cache on port 6379 in namespace test-pods."
  "Permit TCP traffic from payment-service to api-backend on port 8000 in test-pods."
  "Allow UDP traffic from all pods to dns-worker on port 53 in test-pods."
  "In test-pods, permit UDP egress from frontend to dns-worker on port 53."
  "Allow HTTP traffic from all pods to frontend on port 80 in test-pods."
  "In test-pods, permit HTTP ingress to frontend from any pod in the namespace."
  "Allow HTTP connections from toolbox to frontend on port 80 in test-pods."
  "Enable HTTP access to the frontend service from all pods in test-pods."
  "Allow AMQP traffic from api-backend to message-broker on port 5672 in test-pods."
  "In test-pods, permit AMQP connections from notification-service to message-broker on port 5672."
  "The dns-worker should accept DNS queries from everyone in the namespace."
  "Block new connections from api-backend to cache on port 6379"
  "Deny new incoming connections to payment-service on port 3000, but allow existing sessions to continue."
  "Stop frontend from opening new connections to api-backend on port 8000, without dropping connections that are already open."
  "Block new connections from toolbox to grpc-service on port 50051, but preserve any ongoing sessions."
  "Allow frontend to initiate connections to api-backend on port 8000, but api-backend should not be able to open new connections back to frontend."
  "Allow notification-service to send messages to message-broker on port 5672, but message-broker should not be able to initiate new connections to notification-service."
  "Allow cartservice to talk to redis-cart on port 6379"
  "Allow all pods in default namespace to access kube-dns"
  "In the test-pods namespace, the pod labeled app=user-service uses curl to test connectivity. Allow egress from user-service to user-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=social-graph-service uses curl to test connectivity. Allow egress from social-graph-service to social-graph-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."
  "In the test-pods namespace, the pod labeled app=post-storage-service uses curl to test connectivity. Allow egress from post-storage-service to post-storage-mongodb on TCP port 27017 in the test-pods namespace. Apply the policy to the test-pods namespace."

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
