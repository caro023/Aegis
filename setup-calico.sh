#!/bin/bash
set -e

echo "=== Creating kind cluster (Calico) ==="
kind create cluster --config kind-calico.yaml

kubectl config use-context kind-calico-test

echo "=== Installing Calico (Tigera operator) ==="
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/custom-resources.yaml

echo "=== Waiting for Calico to be ready (this can take a few minutes) ==="
sleep 30
kubectl wait --for=condition=Ready pods -l k8s-app=calico-node -n calico-system --timeout=300s

echo "=== Calico cluster ready. Context: kind-calico-test ==="
kubectl get nodes
