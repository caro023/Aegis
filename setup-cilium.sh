#!/bin/bash
set -e

echo "=== Creating kind cluster (Cilium) ==="
kind create cluster --config kind-cilium.yaml

kubectl config use-context kind-cilium-test

echo "=== Installing Cilium ==="
# Requires the cilium CLI: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/
cilium install --version 1.16.5

echo "=== Waiting for Cilium to be ready ==="
cilium status --wait

echo "=== Cilium cluster ready. Context: kind-cilium-test ==="
kubectl get nodes
