#!/usr/bin/env python3
from automatic_verifier import AutomaticVerifier

verifier = AutomaticVerifier(namespace="default")
verifier.verify_enforcement("deny all traffic between all pods")
