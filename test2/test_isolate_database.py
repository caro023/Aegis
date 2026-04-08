#!/usr/bin/env python3
from automatic_verifier import AutomaticVerifier

verifier = AutomaticVerifier(namespace="default")
verifier.verify_enforcement("isolate database pod, deny all ingress traffic")
