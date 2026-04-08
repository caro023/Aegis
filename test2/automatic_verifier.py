#!/usr/bin/env python3
"""
KubeTeus Automatic Intent Verifier - Versione con HTTP Request
"""

import subprocess
import json
import time
import sys
import requests
from typing import Dict, List, Tuple

class AutomaticVerifier:
    def __init__(self, namespace="default", kubeteus_url="http://localhost:9090"):
        self.namespace = namespace
        self.kubeteus_url = kubeteus_url
        self.intent_endpoint = f"{kubeteus_url}/intent"
        
    def send_intent_to_kubeteus(self, intent_text: str):
        """Manda l'intento a KubeTeus via HTTP POST (come fa il client Go)"""
        print(f"\n  🎯 Sending intent to KubeTeus controller...")
        print(f"     Endpoint: {self.intent_endpoint}")
        print(f"     Intent: \"{intent_text}\"")
        
        try:
            # Come nel client Go: POST con Content-Type: text/plain
            response = requests.post(
                self.intent_endpoint,
                data=intent_text,  # testo semplice, non JSON
                headers={"Content-Type": "text/plain"},
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"     ✅ Intent accepted by KubeTeus controller")
                print(f"     Response: {response.text}")
                return True
            else:
                print(f"     ❌ KubeTeus returned status: {response.status_code}")
                print(f"     Response: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            print(f"     ❌ Cannot connect to KubeTeus at {self.intent_endpoint}")
            print(f"     ⚠ Is KubeTeus controller running?")
            return False
        except Exception as e:
            print(f"     ❌ Error sending intent: {e}")
            return False
    
    def capture_state(self, state_name: str) -> Dict:
        """Cattura lo stato attuale del cluster"""
        print(f"  📸 Capturing state: {state_name}")
        
        state = {
            "network_policies": [],
            "cilium_policies": [],
            "cilium_cluster_policies": [],
            "pods": []
        }
        
        # Cattura NetworkPolicy standard
        try:
            result = subprocess.run(
                ["kubectl", "get", "networkpolicies", "-n", self.namespace, "-o", "json"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout:
                policies = json.loads(result.stdout)
                state["network_policies"] = policies.get('items', [])
                print(f"     → Found {len(state['network_policies'])} NetworkPolicies")
        except Exception as e:
            print(f"     ⚠ Error capturing policies: {e}")
        
        # Cattura CiliumNetworkPolicy
        try:
            result = subprocess.run(
                ["kubectl", "get", "ciliumnetworkpolicies", "-n", self.namespace, "-o", "json"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout:
                policies = json.loads(result.stdout)
                state["cilium_policies"] = policies.get('items', [])
                print(f"     → Found {len(state['cilium_policies'])} CiliumNetworkPolicies")
        except Exception:
            pass  # CRD potrebbe non esistere
        
        # Cattura Pod
        try:
            result = subprocess.run(
                ["kubectl", "get", "pods", "-n", self.namespace, "-o", "json"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                pods = json.loads(result.stdout)
                state["pods"] = [p['metadata']['name'] for p in pods.get('items', []) 
                                if p['status']['phase'] == 'Running']
                print(f"     → Found {len(state['pods'])} running pods")
        except Exception as e:
            print(f"     ⚠ Error capturing pods: {e}")
        
        return state
    
    def test_connectivity(self, from_pod: str, to_pod: str) -> bool:
        """Test se due pod possono comunicare"""
        # Get pod IP
        result = subprocess.run(
            ["kubectl", "get", "pod", to_pod, "-n", self.namespace, 
             "-o", "jsonpath={.status.podIP}"],
            capture_output=True, text=True
        )
        to_ip = result.stdout.strip()
        
        if not to_ip:
            return False
        
        # Prova a connetterti con wget
        cmd = f"kubectl exec -n {self.namespace} {from_pod} -- timeout 2 wget -q -O- http://{to_ip}:80 2>&1 || echo 'FAILED'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        return "FAILED" not in result.stdout and result.returncode == 0
    
    def build_connectivity_matrix(self, pods: List[str]) -> Dict:
        """Costruisce matrice di connettività tra tutti i pod"""
        matrix = {}
        total = len(pods)
        
        print(f"  Testing connectivity (this may take a moment)...")
        
        for i, source in enumerate(pods):
            matrix[source] = {}
            for j, target in enumerate(pods):
                if source != target:
                    matrix[source][target] = self.test_connectivity(source, target)
            
            # Progress indicator
            if (i + 1) % 3 == 0:
                print(f"     Progress: {i+1}/{total} sources tested")
        
        return matrix
    
    def compare_and_verify(self, before: Dict, after: Dict, intent_text: str) -> bool:
        """Compara stati e verifica enforcement"""
        print(f"\n{'='*60}")
        print("🔍 ANALYSIS: Policy Changes")
        print(f"{'='*60}")
        
        # Controlla se sono state aggiunte policy
        before_policies = len(before['network_policies']) + len(before['cilium_policies'])
        after_policies = len(after['network_policies']) + len(after['cilium_policies'])
        
        policies_added = after_policies - before_policies
        
        if policies_added > 0:
            print(f"  ✅ Found {policies_added} new policy(ies) created")
            for policy in after['cilium_policies']:
                print(f"     - {policy['metadata']['name']}")
        elif after_policies > 0:
            print(f"  ℹ️  {after_policies} policy(ies) already existed")
        else:
            print(f"  ⚠ No policies detected")
        
        # Test di connettività
        print(f"\n{'='*60}")
        print("🌐 CONNECTIVITY VERIFICATION")
        print(f"{'='*60}")
        
        if len(after['pods']) >= 2:
            matrix = self.build_connectivity_matrix(after['pods'])
            
            intent_lower = intent_text.lower()
            
            # Verifica se tutto è bloccato (per intento deny-all)
            if "deny all" in intent_lower or "block all" in intent_lower:
                print(f"\n  🧪 Verifying: All traffic should be blocked")
                
                blocked_count = 0
                total_count = 0
                failed_connections = []
                
                for src in matrix:
                    for dst in matrix[src]:
                        total_count += 1
                        if matrix[src][dst]:
                            # Questa connessione è riuscita ma NON dovrebbe!
                            failed_connections.append(f"{src} → {dst}")
                        else:
                            blocked_count += 1
                
                print(f"\n  📊 Results: {blocked_count}/{total_count} connections blocked")
                
                if failed_connections:
                    print(f"\n  ❌ FAILED: These connections should be blocked but succeeded:")
                    for conn in failed_connections[:10]:  # Mostra max 10
                        print(f"     - {conn}")
                    if len(failed_connections) > 10:
                        print(f"     ... and {len(failed_connections) - 10} more")
                    return False
                else:
                    print(f"\n  ✅ SUCCESS: All {total_count} connections blocked!")
                    return True
        
        return after_policies > 0
    
    def verify_enforcement(self, intent_text: str) -> bool:
        """Verifica automatica completa"""
        print(f"\n{'#'*60}")
        print(f"🤖 KUBETEUS INTENT VERIFIER")
        print(f"   Intent: \"{intent_text}\"")
        print(f"{'#'*60}")
        
        # Step 1: Capture BEFORE state
        print("\n📊 STEP 1: Capturing cluster state BEFORE intent")
        before = self.capture_state("BEFORE")
        
        # Step 2: Send intent to KubeTeus via HTTP
        print("\n📊 STEP 2: Sending intent to KubeTeus controller")
        success = self.send_intent_to_kubeteus(intent_text)
        
        if not success:
            print("\n❌ Cannot reach KubeTeus controller. Is it running?")
            print("   Check: kubectl logs -l app=kubeteus")
            return False
        
        # Step 3: Wait for controller to process
        print("\n📊 STEP 3: Waiting for KubeTeus to process intent...")
        time.sleep(8)  # Attendi che il controller applichi le policy
        
        # Step 4: Capture AFTER state
        print("\n📊 STEP 4: Capturing cluster state AFTER intent")
        after = self.capture_state("AFTER")
        
        # Step 5: Compare and verify
        result = self.compare_and_verify(before, after, intent_text)
        
        # Final verdict
        print(f"\n{'='*60}")
        print("📋 FINAL VERDICT")
        print(f"{'='*60}")
        
        if result:
            print("✅ INTENT SUCCESSFULLY ENFORCED")
            return True
        else:
            print("❌ INTENT NOT ENFORCED")
            return False


def main():
    # Prendi intento da riga di comando o usa default
    if len(sys.argv) > 1:
        intent = " ".join(sys.argv[1:])
    else:
        intent = "deny all traffic between all pods"
    
    # Configura l'URL di KubeTeus (default localhost:9090)
    kubeteus_url = os.environ.get('KUBETEUS_URL', 'http://localhost:9090')
    
    verifier = AutomaticVerifier(namespace="default", kubeteus_url=kubeteus_url)
    success = verifier.verify_enforcement(intent)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    import os
    main()
