#!/usr/bin/env python3
"""
Test Intent: "allow all traffic between all pods"
Verifica che TUTTI i pod possano comunicare con TUTTI gli altri pod
"""

import subprocess
import time
import sys
import requests

class AllowAllTest:
    def __init__(self, namespace="default", kubeteus_url="http://localhost:9090"):
        self.namespace = namespace
        self.kubeteus_url = kubeteus_url  # <--- IMPORTANTE!
        
    def send_intent(self, intent_text: str):
        """Invia intento a KubeTeus"""
        print(f"\n📤 Sending intent: {intent_text}")
        try:
            response = requests.post(
                f"{self.kubeteus_url}/intent",
                data=intent_text,
                headers={"Content-Type": "text/plain"},
                timeout=5
            )
            if response.status_code == 200:
                print("✅ Intent accepted")
                return True
            else:
                print(f"❌ HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def get_all_pods(self):
        """Ottiene tutti i pod in esecuzione"""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, 
             "-o", "jsonpath='{.items[*].metadata.name}'"],
            capture_output=True, text=True
        )
        pods = result.stdout.strip().strip("'").split()
        
        running_pods = []
        for pod in pods:
            status = subprocess.run(
                ["kubectl", "get", "pod", pod, "-n", self.namespace, 
                 "-o", "jsonpath='{.status.phase}'"],
                capture_output=True, text=True
            )
            if status.stdout.strip().strip("'") == "Running":
                running_pods.append(pod)
        return running_pods
    
    def test_connectivity(self, from_pod, to_pod):
        """Test connettività tra due pod"""
        if not from_pod or not to_pod:
            return False
        
        cmd = f"kubectl exec -n {self.namespace} {from_pod} -- timeout 2 wget -q -O- http://{to_pod}:80 2>&1 || echo 'FAILED'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "FAILED" not in result.stdout and result.returncode == 0
    
    def run_test(self):
        print("\n" + "="*60)
        print("🧪 TEST: Allow All Traffic Between All Pods")
        print("="*60)
        
        # Invia intento a KubeTeus
        intent = "allow all traffic between all pods"
        if not self.send_intent(intent):
            print("❌ Failed to send intent to KubeTeus")
            return False
        
        # Attendi che KubeTeus applichi le policy
        print("\n⏳ Waiting for KubeTeus to apply policies...")
        time.sleep(10)
        
        # Ottieni tutti i pod
        pods = self.get_all_pods()
        print(f"\n📋 Found {len(pods)} running pods")
        
        if len(pods) < 2:
            print("❌ Need at least 2 pods for test")
            return False
        
        # Test tutte le combinazioni
        print("\n🌐 Testing connectivity between all pods...")
        failed_tests = []
        total_tests = 0
        success_count = 0
        
        for i, from_pod in enumerate(pods):
            for to_pod in pods:
                if from_pod == to_pod:
                    continue
                
                total_tests += 1
                connected = self.test_connectivity(from_pod, to_pod)
                
                if connected:
                    success_count += 1
                    if total_tests <= 30:  # Mostra solo primi 30
                        print(f"  ✅ {from_pod[:25]} → {to_pod[:25]}: SUCCESS")
                else:
                    failed_tests.append(f"{from_pod} → {to_pod}")
                    print(f"  ❌ {from_pod[:25]} → {to_pod[:25]}: BLOCKED (should work!)")
            
            print(f"  Progress: {i+1}/{len(pods)} pods tested")
        
        # Report
        print("\n" + "="*60)
        print("📊 RESULTS")
        print("="*60)
        print(f"Total tests: {total_tests}")
        print(f"Successful connections: {success_count}")
        print(f"Failed connections (should work but blocked): {len(failed_tests)}")
        
        if failed_tests:
            print("\n❌ FAILED CONNECTIONS (should work but blocked):")
            for fail in failed_tests[:10]:
                print(f"  - {fail}")
            if len(failed_tests) > 10:
                print(f"  ... and {len(failed_tests) - 10} more")
            print("\n❌ TEST FAILED: Not all pods can communicate")
            return False
        else:
            print("\n✅ TEST PASSED: All pods can communicate with each other")
            return True

if __name__ == "__main__":
    test = AllowAllTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
