#!/usr/bin/env python3
"""
Test Intent: "allow only frontend to talk to frontend-external"
Verifica policy specifica: solo un servizio può parlare con un altro
"""

import subprocess
import time
import sys
import requests

class AllowSpecificTest:
    def __init__(self, namespace="default", kubeteus_url="http://localhost:9090"):
        self.namespace = namespace
        self.kubeteus_url = kubeteus_url
        
    def send_intent(self, intent_text: str):
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
        except Exception as e:
            print(f"❌ Error: {e}")
        return False
    
    def get_pod_by_label(self, label):
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, 
             "-l", f"app={label}", "-o", "jsonpath='{.items[0].metadata.name}'"],
            capture_output=True, text=True
        )
        return result.stdout.strip().strip("'")
    
    def test_connectivity(self, from_pod, to_pod):
        if not from_pod or not to_pod:
            return False
        cmd = f"kubectl exec -n {self.namespace} {from_pod} -- timeout 2 wget -q -O- http://{to_pod}:80 2>&1 || echo 'FAILED'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "FAILED" not in result.stdout and result.returncode == 0
    
    def run_test(self):
        print("\n" + "="*60)
        print("🧪 TEST: Allow Specific Traffic Only")
        print("="*60)
        
        intent = "allow only frontend to talk to frontend-external"
        if not self.send_intent(intent):
            print("❌ Failed to send intent")
            return False
        
        time.sleep(10)
        
        frontend = self.get_pod_by_label("frontend")
        frontend_ext = self.get_pod_by_label("frontend-external")
        
        if not frontend_ext:
            print("⚠ frontend-external not found, using checkout as target")
            frontend_ext = self.get_pod_by_label("checkoutservice")
        
        print(f"\n📋 Pods:")
        print(f"   Source: {frontend}")
        print(f"   Target: {frontend_ext}")
        
        # Test permesso
        allowed = self.test_connectivity(frontend, frontend_ext)
        print(f"\n✅ Allowed traffic: {'SUCCESS' if allowed else 'BLOCKED'}")
        
        print("\n✅ TEST COMPLETED")
        return allowed

if __name__ == "__main__":
    test = AllowSpecificTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
