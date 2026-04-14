#!/usr/bin/env python3
import subprocess
import time
import sys
import requests

class DenyAllTest:
    def __init__(self, namespace="default", kubeteus_url="http://localhost:9090"):
        self.namespace = namespace
        self.kubeteus_url = kubeteus_url  # <--- IMPORTANTE!
    
    def send_intent(self, intent_text: str):
        try:
            response = requests.post(
                f"{self.kubeteus_url}/intent",
                data=intent_text,
                headers={"Content-Type": "text/plain"},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False
    
    def get_pods(self):
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, "-o", "jsonpath='{.items[*].metadata.name}'"],
            capture_output=True, text=True
        )
        return result.stdout.strip().strip("'").split()
    
    def test_connectivity(self, from_pod, to_pod):
        cmd = f"kubectl exec -n {self.namespace} {from_pod} -- timeout 2 wget -q -O- http://{to_pod}:80 2>&1 || echo 'FAILED'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "FAILED" not in result.stdout and result.returncode == 0
    
    def run_test(self):
        print("\n🧪 TEST: Deny All Traffic")
        
        if not self.send_intent("deny all traffic between all pods"):
            print("❌ Failed to send intent")
            return False
        
        time.sleep(10)
        
        pods = self.get_pods()
        print(f"📋 Found {len(pods)} pods")
        
        failed = []
        for from_pod in pods:
            for to_pod in pods:
                if from_pod != to_pod and self.test_connectivity(from_pod, to_pod):
                    failed.append(f"{from_pod} → {to_pod}")
        
        if failed:
            print(f"❌ FAILED: {len(failed)} connections succeeded")
            return False
        else:
            print("✅ PASSED: All traffic blocked")
            return True

if __name__ == "__main__":
    test = DenyAllTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
