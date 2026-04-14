#!/usr/bin/env python3
import subprocess
import time
import sys
import requests

class IsolateDatabaseTest:
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
    
    def get_all_pods(self):
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, "-o", "jsonpath='{.items[*].metadata.name}'"],
            capture_output=True, text=True
        )
        return result.stdout.strip().strip("'").split()
    
    def get_pod_by_label(self, label):
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, 
             "-l", f"app={label}", "-o", "jsonpath='{.items[0].metadata.name}'"],
            capture_output=True, text=True
        )
        return result.stdout.strip().strip("'")
    
    def test_connectivity(self, from_pod, to_pod):
        cmd = f"kubectl exec -n {self.namespace} {from_pod} -- timeout 2 wget -q -O- http://{to_pod}:80 2>&1 || echo 'FAILED'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "FAILED" not in result.stdout and result.returncode == 0
    
    def run_test(self):
        print("\n🧪 TEST: Isolate Database")
        
        if not self.send_intent("isolate database pod, deny all ingress traffic"):
            print("❌ Failed to send intent")
            return False
        
        time.sleep(10)
        
        db_pod = self.get_pod_by_label("redis-cart")
        if not db_pod:
            db_pod = self.get_pod_by_label("database")
        
        if not db_pod:
            print("❌ Database pod not found")
            return False
        
        all_pods = self.get_all_pods()
        other_pods = [p for p in all_pods if p != db_pod]
        
        print(f"Database pod: {db_pod}")
        print(f"Testing {len(other_pods)} other pods...")
        
        failed = []
        for source in other_pods:
            if self.test_connectivity(source, db_pod):
                failed.append(source)
                print(f"  ❌ {source} → {db_pod}: CONNECTED (should be blocked)")
            else:
                print(f"  ✅ {source} → {db_pod}: blocked")
        
        if failed:
            print(f"\n❌ FAILED: {len(failed)} pods can reach database")
            return False
        else:
            print("\n✅ PASSED: Database is isolated")
            return True

if __name__ == "__main__":
    test = IsolateDatabaseTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
