#!/usr/bin/env python3
"""
Test Intent: "allow traffic from emailservice to all other pods"
Verifica che emailservice POSSA parlare con TUTTI gli altri pod
"""

import subprocess
import time
import sys
import requests

class AllowEmailServiceTest:
    def __init__(self, namespace="default", kubeteus_url="http://localhost:9090"):
        self.namespace = namespace
        self.kubeteus_url = kubeteus_url  # <--- QUESTA RIGA ERA MANCANTE!
        
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
    
    def get_pod_by_label(self, label):
        """Trova pod con label specifica"""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, 
             "-l", f"app={label}", "-o", "jsonpath='{.items[0].metadata.name}'"],
            capture_output=True, text=True
        )
        name = result.stdout.strip().strip("'")
        return name if name else None
    
    def test_connectivity(self, from_pod, to_pod):
        """Test connettività tra due pod"""
        if not from_pod or not to_pod:
            return False
        
        cmd = f"kubectl exec -n {self.namespace} {from_pod} -- timeout 2 wget -q -O- http://{to_pod}:80 2>&1 || echo 'FAILED'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return "FAILED" not in result.stdout and result.returncode == 0
    
    def run_test(self):
        print("\n" + "="*60)
        print("🧪 TEST: Allow EmailService to All Other Pods")
        print("="*60)
        
        # Invia intento a KubeTeus
        intent = "allow traffic from emailservice to all other pods"
        if not self.send_intent(intent):
            print("❌ Failed to send intent to KubeTeus")
            return False
        
        # Attendi che KubeTeus applichi le policy
        print("\n⏳ Waiting for KubeTeus to apply policies...")
        time.sleep(10)
        
        # Trova emailservice pod
        email_pod = self.get_pod_by_label("emailservice")
        if not email_pod:
            print("❌ Could not find emailservice pod")
            print("   Available pods:")
            subprocess.run(["kubectl", "get", "pods", "-n", self.namespace], capture_output=False)
            return False
        
        print(f"\n📋 EmailService pod: {email_pod}")
        
        # Ottieni tutti gli altri pod
        all_pods = self.get_all_pods()
        other_pods = [p for p in all_pods if p != email_pod]
        
        print(f"📋 Other pods to test: {len(other_pods)}")
        
        # Test emailservice → ogni altro pod
        print("\n🌐 Testing EmailService → All Pods...")
        failed_connections = []
        successful_connections = []
        
        for i, target in enumerate(other_pods):
            connected = self.test_connectivity(email_pod, target)
            if connected:
                successful_connections.append(target)
                print(f"  ✅ {email_pod[:30]} → {target[:30]}: SUCCESS")
            else:
                failed_connections.append(target)
                print(f"  ❌ {email_pod[:30]} → {target[:30]}: BLOCKED (should work!)")
            
            # Progress indicator
            if (i + 1) % 5 == 0:
                print(f"     Progress: {i+1}/{len(other_pods)}")
        
        # Report
        print("\n" + "="*60)
        print("📊 RESULTS")
        print("="*60)
        print(f"Total other pods: {len(other_pods)}")
        print(f"Successful connections: {len(successful_connections)}")
        print(f"Failed connections (should work): {len(failed_connections)}")
        
        if failed_connections:
            print("\n❌ FAILED CONNECTIONS (should work but blocked):")
            for fail in failed_connections[:10]:
                print(f"  - {email_pod} → {fail}")
            if len(failed_connections) > 10:
                print(f"  ... and {len(failed_connections) - 10} more")
            
            print("\n❌ TEST FAILED: EmailService cannot reach all pods")
            return False
        else:
            print("\n✅ TEST PASSED: EmailService can reach all pods")
            return True

if __name__ == "__main__":
    test = AllowEmailServiceTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
