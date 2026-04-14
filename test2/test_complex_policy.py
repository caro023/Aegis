#!/usr/bin/env python3
"""
Test Intent: "allow emailservice to talk to all pods, but block frontend to checkout"
Verifica policy complessa con più regole:
- EmailService → Tutti i pod: deve funzionare
- Frontend → Checkout: deve essere bloccato
- Frontend → Altri pod (es. Cart): deve funzionare
- Altri pod → Checkout: deve funzionare
"""

import subprocess
import time
import sys
import requests

class ComplexPolicyTest:
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
    
    def get_pod_by_label(self, label):
        """Trova pod con label specifica"""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace, 
             "-l", f"app={label}", "-o", "jsonpath='{.items[0].metadata.name}'"],
            capture_output=True, text=True
        )
        name = result.stdout.strip().strip("'")
        return name if name else None
    
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
        print("🧪 TEST: Complex Policy - Multiple Rules")
        print("="*60)
        print("Rules:")
        print("  1. EmailService → All pods: should SUCCEED")
        print("  2. Frontend → Checkout: should be BLOCKED")
        print("  3. Frontend → Other pods (Cart): should SUCCEED")
        print("  4. Other pods → Checkout: should SUCCEED")
        
        # Invia intento complesso a KubeTeus
        intent = "allow emailservice to talk to all pods, but block frontend to checkout service"
        if not self.send_intent(intent):
            print("❌ Failed to send intent to KubeTeus")
            return False
        
        # Attendi che KubeTeus applichi le policy
        print("\n⏳ Waiting for KubeTeus to apply policies...")
        time.sleep(10)
        
        # Trova tutti i pod necessari
        email_pod = self.get_pod_by_label("emailservice")
        frontend_pod = self.get_pod_by_label("frontend")
        checkout_pod = self.get_pod_by_label("checkoutservice")
        cart_pod = self.get_pod_by_label("cartservice")
        
        print(f"\n📋 Pods found:")
        print(f"   EmailService: {email_pod}")
        print(f"   Frontend: {frontend_pod}")
        print(f"   Checkout: {checkout_pod}")
        print(f"   CartService: {cart_pod}")
        
        if not email_pod:
            print("❌ EmailService pod not found")
            return False
        if not frontend_pod:
            print("❌ Frontend pod not found")
            return False
        if not checkout_pod:
            print("❌ Checkout pod not found")
            return False
        
        # Test 1: EmailService → Tutti i pod (deve funzionare)
        print("\n" + "="*60)
        print("🌐 TEST GROUP 1: EmailService → All Pods")
        print("="*60)
        
        all_pods = self.get_all_pods()
        other_pods = [p for p in all_pods if p != email_pod]
        
        email_failures = []
        email_successes = []
        
        for target in other_pods:
            connected = self.test_connectivity(email_pod, target)
            if connected:
                email_successes.append(target)
                print(f"  ✅ {email_pod[:25]} → {target[:25]}: SUCCESS")
            else:
                email_failures.append(target)
                print(f"  ❌ {email_pod[:25]} → {target[:25]}: BLOCKED (should work!)")
        
        test1_passed = len(email_failures) == 0
        
        # Test 2: Frontend → Checkout (deve essere bloccato)
        print("\n" + "="*60)
        print("🌐 TEST GROUP 2: Frontend → Checkout (should be BLOCKED)")
        print("="*60)
        
        frontend_to_checkout = self.test_connectivity(frontend_pod, checkout_pod)
        test2_passed = not frontend_to_checkout
        print(f"  {'✅ BLOCKED (correct)' if test2_passed else '❌ CONNECTED (wrong!)'}")
        
        # Test 3: Frontend → CartService (deve funzionare)
        print("\n" + "="*60)
        print("🌐 TEST GROUP 3: Frontend → CartService (should SUCCEED)")
        print("="*60)
        
        test3_passed = True
        if cart_pod:
            frontend_to_cart = self.test_connectivity(frontend_pod, cart_pod)
            test3_passed = frontend_to_cart
            print(f"  {'✅ SUCCESS (correct)' if test3_passed else '❌ BLOCKED (wrong!)'}")
        else:
            print("  ⚠ CartService not found, skipping test")
        
        # Test 4: CartService → Checkout (deve funzionare)
        print("\n" + "="*60)
        print("🌐 TEST GROUP 4: CartService → Checkout (should SUCCEED)")
        print("="*60)
        
        test4_passed = True
        if cart_pod:
            cart_to_checkout = self.test_connectivity(cart_pod, checkout_pod)
            test4_passed = cart_to_checkout
            print(f"  {'✅ SUCCESS (correct)' if test4_passed else '❌ BLOCKED (wrong!)'}")
        else:
            print("  ⚠ CartService not found, skipping test")
        
        # Test aggiuntivo 5: Altri pod casuali → Checkout (dovrebbe funzionare)
        print("\n" + "="*60)
        print("🌐 TEST GROUP 5: Other Pods → Checkout (should SUCCEED)")
        print("="*60)
        
        other_pods_excluding_frontend = [p for p in all_pods if p not in [email_pod, frontend_pod, checkout_pod]]
        other_failures = []
        
        for source in other_pods_excluding_frontend[:5]:  # Test massimo 5 pod casuali
            connected = self.test_connectivity(source, checkout_pod)
            if connected:
                print(f"  ✅ {source[:25]} → {checkout_pod[:25]}: SUCCESS")
            else:
                other_failures.append(source)
                print(f"  ❌ {source[:25]} → {checkout_pod[:25]}: BLOCKED (should work!)")
        
        test5_passed = len(other_failures) == 0
        
        # Report finale
        print("\n" + "="*60)
        print("📊 FINAL RESULTS")
        print("="*60)
        print(f"Test 1 (EmailService → All pods): {'✅ PASS' if test1_passed else '❌ FAIL'}")
        print(f"  - Successes: {len(email_successes)}/{len(other_pods)}")
        if email_failures:
            print(f"  - Failures: {email_failures[:3]}")
        
        print(f"\nTest 2 (Frontend → Checkout blocked): {'✅ PASS' if test2_passed else '❌ FAIL'}")
        print(f"Test 3 (Frontend → Cart works): {'✅ PASS' if test3_passed else '❌ FAIL'}")
        print(f"Test 4 (Cart → Checkout works): {'✅ PASS' if test4_passed else '❌ FAIL'}")
        print(f"Test 5 (Other pods → Checkout works): {'✅ PASS' if test5_passed else '❌ FAIL'}")
        
        # Diagnostica
        print("\n" + "="*60)
        print("📋 DIAGNOSIS")
        print("="*60)
        
        if test1_passed and test2_passed and test3_passed and test4_passed and test5_passed:
            print("\n✅ TEST PASSED: Complex policy correctly enforced")
            print("   - EmailService can reach all pods")
            print("   - Frontend → Checkout is blocked")
            print("   - Other traffic flows normally")
            return True
        else:
            print("\n❌ TEST FAILED: Complex policy not properly enforced")
            
            if not test1_passed:
                print("   - EmailService cannot reach some pods (policy too restrictive)")
            if not test2_passed:
                print("   - Frontend → Checkout is NOT blocked (policy missing)")
            if not test3_passed:
                print("   - Frontend → Cart is blocked (policy too restrictive)")
            if not test4_passed:
                print("   - Cart → Checkout is blocked (policy too restrictive)")
            
            return False

if __name__ == "__main__":
    test = ComplexPolicyTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
