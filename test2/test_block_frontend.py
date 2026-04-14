#!/usr/bin/env python3
import subprocess
import time
import sys
import requests

class BlockFrontendCheckoutTest:
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
        except Exception as e:
            print(f"Error: {e}")
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
        print("\n🧪 TEST: Block Frontend → Checkout")
        
        if not self.send_intent("block traffic from frontend to checkout service"):
            print("❌ Failed to send intent")
            return False
        
        time.sleep(10)
        
        frontend = self.get_pod_by_label("frontend")
        checkout = self.get_pod_by_label("checkoutservice")
        cart = self.get_pod_by_label("cartservice")
        
        print(f"Frontend: {frontend}")
        print(f"Checkout: {checkout}")
        print(f"Cart: {cart}")
        
        # Test 1: Frontend → Checkout (deve essere bloccato)
        test1 = not self.test_connectivity(frontend, checkout)
        
        # Test 2: Frontend → Cart (deve funzionare)
        test2 = self.test_connectivity(frontend, cart) if cart else True
        
        # Test 3: Cart → Checkout (deve funzionare)
        test3 = self.test_connectivity(cart, checkout) if cart else True
        
        print(f"\nTest 1 (Frontend→Checkout blocked): {'✅' if test1 else '❌'}")
        print(f"Test 2 (Frontend→Cart works): {'✅' if test2 else '❌'}")
        print(f"Test 3 (Cart→Checkout works): {'✅' if test3 else '❌'}")
        
        if test1 and test2 and test3:
            print("\n✅ TEST PASSED")
            return True
        else:
            print("\n❌ TEST FAILED")
            return False

if __name__ == "__main__":
    test = BlockFrontendCheckoutTest()
    success = test.run_test()
    sys.exit(0 if success else 1)
