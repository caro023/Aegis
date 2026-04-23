#!/usr/bin/env python3
"""
test_block_frontend.py
Test Intent: "block traffic from frontend to checkout service"

Verifica che frontend NON possa parlare con checkoutservice,
ma che altri traffici (cart→checkout, frontend→cart) funzionino.

Uso:
  python3 test_block_frontend.py [namespace] [kubeteus_url]
  python3 test_block_frontend.py default http://localhost:9090
"""

import subprocess
import sys
import time
import requests


class TestBlockFrontend:
    def __init__(self, namespace="default", kubeteus_url="http://localhost:9090"):
        self.namespace = namespace
        self.kubeteus_url = kubeteus_url

    # ------------------------------------------------------------------
    # KubeTeus
    # ------------------------------------------------------------------

    def send_intent(self, intent_text: str) -> bool:
        """Invia un intento a KubeTeus."""
        full_intent = f"In namespace {self.namespace}, {intent_text}"
        print(f"\n📤 Sending intent: '{full_intent}'")
        try:
            response = requests.post(
                f"{self.kubeteus_url}/intent",
                data=full_intent,
                headers={"Content-Type": "text/plain"},
                timeout=500
            )
            if response.status_code == 200:
                print("✅ Intent accepted by KubeTeus")
                return True
            else:
                print(f"❌ HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error contacting KubeTeus: {e}")
            return False

    # ------------------------------------------------------------------
    # Kubernetes helpers
    # ------------------------------------------------------------------

    def get_pod_name(self, app_label: str) -> str | None:
        """Ritorna il nome del primo pod Running con label app=<app_label>."""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace,
             "-l", f"app={app_label}",
             "--field-selector=status.phase=Running",
             "-o", "jsonpath={.items[0].metadata.name}"],
            capture_output=True, text=True
        )
        name = result.stdout.strip()
        return name if name else None

    def get_pod_ip(self, app_label: str) -> str | None:
        """Ritorna l'IP del primo pod Running con label app=<app_label>."""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace,
             "-l", f"app={app_label}",
             "--field-selector=status.phase=Running",
             "-o", "jsonpath={.items[0].status.podIP}"],
            capture_output=True, text=True
        )
        ip = result.stdout.strip()
        return ip if ip else None

    def get_network_policies(self):
        print(f"\n📋 NetworkPolicies in '{self.namespace}':")
        
        # Standard K8s
        result = subprocess.run(
            ["kubectl", "get", "networkpolicies", "-n", self.namespace],
            capture_output=True, text=True
        )
        print("K8s:", result.stdout if result.stdout.strip() else "  (none)")
        
        # Calico
        result = subprocess.run(
            ["kubectl", "get", "networkpolicies.crd.projectcalico.org", 
            "-n", self.namespace],
            capture_output=True, text=True
        )
        print("Calico:", result.stdout if result.stdout.strip() else "  (none)") 

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def test_connectivity(self, from_label: str, to_label: str,
                          port: int = 80) -> bool:
        """
        Testa connettività TCP da from_label → to_label:port.
        Ritorna True se la connessione riesce (HTTP 2xx o 3xx).
        """
        from_pod = self.get_pod_name(from_label)
        to_ip    = self.get_pod_ip(to_label)

        if not from_pod:
            print(f"  ⚠ Pod not found for app={from_label}")
            return False
        if not to_ip:
            print(f"  ⚠ IP not found for app={to_label}")
            return False

        cmd = [
            "kubectl", "exec", from_pod, "-n", self.namespace,
            "--", "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}",
            "--connect-timeout", "3",
            f"http://{to_ip}:{port}"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            http_code = result.stdout.strip()
            ok = http_code.startswith(("2", "3"))
            print(f"  {'✅' if ok else '❌'} {from_label} → {to_label}:{port}"
                  f"  (HTTP {http_code if http_code else 'no response'})")
            return ok
        except subprocess.TimeoutExpired:
            print(f"  ❌ {from_label} → {to_label}:{port}  (timeout)")
            return False

    # ------------------------------------------------------------------
    # Main test
    # ------------------------------------------------------------------

    def run_test(self) -> bool:
        print("\n" + "="*60)
        print("🧪 TEST: Block Frontend → CheckoutService")
        print(f"   Namespace:   {self.namespace}")
        print(f"   KubeTeus:    {self.kubeteus_url}")
        print("="*60)

        # 1. Invia intento
        intent = "block traffic from frontend to checkout service"
        if not self.send_intent(intent):
            print("❌ Could not send intent, aborting.")
            return False

        print("\n⏳ Waiting 10s for KubeTeus to apply the policy...")
        time.sleep(10)

        # 2. Mostra policy applicate
        self.get_network_policies()

        # 3. Verifica che i pod esistano
        print("\n🔍 Checking pods...")
        for label in ("frontend", "checkoutservice", "cartservice"):
            name = self.get_pod_name(label)
            ip   = self.get_pod_ip(label)
            status = f"{name} ({ip})" if name else "NOT FOUND"
            print(f"  app={label:<25} {status}")

        # 4. Esegui i test di connettività
        print("\n🌐 Connectivity tests:")
        print("-"*60)

        # Test principale: frontend → checkout (deve essere BLOCCATO)
        t1 = self.test_connectivity("frontend", "checkoutservice")
        t1_passed = not t1  # Deve fallire!

        # Test controllo: cartservice → checkout (deve funzionare)
        t2 = self.test_connectivity("cartservice", "checkoutservice")
        t2_passed = t2

        # Test controllo: frontend → cart (deve funzionare)
        t3 = self.test_connectivity("frontend", "cartservice")
        t3_passed = t3

        # Test aggiuntivo: emailservice → checkout (deve funzionare)
        t4 = self.test_connectivity("emailservice", "checkoutservice")
        t4_passed = t4

        # 5. Report
        print("\n" + "="*60)
        print("📊 RESULTS")
        print("="*60)

        print("  Mode: block specific policy")
        print(f"  Frontend→Checkout (should BLOCK): {'✅ PASS' if t1_passed else '❌ FAIL'}")
        print(f"  Cart→Checkout (should PASS):     {'✅ PASS' if t2_passed else '❌ FAIL'}")
        print(f"  Frontend→Cart (should PASS):     {'✅ PASS' if t3_passed else '❌ FAIL'}")
        print(f"  Email→Checkout (should PASS):    {'✅ PASS' if t4_passed else '❌ FAIL'}")

        overall = t1_passed and t2_passed and t3_passed and t4_passed

        print()
        if overall:
            print("✅ OVERALL: TEST PASSED")
        else:
            print("❌ OVERALL: TEST FAILED")

        return overall


if __name__ == "__main__":
    namespace    = sys.argv[1] if len(sys.argv) > 1 else "default"
    kubeteus_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:9090"

    test = TestBlockFrontend(namespace=namespace, kubeteus_url=kubeteus_url)
    success = test.run_test()
    sys.exit(0 if success else 1)
