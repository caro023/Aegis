#!/usr/bin/env python3
"""
test_allow_frontend.py
Test Intent: "allow traffic from frontend to all other pods"

Funziona con pod nginx (hanno curl disponibile).
Presuppone che nel cluster sia attiva una default-deny policy,
altrimenti il test "dovrebbe essere bloccato" non ha senso.

Uso:
  python3 test_allow_frontend.py [namespace] [kubeteus_url]
  python3 test_allow_frontend.py default http://localhost:9090
"""

import subprocess
import sys
import time
import requests


class TestAllowFrontend:
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
                timeout=50
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

    def get_all_pod_labels(self) -> list:
        """Ritorna la lista di tutte le label app presenti nei pod Running."""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace,
             "--field-selector=status.phase=Running",
             "-o", "jsonpath={.items[*].metadata.labels.app}"],
            capture_output=True, text=True
        )
        labels = result.stdout.strip().split()
        return list(set(labels))

    def get_network_policies(self):
        """Mostra le NetworkPolicy attive nel namespace."""
        print(f"\n📋 NetworkPolicies in '{self.namespace}':")
        result = subprocess.run(
            ["kubectl", "get", "networkpolicies", "-n", self.namespace],
            capture_output=True, text=True
        )
        print(result.stdout if result.stdout.strip() else "  (none)")

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def test_connectivity(self, from_label: str, to_label: str,
                          port: int = 80) -> bool:
        """
        Testa connettività TCP da from_label → to_label:port
        usando curl dal pod reale.
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
        print("🧪 TEST: Allow Frontend → All Other Pods")
        print(f"   Namespace:   {self.namespace}")
        print(f"   KubeTeus:    {self.kubeteus_url}")
        print("="*60)

        # 1. Invia intento
        intent = "allow traffic from frontend to all other pods"
        if not self.send_intent(intent):
            print("❌ Could not send intent, aborting.")
            return False

        print("\n⏳ Waiting 10s for KubeTeus to apply the policy...")
        time.sleep(10)

        # 2. Mostra policy applicate
        self.get_network_policies()

        # 3. Verifica che i pod esistano
        print("\n🔍 Checking pods...")
        all_labels = self.get_all_pod_labels()
        frontend_pod = self.get_pod_name("frontend")
        if not frontend_pod:
            print("  ❌ frontend pod not found!")
            return False
        
        print(f"  app=frontend: {frontend_pod} ({self.get_pod_ip('frontend')})")
        other_labels = [l for l in all_labels if l != "frontend"]
        for label in other_labels:
            name = self.get_pod_name(label)
            ip = self.get_pod_ip(label)
            print(f"  app={label:<25} {name} ({ip})")

        # 4. Esegui i test di connettività
        print("\n🌐 Connectivity tests:")
        print("-"*60)

        # Test frontend → ogni altro pod
        results = {}
        for target in other_labels:
            results[target] = self.test_connectivity("frontend", target)

        # Test controllo: cartservice → checkoutservice (dovrebbe fallire con default-deny)
        t_cart_checkout = self.test_connectivity("cartservice", "checkoutservice")

        # 5. Report
        print("\n" + "="*60)
        print("📊 RESULTS")
        print("="*60)

        has_default_deny = self._check_default_deny()

        if has_default_deny:
            print("  Mode: default-deny active")
            print("  Frontend → Others (should ALL PASS):")
            all_passed = all(results.values())
            for target, passed in results.items():
                print(f"    → {target}: {'✅ PASS' if passed else '❌ FAIL'}")
            print(f"\n  Cart→Checkout (should FAIL): {'✅ PASS' if not t_cart_checkout else '❌ FAIL'}")
            overall = all_passed and not t_cart_checkout
        else:
            print("  Mode: no default-deny (permissive)")
            print("  Frontend → Others (should ALL PASS):")
            all_passed = all(results.values())
            for target, passed in results.items():
                print(f"    → {target}: {'✅ PASS' if passed else '❌ FAIL'}")
            overall = all_passed

        print()
        if overall:
            print("✅ OVERALL: TEST PASSED")
        else:
            print("❌ OVERALL: TEST FAILED")

        return overall

    def _check_default_deny(self) -> bool:
        """Controlla se esiste una NetworkPolicy di default-deny."""
        result = subprocess.run(
            ["kubectl", "get", "networkpolicies", "-n", self.namespace,
             "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True
        )
        names = result.stdout.strip()
        return "deny" in names.lower() or "default" in names.lower()


if __name__ == "__main__":
    namespace    = sys.argv[1] if len(sys.argv) > 1 else "default"
    kubeteus_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:9090"

    test = TestAllowFrontend(namespace=namespace, kubeteus_url=kubeteus_url)
    success = test.run_test()
    sys.exit(0 if success else 1)
