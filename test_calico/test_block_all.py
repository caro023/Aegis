#!/usr/bin/env python3
"""
test_block_all.py
Test Intent: "block all traffic between all pods" (default-deny)

Verifica che NESSUN pod possa parlare con nessun altro pod.
Presuppone che la policy venga applicata e che non ci siano allow espliciti.

Uso:
  python3 test_block_all.py [namespace] [kubeteus_url]
  python3 test_block_all.py default http://localhost:9090
"""

import subprocess
import sys
import time
import requests


class TestBlockAll:
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
        print("🧪 TEST: Block All Traffic Between All Pods")
        print(f"   Namespace:   {self.namespace}")
        print(f"   KubeTeus:    {self.kubeteus_url}")
        print("="*60)

        # 1. Invia intento
        intent = "deny all traffic between all pods"
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
        for label in all_labels:
            name = self.get_pod_name(label)
            ip = self.get_pod_ip(label)
            print(f"  app={label:<25} {name} ({ip})")

        if len(all_labels) < 2:
            print("❌ Need at least 2 pods for meaningful test")
            return False

        # 4. Esegui i test di connettività (un sottoinsieme per non esagerare)
        print("\n🌐 Connectivity tests (sample):")
        print("-"*60)

        # Test alcune combinazioni rappresentative
        test_pairs = [
            ("frontend", "checkoutservice"),
            ("frontend", "cartservice"),
            ("cartservice", "checkoutservice"),
            ("emailservice", "frontend"),
            ("emailservice", "checkoutservice"),
            ("checkoutservice", "frontend"),
        ]

        results = {}
        for from_label, to_label in test_pairs:
            # Verifica che entrambi i pod esistano
            from_exists = self.get_pod_name(from_label) is not None
            to_exists = self.get_pod_name(to_label) is not None
            if from_exists and to_exists:
                connected = self.test_connectivity(from_label, to_label)
                results[(from_label, to_label)] = connected
            else:
                print(f"  ⚠ Skipping {from_label}→{to_label} (pod not found)")

        # 5. Report
        print("\n" + "="*60)
        print("📊 RESULTS")
        print("="*60)

        print("  Mode: default-deny (all traffic should be BLOCKED)")
        all_blocked = True
        for (from_label, to_label), connected in results.items():
            blocked = not connected
            print(f"  {from_label}→{to_label}: {'✅ BLOCKED' if blocked else '❌ CONNECTED'}")
            all_blocked = all_blocked and blocked

        overall = all_blocked

        print()
        if overall:
            print("✅ OVERALL: TEST PASSED - All traffic blocked")
        else:
            print("❌ OVERALL: TEST FAILED - Some traffic still flows")

        return overall


if __name__ == "__main__":
    namespace    = sys.argv[1] if len(sys.argv) > 1 else "default"
    kubeteus_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:9090"

    test = TestBlockAll(namespace=namespace, kubeteus_url=kubeteus_url)
    success = test.run_test()
    sys.exit(0 if success else 1)
