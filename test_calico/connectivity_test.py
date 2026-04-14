#!/usr/bin/env python3
"""
connectivity_test.py - Test connectivity between microservices-demo pods
Crea pod temporanei con nicolaka/netshoot e le label app= corrette,
così le NetworkPolicy si applicano come se fossero i pod reali.
"""

import subprocess
import sys
import time
from datetime import datetime

# Porte reali dei servizi in microservices-demo
SERVICE_PORTS = {
    "adservice":              9555,
    "cartservice":            7070,
    "checkoutservice":        5050,
    "currencyservice":        7000,
    "emailservice":           5000,
    "frontend":               8080,
    "paymentservice":         50051,
    "productcatalogservice":  3550,
    "recommendationservice":  8080,
    "shippingservice":        50051,
    "redis-cart":             6379,
}

NETSHOOT_IMAGE = "nicolaka/netshoot"
TEST_POD_PREFIX = "netshoot-test"


class ConnectivityTest:
    def __init__(self, namespace="default"):
        self.namespace = namespace
        self.created_pods = []

    # ------------------------------------------------------------------
    # Pod management
    # ------------------------------------------------------------------

    def create_test_pod(self, app_label: str) -> str | None:
        """
        Crea un pod netshoot con label app=<app_label>.
        Le NetworkPolicy si applicano in base a questa label,
        simulando il comportamento del pod reale.
        """
        pod_name = f"{TEST_POD_PREFIX}-{app_label}"

        # Controlla se esiste già
        result = subprocess.run(
            ["kubectl", "get", "pod", pod_name, "-n", self.namespace,
             "-o", "jsonpath={.metadata.name}"],
            capture_output=True, text=True
        )
        if result.stdout.strip() == pod_name:
            return pod_name

        result = subprocess.run([
            "kubectl", "run", pod_name,
            "-n", self.namespace,
            f"--image={NETSHOOT_IMAGE}",
            "--restart=Never",
            f"--labels=app={app_label}",
            "--command", "--", "sleep", "3600"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"  ❌ Failed to create pod {pod_name}: {result.stderr.strip()}")
            return None

        self.created_pods.append(pod_name)
        return pod_name

    def wait_for_pod(self, pod_name: str, timeout: int = 60) -> bool:
        """Attende che il pod sia Running."""
        print(f"  ⏳ Waiting for {pod_name}...", end=" ", flush=True)
        for _ in range(timeout // 2):
            result = subprocess.run(
                ["kubectl", "get", "pod", pod_name, "-n", self.namespace,
                 "-o", "jsonpath={.status.phase}"],
                capture_output=True, text=True
            )
            if result.stdout.strip() == "Running":
                print("Ready")
                return True
            time.sleep(2)
        print("Timeout!")
        return False

    def get_pod_ip(self, app_label: str) -> str | None:
        """
        Ritorna l'IP del pod reale con label app=<app_label>.
        Testa verso i pod reali, non verso i pod netshoot,
        per verificare che le policy proteggano i target corretti.
        """
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace,
             "-l", f"app={app_label}",
             "--field-selector=status.phase=Running",
             "-o", "jsonpath={.items[0].status.podIP}"],
            capture_output=True, text=True
        )
        ip = result.stdout.strip()
        return ip if ip else None

    def delete_test_pods(self):
        """Elimina tutti i pod di test creati in questa sessione."""
        if not self.created_pods:
            return
        print(f"\n🧹 Deleting {len(self.created_pods)} test pods...")
        for pod_name in self.created_pods:
            subprocess.run(
                ["kubectl", "delete", "pod", pod_name, "-n", self.namespace,
                 "--ignore-not-found", "--grace-period=0"],
                capture_output=True
            )
        self.created_pods.clear()

    def cleanup_all(self):
        """Elimina tutti i pod netshoot-test-* nel namespace."""
        for app_label in SERVICE_PORTS:
            subprocess.run(
                ["kubectl", "delete", "pod",
                 f"{TEST_POD_PREFIX}-{app_label}",
                 "-n", self.namespace,
                 "--ignore-not-found", "--grace-period=0"],
                capture_output=True
            )

    # ------------------------------------------------------------------
    # Connectivity test
    # ------------------------------------------------------------------

    def test_tcp(self, from_app: str, to_ip: str, port: int) -> bool:
        """
        Testa connettività TCP dal pod netshoot-test-<from_app>
        verso to_ip:port usando nc (netcat), disponibile in netshoot.
        """
        from_pod = f"{TEST_POD_PREFIX}-{from_app}"
        cmd = [
            "kubectl", "exec", from_pod, "-n", self.namespace,
            "--", "sh", "-c",
            f"nc -z -w 3 {to_ip} {port} 2>/dev/null && echo OK || echo FAILED"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            return "OK" in result.stdout
        except subprocess.TimeoutExpired:
            return False

    # ------------------------------------------------------------------
    # Main test flows
    # ------------------------------------------------------------------

    def setup_test_pods(self, apps: list) -> bool:
        """Crea e attende tutti i pod di test necessari."""
        print(f"\n📦 Creating {len(apps)} test pods ({NETSHOOT_IMAGE})...")
        for app in apps:
            if not self.create_test_pod(app):
                return False
        print()
        for app in apps:
            if not self.wait_for_pod(f"{TEST_POD_PREFIX}-{app}"):
                return False
        return True

    def run_from_source(self, from_app: str) -> dict:
        """
        Testa tutte le connessioni uscenti da un singolo servizio.
        Utile per verificare intenti tipo "allow frontend to all".
        """
        print("\n" + "="*70)
        print(f"🔍 CONNECTIVITY FROM: {from_app}")
        print(f"   Namespace: {self.namespace}")
        print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)

        # Serve solo il pod del mittente — i target sono i pod reali
        if not self.setup_test_pods([from_app]):
            self.delete_test_pods()
            return {}

        print(f"\n🌐 Testing {from_app} → all services (real pod IPs)...\n")
        print(f"  {'Target':<28} {'IP':<16} {'Port':<7} Result")
        print("  " + "-"*62)

        results = {}
        for to_app, port in SERVICE_PORTS.items():
            if to_app == from_app:
                continue
            to_ip = self.get_pod_ip(to_app)
            if not to_ip:
                print(f"  {to_app:<28} {'N/A':<16} {port:<7} ⚠ pod not found")
                continue
            ok = self.test_tcp(from_app, to_ip, port)
            results[to_app] = ok
            status = "✅ REACHABLE" if ok else "❌ BLOCKED"
            print(f"  {to_app:<28} {to_ip:<16} {port:<7} {status}")

        passed = sum(1 for v in results.values() if v)
        print(f"\n  Result: {passed}/{len(results)} reachable")

        self.delete_test_pods()
        return results

    def run_full_matrix(self) -> dict:
        """
        Testa tutte le coppie source→target.
        Crea un pod netshoot per ogni servizio mittente.
        I target IP sono quelli dei pod reali.
        """
        print("\n" + "="*70)
        print("🔍 FULL CONNECTIVITY MATRIX")
        print(f"   Namespace: {self.namespace}")
        print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)

        apps = list(SERVICE_PORTS.keys())

        if not self.setup_test_pods(apps):
            self.delete_test_pods()
            return {}

        # Pre-fetch IP dei pod reali
        print("\n🔎 Fetching real pod IPs...")
        ips = {}
        for app in apps:
            ip = self.get_pod_ip(app)
            ips[app] = ip
            status = ip if ip else "NOT FOUND"
            print(f"  {app:<28} {status}")

        print(f"\n🌐 Testing all pairs...\n")
        print(f"  {'From':<25} {'To':<25} {'Port':<7} Result")
        print("  " + "-"*65)

        results = {}
        for from_app in apps:
            for to_app in apps:
                if from_app == to_app:
                    continue
                port = SERVICE_PORTS[to_app]
                to_ip = ips.get(to_app)
                if not to_ip:
                    continue
                ok = self.test_tcp(from_app, to_ip, port)
                results[(from_app, to_app)] = ok
                status = "✅" if ok else "❌"
                print(f"  {from_app:<25} {to_app:<25} {port:<7} {status}")

        self._print_summary(results)
        self.delete_test_pods()
        return results

    def _print_summary(self, results: dict):
        passed = [k for k, v in results.items() if v]
        failed = [k for k, v in results.items() if not v]
        total = len(results)

        print("\n" + "="*70)
        print("📊 SUMMARY")
        print("="*70)
        print(f"  Total:      {total}")
        print(f"  Reachable:  {len(passed)}")
        print(f"  Blocked:    {len(failed)}")
        if total > 0:
            print(f"  Rate:       {len(passed)/total*100:.1f}%")

        if failed:
            print(f"\n❌ Blocked ({len(failed)}):")
            for item in failed[:20]:
                if isinstance(item, tuple):
                    print(f"   {item[0]} → {item[1]}")
                else:
                    print(f"   {item}")
            if len(failed) > 20:
                print(f"   ... and {len(failed)-20} more")


if __name__ == "__main__":
    namespace = sys.argv[1] if len(sys.argv) > 1 else "default"
    from_app  = sys.argv[2] if len(sys.argv) > 2 else None

    tester = ConnectivityTest(namespace=namespace)
    try:
        if from_app:
            # Testa solo le connessioni uscenti da un servizio specifico
            # es: python3 connectivity_test.py default frontend
            tester.run_from_source(from_app)
        else:
            # Testa tutta la matrice
            tester.run_full_matrix()
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
    finally:
        tester.delete_test_pods()
