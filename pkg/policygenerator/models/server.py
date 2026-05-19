import os
import re
import argparse
from flask import Flask, request, jsonify, Response
from groq import Groq
from langgraph.graph import StateGraph, END
from typing import TypedDict
from typing import Annotated
from ollama import Client
import threading
import queue
import signal

app = Flask(__name__)
VALIDATOR_MODEL = "qwen/qwen3-32b"
INTENT_MODEL = "llama-3.3-70b-versatile"

LLM_TIMEOUT_SECONDS = 180
REQUEST_TIMEOUT_SECONDS = 300

ollama_client = Client(
    host="https://ollama.com",
    headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')},
    timeout = LLM_TIMEOUT_SECONDS 
)
INTENT_TRANSLATOR_PROMPT = """You are a Kubernetes network security expert.
Your task is to translate a high-level security intent into a detailed technical prompt for generating a Kubernetes network policy.

The output must be a single sentence or short paragraph describing:
- Which pod or service is the source (use the pod name and label if provided)
- ALWAYS use the EXACT service name as label value, never truncate it
- The traffic direction (ingress or egress)
- The destination pod or service (if specified)
- The port and protocol (if specified or inferable)
- The action (allow or deny)
- The policy type to generate (always end with: Generate a CiliumNetworkPolicy, CalicoNetworkPolicy or NetworkPolicy)

LABEL RULE (MANDATORY):
- ALWAYS use 'app == "podname"' as selector. Example: frontend → app == "frontend"
- NEVER truncate service names: "checkout service" → app == "checkoutservice" NOT app == "checkout"
- NEVER use other keys like 'service', 'name', 'component', 'pod'.
- NEVER invent label keys

DIRECTION RULE (MANDATORY):
- "A allows/blocks traffic TO B" → this is an EGRESS policy on A, or INGRESS policy on B
- EGRESS = traffic leaving the source pod
- INGRESS = traffic arriving at the destination pod
- "A talks to B" → egress from A AND ingress on B
- If bidirectional → include both directions

OUTPUT FORMAT:
- One paragraph only
- Include: source pod label, direction, destination pod label, port/protocol, action, policy type
- End with the exact policy type from the input (e.g. "Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1.")

If the intent is too generic or does not mention specific pods, infer reasonable defaults based on common Kubernetes security practices.
IMPORTANT: If the input specifies a policy type (e.g. "Generate a CalicoNetworkPolicy" or "Generate a CiliumNetworkPolicy"), you MUST preserve that exact instruction at the end of your output.
DENY/ALLOW DISAMBIGUATION (MANDATORY):
- If the intent uses words like "block", "deny", "restrict", "drop" → the action is DENY.
- If the intent uses words like "allow", "permit", "enable" → the action is ALLOW.
- Always state the action explicitly as "allow" or "deny" in your output.
- Never use ambiguous terms like "control" or "manage".
Output ONLY the translated prompt, no explanations."""

SYSTEM_PROMPT_CALICO = """You are a Kubernetes security engineer.
Your task is to generate valid, production-ready YAML for CalicoNetworkPolicy or standard NetworkPolicy.

STRICT SYNTAX RULES FOR CALICO:
1. Use 'kind: NetworkPolicy' and 'apiVersion: crd.projectcalico.org/v1' or the one passed.
2. 'spec.selector' is a string expression: e.g. 'app == "frontend"'.
3. Each ingress/egress rule MUST have 'action' inside the rule itself.
4. Use 'source.selector' to match source pods. NEVER use 'from'.
5. Use 'destination.selector' to match destination pods. NEVER use 'to'.
6. NEVER include 'protocol' or 'ports' unless explicitly required.
7. NEVER output empty arrays: protocol: [] or ports: [] is FORBIDDEN.
8. 'egress' must be a list [] or omitted entirely. NEVER use egress: {}.
9. To allow/deny traffic to ALL destinations, omit 'destination' entirely. NEVER use destination: {}.
10. DO NOT use Kubernetes NetworkPolicy fields such as:
  - policyTypes
  - to
  - from
  - type
- Use:
  - action
  - source / destination
  - selector

  REQUIRED FIELDS:
- metadata.namespace MUST always be present and set to: default
- NEVER omit metadata.namespace

  FORBIDDEN FIELDS (NEVER use these):
- policyTypes    ← Kubernetes field, NOT Calico
- types          ← also forbidden, Calico does not need it
- from           ← use 'source' instead
- to             ← use 'destination' instead

FORBIDDEN PATTERNS:
- NEVER add 'source: {}' to egress rules
- NEVER add 'destination: {}' to ingress rules  
- An egress rule has ONLY: action + destination (optional)
- An ingress rule has ONLY: action + source (optional)

CROSS-NAMESPACE DESTINATION (MANDATORY):
- When the destination pod is in a different namespace than the source,
  you MUST use 'namespaceSelector' alongside 'selector'
- NEVER assume all pods are in the same namespace
- Common cross-namespace destinations:
    kube-dns     → namespace: kube-system, label: k8s-app == "kube-dns"
    istio-pilot  → namespace: istio-system
    metrics      → namespace: monitoring

SELECTOR FOR ALL PODS:
- To apply a policy to ALL pods in a namespace: selector: all()
- NEVER list individual pod labels when the intent says "all pods"

PROTOCOL + PORT COMBINATIONS:
- When a protocol is specified, always include BOTH TCP and UDP unless
  the intent explicitly restricts to one:
    DNS (port 53)   → both TCP and UDP
    HTTP (port 80)  → TCP only
    HTTPS (port 443) → TCP only
    Custom protocol → follow intent; if not specified, allow both TCP and UDP

PORTS IN DESTINATION (CALICO):
- Ports go inside destination (for egress) or source (for ingress)
- Port values MUST be integers: ports: [53] not ports: [{port: 53, protocol: UDP}]
- Protocol goes at rule level: protocol: UDP

PORTS SYNTAX (CRITICAL):
- Ports go inside destination (for egress) or source (for ingress), NOT as a separate list
- Port values MUST be integers, not objects
- CORRECT:
  egress:
  - action: Allow
    destination:
      selector: app == "redis-cart"
      ports:
      - 6379        ← integer only, no protocol/port object
- INCORRECT:
  destination:
    ports:
    - protocol: TCP   ← FORBIDDEN, port must be integer not object
      port: 6379
- If protocol is needed, specify it at rule level:
  protocol: TCP
  destination:
    selector: app == "redis-cart"
    ports:
    - 6379

If a policy defines Egress or Ingress rules, all other traffic is implicitly denied unless explicitly allowed.

Therefore:
- If the intent is to block specific traffic ONLY,
- You MUST add a final "Allow" rule to permit all other traffic.

CORRECT Calico example (use this as reference):
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: allow-cart-to-checkout
  namespace: default
spec:
  selector: app == "checkoutservice"
  ingress:
  - action: Allow
    source:
      selector: app == "cartservice"

CORRECT example:
  ingress:
  - action: Allow
    source:             # ← not "from"
      selector: app == "cartservice"
    destination:          # ← ports inside destination
      ports:
      - 80          # ← integer, not "0-65535"
"""

SYSTEM_PROMPT_CILIUM = """You are a Kubernetes security engineer.
Your task is to generate valid, production-ready YAML for CiliumNetworkPolicy.

STRICT SYNTAX RULES FOR CILIUM:
1. Use 'kind: CiliumNetworkPolicy' and 'apiVersion: cilium.io/v2' or the one passed.
2. 'spec.endpointSelector' uses 'matchLabels': e.g. matchLabels: {app: frontend}.
3. Use 'fromEndpoints' with 'matchLabels' to match source pods. NEVER use 'from' or 'selector:'.
4. Use 'toEndpoints' with 'matchLabels' to match destination pods. NEVER use 'to' or 'selector:'.
5. Ports MUST be strings: port: "80", NOT port: 80.
6. Protocol MUST be uppercase: TCP, UDP, SCTP, ANY.
7. NEVER use 'action', 'Allow', 'Deny' — these are Calico fields.
8. NEVER use 'policyTypes', 'rules', 'podSelector', 'namespaceSelector'.
9. NEVER use 'selector: app == "name"' — this is Calico syntax, FORBIDDEN in Cilium.
10. metadata.namespace MUST always be present and set to: default.

REQUIRED FIELDS:
- metadata.namespace MUST always be present.
- spec.endpointSelector MUST always be present.
- toPorts MUST always be present in allow rules (ingress and egress).

FORBIDDEN FIELDS (NEVER use these):
- selector:          ← Calico field, FORBIDDEN in Cilium
- action:            ← Calico field, FORBIDDEN in Cilium
- policyTypes:       ← Kubernetes field, FORBIDDEN in Cilium
- from:              ← use 'fromEndpoints' instead
- to:                ← use 'toEndpoints' instead
- podSelector:       ← Kubernetes field, FORBIDDEN in Cilium
- namespaceSelector: ← Kubernetes field, FORBIDDEN in Cilium

BIDIRECTIONAL COMMUNICATION (CRITICAL):
- If intent says "X talks to Y", "allow X to communicate with Y", or similar:
  - MUST generate TWO separate policies:
    1. Egress policy on X (source) allowing traffic to Y
    2. Ingress policy on Y (destination) allowing traffic from X
  - NEVER generate only one side.
  - Separate the two policies with '---'.

DENY RULES:
- Use 'ingressDeny' or 'egressDeny' instead of 'ingress' or 'egress'.
- NEVER use toPorts inside deny rules.
- CORRECT:
  ingressDeny:
  - fromEndpoints:
    - matchLabels:
        app: frontend

PORTS SYNTAX (CRITICAL):
- Ports go inside 'toPorts', which contains a 'ports' list.
- Port values MUST be strings: port: "80" not port: 80.
- Protocol goes inside the port object: protocol: TCP.
- CORRECT:
  toPorts:
  - ports:
    - port: "80"
      protocol: TCP
- INCORRECT:
  toPorts:
  - port: 80          ← FORBIDDEN, must be inside ports list
  - protocol: TCP     ← FORBIDDEN, must be inside port object

PORT DEFAULTS:
- If intent specifies a port → use that port as a string.
- If intent does NOT specify a port → use port "80" protocol TCP.
- NEVER use port: "*"     ← invalid, causes enforcement failure
- NEVER use port: "0"     ← invalid
- NEVER use port: "0-65535" ← invalid range syntax
- NEVER use "*" as port value.
- DNS (port 53) → use both TCP and UDP rules.
- HTTP (port 80) → TCP only.
- HTTPS (port 443) → TCP only.

ALLOW ALL ENDPOINTS:
- To allow traffic from/to any pod: use an empty matchLabels: {}.
- CORRECT:
  fromEndpoints:
  - matchLabels: {}

CORRECT Cilium example (use this as reference):
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-frontend-to-checkoutservice
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  - toEndpoints:
    - matchLabels:
        app: checkoutservice
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-checkoutservice-from-frontend
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: checkoutservice
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP

DO NOT USE <think> TAGS.
DO NOT REASON ABOUT THE RULES.
JUST OUTPUT THE YAML.
Return ONLY valid YAML.
Do not include explanations.
Do not include markdown backticks.
Do not include reasoning or <think> tags.
Output MUST start with: apiVersion:
"""


VALIDATION_PROMPT_CALICO = """You are a Kubernetes network policy validator and fixer.

Your task:
- Validate that the given YAML correctly implements the provided technical intent.
- If the YAML is incorrect, fix it. If correct, return VALID.

OUTPUT RULES (MANDATORY):
- Return ONLY the word VALID or the corrected YAML.
- NO explanations, comments, markdown, or reasoning.
- NO text before or after the YAML.

BIDIRECTIONAL VALIDATION RULE (CRITICAL):
- If the intent implies communication between two services (e.g. "X talks to Y"):
  - The policies created MUST include:
    - Egress from X to Y
    - AND ingress on Y from X
    So there must be at least 2 policies

- For DENY intents:
  - If blocking X → Y:
    - Ensure egress from X to Y is denied
    - AND no rule allows ingress from X to Y

- Reject policies that only define one side when two-sided communication is required.

SYNTAX (CRITICAL - always enforce):
- ingress rules: use 'source' to match origin pods. NEVER use 'from'.
- egress rules: use 'destination' to match target pods. NEVER use 'to'.
- NEVER use 'podSelector' or 'namespaceSelector'.
- 'egress' and 'ingress' MUST be lists, never objects ({}).
- If 'from', 'to', 'podSelector', 'namespaceSelector' are found → replace them.
- The kind policy for Calico is NetworkPolicy

IMPLICIT DENY RULE — READ CAREFULLY:
- This rule applies ONLY when ALL three conditions are true:
  1. The intent contains "block", "deny", "restrict", or "drop"
  2. AND the YAML contains at least one "action: Deny" rule
  3. AND there is no existing "- action: Allow" without destination/source

- For a policy that contains ONLY "action: Allow" rules → it is a pure Allow policy
  → DO NOT add anything → return VALID if everything else is correct

- EXAMPLE of pure Allow policy — return VALID, do NOT modify:
  egress:
  - action: Allow
    destination:
      selector: app == "checkoutservice"
  # ← do NOT add "- action: Allow" here

CROSS-NAMESPACE DESTINATION (MANDATORY):
- When the destination pod is in a different namespace than the source,
  you MUST use 'namespaceSelector' alongside 'selector'
- NEVER assume all pods are in the same namespace
- Common cross-namespace destinations:
    kube-dns     → namespace: kube-system, label: k8s-app == "kube-dns"
    istio-pilot  → namespace: istio-system
    metrics      → namespace: monitoring

SELECTOR FOR ALL PODS:
- To apply a policy to ALL pods in a namespace: selector: all()
- NEVER list individual pod labels when the intent says "all pods"

PROTOCOL + PORT COMBINATIONS:
- When a protocol is specified, always include BOTH TCP and UDP unless
  the intent explicitly restricts to one:
    DNS (port 53)   → both TCP and UDP
    HTTP (port 80)  → TCP only
    HTTPS (port 443) → TCP only
    Custom protocol → follow intent; if not specified, allow both TCP and UDP

PORTS IN DESTINATION (CALICO):
- Ports go inside destination (for egress) or source (for ingress)
- Port values MUST be integers: ports: [53] not ports: [{port: 53, protocol: UDP}]
- Protocol goes at rule level: protocol: UDP

STRUCTURE VALIDATION:
- Must start with apiVersion
- Must include: kind, metadata.name, metadata.namespace, spec.selector
- spec.selector must use Calico syntax (e.g. app == "name"), not matchLabels
- If metadata.namespace is missing → ADD it with value "default"
- FORBIDDEN fields: policyTypes, types, from, to — if present → REMOVE them

STRICT CALICO FIELD VALIDATION:
- If an egress rule contains 'source' → INVALID → REMOVE it
- If an ingress rule contains 'destination' → INVALID → REMOVE it
- If 'source: {}' or 'destination: {}' appears → INVALID → REMOVE it

PORTS SYNTAX (CRITICAL):
- Ports go inside destination (for egress) or source (for ingress), NOT as a separate list
- Port values MUST be integers, not objects
- CORRECT:
  egress:
  - action: Allow
    destination:
      selector: app == "redis-cart"
      ports:
      - 6379       ← integer only, no protocol/port object
- INCORRECT:
  destination:
    ports:
    - protocol: TCP   ← FORBIDDEN, port must be integer not object
      port: 6379
- If protocol is needed, specify it at rule level:
  protocol: TCP
  destination:
    selector: app == "redis-cart"
    ports:               ← WRONG, ports are not inside source
    - 6379

INTENT MATCHING:
- Source/destination labels must match intent exactly using app == "podname"
- Direction (Ingress/Egress) must match intent
- Action (Allow/Deny) must match intent

If everything is correct → return: VALID
Otherwise → return the full corrected YAML."""


VALIDATION_PROMPT_CILIUM = """You are a Kubernetes security engineer.
Your task is to validate and fix a CiliumNetworkPolicy YAML against a provided intent.

OUTPUT RULES (MANDATORY):
- Return ONLY the word VALID or the full corrected YAML.
- NO explanations, comments, markdown, or reasoning.
- NO text before or after the YAML.

FORBIDDEN SYNTAX (if ANY found → REMOVE or REPLACE):
- 'selector: app == "..."'    ← Calico syntax, FORBIDDEN in Cilium
- 'selector:'                 ← unless inside matchLabels context
- 'action:'                   ← Calico field, FORBIDDEN
- 'from:' or 'to:'            ← use fromEndpoints/toEndpoints instead
- 'policyTypes:'              ← Kubernetes field, FORBIDDEN
- 'rules:'                    ← FORBIDDEN
- 'podSelector:'              ← Kubernetes field, FORBIDDEN
- 'namespaceSelector:'        ← Kubernetes field, FORBIDDEN
- Integer ports: port: 80     ← FORBIDDEN, must be string: port: "80"

STRUCTURE VALIDATION (check in this order):
1. apiVersion must be 'cilium.io/v2'.
2. kind must be 'CiliumNetworkPolicy'.
3. metadata.name must exist in kebab-case.
4. metadata.namespace must exist → if missing, ADD it with value 'default'.
5. spec.endpointSelector must exist with matchLabels.
6. Ingress/egress rules must use fromEndpoints/toEndpoints with matchLabels.
7. Allow rules MUST have toPorts with port (string) and protocol.
8. Deny rules MUST use ingressDeny/egressDeny and MUST NOT have toPorts.

LABEL VALIDATION:
- Must use: matchLabels: { app: <name> }
- If 'selector: app == "name"' found → REPLACE with matchLabels: { app: name }
- If matchLabels is missing → ADD it.

PORTS VALIDATION:
- Port values MUST be strings: port: "80" not port: 80.
- Protocol MUST be uppercase: TCP, UDP, SCTP, ANY.
- Ports MUST be nested inside toPorts → ports list.
- If port is integer → convert to string.
- NEVER use port: "*"     ← invalid, causes enforcement failure
- NEVER use port: "0"     ← invalid
- NEVER use port: "0-65535" ← invalid range syntax
- If intent says "all ports" → OMIT toPorts entirely

BIDIRECTIONAL VALIDATION (CRITICAL):
- If the intent implies communication between X and Y:
  - MUST have egress from X to Y AND ingress on Y from X.
  - If only one side is present → ADD the missing side.
  - Separate multiple policies with '---'.

DENY RULE VALIDATION:
- Deny rules MUST use 'ingressDeny' or 'egressDeny'.
- Deny rules MUST NOT contain toPorts.
- If a deny rule contains toPorts → REMOVE toPorts.

INTENT MATCHING:
- Source/destination labels must match intent exactly.
- Direction (ingress/egress) must match intent.
- Allow vs Deny must match intent.

CORRECT Cilium example (use as reference):
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-cartservice-to-checkoutservice
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: cartservice
  egress:
  - toEndpoints:
    - matchLabels:
        app: checkoutservice
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP

If ALL checks pass → return: VALID
Otherwise → return the full corrected YAML.
"""
TEST_GENERATOR_PROMPT = """
#!/bin/bash is the ONLY valid first line of your response.

You are a connectivity tester, NOT a policy generator.
NEVER use kubectl apply. NEVER output YAML. NEVER define policies.
The policy is already applied — you only test if it works.

FORBIDDEN:
- kubectl apply, kubectl create
- Any YAML content: apiVersion, kind, metadata, spec
- Inventing service names not provided by the user
- Using a tool not listed as available in the source pod

REQUIRED:
- kubectl get pods
- kubectl get svc
- kubectl exec ... <tool>

TOOL SELECTION (MANDATORY)
The user will tell you which tools are available in the source pod.
ONLY use tools listed as available. If HTTP priority: curl > wget > nc > /dev/tcp. Else priority_ /dev/tcp > nc > wget
If none are available → print "SKIP: no connectivity tools available in pod" and exit 0
BY PORT (MANDATORY - NO EXCEPTIONS):
- Read SVC_PORT from the Service spec FIRST
- IF SVC_PORT == 80 OR SVC_PORT == 8080 → use curl
- IF SVC_PORT is anything else → use nc
- NEVER use curl on ports like 3550, 7070, 6379, 50051, 5000, 5050

PORT RESOLUTION (CRITICAL — NEVER HARDCODE PORTS):
- ALWAYS read both the ClusterIP and the port from the Service spec:
  SVC_IP=$(kubectl get svc <service> -o jsonpath='{.spec.clusterIP}')
  SVC_PORT=$(kubectl get svc <service> -o jsonpath='{.spec.ports[0].port}')
- NEVER hardcode port 80 or any other port
- Use $SVC_PORT in ALL curl/nc/wget commands
- This is mandatory because services expose non-standard ports (e.g. 3550, 7070, 6379, 50051)

TOOL SELECTION BY PORT (CRITICAL):
- Port 80 or 8080 → use curl if available
- Any other port (3550, 7070, 6379, 50051, 5000, etc.) → use nc if available
- If nc not available for non-HTTP ports → use /dev/tcp
- NEVER use curl on non-HTTP ports like 6379, 3550, 50051

DNS WARNING (CRITICAL):
- NEVER use hostnames like http://checkoutservice:80
- ALWAYS resolve the ClusterIP first and use the IP directly
- Reason: egress policies may block DNS (port 53 UDP) causing hostname
  resolution to fail even when the actual connection would be allowed

TEST METHOD BY TOOL AND PORT

WITH CURL (only for HTTP ports 80, 8080):
  SVC_IP=$(kubectl get svc <service> -o jsonpath='{.spec.clusterIP}')
  SVC_PORT=$(kubectl get svc <service> -o jsonpath='{.spec.ports[0].port}')
  HTTP_CODE=$(kubectl exec $SOURCE_POD -- curl --max-time 3 -s -o /dev/null \
    -w "%{http_code}" http://$SVC_IP:$SVC_PORT 2>/dev/null)
  EXIT_CODE=$?
  ALLOW check: EXIT_CODE == 0 AND HTTP_CODE != "000" → SUCCESS
  DENY  check: EXIT_CODE != 0 OR  HTTP_CODE == "000" → SUCCESS

WITH NC (for any port, mandatory for non-HTTP):
  SVC_IP=$(kubectl get svc <service> -o jsonpath='{.spec.clusterIP}')
  SVC_PORT=$(kubectl get svc <service> -o jsonpath='{.spec.ports[0].port}')
  kubectl exec $SOURCE_POD -- nc -zw3 $SVC_IP $SVC_PORT >/dev/null 2>&1
  EXIT_CODE=$?
  ALLOW check: EXIT_CODE == 0 → SUCCESS
  DENY  check: EXIT_CODE != 0 → SUCCESS

WITH /dev/tcp (fallback when nc not available):
  SVC_IP=$(kubectl get svc <service> -o jsonpath='{.spec.clusterIP}')
  SVC_PORT=$(kubectl get svc <service> -o jsonpath='{.spec.ports[0].port}')
  kubectl exec $SOURCE_POD -- bash -c \
    "echo > /dev/tcp/$SVC_IP/$SVC_PORT" >/dev/null 2>&1
  EXIT_CODE=$?
  ALLOW check: EXIT_CODE == 0 → SUCCESS
  DENY  check: EXIT_CODE != 0 → SUCCESS

SCRIPT STRUCTURE (follow exactly)
#!/bin/bash
set -uo pipefail

SOURCE_POD=$(kubectl get pods -l app=<source> -o jsonpath='{.items[0].metadata.name}')

kubectl get svc <allowed-service> >/dev/null 2>&1 || { echo "SKIP: <allowed-service> not found"; exit 0; }
ALLOWED_SVC_IP=$(kubectl get svc <allowed-service> -o jsonpath='{.spec.clusterIP}')
ALLOWED_SVC_PORT=$(kubectl get svc <allowed-service> -o jsonpath='{.spec.ports[0].port}')

kubectl get svc <blocked-service> >/dev/null 2>&1 || { echo "SKIP: <blocked-service> not found"; exit 0; }
BLOCKED_SVC_IP=$(kubectl get svc <blocked-service> -o jsonpath='{.spec.clusterIP}')
BLOCKED_SVC_PORT=$(kubectl get svc <blocked-service> -o jsonpath='{.spec.ports[0].port}')

echo "=== ALLOWED CONNECTIONS ==="
RESULT=0
for i in 1 2 3 4 5; do
  # Use nc for non-HTTP ports, curl for HTTP ports
  <test command using $ALLOWED_SVC_IP and $ALLOWED_SVC_PORT>
  if [ <success condition> ]; then
    echo "SUCCESS: <source> -> <allowed-service>:$ALLOWED_SVC_PORT is allowed"
    RESULT=1
    break
  fi
  sleep 2
done
if [ $RESULT -eq 0 ]; then
  echo "FAIL: <source> -> <allowed-service>:$ALLOWED_SVC_PORT should be allowed but is blocked"
fi

echo "=== BLOCKED CONNECTIONS ==="
RESULT=0
for i in 1 2 3 4 5; do
  <test command using $BLOCKED_SVC_IP and $BLOCKED_SVC_PORT>
  if [ <success condition> ]; then
    echo "SUCCESS: <source> -> <blocked-service>:$BLOCKED_SVC_PORT is blocked"
    RESULT=1
    break
  fi
  sleep 2
done
if [ $RESULT -eq 0 ]; then
  echo "FAIL: <source> -> <blocked-service>:$BLOCKED_SVC_PORT should be blocked but is allowed"
fi

BLOCKED SERVICE SELECTION:
- The user will explicitly provide SOURCE POD and may provide ALLOWED SERVICE
  and BLOCKED SERVICE
- Use EXACTLY those names — NEVER invent or discover services dynamically
- NEVER use kubectl get svc with label selectors to find services
- NEVER use grep, awk, or head to parse service lists
- If BLOCKED SERVICE is empty → omit the BLOCKED CONNECTIONS section entirely

INTENT TYPE HANDLING:
- If intent is BLOCK type: only test that the specified connections are blocked
- If intent is ALLOW type: test that allowed connections work AND optionally
  that unrelated connections behave as expected

CRITICAL ANTI-LOOP RULE:
- If a service (allowed or blocked) is NOT provided, DO NOT try to infer it
- DO NOT reason about missing services
- Simply skip that section
- NEVER attempt to figure out missing inputs

SERVICE NOT FOUND HANDLING:
Before using any service, verify it exists:
  kubectl get svc <service> >/dev/null 2>&1 || { echo "SKIP: <service> not found"; exit 0; }

FAIL FALLBACK (MANDATORY):
After each loop, if no SUCCESS was printed → print FAIL.
Always use the RESULT variable pattern:

  RESULT=0
  for i in 1 2 3 4 5; do
    <test command>
    if [ <success condition> ]; then
      echo "SUCCESS: ..."
      RESULT=1
      break
    fi
    sleep 2
  done
  if [ $RESULT -eq 0 ]; then
    echo "FAIL: ..."
  fi

DO NOT THINK.
DO NOT EXPLAIN.
OUTPUT ONLY THE FINAL SCRIPT.
NO <think> blocks.
"""

GROQ_MODEL = None

def get_args():
    parser = argparse.ArgumentParser(description="Run a Flask server for text generation using Groq API.")
    parser.add_argument("--model", type=str, required=True, help="Groq model ID to use.")
    parser.add_argument("--port", type=int, required=True, help="Port for the Flask server.")
    return parser.parse_args()

request_queue = queue.Queue(maxsize=50)
_shutdown_event = threading.Event()

def worker_loop():
    while not _shutdown_event.is_set():
        try:
            item = request_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        payload, result_holder, done_event = item
        try:
            result = generate_text(payload["prompt"], payload.get("pod_discovery", []))
            result_holder["result"] = result
            result_holder["error"] = None
        except Exception as e:
            result_holder["result"] = None
            result_holder["error"] = str(e)
        finally:
            done_event.set()
            request_queue.task_done()

def translate_intent(intent, client):
    """Use LLM1 to generate a more detailed prompt."""
    completion = client.chat.completions.create(
        model=INTENT_MODEL,
        messages=[
            {"role": "system", "content": INTENT_TRANSLATOR_PROMPT},
            {"role": "user", "content": intent}
        ],
        temperature=0.2,
        max_tokens=256,
        timeout=LLM_TIMEOUT_SECONDS,
    )
    translated = completion.choices[0].message.content.strip()
    print(f"Translated prompt: {translated}", flush=True)
    return translated


def extract_yaml(text):
    """Remove <think> and markdown code blocks, return just YAML."""
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    
    match = re.search(r"```(?:ya?ml)?\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()

def extract_script(text: str) -> str:
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()

    match = re.search(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL)
    if match:
        candidate = match.group(1).strip()
        if candidate.startswith("#!/bin/bash"):
            return candidate

    match = re.search(r'(#!/bin/bash.*)', text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return ""

    
def format_pod_discovery(pod_discovery: list) -> str:
    """
    Converte la lista di PodDiscoveryInfo (dal controller Go) 
    in una stringa leggibile dall'LLM.
    """
    if not pod_discovery:
        return "No pod discovery info available."

    lines = []
    for pod in pod_discovery:
        name      = pod.get("name", "unknown")
        namespace = pod.get("namespace", "default")
        ports     = pod.get("ports", [])
        tools     = pod.get("availableTools", [])
        labels    = pod.get("labels", {})

        port_strs = [f"{p['port']}/{p['protocol']}" for p in ports] if ports else ["none"]
        tool_strs = tools if tools else ["none"]
        label_str = ", ".join(f"{k}={v}" for k, v in labels.items()) if labels else "none"

        lines.append(
            f"Pod: {name} (ns: {namespace})\n"
            f"  Labels:  {label_str}\n"
            f"  Ports:   {', '.join(port_strs)}\n"
            f"  Tools:   {', '.join(tool_strs)}"
        )

    return "\n".join(lines)

def generate_text(prompt, pod_discovery: list = []):
    try:
        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            raise RuntimeError("GROQ_API_KEY not set")
        
        client = Groq(api_key=groq_api_key)
        graph = build_graph(client)

        final_state = graph.invoke({
            "original_prompt": prompt,
            "technical_prompt": "",
            "yaml_output": "",
            "validation_result": "invalid",
            "test_script": "",
            "iterations": 0,
            "max_iterations": MAX_ITER,
            "validation_done": False,
            "testing_done": False,
            "pod_discovery": pod_discovery,
        })
        return {
            "yaml": final_state["yaml_output"],
            "test": final_state.get("test_script", "")
        }
    except Exception as e:
        print(f"Error: {str(e)}", flush=True)
        raise RuntimeError(str(e))
    
def keep_last(a, b):
    return b

# --- shared state between nodes ---
class PolicyState(TypedDict):
    original_prompt: Annotated[str, keep_last]
    technical_prompt: Annotated[str, keep_last]
    yaml_output: Annotated[str, keep_last]
    validation_result: Annotated[str, keep_last]   # "valid" | "invalid"
    test_script: Annotated[str, keep_last]
    iterations: Annotated[int, keep_last]
    max_iterations: Annotated[int, keep_last]
    validation_done: Annotated[bool, keep_last]
    testing_done: Annotated[bool, keep_last]
    pod_discovery:     Annotated[list, keep_last]

MAX_ITER = 3

# --- Node ---
def node_translate(state: PolicyState, client) -> PolicyState:
    translated = translate_intent(state["original_prompt"], client)
    return {**state, "technical_prompt": translated}

def node_validate(state: PolicyState, client) -> PolicyState:
    if "calico" in state["technical_prompt"].lower():
        VALIDATION_PROMPT = VALIDATION_PROMPT_CALICO
    else:
        VALIDATION_PROMPT = VALIDATION_PROMPT_CILIUM
    completion = client.chat.completions.create(
        model=VALIDATOR_MODEL,
        messages=[
            {"role": "system", "content": VALIDATION_PROMPT},
            {"role": "user", "content": f"INTENT:\n{state['technical_prompt']}\n\nYAML:\n{state['yaml_output']}"}
        ],
        temperature=0.0,
        max_tokens=4096,
        reasoning_format="hidden",
        timeout=LLM_TIMEOUT_SECONDS,
    )
    raw = extract_yaml(completion.choices[0].message.content.strip())
    print(f"Generated text: {raw}")

    if raw.upper().startswith("VALID"):
        return {
            **state,
            "validation_result": "valid",
            "validation_done": True
        }
    else:
        return {
            **state, 
            "yaml_output": raw, 
            "validation_result": "invalid", 
            "validation_done": True
        }

#def node_generate(state: PolicyState, client) -> PolicyState:
#    if "calico" in state["technical_prompt"].lower():
#        SYSTEM_PROMPT = SYSTEM_PROMPT_CALICO
#    else:
#        SYSTEM_PROMPT = SYSTEM_PROMPT_CILIUM
#    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
#    
#    if state["iterations"] > 0 and state["yaml_output"]:
#        messages.append({
#            "role": "user",
#            "content": (
#                f"{state['technical_prompt']}\n\n"
#                f"Previous attempt was invalid. Here is the partially corrected YAML — "
#                f"fix any remaining issues:\n{state['yaml_output']}"
#            )
#        })
#    else:
#        messages.append({"role": "user", "content": state["technical_prompt"]})
#
#    completion = client.chat.completions.create(
#        model=GENERATOR_MODEL,  
#        messages=messages,
#        temperature=0.0,
#        max_tokens=4096,    
#    )
#    raw = extract_yaml(completion.choices[0].message.content.strip())  
#    return {**state, "yaml_output": raw, "iterations": state["iterations"] + 1}
#
#
#def node_testing(state: PolicyState, client) -> PolicyState:
#    match = re.search(r'app == "(\w+)"', state["technical_prompt"])
#    source_app = match.group(1) if match else "unknown"
#    
#    available_tools = get_available_tools(source_app)
#    completion = client.chat.completions.create(
#        model=VALIDATOR_MODEL,
#        messages=[
#            {
#                "role": "system",
#                "content": TEST_GENERATOR_PROMPT
#            },
#            {
#                "role": "user",
#                "content": f"INTENT:\n{state['technical_prompt']}"
#                f"TOOLS AVAILABLE IN SOURCE POD ({source_app}):\n{available_tools}\n"
#            }
#        ],
#        temperature=0.1,
#        max_tokens=4096,
#    )
#    print(f"[node_testing] raw output: {completion.choices[0].message.content.strip()}", flush=True)
#    script = extract_script(completion.choices[0].message.content.strip())
#    return {
#        **state,
#        "test_script": script,
#        "testing_done": True
#    }
def node_generate(state: PolicyState, client) -> PolicyState:
    if "calico" in state["technical_prompt"].lower():
        SYSTEM_PROMPT = SYSTEM_PROMPT_CALICO
    else:
        SYSTEM_PROMPT = SYSTEM_PROMPT_CILIUM

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    if state["iterations"] > 0 and state["yaml_output"]:
        messages.append({
            "role": "user",
            "content": (
                f"{state['technical_prompt']}\n\n"
                f"Previous attempt was invalid. Fix this YAML:\n{state['yaml_output']}"
            )
        })
    else:
        messages.append({
            "role": "user",
            "content": state["technical_prompt"]
        })

    completion = ollama_client.chat(
        model="minimax-m2.5:cloud",
        messages=messages,
        options={
            "temperature": 0.1,
            "num_predict": 4096,
        } 
    )

    raw = extract_yaml(completion['message']['content'].strip())  # ← dizionario

    return {
        **state,
        "yaml_output": raw,
        "iterations": state["iterations"] + 1
    }


def node_testing(state: PolicyState, client) -> PolicyState:
    # Usa le info di discovery passate dal controller
    discovery_context = format_pod_discovery(state.get("pod_discovery", []))
    try:
      completion = ollama_client.chat(
          model="qwen3-coder-next",
          messages=[
              {"role": "system", "content": TEST_GENERATOR_PROMPT},
              {
                  "role": "user",
                  "content": (
                      f"INTENT:\n{state['technical_prompt']}\n\n"
                      f"CLUSTER POD INFO (ports, protocols, available tools):\n"
                      f"{discovery_context}\n"
                  )
              }
          ],
          options={
              "temperature": 0.1,
              "num_predict": 4096,
          }
      )
    except Exception as e:
        print(f"[node_generate] ERROR: {e}", flush=True)  # <-- aggiungi questo
        raise

    raw = completion['message']['content'].strip()
    script = extract_script(raw)

    return {
        **state,
        "test_script": script,
        "testing_done": True
    }



def node_join(state: PolicyState) -> PolicyState:
    return state

# --- Routing ---
def should_continue(state: PolicyState) -> str:
    if state["validation_result"] == "valid":
        return "join"
    if state["iterations"] >= state["max_iterations"]:
        print("Max iterations reached, returning best effort YAML")
        return "join"
    return "generate"  # torna a rigenerare col YAML fixato come contesto
    
def should_end(state: PolicyState) -> str:
    if state.get("validation_done") and state.get("testing_done"):
        return END
    return "wait"

# --- Graph building ---
def build_graph(client):
    graph = StateGraph(PolicyState)

    graph.add_node("translate",  lambda s: node_translate(s, client))
    graph.add_node("generate",   lambda s: node_generate(s, client))
    graph.add_node("validate",   lambda s: node_validate(s, client))
    graph.add_node("testing",   lambda s: node_testing(s, client))
    graph.add_node("join", node_join)

    graph.set_entry_point("translate")
    graph.add_edge("translate", "generate")
    graph.add_edge("translate", "testing")
    graph.add_edge("generate", "validate")

    graph.add_conditional_edges(
        "validate",
        should_continue,
        {"generate": "generate", "join": "join"}
    )

    graph.add_edge("testing", "join")

    graph.add_conditional_edges(
        "join",
        should_end,
        {
            "wait": "join",
            END: END
        }
    )

    return graph.compile()

@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({"error": "Invalid request, missing 'prompt' field"}), 400
    
    pod_discovery = data.get('pod_discovery', [])
    
    try:
        result = generate_text(data['prompt'], pod_discovery)
        return jsonify(result), 200
    except Exception as e:
        print(f"Error: {str(e)}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "backend": "groq+ollama",
        "model": GROQ_MODEL,
        "queue_size": request_queue.qsize(),
        "queue_capacity": 50
    }), 200

@app.route('/queue', methods=['GET'])
def queue_status():
    """Endpoint per monitorare lo stato della coda."""
    return jsonify({
        "queued_requests": request_queue.qsize(),
        "max_capacity": 50,
        "worker_running": _worker_thread.is_alive()
    }), 200

def shutdown_handler(signum, frame):
    """Gestisce SIGTERM e SIGINT per uno shutdown pulito."""
    print("Shutdown signal received, stopping worker...", flush=True)
    _shutdown_event.set()
    _worker_thread.join(timeout=10)
    print("Worker stopped.", flush=True)
    exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

if __name__ == "__main__":
    args = get_args()
    GROQ_MODEL = args.model
    print(f"Starting Flask server with Groq API backend...")
    print(f"Make sure GROQ_API_KEY and OLLAMA_API_KEY environment variable is set")
    print(f"Using Groq model: {GROQ_MODEL}")
    app.run(host='0.0.0.0', port=args.port)
