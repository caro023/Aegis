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
import json
import yaml

app = Flask(__name__)
VALIDATOR_MODEL = "openai/gpt-oss-120b"
INTENT_MODEL = "qwen/qwen3.6-27b"

LLM_TIMEOUT_SECONDS = 250
REQUEST_TIMEOUT_SECONDS = 300

TEST_NAMESPACE = "default"

ollama_client = Client(
    host="https://ollama.com",
    headers={'Authorization': 'Bearer ' + os.environ.get('OLLAMA_API_KEY')},
    timeout = LLM_TIMEOUT_SECONDS 
)

INTENT_TRANSLATOR_PROMPT = """You are a Kubernetes network security expert.
Your task is to translate a high-level security intent into a STRUCTURED JSON
object that will be used both to generate a network policy YAML and to
generate a connectivity test script.

OUTPUT FORMAT (MANDATORY):
- Output ONLY a single valid JSON object. No markdown, no backticks, no
  explanations, no <think> tags, no text before or after the JSON.
- The JSON object MUST have EXACTLY these keys:

{
  "namespace": "<namespace from the input intent, or 'default'>",
  "policy_type": "cilium" | "calico" | "kubernetes",
  "description": "<one paragraph for the YAML generator, see DESCRIPTION RULES>",
  "connections": [
    {
      "source_app": "<pod label value that INITIATES the test connection>",
      "target_app": "<pod/service label value that RECEIVES the connection>",
      "port": "<port as string, e.g. '6379', or null if not specified>",
      "protocol": "TCP" | "UDP" | null,
      "action": "allow" | "deny"
    }
  ]
}

CONNECTIONS RULES (MANDATORY):
- Include one entry per distinct testable connection described by the intent.
- For simple intents (A → B allow/deny): one entry.
- For bidirectional intents ("A talks to B"): still ONE entry
  (source=A, target=B, action=allow) — do not duplicate.
- For deny-except intents ("deny to B from all except A"):
  ONE entry with source=A, target=B, action=allow
  (test the allowed exception, not the denied case).
- For allow-from-all intents ("B reachable from everywhere"):
  ONE entry with source_app="any", target=B, action=allow.
- For multi-endpoint intents ("allow A→B and A→C"):
  TWO entries: {source=A, target=B} and {source=A, target=C}.
- NEVER exceed 3 entries. If the intent is more complex, keep only
  the most representative connections and describe the rest in description.
- source_app and target_app are ALWAYS plain label values, never
  wrapped in 'app == "..."' or matchLabels syntax.
- NEVER invent pod names not mentioned in the intent.

PORT RULE (MANDATORY):
- Extract ONLY ports explicitly stated in the intent.
- NEVER infer or assume a port from the application name or protocol.
- If no port is specified, set "port" to null.

PROTOCOL RULE (MANDATORY):
- Extract ONLY protocols explicitly stated in the intent.
- If no protocol is specified, set "protocol" to null.

POLICY_TYPE RULE (MANDATORY):
- Map the closing instruction to: "cilium", "calico", or "kubernetes".

NAMESPACE RULE (MANDATORY):
- Use the namespace stated in the intent. Default to "default" if absent.

============================================================
TEST ROLES RULE (connections entries — READ CAREFULLY):
============================================================
Each entry in "connections" describes a SINGLE concrete connection
attempt to VERIFY the policy. Use these mappings:

1) "Allow A to B" / "A talks to B":
   -> {source=A, target=B, action="allow"}

2) "Deny A from reaching B":
   -> {source=A, target=B, action="deny"}

3) "Deny ingress to B from all except A" / "only A can reach B":
   -> {source=A, target=B, action="allow"}
   Test the ALLOWED exception. Do NOT set source=B.

4) "Allow ingress to B from all pods":
   -> {source="any", target=B, action="allow"}

5) "Allow A→B and A→C" (multi-target):
   -> [{source=A, target=B, action="allow"},
       {source=A, target=C, action="allow"}]

============================================================
DESCRIPTION RULES (for the YAML generator):
============================================================
- One paragraph describing the FULL policy to generate (may include
  both egress and ingress sides, all endpoints, all ports).
- Include: source/destination pod labels, direction (egress AND ingress
  when bidirectional), port/protocol if specified, action, and end with
  the EXACT policy type instruction from the input.
- NEVER omit the namespace instruction at the end.

DENY/ALLOW DESCRIPTION RULE (CRITICAL — READ CAREFULLY, 3 CASES):

  Case A — "Allow X, everyone else implicitly denied" (NO explicit Deny
  in the original intent; e.g. "only frontend can reach cache",
  "deny ingress except frontend", "lock down X so only Y can connect"):
  -> Write ONLY the Allow rule in the description. Do NOT mention
     "Deny" or "catch-all" at all. A single Allow rule is sufficient:
     Calico/Cilium deny by default anything not explicitly matched
     once a policy selects the pod.
  Example description: "Allow ingress to the pod labeled app == \\"cache\\"
  only from the pod labeled app == \\"frontend\\" on TCP port 6379.
  Generate a CalicoNetworkPolicy..."

  Case B — "Deny X specifically, but allow everything else for that pod"
  (explicit Deny in the intent targeting ONE specific connection;
  e.g. "block api-backend from reaching cache", "stop api-backend
  from talking to cache"):
  -> Mention BOTH: (1) the specific Deny rule with explicit source
     AND destination selectors (never empty), AND (2) an explicit
     instruction to allow all other traffic for that pod afterward,
     using a final rule with selector: all().
  Example description: "Deny egress from the pod labeled
  app == \\"api-backend\\" to the pod labeled app == \\"cache\\", action deny.
  This Deny rule must specify both source and destination selectors.
  Allow all other egress from api-backend using a final Allow rule
  with destination selector all(), placed after the Deny rule.
  Generate a CalicoNetworkPolicy..."

  Case C — "Deny X entirely, no exceptions" (total deny; e.g. "deny
  all ingress to cache", "nobody should reach X"):
  -> Write ONLY the Deny rule, matching everything (selector: all()).
     Do NOT add any Allow rule afterward — an Allow with the same or
     broader selector would cancel the Deny's effect entirely.
  Example description: "Deny all ingress to the pod labeled
  app == \\"cache\\" from all pods (selector: all()), action deny,
  no exceptions, no Allow rule should follow. Generate a
  CalicoNetworkPolicy..."

  NEVER write the generic phrase "add a catch-all Allow rule after
  the Deny" without picking one of the three cases above explicitly.
  Writing it unconditionally causes the YAML generator to add
  meaningless Allow/Deny rules without selectors, which cancel each
  other out and make the policy ineffective (e.g. "allow X only" ends
  up allowing everyone, or "deny everything" ends up denying nothing).

============================================================
EXAMPLES
============================================================

INPUT:
"Allow egress from frontend to api-backend on TCP port 8000.
Generate a CiliumNetworkPolicy in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "cilium", "description": "Allow egress from the pod labeled app == \\"frontend\\" to the pod labeled app == \\"api-backend\\" on TCP port 8000, and allow ingress to app == \\"api-backend\\" from app == \\"frontend\\" on TCP port 8000, action allow. Generate a CiliumNetworkPolicy in namespace test-pods.", "connections": [{"source_app": "frontend", "target_app": "api-backend", "port": "8000", "protocol": "TCP", "action": "allow"}]}

---

INPUT:
"Deny ingress to cache from all pods except frontend on TCP port 6379.
Generate a CiliumNetworkPolicy in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "cilium", "description": "Allow ingress to the pod labeled app == \\"cache\\" only from the pod labeled app == \\"frontend\\" on TCP port 6379, all other ingress implicitly denied. Generate a CiliumNetworkPolicy in namespace test-pods.", "connections": [{"source_app": "frontend", "target_app": "cache", "port": "6379", "protocol": "TCP", "action": "allow"}]}

---

INPUT:
"Allow ingress to dns-worker from all pods on UDP.
Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "calico", "description": "Allow ingress to the pod labeled app == \\"dns-worker\\" from all pods (selector: all()) on UDP, action allow. Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods.", "connections": [{"source_app": "any", "target_app": "dns-worker", "port": null, "protocol": "UDP", "action": "allow"}]}

---

INPUT:
"Deny all ingress to user-timeline-mongodb except from user-timeline-service.
Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "calico", "description": "Allow ingress to the pod labeled app == \\"user-timeline-mongodb\\" only from the pod labeled app == \\"user-timeline-service\\" on all ports. Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods.", "connections": [{"source_app": "user-timeline-service", "target_app": "user-timeline-mongodb", "port": null, "protocol": null, "action": "allow"}]}

---

INPUT:
"Let frontend talk to cache. Generate a CiliumNetworkPolicy in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "cilium", "description": "Allow egress from the pod labeled app == \\"frontend\\" to the pod labeled app == \\"cache\\" and allow ingress to cache from frontend, action allow. Generate a CiliumNetworkPolicy in namespace test-pods.", "connections": [{"source_app": "frontend", "target_app": "cache", "port": null, "protocol": null, "action": "allow"}]}

---

INPUT:
"Allow frontend to reach api-backend, and also allow toolbox to reach cache on port 6379.
Generate a CiliumNetworkPolicy in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "cilium", "description": "Allow egress from frontend to api-backend and ingress to api-backend from frontend, action allow. Also allow egress from toolbox to cache on TCP port 6379 and ingress to cache from toolbox on port 6379, action allow. Generate a CiliumNetworkPolicy in namespace test-pods.", "connections": [{"source_app": "frontend", "target_app": "api-backend", "port": null, "protocol": null, "action": "allow"}, {"source_app": "toolbox", "target_app": "cache", "port": "6379", "protocol": "TCP", "action": "allow"}]}

---

INPUT:
"Stop the api-backend from reaching the cache.
Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "calico", "description": "Deny egress from the pod labeled app == \\"api-backend\\" to the pod labeled app == \\"cache\\", action deny. This Deny rule must specify both source and destination selectors. Allow all other egress from api-backend using a final Allow rule with destination selector all(), placed after the Deny rule. Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods.", "connections": [{"source_app": "api-backend", "target_app": "cache", "port": null, "protocol": null, "action": "deny"}]}

---

INPUT:
"Nobody should be able to reach the cache.
Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods."

OUTPUT:
{"namespace": "test-pods", "policy_type": "calico", "description": "Deny all ingress to the pod labeled app == \\"cache\\" from all pods (selector: all()), action deny, no exceptions, no Allow rule should follow. Generate a CalicoNetworkPolicy with apiVersion: crd.projectcalico.org/v1 in namespace test-pods.", "connections": [{"source_app": "any", "target_app": "cache", "port": null, "protocol": null, "action": "deny"}]}

Output ONLY the JSON object, nothing else."""

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
- metadata.namespace MUST always be present. Set the namespace as the one specified in the intent

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

- In EGRESS rules: ports go inside 'destination'
  (the port the destination pod is listening on)
- In INGRESS rules: ports go inside 'destination' as well
  (the port THIS pod is listening on, which is the destination of the flow)
- NEVER put ports inside 'source' for ingress rules
- NEVER put ports inside 'source' for egress rules

If a policy defines Egress or Ingress rules, all other traffic is implicitly denied unless explicitly allowed.

Therefore:
- If the intent is to block specific traffic ONLY,
- You MUST add a final "Allow" rule to permit all other traffic.

BIDIRECTIONAL RULE (MANDATORY):
- For any Allow intent involving traffic from A to B, ALWAYS generate
  BOTH an egress rule on A AND an ingress rule on B as separate policies.
- NEVER generate only one side.
- This is critical because existing egress policies on A may implicitly
  block new destinations unless explicitly allowed.

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

DO NOT USE <think> TAGS.
DO NOT REASON ABOUT THE RULES.
JUST OUTPUT THE YAML.
If you output more than one YAML separate it with ---
Return ONLY valid YAML.
Do not include explanations.
Do not include markdown backticks.
Output MUST start with: apiVersion:
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
10. metadata.namespace MUST always be present. Use the namespace specified in the input prompt.
If no namespace is specified use "default"

REQUIRED FIELDS:
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
- If intent does NOT specify a port set port to null
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
  namespace: test
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
- Use the namespace specified in the input prompt. If no namespace is specified use "default"

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

BIDIRECTIONAL RULE (MANDATORY):
- For any Allow intent involving traffic from A to B, ALWAYS generate
  BOTH an egress rule on A AND an ingress rule on B as separate policies.
- NEVER generate only one side.
- This is critical because existing egress policies on A may implicitly
  block new destinations unless explicitly allowed.

STRUCTURE VALIDATION:
- Must start with apiVersion
- Must include: kind, metadata.name, metadata.namespace, spec.selector
- spec.selector must use Calico syntax (e.g. app == "name"), not matchLabels
- If metadata.namespace is missing → ADD it 
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

DO NOT USE <think> TAGS.
DO NOT REASON ABOUT THE RULES.
JUST OUTPUT THE YAML.
Return ONLY valid YAML.
Do not include explanations.
Do not include markdown backticks.
Output MUST start with: apiVersion:

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
4. spec.endpointSelector must exist with matchLabels.
5. Ingress/egress rules must use fromEndpoints/toEndpoints with matchLabels.
6. Allow rules MUST have toPorts with port (string) and protocol.
7. Deny rules MUST use ingressDeny/egressDeny and MUST NOT have toPorts.
8. Use the namespace specified in the input prompt. If no namespace is specified use "default"

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
OUTPUT ONLY A VALID BASH SCRIPT. NO YAML. NO KUBECTL APPLY. NO EXPLANATIONS.

CRITICAL RULES:
1. NEVER use kubectl apply, kubectl create, kubectl delete inside the script
2. NEVER consider HTTP 000 as success — it means connection refused/timeout
3. SOURCE_POD is always the pod initiating the connection (egress side)
4. TARGET is always the service receiving the connection
5. ALWAYS use -n <namespace> in every kubectl command — never omit namespace
6. You MUST use EXACTLY the tool given in "TOOL TO USE". NEVER substitute it,
   NEVER fall back to a different tool because of the port number, and NEVER
   add your own "port rules" — TOOL TO USE is already chosen correctly based
   on the tools actually available in the source pod.
7. If TOOL TO USE is "none", the source pod has NO usable networking tool.
   Output ONLY:
     #!/bin/bash
     echo "SKIP: no networking tool available in source pod"
     exit 0
   Do not attempt any connection.

PROTOCOL NOTE:
- TARGET PROTOCOL is given in the input (TCP or UDP).
- If TARGET PROTOCOL is UDP, add "-u" to nc/ncat commands below.
- curl, wget, telnet, openssl, devtcp are NOT reliable for UDP. If TARGET
  PROTOCOL is UDP and TOOL TO USE is one of curl/wget/telnet/openssl/devtcp,
  output the SKIP script from rule 7 instead (do not invent a UDP check).

PER-TOOL TEST COMMAND (use the ONE matching TOOL TO USE):

- curl  (ONLY if SVC_PORT is "80" or "8080"; HTTP check):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- curl --max-time 3 -s -o /dev/null -w "%{http_code}" http://$SVC_IP:$SVC_PORT 2>&1)
    HTTP_CODE="$CMD_OUTPUT"
    SUCCESS_COND=$( [ "$HTTP_CODE" != "000" ] && echo 1 || echo 0 )

- wget  (ONLY if SVC_PORT is "80" or "8080"; HTTP check):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- wget -T 3 -q -O /dev/null http://$SVC_IP:$SVC_PORT 2>&1)
    EXIT_CODE=$?
    SUCCESS_COND=$( [ $EXIT_CODE -eq 0 ] && echo 1 || echo 0 )

- nc    (raw TCP/UDP connect check, any port):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- nc -z -w 3 $SVC_IP $SVC_PORT 2>&1)
    # add -u before -z if TARGET PROTOCOL is UDP
    EXIT_CODE=$?
    SUCCESS_COND=$( [ $EXIT_CODE -eq 0 ] && echo 1 || echo 0 )

- ncat  (raw TCP/UDP connect check, any port):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- ncat -z -w 3 $SVC_IP $SVC_PORT 2>&1)
    # add -u before -z if TARGET PROTOCOL is UDP
    EXIT_CODE=$?
    SUCCESS_COND=$( [ $EXIT_CODE -eq 0 ] && echo 1 || echo 0 )

- telnet (raw TCP connect check, TCP only):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- sh -c "echo | timeout 3 telnet $SVC_IP $SVC_PORT" 2>&1)
    SUCCESS_COND=$( echo "$CMD_OUTPUT" | grep -qi "Connected" && echo 1 || echo 0 )

- openssl (raw TCP connect check, TCP only):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- sh -c "timeout 3 openssl s_client -connect $SVC_IP:$SVC_PORT </dev/null" 2>&1)
    SUCCESS_COND=$( echo "$CMD_OUTPUT" | grep -qi "CONNECTED" && echo 1 || echo 0 )

- devtcp (raw TCP connect check, TCP only, REQUIRES bash — NEVER use sh):
    CMD_OUTPUT=$(kubectl exec -n $SOURCE_NS $SOURCE_POD -- timeout 3 bash -c "echo > /dev/tcp/$SVC_IP/$SVC_PORT" 2>&1)
    EXIT_CODE=$?
    SUCCESS_COND=$( [ $EXIT_CODE -eq 0 ] && echo 1 || echo 0 )

SCRIPT STRUCTURE:
#!/bin/bash
set -uo pipefail

SOURCE_NS="<SOURCE POD NAMESPACE from input>"
TARGET_NS="<TARGET SERVICE NAMESPACE from input>"

SOURCE_POD=$(kubectl get pods -n $SOURCE_NS -l app=<SOURCE_APP> -o jsonpath='{.items[0].metadata.name}')
if [ -z "$SOURCE_POD" ]; then echo "SKIP: source pod not found in ns $SOURCE_NS"; exit 0; fi

kubectl get svc <TARGET_SVC> -n $TARGET_NS >/dev/null 2>&1 || { echo "SKIP: target service not found in ns $TARGET_NS"; exit 0; }
SVC_IP=$(kubectl get svc <TARGET_SVC> -n $TARGET_NS -o jsonpath='{.spec.clusterIP}')
SVC_PORT=$(kubectl get svc <TARGET_SVC> -n $TARGET_NS -o jsonpath='{.spec.ports[0].port}')

echo "=== TEST START ==="
RESULT=0
CMD_OUTPUT=""
EXIT_CODE=""
for i in 1 2 3 4 5; do
  # <insert here the ONE check block matching TOOL TO USE, setting SUCCESS_COND>
  if [ $SUCCESS_COND -eq 1 ]; then
    echo "SUCCESS: Connection behaved as expected."
    RESULT=1
    break
  fi
  echo "Attempt $i failed. Tool output: $CMD_OUTPUT"
  sleep 2
done
if [ $RESULT -eq 0 ]; then
  echo "FAIL: Connection did not behave as expected."
  echo "Last tool output: $CMD_OUTPUT"
  echo "Last exit code: $EXIT_CODE"
  exit 1
fi
exit 0

BLOCKED CONNECTION TEST (only for DENY intents): invert SUCCESS_COND logic above.
"""

GROQ_MODEL = None

def get_args():
    parser = argparse.ArgumentParser(description="Run a Flask server for text generation using Groq API.")
    parser.add_argument("--model", type=str, required=True, help="Groq model ID to use.")
    parser.add_argument("--port", type=int, required=True, help="Port for the Flask server.")
    parser.add_argument("--test-namespace", type=str, default="default", help="Namespace for test pods and policies")
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

def parse_legacy_translation(text: str) -> dict:
    """Fallback: estrae campi strutturati da testo libero."""
    policy_type = "kubernetes"
    if "cilium" in text.lower():
        policy_type = "cilium"
    elif "calico" in text.lower():
        policy_type = "calico"

    ns_match = re.search(r'namespace\s+"?([\w-]+)"?', text, re.IGNORECASE)
    namespace = ns_match.group(1) if ns_match else TEST_NAMESPACE

    apps = re.findall(r'app\s*==\s*"([\w-]+)"', text)
    source_app = apps[0] if len(apps) > 0 else "unknown"
    target_app = apps[1] if len(apps) > 1 else "unknown"

    port_match = re.search(r'port[s]?\s*[:=]?\s*"?(\d+)"?', text, re.IGNORECASE)
    port = port_match.group(1) if port_match else None

    protocol = "UDP" if re.search(r'\bUDP\b', text, re.IGNORECASE) else "TCP"

    if re.search(r'\b(deny|block|restrict|drop)\b', text, re.IGNORECASE):
        action = "deny"
    else:
        action = "allow"

    # produce lo stesso formato di LLM1 con connections array
    return {
        "connections": [
            {
                "source_app": source_app,
                "target_app": target_app,
                "port": port,
                "protocol": protocol,
                "action": action,
            }
        ],
        "namespace": namespace,
        "policy_type": policy_type,
        "description": text,
        "_source": "fallback",
    }

def translate_intent(intent, client):
    completion = client.chat.completions.create(
        model=INTENT_MODEL,
        messages=[
            {"role": "system", "content": INTENT_TRANSLATOR_PROMPT},
            {"role": "user", "content": intent}
        ],
        temperature=0.05,
        max_tokens=4048,
        timeout=LLM_TIMEOUT_SECONDS,
    )
    raw = completion.choices[0].message.content.strip()

    cleaned = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()

    data = None
    if cleaned.startswith("{") or re.search(r"\{.*\}", cleaned, re.DOTALL):
        try:
            data = extract_json(cleaned)
            data["_source"] = "json"
            print(cleaned)
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            print(f"[translate_intent] JSON parse failed: {e}", flush=True)
            data = None

    if data is None:
        print("[translate_intent] using free-text fallback", flush=True)
        data = parse_legacy_translation(cleaned)

    data.setdefault("namespace", TEST_NAMESPACE)
    data.setdefault("description", cleaned)
    return data

def extract_json(text: str) -> dict:
    """Remove <think> tags and markdown fences, parse JSON."""
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    else:
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            text = match.group(1)
    return json.loads(text)

def extract_yaml(text: str) -> str:
    # Rimuovi think tags
    print("entry YAML in extract :")
    print(text)
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    
    # Cerca blocco con backtick (multi-doc: prendi TUTTO fino all'ultimo ```)
    match = re.search(r"```(?:ya?ml)?\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # Nessun backtick: cerca la prima riga che sembra YAML (apiVersion: o ---)
    # e prendi tutto da lì in poi
    yaml_start = re.search(r'^(---|apiVersion:)', text, re.MULTILINE)
    if yaml_start:
        return text[yaml_start.start():].strip()
    
    print("exit YAML ")
    print(text)
    print("stripped yaml")
    print(text.strip())
    
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

def enforce_namespace(yaml_text: str, namespace: str) -> str:
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return yaml_text  # lascia che il validator segnali l'errore di sintassi

    out_docs = []
    for doc in docs:
        if isinstance(doc, dict):
            doc.setdefault("metadata", {})
            doc["metadata"]["namespace"] = namespace
            out_docs.append(doc)
    return "---\n".join(yaml.dump(d, sort_keys=False) for d in out_docs)

    
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
    intent_data: Annotated[dict, keep_last]
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
    intent_data = translate_intent(state["original_prompt"], client)
    return {
        **state,
        "intent_data": intent_data,
        "technical_prompt": intent_data.get("description", ""),
    }

def node_validate(state: PolicyState, client) -> PolicyState:
    if not state["yaml_output"].strip():
        print("[node_validate] yaml_output is empty, marking invalid for retry", flush=True)
        return {**state, "validation_result": "invalid", "validation_done": True}
    if state["intent_data"].get("policy_type", "").lower() == "calico":
        VALIDATION_PROMPT = VALIDATION_PROMPT_CALICO
    else:
        VALIDATION_PROMPT = VALIDATION_PROMPT_CILIUM
    completion = client.chat.completions.create(
        model=VALIDATOR_MODEL,
        messages=[
            {"role": "system", "content": VALIDATION_PROMPT},
            {"role": "user", "content": (
                f"INTENT:\n{state['technical_prompt']}\n\n"
                f"STRUCTURED INTENT: {json.dumps(state['intent_data'])}\n\n"
                f"YAML:\n{state['yaml_output']}"
        )}
        ],
        temperature=0.0,
        max_tokens=4096,
        reasoning_format="hidden",
        timeout=LLM_TIMEOUT_SECONDS,
    )
    raw = extract_yaml(completion.choices[0].message.content.strip())
    #print(f"Generated text: {raw}")
    if not raw:
        print("[node_validate] validator returned empty output, treating as VALID", flush=True)
        return {**state, "validation_result": "valid", "validation_done": True}

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

def node_generate(state: PolicyState, client) -> PolicyState:
    if state["intent_data"].get("policy_type", "").lower() == "calico":
        SYSTEM_PROMPT = SYSTEM_PROMPT_CALICO
    else:
        SYSTEM_PROMPT = SYSTEM_PROMPT_CILIUM

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    namespace = state["intent_data"].get("namespace", TEST_NAMESPACE)
    
    
    if state["iterations"] > 0 and state["yaml_output"]:
        user_content = (
            f"{state['technical_prompt']}\n\n"
            f"Target namespace: {namespace}\n"
            f"Previous attempt was invalid. Fix this YAML:\n{state['yaml_output']}"
            f"If you have to output more than one YAML separate them with ---"
        )
    else:
        user_content = (
            f"{state['technical_prompt']}\n\n"
            f"Target namespace: {namespace}\n"
            f"Use this exact value for metadata.namespace in every document."
            f"If you have to output more than one YAML separate them with ---"
        )

    messages.append({"role": "user", "content": user_content})

    completion = ollama_client.chat(
        model="minimax-m2.5:cloud",
        messages=messages,
        options={
            "temperature": 0.4,
            "num_predict": 2024,
        } 
    )

    raw = extract_yaml(completion['message']['content'].strip())
    raw = enforce_namespace(raw, namespace)

    return {
        **state,
        "yaml_output": raw,
        "iterations": state["iterations"] + 1
    }

def select_tool(tools: list) -> str:
    if "nc" in tools:
        return "nc"
    if "ncat" in tools:
        return "ncat"
    if "bash" in tools:
        return "devtcp"
    if "wget" in tools:
        return "wget"
    if "curl" in tools:
        return "curl"
    if "openssl" in tools:
        return "openssl"
    if "telnet" in tools:
        return "telnet"
    return "none"

def get_pod_namespace(pod_discovery: list, app_label: str, preferred_ns: str = "default") -> str:
    # Prima cerca nel namespace preferito
    for pod in pod_discovery:
        if (pod.get("labels", {}).get("app") == app_label and
            pod.get("namespace") == preferred_ns):
            return preferred_ns
    # Fallback: qualsiasi namespace
    for pod in pod_discovery:
        if pod.get("labels", {}).get("app") == app_label:
            return pod.get("namespace", "default")
    return "default"

def get_source_tools(pod_discovery: list, source_app: str, preferred_ns: str = "default") -> list:
    # Prima cerca nel namespace preferito
    for pod in pod_discovery:
        if (pod.get("labels", {}).get("app") == source_app and
            pod.get("namespace") == preferred_ns):
            return pod.get("availableTools", [])
    # Fallback: qualsiasi namespace
    for pod in pod_discovery:
        if pod.get("labels", {}).get("app") == source_app:
            return pod.get("availableTools", [])
    return []

def node_testing(state: PolicyState, client) -> PolicyState:
    intent_data = state.get("intent_data", {})
    discovery_context = format_pod_discovery(state.get("pod_discovery", []))

    connections = intent_data.get("connections", [])
    if not connections:
        flat_source = intent_data.get("source_app", "unknown")
        flat_target = intent_data.get("target_app", "unknown")
        connections = [{
            "source_app": flat_source,
            "target_app": flat_target,
            "port": intent_data.get("port") or None,
            "protocol": intent_data.get("protocol") or None,
            "action": intent_data.get("action", "allow"),
        }]

    test_conn = next(
        (c for c in connections if c.get("action") == "allow"),
        connections[0]
    )

    source_app = test_conn.get("source_app", "unknown")
    target_app = test_conn.get("target_app", "unknown")
    port = test_conn.get("port") or ""
    protocol = (test_conn.get("protocol") or "TCP").upper()
    action = test_conn.get("action", "allow").lower()

    if source_app == "any":
        candidates = [
            p for p in state.get("pod_discovery", [])
            if p.get("namespace") == TEST_NAMESPACE
            and p.get("labels", {}).get("app") not in (None, target_app)
            and p.get("availableTools")
        ]
        if protocol == "UDP":
            udp_capable = [
                p for p in candidates
                if "nc" in p.get("availableTools", [])
                or "ncat" in p.get("availableTools", [])
            ]
            candidates = udp_capable or candidates
        source_app = candidates[0]["labels"]["app"] if candidates else "unknown"

    source_ns = get_pod_namespace(
        state.get("pod_discovery", []), source_app, TEST_NAMESPACE)
    target_ns = get_pod_namespace(
        state.get("pod_discovery", []), target_app, TEST_NAMESPACE)

    tools = get_source_tools(
        state.get("pod_discovery", []), source_app, TEST_NAMESPACE)
    tool = select_tool(tools)

    print(f"[node_testing] source_app={source_app} ns={source_ns}, "
          f"target_app={target_app} ns={target_ns}, port={port}/{protocol}, "
          f"action={action}, tools={tools}, selected_tool={tool}", flush=True)

    # Log tutte le connections per debug
    print(f"[node_testing] all connections: {connections}", flush=True)

    completion = ollama_client.chat(
        model="qwen3-coder-next",
        messages=[
            {"role": "system", "content": TEST_GENERATOR_PROMPT},
            {
                "role": "user",
                "content": (
                   # f"CLUSTER POD INFO:\n{discovery_context}\n\n"
                    f"SOURCE POD APP LABEL: {source_app}\n"
                    f"SOURCE POD NAMESPACE: {source_ns}\n"
                    f"TARGET SERVICE NAME: {target_app}\n"
                    f"TARGET SERVICE NAMESPACE: {target_ns}\n"
                    f"TARGET PORT: {port}\n"
                    f"TARGET PROTOCOL: {protocol}\n"
                    f"EXPECTED RESULT: {'allowed' if action == 'allow' else 'denied'}\n"
                    f"AVAILABLE TOOLS IN SOURCE POD: {', '.join(tools) if tools else 'none'}\n"
                    f"TOOL TO USE: {tool}\n"
                    f"DO NOT use any other tool. "
                    f"If tool is 'none', print SKIP and exit 0.\n"
                )
            }
        ],
        options={"temperature": 0.1, "num_predict": 4096}
    )

    raw = completion['message']['content'].strip()
    script = extract_script(raw)
    return {**state, "test_script": script, "testing_done": True}

def node_join(state: PolicyState) -> PolicyState:
    return state

def should_continue(state: PolicyState) -> str:
    if state["validation_result"] == "valid":
        return "testing"   # prima testa, poi join
    if state["iterations"] >= state["max_iterations"]:
        return "testing"   # best effort, testa comunque
    return "generate"
    
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

    graph.set_entry_point("translate")
    graph.add_edge("translate", "generate")
    graph.add_edge("generate", "validate")

    graph.add_conditional_edges(
    "validate",
    should_continue,
    {"generate": "generate", "testing": "testing"}
)

    graph.add_edge("testing", END)


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
        import traceback
        print(f"Error: {traceback.format_exc()}", flush=True)  # ← traceback completo
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
    TEST_NAMESPACE = args.test_namespace
    print(f"Starting Flask server with Groq API backend...")
    print(f"Make sure GROQ_API_KEY and OLLAMA_API_KEY environment variable is set")
    print(f"Using Groq model: {GROQ_MODEL}")
    app.run(host='0.0.0.0', port=args.port)
