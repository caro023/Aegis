import os
import re
import argparse
from flask import Flask, request, jsonify, Response
from groq import Groq
from langgraph.graph import StateGraph, END
from typing import TypedDict
from typing import Annotated


app = Flask(__name__)
VALIDATOR_MODEL = "qwen/qwen3-32b"
GENERATOR_MODEL = "llama-3.3-70b-versatile"

INTENT_TRANSLATOR_PROMPT = """You are a Kubernetes network security expert.
Your task is to translate a high-level security intent into a detailed technical prompt for generating a Kubernetes network policy.

The output must be a single sentence or short paragraph describing:
- Which pod or service is the source (use the pod name and label if provided)
- ALWAYS use the EXACT service name as label value, never truncate it
- The traffic direction (ingress or egress)
- The destination pod or service (if specified)
- The port and protocol (if specified or inferable)
- The action (allow or deny)
- The policy type to generate (always end with: Generate a CiliumNetworkPolicy and the version)

LABEL RULE (MANDATORY):
- ALWAYS use 'app == "podname"' as selector. Example: frontend → app == "frontend"
- NEVER use other keys like 'service', 'name', 'component', 'pod'.

DIRECTION RULE (MANDATORY):
- "A allows/blocks traffic TO B" → this is an EGRESS policy on A, or INGRESS policy on B
- EGRESS = traffic leaving the source pod
- INGRESS = traffic arriving at the destination pod
- When in doubt, prefer: EGRESS on source pod

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

SYSTEM_PROMPT = """You are a Kubernetes security engineer.
Your task is to generate valid, production-ready YAML for CiliumNetworkPolicy, CalicoNetworkPolicy, Antrea, Weave or standard NetworkPolicy.

BIDIRECTIONAL CONNECTIVITY RULE (CRITICAL):

- Network connectivity between two services requires BOTH:
  - Egress policy on the source pod
  - Ingress policy on the destination pod

- Therefore:
  - If the intent says "allow X to talk to Y", you MUST:
    - Allow egress from X to Y
    - AND allow ingress on Y from X

  - If the intent says "allow X and Y to talk" or "vice versa":
    - You MUST generate policies for BOTH directions:
      - X → Y
      - Y → X

  - If the intent says "block X to Y":
    - You MUST block traffic from X to Y using egressDeny (Cilium) or Deny rule (Calico)
    - AND ensure ingress from X is not allowed on Y

- Never assume traffic is bidirectional unless explicitly stated or logically required.

STRICT SYNTAX RULES FOR CALICO:
1. Use 'kind: NetworkPolicy' and 'apiVersion: crd.projectcalico.org/v1'.
2. 'spec.selector' is a string expression: e.g. 'app == "frontend"'.
3. Each ingress/egress rule MUST have 'action' inside the rule itself.
4. Use 'source.selector' to match source pods. NEVER use 'from'.
5. Use 'destination.selector' to match destination pods. NEVER use 'to'.
6. NEVER include 'protocol' or 'ports' unless explicitly required.
7. NEVER output empty arrays: protocol: [] or ports: [] is FORBIDDEN.
8. 'egress' must be a list [] or omitted entirely. NEVER use egress: {}.
9. To allow/deny traffic to ALL destinations, omit 'destination' entirely. NEVER use destination: {}.
10.For namespaced policies, ALWAYS use 'kind: NetworkPolicy'.
11.ALWAYS use the field 'types' to specify Ingress or Egress, use the Calico semantic and not the network kubernetes one's

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
  types:
  - Ingress
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

STRICT SYNTAX RULES FOR CILIUM:
1. metadata:
   - MUST include: name (kebab-case), namespace: default

2. endpointSelector:
   - MUST use matchLabels
   - To select all pods: matchLabels: {}

3. ALLOW vs DENY — use the correct field:
   - To ALLOW traffic  → use 'egress' / 'ingress'
   - To DENY traffic   → use 'egressDeny' / 'ingressDeny'
   - NEVER mix allow and deny in the same rule block
   - NEVER use "action", "Allow", or "Deny" as fields inside rules

4. DENY LOGIC (CRITICAL):
   - Use 'egressDeny' to explicitly block egress to a destination
   - Use 'ingressDeny' to explicitly block ingress from a source
   - Example for "block frontend → checkoutservice":
     spec:
       endpointSelector:
         matchLabels:
           app: frontend
       egressDeny:
       - toEndpoints:
         - matchLabels:
             app: checkoutservice

   - Do NOT use matchExpressions with NotIn for deny intents.
     NotIn only restricts allow rules, it does NOT deny traffic.

5. Ports:
   - MUST be strings: port: "80" not port: 80
   - Protocol: TCP, UDP, SCTP, or ANY. NEVER use ALL.

6. Default behavior:
   - If no egress rules → all egress denied
   - If no ingress rules → all ingress denied
   - An egressDeny rule blocks specific traffic while leaving other traffic unaffected

--------------------------------------------------
CORRECT EXAMPLE — DENY intent:

Intent: "Block frontend → checkoutservice"

apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-frontend-to-checkoutservice
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egressDeny:
  - toEndpoints:
    - matchLabels:
        app: checkoutservice

--------------------------------------------------
CORRECT EXAMPLE — ALLOW intent:

Intent: "Allow frontend to talk only to frontend-external"

apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-frontend-to-frontend-external
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  - toEndpoints:
    - matchLabels:
        app: frontend-external
  ingress: []

GENERAL RULES:
- Output ONLY the YAML.
- No explanations or comments.
- Start directly with 'apiVersion:'."""


VALIDATION_PROMPT = """You are a Kubernetes network policy validator and fixer.

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

- If the intent implies bidirectional communication (e.g. "vice versa", "each other", "mutual"):
  - The policies MUST include BOTH directions:
    - X → Y
    - Y → X

- If one direction is missing → the YAML is INVALID and MUST be fixed.

- For DENY intents:
  - If blocking X → Y:
    - Ensure egress from X to Y is denied
    - AND no rule allows ingress from X to Y

- Reject policies that only define one side when two-sided communication is required.

CALICO SYNTAX (CRITICAL - always enforce):
- ingress rules: use 'source' to match origin pods. NEVER use 'from'.
- egress rules: use 'destination' to match target pods. NEVER use 'to'.
- NEVER use 'podSelector' or 'namespaceSelector'.
- 'egress' and 'ingress' MUST be lists, never objects ({}).
- If 'from', 'to', 'podSelector', 'namespaceSelector' are found → replace them.
- The kind policy for Calico is NetworkPolicy

IMPLICIT DENY RULE (only for Deny policies):
- In Calico, a policy with ONLY a Deny rule implicitly blocks ALL other traffic too.
- If the intent is to deny ONLY specific traffic (not all traffic):
  → You MUST add a final Allow rule to preserve other traffic:
    - action: Allow
  → ONLY add this if the intent contains words like "block", "deny", "restrict".
  → Do NOT add it for pure allow policies.

  If an Allow rule restricts traffic to a specific destination:
- You MUST add a final "Allow" rule to permit all other traffic
- Unless the intent explicitly requires restricting all other traffic

STRUCTURE VALIDATION:
- Must start with apiVersion
- Must include: kind, metadata.name, metadata.namespace, spec.selector
- spec.selector must use Calico syntax (e.g. app == "name"), not matchLabels

INTENT MATCHING:
- Source/destination labels must match intent exactly using app == "podname"
- Direction (Ingress/Egress) must match intent
- Action (Allow/Deny) must match intent

- Source/destination labels must match intent exactly using app == "podname"
- Direction (Ingress/Egress) must match intent
- Action (Allow/Deny) must match intent

CILIUM SYNTAX (CRITICAL - always enforce):
- NEVER add "action" field inside egress, ingress, egressDeny, or ingressDeny rules.
- NEVER use matchExpressions with operator: NotIn to implement a deny intent.
  NotIn is only valid for allow rules that restrict allowed destinations.
- For DENY intents: use 'egressDeny' or 'ingressDeny' with toEndpoints/fromEndpoints.
- For ALLOW intents: use 'egress' or 'ingress' with toEndpoints/fromEndpoints.
- NEVER use "policyType", "rules", or "spec.action" fields.
- Ports MUST be strings: port: "80" not port: 80.
- Protocol MUST be one of: TCP, UDP, SCTP, ANY. NEVER use ALL.
- If the intent is allow all traffic: egress: [{}]
- If the YAML uses 'egress' with NotIn for a deny intent → replace with 'egressDeny' + matchLabels.

DENY DETECTION RULE:
- If the translated intent contains words like "block", "deny", "restrict", "drop" →
  the policy MUST use egressDeny or ingressDeny, never egress with NotIn.

If everything is correct → return: VALID
Otherwise → return the full corrected YAML."""

TEST_GENERATOR_PROMPT = """
You are a Kubernetes network policy testing expert.

You will receive a network intent.
Your task is to output ONLY an executable bash script that verifies the policy is correctly enforced using kubectl.

STRICT OUTPUT RULES:

* Output ONLY the bash script, nothing else
* Do NOT write any explanation, reasoning, comments outside the script, or markdown
* Start the script immediately with #!/bin/bash
* Do NOT use -i or -t flags in kubectl exec (non-interactive mode only)
* Do NOT use nc or netcat
* Do NOT use /dev/tcp
* Do NOT use curl

CONNECTIVITY TEST METHOD (MANDATORY):

* All pods expose port 80
* Test connectivity using:
  kubectl exec <POD> -- wget --spider --timeout=3 http://<service>:80
* An allowed connection: exit code 0 → SUCCESS
* A blocked connection: exit code non-zero → SUCCESS

INTENT TYPE RULES (MANDATORY):

* If the intent is DENY → test that the connection is BLOCKED (exit code != 0)
* If the intent is ALLOW → test that the connection is ALLOWED (exit code == 0)
* NEVER output YAML — output ONLY a bash script
* The script tests connectivity, it does NOT apply or define any policy
* Do NOT reproduce or reference the NetworkPolicy YAML in the script

### KUBERNETES CNI PROPAGATION RULE (CRITICAL) ###
Network Policies applied to Kubernetes are not propagated instantaneously by the CNI plugin (e.g., Cilium, Calico). There is a propagation delay.
To avoid race conditions and false negatives, your test script MUST NOT rely on a single attempt.

### SCRIPT STRUCTURE RULES (MANDATORY) ###
1.  **Strict Output Rules**: Output ONLY the bash script starting with #!/bin/bash. No markdown, no explanations.
2.  **Tool Adaptation**: Verify if the pod has 'curl' or 'wget'. If unknown, assume 'wget' or try both.
3.  **RETRY LOGIC for ALLOW intent (MANDATORY)**:
    If the intent is ALLOW, a connection failure on the first attempt might be due to propagation delay. You MUST implement a retry loop in Bash:
    - Attempt the connection (e.g., wget or curl).
    - If it fails, sleep for 1-2 seconds and retry.
    - Loop up to **5 attempts** (total max 10 seconds).
    - If it passes within 5 attempts, log SUCCESS.
    - If it fails after 5 attempts, log FAIL.
4.  **RETRY LOGIC for DENY intent (MANDATORY)**:
    If the intent is DENY, you MUST verify the rule is eventually active. Implement a similar retry loop:
    - Attempt the connection.
    - If it SUCCEEDS (meaning it's not yet blocked), sleep and retry.
    - Loop up to **5 attempts**.
    - If it fails (blocked) within 5 attempts, log SUCCESS.
    - If it still succeeds after 5 attempts, log FAIL.

- Protocol: ALWAYS test TCP connectivity on port 80.
- Check BOTH exit code and tool output (000/timeout) for reliability.

SCRIPT STRUCTURE (follow exactly):
#!/bin/bash
set -uo pipefail

# Retrieve pod names

SOURCE_POD=$(kubectl get pods -l app=<source> -o jsonpath='{.items[0].metadata.name}')

echo "=== ALLOWED CONNECTIONS ==="
kubectl exec $SOURCE_POD -- wget --spider --timeout=3 http://<allowed-service>:80 >/dev/null 2>&1
if [ $? -eq 0 ]; then
echo "SUCCESS: <source> -> <allowed-service> is allowed"
else
echo "FAIL: <source> -> <allowed-service> should be allowed but is blocked"
fi

echo "=== BLOCKED CONNECTIONS ==="
kubectl exec $SOURCE_POD -- wget --spider --timeout=3 http://<blocked-service>:80 >/dev/null 2>&1
if [ $? -ne 0 ]; then
echo "SUCCESS: <source> -> <blocked-service> is blocked"
else
echo "FAIL: <source> -> <blocked-service> should be blocked but is allowed"
fi
"""

GROQ_MODEL = None

def get_args():
    parser = argparse.ArgumentParser(description="Run a Flask server for text generation using Groq API.")
    parser.add_argument("--model", type=str, required=True, help="Groq model ID to use.")
    parser.add_argument("--port", type=int, required=True, help="Port for the Flask server.")
    return parser.parse_args()

def translate_intent(intent, client):
    """Use LLM1 to generate a more detailed prompt."""
    completion = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": INTENT_TRANSLATOR_PROMPT},
            {"role": "user", "content": intent}
        ],
        temperature=0.2,
        max_tokens=256,
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
    # remove <think>...</think>
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()

    match = re.search(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL)
    if match:
        candidate = match.group(1).strip()
        if candidate.startswith("#!/bin/bash"):
            return candidate

    # search for #!/bin/bash 
    match = re.search(r'(#!/bin/bash.*?)(?:\n\n[A-Z]|\Z)', text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Return empty string if not a shell script
    return ""

def generate_text(prompt):
    """Generate and validate the YAML policy"""
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
            "testing_done": False
        })
        return {
            "yaml": final_state["yaml_output"],
            "test": final_state.get("test_script", "")
        }

    except Exception as e:
        print(f"Error calling Groq API: {str(e)}", flush=True)
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

MAX_ITER = 3

# --- Node ---
def node_translate(state: PolicyState, client) -> PolicyState:
    translated = translate_intent(state["original_prompt"], client)
    return {**state, "technical_prompt": translated}

def node_validate(state: PolicyState, client) -> PolicyState:
    completion = client.chat.completions.create(
        model=VALIDATOR_MODEL,
        messages=[
            {"role": "system", "content": VALIDATION_PROMPT},
            {"role": "user", "content": f"INTENT:\n{state['technical_prompt']}\n\nYAML:\n{state['yaml_output']}"}
        ],
        temperature=0.0,
        max_tokens=4096,
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

def node_generate(state: PolicyState, client) -> PolicyState:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    if state["iterations"] > 0 and state["yaml_output"]:
        messages.append({
            "role": "user",
            "content": (
                f"{state['technical_prompt']}\n\n"
                f"Previous attempt was invalid. Here is the partially corrected YAML — "
                f"fix any remaining issues:\n{state['yaml_output']}"
            )
        })
    else:
        messages.append({"role": "user", "content": state["technical_prompt"]})

    completion = client.chat.completions.create(
        model=GENERATOR_MODEL,  
        messages=messages,
        temperature=0.0,
        max_tokens=4096,    
    )
    raw = extract_yaml(completion.choices[0].message.content.strip())  # ← rimuove <think>
    return {**state, "yaml_output": raw, "iterations": state["iterations"] + 1}

def node_testing(state: PolicyState, client) -> PolicyState:
    completion = client.chat.completions.create(
        model=VALIDATOR_MODEL,
        messages=[
            {
                "role": "system",
                "content": TEST_GENERATOR_PROMPT
            },
            {
                "role": "user",
                "content": f"INTENT:\n{state['technical_prompt']}"  # ← solo l'intent, non lo YAML
            }
        ],
        temperature=0.1,
        max_tokens=4096,
    )
    script = extract_script(completion.choices[0].message.content.strip())
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
    try:
        result = generate_text(data['prompt'])
        return jsonify(result), 200
    except Exception as e:
        print(f"Error: {str(e)}", flush=True)
        return jsonify({"error": str(e)}), 500
    #return Response(generated_text, status=200, mimetype='text/plain')

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "backend": "groq", "model": GROQ_MODEL}), 200

if __name__ == "__main__":
    args = get_args()
    GROQ_MODEL = args.model
    print(f"Starting Flask server with Groq API backend...")
    print(f"Make sure GROQ_API_KEY environment variable is set")
    print(f"Using Groq model: {GROQ_MODEL}")
    app.run(host='0.0.0.0', port=args.port)
