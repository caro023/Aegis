import os
import re
import argparse
from flask import Flask, request, jsonify, Response
from groq import Groq
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated
import operator

app = Flask(__name__)
VALIDATOR_MODEL = "qwen/qwen3-32b"
GENERATOR_MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """You are a Kubernetes security engineer.
Your task is to generate valid, production-ready YAML for CiliumNetworkPolicy, CalicoNetworkPolicy, Antrea, Weave or standard NetworkPolicy.

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
   - MUST include:
     name (kebab-case, e.g., deny-frontend-egress)
     namespace: default

2. endpointSelector:
   - MUST use matchLabels
   - If selecting all pods → use:
     matchLabels: {}

3. egress / ingress rules:
   - DO NOT use "action"
   - CiliumNetworkPolicy DOES NOT support "Allow" or "Deny" fields
   - Traffic is allowed ONLY if explicitly specified

4. DENY LOGIC:
   - Cilium does NOT support explicit deny rules
   - To block traffic, you MUST:
     - allow all EXCEPT the target using matchExpressions
   - Example:
     matchExpressions:
     - key: app
       operator: NotIn
       values: ["checkoutservice"]

5. Ports:
   - If ports are specified:
     ports MUST be strings
     Example:
     toPorts:
     - ports:
       - port: "80"
         protocol: TCP

6. Default behavior:
   - If no egress rules → deny all egress
   - If no ingress rules → deny all ingress

--------------------------------------------------
CORRECT EXAMPLE:

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

--------------------------------------------------
ANOTHER EXAMPLE (implicit deny):

Intent: "Block frontend → checkoutservice"

Correct approach:
- DO NOT write a deny rule
- Allow only other destinations (or restrict allowed ones)

Example:

apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: restrict-frontend-egress
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: frontend
  egress:
  - toEndpoints:
    - matchExpressions:
      - key: app
        operator: NotIn
        values:
        - checkoutservice
  ingress: []

GENERAL RULES:
- Output ONLY the YAML.
- No explanations or comments.
- Start directly with 'apiVersion:'."""

INTENT_TRANSLATOR_PROMPT = """You are a Kubernetes network security expert.
Your task is to translate a high-level security intent into a detailed technical prompt for generating a Kubernetes network policy.

The output must be a single sentence or short paragraph describing:
- Which pod or service is the source (use the pod name and label if provided)
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
Output ONLY the translated prompt, no explanations."""

VALIDATION_PROMPT = """You are a Kubernetes network policy validator and fixer.

Your task:
- Validate that the given YAML correctly implements the provided technical intent.
- If the YAML is incorrect, fix it. If correct, return VALID.

OUTPUT RULES (MANDATORY):
- Return ONLY the word VALID or the corrected YAML.
- NO explanations, comments, markdown, or reasoning.
- NO text before or after the YAML.

CALICO SYNTAX (CRITICAL - always enforce):
- ingress rules: use 'source' to match origin pods. NEVER use 'from'.
- egress rules: use 'destination' to match target pods. NEVER use 'to'.
- NEVER use 'podSelector' or 'namespaceSelector'.
- 'egress' and 'ingress' MUST be lists, never objects ({}).
- If 'from', 'to', 'podSelector', 'namespaceSelector' are found → replace them.

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
- NEVER add "action" field inside egress or ingress rules.
- NEVER use "action: Allow" or "action: Deny" anywhere in the spec.
- To DENY traffic in Cilium: use matchExpressions with operator: NotIn.
- To ALLOW traffic: simply list the endpoints in toEndpoints/fromEndpoints.
- NEVER use "policyType", "rules", or "spec.action" fields.
- Ports MUST be strings: port: "80" not port: 80.
- Protocol MUST be one of: TCP, UDP, SCTP, ANY. NEVER use ALL.

If everything is correct → return: VALID
Otherwise → return the full corrected YAML."""
GROQ_MODEL = None

def get_args():
    parser = argparse.ArgumentParser(description="Run a Flask server for text generation using Groq API.")
    parser.add_argument("--model", type=str, required=True, help="Groq model ID to use.")
    parser.add_argument("--port", type=int, required=True, help="Port for the Flask server.")
    return parser.parse_args()

def translate_intent(intent, client):
    """Use LLM1 to generaate a more detailed prompt."""
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
            "iterations": 0,
            "max_iterations": MAX_ITER,
        })
        return final_state["yaml_output"]

    except Exception as e:
        print(f"Error calling Groq API: {str(e)}", flush=True)
        return jsonify({"error": str(e)}), 500
    


# --- Stato condiviso tra i nodi ---
class PolicyState(TypedDict):
    original_prompt: str
    technical_prompt: str
    yaml_output: str
    validation_result: str   # "valid" | "invalid"
    iterations: int
    max_iterations: int

MAX_ITER = 3

# --- Nodi ---
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

    if raw.upper().startswith("VALID"):
        return {**state, "validation_result": "valid"}
    else:
        return {**state, "yaml_output": raw, "validation_result": "invalid"}

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
        model=GENERATOR_MODEL,  # ← era GROQ_MODEL, ora usa Qwen
        messages=messages,
        temperature=0.1,
        max_tokens=4096,        # ← aumenta perché Qwen emette <think> lungo
    )
    raw = extract_yaml(completion.choices[0].message.content.strip())  # ← rimuove <think>
    return {**state, "yaml_output": raw, "iterations": state["iterations"] + 1}

# --- Routing ---
def should_continue(state: PolicyState) -> str:
    if state["validation_result"] == "valid":
        return "end"
    if state["iterations"] >= state["max_iterations"]:
        print("Max iterations reached, returning best effort YAML")
        return "end"
    return "generate"  # torna a rigenerare col YAML fixato come contesto

# --- Costruzione del grafo ---
def build_graph(client):
    graph = StateGraph(PolicyState)

    graph.add_node("translate",  lambda s: node_translate(s, client))
    graph.add_node("generate",   lambda s: node_generate(s, client))
    graph.add_node("validate",   lambda s: node_validate(s, client))

    graph.set_entry_point("translate")
    graph.add_edge("translate", "generate")
    graph.add_edge("generate", "validate")

    graph.add_conditional_edges(
        "validate",
        should_continue,
        {"generate": "generate", "end": END}
    )

    return graph.compile()

@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({"error": "Invalid request, missing 'prompt' field"}), 400
    prompt = data['prompt']
    generated_text = generate_text(prompt)
    return Response(generated_text, status=200, mimetype='text/plain')

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
