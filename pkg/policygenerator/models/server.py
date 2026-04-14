import os
import re
import argparse
from flask import Flask, request, jsonify, Response
from groq import Groq

app = Flask(__name__)
VALIDATOR_MODEL = "llama-3.1-8b-instant"

SYSTEM_PROMPT = """You are a Kubernetes security engineer.
Your task is to generate valid, production-ready YAML for CiliumNetworkPolicy, CalicoNetworkPolicy, Antrea, Weave or standard NetworkPolicy.
STRICT SYNTAX RULES FOR CALICO:
1. Use 'kind: NetworkPolicy' for namespaced policies.
2. Use 'selector' as a string expression, e.g. 'app == "frontend"' or 'all()' for all pods.
3. Always include 'namespace' in metadata.

STRICT SYNTAX RULES FOR CILIUM:
1. 'metadata': ALWAYS include 'name' (kebab-case, e.g., 'deny-frontend-egress') and 'namespace: default'.
2. 'toPorts': The 'port' field MUST be a string inside an object.
   CORRECT: - ports: [{port: "8080", protocol: TCP}]
   INCORRECT: - ports: [8080]
3. 'endpointSelector': Always use 'matchLabels'. If targeting all pods, use 'matchLabels: {}'.
GENERAL RULES:
- Output ONLY the YAML.
- No markdown code blocks (no ```yaml).
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

If the intent is too generic or does not mention specific pods, infer reasonable defaults based on common Kubernetes security practices.
IMPORTANT: If the input specifies a policy type (e.g. "Generate a CalicoNetworkPolicy" or "Generate a CiliumNetworkPolicy"), you MUST preserve that exact instruction at the end of your output.
Output ONLY the translated prompt, no explanations."""

VALIDATION_PROMPT = """You are a Kubernetes network policy validator and fixer.

Your task:
- Validate that the given YAML correctly implements the provided technical intent.
- The intent is already translated into a precise technical description.
- If the YAML is incorrect, incomplete, or inconsistent with the intent, you MUST fix it.

STRICT RULES:
- You MUST return ONLY the word VALID or the correct YAML.
- You MUST NOT include explanations, comments, markdown, or reasoning.
- You MUST NOT include any text before or after the YAML.
- This is mandatory because the output is parsed by an automated pipeline and any extra text will break the application.


VALIDATION REQUIREMENTS:
- Ensure the policy correctly matches the intended pods (labels must be correct).
- Ensure direction (ingress/egress) is correct.
- Ensure ports and protocols are correct.
- Ensure no overly permissive rules (e.g., matchLabels: {} unless explicitly intended).
- Ensure the YAML is syntactically valid and production-ready.

Output ONLY the final corrected YAML or VALID."""

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

def validate_yaml(technical_prompt, yaml_text, client):
    """Use LLM3 to validate and fix the generated YAML."""
    completion = client.chat.completions.create(
        model=VALIDATOR_MODEL,
        messages=[
            {
                "role": "system",
                "content": VALIDATION_PROMPT
            },
            {
                "role": "user",
                "content": f"INTENT:\n{technical_prompt}\n\nYAML:\n{yaml_text}"
            }
        ],
        temperature=0.0,
        max_tokens=1024,
    )

    validated_yaml = completion.choices[0].message.content.strip()
    print(f"Validated YAML: {validated_yaml}", flush=True)
    return validated_yaml

def extract_yaml(text):
    """Extract YAML content from markdown code block."""
    match = re.search(r"```(?:yaml)?\n(.*?)```", text, re.DOTALL)
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

        # Step 1: translate intent
        technical_prompt = translate_intent(prompt, client)

        # Step 2: generate YAML
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": technical_prompt}
            ],
            temperature=0.1,
            max_tokens=1024,
        )

        generated_yaml = completion.choices[0].message.content.strip()
        print(f"Generated YAML: {generated_yaml}", flush=True)

        # Step 3: validate + fix YAML
        raw_output = completion.choices[0].message.content.strip()
        validated_yaml = extract_yaml(raw_output)

        print(f"Raw validator output: {raw_output}", flush=True)
        print(f"Clean YAML: {validated_yaml}", flush=True)

        return validated_yaml

    except Exception as e:
        print(f"Error calling Groq API: {str(e)}", flush=True)
        return jsonify({"error": str(e)}), 500

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
