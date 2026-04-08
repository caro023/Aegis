import os
import re
import argparse
from flask import Flask, request, jsonify, Response
from groq import Groq

app = Flask(__name__)

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

def generate_text(prompt):
    """Generate the YAML policy using LLM2"""
    try:
        groq_api_key = os.environ.get("GROQ_API_KEY")
        if not groq_api_key:
            raise RuntimeError("GROQ_API_KEY not set")
        
        client = Groq(api_key=groq_api_key)

        # Step 1: translate intent in a technical prompt
        technical_prompt = translate_intent(prompt, client)

        # Step 2: generate the YAML
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": technical_prompt}
            ],
            temperature=0.1,
            max_tokens=1024,
        )
        generated_text = completion.choices[0].message.content.strip()
        print(f"Generated text: {generated_text}", flush=True)
        return generated_text

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
