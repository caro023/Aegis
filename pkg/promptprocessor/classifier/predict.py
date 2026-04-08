import re
import argparse
import json

# Known Kubernetes service/pod names from the microservices-demo cluster.
# These are recognized as POD_NAME even without the word "pod" after them.
# Add or remove names here based on your actual cluster services.
KNOWN_K8S_SERVICES = {
    'frontend', 'checkoutservice', 'cartservice', 'productcatalogservice',
    'currencyservice', 'paymentservice', 'shippingservice', 'emailservice',
    'recommendationservice', 'adservice', 'redis-cart', 'loadgenerator',
}

# Entity tag patterns (from custom_tokenizer.py + predict.py)
PATTERNS = {
    "POLICY":           re.compile(r'\b(CiliumNetworkPolicy|network policy|security policy|KubeArmorHostPolicy|KubeArmorPolicy|policy|Policy)\b', re.IGNORECASE),
    "LABEL":            re.compile(r"([\w\.-]+)\s*:\s*([\w\.-]+)|(matchLabels|matchlabels)"),
    "POD_NAME":         re.compile(r"'\s*([^']+?)\s*'\s+(pod|pods)\b|\b([^'\s]+)\s+(pod|pods)\b", re.IGNORECASE),
    "NAMESPACE":        re.compile(r"(?<!\w\s)(?<!['\w])\b(\w+)\s+(namespace|namespaces)\b|'([^']+)'(?:\s+namespace)?\b|namespace\s+'([^']+)'", re.IGNORECASE),
    "ACTION":           re.compile(r'\b(allow|allows|deny|denies|block|blocks|audit|restrict|prevent|prevents|blocking)\b', re.IGNORECASE),
    "TRAFFIC_DIRECTION":re.compile(r'\b(ingress|egress|income|incoming|inbound|outcome|outcoming|outbound)\b', re.IGNORECASE),
    "CIDR":             re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b'),
    "PORT":             re.compile(r'\bport\s+(\d+)\b|\b(\d+)\s+port\b|\bport\b|\'(\d+)\'', re.IGNORECASE),
    "PROTOCOL":         re.compile(r'\b(TCP|UDP|ICMP)\b', re.IGNORECASE),
    "PATH":             re.compile(r'(/[a-zA-Z_][-a-zA-Z0-9_/.]*[^/])'),
    "FILE":             re.compile(r'(/[\w/\.-]+\.\w+)(?![/\w])'),
    "HTTP_METHOD":      re.compile(r'\b(POST|GET|PUT|DELETE|PATCH)\b', re.IGNORECASE),
    "HTTP_PATH":        re.compile(r'\b(/[a-zA-Z][a-zA-Z0-9_/.-]*(?![\d/]))\b'),
    "FQDN":             re.compile(r'\b([\w-]+\.)+[\w-]+\.[a-z]{2,}\b(?!:\s*)'),
    "ENDPOINT":         re.compile(r'\b(endpoints|endpoint)\b', re.IGNORECASE),
}

# Keywords that are NOT pod names (common english words to exclude)
NOT_POD_NAMES = {
    'a', 'the', 'this', 'that', 'all', 'any', 'no', 'not', 'pod', 'pods',
    'traffic', 'from', 'to', 'in', 'on', 'at', 'by', 'with', 'for',
    'allow', 'deny', 'block', 'create', 'make', 'set', 'get',
    'incoming', 'outgoing', 'ingress', 'egress', 'inbound', 'outbound',
    'communicate', 'should', 'must', 'can', 'cannot', 'between',
    'network', 'policy', 'security', 'namespace', 'service', 'port',
    'labeled', 'label', 'endpoint', 'endpoints'
}

def classify_entities(text):
    """
    Classify entities in text using regex patterns.
    Returns a list of (start, end, matched_text, entity_type) tuples,
    non-overlapping, sorted by position.
    """
    matches = []

    for entity_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            matched_text = match.group(0).strip()

            # Filter out generic words from POD_NAME
            if entity_type == "POD_NAME":
                # Extract the actual pod name (before " pod")
                pod_name = re.sub(r'\s+(pod|pods)$', '', matched_text, flags=re.IGNORECASE).strip().strip("'")
                if pod_name.lower() in NOT_POD_NAMES:
                    continue
                matched_text = pod_name  # return just the name, without "pod"

            matches.append((match.start(), match.end(), matched_text, entity_type))

    # Also scan for known K8s service names directly (without needing "pod" after them)
    for service_name in KNOWN_K8S_SERVICES:
        pattern = re.compile(r'\b' + re.escape(service_name) + r'\b', re.IGNORECASE)
        for match in pattern.finditer(text):
            matches.append((match.start(), match.end(), service_name, "POD_NAME"))

    # Sort by start position
    matches.sort(key=lambda x: x[0])

    # Remove overlapping matches (keep first/longest)
    non_overlapping = []
    last_end = 0
    for start, end, text_match, entity_type in matches:
        if start >= last_end:
            non_overlapping.append((start, end, text_match, entity_type))
            last_end = end

    return non_overlapping


def infer_action(text):
    """
    If no ACTION entity found, try to infer from negation patterns.
    e.g. 'should not communicate' -> deny
    """
    negation_pattern = re.compile(
        r'\b(should not|must not|cannot|can not|not allow|not communicate|block|prevent|deny)\b',
        re.IGNORECASE
    )
    if negation_pattern.search(text):
        return "deny"
    allow_pattern = re.compile(
        r'\b(should|must|allow|permit|enable)\b',
        re.IGNORECASE
    )
    if allow_pattern.search(text):
        return "allow"
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--text', type=str, required=True, help="Input text for prediction")
    args = parser.parse_args()

    text = args.text
    matches = classify_entities(text)

    entities = [{"text": m[2], "type": m[3]} for m in matches]

    # Check if ACTION was found; if not, infer from context
    has_action = any(e["type"] == "ACTION" for e in entities)
    if not has_action:
        inferred = infer_action(text)
        if inferred:
            entities.append({"text": inferred, "type": "ACTION"})

    result = {"entities": entities}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
