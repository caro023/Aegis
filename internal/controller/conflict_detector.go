package controller

import (
	"context"
	"fmt"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/go-logr/logr"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConflictResolution described a removed policy
type ConflictResolution struct {
	Name      string
	Namespace string
	CNI       string
	Kind      string
	Reason    string
}

// parsedPolicy contains extracted info from a policy YAML
type parsedPolicy struct {
	name         string
	namespace    string
	cniType      string // "cilium" | "calico"
	podSelector  map[string]string
	ingressRules []parsedRule
	egressRules  []parsedRule
}

// parsedRule is a sigled normalized rule
type parsedRule struct {
	action       string            // "allow" | "deny"
	peerSelector map[string]string // from/to
	peerIsAny    bool              // true se matchLabels: {} (all pods)
	ports        []string          // es. ["6379/TCP", "53/UDP"]
}

func DetectAndResolveConflicts(
	ctx context.Context,
	k8sClient client.Client,
	logger logr.Logger,
	newPoliciesYAML []string,
	cniType string,
	namespace string,
) ([]ConflictResolution, error) {

	// Parse new policy from YAML
	newPolicies := make([]parsedPolicy, 0, len(newPoliciesYAML))
	for _, rawYAML := range newPoliciesYAML {
		for _, doc := range splitYAMLDocuments(rawYAML) {
			pp, err := parsePolicyYAML(doc, cniType)
			if err != nil {
				logger.Info("[ConflictDetector] Could not parse new policy YAML, skipping",
					"error", err)
				continue
			}
			newPolicies = append(newPolicies, pp)
		}
	}

	if len(newPolicies) == 0 {
		return nil, nil
	}

	// List the existing policies
	existing, err := listExistingPolicies(ctx, k8sClient, cniType, namespace)
	if err != nil {
		return nil, fmt.Errorf("listing existing policies: %w", err)
	}

	// Retrieve and remove conflicts
	var resolutions []ConflictResolution

	for _, newP := range newPolicies {
		for _, exP := range existing {
			reason := detectConflict(newP, exP)
			if reason == "" {
				continue
			}

			if err := deleteExistingPolicy(ctx, k8sClient, exP, cniType); err != nil {
				logger.Error(err, "[ConflictDetector] Failed to delete conflicting policy",
					"name", exP.name)
				continue
			}

			resolutions = append(resolutions, ConflictResolution{
				Name:      exP.name,
				Namespace: exP.namespace,
				CNI:       cniType,
				Kind:      policyKind(cniType),
				Reason:    reason,
			})
		}
	}

	return resolutions, nil
}

func detectConflict(newP, exP parsedPolicy) string {
	if !selectorMatches(newP.podSelector, exP.podSelector) {
		return ""
	}

	// Check ingress rules
	for _, nr := range newP.ingressRules {
		for _, er := range exP.ingressRules {
			if reason := ruleConflict(nr, er, "ingress"); reason != "" {
				return reason
			}
		}
	}

	// Check egress rules
	for _, nr := range newP.egressRules {
		for _, er := range exP.egressRules {
			if reason := ruleConflict(nr, er, "egress"); reason != "" {
				return reason
			}
		}
	}

	return ""
}

func ruleConflict(nr, er parsedRule, direction string) string {
	if !peersOverlap(nr, er) {
		return ""
	}

	if !portsOverlap(nr.ports, er.ports) {
		return ""
	}

	if nr.action == er.action {
		return fmt.Sprintf(
			"residual policy: %s rule with same action (%s) and overlapping selectors/ports",
			direction, nr.action,
		)
	}

	return fmt.Sprintf(
		"direct conflict: %s rule — new policy action=%s conflicts with existing action=%s on overlapping selectors/ports",
		direction, nr.action, er.action,
	)
}

func peersOverlap(a, b parsedRule) bool {
	if a.peerIsAny || b.peerIsAny {
		return true
	}
	return selectorMatches(a.peerSelector, b.peerSelector)
}

// portsOverlap: due insiemi di porte si sovrappongono se condividono
// almeno una porta, oppure se almeno un insieme è vuoto (tutte le porte)
func portsOverlap(aPorts, bPorts []string) bool {
	if len(aPorts) == 0 || len(bPorts) == 0 {
		return true
	}
	for _, ap := range aPorts {
		for _, bp := range bPorts {
			if ap == bp {
				return true
			}
		}
	}
	return false
}

// selectorMatches: due label selector sono identici se hanno
// esattamente le stesse coppie chiave/valore.
func selectorMatches(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// parsePolicyYAML converte un singolo documento YAML in parsedPolicy.
// Supporta CiliumNetworkPolicy e Calico NetworkPolicy.
func parsePolicyYAML(rawYAML, cniType string) (parsedPolicy, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(rawYAML), &doc); err != nil {
		return parsedPolicy{}, err
	}

	meta, _ := doc["metadata"].(map[string]interface{})
	name, _ := meta["name"].(string)
	ns, _ := meta["namespace"].(string)
	spec, _ := doc["spec"].(map[string]interface{})

	pp := parsedPolicy{
		name:      name,
		namespace: ns,
		cniType:   cniType,
	}

	switch cniType {
	case "cilium":
		pp.podSelector = extractCiliumSelector(spec, "endpointSelector")
		pp.ingressRules = extractCiliumRules(spec, "ingress", "allow")
		pp.ingressRules = append(pp.ingressRules,
			extractCiliumRules(spec, "ingressDeny", "deny")...)
		pp.egressRules = extractCiliumRules(spec, "egress", "allow")
		pp.egressRules = append(pp.egressRules,
			extractCiliumRules(spec, "egressDeny", "deny")...)

	case "calico":
		sel, _ := spec["selector"].(string)
		pp.podSelector = parseCalicoSelector(sel)
		pp.ingressRules = extractCalicoRules(spec, "ingress")
		pp.egressRules = extractCalicoRules(spec, "egress")
	}

	return pp, nil
}

// ── Cilium helpers ────────────────────────────────────────────────────────────

func extractCiliumSelector(spec map[string]interface{}, key string) map[string]string {
	sel, _ := spec[key].(map[string]interface{})
	ml, _ := sel["matchLabels"].(map[string]interface{})
	result := make(map[string]string, len(ml))
	for k, v := range ml {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}

func extractCiliumRules(spec map[string]interface{}, key, action string) []parsedRule {
	rulesRaw, ok := spec[key].([]interface{})
	if !ok {
		return nil
	}
	var rules []parsedRule
	for _, r := range rulesRaw {
		rm, _ := r.(map[string]interface{})

		// Peer selector: toEndpoints (egress) o fromEndpoints (ingress)
		var peerSel map[string]string
		peerIsAny := false
		for _, peerKey := range []string{"toEndpoints", "fromEndpoints"} {
			peers, ok := rm[peerKey].([]interface{})
			if !ok || len(peers) == 0 {
				continue
			}
			firstPeer, _ := peers[0].(map[string]interface{})
			ml, _ := firstPeer["matchLabels"].(map[string]interface{})
			if len(ml) == 0 {
				peerIsAny = true
			} else {
				peerSel = make(map[string]string, len(ml))
				for k, v := range ml {
					peerSel[k] = fmt.Sprintf("%v", v)
				}
			}
		}

		// Porte
		var ports []string
		toPorts, _ := rm["toPorts"].([]interface{})
		for _, tp := range toPorts {
			tpm, _ := tp.(map[string]interface{})
			portsRaw, _ := tpm["ports"].([]interface{})
			for _, p := range portsRaw {
				pm, _ := p.(map[string]interface{})
				port, _ := pm["port"].(string)
				proto, _ := pm["protocol"].(string)
				if proto == "" {
					proto = "TCP"
				}
				ports = append(ports, port+"/"+proto)
			}
		}

		rules = append(rules, parsedRule{
			action:       action,
			peerSelector: peerSel,
			peerIsAny:    peerIsAny,
			ports:        ports,
		})
	}
	return rules
}

// ── Calico helpers ────────────────────────────────────────────────────────────

// parseCalicoSelector converte un selettore Calico stringa
// (es. `app == "frontend"`) in una mappa chiave/valore.
// Supporta solo la forma semplice "key == value"; le espressioni
// composte vengono trattate come "any" per semplicità.
func parseCalicoSelector(sel string) map[string]string {
	sel = strings.TrimSpace(sel)
	if sel == "" || sel == "all()" {
		return map[string]string{}
	}
	// Forma semplice: key == "value"
	parts := strings.SplitN(sel, "==", 2)
	if len(parts) != 2 {
		return map[string]string{}
	}
	key := strings.TrimSpace(parts[0])
	val := strings.Trim(strings.TrimSpace(parts[1]), `"`)
	return map[string]string{key: val}
}

func extractCalicoRules(spec map[string]interface{}, direction string) []parsedRule {
	rulesRaw, ok := spec[direction].([]interface{})
	if !ok {
		return nil
	}
	var rules []parsedRule
	for _, r := range rulesRaw {
		rm, _ := r.(map[string]interface{})
		action, _ := rm["action"].(string)
		action = strings.ToLower(action)

		// Peer: source (ingress) o destination (egress)
		peerKey := "source"
		if direction == "egress" {
			peerKey = "destination"
		}
		peerBlock, _ := rm[peerKey].(map[string]interface{})
		peerSelStr, _ := peerBlock["selector"].(string)
		peerSel := parseCalicoSelector(peerSelStr)
		peerIsAny := peerSelStr == "" || peerSelStr == "all()"

		// Calico's port in destination.ports
		var ports []string
		dest, _ := rm["destination"].(map[string]interface{})
		proto, _ := rm["protocol"].(string)
		if proto == "" {
			proto = "TCP"
		}
		rawPorts, _ := dest["ports"].([]interface{})
		for _, p := range rawPorts {
			ports = append(ports, fmt.Sprintf("%v/%s", p, proto))
		}

		rules = append(rules, parsedRule{
			action:       action,
			peerSelector: peerSel,
			peerIsAny:    peerIsAny,
			ports:        ports,
		})
	}
	return rules
}

// listExistingPolicies list the existing policies
func listExistingPolicies(
	ctx context.Context,
	k8sClient client.Client,
	cniType, namespace string,
) ([]parsedPolicy, error) {

	gvr := policyGVR(cniType)
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gvr.Group,
		Version: gvr.Version,
		Kind:    policyKind(cniType) + "List",
	})

	if err := k8sClient.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	var policies []parsedPolicy
	for _, item := range list.Items {
		rawYAML, err := item.MarshalJSON()
		if err != nil {
			continue
		}
		pp, err := parsePolicyYAML(string(rawYAML), cniType)
		if err != nil {
			continue
		}
		if pp.name == "" {
			pp.name = item.GetName()
		}
		if pp.namespace == "" {
			pp.namespace = item.GetNamespace()
		}
		policies = append(policies, pp)
	}
	return policies, nil
}

// deleteExistingPolicy delete the existing policy
func deleteExistingPolicy(
	ctx context.Context,
	k8sClient client.Client,
	p parsedPolicy,
	cniType string,
) error {
	gvr := policyGVR(cniType)
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gvr.Group,
		Version: gvr.Version,
		Kind:    policyKind(cniType),
	})
	obj.SetName(p.name)
	obj.SetNamespace(p.namespace)
	return k8sClient.Delete(ctx, obj)
}

// InjectCalicoOrder add the field order to Calico's policies, giving to the new policies higher priority
func InjectCalicoOrder(rawYAML string) string {
	const kubeTeusOrder = "50.0"

	lines := strings.Split(rawYAML, "\n")
	var result []string
	inSpec := false

	for _, line := range lines {
		result = append(result, line)
		trimmed := strings.TrimSpace(line)

		if trimmed == "spec:" {
			inSpec = true
			continue
		}
		if inSpec && trimmed == "spec:" {
			result = append(result, "  order: "+kubeTeusOrder)
			inSpec = false
			continue
		}
		if inSpec && strings.HasPrefix(trimmed, "selector:") {
			idx := len(result) - 1
			result = append(result[:idx],
				append([]string{"  order: " + kubeTeusOrder}, result[idx:]...)...)
			inSpec = false
		}
	}
	return strings.Join(result, "\n")
}

type groupVersionResource struct {
	Group   string
	Version string
	Kind    string
}

func policyGVR(cniType string) groupVersionResource {
	switch cniType {
	case "cilium":
		return groupVersionResource{
			Group:   "cilium.io",
			Version: "v2",
			Kind:    "CiliumNetworkPolicy",
		}
	case "calico":
		return groupVersionResource{
			Group:   "crd.projectcalico.org",
			Version: "v1",
			Kind:    "NetworkPolicy",
		}
	default:
		return groupVersionResource{
			Group:   "networking.k8s.io",
			Version: "v1",
			Kind:    "NetworkPolicy",
		}
	}
}

func policyKind(cniType string) string {
	switch cniType {
	case "cilium":
		return "CiliumNetworkPolicy"
	default:
		return "NetworkPolicy"
	}
}

var _ = metav1.ObjectMeta{}
var _ = ciliumv2.CiliumNetworkPolicy{} //caso il file sia standalone.
