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
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ──────────────────────────────────────────────────────────────────────────────
// Tipi pubblici
// ──────────────────────────────────────────────────────────────────────────────

// ConflictResolution descrive una policy rimossa o de-prioritizzata.
type ConflictResolution struct {
	Name      string
	Namespace string
	CNI       string
	Kind      string
	Reason    string
}

// parsedPolicy contiene le informazioni estratte da uno YAML di policy,
// normalizzate in un formato comune per il confronto.
type parsedPolicy struct {
	name      string
	namespace string
	cniType   string // "cilium" | "calico"

	// endpointSelector / selector (il pod a cui la policy si applica)
	podSelector map[string]string

	// regole ingress e egress come slice di regole normalizzate
	ingressRules []parsedRule
	egressRules  []parsedRule
}

// parsedRule è una singola regola normalizzata (ingress o egress).
type parsedRule struct {
	action       string            // "allow" | "deny"
	peerSelector map[string]string // selettore del peer (from/to)
	peerIsAny    bool              // true se matchLabels: {} (tutti i pod)
	ports        []string          // es. ["6379/TCP", "53/UDP"]
}

// ──────────────────────────────────────────────────────────────────────────────
// Funzione principale
// ──────────────────────────────────────────────────────────────────────────────

// DetectAndResolveConflicts analizza le policy che stanno per essere applicate,
// le confronta con quelle già presenti nel cluster e:
//
//  1. Rimuove le policy RESIDUE (stessa direzione, stesso pod, azione compatibile
//     ma policy precedente non pulita) — sia Cilium che Calico.
//  2. Rimuove le policy in CONFLITTO DIRETTO (stessa direzione, stesso pod,
//     azione opposta, stessa porta) — sia Cilium che Calico.
//  3. Solo Calico: assegna un campo "order" basso (alta priorità) alla nuova
//     policy per gestire i conflitti di SOVRAPPOSIZIONE che non sono stati
//     rimossi (es. una deny-all più ampia residua).
//
// Va chiamata DOPO la validazione e PRIMA dell'enforcement.
func DetectAndResolveConflicts(
	ctx context.Context,
	k8sClient client.Client,
	logger logr.Logger,
	newPoliciesYAML []string,
	cniType string,
	namespace string,
) ([]ConflictResolution, error) {

	logger.Info("[ConflictDetector] Entering", "cniType", cniType, "namespace", namespace, "yamlCount", len(newPoliciesYAML))
	// 1. Parsa le nuove policy dallo YAML
	newPolicies := make([]parsedPolicy, 0, len(newPoliciesYAML))
	logger.Info("[ConflictDetector] Parsed policies", "count", len(newPolicies))
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

	// 2. Elenca le policy esistenti nel cluster per questo CNI e namespace
	existing, err := listExistingPolicies(ctx, k8sClient, cniType, namespace)
	if err != nil {
		return nil, fmt.Errorf("listing existing policies: %w", err)
	}

	logger.Info("[ConflictDetector] Existing policies found", "count", len(existing))
	for _, p := range existing {
		logger.Info("[ConflictDetector] Existing policy",
			"name", p.name,
			"podSelector", p.podSelector,
			"ingressRules", len(p.ingressRules),
			"egressRules", len(p.egressRules),
		)
	}
	// 3. Rileva e risolvi conflitti
	var resolutions []ConflictResolution

	for _, newP := range newPolicies {
		for _, exP := range existing {
			reason := detectConflict(newP, exP)
			if reason == "" {
				continue
			}

			logger.Info("[ConflictDetector] Conflict detected — removing existing policy",
				"existing", exP.name,
				"namespace", exP.namespace,
				"reason", reason,
			)

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

// ──────────────────────────────────────────────────────────────────────────────
// Logica di rilevamento conflitti
// ──────────────────────────────────────────────────────────────────────────────

// detectConflict confronta una nuova policy con una esistente e restituisce
// una stringa descrittiva se c'è conflitto, altrimenti "".
//
// Casi rilevati:
//
//	A. Policy RESIDUA: stesso endpointSelector, stessa direzione, stessa azione
//	   → la vecchia policy fa la stessa cosa e va rimossa per evitare duplicati
//	   che possono creare race condition nel datapath.
//	B. Conflitto DIRETTO: stesso endpointSelector, stessa direzione,
//	   azione OPPOSTA, con almeno una porta/protocollo in comune (o entrambe
//	   senza restrizioni di porta).
func detectConflict(newP, exP parsedPolicy) string {
	// I pod selector devono corrispondere (stessa policy target)
	if !selectorMatches(newP.podSelector, exP.podSelector) {
		return ""
	}

	// Controlla le regole ingress
	for _, nr := range newP.ingressRules {
		for _, er := range exP.ingressRules {
			if reason := ruleConflict(nr, er, "ingress"); reason != "" {
				return reason
			}
		}
	}

	// Controlla le regole egress
	for _, nr := range newP.egressRules {
		for _, er := range exP.egressRules {
			if reason := ruleConflict(nr, er, "egress"); reason != "" {
				return reason
			}
		}
	}

	return ""
}

// ruleConflict confronta due regole nella stessa direzione.
func ruleConflict(nr, er parsedRule, direction string) string {
	// I peer selector devono sovrapporsi
	if !peersOverlap(nr, er) {
		return ""
	}

	// Le porte devono sovrapporsi
	if !portsOverlap(nr.ports, er.ports) {
		return ""
	}

	// Stessa azione → policy residua
	if nr.action == er.action {
		return fmt.Sprintf(
			"residual policy: %s rule with same action (%s) and overlapping selectors/ports",
			direction, nr.action,
		)
	}

	// Azione opposta → conflitto diretto
	return fmt.Sprintf(
		"direct conflict: %s rule — new policy action=%s conflicts with existing action=%s on overlapping selectors/ports",
		direction, nr.action, er.action,
	)
}

// peersOverlap: due regole si sovrappongono se i loro peer selector
// corrispondono, oppure se almeno uno dei due è "any" ({}).
func peersOverlap(a, b parsedRule) bool {
	if a.peerIsAny || b.peerIsAny {
		return true
	}
	return selectorMatches(a.peerSelector, b.peerSelector)
}

// portsOverlap: due insiemi di porte si sovrappongono se condividono
// almeno una porta, oppure se almeno un insieme è vuoto (nessuna
// restrizione di porta = tutte le porte).
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

// ──────────────────────────────────────────────────────────────────────────────
// Parsing degli YAML di policy
// ──────────────────────────────────────────────────────────────────────────────

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
		action = strings.ToLower(action) // "Allow" → "allow"

		// Peer: source (ingress) o destination (egress)
		peerKey := "source"
		if direction == "egress" {
			peerKey = "destination"
		}
		peerBlock, _ := rm[peerKey].(map[string]interface{})
		peerSelStr, _ := peerBlock["selector"].(string)
		peerSel := parseCalicoSelector(peerSelStr)
		peerIsAny := peerSelStr == "" || peerSelStr == "all()"

		// Porte: in Calico stanno in destination.ports
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

// ──────────────────────────────────────────────────────────────────────────────
// Listing e cancellazione delle policy esistenti
// ──────────────────────────────────────────────────────────────────────────────

// listExistingPolicies elenca tutte le policy esistenti nel namespace
// usando il client dinamico (unstructured) per essere indipendente
// dalle versioni CRD installate.
func listExistingPolicies(
	ctx context.Context,
	k8sClient client.Client,
	cniType, namespace string,
) ([]parsedPolicy, error) {

	logger := log.FromContext(ctx)

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
		logger.Info("[ConflictDetector] Parsed policy", "name", pp.name)
		if pp.name == "" {
			pp.name = item.GetName()
		}
		if pp.namespace == "" {
			pp.namespace = item.GetNamespace()
		}
		policies = append(policies, pp)
	}
	logger.Info("[ConflictDetector] Existing policies found", "count", len(policies))
	for _, p := range policies {
		logger.Info("[ConflictDetector] Existing policy",
			"name", p.name,
			"podSelector", p.podSelector,
			"ingressRules", len(p.ingressRules),
			"egressRules", len(p.egressRules),
		)
	}
	return policies, nil
}

// deleteExistingPolicy elimina una policy esistente dal cluster.
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

// ──────────────────────────────────────────────────────────────────────────────
// Calico Order: gestione conflitti di sovrapposizione
// ──────────────────────────────────────────────────────────────────────────────

// InjectCalicoOrder aggiunge il campo "order" alle policy Calico nello YAML
// grezzo, assegnando una priorità alta (numero basso) alle nuove policy.
// Questo gestisce i conflitti di SOVRAPPOSIZIONE che la rimozione non copre:
// se una deny-all residua sopravvive, la nuova policy Allow con order più
// basso la sovrascrive nel datapath Calico.
//
// In Calico: order più basso = priorità più alta.
// Usiamo 50.0 come valore fisso per le policy generate da KubeTeus,
// assumendo che le policy manuali abbiano order > 100 (default Calico).
func InjectCalicoOrder(rawYAML string) string {
	const kubeTeusOrder = "50.0"

	lines := strings.Split(rawYAML, "\n")
	var result []string
	inSpec := false

	for _, line := range lines {
		result = append(result, line)
		trimmed := strings.TrimSpace(line)

		// Dopo "spec:" inseriamo "order:" se non già presente
		if trimmed == "spec:" {
			inSpec = true
			continue
		}
		if inSpec && trimmed == "spec:" {
			// secondo spec: in un multi-doc
			result = append(result, "  order: "+kubeTeusOrder)
			inSpec = false
			continue
		}
		if inSpec && strings.HasPrefix(trimmed, "selector:") {
			// Inseriamo order prima del selector (primo campo del spec Calico)
			idx := len(result) - 1
			result = append(result[:idx],
				append([]string{"  order: " + kubeTeusOrder}, result[idx:]...)...)
			inSpec = false
		}
	}
	return strings.Join(result, "\n")
}

// ──────────────────────────────────────────────────────────────────────────────
// Utilità
// ──────────────────────────────────────────────────────────────────────────────

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

// splitYAMLDocuments divide un multi-documento YAML separato da "---".
// Già definita in test_result_logger.go — se hai entrambi i file nello
// stesso package, rimuovi questa e usa quella.
// La lasciamo qui come riferimento nel caso il file sia standalone.
//func splitYAMLDocumentsCD(yamlStr string) []string {
//	if strings.TrimSpace(yamlStr) == "" {
//		return nil
//	}
//	parts := strings.Split(yamlStr, "\n---")
//	var docs []string
//	for _, p := range parts {
//		p = strings.TrimPrefix(strings.TrimSpace(p), "---")
//		p = strings.TrimSpace(p)
//		if p != "" {
//			docs = append(docs, p)
//		}
//	}
//	return docs
//}

// In test_result_logger.go o conflict_detector.go
//func splitYAMLDocuments(yamlStr string) []string {
//	if strings.TrimSpace(yamlStr) == "" {
//		return nil
//	}
//	// Separa per "\n---" ma attento a non rompere se "---" compare nei valori
//	parts := strings.Split(yamlStr, "\n---")
//	var docs []string
//	for _, p := range parts {
//		p = strings.TrimSpace(p)
//		if p != "" {
//			docs = append(docs, p)
//		}
//	}
//	return docs
//}

// metav1 è importato solo per avere il tipo ObjectMeta disponibile
// nel caso si voglia estendere. Se non usato, rimuovere l'import.
var _ = metav1.ObjectMeta{}
var _ = ciliumv2.CiliumNetworkPolicy{} //caso il file sia standalone.
