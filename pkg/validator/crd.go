package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

var (
	ciliumNetworkPolicySchema *gojsonschema.Schema
	calicoNetworkPolicySchema *gojsonschema.Schema
)

func init() {
	// Cilium
	ciliumSchemaLoader := gojsonschema.NewStringLoader(loadSchema("cilium_network_policy_crd.json"))
	ciliumSchema, _ := gojsonschema.NewSchema(ciliumSchemaLoader)
	ciliumNetworkPolicySchema = ciliumSchema

	// Calico
	calicoSchemaLoader := gojsonschema.NewStringLoader(loadSchema("calico_network_policy_crd.json"))
	calicoSchema, _ := gojsonschema.NewSchema(calicoSchemaLoader)
	calicoNetworkPolicySchema = calicoSchema
}
func loadSchema(schemaFile string) string {
	// Assuming the file is in the same directory
	path, err := filepath.Abs(filepath.Join("./pkg/validator/schemas", schemaFile))
	if err != nil {
		panic(fmt.Sprintf("failed to get absolute path for schema file: %v", err))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("failed to read schema file: %v", err))
	}
	return string(data)
}

func CRDValidator(policy map[string]interface{}) []error {
	var validationErrors []error

	var schema *gojsonschema.Schema
	var policyJSON []byte
	var err error

	kind, ok := policy["kind"].(string)
	if !ok {
		validationErrors = append(validationErrors, fmt.Errorf("missing policy kind"))
		return validationErrors
	}

	switch kind {
	case "CiliumNetworkPolicy":
		schema = ciliumNetworkPolicySchema

	case "NetworkPolicy":
		// distinguish between Kubernetes and Calico
		apiVersion, _ := policy["apiVersion"].(string)

		if strings.Contains(apiVersion, "projectcalico.org") {
			schema = calicoNetworkPolicySchema
		} else {
			validationErrors = append(validationErrors, fmt.Errorf("unsupported Kubernetes NetworkPolicy"))
			return validationErrors
		}

	default:
		validationErrors = append(validationErrors, fmt.Errorf("unknown policy kind: %s", kind))
		return validationErrors
	}

	policyJSON, err = json.Marshal(policy)
	if err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("failed to marshal policy: %v", err))
		return validationErrors
	}

	documentLoader := gojsonschema.NewStringLoader(string(policyJSON))
	result, err := schema.Validate(documentLoader)
	if err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("failed to validate policy: %v", err))
		return validationErrors
	}

	if !result.Valid() {
		for _, desc := range result.Errors() {
			validationErrors = append(
				validationErrors,
				fmt.Errorf("%s", desc.String()),
			)
		}
	}

	return validationErrors
}
