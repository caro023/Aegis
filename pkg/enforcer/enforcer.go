package enforcer

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

func Enforcer(ctx context.Context, k8sClient client.Client, policies interface{}) error {
	// Supporta sia []string che []interface{}
	var policySlice []interface{}
	switch v := policies.(type) {
	case []string:
		for _, s := range v {
			policySlice = append(policySlice, s)
		}
	case []interface{}:
		policySlice = v
	default:
		return fmt.Errorf("failed to assert policies as a slice of interfaces")
	}

	for _, policyInterface := range policySlice {
		unstructuredPolicy, err := convertToUnstructured(policyInterface)
		if err != nil {
			return fmt.Errorf("failed to convert policy to unstructured: %v", err)
		}
		if err := applyPolicy(ctx, k8sClient, unstructuredPolicy); err != nil {
			return err
		}
	}
	return nil
}

func convertToUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
	// If it's a YAML string parse it directly
	if yamlStr, ok := obj.(string); ok {
		var objMap map[string]interface{}
		if err := yaml.Unmarshal([]byte(yamlStr), &objMap); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %v", err)
		}
		return &unstructured.Unstructured{Object: objMap}, nil
	}
	// try standard conversion otherwise
	if m, ok := obj.(map[string]interface{}); ok {
		return &unstructured.Unstructured{Object: m}, nil
	}
	return nil, fmt.Errorf("unsupported policy type: %T", obj)
}

func applyPolicy(ctx context.Context, k8sClient client.Client, policy *unstructured.Unstructured) error {
	if err := k8sClient.Create(ctx, policy); err != nil {
		if errors.IsAlreadyExists(err) {
			if err := k8sClient.Update(ctx, policy); err != nil {
				return fmt.Errorf("failed to update existing policy: %v", err)
			}
		} else {
			return fmt.Errorf("failed to create policy: %v", err)
		}
	}
	return nil
}
